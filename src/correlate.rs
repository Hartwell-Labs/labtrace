//! Correlation layer — elevates isolated findings into incidents.
//!
//! An incident is born when:
//! 1. multiple findings share a process chain (same ancestry), or
//! 2. a finding is upstream of a taint flow (sensitive data reached a sink),
//! or both. Each incident gets an aggregated severity: the max of its parts,
//! raised one level when chain + taint confirm each other.

use crate::event::Event;
use crate::proctree::ProcTree;
use crate::rules::{Finding, Severity};
use crate::taint::TaintFlow;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub title: String,
    pub severity: Severity,
    /// pids participating (deduped)
    pub actors: Vec<u32>,
    /// rendered chain of the primary actor
    pub chain: String,
    /// rule ids involved
    pub findings: Vec<String>,
    /// taint kinds confirmed (if any)
    pub taints: Vec<String>,
    /// seq range covering the incident
    pub seq_from: u64,
    pub seq_to: u64,
    /// narrative summary for the report
    pub summary: String,
}

fn raise(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::Critical,
        Severity::High => Severity::Critical,
        Severity::Medium => Severity::High,
        Severity::Low => Severity::Medium,
        Severity::Info => Severity::Low,
    }
}

fn max_sev(a: Severity, b: Severity) -> Severity {
    if a >= b {
        a
    } else {
        b
    }
}

/// Group findings by process ancestry and fuse with taint flows.
pub fn correlate(events: &[Event], tree: &ProcTree, findings: &[Finding], flows: &[TaintFlow]) -> Vec<Incident> {
    // bucket findings by their highest ancestor observed in telemetry
    let mut buckets: BTreeMap<u32, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        // root of the observed chain = first pid in chain
        let root = tree.chain(f.pid).first().copied().unwrap_or(f.pid);
        buckets.entry(root).or_default().push(f);
    }

    // map taint flows to their sink pid chain root as well
    let mut taint_by_root: BTreeMap<u32, Vec<&TaintFlow>> = BTreeMap::new();
    for fl in flows {
        let root = tree.chain(fl.sink_pid).first().copied().unwrap_or(fl.sink_pid);
        taint_by_root.entry(root).or_default().push(fl);
    }

    let mut incidents = Vec::new();

    for (root, fs) in buckets {
        let multi = fs.len() > 1;
        let tainted = taint_by_root.get(&root);
        let chained_taint = tainted.map(|v| !v.is_empty()).unwrap_or(false);

        // lone info/low finding without taint is noise; lone medium+ stands alone
        if !multi && !chained_taint {
            let lone = fs[0];
            if matches!(lone.severity, Severity::Info | Severity::Low) {
                continue;
            }
        }

        let mut sev = fs.iter().map(|f| f.severity).fold(Severity::Info, max_sev);
        if multi {
            sev = raise(sev);
        }
        if chained_taint {
            sev = raise(sev);
        }

        let seq_from = fs.iter().map(|f| f.seq).min().unwrap_or(0);
        let seq_to = fs
            .iter()
            .map(|f| f.seq)
            .chain(tainted.into_iter().flatten().map(|t| t.sink_seq))
            .max()
            .unwrap_or(0);

        let actors: Vec<u32> = {
            let mut set: Vec<u32> = fs.iter().map(|f| f.pid).collect();
            if let Some(v) = tainted {
                set.extend(v.iter().map(|t| t.sink_pid));
            }
            set.sort_unstable();
            set.dedup();
            set
        };

        let primary = fs
            .iter()
            .max_by_key(|f| f.severity)
            .copied()
            .expect("non-empty");
        let chain = tree.chain_str(primary.pid);

        let taints: Vec<String> = tainted
            .into_iter()
            .flatten()
            .map(|t| t.taint.kind.label().to_string())
            .collect::<Vec<_>>();
        let taints = {
            let mut v = taints;
            v.sort();
            v.dedup();
            v
        };

        let title = if chained_taint {
            format!(
                "Data theft chain: {} with exfiltration of {}",
                primary.title,
                taints.join(" + ")
            )
        } else if multi {
            format!(
                "Suspicious activity chain: {} + {} more signal(s)",
                primary.title,
                fs.len() - 1
            )
        } else {
            primary.title.to_string()
        };

        let summary = format!(
            "actor(s) [{}]; evidence seq {}–{}; signals: {}; {}",
            actors
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            seq_from,
            seq_to,
            fs.iter()
                .map(|f| f.rule_id)
                .collect::<Vec<_>>()
                .join(", "),
            if chained_taint {
                format!("taint flows confirmed: {}", taints.join(", "))
            } else {
                "no taint confirmation".into()
            }
        );

        incidents.push(Incident {
            title,
            severity: sev,
            actors,
            chain,
            findings: fs.iter().map(|f| f.rule_id.to_string()).collect(),
            taints,
            seq_from,
            seq_to,
            summary,
        });
    }

    incidents.sort_by(|a, b| b.severity.cmp(&a.severity));
    incidents
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::proctree::ProcTree;
    use crate::rules::run as run_rules;
    use crate::taint::analyze as run_taint;
    use std::collections::BTreeMap;

    fn ev(seq: u64, pid: u32, ppid: u32, kind: &str, exe: &str, target: &str, cmdline: &str) -> Event {
        Event {
            seq,
            ts: String::new(),
            epoch: None,
            pid,
            ppid,
            uid: 1000,
            kind: kind.into(),
            exe: exe.into(),
            cmdline: cmdline.into(),
            target: target.into(),
            success: true,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn full_chain_becomes_critical_incident() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/bin/sh", "", "sh"),
            ev(2, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat ~/.aws/credentials"),
            ev(3, 100, 1, "exec", "/bin/tar", "/tmp/s.tar.gz", "tar -czf /tmp/s.tar.gz .aws"),
            ev(4, 100, 1, "net-connect", "curl", "185.199.108.153:443", "curl https://x"),
        ];
        let tree = ProcTree::build(&evs);
        let findings = run_rules(&evs);
        let flows = run_taint(&evs, &tree);
        let incidents = correlate(&evs, &tree, &findings, &flows);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
        assert!(incidents[0].title.contains("exfiltration"));
        assert!(!incidents[0].taints.is_empty());
    }

    #[test]
    fn lone_low_finding_is_noise() {
        let evs = vec![ev(1, 100, 1, "net-connect", "curl", "93.184.216.34:443", "curl")];
        let tree = ProcTree::build(&evs);
        let findings = run_rules(&evs);
        let incidents = correlate(&evs, &tree, &findings, &[]);
        assert!(incidents.is_empty());
    }
}
