//! Process tree reconstruction from telemetry.
//!
//! Build a parent→child graph from (pid, ppid) pairs, then answer reachability
//! queries: which processes could have influenced process X? This is the
//! backbone of cross-process correlation — an attack chain is a path in this
//! tree combined with data-flow edges.

use crate::event::Event;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct ProcTree {
    /// pid -> ppid (latest observation wins; telemetry may be out of order)
    parent: BTreeMap<u32, u32>,
    /// pid -> exe of that pid (latest)
    exe: BTreeMap<u32, String>,
    /// pid -> cmdline (latest)
    cmdline: BTreeMap<u32, String>,
}

impl ProcTree {
    pub fn build(events: &[Event]) -> Self {
        let mut t = ProcTree::default();
        for e in events {
            if e.pid == 0 {
                continue;
            }
            t.parent.insert(e.pid, e.ppid);
            if !e.exe.is_empty() {
                t.exe.insert(e.pid, e.exe.clone());
            }
            if !e.cmdline.is_empty() {
                t.cmdline.insert(e.pid, e.cmdline.clone());
            }
        }
        t
    }

    /// Is `ancestor` an ancestor of `pid` in the observed tree?
    pub fn is_ancestor(&self, ancestor: u32, pid: u32) -> bool {
        let mut cur = pid;
        let mut hops = 0;
        while let Some(&p) = self.parent.get(&cur) {
            if p == ancestor {
                return true;
            }
            cur = p;
            hops += 1;
            if hops > 64 {
                // guard against cycles in malformed telemetry
                break;
            }
        }
        false
    }

    /// Path from root-ish ancestor down to `pid` (exclusive of unknowns).
    pub fn chain(&self, pid: u32) -> Vec<u32> {
        let mut path = vec![pid];
        let mut cur = pid;
        let mut hops = 0;
        while let Some(&p) = self.parent.get(&cur) {
            if p == cur || hops > 64 {
                break;
            }
            path.push(p);
            cur = p;
            hops += 1;
        }
        path.reverse();
        path
    }

    /// Render the chain as a human-readable string: sshd(900) → sh(1000) → curl(1001)
    pub fn chain_str(&self, pid: u32) -> String {
        self.chain(pid)
            .iter()
            .map(|&p| {
                let exe = self.exe.get(&p).map(|s| short_exe(s)).unwrap_or("?").to_string();
                format!("{exe}({p})")
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

fn short_exe(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(pid: u32, ppid: u32, exe: &str) -> Event {
        Event {
            seq: 0,
            ts: String::new(),
            epoch: None,
            pid,
            ppid,
            uid: 0,
            kind: "exec".into(),
            exe: exe.into(),
            cmdline: String::new(),
            target: String::new(),
            success: true,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn ancestor_detection() {
        let evs = vec![ev(1, 0, "/sbin/init"), ev(100, 1, "/usr/sbin/sshd"), ev(200, 100, "/bin/sh")];
        let t = ProcTree::build(&evs);
        assert!(t.is_ancestor(100, 200));
        assert!(t.is_ancestor(1, 200));
        assert!(!t.is_ancestor(200, 100));
    }

    #[test]
    fn chain_renders() {
        let evs = vec![ev(1, 0, "/sbin/init"), ev(100, 1, "/usr/sbin/sshd"), ev(200, 100, "/bin/sh")];
        let t = ProcTree::build(&evs);
        let s = t.chain_str(200);
        assert!(s.contains("sshd"));
        assert!(s.contains("sh(200)"));
    }

    #[test]
    fn cycle_guard() {
        let evs = vec![ev(7, 8, "/a"), ev(8, 7, "/b")];
        let t = ProcTree::build(&evs);
        // must terminate, not hang
        let _ = t.chain(7);
        assert!(!t.is_ancestor(99, 7));
    }
}
