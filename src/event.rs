//! Event model for Linux auditd telemetry.
//!
//! LabTrace ingests JSONL events (one JSON object per line) shaped like
//! enriched auditd/syslog records. Only a handful of fields are required;
//! anything extra is preserved and echoed back in reports.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One telemetry event (normalized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic sequence number (original order preserved).
    #[serde(default)]
    pub seq: u64,
    /// RFC3339 or epoch seconds as string — kept verbatim for the timeline.
    #[serde(default)]
    pub ts: String,
    /// Numeric timestamp used for ordering when present.
    #[serde(default)]
    pub epoch: Option<f64>,
    /// Process id of the acting process.
    #[serde(default)]
    pub pid: u32,
    /// Parent process id.
    #[serde(default)]
    pub ppid: u32,
    /// User id.
    #[serde(default)]
    pub uid: i64,
    /// Event class: exec, file, net-connect, net-accept, socket, user-add, ...
    #[serde(default)]
    pub kind: String,
    /// Executable path (for exec) or acting binary path.
    #[serde(default)]
    pub exe: String,
    /// Full command line (argv joined).
    #[serde(default)]
    pub cmdline: String,
    /// Operation target: file path, remote ip:port, account name, ...
    #[serde(default)]
    pub target: String,
    /// Success flag (syscall result >= 0).
    #[serde(default)]
    pub success: bool,
    /// Free-form extra fields (hostname, tty, cwd, ...).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Event {
    /// A short human label used in timelines.
    pub fn label(&self) -> String {
        match self.kind.as_str() {
            "exec" => format!("exec {}", self.exe),
            "file" => format!("file {}", self.target),
            "net-connect" => format!("connect {}", self.target),
            "net-accept" => format!("accept {}", self.target),
            "socket" => format!("socket {}", self.target),
            "user-add" => format!("useradd {}", self.target),
            other => format!("{other} {}", self.target),
        }
    }
}

/// Parse a JSONL stream into events, preserving order. Lines that fail to
/// parse are reported as errors but do not abort ingestion.
pub fn parse_jsonl(input: &str) -> (Vec<Event>, Vec<String>) {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(mut ev) => {
                if ev.seq == 0 {
                    ev.seq = (i + 1) as u64;
                }
                events.push(ev);
            }
            Err(e) => errors.push(format!("line {}: {e}", i + 1)),
        }
    }
    events.sort_by(|a, b| {
        let ea = a.epoch.unwrap_or(0.0);
        let eb = b.epoch.unwrap_or(0.0);
        ea.partial_cmp(&eb).unwrap_or(std::cmp::Ordering::Equal).then(a.seq.cmp(&b.seq))
    });
    (events, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_event() {
        let line = r#"{"pid":100,"ppid":1,"kind":"exec","exe":"/bin/sh","cmdline":"sh -c id","success":true}"#;
        let (evs, errs) = parse_jsonl(line);
        assert!(errs.is_empty());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "exec");
        assert_eq!(evs[0].seq, 1);
    }

    #[test]
    fn orders_by_epoch() {
        let input = r#"
{"seq":1,"epoch":10.0,"pid":1,"kind":"exec","exe":"/a","success":true}
{"seq":2,"epoch":5.0,"pid":2,"kind":"exec","exe":"/b","success":true}
"#;
        let (evs, _) = parse_jsonl(input);
        assert_eq!(evs[0].exe, "/b");
    }

    #[test]
    fn bad_lines_do_not_abort() {
        let input = "{\"pid\":1}\nnot json\n{\"pid\":2,\"kind\":\"file\"}\n";
        let (evs, errs) = parse_jsonl(input);
        assert_eq!(evs.len(), 2);
        assert_eq!(errs.len(), 1);
    }
}
