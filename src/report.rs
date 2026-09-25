//! Report rendering: terminal (ANSI) and machine (JSON).

use crate::correlate::Incident;
use crate::rules::Severity;

const C: [&str; 5] = ["\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[91m", "\x1b[1;91m"];
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Info => C[0],
        Severity::Low => C[1],
        Severity::Medium => C[2],
        Severity::High => C[3],
        Severity::Critical => C[4],
    }
}

pub fn terminal(incidents: &[Incident], stats: &str) -> String {
    let mut out = String::new();
    out.push_str("\n┌──────────────────────────────────────────────────────────┐\n");
    out.push_str("│  LabTrace — forensic incident report                     │\n");
    out.push_str("└──────────────────────────────────────────────────────────┘\n\n");
    out.push_str(&format!("{DIM}{stats}{RESET}\n\n"));

    if incidents.is_empty() {
        out.push_str("  \x1b[32m✓ No incidents correlated.\x1b[0m\n");
        return out;
    }

    for (i, inc) in incidents.iter().enumerate() {
        let color = sev_color(inc.severity);
        out.push_str(&format!(
            "{color}[{:>8}] {title}{RESET}\n",
            inc.severity.label().to_uppercase(),
            title = inc.title
        ));
        out.push_str(&format!("  {DIM}chain:{RESET}   {}\n", inc.chain));
        out.push_str(&format!("  {DIM}signals:{RESET} {}\n", inc.findings.join(", ")));
        if !inc.taints.is_empty() {
            out.push_str(&format!("  {DIM}taint:{RESET}   {}\n", inc.taints.join(", ")));
        }
        out.push_str(&format!("  {DIM}scope:{RESET}   seq {}–{}\n", inc.seq_from, inc.seq_to));
        out.push_str(&format!("  {DIM}summary:{RESET} {}\n", inc.summary));
        if i + 1 < incidents.len() {
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

pub fn json(incidents: &[Incident], stats: &str) -> String {
    let v = serde_json::json!({
        "tool": "labtrace",
        "version": env!("CARGO_PKG_VERSION"),
        "stats": stats,
        "incidents": incidents,
    });
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())
}

/// SARIF 2.1.0 output — feeds GitHub code scanning and most SIEM parsers.
pub fn sarif(incidents: &[Incident]) -> String {
    let rules: Vec<serde_json::Value> = incidents
        .iter()
        .enumerate()
        .map(|(i, inc)| {
            serde_json::json!({
                "id": format!("LT-INC-{:03}", i + 1),
                "shortDescription": { "text": inc.title },
                "defaultConfiguration": { "level": sarif_level(inc.severity) },
            })
        })
        .collect();
    let results: Vec<serde_json::Value> = incidents
        .iter()
        .enumerate()
        .map(|(i, inc)| {
            serde_json::json!({
                "ruleId": format!("LT-INC-{:03}", i + 1),
                "level": sarif_level(inc.severity),
                "message": { "text": format!("{} [{}]", inc.summary, inc.chain) },
                "properties": {
                    "severity": inc.severity.label(),
                    "actors": inc.actors,
                    "taints": inc.taints,
                }
            })
        })
        .collect();
    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "LabTrace", "rules": rules } },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_is_valid_structure() {
        let inc = Incident {
            title: "test".into(),
            severity: Severity::High,
            actors: vec![1],
            chain: "a(1)".into(),
            findings: vec!["LT001".into()],
            taints: vec![],
            seq_from: 1,
            seq_to: 2,
            summary: "s".into(),
        };
        let doc = sarif(&[inc]);
        assert!(doc.contains("\"version\": \"2.1.0\""));
        assert!(doc.contains("LabTrace"));
    }
}
