use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

mod correlate;
mod event;
mod proctree;
mod report;
mod rules;
mod taint;

/// LabTrace — forensic timeline reconstruction and cross-process threat
/// correlation for Linux audit telemetry. Rules find suspicious events;
/// data-flow taint analysis connects them into incidents.
#[derive(Parser, Debug)]
#[command(name = "labtrace", version, about, long_about = None)]
struct Args {
    /// JSONL telemetry file (use '-' for stdin)
    input: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Show only incidents at or above this severity
    #[arg(short, long, value_enum, default_value_t = MinSeverity::Low)]
    min_severity: MinSeverity,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Sarif,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum MinSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<MinSeverity> for rules::Severity {
    fn from(m: MinSeverity) -> Self {
        match m {
            MinSeverity::Info => rules::Severity::Info,
            MinSeverity::Low => rules::Severity::Low,
            MinSeverity::Medium => rules::Severity::Medium,
            MinSeverity::High => rules::Severity::High,
            MinSeverity::Critical => rules::Severity::Critical,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = if args.input.as_os_str() == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(&args.input)
            .with_context(|| format!("reading {}", args.input.display()))?
    };

    let (events, errors) = event::parse_jsonl(&input);
    for e in &errors {
        eprintln!("warn: {e}");
    }
    if events.is_empty() {
        eprintln!("no events parsed — nothing to do");
        std::process::exit(1);
    }

    let tree = proctree::ProcTree::build(&events);
    let findings = rules::run(&events);
    let flows = taint::analyze(&events, &tree);
    let mut incidents = correlate::correlate(&events, &tree, &findings, &flows);

    let min: rules::Severity = args.min_severity.into();
    incidents.retain(|i| i.severity >= min);

    let stats = format!(
        "{} events ingested · {} rule signals · {} taint flows · {} incidents",
        events.len(),
        findings.len(),
        flows.len(),
        incidents.len()
    );

    let out = match args.format {
        Format::Terminal => report::terminal(&incidents, &stats),
        Format::Json => report::json(&incidents, &stats),
        Format::Sarif => report::sarif(&incidents),
    };
    println!("{out}");

    if !incidents.is_empty() {
        std::process::exit(2); // findings present — CI-friendly exit code
    }
    Ok(())
}
