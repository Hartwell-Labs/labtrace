# LabTrace

**Forensic timeline reconstruction and cross-process threat correlation for Linux audit telemetry.**

Rules find suspicious events. Taint analysis connects them. LabTrace turns a raw
JSONL event stream into ranked incident reports with full process chains —
zero agent required.

```
┌──────────────────────────────────────────────────────────┐
│  LabTrace — forensic incident report                     │
└──────────────────────────────────────────────────────────┘

14 events ingested · 10 rule signals · 2 taint flows · 1 incidents

[CRITICAL] Data theft chain: Reverse shell pattern in command line with exfiltration of cloud-credentials
  chain:   sshd(900) → sh(1000)
  signals: LT005, LT010, LT006, LT001, LT002, LT007, LT008, LT003, LT004
  taint:   cloud-credentials
  scope:   seq 3–12
```

## Why

SIEMs show you events. Auditors need incidents. The gap between "500 suspicious
log lines" and "this SSH session stole AWS credentials and shipped them to a raw
IP, then installed persistence and created a backdoor account" is manual,
painful and slow — exactly what an incident responder does not have time for.

LabTrace closes that gap in two passes:

1. **Rules (LT001–LT010)** — single-event signals: reverse-shell primitives,
   key material access, cloud credential stores, persistence writes,
   log truncation, database dumps, sensitive archives.
2. **Taint tracking** — sensitive data (SSH keys, cloud tokens, cookies, DB
   dumps) is marked at the source and *propagated* through file writes, exec
   arguments and child processes. A finding is elevated to an incident when
   taint reaches a sink: an outbound connection or an archive.

Correlation fuses both: findings sharing a process chain become one incident,
and a chain confirmed by taint flow gets its severity raised. Lone low-severity
noise is dropped.

## Install

```bash
cargo install --path .
# or
docker build -t labtrace .
```

## Usage

```bash
labtrace ./demo/incident-demo.jsonl
labtrace events.jsonl --format json        # machine-readable
labtrace events.jsonl --format sarif       # GitHub code scanning / SIEM
labtrace events.jsonl --min-severity high  # trim the noise
cat events.jsonl | labtrace -              # stdin
```

Exit codes: `0` clean, `1` input error, `2` incidents found (CI-friendly).

## Input format

JSONL — one event per line, `success`-filtered, ordered by epoch:

```json
{"seq":3,"epoch":1780000012,"ts":"2026-09-25T21:00:12Z","pid":1000,"ppid":900,
 "uid":1000,"kind":"file","exe":"/bin/cat","cmdline":"cat /home/pi/.aws/credentials",
 "target":"/home/pi/.aws/credentials","success":true}
```

`kind` values: `exec`, `file`, `net-connect`, `net-accept`, `user-add`, `socket`.
Unknown fields are preserved and echoed in reports.

## Telemetry sources

Adapters (planned / partial):

- **auditd** → `ausearch --format json` mapping (enriched: exe, cmdline from
  EXECVE + PROCTITLE)
- **eBPF/Go agent** — the talus ecosystem ships a Go agent emitting compatible
  events; LabTrace consumes them as-is
- **osquery / Falco JSONL** — mapping tables in `docs/adapters.md` (WIP)

## Rules

| ID | Signal | Severity |
|----|--------|----------|
| LT001 | Reverse-shell primitives in argv (`/dev/tcp`, `mkfifo`, `nc -e`) | Critical |
| LT002 | sudo/su from a non-root session | High |
| LT003 | Local account created | High |
| LT004 | SSH private key / authorized_keys access | Medium |
| LT005 | Cloud credential store access (AWS/gcloud/kube) | Medium |
| LT006 | Direct-IP connection (DNS-logging bypass) | Low |
| LT007 | Persistence write/registration (cron, systemd, authorized_keys) | High |
| LT008 | Log/history truncation (anti-forensics) | Medium |
| LT009 | Database dump command | Medium |
| LT010 | Archive covering sensitive paths | Medium |

Taint sources: SSH keys, `.aws/credentials`, gcloud/kube configs, keystore
formats (`.kdbx`, `.p12`, `.pfx`), `.env` files, browser cookie stores, DB
dumps, customer CSVs. Taint sinks: any outbound network connection, archive
creation.

## Design notes

- **Single static binary, no daemon, no agent, no database.** Point it at a
  file, get an incident report. Fits air-gapped forensics and offline triage.
- **Deterministic:** same input → same report. Reproducibility matters when a
  report ends up in front of a court, an insurer or an Amazon auditor.
- **SARIF out:** results land in GitHub code scanning, DefectDojo or any SIEM
  without glue code.
- **Honest scope:** this is post-hoc forensics and triage, not a replacement
  for a runtime EDR. It answers "what happened and how bad", not "stop it now".

## Status

v0.1.0 — core engine, 10 rules, taint engine, correlation, 3 output formats.
16 unit tests, demo scenario included.

## License

MIT — see [LICENSE](LICENSE). Built by [Hartwell Labs](https://hartwell-labs.github.io).
