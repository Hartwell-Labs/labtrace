# Telemetry adapters

LabTrace consumes a normalized JSONL event stream. This document maps real
telemetry sources onto that schema. Fields marked **required** must be present;
everything else is optional and preserved verbatim in reports.

## Event schema

```json
{
  "seq":   3,
  "epoch": 1780000012.5,
  "ts":    "2026-09-25T21:00:12Z",
  "pid":   1000,
  "ppid":  900,
  "uid":   1000,
  "kind":  "file",
  "exe":   "/bin/cat",
  "cmdline": "cat /home/pi/.aws/credentials",
  "target":  "/home/pi/.aws/credentials",
  "success": true
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `pid`, `ppid` | **yes** | process graph is built from these |
| `kind` | **yes** | one of: `exec`, `file`, `net-connect`, `net-accept`, `user-add`, `socket` |
| `success` | **yes** | failed calls are skipped entirely |
| `epoch` | recommended | numeric sort key; fall back is file order |
| `exe`, `cmdline`, `target` | per kind | `exec` needs exe+cmdline; `file`/`net-*` need target |
| everything else | no | hostname, tty, cwd… — preserved in output |

## auditd

```bash
ausearch --start today --format json | jq -c '
  def kind:
    if .type == "SYSCALL" and (.syscall | test("execve")) then "exec"
    elif .type == "SYSCALL" and (.syscall | test("open|unlink|rename")) then "file"
    elif .type == "SYSCALL" and (.syscall | test("connect")) then "net-connect"
    elif .type == "SYSCALL" and (.syscall | test("accept")) then "net-accept"
    elif .type == "USER_ADD" or .type == "ADD_USER" then "user-add"
    else empty end;
  select(.type=="SYSCALL" or .type=="USER_ADD" or .type=="ADD_USER")
  | {
      epoch: (.epoch | tonumber),
      ts: .timestamp,
      pid: .node[0].pid,
      ppid: .node[0].ppid,
      uid: .node[0].uid,
      kind: kind,
      exe: .node[0].exe,
      cmdline: .node[0].proctitle,
      target: (.node[0].name // ""),
      success: ((.node[0].success // "1") == "1")
    }'
```

Notes:
- `ppid` from auditd is the parent at syscall time — good enough for chain
  reconstruction; for exec chains also consider enriching with `EXECVE`.
- `proctitle` is hex-encoded when it contains spaces; decode with
  `perl -0777 -pe 's/([0-9a-f]{2})/chr(hex($1))/gie'` if needed.

## talus Go agent (eBPF)

The talus ecosystem ships a Go agent that emits LabTrace-compatible events
natively (`kind` is derived from the syscall class, `cmdline` from
`/proc/<pid>/cmdline` snapshot at exec time — richer than auditd's proctitle).

```bash
talus-agent stream --format labtrace | labtrace -
```

## Falco JSON

```bash
falco --json | jq -c '
  { epoch: (.time | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601),
    ts: .time,
    pid: (.output_fields["proc.pid"] | tonumber),
    ppid: (.output_fields["proc.ppid"] | tonumber),
    uid: (.output_fields["user.uid"] | tonumber),
    kind: (if .output_fields["evt.type"] == "execve" then "exec"
           elif .output_fields["evt.type"] == "connect" then "net-connect"
           else "file" end),
    exe: .output_fields["proc.exe"],
    cmdline: (.output_fields["proc.cmdline"] // ""),
    target: (.output_fields["fd.name"] // .output_fields["fd.sip"] // ""),
    success: true }'
```

## osquery

```
osqueryi --json "SELECT * FROM shell_history"  # file events (kind=file)
osqueryi --json "SELECT * FROM process_events" # kind=exec (via audit sink)
```

Map columns directly; `path`/`destination` → `target`.

## Caveats

- **Container runtimes:** pids are host-namespace pids in auditd/Falco output.
  If events come from inside a container with its own pid namespace, chains
  will break across the namespace boundary — normalize to host pids first.
- **PPID after fork servers:** preforking servers (sshd, Apache) show the
  *master* as ppid — chains render as `sshd → child`, which is what you want.
- **Clock skew across hosts:** only mix events from multiple hosts if you
  trust NTP; otherwise process per host and correlate manually.
