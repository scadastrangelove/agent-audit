# EDR backlog — for v1.0 runtime mode

This file tracks ideas and requirements that were evaluated during forensic
(v0.7.x and earlier) development but require **runtime telemetry** beyond
what Claude Code / Codex / OpenClaw JSONL session logs expose. They are
parked here for the eventual EDR mode (v1.0+).

## Why this matters

agent-audit in its current form is a **forensic-on-logs scanner** — it reads
JSONL session files after the fact. EDR mode would be a daemon that hooks
into agent runtime via:
  - MCP proxy for tool call interception
  - strace / eBPF / sysdig for syscall-level events
  - filesystem watcher for writes
  - local process tree walker

Once we have those sources, the ideas below become realistically
implementable. Today, on JSONL alone, they cannot be done correctly.

## What we cannot see from JSONL (and thus cannot detect forensically)

Source: from discussion on Behavioral Provenance Graph material
(v0.7.2 planning, April 2026).

- **`user_input → exec(command)` taint propagation** — shell command args
  are visible, but the semantic connection "user said X in turn 5, the
  shell command in turn 12 is causally derived from it" requires
  NLP-level taint tracking we don't have. Partial workaround: heuristic
  causality within one autonomy window (what we'll do in v0.7.2) —
  "source appeared before sink in same window, likely related". Not real
  taint propagation.

- **Environment variables → data flow** — agents frequently do
  `git diff` or `curl` that reference `$AWS_SECRET` / `$GITHUB_TOKEN`.
  Session logs don't capture environment at invocation. We can't tell
  whether `git diff HEAD` included secrets that leaked. Needs:
  `/proc/<pid>/environ` snapshot at exec time.

- **Process tree / PPID** — Claude Code logs
  `Bash(python script.py)` but not that python spawned curl that spawned
  another python. We see a flat tool_call list. Multi-level process
  spawning (shell.spawned_process(python)) is invisible. Needs:
  strace `execve` tracing or `ps -ef` snapshots keyed on parent PID.

- **Interpreter exec chains** — `Bash(python -c '<code>')` where the
  `<code>` contains an unshelled curl call. We see the bash command but
  not that python internally forked. Needs: syscall tracing.

- **Byte counts on network** — "agent sent 48KB to external host" vs
  "agent connected and got 404" are very different signals. We see the
  curl command but not the response size or request body. Needs:
  tcpdump / eBPF sock hooks / LD_PRELOAD wrapping libc.

- **File read byte counts** — did the agent read 100 bytes from .env
  (just checked if key exists) or 10KB (full secret dump)? Needs:
  file descriptor tracking at syscall level.

- **Real-time approval state** — session logs show requests and results
  but not the approval dialog state. Did the user click "yes" quickly?
  Did they hesitate? Were consent flags bypassed? Needs: MCP proxy
  intercepting the approval flow in realtime.

- **Clipboard / browser session storage** — for agents that touch GUI
  (Claude Computer Use, Cursor with desktop control) — no way to see
  clipboard state or browser session cookies from JSONL. Needs: OS-level
  hooks.

- **Sandbox-level file I/O** — writes through Claude's internal file
  operations may or may not go through logged tool calls. Internal
  caching, tmp dir creation, log rotation inside the agent itself — all
  invisible. Needs: filesystem watcher on the agent's working dirs.

- **Timing fidelity** — session log timestamps are at message granularity,
  ~100ms+ resolution. Real taint propagation often needs microsecond
  ordering. Not catastrophic, but limits some detectors.

- **Cross-session correlation at runtime** — session boundaries in JSONL
  are clean, but "same agent, two sessions, coordinated attack across
  them" is hard to detect after the fact. Runtime daemon would see
  them as one continuous process. Needs: agent process tracking.

## What we CAN see from JSONL (current scope — enough for ~70% of vocabulary)

| Taint source concept | JSONL signal |
|----------------------|--------------|
| user prompt | user message text |
| retrieved web content | WebFetch tool_result |
| tool stdout/stderr | tool_result content (when included) |
| secrets | Read path → Aegis path classification |
| downloaded artifacts | curl/wget in Bash with write destination |
| generated code | Write/Edit path + content diff |

| Taint sink concept | JSONL signal |
|---------------------|--------------|
| shell exec | Bash/shell tool calls |
| sensitive file write | Write/Edit path → Aegis classification |
| package install | Bash pattern (pip install, npm install, etc.) |
| network egress | curl/wget/scp in Bash command args |
| repo push | Bash(git push) |
| secret read | Read of path matching Aegis secrets rules |
| persistence write | Existing persistence_write detector |

This is enough to build a **heuristic** taint-chain model for v0.7.2.

## Priority items for v1.0 EDR mode

When runtime telemetry becomes available, these are the top wins:

1. **Real process tree via strace** — close the fork/exec observability gap
2. **MCP proxy for realtime approval tracking** — see exactly what was
   auto-approved vs human-approved
3. **eBPF net hooks for byte counts** — quantify exfil volume, not just
   presence
4. **Environment snapshot at exec** — /proc/<pid>/environ captured
5. **Filesystem watcher for writes outside tool calls** — catch sideband
   writes invisible to session logs
6. **Cross-session process correlation** — agent restart persistence,
   state continuity

## Behavioral Provenance Graph (full form) — deferred

The full node-edge-attribute graph model from the v0.7.2 planning
discussion (nodes: Agent, LLM Turn, Tool Call, Process, File, Socket,
Secret, Repo Ref, Prompt Chunk, Decision Gate; edges: invoked, spawned,
read, wrote, connected_to, downloaded_from, derived_from, tainted_by,
approved_by, blocked_by, within_window, caused) requires most of the
unavailable runtime telemetry above.

For v0.7.2 we implement a **subset** of this model as heuristic causality
chains over the event sequence we do have. The graph formalism is the
right architecture for v1.0. Do not try to retrofit it to JSONL-only.

## D3FEND integration — deferred to v0.9

Mapping our rule_id's to D3FEND defensive concepts is valuable for
interoperability and explainability. Deferred until the HTML report
format lands in v0.9 — that's the surface where D3FEND annotations pay
off (clickable links, taxonomy-based grouping).

## ATT&CK taxonomy on graph nodes — deferred to v1.0

Useful only once we have a proper graph (see Behavioral Provenance
Graph above).

## Self-improving rule calibration loop — deferred to v0.9+

Feed verified TP/FP data back into rule parameters automatically. Needs:
stable benchmark corpus, safety against prompt injection of the calibration
loop itself, human-in-the-loop for edge cases. Not v0.7.2.
