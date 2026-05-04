# Live Scan Timing Note (2026-05-04)

This private-only artifact captures a full live `agent-audit scan` run on the
maintainer workstation using:

```bash
agent-audit scan --mode full --no-verify --output <bundle> -y
```

The run was intentionally stopped after `1279.893s` (`21m 19.9s`) because it
did not complete in a reasonable time window.

## Top-level timing

- `Step 1` discovery: `0.089s`
- `Step 2` consent/setup: `0.003s`
- `Step 3` scan: `1279.326s` and still not finished when terminated
- `Step 4` report write: not reached
- `Step 5` LLM verify: disabled (`--no-verify`)

## What completed before termination

- `Claude Code` config + sessions completed
- elapsed until first Codex parse: `400.020s`
- inferred `Claude Code` phase duration: `399.619s`
- parsed `345` Claude sessions

## Bottleneck

The first Codex session was extremely large:

- path:
  `/Users/serg/.codex/sessions/2026/04/20/rollout-2026-04-20T17-38-38-019dab54-40c6-73c2-95a7-744c28f47da4.jsonl`
- size: `41 MB`
- lines: `21,196`
- parsed events (from audit log): `8,280`

After entering this session, the scanner remained CPU-bound near `99%` and did
not advance to the next session during the observation window.

## Key findings

1. Live-scan performance is dominated by very large Codex rollout files rather
   than discovery or report writing.
2. There appears to be a mode-plumbing gap: the CLI accepts `--mode full`, but
   the current `scanner.scan()` path does not pass a detection mode into
   `run_config_rules()` / `run_session_rules()`. The run was "full" from the
   CLI perspective, but the rule engine path does not obviously consume that
   mode.

Relevant code:

- `src/agent_audit/cli.py`
- `src/agent_audit/scanner.py`
- `src/agent_audit/rules.py`

## Files kept in-repo

- `scan-full-timings.json`: compact machine-readable summary

## Files kept outside git

The following were intentionally not committed:

- external audit log under `~/.local/share/agent-audit/logs/`
- raw local `.codex` session files
- aborted output bundle directory

Those files are machine-local and may contain operational details not suitable
for repo history.
