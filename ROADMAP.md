<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# agent-audit roadmap

## Philosophy

Static analysis is the wide net; the LLM is the filter. Detectors generate
candidates, and the LLM verifier filters them using surrounding context.
Static rules can therefore be more aggressive than usual in security tooling,
because the verifier is expected to absorb part of the precision burden.

## Current backlog (post-v0.14.4)

Actionable items discovered via grand-runs and lexicon audits. Each item
has concrete entry points and rough effort estimate.

### Intent-based suppressor for security-research skills

**Problem**: `\bjailbreak\b` in IDENTITY_HARD fires CRITICAL on defensive
security skills (danielmiessler/Personal_AI_Infrastructure/Security/
PromptInjection/SKILL.md — 8 mentions, all discussing jailbreak as an
analyzed attack pattern, not performing it). Current behavior treats
descriptive and prescriptive language identically.

**Approach**: add intent classifier. Signal candidates:
- Path markers: `/security/`, `/guardrail`, `/defense/`, `/research/`, filenames containing `PromptInjection`, `Analysis`
- Frontmatter `description` field containing "detect", "analyze", "identify", "classify", "catalog"
- Frame words in surrounding prose: "attack pattern", "taxonomy", "example of", "research", "paper"

Entry point: `knowledge/intent_suppressor.py` (new module), applied to
`identity_redefinition.check_file()` as a severity demoter similar to
how `educational_suppressor` demotes rule-pack findings. Structural skill
markers (frontmatter, MCP manifest) should override intent suppression —
we don't want a real attacker skill hiding behind a "research" label.

**Effort**: 1-2 days. Must include regression fixtures for both sides:
research skills stay at INFO, red-team skills (godmode, obliteratus)
stay at CRITICAL.

### D-2 partial: prose-around-code context for autonomy flags

**Problem**: `--watch\b` in AUTONOMY_LOOP fires 36 times in test corpus,
all 36 matches inside code blocks, 0 in prose. Current AST prefilter
suppresses code-fence matches, so autonomy_loop detector silently
misses this class of "autonomy-via-flag" signals.

**Approach**: when a code fence contains an autonomy marker, check the
surrounding prose (200 chars before and after the fence) for autonomy
framing. If prose says "run continuously with", "in watch mode", "poll
until done" around a `gh pr checks --watch` example, it's a TP.

Entry point: extend `markdown_features.extract()` to return
`code_blocks_with_surrounding_prose: List[(code, prose_before, prose_after)]`.
Extend `classify_capabilities()` to take an optional secondary-signal
parameter that boosts autonomy_loop_total when code-fence markers have
autonomy-framing prose nearby.

**Effort**: 2-3 days. Calibration required — must not reintroduce the
install-instruction FP class that rule-surface-routing closed in v0.14.0.

### `\breuse session` collection-scale verification

**Observation**: 732/735 matches of `\breuse session` are identical
boilerplate ("Session reuse: Reuse session IDs within a workflow. Generate
new ones for new workflows") replicated across 732 skill files.

**Question**: is collection-scale aggregator catching this? If yes, one
aggregate per cohort is correct behavior. If no, aggregator needs either
lower thresholds for boilerplate-replication cases or a dedicated
"boilerplate detector" that identifies byte-identical strings across
cohort members.

**Effort**: 0.5 day investigation + fix. Low priority — this is
signal-dense but highly repetitive, not a correctness issue.

### LLM verifier hookup for native findings

**Context**: `llm_verifier.py` infrastructure exists for session findings
but `scan-project` bypasses it. Native findings are the prime candidates —
~16 findings per 10-target suite, manageable batch size.

**Approach**: add `--verify` flag to `scan-project`. For each native
finding, send the file text + finding summary to Claude/GPT-4 and ask
"is this a real capability declaration or documentation/example?". Store
verdict in `Finding.llm_verdict`. Downgrade CRITICAL→HIGH or drop if LLM
says FP.

Entry point: `cli.scan_project_command()` already has `--yes` flag pattern;
add `--verify` alongside. Verifier module lives at `llm_verifier.py`.

**Effort**: 2-3 days. Must include cost / rate-limit controls (default
off, batch size cap).

### Subtree scan mode

**Context**: Full corpus scans on large repos (secondsky/claude-skills,
affaan-m/everything-claude-code) take >2 min each. Most of the work is
scanning non-instruction files.

**Approach**: `--only-instruction-subtrees` flag that pre-prunes the walk
to only directories containing at least one `SKILL.md`, `AGENTS.md`, or
MCP manifest. Typical 2-5x speedup on monorepos.

**Effort**: 0.5 day.

### Cross-cohort path-based aggregation

**Observation**: ruflo/ruvnet has 6 copies of `sparc-methodology/SKILL.md`
in different subprojects (`v2/.claude/skills/`, `v3/@claude-flow/cli/`,
`v3/@claude-flow/mcp/`, `.agents/skills/`, `.claude/skills/`). Current
aggregator treats each copy as separate cohort member (different parent
dir), so replicated finding on the same file across 4 cohorts stays as
4 findings.

**Approach**: secondary aggregation pass on (rule_id, basename) tuples
after the primary cohort pass. If the same file name under the same
skill name fires the same rule across ≥3 different cohort parents,
collapse to one "cross-cohort replication" aggregate.

**Effort**: 1-2 days. Must preserve individual findings' paths for
triage.

### High-density pattern audit follow-ups

From 2026-04-21 lexicon audit on 2565 files, patterns needing deeper
investigation:

- `\bRUBE_[A-Z_]+\b` — density 12.8, 10015 matches on 782 files. Composio
  tool prefix. Likely signal-dense TP (each RUBE_* token is a real
  Composio tool name), but inflates `remote_action_surface_total`
  artificially in Composio-style corpora. Consider deduplicating
  RUBE_* matches to distinct count only before applying threshold.
- `\b(takes? effect)?(on )?(next|future )?session\b` in PERSIST_WRITE —
  959 files, 2519 matches. Bare "session" as word fires too much.
  Narrow pattern to `\b(next|future)\s+session\b` or require `takes
  effect` prefix.
- `\bcontinuously\b` — 42 files, 49 matches, density 1.2. Mixed prose
  usage ("continuously improving") vs autonomy ("runs continuously").
  Manual review recommended; possibly split into CI vs runtime autonomy.

### ASAMM maturity rollup

See dedicated section below. Blocked on data-quality items above.
Once intent-suppressor and cross-cohort aggregation land, findings
will be clean enough to start computing L1/L2/L3.

## Releases

### v0.1 — P0 MVP *(done)*

Discovery, Claude Code / Codex parsers, 5 detectors, consent flow,
Markdown + JSON reports, transparent audit log.

### v0.2 — Sub-agents + calibration *(done)*

- 3 new detectors: AI-04.persistence-write, AD-02.out-of-cwd-write,
  C2.private-key-exfil
- Adaptive severity in C3.autonomy-window-excess
- Outbound classifier in C2.credential-exfil-chain
- Sub-agent lineage

### v0.3 — Batch + Preflight + Honest errors *(done)*

- Batch verification (10 findings in one prompt)
- Preflight check with a minimal test
- Honest error reporting from the Claude CLI JSON body
- Abstract VerifierBackend

### v0.4 — BYO key + Local LLMs + Proxy *(done)*

- AnthropicAPIBackend, OpenAICompatibleBackend — direct HTTP
- OpenRouter support, Ollama / LM Studio / vLLM / llama.cpp
- `--proxy` and auto-detect from env
- 2 detectors from `orghound.db-wipe`: AG-04.destructive-without-backup, AV-01.test-touches-prod

### v0.5 — ASAMM samples + Integrity review + Patches *(done)*

- 5 new detectors from SecOps / claude-code-zhet / ouroboros samples
- --mode conservative / standard / full
- --integrity-review (second-pass self-check)
- --patches (config fix generator)

### v0.9.0 — Codex taint engine fix *(done, current release)*

Completes v0.8.2 Codex normalization work. v0.8.2 fixed detectors'
tool_name checks but missed the deeper layer — `nlu/taint.py` taint
classifier that feeds C2/C3/AI-04/AI-06/AD-02/advice detectors. Real
data analysis showed 10 rules remained Codex-blind despite v0.8.2
patches because taint engine returned empty EventClassification for
every Codex event.

Fix: canonical_tool fallback in 4 taint branches + 3 secondary patches
(credential_context_bleed second bash check, chaos_behaviors test-runner
threshold, AI-06 internal helpers).

10/10 Codex-blind rules confirmed fire on synthetic E2E test. Claude
Code parity preserved. Expected production impact: Codex structural
findings from ~10 to ~30-40.

### v0.8.2 — Codex tool normalization *(done)*

Canonical cross-agent tool names. Codex `exec_command`/`write_stdin`/
`apply_patch`/`read_file` now map to canonical `Bash`/`BashStdin`/
`Patch`/`Read`. Previously the detectors (destructive-backup, credential-exfil,
persistence-write, out-of-cwd, confirmation-bypass) silently missed
all Codex sessions because the `tool_name` check did not match.

10 detectors were patched to use canonical fallback. 4/4 Codex coverage
smoke tests are green. Claude Code parity preserved.

### v0.8.1 — Project-type awareness *(done)*

`.agent-audit.yaml` at project root — user declares project intent
(`tags: [dast]`, trusted_targets, severity_overrides, suppress_rules,
allowlist_writes). Plus auto-detection from CLAUDE.md/AGENTS.md keywords
(DAST/EASM/pentest/red-team). Detectors apply severity overrides
and suppressions via `scanner._apply_project_config()`.

Default tag overrides cover known false-positive patterns:
DAST projects downgrade `C3.autonomy-with-exfil-chain` → info
(legitimate scan workflow), `AG-04.destructive-without-backup` → low.

### v0.8.0 — Session aggregation + real-data calibration *(done)*

The first of three v0.8 UX shifts, plus critical calibration using
codex-cli-verified data.

**Session aggregation (MD report):**
- **Sessions of concern** cards (3+ findings each) with severity rollup
- **Rule clusters** inside each card
- **Pattern groups** inside each cluster (the evidence shape hash normalizes
  /tmp/X, sprint numbers, PIDs, UUIDs)
- **Quiet sessions** rendered one line each
- **Config/environment** findings in a separate section
- **Full flat list** preserved in a `<details>` appendix for search
- JSON report unchanged (data fidelity)

**Real-data calibration (325 LLM-verified findings):**
- **Claim detector "substantial tool activity" gate** — a 91% FP rate in
  `unverified-completion-claim`, because the claims were supported by real
  tool activity while our category-specific regexes did not match it. Gate:
  ≥5 prior tools → skip, ≥2 tools → downgrade by 2 levels, <2 → full.
  Projection on the verified subset: **128/203 FPs eliminated, 0 TPs
  false-suppressed**.
- **Poisoned-project-config** FP on `example.com` and URLs inside Markdown
  code fences. Fix: add IANA docs TLDs to the exclusion list and strip fenced
  code blocks for `.md` files.
- **`render_json` cwd/git_branch leak** — the Codex parser in v0.7.7 correctly
  extracted `cwd` from `session_meta.payload.cwd`, but the reporter dropped it.
  Fix: all Session fields now flow into JSON output.

**Measured impact:** an 871-finding Markdown report now has a 91 KB / 1778-line
top section versus 1.69 MB / 35935 lines in the flat layout (5% of the size).
Critical TPs are visible on the first scroll.

No rule IDs changed — still 27 total.

Next: **v0.8.1** — project-type awareness (`.agent-audit.yaml`
+ auto-detect from CLAUDE.md keywords). **v0.8.2** — Codex tool
normalization (a `canonical_tool` field for cross-agent detector
compatibility).

### v0.7.7 — Sonnet default + Codex fixes *(done)*

Three Codex coverage bugs found while analyzing the 871-finding report,
plus one performance win.

- **Sonnet as the default for the Claude CLI backend** (2x faster, 3x cheaper
  than Opus on the verify workload). Override: `--claude-model opus`.
- **`unbounded-loop` polling whitelist** — `write_stdin(chars="")` is a
  semantic READ from the tmux session, not a repeated action. Removes 3/6 FP.
- **`dangerous-recommendation` skip on verifier JSON** — our own output from
  a previous verify run must not trigger the advice detector. Removes ~3/5 FP.
- **Codex parser now extracts `cwd` from the correct location** —
  `session_meta.payload.cwd` (primary, line 1) + `turn_context.payload.cwd`
  (per-turn fallback) + `exec_command.workdir` (last-resort). Previously
  we looked at the top level, which did not match the real Codex schema. Also
  adds `json.loads(..., strict=False)` for tolerance to raw control chars
  inside `user_instructions` strings. This fixes
  `AI-05.poisoned-project-config` on all Codex sessions.

Total: 27 rule IDs, unchanged.

### Lessons for v0.8 (not implemented in v0.7.7)

- Power-law findings distribution: 10 sessions = 95% of findings. UX overhaul.
- Project-type awareness (`.agent-audit.yaml`) for DAST/pentest workflows.
- Codex tool-name normalization (all C2/C3/AG detectors were shaped around
  the Claude Code event structure and therefore missed signal on Codex).

### v0.7.6 — Markdown + verify timeout fixes *(done)*

Two real bugs found in Sergey’s run on v0.7.5:

- **Markdown corruption:** nested ``` blocks in `report.py` broke the outer
  fence in the `.md` report. Fixed by counting the longest backtick run and
  using an outer fence of length N+1. Verified on a real 871-finding report:
  0 unclosed fences after the fix.
- **Integrity review 120s timeouts:** implicit default timeout
  `backend.call()` was 120s. Integrity prompts were 2× larger than primary
  verify prompts; codex-cli at `concurrency=4` with large prompts hit timeout
  on several batches at once.

Fix:
- `verify_batch` timeout default 120s → 240s, param-able
- `integrity_review` timeout default 300s
- `--timeout` CLI flag (default 240s)
- Integrity review throttles concurrency to `min(concurrency, 2)`
  + uses `timeout × 1.5`

No rule changes — same 27 rule IDs as v0.7.5.

### v0.7.5 — Cyber-class detectors + version audit *(done)*

The first release where the threat model shifted from self-inflicted
(over-reliance) to cyber-sourced risk (the agent as victim or vector).
Based on Check Point Research Feb 2026 disclosures and the Cursor/MCP CVE landscape.

**2 new detectors + 1 extended detector:**

- `AI-05.poisoned-project-config` (CRITICAL/HIGH/MEDIUM) — inverse
  of `mcp-config-mutation`. Scans `.claude/`, `.cursor/`,
  `.windsurf/`, `CLAUDE.md` *inside* the project dir (`session.cwd`) for
  shell-in-hook, STDIO-MCP, invisible unicode, sensitive path refs,
  and external exfil URLs. One scan per unique project root, bounded to
  (≤30 files/project, ≤50 projects/run, ≤256KB/file). Catches the Check Point
  CVE-2025-59536 / CVE-2026-21852 class retroactively.

- `AI-05.agent-version-vulnerable` (severity per CVE) — reads installed
  agent CLI version via subprocess and compares it to a maintained table.
  Current entries: Claude Code ≤2.0.64 (CVE-2025-59536), Cursor ≤1.9.99
  (CVE-2025-54136). Zero-FP by construction.

- `persistence_write` extended — added `.claude/hooks/*`,
  `.cursor/hooks/*`, `.windsurf/hooks/*`, `.codex/hooks/*`,
  `.continue/hooks/*`. Previously only `.git/hooks/`. Agent-tool
  hooks are executable at project open, so they carry the same persistence semantics.

**Total: 27 rule IDs** (up from 25 in v0.7.4).

### v0.7.4 — Parallel verify + real-data calibration *(done)*

Calibration based on a 143-session real-data run (871 findings) from
CyberOK. Three failure modes plus a claim-heavy detector created 80% FP noise
and 30+ minutes of verify time. This release addresses both problems.

**Parallel verify infrastructure:**

- `batch_verifier.verify_all_batched` rewritten on top of `ThreadPoolExecutor`
- New `--concurrency` flag (default 4)
- `--batch-size` default 10 → 25
- Integrity review also runs in parallel
- **Measured speedup 9.92x** on benchmark (bs=10 seq → bs=25 c=4)

**FP fixes for real-data clusters:**

- AG-04 `_is_ephemeral_only` now stops at the first shell separator — fixes
  the multi-stage `rm /tmp/X && python script.py` regression (closes 51/70)
- `AI-04.mcp-config-mutation` narrowed to only `mcp.json`, `.cursorrules`,
  and system-level configs. Project-local `CLAUDE.md` and Claude Code memory
  no longer trigger it (closes 36/39)
- `behavior.hypothetical-executed` + imperative filter (EN/RU/ZH).
  "let's check X" is no longer treated as hypothetical (closes 1/1)
- `claim_detector` threshold 4 → 5. Verb + cross-category-object alone
  now stays `uncertain`, not `claim`. A direct-category object
  or evidence anchor is required (closes 220/523, downgrades 261 HIGH → MEDIUM)

**Projection on real data:** 871 → 563 findings (35% FP eliminated).

No new detectors — the focus was calibration. Total remains 25 rule IDs.

### v0.7.3 — i18n + attachment failure modes + OX MCP research *(done)*

**Multi-language NLU (RU/ZH):** `nlu/lexicons.py` with three-language
lexicons, `claim_detector` rewritten for CJK substrings plus RU/EN
tokens. 11/11 RU + 8/8 ZH + 17/18 EN regression cases.

**New detectors (5):**

- `behavior.confirmation-bypass` (HIGH/CRITICAL) — `--force`/`-y`/
  `--auto-approve`/`--accept-data-loss` on destructive commands. From GitHub
  issues #27063 (Railway drizzle), #34729 (Prisma reset), #4969 (Codex).
- `behavior.hypothetical-executed` (CRITICAL) — the user asked
  hypothetically, the agent executed anyway. Issue #28699.
- `AI-04.mcp-config-mutation` (CRITICAL/HIGH) — the agent writes to
  `mcp.json`/settings.json/CLAUDE.md/.cursorrules. OX Security research,
  CVE-2026-30615 (Windsurf).
- `credential.context-bleed` (HIGH/CRITICAL) — `export
  GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/...` or a cloud profile
  switch. Reddit r/ClaudeAI Apr 2026 case (25k docs deleted).
- `resource.api-storm` (MEDIUM/HIGH/CRITICAL) — same endpoint, varying
  args, >=25 calls. Reddit r/AI_Agents Apr 2026 (50k API / prod DB crash).

**Extended existing detectors:**

- AG-04/cascading-destructive: Windows (`rmdir /s /q`, `Remove-Item`),
  macOS (`diskutil apfs deleteVolume`), migrations (drizzle/prisma/n8n)
- `cascading-destructive-chain`: added Tier 0 diagnostic ops
  (`pkill -9`, `rm *-wal`, cache clear) to catch n8n-style remediation chains
- `advice.dangerous-recommendation`: `wrapper-bypass` pattern —
  `npx -c`/`sh -c`/`python -c`/`eval` to bypass allowlists (OX Flowise)

**Total: 25 rule IDs** (up from 22 in v0.7.2).

### v0.7.2 — Calibration from real data + composite C3 + CST *(done)*

Calibration based on a real 108-session run (Apr 2026), where
codex-cli verified 256 findings and explained the rationale for each FP.
The goal was to reduce a 79% FP rate to roughly 30-35% through targeted
cluster fixes and structural improvements.

**New: Compact Sandbox Trace (CST).** For each significant autonomy
window, the tool builds a structured summary — control flow, taint chains,
sensitive paths, network endpoints, claims, per-category subgraph
scores, anomaly heuristic. It attaches to findings as Evidence in two
formats: Markdown (for the `.md` report) and JSON (for the LLM verifier).
This addresses the Codex complaint that "the alert omits the transfer target and data".

**New: NLU claim detector.** `nlu/claim_detector.py` — a score-based
pipeline built from D+E+F+H+I+J+K+M+N tactics (sentence typing, category lexicons,
modality/hedge penalties, evidence anchors, three-bucket output).
94% accuracy on 18 regression cases from Codex rationales. Stdlib only.

**C3 rewritten into composite rules:**

- `C3.autonomy-window-context` INFO — a context pointer carrying CST, not an alert
- `C3.autonomy-with-sensitive-sink` MEDIUM — window + sensitive write
- `C3.autonomy-with-exfil-chain` HIGH/CRITICAL — window + causality
  chain external source → non-shell sink (score >=0.5 / >=0.8)
- `C3.autonomy-with-persistence` HIGH — window + persistence write

**Quick fixes:**

- AG-04 `/tmp` filter — destructive actions on ephemeral paths are skipped
  (closes 87/87 FP)
- AI-06 localhost filter — `127.0.0.1`/`localhost`/private IP are no longer
  treated as "external" (closes 51/82 FP)
- SSH probe evidence fix — the snippet now correctly describes
  ssh-keygen verification (closes 2/2 FP)
- Unbounded-loop pytest whitelist — threshold 10 for test runners
  (closes 6/8 FP)

**New in `src/`:**

- `nlu/claim_detector.py`, `nlu/taint.py`, `nlu/filters.py`
- `cst.py` — Compact Sandbox Trace builder with JSON + Markdown renderers
- `EDR_BACKLOG.md` — items that require runtime telemetry and are deferred to v1.0

### v0.7 — Chaos detectors + dangerous advice *(done)*

Five new session-based detectors derived from deep analysis of 16
AiAIFail incidents plus 11 "Agents of Chaos" case studies. They cover
failure modes that config-only auditing cannot see.

**New detectors:**

- `behavior.unverified-completion-claim` — the agent claims it completed
  (committed/pushed/deployed/tests pass/migrated/fixed) without evidence in
  tool calls. 7 claim specs. The main lesson from the ASAMM integrity review,
  and the key quote from the Agents of Chaos abstract: "agents reported task
  completion while the underlying system state contradicted those reports".
- `behavior.cascading-destructive-chain` — 3+ destructive actions with
  tier escalation (T1→T4) in one autonomy window. From CS6 in Agents
  of Chaos (guilt-trip → progressive self-destruction).
- `resource.unbounded-loop` — the same tool + the same input 4+ times in one
  window (MEDIUM), 8+ times (HIGH). From CS4 (a 9-day relay on 60K tokens)
  and CS5 (silent DoS via unbounded attachments).
- `AI-06.indirect-prompt-injection-vector` — external fetch (WebFetch,
  curl, Read CLAUDE.md/AGENTS.md/MEMORY.md, etc.) → sensitive action
  without a user turn between them. From CS10 (constitution GIST injection).
- `advice.dangerous-recommendation` — 10 classes of dangerous advice in
  assistant text: run-as-root, disable-firewall, chmod-777, tls-bypass,
  git-force-push, skip-tests, delete-no-backup, hardcoded-secret,
  curl-pipe-sh, wildcard-iam. Negation-aware ("never do X" is not flagged).
  From the Meta SEV1 incident caused by the agent’s _advice_, not its actions.

**All 5 detectors** set `needs_llm_verification=True` —
recall over precision, with the LLM verifier filtering false positives.

### v0.6 — OSS imports: Aegis + AGT + LLM Guard *(done)*

Imports of ready-made signature bases from vetted open-source projects,
with proper attribution. No need to reinvent the wheel.

**Aegis import (MIT, antropos17/Aegis):**
- 107 agent profiles in `knowledge/aegis_agents.json`
- 180 known domains + 93 config paths + 260 process names
- 70 sensitive path rules across 8 categories

**AGT MCP patterns import (MIT, microsoft/agent-governance-toolkit):**
- 8 regex categories in `knowledge/agt_mcp_patterns.py`

**LLM Guard approach import (MIT, protectai/llm-guard):**
- Invisible unicode via stdlib `unicodedata`

**v0.6 detectors:**
- `MCP-08.poisoned-tool-description` — AGT patterns
- `AI-05.invisible-unicode` — LLM Guard approach
- `C2.credential-exfil-chain` — integrated with 70 Aegis rules
- Extended discovery — ~100 Aegis agents via `--extended`

### v0.8 — Canary tokens *(planned)*

From the OSS landscape analysis: Rebuff was the only OSS example with canary tokens
and has been archived since May 2025. The niche is empty.

- `agent-audit plant-canaries` — creates decoys in `~/.ssh/`, `~/.aws/`, `.env`
- Scan checks whether they were read in sessions
- Zero FP rate, deterministic signal

### v0.9 — HTML report + Mission interview *(planned)*

- HTML single-page printable output (as in the ASAMM samples)
- Interactive mission interview at the start of scan (5 questions)
- Severity recomputation from the owner’s answers

### v1.0 — EDR mode *(future)*

Shift from forensic to realtime: MCP proxy mode, a continuous daemon
watching `~/.claude/projects/`, active defense via auto-applied deny rules.

## OSS attribution

All external data is imported verbatim with explicit references:

| Source | License | Usage | Location |
|--------|---------|-------|----------|
| antropos17/Aegis | MIT | 107 agents + 70 path rules | `knowledge/aegis_*` |
| microsoft/agent-governance-toolkit | MIT | MCP poisoning regex | `knowledge/agt_mcp_patterns.py` |
| protectai/llm-guard | MIT | Unicode category approach | `detectors/secrets_in_config.py` |
| OWASP AST10 | CC-BY-SA 4.0 | Reference taxonomy in findings | `references=[]` |

When upstream updates, re-import it instead of doing manual merges.

## Detector inventory (v0.7.5)

| ID | Severity | Source | Added |
|----|----------|--------|-------|
| C2.credential-exfil-chain | CRITICAL/HIGH/MEDIUM/LOW | session | v0.1, Aegis integration v0.6 |
| C2.private-key-exfil | CRITICAL | session | v0.2 |
| credential.context-bleed | HIGH/CRITICAL | session | v0.7.3 — wrong-project creds |
| C3.autonomy-window-context | INFO | session | v0.7.2 — CST carrier |
| C3.autonomy-with-sensitive-sink | MEDIUM | session | v0.7.2 — composite |
| C3.autonomy-with-exfil-chain | HIGH/CRITICAL | session | v0.7.2 — causality-aware |
| C3.autonomy-with-persistence | HIGH | session | v0.7.2 — composite |
| behavior.user-interruptions | HIGH/MEDIUM | session | v0.1 |
| behavior.unverified-completion-claim | HIGH/MEDIUM/LOW | session | v0.7, NLU v0.7.2, i18n v0.7.3, tightened v0.7.4 |
| behavior.cascading-destructive-chain | CRITICAL | session | v0.7 (CS6), Tier 0 v0.7.3 |
| behavior.confirmation-bypass | HIGH/CRITICAL | session | v0.7.3 — --force/--yes |
| behavior.hypothetical-executed | CRITICAL | session | v0.7.3 — issue #28699, imperative fix v0.7.4 |
| resource.unbounded-loop | HIGH/MEDIUM | session | v0.7, pytest whitelist v0.7.2 |
| resource.api-storm | MEDIUM/HIGH/CRITICAL | session | v0.7.3 — endpoint pounding |
| advice.dangerous-recommendation | CRITICAL/HIGH/MEDIUM | session | v0.7 (Meta SEV1), wrapper-bypass v0.7.3 |
| AI-04.persistence-write | HIGH | session | v0.2, agent hooks v0.7.5 |
| AI-04.mcp-config-mutation | CRITICAL/HIGH | session | v0.7.3 — OX research / CVE-2026-30615, narrowed v0.7.4 |
| **AI-05.poisoned-project-config** | **CRITICAL/HIGH/MEDIUM** | session | **v0.7.5 — Check Point CVE-2025-59536** |
| **AI-05.agent-version-vulnerable** | **CRITICAL/HIGH per CVE** | config | **v0.7.5 — version audit** |
| AD-02.out-of-cwd-write | HIGH | session | v0.2 |
| AI-06.indirect-prompt-injection-vector | HIGH | session | v0.7, localhost fix v0.7.2 |
| AG-04.destructive-without-backup | CRITICAL/HIGH | session | v0.4, ephemeral v0.7.2, Win/mac v0.7.3, multi-stage v0.7.4 |
| AV-01.test-touches-prod | HIGH | session | v0.4 |
| AG-02.unversioned-mcp | MEDIUM | config | v0.5 |
| AI-05.secrets-in-agent-config | CRITICAL/HIGH | config | v0.5 |
| AI-05.invisible-unicode | HIGH | config | v0.6 (LLM Guard) |
| MCP-08.poisoned-tool-description | CRITICAL/HIGH | config | v0.6 (AGT) |
| MCP-08.poisoned-tool-description.schema | HIGH | config | v0.6 (AGT) |
| config.claude-code.permissive.* | CRITICAL/HIGH | config | v0.1/v0.5 |
| config.codex.permissive.* | HIGH | config | v0.1 |
| probe.ssh-key-unencrypted | HIGH | env probe | v0.5, evidence fix v0.7.2 |
| AD-03.adjacent-repo-reach | CRITICAL/HIGH | env probe (full) | v0.5 |

**Total: 27 rule IDs** across session/config/env-probe surfaces.

The AI-05 (Supply Chain) cluster now has 4 distinct rules covering
different sub-surfaces: `secrets-in-agent-config`, `invisible-unicode`,
`poisoned-project-config`, `agent-version-vulnerable`.

### v0.8 — Ensemble verification *(planned)*

When 2+ working verifiers are available, critical findings are checked
by both. Disagreement = human review.

- Applicable only to critical/high findings (doubles cost)
- Most useful for private-key-exfil, destructive-without-backup, cascading-destructive-chain
- Inter-model agreement as a metric

## Matrix verifier backends

| Backend | Notes |
|---------|-------|
| claude -p (CLI) | Parses 403/401/429 from JSON body |
| codex exec (CLI) | npm i -g @openai/codex |
| Anthropic API | Direct HTTP via ANTHROPIC_API_KEY |
| OpenAI API | OPENAI_API_KEY |
| OpenRouter | OPENROUTER_API_KEY, works in RU |
| Ollama (local) | OLLAMA_MODEL=llama3.3 |
| Custom OpenAI-compat | LM Studio, vLLM, llama.cpp |

## Backlog (unversioned ideas)

### AST Precision Plan

A detailed plan for introducing markdown AST / tree-sitter / Rego lives
separately here: [docs/ast-precision-plan.md](docs/ast-precision-plan.md).

In short:
- **v0.12** — markdown-it-py prefilter for native detectors (measurable,
  reversible, local)
- **v0.13** — tree-sitter for fenced shell (conditional on v0.12)
- **v0.14** — feature extraction cache (refactor bridge)
- **v1.0** — Rego for maturity rollup (not for detection)

### ASAMM maturity rollup

Findings currently carry primary + secondary ASAMM controls in `references`,
but the final L1/L2/L3 assessment is not computed yet. This should be a
**post-scan correlation** step — a separate module that takes a findings stream
and the ASAMM control catalog, and produces `{control_id: maturity_level}` plus a projected
trust grade (A-F × 1-6).

Open design questions before implementation:

- where should the machine-readable ASAMM v0.3 control catalog live (YAML/JSON)?
- what threshold should apply: "how many HIGH on control X = downgrade maturity"?
- positive-evidence detection for L2+ (presence of tests/logs/docs, not only
  absence of findings)
- how should session findings + project findings + config findings
  combine into one rollup

Estimated effort: 3-5 days after collection-scale and subtree mode
close the remaining data-quality gaps. Preferred engine: **OPA/Rego**
(see AST Precision Plan D-4).

## Principles

1. Transparency over magic — no silent fallbacks
2. Consent for expanded scope — explicit agreement with precise wording
3. Recall over precision in aggressive mode — the LLM verifier handles cleanup
4. Never auto-apply — we are a forensic tool, not active defense
5. Zero-dependency backends — urllib only
6. Integrity review over a single pass — structural control
7. OSS over inventing — proven MIT signature packs beat homegrown ones
