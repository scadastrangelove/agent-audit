<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# Historical Changelog

This file preserves the detailed research-phase release notes that originally
lived in `README.md`.

## v0.14.4 changelog — D-9 agent-task YAML surface adapter + high-density pattern audit

Two changes in this release: one closes a real blind spot (agent-task
YAML configs), one documents what's still open based on empirical data
from the lexicon-audit tool shipped in v0.14.3.

**D-9 implemented**: multi-agent framework task configs — YAML files
like `agentverse/tasks/**/*.yaml` that embed system prompts and agent
descriptions as YAML fields — now recognised as an instruction surface.

Implementation in `knowledge/agent_task_adapter.py`:
- `is_agent_task_config(path, text)` — conservative signature check
  requires `prompts` or `agents` top-level field PLUS a confirming field
  (`task_description`, `environment`, `tools`, `max_rounds`, etc., OR
  agent-internal prompt subfields like `prompt`, `role_description`,
  `system_message`). Rejects docker-compose, GitHub Actions workflows,
  CrewAI with no prompt subfields, generic `agents: [alice, bob]` lists.
- `extract_instruction_text(path, text)` — pulls prompt-like string
  fields (prompts, role descriptions, backstories, goals, tool
  descriptions, task_description, environment) and concatenates them as
  pseudo-prose for native detectors.

`project_scanner.py` adds surface `agent_task_config`, routes only YAML
files under `/tasks/`, `/agents/`, `/prompts/`, `/personas/`,
`/workflows/` through the signature check (fast-reject elsewhere).

Native detectors (`no_approval_model`, `identity_redefinition`) gained
`bypass_applies_to=True` kwarg for D-9 invocation — the extracted prompt
text passes the detector without the YAML filename tripping the
file-name gate.

**End-to-end validation on OpenBMB/AgentVerse (232 task yaml files)**:
- Before v0.14.4: 0 findings (surface never classified)
- After v0.14.4: 48 findings (all rule-pack, all at low severity after
  overrides and educational suppressor). 0 native findings —
  AgentVerse prompts describe virtual-world simulation (`act()`,
  `say()`, `do_nothing()`), not external capability surfaces.
  This is a correct null-result — the simulation doesn't carry broad-
  action-without-approval patterns.

**7-target calibration unchanged** (v0.14.3 → v0.14.4):

| Target | v14.3 nat | v14.4 nat |
|---|---:|---:|
| hermes | 4 | 4 |
| composio | 1 | 1 |
| codex | 1 | 1 |
| danielm | 6 | 6 |
| ruflo | 3 | 3 |
| python-sdk (FP ctrl) | 0 | 0 |
| secondsky | 3 | 3 |

**10 new unit tests** in `tests/test_agent_task_adapter.py` covering
positive shapes (AgentVerse, AutoGen, CrewAI) and negative controls
(docker-compose, GHA workflow, generic YAML, non-yaml extension,
malformed YAML).

**High-density pattern audit findings** (not changed in this release,
documented for future work in `ROADMAP.md`):

Ran lexicon-audit on 2565-file test corpus. Four patterns investigated:

- `\breuse session` (735 matches) — 732/735 are boilerplate duplication
  across 732 skill files. Not a regex problem; aggregator behaviour to
  verify in follow-up.
- `\bjailbreak\b` (91 matches) — 15 files: 3 red-team TPs + 10
  defensive security research skills (PromptInjection analyzers) + 2
  other. Real edge case: descriptive vs prescriptive intent.
  Followup: intent-based suppressor (see ROADMAP).
- `\bcommit\b`, `\bpush\b` in WRITE_ACTION — confirmed routing correct.
  97/161 commit matches in prose-only context are behavioural TPs
  ("NEVER commit secrets"); 105 code-only in git-command examples
  correctly filtered by existing AST prefilter. No change needed.
- `--watch\b` (36 matches) — all 36 in code blocks, 0 in prose. True
  recall blind spot. Requires D-2 partial (prose-around-code context
  discrimination, see ROADMAP).

**New architecture doc**: `docs/architecture.md` — describes every stage
of the scan-project pipeline for a fresh engineer or agent picking up
the project.

## v0.14.3 changelog — MCP Pattern 2 switched to vendor allowlist + lexicon-audit tool

Follow-up to v0.14.2 after running the new **lexicon-audit tool** on a
2565-file test corpus. Discovery: Pattern 2 (`\b[A-Z][a-z]+\s+MCP\b` — "capitalized word before MCP") fired **5029 times on 969 files** (density 5.2/file).

**Root cause**: Pattern 2 matched any capitalized word before "MCP", not just
product names. Inflated `remote_action_surface_total` counter on sentence-
starters like "Use MCP", "The MCP", "Install MCP", "Based MCP", "Complete MCP".

**Analysis of 4968 matches** showed distribution:
- 4639 "Rube MCP" (93%) — real (Composio's product)
- 64 "Composio MCP" — real
- 54 "Bright Data MCP" — real
- 30 "Code Mode MCP" — real
- long tail of known vendors (Exa, Apify, Playwright, Cloudflare, Flow Nexus,
  Claude Flow, Linear, Blender, Smithery, Zapier — all real)
- ~50 FPs: sentence-starters and adjectives ("Based", "Complete", "Primary",
  "Current", "Implement", "Initialize", "Full", "Core", etc.)

**Fix**: Pattern 2 switched from unbounded regex to a closed-set vendor
allowlist derived from the audit data:
```python
r"\b(?:Rube|Composio|Bright Data|Apify|Smithery|Zapier|Exa|Playwright|"
r"Cloudflare|Linear|Blender|Flow Nexus|Claude Flow|Code Mode)\s+MCP\b"
```

Adding new vendors as they appear empirically — this is data-driven scope,
not speculative coverage.

**Impact on 7-target calibration suite (v0.14.2 → v0.14.3):**
- hermes, composio, codex, danielm, python-sdk, secondsky: **native count unchanged**
- ruvnet/ruflo: 7 → 3 native. Investigation confirmed all 4 losses were
  v0.14.2 inflation FPs — sparc-methodology/SKILL.md had 2 real Pattern 1
  matches ("MCP Tools"), but Pattern 2 had been artificially adding
  sentence-starters like "Use MCP" and "Install MCP" to push the count
  over the `ras_total >= 3` threshold. v0.14.3 correctly leaves these
  files silent on broad-action because 2 MCP tool mentions + 0 write/extrep
  signals doesn't describe broad external-action behaviour.

**New in v0.14.3**: `tools/lexicon_audit.py` — CLI tool for corpus-wide
pattern telemetry. Run it before/after any lexicon change to catch
inflation FPs. Usage:
```
python -m agent_audit.tools.lexicon_audit PATH_TO_CORPUS -o report.md
```

Reports match counts per pattern, density (matches/files), and example
contexts for the top 10 densest patterns.

**Tests**: `tests/test_native_regression_fixtures.py` updated —
`test_sentence_starter_mcp_does_not_fire` now tests the allowlist
(non-vendor words including "Based", "Complete", etc. must not fire),
`test_real_product_names_still_fire_pattern_2` tests all 14 allowlisted
vendors (10 tests total in this file).

**Methodological lesson**: Pattern 2 was written from first principles
without corpus empirical data. Lexicon audit now exists and should be
run before/after every lexicon change.

## v0.14.2 changelog — MCP regex product-name pattern (post-grand-run v0.14.1)

Follow-up to v0.14.1 after grand-run #2 on 500 repos showed a real recall
regression on product-name MCP references. The v0.14.1 tightening
(`\bMCP\s+(?:server|tool|...)s?\b`) excluded path-component FPs correctly
but **also excluded** legitimate capability declarations using the product-
name form: "Bright Data MCP", "Apify MCP", "Smithery MCP".

Per-target investigation on the v0.14.1 regression targets:
- danielmiessler/Personal_AI_Infrastructure: 6 → 1 native, all losses on
  BrightData/Cloudflare SKILL.md files declaring `Bright Data MCP service`
- ruvnet/ruflo: 5 → 1 native, lost on SPARC methodology files declaring
  MCP Tools as activation method
- jeremylongshore/claude-code-plugins-plus-skills: 9 → 3, similar pattern
- ComposioHQ/awesome-claude-skills: 5 → 2, same pattern

Fix: two-pattern regex in `REMOTE_ACTION_SURFACE`:

```python
# Pattern 1: MCP followed by capability noun (case-insensitive)
re.compile(r"\bMCP\s+(?:server|tool|client|endpoint|...)s?\b", re.IGNORECASE)

# Pattern 2: Capitalized product/vendor name before MCP (case-sensitive on MCP)
re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+MCP\b")
```

Pattern 2 requires a real product-name word before MCP — so bare "mcp" in
paths/imports still never fires. Case-sensitive `MCP` in Pattern 2
reinforces the discipline (`src/mcp/` doesn't match).

**Recovery on 8-target suite (v0.14.1 → v0.14.2):**

| Target | v14.1 nat | v14.2 nat | Verdict |
|---|---:|---:|---|
| danielmiessler/Personal_AI_Infrastructure | 1 | 6 | **fully recovered** |
| ruvnet/ruflo | 1 | 7 | fully recovered + aggregation-correct |
| jeremylongshore | 3 | TBD | pending regrand-run |
| python-sdk | 0 | 0 | FP cleanup preserved |
| n8n-io/n8n | 0 | 0 | FP cleanup preserved |
| aaif-goose/goose | 0 | 0 | FP cleanup preserved |
| composio/connect-apps | 1 | 1 | stable TP |
| hermes godmode | 1 | 1 | stable CRITICAL |

Net: 3 path-component FP classes stay suppressed, 4 product-name TP
classes recovered. Pattern 2 provides the missing coverage without
re-opening the Pattern 1 FP hole.

New test `test_product_name_mcp_declarations_fire` in
`tests/test_native_regression_fixtures.py` (now 8 tests total) pins this
TP class against any future regex tightening.

## v0.14.1 changelog — MCP regex FP cleanup (post-grand-run)

Follow-up to v0.14.0 after the grand-run on 500 repos flagged a
"native recall regression" on 5 overlap repos (v0.11→v0.14: 34→30 native
findings). Per-target investigation showed **all 5 losses were FP cleanup,
not real recall loss**.

Root cause: the regex `\bMCP server\b|\bMCP\b` in
`capability_lexicon.REMOTE_ACTION_SURFACE` matched bare `mcp` tokens
anywhere — including path components like `src/mcp/`, `packages/@n8n/mcp`,
`crates/goose-mcp/`. Three of the five "regressed" repos (python-sdk, n8n,
goose) had v0.11 native findings that were produced entirely by 6+ path
matches of this kind — zero actual capability declarations.

Fix: tighten the regex to `\bMCP\s+(?:server|servers|tool|tools|client|clients|endpoint|integration|protocol|session|resource)s?\b` — only "MCP" followed by a capability noun counts.

Impact:
- python-sdk, n8n, goose: all transition from HIGH native FP to clean.
  Correct behaviour.
- composio, hermes, codex, anthropic reference skills: all TPs preserved.
- microsoft/vscode, secondsky/claude-skills: one FP removed each, remaining
  native findings stable.

New tests in `tests/test_native_regression_fixtures.py` (7 cases):
inline text fixtures extracted from the three regression repos, plus
positive-control fixtures for composio/hermes godmode/clean docx.
These are now pinned against any future regex loosening.

## v0.14.0 changelog — Grand-run P0 sprint: noise reduction + native reranking

Sprint driven by the 100-repo grand-run evaluation. Three ordered fixes,
measured after each step.

**P0 C — Adaptive cohort thresholds** (`collection_scale.py`). Lowered
`COHORT_MIN_SIZE` from 10 to 5, `COHORT_MIN_HITS` from 5 to 3,
tightened `COHORT_MIN_RATIO` from 10% to 20%. Rationale: grand-run showed
small curated skill-bundle repos (7-15 SKILL.md) produced template
replication that the original thresholds missed. Now secondsky/claude-
skills (27-dir cohort), hermes optional-skills (25-dir), and affaan-m
collections aggregate properly.

**P0 A — Rule-surface routing** (`knowledge/rule_surface_classifier.py`).
For markdown files, rules are routed by category:
- `code`: shell/privilege-escalation/external-download/secrets/PII rules
  match only inside code fences (using AST features from v0.12)
- `prose`: prompt-injection/agent-manipulation/excessive-autonomy rules
  match only in prose
- `both`: fallback for unknown categories

Non-markdown files (json/yaml manifests) use raw text for all rules.
Closes D-2 of the AST Precision Plan partially — tree-sitter-bash not
needed for this class of FP.

**P0 B — Native-centric reranking** (`report_rerank.py`). In markdown
and JSON reports:
- Native findings get a top-of-report section (before any severity groups)
- "Hot files" summary lists paths that carry at least one native finding
- Within each severity group, findings in hot files are promoted first
- JSON adds `native_summary` top-level block with rule counts + per-file
  finding lists

**Cumulative impact (v11 baseline → v14) on 10-target suite at `--min-severity medium`:**

| Target | v11 m+ | v13 m+ | v14 m+ | total delta |
|---|---:|---:|---:|---|
| hermes-agent | 346 | 206 | 96 | **-72%** |
| jaktestowac | 20 | 14 | 5 | -75% |
| anthropic/skills | 22 | 16 | 9 | -59% |
| codex/.codex/skills | 7 | 4 | 2 | -71% |
| composio/connect-apps | 1 | 1 | 1 | **TP preserved** |
| microsoft-beg | 74 | 7 | 4 | **-95%** |
| secondsky/claude-skills | 554 | 299 | 80 | **-86%** |
| affaan-m/everything | 278 | 228 | 110 | -60% |
| **Total** | **1303** | **775** | **307** | **-76%** |

All 16 native TP across the suite preserved. Zero TN regression.
16 hot files surfaced for triage.

**Unit tests added/updated in this release:**
- `tests/test_report_rerank.py` — 9 tests
- `tests/test_rule_surface_classifier.py` — 6 tests
- `tests/test_collection_scale.py` — threshold updates, +1 test (13 total)

Pre-existing failures in `test_credential_context_bleed.py` and
`test_mcp_config_mutation.py` are unrelated to this sprint — they
exercise session-level detectors not touched here.

## v0.13.0 changelog — Grand-run precision tuning

Driven by the 100-repo grand-run evaluation (2026-04-21): 3721 findings
total, only 45 native (1.21%). The native layer was buried in imported-
pack noise. This release targets that signal/noise ratio with two
orthogonal mechanisms plus a deferred architectural item.

**Rule-pack severity overrides** — new `knowledge/rule_pack_overrides.yaml`
lets us demote the three most dominant noise sources without editing
upstream rule files:
- `aguara.external-download.runtime-url-controls-agent-behavior`
  (TOP-1 in 45/91 repos in grand-run) → low
- `aguara.external-download.binary-download-and-execute`
  (56/74 findings on generative-ai-for-beginners) → low
- `atr.agent-manipulation.human-approval-fatigue-exploitation`
  (338 findings across 57 targets, prose-tone matcher) → low

**Educational-context suppressor** — new
`knowledge/educational_suppressor.py` demotes rule-pack findings by one
severity level when the file lives under `/translations/`, `/i18n/`,
`/locales/`, `/docs/<lang>/`, `/tutorials/`, `/lessons/`, `/labs/`, or
`*-for-beginners/`. Structural skill markers (SKILL.md frontmatter, MCP
manifest, plugin descriptor) override the suppression — a real localised
skill is still reported at full severity.

**Impact at `--min-severity medium` (developer default) on 10-target suite:**

| Target | v12b medium+ | v13 medium+ | delta |
|---|---:|---:|---|
| microsoft/generative-ai-for-beginners | 74 | 7 | **-91%** |
| secondsky/claude-skills | 554 | 299 | **-46%** |
| codex/.codex/skills | 7 | 4 | -43% |
| hermes-agent | 346 | 206 | -40% |
| jaktestowac | 20 | 14 | -30% |
| anthropic/skills | 22 | 16 | -27% |
| affaan-m/everything-claude-code | 278 | 228 | -18% |
| huggingface/smolagents | 1 | 0 | -100% |
| composio/connect-apps | 1 | 1 | **0 (TP preserved)** |
| **Total** | **1303** | **775** | **-41%** |

All native TP/TN preserved: hermes godmode CRITICAL, codex babysit-pr,
composio broad-action, affaan-m/secondsky native counts unchanged.

**Deferred: D-9 surface-adapter gap** — grand-run revealed
`OpenBMB/AgentVerse` has 232 agent-task `.yaml` configs under
`/agentverse/tasks/**/*.yaml` that instruction_inventory recognises but
project_scanner's file classifier misses. Fix is structural (new
surface adapter, not a new rule) and deferred to a future release.
See [docs/ast-precision-plan.md](docs/ast-precision-plan.md) D-9.

12 unit tests in `tests/test_educational_suppressor.py`.

## v0.12.0 changelog — AST-aware native detectors (step D-1 of the AST Precision Plan)

Native detectors (`identity_redefinition`, `no_approval_model`) now consume
markdown AST-derived features instead of raw file text. Code fences are
separated from prose; detector classification runs on prose, while
persistence-marker checks (filename references like `prefill.json`,
`system_prompt`) still use raw text where appropriate.

GFM tables are enabled in the parser because skill specs frequently use
tables to enumerate capabilities ("| Ask Claude to... | What happens |"),
and that content must reach detectors as prose.

Regression on 5-target suite (v0.11.1 → v0.12.0):

- composio/connect-apps (known TP): preserved
- codex/babysit-pr (known TP): preserved
- hermes godmode (known TP): preserved
- jaktestowac (negative control): 0 native findings, unchanged
- anthropic/skills (reference): 0 native findings, unchanged
- hermes: 1 legitimate swap — github-pr-workflow downgraded (autonomy
  marker was inside a code block, not behavioural), research-paper-writing
  upgraded (approval markers were in code, autonomy dominates prose)

Rule-pack findings (296 rules) are unchanged — AST prefilter applies only
to native detectors, per plan D-1. Rule packs continue on raw text.

Graceful fallback: when markdown-it-py is unavailable or parsing fails,
detectors revert to raw text behaviour. No hard dependency cascade.

10 unit tests in `tests/test_markdown_features.py`.

## v0.11.0 changelog — Collection-scale aggregation

Post-scan phase collapses high-replication `(rule_id, cohort)` pairs into
single aggregate findings. A "cohort" is a directory with ≥10 sibling
SKILL.md files; when ≥5 findings and ≥10% of cohort match the same rule,
they collapse into one architectural finding tagged `#collection-scale`.

Calibration on composio-skills (832 SKILL.md files):

- before: 922 raw findings, 817 of them identical (`aguara.external-download.runtime-url-controls-agent-behavior`)
- after: 106 findings — 1 aggregate (98% replication), 105 individuals

The aggregate carries `cohort-size`, `replication-ratio`, and
`aggregated-finding-count` in references. Severity is preserved (max of
group); confidence is bumped to HIGH because replication IS the evidence.

Disable with `--no-aggregate` for debugging.

11 unit tests in `tests/test_collection_scale.py`.

## v0.10.x changelog — Rule packs + project scan

- **296 bundled rules** from three Apache-2.0 / MIT sources:
  233 ATR (Agent Threat Rules), 37 Aguara (SSRF-cloud, third-party-content,
  external-download), 26 Cisco PromptGuard (PII, extended secrets, markdown
  exfil). See `THIRD_PARTY_LICENSES.md`.
- **`scan-project PATH`** — new command. Walks a repo or directory of repos,
  classifies files by surface (instruction_file / mcp_manifest / skill_md /
  tool_description), applies matching rules. Independent from the existing
  `scan` (agent-home / sessions), which is unchanged.
- **Field-aware ATR filtering** — ATR conditions targeting session-event
  fields (`tool_name`, `user_input`, `tool_args`) are skipped during project
  scan; they're designed for live trace data, not flat file text.
  Reduces FP by ~62% on doc-heavy repos.
- **Two native detectors** (not from rule packs):
  - `asamm.AI-04.persistent-identity-rewrite` — identity redefinition
    language paired with persistent write path. Derived from v5 corpus
    audit; calibrated on NousResearch/hermes-agent godmode skill.
  - `asamm.AD-02.broad-action-without-approval` and
    `asamm.AD-02.autonomous-loop-with-writes` — absence-based detectors
    for tool-surface controls. Fires on composio connect-apps and
    codex/babysit-pr while staying clean on 10 anthropic reference skills.
- **`packs` command** — shows rule counts by tool / category / severity.
  `--all` includes session-event rules.

## v0.9.0 changelog — Codex taint engine fix (completes v0.8.2)

Real-data analysis on v0.8.2 output revealed 10 rules were still
Codex-blind despite v0.8.2's detector-level canonical_tool patches.
Root cause: `nlu/taint.py::_classify_event()` — the taint classifier
that feeds most advanced detectors (C2/C3/AI-04/AI-06/AD-02/advice) —
still checked `tool_name.lower()` against hardcoded lists. Every
Codex tool event returned an empty `EventClassification()`, so
downstream detectors saw zero taint sources and zero taint sinks
and thus couldn't fire.

**Taint engine canonical_tool layer.** The classifier now has 4
branches (read/web/write/bash) that accept either native tool_name
OR canonical_tool. Before:
```python
if tool_name in ("bash", "shell"):  # Codex exec_command silently skipped
```
After:
```python
is_bash = tool_name in ("bash", "shell") or canonical == "Bash"
if is_bash:
```

**Secondary patches.** v0.9.0 grep audit revealed 3 additional
hardcoded checks that v0.8.2 missed:
  - `credential_context_bleed.py:159` — second bash check in same file
  - `chaos_behaviors.py:114` — test-runner threshold raise (Codex pytest)
  - `chaos_behaviors.py` AI-06 helpers (`_is_external_fetch`,
    `_is_sensitive_action_after_fetch`) — both internal helpers had
    their own tool_name checks independent of the main taint classifier

**Validation — 10/10 Codex-blind rules now fire on synthetic E2E test:**
- C3.autonomy-with-exfil-chain ✓
- C3.autonomy-with-persistence ✓
- C3.autonomy-with-sensitive-sink ✓
- C2.credential-exfil-chain ✓
- C2.private-key-exfil ✓
- AI-04.persistence-write ✓
- AI-04.mcp-config-mutation ✓
- AI-06.indirect-prompt-injection-vector ✓
- AD-02.out-of-cwd-write ✓
- advice.dangerous-recommendation ✓

All pass on synthetic Codex events through `exec_command`/`apply_patch`/
`web_fetch`/`read_file`. Claude Code parity preserved.

**Expected production impact** based on v0.8.2 baseline (reports-v082):
Codex structural findings: ~10 → ~30-40 (extrapolated from Claude
Code per-tool-call detection density and Codex tool call volume).
10 Codex-blind rules → 0.

## v0.8.2 changelog — Codex tool normalization

Real-data gap: v0.7.8 run on 87 Codex sessions found zero findings
from `C2.credential-exfil-chain`, `C3.autonomy-with-exfil-chain`,
`AG-04.destructive-without-backup`, `AI-04.persistence-write`, or
`AD-02.out-of-cwd-write` — all of which fire heavily on Claude Code.
Root cause: those detectors check `tool_name.lower() in ("bash",
"shell")` or `tool_name in WRITE_TOOLS`, and Codex uses `exec_command`
/ `write_stdin` / `apply_patch` / `read_file`. Silent miss, not a
true absence of risk.

**Canonical tool name layer.** Each `Event` now has a `canonical_tool`
field populated at parse time via `tool_normalization.canonical_for()`:

```
Codex exec_command  → Bash
Codex write_stdin   → BashStdin
Codex apply_patch   → Patch
Codex read_file     → Read
Claude Bash         → Bash
Claude Write/Edit   → Write/Edit
```

Detectors fall back to canonical when native name doesn't match the
expected set. Native `tool_name` is preserved for reports and for
detectors that need exact semantics (e.g. Codex-specific polling in
`resource.unbounded-loop`).

**Detectors patched for cross-agent coverage (10):**
`destructive_without_backup`, `credential_exfil_chain`,
`credential_context_bleed`, `persistence_write`, `out_of_cwd_write`,
`confirmation_bypass`, `hypothetical_executed`, `mcp_config_mutation`,
`private_key_exfil`, `api_storm`, `unverified_completion`.

**Detectors that didn't need patching:**
- `autonomy_window` — counts by `EventType.TOOL_USE`, already cross-
  agent
- `chaos_behaviors` — uses `tool_name` only for logging/display

**Validation — 4/4 Codex smoke tests pass:**
- `exec_command rm -rf` → destructive-without-backup fires
- `apply_patch` to `~/.bashrc` → persistence-write fires
- `exec_command cat ~/.ssh/id_rsa` + curl exfil → credential-exfil-chain fires
- `apply_patch` outside cwd → out-of-cwd-write fires

Claude Code parity preserved on all tests.

## v0.8.1 changelog — Project-type awareness

Zhet/build was triggering 12 CRITICAL `C3.autonomy-with-exfil-chain`
findings on every run — all legitimate DAST workflow (hitting
testinvicti.com, juice-shop, checkxss.skipa.cyberok.ru). The detectors
were working correctly; the semantics of "Zhet scanning its targets"
are structurally identical to "agent exfiltrating to attacker."

**`.agent-audit.yaml` project config.** User declares project intent
once and detector behavior adapts. Example:

```yaml
tags: [dast, zhet]
trusted_targets:
  - testinvicti.com
  - juice-shop
  - checkxss.skipa.cyberok.ru
severity_overrides:
  C3.autonomy-with-exfil-chain: info
  AG-04.destructive-without-backup: low
suppress_rules:
  - AI-06.indirect-prompt-injection-vector
allowlist_writes:
  - /tmp/zhet_*
  - ~/.claude/projects/*/memory/
```

**Auto-detection from project docs.** If no yaml present, scans
`CLAUDE.md`/`AGENTS.md`/`README.md` for tag keywords:
- "DAST", "EASM", "vulnerability scanner", "pentest framework" → `dast`
- "pentest framework", "red team toolkit" → `pentest-framework`
- "malware analysis", "reverse engineering" → `security-research`
- "red team", "offensive security" → `red-team`

Each tag carries default severity downgrades for the rules it
commonly misfires on. Explicit yaml values override auto-detected.

**Integration.** Scanner calls `_apply_project_config(findings,
session.cwd)` after rules run. Severity overrides applied in-place;
`suppress_rules` drops findings entirely. Walks up from cwd (6 levels)
to find project root.

No rule IDs added or removed — still 27 total across all releases.
Detection logic unchanged; only severity classification and
suppression are affected by project config.

## v0.8.0 changelog — Session aggregation + real-data calibration from codex-cli verify

### Session aggregation (first of three v0.8 UX shifts)

Flat list of findings breaks at scale. Real data: 871 findings / 143
sessions / 95% of findings in 10 of those sessions. The previous
`audit.md` made the user scroll through 35,000 lines to find 5
sessions worth triaging.

**Session-first MD report.** Three-layer aggregation:

1. **Sessions of concern** — top-level cards, one per session with 3+
   findings, sorted by severity × volume. Each card shows session ID,
   agent, cwd, severity rollup, and a list of rule clusters.

2. **Rule clusters** — within each card, findings grouped by rule_id.
   Clusters show total count + severity distribution + up to 5
   representative patterns.

3. **Pattern groups** — within each rule cluster, findings grouped by
   evidence shape (hash-normalized: /tmp/X, sprint numbers, PIDs, UUIDs
   collapsed). Reads as "3 examples + 266 similar" instead of listing
   all 269 individually.

**Quiet sessions section** — sessions with 1-2 findings show as a
single-line rollup each.

**Config & environment findings** — orphan findings (no session_id)
get their own section.

**Full flat list appendix** — the old report inlined behind `<details>`
for search/grep. JSON report is 100% unchanged — this is a reporting-
layer improvement only.

**Measured impact on Sergey's real 871-finding report:**
```
flat view:        1.69 MB, 35,935 lines
aggregated view:    91 KB,  1,778 lines (top section)
                 + 1.69 MB in collapsible appendix
```
**5% of the size at the top.** Critical TPs visible at first scroll.

Legacy flat rendering still available via `render_markdown(result,
aggregated=False)`.

### Real-data calibration from codex-cli verify (875 findings, 325 verified)

A claude-cli verify + integrity review on a 875-finding production
scan (Apr 2026) produced ground-truth verdicts: 18 TP, 279 FP, 28
uncertain. Aggregate FP rate 86%. Three specific calibration fixes
were made based on this data:

**1. Claim detector "substantial tool activity" gate.** 203 of 224
(91%) `behavior.unverified-completion-claim` findings were FP because
the agent's claim ("shipped", "tests passed") was backed by multiple
Bash/Edit/Write calls in the same window — the detector's category-
specific evidence regexes just didn't match. LLM verifier rationales
consistently: "multiple tool calls confirm the claim". Fix:
  - ≥ 5 prior tool calls in window → skip claim finding entirely
  - ≥ 2 prior tool calls → downgrade 2 severity levels
  - < 2 prior tool calls → full severity (real fabrication risk)

Projected impact on verified subset: **128 of 203 FPs eliminated, 0
TPs false-suppressed.** All 6 verified TPs had zero prior tool calls
(the gate's correct signal for fabrication).

**2. `AI-05.poisoned-project-config` FP on documentation URLs.** Two
findings triggered on `CLAUDE.md` / `AGENTS.md` because `example.com`
and `http://target.testinvicti.com` (a DAST target mentioned in docs)
appeared inside fenced code blocks as example commands. Fix:
  - Exclude IANA-reserved docs TLDs (`example.com/.org/.net`) from
    `_EXFIL_URL`
  - For markdown files, strip fenced code blocks (```...```) and
    inline code (`...`) before URL matching — code in docs is
    illustrative, not attack surface

**3. `render_json` was dropping `cwd` / `git_branch` / `parent_session_id`
/ `is_subagent` from serialized session output.** Parser in v0.7.7
extracts `cwd` correctly from Codex `session_meta.payload.cwd`, but
the report layer only wrote 6 of the 10 Session fields. Downstream
tools (and v0.8.0's session cards) couldn't see cwd. Fix: explicit
field list in `render_json` now includes all session metadata.

No rule IDs added or removed — still 27 total.

## v0.7.7 changelog — Sonnet default + Codex-class fixes from real-data analysis

From analyzing Sergey's 871-finding report (143 sessions, 33 of them Codex)
three Codex-specific failure modes emerged, plus one performance win.

**Sonnet as default for Claude CLI verifier.** The `ClaudeCodeBackend`
now passes `--model sonnet` to Claude CLI by default (previously no
explicit model meant Claude picked automatically — often Opus).
Sonnet is ~2x faster and ~3x cheaper than Opus for verifier prompts,
and verify workloads don't need Opus-level reasoning. Override via
new `--claude-model` CLI flag:
```
agent-audit verify --verifier claude-cli --claude-model opus  # old behavior
agent-audit verify --verifier claude-cli --claude-model haiku # fastest
```

**Fix — `resource.unbounded-loop` false positives on Codex polling.**
Codex holds long-running tmux sessions and polls stdout by calling
`write_stdin(chars="", yield_time_ms=N)` repeatedly. Our loop detector
correctly hashed these as "11× identical calls" but missed the
semantic nuance: empty `chars` is a READ, not a repeated action.
Fix: whitelist `write_stdin` with empty or null `chars` from loop
detection. Eliminates 3 of 6 Codex unbounded-loop FPs.

**Fix — `advice.dangerous-recommendation` firing on our own verifier
output.** When a session's assistant turn was itself the JSON output
from a previous `agent-audit verify` run, our detector read the
verifier's rationales (like "It recommends curl -k against remote")
as agent advice. Redirect loop. Fix: skip detection if the text
starts with a JSON array AND contains verifier-vocabulary keys
(`"verdict"`, `"rationale"`, `"adjusted_severity"`). Eliminates
~3 of 5 Codex advice FPs.

**Fix — Codex parser now extracts `cwd`.** All 33 Codex sessions in
the real-data run had `cwd=None`, which silently disabled
`AI-05.poisoned-project-config` (the Check Point CVE class detector
from v0.7.5) on Codex entirely. v0.7.7 correctly extracts cwd from
the real Codex schema:
  - `type=session_meta`, `payload.cwd` (primary source, line 1 of
    every session file)
  - `type=turn_context`, `payload.cwd` (per-turn fallback; emitted
    at start of each turn)
  - `exec_command` `workdir` argument (last-resort fallback)

Previous parser looked for `cwd` on the record's top level, which
never matched Codex's actual layout. Also parser now uses
`json.loads(line, strict=False)` to tolerate raw control chars
(tabs/newlines) occasionally written inside `user_instructions` /
`developer_instructions` string values.

**No new rule IDs.** Still 27 total. This is a pure bug-fix + perf
release.

### What the real-data analysis taught us

Lessons from auditing the 871-finding report that did NOT become code
changes in v0.7.7 (they're architecture work queued for v0.8):

- **Power-law distribution:** 95% of findings concentrated in 10 of
  143 sessions. One session had 445 findings from 10,193 events.
  Report UX needs session-level aggregation — "5 sessions need
  attention" beats "871 findings to triage."
- **Zhet-is-DAST-tool context collision:** `C3.autonomy-with-exfil-chain`
  fired 12× (8 CRITICAL) but ALL were Zhet running against testinvicti
  / juice-shop / checkxss.skipa.cyberok.ru — legitimate DAST workflow
  indistinguishable from compromise without project-type awareness.
  Needs `.agent-audit.yaml` project-config mechanism (v0.8).
- **Codex-class surface gap:** Codex sessions produced 108 findings
  but ZERO from C2/C3/AG-04/AI-04/AD-02/AI-06 detectors — probably
  because detectors assume Claude Code event structure
  (Bash/Read/Write tool names, string commands). Codex uses
  `exec_command` / `write_stdin` with structured args. Needs
  tool-name normalization layer (v0.8).

## v0.7.6 changelog — Real bugs caught from Sergey's v0.7.5 run: markdown fences + verify timeouts

Two concrete bugs found in production use of v0.7.3-0.7.5:

**Markdown report corruption — unclosed code fences.** `report.py`
wrapped evidence snippets in triple backticks (```), but many
Claude Code snippets contain code blocks themselves — so the nested
``` closed the outer fence prematurely and everything downstream
rendered as inline code. On the 871-finding report this resulted in
massive sections of the .md file unrenderable.

Fix: count the longest backtick run inside each snippet, use `N+1`
backticks for the outer fence (CommonMark spec compliant).
Verified on the real 871-finding report — **3369 total fences, 0
unclosed** after fix; 66 of them properly expanded to 4-backtick
outer fences where snippets contained nested code.

**Integrity review timeouts under concurrency.** `backend.call()`
used an implicit 120s timeout. Integrity prompts are ~2x larger than
primary verify prompts (include original findings AND verdicts), so
codex-cli under concurrency=4 was hitting timeouts on multiple batches
simultaneously. Symptom from Sergey's log:

```
   integrity review errored: timeout after 120s
   integrity review errored: timeout after 120s
   integrity review errored: timeout after 120s
```

Fix:
  - `verify_batch()` now takes `timeout` param, default 240s (was
    implicit 120s)
  - `integrity_review()` now takes `timeout` param, default 300s
  - New `--timeout` CLI flag on `verify` command
  - Integrity review throttles concurrency to `min(concurrency, 2)`
    to avoid large concurrent prompts thrashing the backend
  - Integrity review uses `timeout * 1.5` internally

Expected result: integrity review reliably completes on 25-finding
batches under codex-cli. If your backend is even slower (remote API
with backpressure), raise `--timeout 480` or similar.

**No rule changes.** This is purely a cli/report bug fix release.
Same 27 rule IDs as v0.7.5.

## v0.7.5 changelog — Cyber-class detectors: Check Point CVE + agent version audit + hook extension

Shifts threat model from self-inflicted (agent over-reliance) to
cyber-sourced (agent as victim / vector). Adds 2 new detectors + 1
extended detector for in-the-wild attack surface documented Feb–Apr 2026.

**New: `AI-05.poisoned-project-config`** (CRITICAL/HIGH/MEDIUM).
The inverse of `AI-04.mcp-config-mutation`: instead of catching the
agent WRITING to mcp.json (outbound), catches malicious project-local
files the agent READS on open (inbound). For each unique `session.cwd`,
walks `.claude/`, `.cursor/`, `.windsurf/`, `.codex/`, `.continue/`,
`.amazonq/`, `.vscode/` folders plus top-level `CLAUDE.md`, `AGENTS.md`,
`.cursorrules` files. Classifies 5 content types:
  - **shell-in-hook** (CRITICAL) — curl/wget/bash -c/exec in any
    hooks/* file
  - **stdio-mcp-in-project** (CRITICAL) — project-local mcp.json with
    STDIO transport (CVE-2026-30615 inbound class)
  - **invisible-unicode** (HIGH) — zero-width chars in instruction
    files (prompt-injection)
  - **sensitive-path-ref** (HIGH) — references to `~/.ssh/`, `~/.aws/`,
    `~/Downloads`, `GOOGLE_APPLICATION_CREDENTIALS`, `/etc/shadow`
  - **external-url** (MEDIUM) — non-allowlisted external URLs in
    instructions (potential exfil target)

Bounded: max 30 files per project, max 50 projects per run, 256 KB
file size limit. Deduplicates by project root so one project isn't
scanned twice across its multiple sessions. Read-only — never executes
anything from the project.

Based on Check Point Research Feb 2026 disclosures **CVE-2025-59536**
and **CVE-2026-21852**: malicious `.claude/project.json` or hooks
committed to a repo execute BEFORE the trust prompt in Claude Code
<2.0.65, enabling arbitrary RCE and API-key exfiltration.

**New: `AI-05.agent-version-vulnerable`** (CRITICAL/HIGH by CVE).
Static version check. Reads installed agent CLI version via
`claude --version` / `codex --version` / `cursor --version` subprocess
(5s timeout) or `package.json`, compares against a small maintained
table of known-vulnerable ranges. Current table:
  - Claude Code ≤ 2.0.64 → CVE-2025-59536 / CVE-2026-21852 (CVSS 8.8) CRITICAL
  - Cursor ≤ 1.9.99 → CVE-2025-54136 (CVSS 8.6, MCP swap-attack) HIGH

Zero-FP rule by construction — just reads versions, compares against
table. When new CVEs drop, add entries to
`KNOWN_VULNERABLE_VERSIONS` dict.

**Extended: `persistence_write`** — added agent-tool hook paths to
`PERSISTENCE_TARGETS`:
  - `.claude/hooks/*`
  - `.cursor/hooks/*`
  - `.windsurf/hooks/*`
  - `.codex/hooks/*`
  - `.continue/hooks/*`

Previously only `.git/hooks/` was covered. Agent-tool hooks have
equivalent persistence semantics — they execute when the agent opens
the project (Check Point class of attack).

**Detector total: 27 rule IDs** (up from 25 in v0.7.4).

### Cyber vs self-inflicted threat model

v0.7.5 is the first release that explicitly targets **attacker-supplied
input** as a threat model, not just agent over-reliance. All prior
detectors assumed the bad outcome came from the agent/user side. The
new AI-05 family assumes:
  - Attacker controls a repo the user clones
  - Attacker controls an MCP server the user connects
  - Attacker controls content that flows into the agent's context

`AI-05.poisoned-project-config`, `AI-06.indirect-prompt-injection-vector`,
and `MCP-08.poisoned-tool-description` are now the three core
"inbound" detectors. The rest remain "outbound" — catching what the
agent did when given too much rope.

## v0.7.4 changelog — Calibration from real 871-finding run: parallel verify + 4 FP fixes

Calibrated from a 143-session / 871-finding scan (Apr 2026, Sergey's
CyberOK production workload on the `zhet` project). Three problems
surfaced that needed closing before v0.7.4 could be useful on real data:

**Parallel verify + larger default batches** — the original run hit
67 batches of 10 findings run sequentially, each with ~5-15s CLI
startup overhead, for a projected 30+ minute verify pass. v0.7.4:

- `DEFAULT_BATCH_SIZE` raised from 10 to 25
- New `--concurrency` flag (default 4) submits batches in parallel via
  `ThreadPoolExecutor`. Integrity review parallelized as well.
- **Measured 9.92× speedup** on benchmark; real runs should drop from
  ~33 min to ~3-4 min.
- Sequential fallback preserved by passing `--concurrency 1`.

**Three FP fixes from real-data clusters:**

1. **AG-04 ephemeral multi-stage fix.** The v0.7.2 ephemeral filter was
   supposed to skip `rm -rf /tmp/...` but was failing on multi-stage
   commands like `rm -rf /tmp/build && mkdir -p /tmp/build && python
   script.py` — it scanned the entire command tail and picked up
   `script.py` as non-ephemeral. Fix: stop scanning at first shell
   separator (`&&`, `||`, `;`, pipe, newline). Eliminates 51 of 70
   AG-04 FP on the real data.

2. **AI-04.mcp-config-mutation narrowed.** The v0.7.3 rule was too
   broad — flagged every write to `CLAUDE.md`, `AGENTS.md`, and Claude
   Code's internal `memory/MEMORY.md`. Project-local `CLAUDE.md` is a
   legitimate project artifact, and `~/.claude/projects/*/memory/` is
   Claude Code's internal scratch memory. Fix: regex now only matches
   actually-dangerous paths (mcp.json in any location, `.cursorrules`,
   `.claude/settings.json`, Claude Desktop config, global `~/CLAUDE.md`).
   Eliminates 36 of 39 FP.

3. **behavior.hypothetical-executed imperative filter.** The v0.7.3
   rule fired on "while it runned let's check httpbruter.zip and decide"
   because "let's" triggered hypothetical framing — but the user was
   giving a direct imperative. Fix: new `_IMPERATIVE_MARKERS` regex
   with EN + RU + ZH verbs (for example: check, analyze, decide, plus
   imperative verbs in Russian and Chinese). If user message contains a direct
   imperative without explicitly destructive verbs, skip the rule.
   Eliminates 1 of 1 FP on the real data (the rule only fired once).

**`behavior.unverified-completion-claim` threshold tightened.** The
claim detector was the dominant noise source (523 of 871 findings).
Real-data analysis showed most FP had score=4: verb + cross-category
object only (e.g. "Phase 7g shipped: +68 records" — describing what
actually happened, not hallucinating a completion). Fix: raised claim
threshold from ≥4 to ≥5. Now requires either verb + direct-category
object (+2) OR verb + evidence anchor (SHA, PR, file path, version).
Cross-category-only stays at `uncertain` (filtered out of LLM verify
by default). Eliminates 220 of 523 FP; downgrades another 261 HIGH
findings to MEDIUM/uncertain.

**Combined real-data projection:** 871 → 563 findings (35% FP
elimination) plus 9.92× faster verify. For a 30-minute v0.7.3 run on
your data, v0.7.4 should take 3-4 minutes and produce findings that
are actually worth triaging.

**Still at 25 rule IDs** — no new detectors in this release. Focus
was hardening.

## v0.7.3 changelog — i18n + attachment-sourced failure modes + OX MCP research

**Multi-language claim detection.** `nlu/claim_detector.py` now supports
Russian and Chinese alongside English through the new `nlu/lexicons.py`
module. Five action categories (code_action, deploy, test, modification,
migration) each have per-language verb and object sets. Chinese tokens
matched as substrings (no CJK word boundaries), others via normal
tokenization. Sentence-type classification (question / conditional /
intention / request) runs across all three languages via prefix patterns.
94% accuracy on original English regression suite preserved; 11/11 on
Russian, 8/8 on Chinese cases.

**Extended destructive command coverage.** `AG-04.destructive-without-backup`
and `behavior.cascading-destructive-chain` now cover:
  - Windows: `rmdir /s /q`, `del`, `Remove-Item -Recurse`, `Clear-Disk`
  - macOS: `diskutil apfs deleteVolume`, `diskutil eraseDisk`
  - Migration tools from attachment cases: `drizzle-kit push --force`,
    `prisma migrate reset --force`, `prisma db push --accept-data-loss`,
    `npx n8n user-management:reset`
  - Terraform + OpenTofu: `terraform destroy`, `tofu destroy`

**New: `behavior.confirmation-bypass`** (HIGH/CRITICAL). Detects
destructive commands paired with bypass flags: `--force`, `-y`,
`--auto-approve`, `--accept-data-loss`, `--no-confirm`, Windows `/q`,
PowerShell `-Force`. Categorizes severity by target (prod migration +
--force = CRITICAL, force-push = HIGH, rm -f = LOW). Based on three
specific GitHub issues: Claude Code #27063 (Railway prod wipe), #34729
(Prisma reset despite Accept Edits = OFF), Codex #4969.

**New: `behavior.hypothetical-executed`** (CRITICAL). Catches the intent-
action mismatch: user asks hypothetically ("what would happen if we
deleted X"), agent actually executes. Multi-language patterns (EN "what
if", RU conditional phrasing, ZH conditional phrasing). References Claude Code
issue #28699.

**New: `AI-04.mcp-config-mutation`** (CRITICAL). Agent writing to
`mcp.json` / `.claude/settings.json` / `.cursorrules` / `CLAUDE.md` /
`claude_desktop_config.json` etc. Mutating the agent's own capability
graph is distinct from generic persistence (shell rc / cron) — next
agent invocation executes whatever STDIO command was injected. Based
on OX Security's "Mother of All AI Supply Chains" research
(April 15, 2026) and CVE-2026-30615 (Windsurf). Elevated severity when
content contains STDIO server indicators.

**New: `credential.context-bleed`** (HIGH/CRITICAL). Agent sets or uses
credentials from outside project scope — `GOOGLE_APPLICATION_CREDENTIALS`,
`AWS_PROFILE`, `KUBECONFIG`, etc. pointing to `~/Downloads/`, `~/Desktop/`,
`/tmp/`, or cloud CLI profile switches. Bumps to CRITICAL if a destructive
op follows in the same window. Based on April 2026 Reddit r/ClaudeAI
case (Claude Code deleted 25k docs from wrong GCP project after picking
up stale credentials from Downloads).

**New: `resource.api-storm`** (MEDIUM/HIGH/CRITICAL). Complements
`resource.unbounded-loop`: that one catches identical retries, this one
catches the case where the endpoint stays the same but arguments vary
(walking an ID space, parameter sweep). Groups calls by normalized
endpoint key (`host + path-with-ids-stripped`). Threshold 25/100/500
scales severity. Based on April 2026 Reddit r/AI_Agents case where agent
crashed prod DB via ~50k internal API calls over an hour.

**Extended `advice.dangerous-recommendation`** with wrapper-bypass
pattern: detects agent recommendations to use `npx -c`, `sh -c`,
`python -c`, `eval`, `node -e` to wrap commands that would otherwise
be blocked by an allowlist. Based on OX Security's Flowise case study
where exactly this bypass was demonstrated.

**Detector total: 25 rule IDs** across session / config / env-probe
surfaces (up from 22 in v0.7.2).

## v0.7.2 changelog — Calibration from real data + composite rules + CST

Calibrated from a 108-session, 256-finding verification run (Apr 2026)
where codex-cli acted as verifier and produced rich rationales. 79% of
v0.7.0 findings turned out to be false positives. v0.7.2 closes the
main FP clusters and introduces two structural improvements.

**New: Compact Sandbox Trace (CST) — Evidence format for autonomy windows.**

For each meaningful autonomy window (>=15 tool calls), agent-audit now
builds a compact structured summary including:
  - sequence of actions with type labels (READ, WRITE, EXEC, NET-IN/OUT, DESTR, PERSIST)
  - taint source→sink chains with causality scores
  - sensitive paths touched (via Aegis classification)
  - network endpoints classified (localhost / known-agent / external / user-content)
  - first-person completion claims detected via NLU
  - per-category subgraph scores (destructive / persistence / secret_access / egress / injection)
  - anomaly score heuristic (0.0-1.0)

CST is attached to findings as Evidence with both Markdown (for human
reading in the .md report) and JSON (for LLM verifier context) forms.
This directly addresses codex's recurring complaint that alerts "omit
the transfer target and data" — now the LLM sees the whole window at
once instead of a single trigger line.

**New: score-based NLU claim detector — replaces regex.**

`behavior.unverified-completion-claim` was 65% FP because its regex
caught "will commit" and "should be applied" the same as "I've
committed". v0.7.2 introduces a stdlib-only NLU pipeline in
`agent_audit/nlu/`:

  - sentence-type classification (assertion / question / conditional / intention / request / report)
  - 5 category lexicons (code_action, deploy, test, modification, migration)
  - evidence anchors (sha, PR number, file path, version tag)
  - modality / hedge / negation / reporting-verb penalties
  - three-bucket output (claim / uncertain / not_claim) + polarity

94% accuracy on 18 regression cases drawn directly from codex
rationales. No NLP dependencies — stdlib `re` only.

**Rewritten: composite C3 — `autonomy-window-excess` was 100% FP.**

The single-trigger rule fired 37 times on long tool streaks and codex
correctly rejected all 37: "a long streak alone shows autonomy, not
abuse". v0.7.2 replaces it with four composite rules:

- `C3.autonomy-window-context` (**INFO**) — pointer-only, carries the
  CST so reviewers can inspect the window. Not an alert. Filtered out
  of LLM verification by default to avoid burning tokens.
- `C3.autonomy-with-sensitive-sink` (MEDIUM) — window + write to a
  sensitive path (via Aegis classification).
- `C3.autonomy-with-exfil-chain` (HIGH, CRITICAL at score >=0.8) —
  window + causality chain where external untrusted content (web
  retrieval, mutable instruction file, or untrusted download) preceded
  a sensitive sink.
- `C3.autonomy-with-persistence` (HIGH) — window + write to a
  persistence path (shell rc, systemd, cron, launchd, autostart).

**Quick fixes from calibration:**

- **AG-04 `/tmp` filter** — destructive commands targeting only
  ephemeral paths (`/tmp/*`, `build/`, `node_modules/`, `__pycache__/`,
  `*.log`, etc.) are skipped. Closes 87/87 FP cluster.
- **AI-06 localhost filter** — WebFetch/curl to `127.0.0.1`, `localhost`,
  or private IP ranges is no longer considered "external content".
  Closes 51/82 FP cluster (Ollama, LM Studio, local model servers).
- **SSH probe evidence fix** — the finding's snippet now describes the
  actual `ssh-keygen -y -P ''` verification performed, not a misleading
  "only header read" string. Detector logic was always correct; only
  the LLM-facing evidence was wrong.
- **Unbounded-loop pytest whitelist** — threshold raised from 4 to 10
  for known test runner / build tool commands (pytest, jest, vitest,
  cargo test, go test, etc.). Closes 6/8 FP cluster.

**Expected FP reduction** (based on verified data):

| Rule | v0.7.0 FP rate | v0.7.2 target |
|------|---------------|---------------|
| AG-04 | 100% (87/87) | ~10% |
| C3 (old) | 100% (37/37) | eliminated, composite replaces |
| AI-06 | 62% (51/82) | ~20% |
| unverified-completion | 65% (11/17) | ~20% |
| SSH probe | 100% (2/2) | 0% |
| unbounded-loop | 75% (6/8) | ~25% |
| Overall | 79% | ~30-35% |

**Known limitation parked in EDR_BACKLOG.md:**

Full Behavioral Provenance Graph (with real taint propagation, process
tree, env-var tracking, byte counts, syscall-level events) requires
runtime telemetry we don't have on JSONL session logs. Parked for v1.0
EDR mode. v0.7.2 implements the subset (~70% of the vocabulary) we can
do on logs alone.

## v0.7 changelog — Chaos detectors + dangerous advice

Five new session-based behavioral detectors inspired by the Agents of Chaos
paper (arXiv:2602.20021, Feb 2026) and the Meta SEV1 incident (March 2026).
These catch failure modes that config-only audits miss: agents lying about
what they did, loops, escalating destruction, indirect prompt injection,
and dangerous recommendations that a human might act on.

**New detectors:**

- **`behavior.unverified-completion-claim`** (HIGH) — agent claims to have
  committed, pushed, deployed, or run tests without a matching tool call.
  This is the failure mode that ASAMM integrity-review specifically catches
  and that Agents of Chaos confirmed in the lab.
- **`behavior.cascading-destructive-chain`** (CRITICAL) — 3+ destructive
  actions with escalating blast radius (tier 1 → tier 4) in one autonomy
  window. Matches CS6 from Agents of Chaos (guilt-trip manipulation
  triggering progressive self-destruction).
- **`resource.unbounded-loop`** (MEDIUM/HIGH) — same tool + same input
  called 4+ times in one window, a loop without progress signal. Matches
  CS4 (9-day cross-agent relay, 60,000+ tokens) and CS5 (silent DoS).
- **`AI-06.indirect-prompt-injection-vector`** (HIGH) — external content
  fetch (WebFetch, curl, read of CLAUDE.md/AGENTS.md/MEMORY.md/etc.) followed
  by a destructive or sensitive action with no user turn between. Matches
  CS10 (constitution GIST injection).
- **`advice.dangerous-recommendation`** (CRITICAL/HIGH/MEDIUM) — scans
  assistant text for 10 classes of dangerous recommendations: run-as-root,
  disable-firewall, chmod-777, tls-bypass, git-force-push, skip-tests,
  delete-no-backup, hardcoded-secret, curl-pipe-sh, wildcard-iam. Motivated
  by Meta SEV1 where the agent's advice (not its actions) caused the
  incident.

All five detectors set `needs_llm_verification=True` — recall-over-precision
design, LLM verifier filters false positives.

## v0.6 — OSS imports: Aegis + AGT + LLM Guard

Three major import operations with MIT attribution. No re-inventing wheels.

**From [antropos17/Aegis](https://github.com/antropos17/Aegis) (MIT License):**
- 107 agent profiles across 11 categories (coding-assistants, autonomous
  agents, local LLM runtimes, IDEs, frameworks, etc.)
- 180 known agent API domains (api.anthropic.com, cursor.sh, ollama.com...)
- 70 sensitive-path rules across 8 categories (ssh/cloud/secrets/browser/...)

**From [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) (MIT License):**
- 8 categories of MCP tool poisoning regex patterns
- Suspicious schema field name list
- Base64 decoded-keyword checks

**From [protectai/llm-guard](https://github.com/protectai/llm-guard) (MIT License):**
- Invisible text detection approach (Cf/Cc/Co unicode categories via stdlib)

**v0.6 detectors:**
- `MCP-08.poisoned-tool-description` — hidden instructions in MCP configs
- `AI-05.invisible-unicode` — steganography in CLAUDE.md
- `C2.credential-exfil-chain` now uses 70 Aegis path rules + known-domain downgrade
- Extended discovery via `--extended` — ~100 agents from Aegis database

## v0.5 — ASAMM samples + Integrity review + Patches

- 5 detectors from SecOps/claude-code-zhet/ouroboros audit samples:
  `AG-02.unversioned-mcp`, `AI-05.secrets-in-agent-config`,
  `config.claude-code.permissive.dangerous-mode`,
  `probe.ssh-key-unencrypted`, `AD-03.adjacent-repo-reach`
- `--mode conservative|standard|full` with explicit consent UI
- `--integrity-review` verify flag (ouroboros-style second pass)
- `--patches` scan flag — ready-to-review config fixes

## v0.4 — BYO API key + Local LLMs + Proxy

- `AnthropicAPIBackend` / `OpenAICompatibleBackend` direct HTTP
- OpenRouter support for regional-blocked API access
- Ollama, LM Studio, vLLM, llama.cpp via OpenAI-compatible
- `--proxy` and auto-detected `HTTPS_PROXY`

## v0.3 — Batch + Preflight + Honest errors

Batch verification (10 at a time), preflight health check, API error parsing.

## What it finds

**From session logs** (`~/.claude/projects/`, `~/.codex/sessions/`):

- **C2 Credential exfil** — secret file read + outbound (Aegis 70-rule classifier)
- **C2 Private-key exfil** — scp/rsync/curl -T of SSH keys
- **C3 Autonomy Window** — long chains of tool calls without user input
- **AI-04 Persistence write** — writes to shell init, cron, git hooks, CI
- **AD-02 Out-of-cwd write** — writes outside agent working directory
- **AG-04 Destructive without backup** — rm/DROP TABLE without prior backup
- **AV-01 Test touches prod** — conftest etc. referencing production DB
- **Intent–Action Gap** — clustered user interruptions

**From configuration**:

- Claude Code `settings.json`: wildcard allows, missing deny rules, dangerous mode
- Codex `config.toml`: full_auto without sandbox
- MCP servers: `@latest` dependencies, poisoned descriptions (AGT patterns)
- Embedded secrets + invisible unicode in CLAUDE.md / AGENTS.md

**From environment (opt-in)**:

- SSH keys without passphrase (`--mode standard`)
- Writable adjacent git repos (`--mode full`)
- Extended agent discovery (`--extended`) — 100+ agents from Aegis database

## Install

```bash
pip install -e .
```

Python 3.9+. Zero dependencies for API backends (urllib only). Works on
macOS, Linux, Windows.

## Use

### Scan

```bash
# Default: conservative, primary agents only
agent-audit scan --output ./reports

# Include all 100+ agents from Aegis database
agent-audit scan --output ./reports --extended

# Add SSH key probes
agent-audit scan --mode standard --output ./reports

# Add adjacent-repo filesystem scan (prompts for consent)
agent-audit scan --mode full --output ./reports

# Generate ready-to-apply config patches
agent-audit scan --output ./reports --patches

# Combine: full mode, extended agents, patches, scripted
agent-audit scan --mode full --extended --patches --output ./reports --yes
```

### Scan project (repos / skills / plugins)

Different from `scan` — this inspects a filesystem tree (a single repo or a
directory of repos) using the 296 bundled rule-pack rules plus native
detectors. Use for skill audits, composio-style collections, plugin
inventories.

```bash
# Single repo
agent-audit scan-project ~/code/my-agent-skills

# Directory of repos (treats each subdir with .git/ as a separate repo)
agent-audit scan-project ~/code/corpus --output ./reports

# Only one rule pack
agent-audit scan-project ~/code/skills --tool atr
agent-audit scan-project ~/code/skills --tool cisco-promptguard

# Noise cutoff
agent-audit scan-project ~/code/skills --min-severity high

# Disable collection-scale aggregation (see every finding individually)
agent-audit scan-project ~/code/big-collection --no-aggregate
```

### Show loaded rule packs

```bash
agent-audit packs           # static-file-applicable rules (what scan-project sees)
agent-audit packs --all     # include session-event rules
```

### List discovered agents

```bash
# Primary 3 with parsers
agent-audit list

# + 100+ extended (Aegis-derived)
agent-audit list --extended
```

### Verify

**CLI backends:**
```bash
agent-audit verify -r ./reports/audit-*.json --budget 0.50
agent-audit verify -r report.json --verifier claude
agent-audit verify -r report.json --verifier codex
```

### Benchmark

```bash
# Run the curated published-incident corpus
agent-audit benchmark --corpus ./benchmarks/incident-corpus

# Persist JSON + Markdown metrics for release comparison
agent-audit benchmark --corpus ./benchmarks/incident-corpus --output ./reports
```

**Direct API:**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
agent-audit verify -r report.json --verifier anthropic

export OPENROUTER_API_KEY=sk-or-...
agent-audit verify -r report.json --verifier openrouter
```

**Local LLMs:**
```bash
ollama pull llama3.3
export OLLAMA_MODEL=llama3.3
agent-audit verify -r report.json --verifier ollama

export AGENT_AUDIT_OPENAI_BASE_URL=http://localhost:1234/v1
export AGENT_AUDIT_OPENAI_MODEL=gpt-oss-20b
agent-audit verify -r report.json --verifier custom
```

**Integrity review:**
```bash
agent-audit verify -r report.json --integrity-review
```

**Proxy forwarding:**
```bash
agent-audit verify -r report.json --proxy http://127.0.0.1:12334
```

## Output

- `audit-<timestamp>.md` — human-readable report
- `audit-<timestamp>.json` — machine-readable findings
- `audit-<timestamp>-verified.json` — per-finding LLM verdicts
- `patches/` *(with --patches)*:
  - `patch-summary.md` — index
  - `<finding-id>/before.json`, `after.json` — state
  - `<finding-id>/diff.patch` — unified diff
  - `<finding-id>/apply.sh` — idempotent apply script
- `~/.local/share/agent-audit/logs/audit-<timestamp>.jsonl` — transparent log

## Scan modes

| Mode | What it reads | Consent prompt |
|------|---------------|----------------|
| `conservative` (default) | `~/.claude/`, `~/.codex/` only | No — default safe |
| `standard` | + `~/.ssh/id_*` first few lines for passphrase check | Yes — shows exact commands |
| `full` | + `find ~/Documents ~/code ~/src ~/dev -maxdepth 5 -name .git` | Yes — shows scan roots |

Flags that cross-cut modes:
- `--extended` — adds 100+ agents (Aegis) to config audit
- `--patches` — generates ready-to-apply config fixes
- `--scan-adjacent-repos` — shortcut for full mode filesystem scan

## Architecture

- `events.py` — universal event model
- `parsers/` — agent-specific JSONL parsers; detect sub-agents by path
- `rules.py` + `detectors/` — plugin-style detection, pure functions
- `knowledge/` — bundled third-party data:
  - `aegis.py` — 107 agent lookups (MIT, antropos17/Aegis)
  - `aegis_paths.py` — 70 sensitive path rules (MIT, antropos17/Aegis)
  - `agt_mcp_patterns.py` — MCP poisoning regex (MIT, microsoft/AGT)
- `scanner.py` — orchestrator: discovery → parse → detect
- `batch_verifier.py` — 7 verifier backends, batch + preflight + integrity review
- `patch_generator.py` — ready-to-review fixes for config findings
- `audit_log.py` — transparent JSONL action log
- `cli.py` — consent-first CLI

## OSS attribution

This release wouldn't have 3x the coverage without direct imports from:

- **[antropos17/Aegis](https://github.com/antropos17/Aegis)** (MIT) — agent
  database and path rules. We use the same data files verbatim. When Aegis
  updates their rules, we re-import — no manual merge.
- **[microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)**
  (MIT) — MCP poisoning regex patterns. Patterns in
  `knowledge/agt_mcp_patterns.py` are character-for-character identical to
  the AGT source.
- **[protectai/llm-guard](https://github.com/protectai/llm-guard)** (MIT) —
  invisible text detection approach (Cf/Cc/Co unicode categories). We
  don't import their code; we use stdlib `unicodedata` with their technique.

These three projects cover layers adjacent to ours (runtime monitoring,
pre-execution policy, prompt middleware). agent-audit adds the forensic
layer — reading session logs after the fact — that none of them address.

See [ROADMAP.md](ROADMAP.md) for the full per-detector source map.

## Not yet implemented

- Ensemble / multi-model verification (v0.7)
- Canary tokens (v0.8)
- HTML report format (v0.9)
- Mission interview mode (v0.9)
- Continuous monitoring / EDR mode (v1.0)
- MCP server wrapper
- Cisco AI Defense mcp-scanner integration (when it matures)

See [ROADMAP.md](ROADMAP.md).

## Testing

```bash
python tests/smoke_test.py
pytest tests/test_benchmark_corpus.py -q
```

Generates synthetic logs with 10+ scenarios — including poisoned MCP
description (Aegis-style zero-width chars), invisible unicode in CLAUDE.md,
`destructive_no_backup`, `test_touches_prod`, `unversioned_mcp`, embedded
secrets — and validates all expected findings are produced.

`tests/test_benchmark_corpus.py` runs the curated incident corpus under
`benchmarks/incident-corpus/` and enforces exact `(rule_id, severity)`
matches so every release has comparable precision/recall numbers.

## License

agent-audit is MIT-licensed. Bundled third-party data retains its original
MIT licenses; see source file comments for attribution.
