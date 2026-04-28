# agent-audit technical architecture

**Status**: current as of v0.14.4 (2026-04-21). Written for another agent
or engineer to pick up the project without session history.

## What this tool does

`agent-audit` is a forensic auditor for AI coding-agent surfaces — skill
specifications (SKILL.md), agent instruction files (AGENTS.md, CLAUDE.md),
MCP manifests, plugin manifests, and multi-agent task YAML configs.
It reads filesystem contents and emits findings about risky agent
behaviour: broad external action without approval gates, autonomous loops
that perform writes, persistent identity rewrites, tool poisoning, and so on.

Two entry points:

- `agent-audit scan` — forensic session log auditor (for runtime Claude Code /
  Codex / OpenClaw sessions). Not the focus of this document.
- `agent-audit scan-project PATH` — static project-surface scanner. This
  document describes its pipeline end to end.

## Pipeline, one sentence at a time

`scan-project PATH` walks the filesystem under PATH, classifies each file
into one or more audit surfaces, loads ~296 rules from YAML rule packs
(ATR / Aguara / Cisco PromptGuard) plus two native structural detectors,
applies severity overrides and educational-context suppression, routes
each rule-pack rule to the prose or code view of the file based on
category, runs native detectors against AST-filtered prose (with agent-
task YAML configs getting a prompt-extraction pass first), post-processes
by collapsing replicated findings into collection-scale aggregates, and
reranks the report so native findings and hot files come first.

## Pipeline, one stage at a time

### Stage 1 — Project discovery

`project_scanner._discover_repos(path)` treats `path` as either a single
repo (has `.git`) or a directory of sibling repos. The `scan-project`
command scans all discovered repos.

### Stage 2 — File walk

`project_scanner._walk_project_files(root)` yields files under root that
pass a skip list (`.git`, `node_modules`, `dist`, `build`, `.venv`, ...)
and have a text-relevant extension (`.md`, `.mdc`, `.txt`, `.json`,
`.yaml`, `.yml`, `.toml`) OR match one of the known instruction filenames.

### Stage 3 — Surface classification

`project_scanner._classify_file(path, repo_root)` returns a set of
audit-surface tags:

| Surface | Matched by |
|---|---|
| `skill_md` | filename is `SKILL.md` |
| `instruction_file` | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `COPILOT.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` |
| `mcp_manifest` | `mcp.json`, `.mcp.json`, `.claude/mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` |
| `plugin_manifest` | `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, `.cursor-plugin/plugin.json` |
| `tool_description` | any `.json`/`.yaml`/`.yml` under `/tools/` |
| `agent_task_config` | **D-9** — any `.yaml`/`.yml` under `/tasks/`, `/agents/`, `/prompts/`, `/personas/`, `/workflows/` that passes `agent_task_adapter.is_agent_task_config()` signature check (has `prompts` or `agents` top-level fields plus a confirmation field like `task_description`, `environment`, `tools`, or agent-internal prompt fields) |

A file can belong to multiple surfaces — SKILL.md is both `skill_md`
and `instruction_file`. Files classified to zero surfaces are skipped.

### Stage 4 — Rule pack load (cached)

`knowledge/rule_pack_loader.load_all_rules()` reads every YAML rule file
under `knowledge/rule_packs/`:

- `atr/**/*.yaml` — Agentic Threat Radar, 233 rules, MIT
- `external/aguara/**/*.yaml` — 37 rules, Apache-2.0
- `external/cisco-promptguard/**/*.yaml` — 26 rules, Apache-2.0

Each YAML compiles to a `RulePackRule` dataclass with patterns,
exclude-patterns, surface tags, severity, ASAMM mapping, remediation.

**Severity overrides** are applied at load-time from
`knowledge/rule_pack_overrides.yaml` — a per-rule allowlist of
demotions. The three loudest rules in grand-run (runtime-url-controls,
binary-download-and-execute, human-approval-fatigue) are pinned to
`low` without editing upstream pack files. Adding a new demotion is
a YAML edit, not a code change.

Loader has a mode cache keyed by `static_only` (used by `scan-project`
to filter out rules whose patterns target live session-event fields).
`packs --all` shows all rules, default `packs` shows static-applicable.

### Stage 5 — Per-file, per-rule match

For each file under scan:

1. **Safe read** (`_safe_read`) — cap at 256 KB, ignore OSError, utf-8 with
   `errors="replace"`.
2. **Educational context check** — `educational_suppressor.is_educational_context(path, text)` returns True for `/translations/`, `/i18n/`, `/locales/`, `/docs/<lang>/`, `/tutorials/`, `/lessons/`, `/labs/`, `*-for-beginners/` paths. Structural skill markers (SKILL.md frontmatter, MCP manifest, plugin descriptor) override the suppression so a legitimately localised skill still fires at full severity.
3. **Markdown AST extraction** (only for `.md`/`.mdc`) — `markdown_features.extract(text)` returns a `MarkdownFeatures` dataclass with `text_without_code` (prose), `code_blocks_by_lang` (fence content), `heading_paths`, `raw`, and `ast_available`. Uses `markdown-it-py` with `commonmark + table` enabled. Falls back to raw text if parse fails.
4. **Rule-surface routing** — for each rule, `rule_surface_classifier.classify_rule_surface(rule)` returns `"code"`, `"prose"`, or `"both"`:
   - Code-oriented categories (privilege-escalation, external-download, hardcoded_secrets, pii_exposure, ssrf-cloud, command-injection, markdown_exfil): match only against concatenated code fences.
   - Prose-oriented categories (prompt-injection, agent-manipulation, skill-compromise, tool-poisoning, excessive-autonomy, model-abuse, unicode-attack, etc.): match only against prose.
   - Unknown categories: match against raw (fallback).
   Non-markdown files use raw text regardless.
5. **Rule pattern match** — `_match_rule_in_text(rule, view)`. Any pattern match fires the rule; any exclude-pattern match suppresses it.
6. **Educational demotion** — if step 2 marked the file as educational, the rule's severity is demoted one level (`critical → high → medium → low → info` floor).
7. **Emit Finding** — with evidence snippet, ASAMM primary/secondary references, upstream rule identity, surface-route tag.

### Stage 6 — Native detectors

Two detectors sit outside the rule-pack framework and encode ASAMM
structural checks:

**`detectors/no_approval_model.py`** — ASAMM AD-02. Fires when:
- `broad_action_without_approval`: skill declares ≥3 remote_action_surface phrases, plus ≥1 of {autonomy_loop, external_reply, write_action}, AND 0 approval markers → HIGH `asamm.AD-02.broad-action-without-approval`
- `autonomous_loop_with_writes`: ≥2 distinct autonomy_loop markers + ≥1 write_action + autonomy:approval ratio >1 → HIGH `asamm.AD-02.autonomous-loop-with-writes`

**`detectors/identity_redefinition.py`** — ASAMM AI-04/AI-05. Three-tier logic:
- IDENTITY_HARD (jailbreak, bypass-safety, without-restrictions) alone in prose → HIGH
- IDENTITY_HARD + PERSIST_WRITE marker (prefill.json, system_prompt file, future-session effects) → CRITICAL `asamm.AI-04.persistent-identity-rewrite`
- IDENTITY_SOFT only (from-now-on, act-as-an, you-are-now, roleplay-as) → INFO with template-context suppressor (`example`, `template`, `schema`, `placeholder`, `sample`, `demo`)

Both detectors run AST prefilter. Identity classifier runs on `text_without_code` (prose), persistence markers allowed from both prose and code (because filename references like `prefill.json` often sit in example blocks). Approval detector runs fully on prose.

**D-9 bypass**: when `project_scanner` encounters an `agent_task_config` surface, it calls `agent_task_adapter.extract_instruction_text(path, text)` to pull prompt-like string fields from the YAML, then invokes native detectors with `bypass_applies_to=True` so the YAML filename passes the detector's file-name gate.

### Stage 7 — Collection-scale aggregation

`collection_scale.aggregate(findings)` — post-processing pass that
collapses high-replication findings into aggregates:

- Cohort = parent directory that holds ≥5 sibling SKILL.md files (threshold v0.13).
- For each (rule_id, cohort) pair: if ≥3 hits and ≥20% of cohort files fired, collapse all individuals into one aggregate with `rule_id#collection-scale` suffix.
- Aggregate carries references `aggregated-count:N`, `cohort-size:M`, `replication-ratio:X%`, max severity across members, evidence pointing at cohort root.

Aggregator never merges across different cohorts — a rule that fires in
both `ruflo/.claude/skills/` and `ruflo/v2/.claude/skills/` stays as two
separate findings.

### Stage 8 — Report rerank

`report_rerank.rerank(findings)` returns a `RerankResult` with three
parts:

1. `native_findings` — all findings carrying `source:agent-audit-native` reference, severity-ordered (critical → high → medium → low → info).
2. `hot_files` — distinct source paths that carry at least one native finding, sorted by total finding count descending.
3. `by_severity` — non-native findings grouped by severity. Within each group, findings in hot files come first (stable partition).

CLI writes two reports to the output directory:

- `project-findings.json` — full data, plus top-level `native_summary` block (`{total_native, rule_counts, hot_files: [{file, findings: [...]}]}`).
- `project-findings.md` — native section first, then hot files summary, then rule-pack findings grouped by severity with hot-file promotion.

### Stage 9 — Dead-ends we decided against

See `docs/ast-precision-plan.md` for decisions D-1 through D-9 in full.
One-line summary per decision:

- **D-1** markdown-it-py AST prefilter — shipped v0.12
- **D-2** tree-sitter-bash — partially closed v0.14.0 via rule-surface classifier (no tree-sitter needed for the shell-metachar-in-prose FP class); full tree-sitter deferred
- **D-3** feature-extraction cache — deferred, not yet hot enough
- **D-4** Rego for ASAMM maturity rollup — v1.0 candidate only
- **D-5** platform-wide Security IR — rejected (YAGNI); small tactical IR inside each module is fine
- **D-6, D-7** graph engine / subgraph isomorphism — deferred with G-1..G-5 triggers listed
- **D-8** OpenTelemetry + W3C PROV — deferred until runtime auditor exists
- **D-9** agent-task YAML surface adapter — shipped v0.14.4

## Key files and where to find things

### Source (`src/agent_audit/`)

```
cli.py                       # click CLI — scan, scan-project, packs commands
project_scanner.py           # scan-project pipeline; file walk, classify, match, emit
collection_scale.py          # cohort detection, aggregation thresholds
report_rerank.py             # native-first reranking for markdown/JSON output

detectors/
  no_approval_model.py       # ASAMM AD-02 — broad-action + autonomous-loop-with-writes
  identity_redefinition.py   # ASAMM AI-04/AI-05 — three-tier identity hijack

knowledge/
  rule_pack_loader.py        # YAML → RulePackRule, with override merge, static_only filter
  rule_pack_overrides.yaml   # per-rule severity demotions, keep out of upstream edits
  rule_surface_classifier.py # rule category → code/prose/both routing decision
  educational_suppressor.py  # path-based severity demotion with structural-marker override
  markdown_features.py       # markdown-it-py AST extractor, commonmark + GFM tables
  agent_task_adapter.py      # D-9: signature-check YAML configs, extract prompt text
  capability_lexicon.py      # REMOTE_ACTION_SURFACE, WRITE_ACTION, AUTONOMY_LOOP, etc.
  identity_lexicon.py        # IDENTITY_HARD, IDENTITY_SOFT, PERSIST_WRITE, TEMPLATE_CONTEXT
  rule_packs/                # bundled YAML rules
    atr/                     # 233 rules, MIT
    external/aguara/         # 37 rules, Apache-2.0
    external/cisco-promptguard/  # 26 rules, Apache-2.0

tools/
  lexicon_audit.py           # standalone corpus telemetry tool; density stats per pattern
```

### Tests (`tests/`)

```
test_markdown_features.py              # 10 tests — AST extraction, table support, fallback
test_collection_scale.py               # 12 tests — cohort thresholds, aggregation logic
test_educational_suppressor.py         # 12 tests — path patterns, structural override
test_rule_surface_classifier.py        # 6 tests — code/prose/both routing decisions
test_report_rerank.py                  # 9 tests — native separation, hot files, severity order
test_native_regression_fixtures.py     # 10 tests — pinned TPs and FPs (incl. MCP regex)
test_agent_task_adapter.py             # 10 tests — D-9 YAML signature and extraction
(plus existing: claim_detector, confirmation_bypass, taint, hypothetical_executed,
 credential_context_bleed, mcp_config_mutation — for session-level detectors)
```

### Docs

```
README.md                         # user-facing docs, per-release changelog at bottom
docs/ast-precision-plan.md        # D-1..D-9 decision record, revision history
docs/architecture.md              # this document
ROADMAP.md                        # forward backlog
```

## How to add things

### Add a new rule pack

1. Drop YAML files under `src/agent_audit/knowledge/rule_packs/<pack-name>/`
2. Each rule file must have top-level `agent_audit_id: <pack>.<category>.<short-slug>`,
   `title`, `severity_default`, `audit_surface: [instruction_file, skill_md, ...]`,
   and `patterns: [{value: 'regex', ...}]` structure.
3. Pack loader auto-discovers new directories. No code change needed.
4. If the pack is noisy: add demotion entries to `rule_pack_overrides.yaml`
   rather than editing upstream rule files.

### Add a new native detector

1. Create `detectors/<name>.py` with a `check_file(path, text=None, bypass_applies_to=False) -> List[<Your>Finding]` function. Include `applies_to(path)` gate. Use AST prefilter for markdown semantic analysis, fall back to raw text when `features.ast_available` is False.
2. Add a `convert_to_finding(f) -> Finding` shim that tags references with `source:agent-audit-native` and your ASAMM control mapping.
3. Wire invocation in `project_scanner.scan_project()` next to the existing two detectors. If you're adding a non-markdown file surface, support `bypass_applies_to` for the D-9 pattern.
4. Pin your detector with fixtures in `tests/test_native_regression_fixtures.py` — a positive control (must fire) and a path-component negative control (must not fire).

### Add a new surface adapter (like D-9 did)

1. Create `knowledge/<surface>_adapter.py` with two functions:
   - `is_<surface>(path, text=None) -> bool` — conservative signature check.
   - `extract_instruction_text(path, text=None) -> str` — concatenate prompt-like string fields as pseudo-prose for native detectors.
2. Add the surface tag to `_PROJECT_SURFACES` and `_classify_file()` in `project_scanner.py`.
3. Wire native-detector invocation to extract text and bypass applies-to.
4. Unit tests must cover: positive-shape fixtures, and negative controls for the common surface shapes that could trigger FP (docker-compose, GHA workflow, package manifest, etc.).

### Tune a noisy pattern

1. Run `python -m agent_audit.tools.lexicon_audit PATH_TO_CORPUS -o /tmp/report.md`.
2. Open the report. Look at match count, density (matches/files), and the example contexts for the top 10 densest patterns.
3. For regex patterns specifically: run the audit before AND after your change. If match count drops but example contexts still look like TPs, you've tightened correctly. If example contexts look like sentence-starters or path components, you're still over-matching.
4. Data-driven regex discipline: the MCP-regex saga (v0.14.1 → 0.14.2 → 0.14.3) shows what happens when you tune regex without empirical corpus telemetry. Always audit, never speculate.

## Grand-run methodology

The canonical validation is a run against a 500-repo corpus from
`<instruction-corpus-root>`. Results stored
in `reports/agent-audit-grand-run-v<version>/`. Each run produces:

- Lab summary (`agent-audit-grand-run-YYYY-MM-DD-v<version>.md`)
- Per-repo review (`*-per-repo.md`, `*-per-repo.json`)
- Corpus summary (`corpus-summary.json`)
- Regression diff vs prior baseline (`regression-compare-v<prev>-to-v<next>.json`)
- Raw per-target outputs (`repo-runs/<repo>/project-findings.{json,md}`)

Two investigation rules learned the hard way:

1. **Native-finding deltas need per-target investigation.** Grand-run diff
   between v0.11.1 and v0.14.0 showed "34 → 30 native" regression. Per-
   target probe revealed 5/5 "losses" were FP cleanup (the `\bMCP\b` regex
   was matching `src/mcp/` path components).
2. **Collection-scale aggregation changes raw native count.** A file that
   fired 4× in v0.14.0 (4 siblings of the same replicated skill) collapses
   to 1 aggregate in v0.14.0+. This is not recall loss; it's correct
   aggregation. Always sanity-check whether "lost" findings are actually
   grouped into aggregates in the new version.

## Versioning discipline

Patch version bumps when a lexicon or surface adapter change is
non-architectural (v0.14.1, .2, .3 — all MCP regex iterations +
lexicon-audit tooling; v0.14.4 = D-9 adapter). Minor bump for
architectural shift (v0.12 = AST prefilter, v0.13 = suppressors, v0.14 =
rule-surface routing + reranker).

Every release:
- README has a new `## v<version>` changelog section at top of per-release
  section, with a table showing measured delta on the 10-target calibration
  suite (at `--min-severity medium`) plus any recovered/regressed native counts.
- Tests relevant to the change land in the same commit.
- `tests/test_native_regression_fixtures.py` pins any TP/FP transition.

## Anti-patterns to avoid (learned the hard way)

- **Regex by speculation.** Every regex change gets a before/after lexicon
  audit. No exceptions. "I bet this pattern is FP" is how you ship
  v0.14.1-style partial-regression releases.
- **Native "regression" without per-target probe.** If the diff says
  "-N native findings", clone the affected repos and check whether
  those were TPs or FPs before calling it regression.
- **Changing rule-pack YAMLs directly.** Use `rule_pack_overrides.yaml`
  to preserve upstream update path.
- **Per-rule severity decisions inside detectors.** Severity belongs in
  rule YAML or overrides. Detectors emit fixed severities.
- **Growing blocklists.** If a blocklist grows past ~20 entries, switch
  to an allowlist (the Pattern 2 MCP saga: `[A-Z][a-z]+ MCP` with
  sentence-starter blocklist was wrong; closed-set vendor allowlist of
  ~14 names is correct).
