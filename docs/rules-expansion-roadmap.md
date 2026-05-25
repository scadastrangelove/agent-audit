<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# Rules Expansion Roadmap

## Purpose

This document tracks planned expansion of `agent-audit`'s signature
sources beyond the three packs currently bundled (ATR, Aguara,
Cisco PromptGuard) plus the two native detectors. The motivation is
landscape coverage: the agent-security ecosystem has produced multiple
new pack sources and taxonomies in 2025–2026, and our `references`
field plus `finding_dedup.canonical_class_for_rule` mapping should
reflect that.

This is **not** a wishlist. Each item has:
- a concrete entry point in the codebase
- a license check and ingestion strategy
- a regression-fixture obligation (where rules ship)
- a calibration plan (where signal volume is large enough to risk FP)

The grand-run methodology stays the same: every pack addition gets a
before/after lexicon audit on the 509-repo corpus, and any noisy class
gets a `rule_pack_overrides.yaml` demotion entry rather than upstream
edits.

## Source Categories

Four categories are tracked separately because their integration
strategies differ:

- **A — Direct rule-pack peers**: shipped as additional YAML/TOML packs
  under `knowledge/rule_packs/external/`. Loader normalizes to
  `RulePackRule`. Subject to the same surface-routing and
  educational-suppressor pipeline as existing packs.
- **B — Taxonomies and reference catalogs**: not rule sources; they
  populate `references` fields and `finding_dedup.CANONICAL_CLASS_PREFIXES`
  for cross-framework mapping.
- **C — Alternative rule formats**: NOVA, Semgrep, Gitleaks, TruffleHog.
  Require format adapters before they fit `RulePackRule`. Some (NOVA)
  are hybrid pattern+semantic+LLM and need a richer compile target.
- **D — Adversarial benchmarks**: not rule sources; provide labelled
  test cases for measuring our rules' precision/recall.

## Executive Read

Highest-value items, in execution order:

1. ✅ **Aguara upgrade** — *shipped in v0.16.0*. Aguara rule count rose
   37 → 189 across 13 categories. New build-time importer at
   `tools/aguara_import.py`. Total static-applicable rules: 167 → 310.
2. ✅ **OWASP MCP Top 10 mapping layer** — *shipped in v0.16.0*. Auto-
   enriches `references.owasp_mcp` at rule-load time via
   `(tool, category) → MCP IDs` mapping; 310/310 rules now carry
   derived OWASP MCP refs.
3. ✅ **Gitleaks pack** — *shipped in v0.16.0*. TOML→YAML normalizer,
   217 secret patterns under category `hardcoded_secrets`. Total
   pack count went from 3 to 4. Calibration on benign canonical
   tokens (AWS, GitHub, OpenAI examples) showed 0 Gitleaks FPs.
4. ✅ **MITRE ATLAS auto-validation** — *shipped in v0.16.0*. CI
   utility validates `mitre_atlas:*` IDs against vendored ATLAS
   snapshot. All 12 name-drift cases from first run resolved
   via the v0.16 references-rewrite mechanism.
5. ✅ **NOVA rules pack as fifth source** — *shipped in v0.17.0*.
   46 rules from `Nova-Hunting/nova-rules`. Keyword-only import (the
   `semantics` + `llm` sections are preserved as metadata for the M3
   evaluator). All NOVA rules ship at LOW severity until M3 lands;
   calibration on benign skill SKILL.md showed multi-word keyword
   conjunctions firing too readily without the upstream evaluator gates.
6. ✅ **Tool-pinning / rug-pull native detector** — *shipped in v0.17.0*.
   State-tracking detector at `src/agent_audit/tool_pinning.py` that
   records SHA-256 hashes of MCP tool descriptions per project under
   `~/.agent-audit/tool-pinning/`. Three finding kinds: HIGH-severity
   description-changed (the rug-pull), LOW added/removed (informational).
   Opt-in via `--track-tool-pinning` flag on `scan-project`.

Items beyond this are scoped further in section "Backlog by Category".

## Backlog by Category

### A. Direct rule-pack peers

#### A1. Aguara upgrade to current 177-rule pack

**Status**: ✅ shipped in v0.16.0.

**What we had today**: `knowledge/rule_packs/external/aguara/` with 37
rules across 3 categories. Snapshot taken from an earlier Aguara release.

**What landed**:
- vendored upstream Aguara at SHA `d8797926`: **189 rules across 13 categories**
- new build-time importer `tools/aguara_import.py` — idempotent, takes
  upstream multi-doc YAML and emits our per-rule format with attribution.
  Output committed to repo so runtime needs no Aguara dependency
- 10 new Aguara categories added: command-execution, credential-leak,
  exfiltration, indirect-injection, mcp-attack, mcp-config,
  prompt-injection, supply-chain, supply-chain-exfil, unicode-attack
- extended `_CATEGORY_TO_MCP` and `_CATEGORY_TO_ASI` mapping tables for
  all new categories — 100% coverage of all 310 static-applicable rules
  for both OWASP taxonomies (was 78% before A1)
- weekly refresh job in `refresh-vendored-data.yml`
- 17 new tests in `tests/test_aguara_a1.py`

**Architectural fix surfaced by A1 calibration**: rules declaring
upstream `targets:` (file-extension globs like `*.pth`) were firing on
all surfaces that matched their content — including Markdown
documentation that happened to contain `import` or `from`. Promoted
upstream `targets:` to `RulePackRule.file_types` and added match-time
filtering in `project_scanner._match_rule_in_text`. Calibration on
benign SKILL.md showed the FP class disappeared.

**Effort actual**: ~1 day (matched the estimate; calibration revealed
one architectural gap that took an extra hour to fix cleanly rather
than working around with overrides).

#### A2. NOVA rules pack (with Proximity)

**Status**: ✅ shipped in v0.17.0 (with caveats — see below).

**What landed**: 46 NOVA rules imported from
[Nova-Hunting/nova-rules](https://github.com/Nova-Hunting/nova-rules).
NOVA's three-section format is honored *partially*: keywords are
imported as regex patterns; `semantics` and `llm` sections are preserved
as upstream metadata fields (`upstream_semantics_patterns`,
`upstream_llm_checks`) for a future evaluator (M3).

**Severity floored at LOW.** Calibration on a benign skill SKILL.md
showed multiple NOVA rules firing on innocuous text — the
"messaging-scripting" rule fires on the words "code", "script",
"program" appearing anywhere; "policy-puppetry-universal-bypass" fires
on `<interaction-config>`-shaped HTML. The upstream design depended on
the semantics/llm gates to suppress those generic keyword matches; we
don't have those gates yet, so we floor severity to LOW for every
imported NOVA rule. Per-rule severity restoration will happen
selectively when M3 lands and we can audit which rules are tight enough
to fire at higher confidence.

**No `session_*` audit surfaces.** Same reasoning — keyword-only NOVA
rules are too noisy for forensic mode. Static surfaces only until M3.

**Build-time importer** `tools/nova_import.py`:
- hand-rolled .nov DSL parser handles three sections + condition expression
- `_condition_to_match_mode()` lossy mapping: `any of keywords.*` →
  `match_mode: any`; `N of keywords.*` where N == total → `all`,
  otherwise `any` with a documented note
- `_NOVA_CATEGORY_MAP` resolves NOVA's path-style categories
  (`prompt_manipulation/jailbreak`, `suspicious_patterns/encoding_obfuscation`)
  to our internal categories
- 4 NOVA rules with no keyword section are skipped on import (semantics/llm-only)

**Refresh job** in `.github/workflows/refresh-vendored-data.yml`
(weekly): fetch upstream, re-import, run A2/C1 regression tests, run
all three reference validators, open PR on diff. PR body explains the
keyword-only policy explicitly so reviewers know what's missing.

**Test coverage**: 35 tests in `tests/test_nova_a2_c1.py` covering
rule splitting, parser, condition shape coverage, severity flooring,
static-surface-only assertion, and end-to-end import.

**Effort actual**: ~1 day for the importer + tests. The semantics/llm
evaluator (M3) is deferred — that's a separate item with its own
calibration.

#### M3. NOVA semantics + llm evaluator

**Status**: ✅ shipped in v0.17.0.

**What landed**: a post-hoc evaluator at
`src/agent_audit/nova_evaluator.py` that runs the NOVA `semantics:`
and `llm:` gates which the A2/C1 importer had to skip. The two gates
are independent and degrade gracefully:

- **semantics gate**: cosine similarity between the matched snippet
  and each upstream prose pattern, using a small sentence-transformers
  model (`all-MiniLM-L6-v2`, ~80MB, downloaded on first use). Pass =
  max similarity ≥ strictest declared threshold across patterns.
- **llm gate**: yes/no question to a configured `VerifierBackend`
  (Claude CLI, Codex CLI, Anthropic API, or OpenAI-compatible). Pass =
  ALL llm checks return yes (conservative AND, since we don't have
  the upstream condition structure available at evaluation time).

**Severity policy**:
- both gates available, both pass → lift to upstream severity
- both gates available, both fail → demote to INFO (suppressed)
- gates disagree → demote one notch (trust the failing gate)
- only one gate available, passes → partial lift (one notch up,
  capped at upstream)
- only one gate available, fails → demote one notch
- neither gate available → no change (the fail-open path; matches
  v0.17 baseline keyword-only behavior)

**New CLI subcommand `agent-audit nova-evaluate`**: takes a
`project-findings.json` produced by `scan-project`, runs the gates on
every NOVA finding, and updates severity in place (or `--dry-run`
prints verdicts without writing). Supports `--no-llm`/`--no-semantics`
flags so users can run with just one gate when the other dependency
isn't available.

**Loader extension**: `RulePackRule` gained three new optional fields:
- `upstream_semantics_patterns: List[dict]`
- `upstream_llm_checks: List[dict]`
- `upstream_severity: Optional[Severity]` — the pre-flooring severity
  from the .nov meta block, used to decide how high a finding can be
  lifted

The A2/C1 importer was updated to write `upstream_severity` to YAML so
loader and evaluator agree on the cap. Non-NOVA rules leave these
fields empty — verified by a regression test.

**Calibration outcome on the v0.17 benign skill corpus**: the same
SKILL.md that produced 5 LOW-severity NOVA findings under A2/C1 now
demotes 4 of those to INFO under semantics-only evaluation (no LLM,
no API key needed) — the matched snippets are semantically far from
the upstream prose patterns about phishing themes, policy puppetry,
APT TTPs, and PII disclosure. This is the desired suppression effect.

**Test coverage**: 36 tests in `tests/test_nova_evaluator_m3.py`
covering every cell of the severity decision matrix, fail-open paths
when dependencies are missing, mock LLM backend with yes/no/error
responses, and end-to-end smoke on the real NOVA pack. The tests do
not require sentence-transformers to be installed; the model is
explicitly mocked or treated as unavailable in unit tests.

**Effort actual**: ~1 day. Most of the time was decision matrix
calibration and ensuring fail-open paths don't crash the scan.

**Out of scope (not done in this PR)**:
- Network embedding APIs (OpenAI, Cohere). The local
  sentence-transformers path is sufficient and offline-friendly.
- Per-rule threshold tuning. Upstream NOVA YAMLs ship thresholds; we
  honor as-is. Tightening per-rule thresholds is research-grade
  calibration for a future pass.
- Auto-running the evaluator inside `scan-project`. Today users invoke
  `nova-evaluate` separately. Auto-invoke gated on backend availability
  is a follow-up if it proves useful.

#### A3. Gitleaks pack (TOML)

**Status**: ✅ shipped in v0.16.0.

**What landed**: 217 secret-detection rules imported from
[gitleaks/gitleaks](https://github.com/gitleaks/gitleaks). Single
category `hardcoded_secrets`, all mapped to `ASAMM:AG-03`, OWASP
MCP01, OWASP ASI03. Default severity HIGH.

**Build-time importer** `tools/gitleaks_import.py`:
- TOML→YAML conversion using `tomllib` (Python 3.11+) with `tomli` fallback
- regex compatibility layer: Gitleaks targets Go RE2, our matcher uses
  Python re. The `_normalize_regex()` function hoists interior `(?i)`
  inline flags to the front (Python 3.11+ deprecates them mid-pattern)
  and skips genuinely incompatible patterns. 217/222 (97.7%) survive
- baseline FP-prevention: every imported rule carries a shared
  `exclude_patterns` block with known canonical example tokens
  (AWS canonical, GitHub PAT placeholders, `<your_api_key_here>`-style
  templates, RSA test fixtures, OpenAI sandbox examples)
- `entropy` and `path` upstream fields preserved as informational
  `upstream_entropy_threshold` and `upstream_path_regex` — current
  matcher doesn't enforce them; future work

**Calibration outcome**: synthetic SKILL.md with AWS canonical
example tokens, GitHub PAT placeholders, and `xxx-xxx-xxx` placeholders
produced **0 Gitleaks findings**. Same skill fired 3 Aguara
credential-leak findings, indicating Aguara's own excludes are narrower
than ours. TP sanity check (realistic AWS-shaped key) confirms gitleaks
fires on actual secrets.

**Refresh job** in `.github/workflows/refresh-vendored-data.yml`
(weekly): fetch upstream, re-import, run A3 regression tests, run all
three reference validators, open PR on diff.

**Test coverage**: 31 tests in `tests/test_gitleaks_a3.py` covering
regex normalization paths, slug stability, end-to-end import on
synthetic TOML, baseline-exclude enforcement, and TP sanity.

**Effort actual**: ~1 day (the importer + tests). Calibration time
saved by the existing `_BASELINE_EXCLUDE_PATTERNS` design — common
example tokens listed once, applied to all 217 rules.

#### A4. TruffleHog regex extracts (regex only, not verifier)

**Status**: deferred until A3 calibrated.

**What it is**: TruffleHog ships 800+ purpose-built credential
detectors written in Go. Each detector pairs a regex with a live API
verifier. We can't use the verifier (out of scope — we're static), but
the regex parts are useful additions to A3 once Gitleaks is calibrated.

**Why deferred**: significant overlap with Gitleaks. Better to ship A3
first, run lexicon audit, then ingest only TruffleHog regex that adds
non-overlapping coverage.

**Entry points** (when reached):
- per-detector regex extraction script. License surface: TruffleHog
  core is AGPL — we extract only the regex strings, document
  attribution, and check that pattern strings alone are not derivative
  of AGPL source structure. If counsel disagrees, drop this item.
- ship under `external/trufflehog-extracts/` with explicit attribution

**Effort**: 2–3 days, contingent on the AGPL question.

#### A5. Cisco mcp-scanner integration (YARA)

**Status**: design, scope expansion.

**What it is**: Cisco's `mcp-scanner` is a separate pack from
PromptGuard. It runs YARA-based pattern matching plus LLM-as-a-judge
plus VirusTotal hash lookups against MCP server tool descriptions and
source code. Apache-2.0.

**Why it matters here**: only public source that scans MCP server
**source code** (Python, TS, JS, Go, Java, Kotlin, C#, Rust, Ruby,
PHP). Today our scope is instruction surfaces (Markdown, JSON, YAML)
only.

**Why design-stage**: source-code scanning expands `agent-audit`'s
scope significantly. EDR_BACKLOG already lists "syscall-level events"
as deferred to v1.0; source-code SAST is a similar boundary question.
Decision pending: do we ship a `--scan-mcp-source` mode, or stay
instruction-surface-only and let users compose with `semgrep` and
Cisco mcp-scanner?

**Entry points** (if approved):
- YARA rule loader (new) under `knowledge/yara_loader.py` —
  optional dependency on `yara-python`
- new audit surface `mcp_server_source` in `_PROJECT_SURFACES`
- new file walk that respects per-language extensions

**Effort**: 2 weeks if approved. Defer until the scope question is
decided in a separate doc.

#### A6. mcp-audit cross-server attack-path rules

**Status**: scope check.

**What it is**: Adam Dudley's `mcp-audit` (Apache-2.0) ships 37 SAST
rules for Python and TypeScript plus governance rules and cross-server
attack-path detection. Maps to OWASP MCP Top 10.

**Why interesting**: cross-server attack paths are a class of finding
we don't currently emit. When a project ships multiple MCP server
configs, capability-overlap analysis (one server reads credentials,
another sends to a webhook) is the natural finding. Aguara's current
build does intra-server toxic-flow detection; mcp-audit does
cross-server.

**Entry points**:
- evaluate whether mcp-audit's rule format is YAML-portable into
  `RulePackRule`
- if yes: new pack under `external/mcp-audit/`
- if no: the cross-server idea becomes a native detector instead,
  parallel to the existing identity/approval detectors

**Effort**: 1 day investigation, 4–6 days implementation depending on
which path.

### B. Taxonomies and reference catalogs

#### B1. OWASP MCP Top 10 mapping (most important non-rule item)

**Status**: ✅ shipped in v0.16.0.

**What it is**: OWASP MCP Top 10 is the first OWASP framework
specifically for Model Context Protocol security. Categories
MCP01:2025–MCP10:2025 cover token mismanagement, scope creep, tool
poisoning, supply chain, command injection, context oversharing,
shadow servers, and more. CC BY-SA 4.0.

**Why it matters here**: today our `references` field carries
`asamm:*`, `owasp_llm:*`, `owasp_agentic:*`, `mitre_atlas:*`, and
`upstream:*`. OWASP MCP Top 10 is the first taxonomy specifically for
MCP, and security teams already use it. Adding it as a third OWASP
mapping makes our reports immediately readable in MCP-governance
contexts.

**What landed**:
- vendored OWASP MCP Top 10 markdown + LICENSE (CC BY-SA 4.0) under
  `src/agent_audit/data/owasp_mcp/`
- generated machine-readable index `owasp_mcp_top10.yaml` (10 categories)
- new module `knowledge/owasp_mcp_mapping.py` with the authoritative
  `(tool, category) → MCP IDs` table (17 source-classifications mapped)
- rule-pack loader auto-enriches `references.owasp_mcp` at load time;
  131 of 167 static-applicable rules carry derived MCP refs
- new validator `tools/owasp_mcp_validate.py` with the same shape as
  `atlas-validate` (unknown ID / name mismatch / missing-backfill modes,
  lenient/strict, JSON output)
- new CLI subcommand `agent-audit owasp-mcp-validate`
- 29 new tests; CI gate runs in strict mode
- `finding_dedup.owasp_mcp_for_finding(rule_id)` helper

**Side-quest also done — references rewrite mechanism**:
extended `rule_pack_overrides.yaml` with a `references_rewrite` block
for global text-replacement of upstream taxonomy strings. Applied at
rule load time; both validators consume the same rewrites. Used to
ship 12 ATLAS name-drift fixes from B3, resolving the entire B3
findings backlog without editing upstream YAMLs. 13 additional tests
under `tests/test_references_rewrite.py`.

**Effort actual**: ~2 days (matched estimate for the mapping module
and validator; ~half a day for the references-rewrite extension; ~half
a day for tests).

#### B2. OWASP Agentic AI Top 10 (ASI series) — systematic mapping

**Status**: ✅ shipped in v0.16.0.

**What we had today**: `identity_redefinition.py` and
`no_approval_model.py` carried `owasp_agentic:ASI03`,
`owasp_agentic:ASI06` references. Most rule-pack rules carried
inconsistent ASI cites — first-run validator found 15 distinct ASI IDs
(both `ASInn` and `ASInn:2026` forms) with **10 categories each having
name drift** because rules were authored across the draft → 1.0.0
release transition.

**What landed**:
- vendored canonical ASI index (10 categories, v1.0.0, CC BY-SA 4.0)
  under `src/agent_audit/data/owasp_agentic/` — synthesized from the
  upstream PDF; OWASP doesn't publish structured machine-readable
  exports for this top-10 series
- new mapping module `knowledge/owasp_agentic_mapping.py` with the
  authoritative `(tool, category) → ASI IDs` table (17 source-classifications)
- rule-pack loader auto-enriches `references.owasp_agentic` at load
  time; 131 of 167 static-applicable rules now carry derived refs
- new validator `tools/owasp_agentic_validate.py` (same shape as
  `owasp-mcp-validate` and `atlas-validate`)
- new CLI subcommand `agent-audit owasp-agentic-validate`
- 25 new tests
- **68 references_rewrite entries** for ASI taxonomy drift (every
  draft → 1.0.0 rename, both `ASInn` and `ASInn:2026` forms)
- one native detector fix in `no_approval_model.py` (semantically
  re-aligned the AD-02 detector to ASI10 + ASI03 to match the canonical
  mapping)
- CI gate runs `owasp-agentic-validate --strict` on every PR

**Effort actual**: ~1 day (matched the estimate; references_rewrite
infrastructure from B1 carried over directly).

#### B3. MITRE ATLAS auto-validation utility

**Status**: ✅ shipped in v0.16.0.

**What it is**: `mitre-atlas/atlas-data` is the canonical machine-readable
ATLAS dataset (STIX 2.1 + YAML) covering tactics, techniques, mitigations,
case studies. As of 2026, ATLAS contains 16 tactics and 84 techniques,
with v5.4 adding agent-focused additions from the Zenity Labs
collaboration.

**Why it matters here**: our ATR rules carry `mitre_atlas:AML.T0053`
and similar references. There's no current process to detect when
ATLAS deprecates or renumbers a technique. A simple CI gate catches
this drift.

**What landed**:
- vendored ATLAS snapshot (currently v5.6.0, 170 techniques) under
  `src/agent_audit/data/atlas/ATLAS.yaml` with Apache-2.0 LICENSE alongside
- `src/agent_audit/tools/atlas_validate.py` walks every rule pack YAML
  plus native detector source and collects `mitre_atlas:*` references
- validator distinguishes three issue classes — unknown ID, deprecated
  technique, name-mismatch — and emits text or JSON
- CLI subcommand `agent-audit atlas-validate` with `--strict`, `--json`,
  `--quiet` flags
- 28 new tests under `tests/test_atlas_validate.py`
- documented refresh procedure in `data/atlas/README.md`

**Findings on first run**: 21 distinct ATLAS IDs cited across 279 citations.
All 21 IDs are valid and non-deprecated. 12 name-drift cases found —
ATLAS's AI/ML wording sweep renamed many techniques (`ML Supply Chain
Compromise` → `AI Supply Chain Compromise`, `LLM Plugin Compromise` →
`AI Agent Tool Invocation`, etc.). Default mode tolerates these
(non-blocking warning); `--strict` mode treats them as hard errors.
Follow-up rule-maintenance commits will fix the upstream-derived names
without editing source ATR YAMLs (using a new
`rule_pack_overrides.yaml` mechanism for reference rewrites).

**Effort actual**: ~1 day. Matched estimate.

#### B4. AVID (AI Vulnerability Database) cross-link

**Status**: ✅ shipped in v0.17.0.

**What landed**: cross-link to AVID's SEP (Security, Ethics, Performance)
taxonomy through a `(source_tool, category) → SEP subcategory` mapping
table, mirroring the OWASP MCP / OWASP Agentic mapping shape.

- new module `src/agent_audit/knowledge/avid_mapping.py` carries the
  canonical 48-entry SEP enum (verbatim from upstream avidtools) plus
  29-entry mapping covering every `(source_tool, category)` key
  produced by the live rule packs
- loader enrichment pass populates `references["avid"]` for every rule
  whose category has a known mapping — same flow as MCP and ASI
  enrichment
- new tool `tools/avid_validate.py` and CLI `agent-audit avid-validate`
  with `--strict`, `--include-missing`, `--json`, `--quiet` flags.
  Catches three drift classes: UNKNOWN SEP IDs, NAME_MISMATCH against
  upstream titles, and MISSING references where a mapping exists but
  hasn't flowed through to the runtime
- CI integration in `.github/workflows/ci.yml` — fourth strict
  validator step alongside ATLAS / MCP / ASI
- 30 new tests in `tests/test_avid_b4.py` covering mapping integrity,
  loader enrichment, validator behavior, and the specific
  pack→SEP joins so future drift in our mapping decisions surfaces
  loudly

**Coverage**: 100% across all loaded rules — every rule pack rule and
native detector that flows through the loader picks up at least one
SEP subcategory. Total references: 1372 across 12 distinct SEP IDs
(S0100, S0200, S0202, S0300, S0301, S0400, S0403, S0500, S0502, S0600,
S0601, P0300).

**Why no vendored snapshot file**: AVID ships ~weekly database
releases, but the SEP taxonomy changes infrequently and is small (48
subcategories). Inline canonical labels in `avid_mapping._SEP_LABELS`
are sufficient. If upstream renames a category, fix the label there
and add a `references_rewrite` entry — same recipe used for the OWASP
ASI draft → 1.0.0 migration.

**Why no per-record AVID-YYYY-V/R IDs**: the original roadmap hoped
for per-rule incident attribution. The 2026 GPAI rebuild reorganized
AVID's database around a Taxonomy Library where individual record IDs
are less stable across migrations. Cross-linking at the SEP layer
survives upstream reorganization. Per-rule AVID-ID references can
still be added manually in YAML's `references.avid` block where
lineage is genuine.

**Why not the Lifecycle view**: SEP subcategories carry the threat-
class semantics that match our rule packs. Lifecycle stages (L01-L06)
are a developer-side dimension that doesn't slice cleanly along
rule-pack lines — most of our rules apply to L05-L06 anyway.

**Effort actual**: ~1 day. Mapping table authoring was the bulk of
the work — most other items reused the existing reference-validator
machinery.

#### B5. AIID (AI Incident Database) linkage

**Status**: deferred.

**What it is**: incidentdatabase.ai indexes real-world AI harm
incidents (bias, fabricated content, unsafe autonomy outcomes). Most
records are user-facing failures, not the static-instruction-surface
patterns we detect.

**Why deferred**: low signal-to-effort match. Our detection scope is
upstream of where AIID typically reports. Revisit if AIID expands
explicit MCP/agent-tool incident coverage.

### C. Alternative rule formats

#### C1. NOVA rule format adapter

**Status**: ✅ shipped in v0.17.0 alongside A2.

The .nov DSL parser, three-section handling, and condition-expression
mapping all live in `src/agent_audit/tools/nova_import.py`. See the A2
entry above for the full description — listed here separately because
the format-adapter work was the actual lift, but the deliverable is one
PR. Don't double-count in effort estimates.

#### C2. Semgrep registry — opt-in for MCP server source code

**Status**: design, scope question.

**What it is**: Semgrep ships 2,000+ community AST-pattern rules in
YAML; Pro adds 20,000+ more. Cross-file dataflow analysis on Python,
JavaScript, TypeScript, Java, Go, C#, others. Several relevant
registry packs: `p/security-audit`, `p/owasp-top-ten`, `p/python`,
`p/javascript`.

**Why interesting**: if we expand to MCP server source-code scanning
(see A5), Semgrep is the right substrate. It's AST-aware, has taint
mode, and the registry is mature.

**Why design-stage**: same scope question as A5. Wait for that
decision, then either ingest curated Semgrep packs as a fifth source
or keep `agent-audit` instruction-surface-only and document Semgrep
as a recommended companion.

**Entry points** (if approved):
- optional dependency on `semgrep` CLI, invoked as subprocess
- new audit surface `mcp_server_source`
- merge Semgrep findings via the same `RulePackRule` pipeline using
  `rule_id: semgrep.<rule-name>`, `severity` mapped from Semgrep
  severity, evidence carried through

**Effort**: 1 week if approved, mostly in surface plumbing and
calibration on top of A5's scope expansion.

#### C3. Rego / OPA for governance-style rules

**Status**: design. Already partially scoped in
`docs/ast-precision-plan.md` D-track ("Rego adoption plan").

**What it is**: Rego is OPA's policy language. Suitable for
declarative governance rules where the question is "does this config
match policy" rather than "does this string match a pattern". Examples:
MCP manifests must declare a version pin, plugin manifests must scope
permissions narrowly.

**Why interesting**: today our governance-style rules
(`unversioned_mcp.py`, `secrets_in_config.py`) are hand-written native
detectors. Rego would let users write project-specific governance as
declarative policy without a Python diff.

**Entry points**:
- already scoped in `ast-precision-plan.md` — keep this section as a
  cross-reference rather than re-expanding scope here

### D. Adversarial benchmarks (for evaluation, not rules)

These items don't add signatures; they add labelled corpora to measure
our rules' precision and recall.

#### D1. AgentDojo (existing comparison reference)

Already cited in `paper/manuscript.md`. No additional ingestion
required — keep as comparison reference.

#### D2. AgentDyn

**Status**: ✅ shipped in v0.17.0.

**What landed**: an adapter at `src/agent_audit/injection_benchmarks.py`
that harvests injection text strings from a user-cloned AgentDyn
checkout and runs the loaded rule packs against them. Implemented
together with WASP (D3) since both share the same runner machinery.

**Approach**: the adapter walks `src/agentdojo/default_suites/*/*/injection_tasks.py`
via `ast.parse`, extracts `GOAL = "..."` class attributes from
`Injection*` classes, and substitutes class-level constants like
`_RECIPIENT = "x@y.com"` into the GOAL text. f-string placeholders
like `{var}` stay as text — rule packs match prose around them.

**Why not pip-install upstream**: AgentDyn requires playwright + LLM
API keys + ~60 runtime dependencies. We only need the prompt strings
for static rule-pack measurement. AST walk over a local clone is
leaner.

**Why measure recall only, not precision**: AgentDyn ships malicious
cases; benign cases come from a separate corpus (our own benign-skill
calibration set). Pairing the two gives FP/TP numbers; the D2 adapter
focuses on the malicious side.

**Empirical baseline at v0.17.0**: 82 cases harvested from current
upstream master, **recall 93.9%** (77/82). Top contributing rule:
`nova.prompt-injection.policy-puppetry-universal-bypass` on 53 cases.
Note that the same NOVA rule that drives recall here is also FP-prone
on benign content (calibration showed it firing on documentation —
that's why M3 evaluator gates exist).

**CLI**: `agent-audit injection-benchmark --agentdyn PATH` runs the
adapter standalone; combine with `--wasp PATH` to measure both in one
invocation.

**Effort actual**: ~1 day (combined with D3).

#### D3. WASP (NeurIPS 2025)

**Status**: ✅ shipped in v0.17.0.

**What landed**: WASP loader added to the same
`injection_benchmarks.py` module as D2. Reads
`webarena_prompt_injections/configs/experiment_config.raw.json` from
a user-cloned WASP checkout, substitutes `{placeholder}` parameters
into each `instruction` string, and tags cases with `environment`
(gitlab/reddit/etc) and `exfil` boolean metadata.

**Licensing constraint**: WASP data is **CC-BY-NC 4.0** —
non-commercial. We cannot bundle the corpus. The adapter requires the
user to clone the upstream repo locally. Documented in
`docs/benchmark-corpus-howto.md` so users see the constraint before
running.

**Empirical baseline at v0.17.0**: 21 cases harvested, **recall 100%**
(21/21). Top contributing rule:
`nova.prompt-injection.job-recruitment-variation-rule` on 14 cases.
WASP's small corpus means single-case shifts move recall by ~5% — a
sensitivity worth noting when tracking regressions.

**Same out-of-scope items as D2**: no agent harness execution, no
selenium/webarena environment spin-up, no precision measurement
(needs paired benign corpus, deferred).

**Effort actual**: ~1 day (combined with D2).

#### D4. WAInjectBench

**Status**: ready.

**What it is**: prompt-injection benchmark for web agents covering
text and image modalities, with 12 detectors evaluated as baselines.

**Why useful**: gives us baseline numbers to compare against. If we
match or beat existing detector baselines on the textual subset, that
goes in the paper as a strong empirical claim.

#### D5. Gray Swan AI Red Teaming corpus

**Status**: ready.

**What it is**: labelled prompt-injection test cases from the public
red-team challenge with adversarial difficulty (some achieve 100%
attack success rate against current SOTA agents). Hard cases.

**Why useful**: stresses our rules against adversarial inputs that
bypass typical pattern matching. Expected outcome: most won't fire on
current rules, which is informative — characterizes the residual gap
that LLM-verifier or NOVA semantic sections are meant to close.

#### D6. RAG / Agent injection benchmark (arXiv 2511.15759)

**Status**: ready.

**What it is**: 847 adversarial test cases across five attack
categories (direct injection, context manipulation, instruction
override, data exfiltration, cross-context contamination).

**Why useful**: category structure aligns with our `canonical_class`
system. Direct mapping for evaluation.

## Cross-Mode Architecture Track

Items here are not pack additions or new rule sources — they're
architectural shifts that change *which rules run in which mode*. They
matter because today the forensic and static modes use disjoint
machinery: rule packs (310 rules) only feed the project scanner, and
native detectors (27) only feed the forensic scanner. Each item below
closes part of that diagonal.

### M1. Unified rule execution — close the diagonal

**Status**: ✅ shipped in v0.16.0.

**What it was**: `scanner.py` (forensic) read `_SESSION_RULES` and
`_CONFIG_RULES` only — populated by `@register_session_rule` decorators
on 27 native detectors. `project_scanner.py` (static) read
`load_all_rules()` from rule_pack_loader. The two paths shared no
machinery despite consuming the same `Finding` shape downstream.

The infrastructure for unification was already half-built: ATR rule
YAMLs declared `audit_surface: [session_user_input, session_agent_output, ...]`
fields, and `_compile_patterns()` filtered them via `static_only=True`
to keep session-only patterns out of project scans. The mirror — using
those declarations to feed forensic — was missing.

**What landed**:
- new module `session_rule_executor.py` that runs rule-pack rules
  (with at least one `session_*` audit_surface) against
  `Session.events[]` fields. Maps from declaration to runtime field:
  `session_user_input` → events with `role=user` and their `text`;
  `session_tool_args` → events with `type=TOOL_USE` and their
  `tool_input`; `session_tool_output`/`session_tool_response` → events
  with `type=TOOL_RESULT` and their `tool_result`;
  `session_agent_output` → assistant text; `session_event_stream` → all
  fields concatenated for cross-field rules
- adapter class `RulePackSessionRule` wraps each rule-pack rule as a
  `Rule` object using the existing `check_session()` contract; the
  forensic scanner just runs them alongside native detectors
- forensic scanner now produces findings from rule packs *and* native
  detectors. Empirically **78 rule-pack rules** that previously had
  zero forensic effect now run (rules declaring at least one
  `session_*` surface and carrying compiled patterns)
- per-event de-duplication: a rule declaring both `session_tool_output`
  and `session_event_stream` produces one finding per event, not two
- error isolation: a buggy rule emits a low-severity error finding
  instead of aborting the scan, mirroring the pre-existing
  `run_session_rules()` behavior
- 29 new tests in `tests/test_unified_rule_execution.py`

**What is explicitly NOT part of M1**:
- **Native detectors → static.** All 27 native detectors are written
  against `Session` / `agent_home`, not file paths. Porting any of them
  to the project scanner is per-detector work (which session events
  carry the equivalent file content? what's the per-rule prior?) and
  belongs under future native-track items, not under M1.
- **Cross-mode signal flow.** A static finding on a SKILL.md does not
  yet inform forensic confidence on a session that uses that skill.
  That's M2 — separate item, separate calibration.

**Effort actual**: 1 day (matched estimate; the
`_compile_patterns(static_only=True)` machinery already existed as
upstream infrastructure, so the executor is mostly the field-extraction
mapping plus the adapter).

### M2. Cross-mode signal flow

**Status**: design draft + D1-D5 decisions completed in v0.17.
**Phase 1 + Phase 2 shipped in v0.18.0-dev**. See
`docs/m2-cross-mode-design-draft.md` for the merged design,
`docs/m2-d1-d5-decisions.md` for the settled decisions, and
`docs/m2-source-unified-static-dynamic-design.md` for the external
source preserved for traceability.

**v0.18 Phase 1+2 implementation status**:

- ✅ Phase 1: `src/agent_audit/cross_mode/` package with
  `inventory.py` + `proximity.py` (resolver). 9 structural tags,
  4 counts, mtime-based caching. Wired silently into
  `scanner.scan` via `ScanResult.repo_inventories` field. 35 tests.
- ✅ Phase 2: 4 named correlators in `correlators.py`, linker
  contract in `linker.py`, `SignalRecord` aggregate type in
  `signal_record.py`, severity policy in `policy.py`,
  calibration corpus loader in `calibration_corpus.py`. 53 tests.
- ✅ Calibration corpus seed: 7 paired test cases at
  `benchmarks/m2-calibration-corpus/` covering all 4 correlators
  + 3 negative-case patterns. Initial seed baseline: TPR=100% (4/4),
  FPR=0% (0/3).
- ✅ M2 cross-mode CLI subcommand: `agent-audit cross-mode --forensic
  <path> [--repo-root <override>] [--output <dir>] [--format json|md|both]`.
  Per D4 — separate subcommand over saved scan outputs. 18 tests.
- ✅ Calibration corpus expansion to 20 cases per design §6.1 target.
  TPR robustness (5 variants), FPR robustness (4 variants), severity
  propagation (4 D2/D3 boundaries). **Expanded baseline metrics**:
  TPR=11/11=100%, FPR=0/9=0%. Per-correlator TP: approval_gap=5,
  fetch_surface=3, identity_persistence=2, educational=2.
- ✅ scan-project adapter — static `Finding` objects from a paired
  `scan-project` run feed correlators alongside (or instead of)
  inventory tags. Either source satisfies a correlator's static
  side; both firing produces stronger evidence. Per-correlator
  canonical_class sets in `correlators.py`; linker accepts optional
  `static_findings` kwarg; CLI gains `--scan-project <path>`. 21 tests.
- □ Phase 3: mixed-evidence clustering. Deferred to v0.19+.
- □ Phase 4: verifier prompt integration. Deferred to v0.19+.
- ✅ v0.18.0 release tag — shipped 2026-05-03.
- ✅ v0.18.1 real-data hardening patch — shipped 2026-05-04 (perf
  safeguards + vendor prune + hypothesis audit).

**Summary of the reconciled design** (kept for reference):

- **Architecture**: unified signal inventory layer between scan
  execution and reporting. Both modes emit `SignalRecord` objects
  with `origin_mode` (static/dynamic/probe/aggregate); cross-signal
  correlators consume them; clustering and verifier prompts read
  from the layer.

- **Identity model**: three strategies (content hash, name,
  project-relative path) with confidence tiers. Hash is highest
  trust; name is medium; relpath is medium-low. Implementation order:
  hash-only at v1, name fallback at v1.1, path fallback gated on
  calibration metrics.

- **Proximity ladder** (independent from identity): `repo_present` /
  `repo_present_and_same_subtree` /
  `repo_present_and_named_artifact_touched`. Each correlator declares
  the proximity tier it requires.

- **Four named correlators** ship initially:
  `repo_approval_gap_supports_autonomy_risk` (proximity 1),
  `repo_fetch_surface_supports_indirect_injection` (proximity 1),
  `repo_identity_surface_supports_persistence_risk` (proximity 2),
  `repo_educational_context_demotes_runtime_advice` (proximity 1,
  the only correlator that demotes — priority only, never severity).

- **Severity invention prohibited**: aggregate records NEVER exceed
  max(component severities). Joining is for **confidence escalation**,
  not severity invention. Two LOW signals on the same artifact stay
  LOW. Two HIGH signals stay HIGH (no CRITICAL escalation). Severity
  is a stable communication channel for downstream consumers (CI
  gates, dashboards); inflating it would break that contract.

- **Four-phase implementation plan**: (1) shared inventory + resolver,
  no UX change. (2) named correlators + calibration. (3) mixed-evidence
  clustering. (4) verifier prompt integration. Phases 1-2 fit in
  ~3 weeks; phases 3-4 deferred to v0.19+.

- **Calibration plan**: synthetic 20-pair corpus + corpus_lab
  cross-pairing experiment for false-link rate. Acceptance: ≥95%
  true-link, ≤2% false-link, ≥80% per-correlator TPR, ≤5% per-correlator
  FPR on benign repos. Below thresholds → ship in `experimental` mode
  or defer.

- **Five settled decisions (D1-D5)**: hash-only identity at v1
  (name/path fallback deferred), strict cap-at-max severity
  (priority escalation only), educational-context demotes priority
  not severity, separate `cross-mode` subcommand at v1, and a
  two-layer model for project-config interaction (finding joins run
  AFTER suppressions; structural inventory tags survive). Full
  rationale in `docs/m2-d1-d5-decisions.md`.

**Why design + decisions only in v0.17**: implementation depends on
calibration corpus assembly, which is the only remaining gate now
that D1-D5 are settled. Shipping a half-calibrated linker would
introduce false-link noise. Better to settle the design and proceed
cleanly in a subsequent release.



Items that aren't rule packs but native detector additions, motivated
by the same source review.

### N1. Tool-pinning / rug-pull detector (state-tracking)

**Status**: ✅ shipped in v0.17.0.

**What landed**: a new native detector at
`src/agent_audit/tool_pinning.py` that records the SHA-256 hash of
every MCP tool description on first scan and emits findings when those
hashes change on subsequent scans. Inspired by Invariant Labs `mcp-scan`
rug-pull detection. State-tracking detector — opt-in via CLI flag.

**Storage**: per-project baselines under
`~/.agent-audit/tool-pinning/<sha1(abspath)>.json` with `schema_version`,
`tools` map, `first_seen` / `last_seen` / `scan_count` metadata. Atomic
write via .tmp + rename. `AGENT_AUDIT_STATE_DIR` env override for
testability. Did NOT reuse `corpus_lab` after all — its snapshot format
was scan-finding-shaped, not tool-description-shaped, and the join key
is different (corpus-lab keys on cohort path, tool-pinning keys on
manifest+server+tool).

**Three finding kinds**:
- `N1.tool-pinning.description-changed` — HIGH severity, the actual
  rug-pull. Carries before-and-after preview in evidence and a hash
  prefix so the change is auditable even when the descriptions are
  long.
- `N1.tool-pinning.tool-added` — LOW severity, informational. New tool
  appeared since last scan.
- `N1.tool-pinning.tool-removed` — LOW severity, informational. Tool
  disappeared since last scan.

**Identity model**: `(manifest_relpath, server_name, tool_name)`. Two
different manifests with the same `(server, tool)` produce different
keys — no conflation. Description content is NOT in the identity, so
description changes show up as drift, not as add+remove pairs.

**Normalization before hash**: NFC Unicode normalization +
whitespace-run collapse. Zero-width characters (ZWSP, ZWNJ) survive
intentionally — a rug-pull that smuggles invisible characters into a
description IS the attack class we want to detect, so the hash must be
sensitive to them. Whitespace reformatting alone (different indentation,
extra spaces) does NOT trigger drift, because that's a common authoring
change with no semantic effect.

**Two-flag CLI design**:
- `--track-tool-pinning` enables comparison against the baseline. Off by
  default because mutating state on ad-hoc scans of arbitrary repos is
  a footgun.
- `--update-pinning-baseline` (only meaningful with the above) writes the
  current state back. Without it, drift fires on every scan — important
  for CI: the same drift firing repeatedly is the desired CI behavior,
  vs. silently accepting the change and missing it forever.

**Calibration**: skipped the originally-planned cohort-aware diff
analysis (running prompt-injection rules on the diff text). The simpler
hash-based approach already produces near-zero FPs on legitimate edits
because the baseline is per-project and per-tool — there's no
cross-project corpus drift to confuse it. Calibration of which
description-content changes should be considered "benign" is a future
follow-up if FP rate proves too high in practice.

**Test coverage**: 41 tests in `tests/test_tool_pinning_n1.py` covering
fingerprint determinism + symlink resolution, normalization preserving
ZWSP and collapsing whitespace, manifest discovery for all four common
locations (.claude/, .cursor/, .vscode/, claude_desktop_config.json),
inline-tools and server-level-description extraction shapes, malformed
JSON handling, baseline I/O including atomic write and corruption
recovery, all three finding kinds with their severity and reference
expectations, and the persistence semantics of `--update-pinning-baseline`
vs the CI-friendly default.

**Effort actual**: ~1 day (matched estimate). Most time was in the
calibration philosophy decision — choosing hash equality over diff-
content rule scanning made the implementation much simpler and the FP
rate predictable.

**What is explicitly NOT part of N1**:
- **Schema-shape rug-pulls** (input args, output type changes). Those
  are a separate detector class.
- **Server-side description changes** when the project doesn't ship the
  manifest itself. Remote MCP servers can change descriptions at
  runtime; that requires runtime probing, not file inspection.
- **First-scan baseline poisoning detection.** If the very first scan
  sees an already-poisoned description, we silently record it as the
  baseline. Mitigation is to pair N1 with the static tool-description
  rule pack scans (which DO catch poisoned text on first sight) — both
  detectors run in the same `scan-project` invocation so users get both
  signals.

### N2. Cross-server toxic-flow detector

**Status**: design. Optional substitute for A6 if mcp-audit's rules
don't ingest cleanly.

**What it is**: when a project ships multiple MCP server configs in
the same repo, look for capability-overlap patterns where one server
declares credential-read capability and another declares external-write
capability. Aguara does intra-server detection of this; we'd extend to
cross-server within one repo.

**Entry points**:
- new detector `detectors/cross_server_toxic_flow.py`
- reuses `nlu/taint.py` `TaintSource`/`TaintSink` classifications
- runs over all MCP manifests in a repo, builds a directed
  capability graph, emits a finding when sensitive-source server +
  external-sink server share a configuration

**Effort**: 1 week.

## Calibration Discipline

All pack additions follow the existing methodology documented in
`docs/architecture.md`:

1. before/after lexicon audit on the 509-repo corpus via
   `python -m agent_audit.tools.lexicon_audit`
2. for any rule with density > N hits per 1000 files, demote via
   `rule_pack_overrides.yaml` or add `exclude_patterns` — never edit
   upstream YAMLs
3. negative-control fixture for every TP/FP class transition lands in
   `tests/test_native_regression_fixtures.py`
4. grand-run delta reported in CHANGELOG with measured numbers, not
   "should improve coverage" claims

## Vendored-Data Automation

Every upstream source we ingest follows the same automation pattern,
codified in `.github/workflows/refresh-vendored-data.yml`:

1. **Vendor a snapshot** — bundle the canonical upstream file into
   `src/agent_audit/data/<source>/` along with its LICENSE. The runtime
   never reaches out to the network.
2. **Validation gate** (`.github/workflows/ci.yml`) — every PR runs
   `atlas-validate --strict` (and, as new validators ship, the same
   pattern for OWASP MCP, Gitleaks, etc.). The validators answer
   one question: *do the references inside our rules still match the
   vendored data?*
3. **Scheduled refresh** (weekly cron) — a workflow re-fetches each
   upstream source, copies the canonical files into the vendored
   location, runs the lenient validator to confirm parseability, and
   **opens a PR** if anything changed. The PR body includes:
   - previous vs new upstream version
   - whether the strict-mode validator still passes (i.e., no rule-side
     fixes needed) or whether the new release introduces drift that
     requires follow-up
4. **Human review on the PR** — author reviews the diff, the CI
   validation gate runs in strict mode against the new snapshot, and
   if strict mode fails the affected rule files get fixed in the same
   PR. No CI auto-merge.

This pattern keeps three properties simultaneously:
- **deterministic versioning**: runtime sees exactly the snapshot
  committed to the repo
- **offline-first contract**: no network calls during scans
- **drift visibility**: weekly PRs expose upstream changes within days
  of release rather than at quarterly manual refresh

When adding a new vendored source under this roadmap (A1 Aguara, A3
Gitleaks, B1 OWASP MCP Top 10, etc.), each item must:
- ship its vendored snapshot under `src/agent_audit/data/<source>/`
- ship a validator under `tools/<source>_validate.py` exposed as both
  a Python module and an `agent-audit <source>-validate` CLI subcommand
- add a job to `refresh-vendored-data.yml` that fetches and PRs
- document its refresh procedure in `data/<source>/README.md`

The B3 ATLAS validator is the reference implementation. Future items
should keep the same shape — three issue classes, lenient/strict
modes, JSON output, CLI subcommand — so reviewers don't relearn the
interface for each new source.

## License Surface

Quick reference for ingestion. Verify before merge.

| Source | License | Bundling |
|---|---|---|
| Aguara (current) | Apache-2.0 | bundle verbatim, attribution preserved |
| NOVA (Proximity) | open source — confirm exact license at ingestion | bundle if compatible |
| Gitleaks rules | MIT | bundle verbatim |
| TruffleHog regex extracts | AGPL core — open question | counsel review before bundle |
| Cisco mcp-scanner YARA | Apache-2.0 | bundle verbatim |
| mcp-audit (Adam Dudley) | Apache-2.0 | bundle verbatim |
| OWASP MCP Top 10 | CC BY-NC-SA 4.0 | reference only, not commercial-bundled rules |
| OWASP Agentic Top 10 | open | reference only |
| MITRE ATLAS data | Apache-2.0 | reference only; can vendor `ATLAS.yaml` |
| AVID | open | reference only |
| Semgrep registry | LGPL community / commercial Pro | community packs OK to invoke as CLI; do not vendor Pro rules |
| AgentDojo / AgentDyn / WASP / WAInjectBench / Gray Swan | open | benchmarks, not bundled rules |

`THIRD_PARTY_LICENSES.md` updated for each new bundled pack.

## Sequencing

Suggested execution order across two release cycles:

**v0.16 (complete):**
- ✅ B3: ATLAS auto-validation (1 day) — *shipped*
- ✅ B1: OWASP MCP Top 10 mapping module (2 days) — *shipped*
- ✅ B2: OWASP Agentic systematic backfill (1 day) — *shipped*
- ✅ A1: Aguara upgrade (1 day) — *shipped*
- ✅ M1: Unified rule execution (1 day) — *shipped*
- ✅ A3: Gitleaks pack (1 day) — *shipped*

Final state of v0.16: pack count went from 3 → 4 (Gitleaks added);
total static-applicable rules grew from 167 → **527** (3.2× increase);
references field gained OWASP MCP and full ASI coverage; CI catches
ATLAS / OWASP MCP / OWASP Agentic drift; forensic mode now consumes
rule packs alongside native detectors via the M1 unified executor.

**v0.17 (release-ready):**
- ✅ A2 / C1: NOVA pack + format adapter (1 day) — *shipped*
- ✅ M3: NOVA evaluator (semantics + llm) (1 day) — *shipped*
- ✅ N1: Tool-pinning detector (1 day) — *shipped*
- ✅ B4: AVID cross-link (1 day) — *shipped*
- ✅ D2 / D3: AgentDyn + WASP benchmark adapters (1 day, combined) — *shipped*
- ✅ M2: Cross-mode signal flow — design + D1-D5 decisions settled — *no code, ready to implement in v0.18*

All v0.17 items closed. M2 implementation cleared for v0.18 — calibration
corpus assembly is the only remaining gate before Phase 1 begins. CI runs
four reference validators (ATLAS, OWASP MCP, OWASP Agentic, AVID).
External benchmark baselines: AgentDyn 93.9% recall, WASP 100% recall.

**v0.18.0 (released 2026-05-03):**
- ✅ M2 Phase 1: shared inventory + session-to-repo resolver, no UX (1 day) — *shipped*
- ✅ M2 Phase 2: 4 named correlators + linker + calibration corpus seed (1 day) — *shipped*
- ✅ M2 cross-mode CLI subcommand (per D4 — separate subcommand) — *shipped*
- ✅ Calibration corpus expansion to 20 cases per design §6.1 target — *shipped*
- ✅ scan-project adapter — static-side findings feed correlators alongside tags — *shipped*
- ✅ v0.18.0 release tag — *shipped*
- □ M2 Phase 3: mixed-evidence clustering — *deferred to v0.19+*
- □ M2 Phase 4: verifier prompt integration — *deferred to v0.19+*

Expanded corpus baseline on 20 cases (synthetic): TPR=11/11=100%,
FPR=0/9=0%. §6.2 thresholds met. Locked as a regression guard via
`test_calibration_baseline_metrics`. Test count after v0.18.0: 693
passing, 1 skipped. CI runs four reference validators (ATLAS, OWASP MCP,
OWASP Agentic, AVID).

**v0.18.1 (released 2026-05-04, real-data hardening patch):**
- ✅ Forensic perf: hung pattern in `ATR-2026-00275` rewritten; Tier 1
  content cap (default 64KB, env override) + per-event SIGALRM timeout
  (default 5s); Tier 2 fast-keyword anchor pre-skip — *shipped*
- ✅ Inventory walker vendor-prune (initial, hardcoded): `_SKIP_DIRS`
  extended for test fixtures and documentation files — *shipped, then
  REVERSED in v0.18.3 (over-fitted to agent-audit's own dev tree)*
- ✅ Hypothesis audit document `docs/v017-v018-hypothesis-audit.md`
  inventories every v0.17/v0.18 production claim against real-data
  evidence (8 CONFIRMED, 5 ПФЗ, 4 REFUTED) — *shipped*

**v0.18.3 (released 2026-05-04, follow-up combining v0.18.2 fixes):**
- ✅ DetectionMode plumbing through `scan()` — `--mode full` CLI value
  now actually reaches `run_session_rules`/`run_config_rules`.
  v0.18.1 hypothesis audit had marked this REFUTED-pending — now
  CONFIRMED-fixed. *shipped*
- ✅ Vendor-prune defaults reversed — opt-in via `--vendor-prune` flag
  (off by default) on both `scan` and `cross-mode` subcommands. The
  v0.18.1 hardcoded skip silently dropped legitimate signal on
  projects where `benchmarks/` carries product content (e.g.
  `benchmarks/agent-tasks/AGENTS.md` for an RL training repo).
  Default behavior now scans everything that isn't unambiguous
  third-party content. *shipped*
- ✅ Cross-mode runs by default in `scan()` — reverses v0.18.0 D4
  decision once cross-mode proved stable. Two-step UX
  (`scan` then `cross-mode`) created friction without commensurate
  benefit; integration reuses Phase 1 inventory at zero perf cost.
  Standalone `cross-mode` subcommand stays for rerun-on-saved-bundle
  workflows. *shipped*
- ✅ Verbose progress mode (`-v` / `--verbose` flag) replaces D4
  "separate subcommand for debugging" rationale — timestamped
  progress output gives the same observability without the friction.
  *shipped*

Test count after v0.18.3: 748 passing, 1 skipped. All 4 validators
green. Combined with v0.18.1 perf gains, agent-audit now: scans
multi-GB Codex sessions without stalling, reaches all 1300+ rule
patterns at user-controlled detection mode, and surfaces cross-mode
correlations alongside main audit output by default.

**v0.19.0 (released 2026-05-04, real-data hardening + eval harness):**
- ✅ Critical bug fix: `_findings_by_session` reads session_id from
  evidence array (was on top level only). Pre-fix cross-mode CLI
  produced 0 aggregates on every real bundle. *shipped*
- ✅ Diagnostic warning: when cross-mode emits 0 aggregates with
  findings present, console explains possible causes. Catches
  recurrence of this class of bug. *shipped*
- ✅ Autodetect fixture-corpus shape: `_FIXTURE_CASE_DIR_PATTERN` +
  `_is_fixture_corpus_root()` recognize `benchmarks/c*/case.json`
  layout and prune that subtree without requiring `--vendor-prune`
  for the whole repo. *shipped*
- ✅ Performance: scan-session inventory trust mode. 145× speedup
  measured on synthetic 200-file repo with 252 lookups. Real-bundle
  cross-mode time should drop from 277s to ~30-50s. *shipped*
- ✅ Real-data evaluation harness: `agent-audit eval` subcommand.
  Runs scan + scan-project + cross-mode end-to-end on a corpus,
  produces TPR/FPR/perf summary, supports `--baseline` for drift
  detection and `--ci` for non-zero exit on failure. *shipped*
- ✅ Incident corpus label refinement: 4 cases got missing
  expected_findings labels per v0.18.1 hypothesis audit. Benchmark
  now reports 16/16 passed, precision 1.0, recall 1.0. *shipped*
- ✅ Benchmark materialization path fix: workspace lives under
  `$HOME/.cache/agent-audit/` instead of `/tmp/`, eliminating
  AG-04 ephemeral-filter false-skip on Linux. *shipped*

Test count after v0.19: 800 passing, 1 skipped. All 4 validators
green. The `eval` subcommand becomes the regression guard for future
work — every release should produce a comparable artifact.

**v0.20.0 (released 2026-05-04, N2 cross-server toxic flow):**
- ✅ N2 — native cross-server toxic flow detector. Fires when
  content from one MCP server's tool result flows into a different
  MCP server's tool argument carrying injection / secret / destructive
  markers. Severity escalation by payload class. Same-server and
  native-tool flows excluded. Per-pair de-dup. *shipped*
- ✅ 3 incident-corpus cases demonstrating positive (injection,
  destructive) and negative (benign cross-server) detection. *shipped*
- ✅ 36 new tests covering server-name extraction, payload
  classification, content-flow proof, end-to-end detection, dedup,
  registration. *shipped*

Test count after v0.20.0: 836 passing, 1 skipped. All 4 validators
green. Eval on incident-corpus: 19 cases, 19 passed, forensic
precision 1.0, recall 1.0.

**v0.21.0 (released 2026-05-08, A5 Cisco YARA integration):**
- ✅ Vendored 10 Cisco AI Defense YARA rules at
  `src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/`
  (Apache 2.0, attribution preserved). *shipped*
- ✅ Optional dependency: `pip install agent-audit[yara]`. Base install
  unchanged; missing yara handled gracefully without crashing.
  *shipped*
- ✅ `mcp_yara_scanner` module: parses 4 manifest shapes
  (mcpServers/tools/prompts/instructions), runs YARA at
  field-granularity, maps Cisco threat_type → agent-audit severity.
  *shipped*
- ✅ scan-project integration: each YARA match becomes a Finding
  with rule_id `A5.cisco-yara-<rule-name>`, MEDIUM confidence,
  evidence carrying field path + matched-string snippets. *shipped*
- ✅ 31 new tests, 3 incident-corpus cases (2 positive, 1 negative).
  *shipped*

Test count after v0.21.0: 867 passing, 1 skipped. All 4 validators
green. Eval on incident-corpus: 22 cases, 22 passed end-to-end,
forensic + static + correlator recall all 1.0.

**v0.22+ (deferred, eval-first cadence):**
- **A6 vs N2-extended** — data-driven decision after multi-MCP-server
  bundle eval lands. N2 fired 0 times on the v0.19 live-run bundle
  (no cross-server activity in that population) — until a bundle
  with cross-server flows is available, the comparison can't be
  made on real data.
- **A4 (TruffleHog regex)** — still gated on AGPL-3.0 vs MIT counsel
  call. Vendoring AGPL into MIT changes effective project license.
  No go-ahead until cleared.
- **C2 (Semgrep)** — descoped further now that A5 covers MCP
  source-side. Cisco mcp-scanner's YARA stack already covers the
  high-value patterns Semgrep's MCP-relevant rules would catch. May
  get re-evaluated as user-instructions ("run semgrep separately")
  rather than vendored. Re-open if A5 real-bundle eval shows
  meaningful gaps Semgrep would close.
- **D1, D4, D5, D6 (additional benchmark suites)** — driven by paper
  v2 scope. Out of release-cadence list; built on demand.
- **Per-rule parallelism for giant Codex sessions** (P1 perf). 41MB
  rollouts still take ~110s after v0.18.1 perf safeguards;
  ProcessPoolExecutor across rules could halve this. Real-bundle
  measurement in v0.19 confirmed 18% scan-time improvement from
  scan-session trust mode, but the giant-session tail remains.
- **Real-data corpus expansion** — add `expected_static_findings`
  and `expected_correlators` to existing cases as labeling matures.
  v0.21 lands the first 3 cases with `expected_static_findings`
  (the A5 cases). Each future labeled case directly closes a ПФЗ
  row in the audit doc.

## Out of Scope

To keep the boundary clear:

- runtime probing (Garak, PyRIT, AgentDojo runtime, Promptfoo runtime
  red-team) — `agent-audit` stays static. Documented as companion
  tools, not bundled.
- commercial enterprise scanners (mcpscan.ai, DefenseClaw, GitGuardian
  paid tier) — not bundleable.
- secret-validation API calls (TruffleHog's verifier mode) — not in
  static-scan scope.
- Aguara runtime mode, Cisco AI Defense API mode — those exist for
  good reason but live outside this codebase's static contract.

## Update Cadence

This document is reviewed every minor release. Items completed are
moved to CHANGELOG and to `docs/HISTORICAL_CHANGELOG.md` with measured
deltas. New items are added when the upstream landscape shifts —
notably when a new OWASP framework releases, when ATLAS publishes a
material update, or when a new pack source crosses the bar of "open
license + sustained activity + non-overlapping coverage".
