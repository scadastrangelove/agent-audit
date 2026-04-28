# AST Precision Plan

> Status: planning · Owner: CyberOK agent-audit · Last revised: 2026-04-21

This document consolidates a three-round design discussion about introducing
AST-level parsing, intermediate representations, graph analytics, and
declarative policy engines into agent-audit. It intentionally **does not**
commit to a product-wide rearchitecture. Instead, it proposes a staged,
reversible, evidence-driven adoption path that borrows specific tools into
specific pain points, while keeping the existing rule packs and detector
architecture intact.

The plan name is narrow on purpose: **AST Precision**. The first and most
concrete goal is measurable FP reduction on text-heavy instruction files.
Everything else — IR, graphs, runtime tracing, Rego — is either
subordinated to that goal, scoped to a single detector family, or parked
until real empirical triggers arrive.

## Context

agent-audit v0.11.1 already contains:

- 296 rule-pack rules loaded from YAML (ATR, Aguara, Cisco PromptGuard)
- Field-aware applier that distinguishes session-event and static-file rules
- Two native detectors (identity_redefinition, no_approval_model) derived
  from v5 corpus audit, calibrated on 5 targets
- Collection-scale aggregator that collapses cohort-wide replication into
  one architectural finding
- Regression corpus: hermes godmode (TP), jaktestowac (TN2), anthropic
  skills (clean), codex babysit-pr (autonomy TP), composio connect-apps
  (broad-action TP)

The pain points that motivate this plan are empirical:

- `atr.excessive-autonomy.high-risk-tool-invocation-without-human-confirmation`
  fires 18× on anthropic/skills — a reference corpus. All matches are on
  documentation prose describing what skills can do, not on actual agent
  actions.
- `atr.privilege-escalation.shell-metacharacter-injection-in-tool-arguments`
  fires on `;` and `|` inside markdown prose, not inside shell code blocks.
- Native detector `no_approval_model` currently counts approval markers
  across the whole file including code fences, which can contain variable
  names like `confirm` or `approve`.

The common thread is that our regex matchers treat markdown files as flat
text. Introducing markdown-level structure (heading paths, code fences,
section semantics) is the cheapest way to recover precision on exactly
these failures, without discarding 296 existing rules.

## Decisions

### Adopt now

**D-1. Markdown AST prefilter for native detectors (v0.12).**

Use markdown-it-py to parse SKILL.md and related files into a token stream.
Consume headings, code fences, and paragraph boundaries; do not build a
product-wide IR. Native detectors (identity_redefinition, no_approval_model)
consume two derived views:

- `text_without_code` — concatenated prose, code fences removed
- `code_blocks_by_lang` — dict of language → list of fence contents

Rule packs continue to operate on raw text; the prefilter applies only to
native detectors for now. This is reversible: if the experiment fails, we
delete the prefilter and native detectors revert to current behavior.

Acceptance criteria:

- Precision delta measured on 5-target regression (before/after)
- Coverage delta measured on the same regression: do we detect anything
  new, e.g. identity language inside a specific `## Red Team Instructions`
  section that previously got averaged out?
- Delta is the ship criterion. If either metric moves materially in a
  positive direction, promote the prefilter. If neither moves, revert.

### Adopt conditionally

**D-2. tree-sitter-bash for fenced shell code (v0.13).**

Partially completed in v0.14.0 via `knowledge/rule_surface_classifier.py`.
Instead of parsing shell AST, we route rules by category: shell-oriented
rules (privilege-escalation, external-download, hardcoded_secrets) match
only against `code_blocks_by_lang` (the concatenated code fences from the
markdown AST), while prose-oriented rules (prompt-injection, agent-
manipulation, excessive-autonomy) match only against `text_without_code`.

Result on 10-target suite at `--min-severity medium`: 775 → 307 medium+
findings (-60% further reduction beyond v0.13), zero TP regression.

Full tree-sitter-bash integration is deferred — the category-based
routing closed the "shell metachar in prose" FP class, which was the
original driver for D-2.

**D-3. Feature extraction cache (v0.14).**

Between D-2 and longer-term architecture, introduce a normalized feature
layer that stores per-file derived features once per scan:

- `text_without_code`
- `code_blocks_by_lang`
- `heading_paths`
- `shell_commands` (when tree-sitter is in play)
- `suspicious_urls`
- `approval_markers`
- `scope_hints`

Detectors consume features rather than raw text. This is the bridge to
a future IR without committing to one.

Acceptance criteria: no new detection, purely a refactor. Ship when
D-1 and D-2 have both proven their cost.

### Adopt much later

**D-4. Rego for ASAMM maturity rollup (v1.0).**

Rego replaces nothing in detection. It runs over aggregated findings as a
compliance engine: "control X at L2 iff no CRITICAL findings AND
approval_markers.count > N AND …". This is the natural home for Rego:
policy over structured data.

Upstream rule packs remain in their original YAML. No conversion.

Acceptance criteria: maturity rollup feature reaches design stage;
open-design-questions in ROADMAP backlog are resolved; Rego catalog
written against real v0.x finding streams, not synthetic specs.

### Do not adopt now (but keep on radar)

**D-5. Security IR as platform-wide refactor — rejected for v0.x.**

However, `small tactical IR` for individual detector families is fine
and often unavoidable. The difference is scope: a micro-IR inside
`no_approval_model` with nodes like `section`, `code_block`,
`header_path`, `contains_shell_command`, `contains_approval_language`
is acceptable and may ship as part of D-1 or D-3. A product-wide
`allow/deny/delegate/persist/...` IR breaks the scanner → detector →
aggregator → report flow and is deferred until post-v1.0.

**D-6. Graph engine (NetworkX or rustworkx) — deferred.**

No current finding requires graph traversal. Collection-scale aggregator
is group-by, not graph. Native detectors are per-file classifiers. However,
graph-shaped data model in naming and mental model is encouraged —
"parent of", "read by", "derived from" relations should be named even when
stored as simple references. This prevents a conceptual break when graph
triggers arrive.

**D-7. Subgraph isomorphism / motif matching — research mode, not shipping.**

Even the source plan acknowledges this is late-stage. We don't have motifs
yet; building matching for nonexistent motifs is premature.

**D-8. OpenTelemetry + W3C PROV — deferred until runtime auditor exists.**

OTel and PROV make sense for session/runtime provenance. agent-audit scan
and scan-project are static. When we build the runtime auditor mentioned
in ROADMAP, PROV becomes the natural reference model for
`instruction file → agent read → action → side effect` traces.

**D-9. Surface adapters for agent-task config directories — deferred.**

Discovered via grand-run (100 repos, 2026-04-21). Example case:
`OpenBMB/AgentVerse` — instruction_inventory reports 232 categorized
files under `/agentverse/tasks/**/*.yaml` (prompt templates for multi-agent
task pipelines), but scan-project returns 0 findings because our file
classifier only recognises SKILL.md / AGENTS.md / MCP manifests.

The fix is not a new rule — it's a new surface adapter:
- recognise `/tasks/**/*.yaml`, `/agents/**/*.yaml`, `/prompts/**/*.yaml`
  that contain system-prompt-like string fields
- classify them as a new surface `agent_task_config`
- route rule-pack rules with `audit_surface: tool_description` or
  a new `audit_surface: agent_task_config` to these files

Scope and risk: adding a file classifier is structural, not a tweak.
Probably a 2-day effort including calibration on AgentVerse + similar
multi-agent frameworks (AutoGen, CrewAI). Deferred until subtree-scan
mode lands so we can scope experiments to known directories.

## Graph triggers backlog

Per the critique: we don't build graph infrastructure without concrete
triggers. A graph layer becomes legitimate when at least three of the
following five conditions hold simultaneously:

- **G-1. Cross-file precedence conflicts.** Two instruction files
  contradict each other and we need to identify the conflict; today we
  only detect per-file content.
- **G-2. Instruction-read → action linkage.** Runtime data shows an agent
  reading file X then performing action Y; we want to render that as an
  audit trail, not a per-event list.
- **G-3. Parent/subagent delegation chain.** Multi-agent systems where
  agent A spawns B which spawns C, and a finding needs to be attributed
  to the spawn chain.
- **G-4. Runtime provenance over multiple artifacts.** A secret leaks
  from file A through tool B into output C; the path matters, not the
  endpoints.
- **G-5. Motif accumulation.** We have a corpus of known-bad patterns
  expressed as small subgraphs and want to search for them across new
  repositories.

Until three of these exist, the implementation stays NetworkX-free.
Once they exist, adoption follows the NetworkX → rustworkx path from the
original plan.

## Metrics

All intermediate steps (D-1, D-2, D-3) must ship with a before/after
comparison on the 5-target regression suite. Both metrics are reported:

- **Precision delta.** How many previous findings were removed as FP?
  Breakdown by rule_id.
- **Coverage delta.** How many new findings appeared? New findings are
  individually reviewed: real positives count for coverage, regressions
  on known positives are blockers.

Shipping criterion: positive precision delta OR positive coverage delta,
with no regression on true positives.

## Non-goals

- Do not rewrite 296 rule-pack rules. Upstream compatibility matters more
  than internal consistency.
- Do not build an IR before we have detector-family-specific evidence of
  what primitives are actually needed.
- Do not introduce graph algorithms, model checkers, or policy engines
  that lack a concrete immediate win on existing pain.

## Relationship to other roadmap items

- Maturity rollup (v1.0 candidate) depends on D-4.
- Runtime auditor (unscheduled) would unlock D-8.
- Collection-scale aggregator (shipped in v0.11.0) is orthogonal — it
  operates on the finding stream, not on AST.
- 296 rule packs continue to grow independently. AST Precision does not
  block rule imports.

## Decision revision history

- 2026-04-21: initial consolidation from three-round design discussion
  (ambitious plan → engineering critique → critique-of-critique).
  All adopted positions reflect the second critique.
- 2026-04-21 (v0.13.0 prep): added D-9 surface-adapter gap for agent-task
  config directories, discovered via grand-run on 100 repos. Severity
  overrides (rule_pack_overrides.yaml) and educational-context suppressor
  shipped from the same analysis. Noise reduction at --min-severity
  medium on 10-target suite: 1303 → 775 (-41%), zero TP regression.
- 2026-04-21 (v0.14.0): P0 sprint completed — adaptive cohort thresholds,
  rule-surface routing (D-2 partially closed without tree-sitter),
  native-centric reranking. Cumulative noise reduction: 1303 → 307
  (-76%), 16 native TP preserved, 16 hot files surfaced for triage.
