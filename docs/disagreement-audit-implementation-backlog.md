# Disagreement Audit Implementation Backlog

## Purpose

This document converts the trio disagreement audit into an implementation
backlog for `agent-audit`.

Source audit artifacts:
- `/Users/serg/Documents/ASAMM/audits/trio-analysis-2026-04-27/product-impact-from-disagreement-audit.md`
- `/Users/serg/Documents/ASAMM/audits/trio-analysis-2026-04-27/non-unanimous-deep-assessment.md`
- `/Users/serg/Documents/ASAMM/audits/trio-analysis-2026-04-27/trio-analysis.md`

The goal is not to "make reviewers agree." The goal is to tighten the
product boundary where disagreement revealed one of four concrete problems:

1. weak evidence packaging
2. wrong canonical class
3. over-broad detector semantics
4. over-claiming report language

## Executive Read

Highest-value changes, in order:

1. stop presenting `category-root` collection aggregates as ordinary
   artifact-backed issue instances
2. narrow `broad-action-without-approval` into operationally distinct
   sub-classes and add a project-scan class for persistent capability
   expansion via config/tool registration
3. add documentary/setup suppressors so native and imported findings stop
   over-firing on integration guides and planning heuristics
4. make exact-pattern rule titles and report text match the evidence that
   actually fired
5. add family-level dedup plus evidence-strength metadata so downstream
   datasets can distinguish "real issue", "weak packet", and "wrong class"

## Findings That Drive This Backlog

Most informative disagreement cases:

- `TPFPV1-0089`: real risky surface, wrong class
- `TPFPV1-0094`, `0096`, `0114`: integration/MCP docs, not live action
  workflows
- `TPFPV1-0063`, `0090`, `0092`: bounded planning or CI guidance,
  over-read as autonomy/action
- `TPFPV1-0251`: real pattern, weak aggregate packaging
- `TPFPV1-0286`: real SSRF-adjacent surface, title over-claims the exact
  matched behavior
- `TPFPV1-0068`, `0113`, `0171`, `0213`, `0332`, `0373`: category-root
  aggregates are poor adjudication units in their current form

## P0

### P0.1 Separate aggregate signals from artifact-backed issue instances

Problem:
- `category-root` records had the weakest agreement in the trio audit.
- Current `#collection-scale` outputs are emitted as normal `Finding`
  objects, clustered as normal canonical issues, and rendered in the same
  report lanes as repo/file-backed findings.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/collection_scale.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/finding_dedup.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/cli.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/corpus_lab.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_collection_scale.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_finding_dedup.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_corpus_lab.py`

Tasks:
- Introduce a distinct output kind for collection-wide signals:
  - `aggregate_signal`
  - `artifact_backed = false`
  - `promotion_required = true`
- Stop clustering `#collection-scale` findings into the same issue-instance
  stream as normal file-backed findings by default.
- Preserve aggregate signals in JSON and Markdown, but render them in a
  separate section such as `Collection-scale signals`.
- Require representative excerpts in aggregate output:
  - at least `N` example files
  - excerpt snippets for each representative file
  - no more bare path-only packets for reviewer-facing datasets
- Add an explicit `scope_type` or `evidence_kind` field at the JSON level.

Acceptance criteria:
- `project-findings.json` distinguishes `artifact_backed_issue_instances`
  from `aggregate_signals`.
- `project-findings.md` no longer mixes category-root aggregates into
  `Issue Instances To Review First`.
- adjudication packets can exclude aggregate signals or include them under a
  dedicated rubric without lossy post-processing.

Audit cases addressed:
- `0068`, `0113`, `0171`, `0213`, `0332`, `0373`

### P0.2 Add evidence-strength and class-fit metadata end-to-end

Problem:
- Current report output does not distinguish:
  - direct artifact evidence
  - partial class fit
  - exact-pattern hit with semantic over-claim
  - aggregate-only evidence

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/finding_dedup.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_finding_dedup.py`

Tasks:
- Add machine-readable fields:
  - `evidence_strength: artifact | excerpt | aggregate`
  - `classification_confidence: exact-pattern | structural | inferred`
  - `class_fit: strong | partial | weak`
  - `packet_limitations: []`
- Populate these fields for:
  - native findings
  - imported rule-pack findings
  - clustered issue instances
  - aggregate signals
- Surface them in Markdown summaries and JSON sidecars.

Acceptance criteria:
- a reviewer can tell, without external notes, whether a finding is
  artifact-backed, aggregate-only, exact-pattern, or structurally inferred
- `TPFPV1-0089`, `0251`, and `0286` can be represented as
  `partial class fit` or `weak aggregate packaging` instead of only TP/FP

Audit cases addressed:
- `0089`, `0251`, `0286`

### P0.3 Reduce semantic over-claim in exact-pattern findings

Problem:
- Some imported rules correctly match a risky pattern family but overstate
  the precise behavior in the title/summary.
- The clearest example is `aguara.ssrf-cloud.aws-imds-token-request`,
  which can fire on metadata endpoint references without a full IMDSv2 token
  request flow.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/knowledge/rule_packs/external/aguara/ssrf-cloud/SSRF_004-aws-imds-token-request.yaml`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/knowledge/rule_pack_overrides.yaml`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_rule_surface_classifier.py`
- add targeted regression test under `/Users/serg/Documents/ASAMM/agent-audit/tests/`

Tasks:
- Tighten the IMDS rule so `imdsv2_token_request` requires actual token-flow
  markers, not only metadata endpoints.
- If upstream parity is intentionally kept, then demote the local display
  title/summary to something the evidence supports, such as
  `AWS metadata endpoint reference`.
- Review other exact-pattern rules with the same failure mode and encode
  display-title overrides where needed.

Acceptance criteria:
- `0286` no longer appears as a strong-fit token-request finding when the
  artifact only references metadata endpoints
- exact-pattern titles in reports are auditable against the matched pattern

Audit cases addressed:
- `0286`

## P1

### P1.1 Split `broad-action-without-approval` into narrower native classes

Problem:
- One detector currently covers three different situations:
  - live external action workflows
  - setup/integration/configuration guidance
  - capability expansion via config or tool registration

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/detectors/no_approval_model.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/finding_dedup.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/docs/architecture.md`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_native_regression_fixtures.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_finding_dedup.py`

Tasks:
- Keep the current detector as a recall layer if necessary, but emit
  narrower rule IDs based on structural cues.
- Proposed project-scan native classes:
  - `asamm.AD-02.live-external-action-without-approval`
  - `asamm.AG-02.persistent-capability-expansion-via-config`
  - `asamm.AD-02.integration-surface-without-approval-context`
    only if retained after suppressor pass; otherwise suppress
- Update canonical mapping so config-surface expansion no longer collapses
  into `broad_external_action_without_approval`.

Acceptance criteria:
- `0088` stays positive under a live-action class
- `0089` becomes a class-fit win instead of a TP-under-the-wrong-class
- `0094`, `0096`, `0114` stop landing in the same class as live action
  skills

Audit cases addressed:
- `0088`, `0089`, `0094`, `0096`, `0114`, `0121`

### P1.2 Add first-class documentary/setup suppressors

Problem:
- Several disagreements came from planning, research, setup, and
  integration documents that mention risky capabilities without
  operationalizing them.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/detectors/no_approval_model.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/knowledge/markdown_features.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/knowledge/capability_lexicon.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/knowledge/rule_pack_overrides.yaml`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_native_regression_fixtures.py`
- add dedicated suppressor tests under `/Users/serg/Documents/ASAMM/agent-audit/tests/`

Tasks:
- Add documentary/setup scoring or suppressor features for:
  - `When to use`
  - `Installation`
  - `Configuration`
  - `Troubleshooting`
  - `Example`
  - `Research/plan before coding`
  - defensive checklists / audit personas
- Allow native detectors to demote or suppress when:
  - imperative action is example-only
  - approval/checklist language is dominant
  - the artifact is teaching integration rather than invoking it
- Mirror the same context into imported-rule post-processing where exact
  patterns are otherwise too eager.

Acceptance criteria:
- `0063`, `0090`, `0092`, `0094`, `0096`, `0114` are no longer high-signal
  positives
- documentation-shaped artifacts are still available for signature
  harvesting mode if needed, but do not dominate developer-facing output

Audit cases addressed:
- `0063`, `0090`, `0092`, `0094`, `0096`, `0114`

### P1.3 Bridge project-scan config mutation with session-scan config mutation

Problem:
- `mcp_config_mutation.py` already models session-level capability-graph
  mutation well, but project-scan native findings do not yet have a clean
  equivalent for static instruction/config artifacts.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/detectors/mcp_config_mutation.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/detectors/no_approval_model.py`
- or new file:
  `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/detectors/config_surface_expansion.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/project_scanner.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_mcp_config_mutation.py`
- add project-scan regression tests

Tasks:
- Extract shared semantics for "persistent capability expansion via config"
  between session and project scan.
- Detect static artifacts that:
  - register MCP servers
  - persist tool enablement
  - mutate agent config or approval defaults
  - normalize external skill/plugin definitions into native execution
    surfaces
- Keep this separate from generic persistence and generic broad action.

Acceptance criteria:
- a file-level equivalent of `0089` lands in a native class that matches the
  actual risk
- session and project findings share vocabulary and remediation framing
  instead of diverging

Audit cases addressed:
- `0089`

## P2

### P2.1 Add family-level dedup and mirrored-artifact suppression

Problem:
- The same artifact families recur across corpus categories and mirrored
  collections, creating repeated disputes and overstating prevalence.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/finding_dedup.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/collection_scale.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/corpus_lab.py`
- add new helper if needed, for example:
  `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/family_fingerprint.py`
- add regression tests under `/Users/serg/Documents/ASAMM/agent-audit/tests/`

Tasks:
- fingerprint near-duplicate skill/instruction families
- allow suppressor inheritance or mirrored-family collapsing
- keep raw hits intact, but add an issue-family view for prevalence analysis

Acceptance criteria:
- repeated mirrored artifacts do not inflate adjudication packets or
  prevalence summaries by default
- research outputs can report both raw counts and family-deduped counts

### P2.2 Add disagreement-driven regression fixtures and gates

Problem:
- The trio audit surfaced a compact set of high-value edge cases.
- Those cases should become permanent regression fixtures, not only a memo.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_native_regression_fixtures.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/tests/test_collection_scale.py`
- `/Users/serg/Documents/ASAMM/agent-audit/benchmarks/incident-corpus/`
- optionally new corpus notes under `/Users/serg/Documents/ASAMM/agent-audit/docs/`

Tasks:
- encode the disagreement cases as permanent fixtures:
  - file-level TP controls
  - file-level FP controls
  - aggregate packaging controls
  - exact-pattern title-fit controls
- add pass/fail expectations that track:
  - label stability
  - class-fit stability
  - aggregate-vs-artifact separation

Acceptance criteria:
- future releases cannot silently regress into the same disagreement modes
- release notes can cite explicit disagreement-fixture coverage

### P2.3 Improve report language for research and reviewer handoff

Problem:
- Human-readable reports still emphasize detector phrasing more than
  evidence strength and issue semantics.

Modules:
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/project_report.py`
- `/Users/serg/Documents/ASAMM/agent-audit/src/agent_audit/cli.py`
- `/Users/serg/Documents/ASAMM/agent-audit/docs/report-redesign.md`
- tests in `/Users/serg/Documents/ASAMM/agent-audit/tests/`

Tasks:
- add explicit report sections:
  - `Artifact-backed issue instances`
  - `Aggregate signals requiring representative evidence`
  - `Partial class-fit findings`
- show top-line issue interpretation before raw detector listings
- expose packet limitations in reviewer-facing bundles

Acceptance criteria:
- a reviewer can understand what requires manual caution without reading the
  code or external methodology notes
- report output naturally supports TP/FP dataset construction

## Recommended Delivery Order

### Milestone A
- `P0.1`
- `P0.2`
- `P0.3`

Why first:
- this fixes the biggest honesty and packaging issues without changing the
  detector frontier too much

### Milestone B
- `P1.1`
- `P1.2`
- `P1.3`

Why second:
- once reports distinguish weak packets from strong ones, class-splitting
  and suppressor work become easier to validate

### Milestone C
- `P2.1`
- `P2.2`
- `P2.3`

Why third:
- this turns the disagreement audit into durable product infrastructure and
  better research outputs

## Non-Goals

These changes should not:
- delete raw rule hits
- hide imported pack behavior
- treat every documentation mention as benign
- collapse all overlap into a single issue type

The product should preserve:
- raw detector view
- clustered issue view
- aggregate signal view

Each of these serves a different truth.

## Definition of Done

This backlog is complete when all of the following are true:

- category-root aggregates are no longer confused with artifact-backed issue
  instances
- the `broad-action-without-approval` family no longer carries setup docs,
  live remote action, and config mutation under one class
- reports can explicitly state evidence strength and class fit
- exact-pattern titles no longer overstate the matched behavior
- disagreement cases from the trio audit are encoded as regression fixtures
