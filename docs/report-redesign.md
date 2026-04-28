# Report Redesign

Status: proposed  
Owner: agent-audit  
Last revised: 2026-04-21

## Why This Exists

The current report bundle is technically rich but easy to misread.

Empirical review of `./reports-v14.4` found:

- the primary human-readable artifact is the raw markdown report
- the raw markdown overstates risk unless the reader also opens
  `*-verified.json`
- verified outcomes are not surfaced in the main markdown
- raw JSON does not expose the same grouped view the markdown presents
- config/probe truths and noisy behavior hypotheses are mixed together

This document proposes a redesign that keeps the current scanner and
verification pipeline, but makes the output bundle read correctly on first
open.

The goal is not a new detection engine. The goal is:

1. make the bundle truthful by default
2. make the verified layer first-class
3. preserve raw data without making it the primary narrative
4. make machine and human outputs represent the same structure

## Problems In The Current Bundle

### P1. Raw report is the default narrative

Today the folder opens to:

- `audit-<stamp>.md`
- `audit-<stamp>.json`
- `audit-<stamp>-verified.json`
- `patches/`

The markdown report is raw scanner output. It is useful, but it is not the
best final narrative when verification exists.

Consequence:

- users will anchor on `687 findings`
- users will read `Sessions of concern`
- users may never open the verification file that later downgrades many items

### P2. Verification is not visible enough

`*-verified.json` is valuable, but currently it is:

- JSON only
- sampled / batch-oriented
- not linked back into the main markdown narrative

Consequence:

- real config truths and noisy behavior-layer findings are not separated
- readers cannot quickly see what survived review

### P3. Human and machine views do not match

The markdown groups findings into:

- sessions of concern
- quiet sessions
- config and environment findings

But raw JSON mostly exposes:

- installations
- sessions
- findings

There is no machine-readable equivalent of the grouped markdown sections.

Consequence:

- the grouped report is not reproducible from JSON without re-running report
  logic
- downstream diffing and dashboards are harder than necessary

### P4. Heterogeneous finding classes are mixed

The report currently mixes:

- local config truths
- local probes
- behavior hypotheses
- autonomy windows
- unverified-completion claims

These classes have very different confidence characteristics.

Consequence:

- the report feels louder than the actual high-confidence risk picture

### P5. Patches are disconnected from the main conclusion

Patches exist and are useful, but they are not integrated into the report
summary. The user has to discover them separately.

## Design Principles

1. Raw findings remain available, but are no longer the default story.
2. If verification exists, the primary summary must reflect it.
3. Verified and unverified findings must be visually separated.
4. Confirmed local configuration risks must be surfaced before session noise.
5. Markdown and JSON must represent the same report structure.
6. The bundle must be understandable by a human in under two minutes.

## Proposed Bundle Layout

Replace the current loose file set with a structured report bundle.

Example:

```text
reports-2026-04-21-194807/
  README.md
  manifest.json
  summary.json
  verified-summary.json
  findings-raw.json
  findings-verified.json
  sessions-of-concern.json
  config-findings.json
  local-probes.json
  behavior-findings.json
  patches/
    patch-summary.md
    ...
```

### File roles

- `README.md`
  - primary human-readable report
  - if verification exists, this is a verified-first summary
- `manifest.json`
  - metadata about the bundle and what files exist
- `summary.json`
  - machine-readable top-level report summary
- `verified-summary.json`
  - machine-readable verification rollup
- `findings-raw.json`
  - all raw findings
- `findings-verified.json`
  - all verified outcomes with links back to raw finding ids
- `sessions-of-concern.json`
  - the same grouped section shown in markdown
- `config-findings.json`
  - local config and environment findings only
- `local-probes.json`
  - non-session local truths like SSH key checks
- `behavior-findings.json`
  - session-behavior findings, explicitly marked as noisier

Compatibility:

- keep writing legacy `audit-*.json` and `audit-*.md` for one release
- add a pointer inside them saying the new bundle is canonical

## Proposed README Structure

`README.md` should become the canonical report.

### Section order

1. `Executive Summary`
2. `Confirmed Local Risks`
3. `Verified Behavioral Findings`
4. `Uncertain / Needs Review`
5. `Noisy / Raw Hypothesis Classes`
6. `Sessions Of Concern`
7. `Patchable Findings`
8. `Method / Coverage`
9. `Appendix: Raw Counts`

### 1. Executive Summary

Always start with:

- installations discovered
- sessions parsed
- raw findings count
- verified findings reviewed
- true positive / false positive / uncertain counts
- top confirmed risks
- whether patches are available

Example:

```md
## Executive Summary

- Agents discovered: Claude Code (164), Codex (122)
- Sessions parsed: 286
- Raw findings: 687
- Findings reviewed by verifier: 232
- Verified outcome: 24 true positive, 188 false positive, 20 uncertain
- Confirmed local risks: dangerous Claude setting, missing secret deny rules, unencrypted SSH keys
- Patch bundle available: 2 config patches
```

This prevents the reader from anchoring on raw counts alone.

### 2. Confirmed Local Risks

This section should surface things that correspond to current local state:

- config truths
- passphrase-free key probes
- version vulnerabilities
- actual local policy gaps

These are the highest trust findings and should come first.

Each item should include:

- current severity
- source of truth path
- whether verifier reviewed it
- patch availability

### 3. Verified Behavioral Findings

Only findings with verifier outcome:

- `true_positive`
- or `uncertain` with adjusted severity >= medium

These should be grouped by session, but clearly marked as:

- behavior-layer findings
- based on session evidence, not current local file state

### 4. Uncertain / Needs Review

This is where `uncertain` findings belong.

They are worth attention, but they should not be mixed with confirmed truths.

### 5. Noisy / Raw Hypothesis Classes

This section should explicitly call out noisy families, for example:

- `behavior.unverified-completion-claim`
- autonomy-window informational traces
- heuristic exfil chains that often need context

Do not bury this fact. State it directly.

### 6. Sessions Of Concern

This can keep the current session-card view, but should:

- use verified severity if available
- annotate each cluster with raw count and verified status summary

Example:

```md
**behavior.unverified-completion-claim** — 110 raw, 8 reviewed
- verifier: 1 true positive, 5 false positive, 2 uncertain
```

### 7. Patchable Findings

If patches exist, summarize them in the main report:

- what file they touch
- whether finding was verified true positive
- whether patch is safe / needs review

### 8. Method / Coverage

Briefly explain:

- what classes are static truths vs session heuristics
- whether verification was full or sampled
- which verifier was used
- cost spent

### 9. Appendix: Raw Counts

Keep the raw counts and full flat list here, not near the top.

## Proposed JSON Contract

### `summary.json`

This should be the machine-readable top-level truth.

Suggested schema:

```json
{
  "generated_at": "...",
  "bundle_version": 2,
  "source_scan": {
    "sessions_parsed": 286,
    "installations": 5,
    "raw_findings": 687
  },
  "verification": {
    "enabled": true,
    "verifier": "claude-cli",
    "mode": "batch",
    "reviewed_findings": 232,
    "true_positive": 24,
    "false_positive": 188,
    "uncertain": 20,
    "total_spend_usd": 1.576
  },
  "confirmed_local_risks": 5,
  "verified_behavioral_findings": 19,
  "uncertain_findings": 20,
  "patch_count": 2,
  "files": {
    "readme": "README.md",
    "raw_findings": "findings-raw.json",
    "verified_findings": "findings-verified.json",
    "sessions_of_concern": "sessions-of-concern.json",
    "patches": "patches/patch-summary.md"
  }
}
```

### `findings-raw.json`

Current raw finding schema is close enough. Add:

- `finding_id`
- `finding_class`
- `report_group`

Suggested fields:

- `finding_class`: `config`, `probe`, `behavior`, `autonomy_window`, `session_chain`
- `report_group`: `confirmed_local`, `behavioral`, `uncertain`, `raw_only`

### `findings-verified.json`

Current `*-verified.json` should be upgraded from a verifier ledger to a
joinable report artifact.

Add:

- `finding_id`
- `raw_severity`
- `final_severity`
- `verdict`
- `rationale`
- `report_group`
- `session_id`
- `source_paths`

This file should support rendering the final markdown without requiring the
raw markdown report.

### `sessions-of-concern.json`

Export the same grouped cards used by markdown:

```json
[
  {
    "session_id": "...",
    "agent": "claude_code",
    "cwd": "...",
    "raw_findings": 230,
    "verified_true_positive": 4,
    "verified_uncertain": 2,
    "verified_false_positive": 17,
    "clusters": [
      {
        "rule_id": "behavior.unverified-completion-claim",
        "raw_count": 110,
        "verified": {
          "true_positive": 1,
          "false_positive": 8,
          "uncertain": 3
        }
      }
    ]
  }
]
```

This closes the current human/machine mismatch.

## Severity Model In The Report

A report severity should not always equal detector severity.

Introduce:

- `raw_severity`
- `report_severity`

Rules:

- if verifier says `false_positive`, `report_severity = low`
- if verifier says `uncertain`, use `adjusted_severity`
- if verifier says `true_positive`, use `adjusted_severity`
- if no verifier result exists, keep raw severity but mark `unverified`

This lets markdown say:

```md
severity: high (verified)
severity: medium (uncertain)
severity: critical (raw, unverified)
```

That is much more honest than showing only the raw detector severity.

## Finding Classes

The report should classify findings up front.

Suggested classes:

- `config`
  - current local agent config truth
- `probe`
  - local host probe that checks real state
- `behavior`
  - interpretation of session text/tool traces
- `window`
  - autonomy-chain / graph-level findings
- `meta`
  - report integrity / verifier pipeline findings

This is the most important narrative upgrade after verified-first ordering.

## Patches Integration

Patch generation is useful and should be surfaced in the primary report.

Add per patch:

- `patch_id`
- `target_file`
- `finding_id`
- `verified_status`
- `safe_to_apply`: `true/false`
- `review_notes`

Then render a compact section:

```md
## Patchable Findings

- `config.claude-code.permissive.dangerous-mode`
  - target: `~/.claude/settings.json`
  - verifier: true positive
  - patch: available

- `config.claude-code.permissive.no-secret-deny`
  - target: `~/.claude/settings.json`
  - verifier: true positive
  - patch: available
```

## CLI / Implementation Plan

### Phase 1: safe additive redesign

Do not break current files yet.

Keep:

- `audit-<stamp>.md`
- `audit-<stamp>.json`
- `audit-<stamp>-verified.json`

Add:

- `README.md`
- `summary.json`
- `findings-raw.json`
- `findings-verified.json`
- `sessions-of-concern.json`
- `config-findings.json`
- `behavior-findings.json`

### Phase 2: flip default narrative

Once stable:

- `README.md` becomes canonical
- `audit-<stamp>.md` becomes raw appendix or compatibility artifact

### Code touch points

#### `src/agent_audit/report.py`

Current responsibilities are too narrow:

- renders raw markdown
- renders raw JSON
- writes both

Refactor into:

- raw serialization
- grouped summary building
- bundle writing

Suggested split:

- `report_raw.py`
- `report_bundle.py`
- `report_markdown.py`

#### `src/agent_audit/cli.py`

Current verify command writes `*-verified.json` separately.

Change so that after scan + verify:

- a single bundle manifest is updated
- verified outcomes are merged into summary artifacts
- patches are linked into the bundle summary

#### `src/agent_audit/report_aggregation.py`

This already contains useful grouping logic.

Reuse it for:

- markdown
- `sessions-of-concern.json`

Do not keep session-card logic markdown-only.

#### `src/agent_audit/patch_generator.py`

Add machine-readable patch index output:

- `patches/patch-index.json`

Then `README.md` can render patches without scraping markdown.

## Minimal Acceptance Criteria

The redesign is successful if:

1. opening the report folder and reading `README.md` gives the correct risk
   picture without opening raw JSON
2. verified outcomes are visible in the first screenful
3. `sessions-of-concern.json` exists and matches markdown cards
4. confirmed local config truths appear before noisy behavior hypotheses
5. patches are visible from the main report

## Non-Goals

This redesign does not require:

- changing detector logic
- changing verifier prompts
- removing raw report artifacts
- introducing a database

It is a packaging and truth-ordering redesign, not a new scanner.

## Recommended First Cut

If only one small change ships in the next version, it should be this:

> When `*-verified.json` exists, generate a `README.md` that starts with a
> verified summary block and lists confirmed local risks before raw session
> findings.

That one change would fix most of the current bundle readability problem.
