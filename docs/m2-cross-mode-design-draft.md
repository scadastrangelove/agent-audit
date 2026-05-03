# M2 — Cross-mode signal flow (design draft, reconciled)

**Status**: design draft for v0.18 or later. NO code shipped in v0.17.
This document supersedes the earlier `m2-cross-mode-design-draft.md`
and `unified-static-dynamic-design.md` — they are reconciled here.

**Author**: Sergey Gordeychik
**Last revised**: 2026-05-03
**Previous revisions**: identity-first draft (this file's predecessor),
unified-signal-inventory draft (uploaded externally).

This is a design document. **Decisions D1–D5 are settled** in the
companion memo `docs/m2-d1-d5-decisions.md`; the §11 section below
records the same decisions inline with cross-references. The
reconciled architecture below reflects the settled choices, not
optionals. Implementation can begin once calibration corpus is
available — see §6.

---

## 0. What changed in this revision

The earlier identity-first draft and the unified-signal-inventory
draft addressed **different problems**:

- **Identity-first**: "when both modes have findings on the same
  artifact, how do we recognize that and merge?"
- **Unified-inventory**: "static repo context should inform dynamic
  reasoning even when no static finding fired."

The unified-inventory framing is a strict superset. Repo tags
(`has_remote_fetch_instructions`, `has_broad_action_without_approval`)
can feed forensic reasoning even when no static rule fired — the
identity-first model can't express that. So this revision adopts the
unified-inventory architecture as the spine and merges the
identity-first material as the rigor for the join layer where
findings DO meet.

The four-phase plan, named cross-signal correlators, proximity
ladder, and verifier integration come from the unified-inventory
draft. The identity model with confidence tiers, calibration
acceptance thresholds, severity invention prohibition, and
unlinkable-subset honesty come from the identity-first draft.

---

## 1. Why M2 exists

`agent-audit` runs in two modes:

- **forensic** (`scan`): replays past agent sessions and detects
  problematic behavior in the event stream.
- **static** (`scan-project`): walks a project tree and detects
  problematic content in instruction files, MCP manifests, skills,
  plugin manifests, agent task configs.

Today these modes share a lot of plumbing — `Finding`, `Evidence`,
severity/confidence enums, `needs_llm_verification`, clustering
vocabulary — but produce **independent** outputs. A session that
exhibited an autonomous write loop is reported with no awareness of
whether the same repo ships approval-bypass instructions. A repo with
broad-action skills is reported with no awareness of whether any
session ever exercised them.

These are the same incident class. M2's purpose: when both modes
observe the same context, surface that as **stronger combined signal**
rather than as two unrelated findings — but without inventing
severity, double-counting, or guessing identity.

## 2. Core architectural choice

Adopt the **unified signal inventory** model: define a shared
intermediate layer between scan execution and reporting. Both modes
emit `SignalRecord` objects into this layer; cross-signal correlators
consume them; clustering and verifier prompts read from it.

```text
SignalRecord
  id
  origin_mode                # static | dynamic | probe | aggregate
  source_kind                # repo_file | session_window | config | env_probe
  canonical_class
  severity
  confidence
  repo_root                  # optional
  session_id                 # optional
  scope_key                  # used for proximity ladder, see §5.2
  evidence[]
  needs_llm_verification
  tags[]                     # e.g. educational, red-team, collection-scale
  supporting_signal_ids[]
```

`SignalRecord` does NOT replace `Finding`. `Finding` remains the
public output type. `SignalRecord` is the internal normalized form
between scan and report-rendering. The translation `Finding →
SignalRecord` is mechanical and lossless when the finding originates
from a single mode; cross-mode aggregate records are new.

## 3. The hard problem: identity

Cross-mode joining requires a stable identity for the artifact each
finding refers to. We have to be able to say "this static signal and
this dynamic signal are about the same thing."

### 3.1 Available identifiers

**Static side** (per `Finding.evidence[]`):

- For skill_md findings: filesystem path
- For mcp_manifest findings: `(manifest_path, server_name, tool_name)` triple
- For instruction_file: filesystem path
- For tool_description: filesystem path + manifest/server/tool triple

**Forensic side** (per `SessionEvent`):

- `session_id`, `turn_index`, `timestamp`
- `tool_name`, `canonical_tool`
- `cwd` — working directory at the time of the event
- `tool_input` — for `Read`/`Edit`, contains `file_path`
- For skill invocations: usually inferred from prompt text or `Task`
  tool args; not first-class

### 3.2 Three identity strategies

**Strategy A — content hash.** Static computes SHA-256 of artifact
body (NFC + whitespace-collapse normalization, same as N1). Forensic
computes the same hash if the body appears in any system prompt /
tool result / prompt text. Strongest bind. Limitation: forensic
sessions don't always carry the full artifact body.

**Strategy B — name-based.** Skills have names from frontmatter or
directory; MCP tools have `(server, tool)` pairs. Forensic side gets
the name from `tool_input.skill` or prompt text. Limitation: name
collisions across projects.

**Strategy C — relative-path-from-repo-root.** Both modes record a
project-relative path like `.claude/skills/git-tools/SKILL.md`.
Machine-portable but requires forensic side to resolve repo root from
`session.cwd`.

### 3.3 Decision: layered with confidence tiers

A match through strategy A is **exact** (highest trust). Through B
alone is **name match** (medium). Through C alone is **path match**
(medium-low). Multiple strategies agreeing upgrades; disagreement
downgrades or splits.

Implementation order:
1. Ship hash-only matching first. Conservative; any production
   data is high-confidence.
2. Add name fallback after calibration corpus shows acceptable
   false-link rate (§6.2).
3. Path fallback last, gated on §6.2 metrics.

### 3.4 The proximity ladder

Identity matching answers "is this the same artifact?" The proximity
ladder answers a related but separate question: **"how spatially
close was the dynamic execution to the static surface?"**

For a session with `cwd = /repo/work`:

- `repo_present`: static surface lives somewhere under `/repo`. Weakest
  signal — surface exists but session may have ignored it.
- `repo_present_and_same_subtree`: session `cwd` is at or under the
  directory that contains the static surface. Stronger — session
  literally operated in the area where the surface lives.
- `repo_present_and_named_artifact_touched`: a tool event in the
  session referenced the artifact by path or name. Strongest —
  session demonstrably interacted with the artifact.

The proximity ladder is independent from the identity strategy. They
combine: a hash-match (identity A) at proximity 3 (`named_artifact_touched`)
is the strongest possible cross-mode signal. A name-match (B) at
proximity 1 (`repo_present` only) is much weaker.

Cross-signal correlators declare which proximity tier they require to
fire. `repo_approval_gap_supports_autonomy_risk` (§5.1) requires
proximity 1 minimum (the surface need only exist in the repo for the
joint signal to matter). `repo_identity_surface_supports_persistence_risk`
requires proximity 2 (the session has to be operating in the same
subtree as the identity-rewrite instructions).

## 4. New internal components

```
src/agent_audit/cross_mode/
├── __init__.py
├── inventory.py          # build_repo_signal_inventory()
├── identity.py           # CrossModeArtifact + extraction
├── proximity.py          # repo_present / same_subtree / artifact_touched
├── correlators.py        # named cross-signal rules (§5)
├── linker.py             # combines inventory + identity + proximity
└── policy.py             # severity combination, demotion rules
```

### 4.1 Repository inventory builder

```python
def build_repo_signal_inventory(repo_root: Path) -> RepoSignalInventory:
    """Build the static signal inventory for a repo without rendering
    a full project report. Reuses project_scanner machinery, skips
    markdown rendering, returns SignalRecord list plus tag set:
      has_skills, has_remote_fetch_instructions,
      has_broad_action_without_approval, has_identity_rewrite,
      has_mcp_manifests, has_plugin_manifests,
      educational_heavy, red_team_heavy
    Cached by (repo_root, mtime_fingerprint).
    """
```

### 4.2 Session-to-repo resolver

```python
def resolve_session_repo(session_cwd: str) -> Optional[Path]:
    """Walk up from cwd looking for .git or instruction files.
    Returns None if no repo found or cwd is empty/missing.
    Honesty contract: returning None is a normal outcome, not an error.
    Many sessions are unlinkable; the linker handles that gracefully."""
```

### 4.3 The linker contract

```python
def link_signals(
    static_inventory: RepoSignalInventory,
    dynamic_records: List[SignalRecord],
) -> List[SignalRecord]:
    """Returns the input records plus zero or more new aggregate
    records of origin_mode='aggregate'. Aggregate records reference
    their components via supporting_signal_ids. Severity capped at
    max(component severities) — never higher. Demotion via
    educational-context tag is the only exception (§7.2)."""
```

## 5. Cross-signal correlators (initial set)

Four named correlators ship in the first implementation phase. Each
declares its required static-side condition, dynamic-side condition,
proximity tier, and output policy.

### 5.1 `repo_approval_gap_supports_autonomy_risk`

**Static condition**: inventory tag `has_broad_action_without_approval`
OR a static finding in canonical class
`broad_external_action_without_approval`.

**Dynamic condition**: session finding from
`{C3.autonomy-with-exfil-chain, resource.unbounded-loop,
file.destructive-without-backup}`.

**Proximity required**: 1 (`repo_present`). The bypass instructions
need only exist in the repo for the joint signal to matter; the
session doesn't have to demonstrably read them.

**Output**: emit a supporting `SignalRecord` (origin_mode=aggregate,
canonical_class same as the dynamic finding's). DO NOT duplicate the
base dynamic finding. Increase verification priority by one notch.

### 5.2 `repo_fetch_surface_supports_indirect_injection`

**Static condition**: inventory tag `has_remote_fetch_instructions`
OR static finding in canonical class
`remote_fetch_or_install_expands_trust_boundary` OR MCP tool
poisoning surface findings.

**Dynamic condition**: session finding `AI-06.indirect-prompt-injection-vector`.

**Proximity required**: 1.

**Output**: aggregate `SignalRecord` with explanatory rationale
"runtime fetch behavior occurred in a repository that also ships
fetch-mediated instruction surfaces". Increase verification priority.

### 5.3 `repo_identity_surface_supports_persistence_risk`

**Static condition**: inventory tag `has_identity_rewrite` OR static
finding in canonical class `identity_rewrite_persistent_persona`.

**Dynamic condition**: session finding from
`{AI-04.persistence-write, config.mutation-future-session-effect}`.

**Proximity required**: 2 (`same_subtree`). Persistent persona
instructions matter most when the session is operating where they
live.

**Output**: aggregate record. DO NOT escalate severity (HIGH
persistence stays HIGH; the static support increases confidence and
verification priority but not severity).

### 5.4 `repo_educational_context_demotes_runtime_advice`

**Static condition**: inventory tag `educational_heavy` OR
`red_team_heavy` (calibration corpus, benchmark repo, training
material).

**Dynamic condition**: session finding `advice.dangerous-recommendation`
at MEDIUM or below.

**Proximity required**: 1.

**Output**: the dynamic finding gets a `context_demoted` tag and its
verification priority drops. Severity is NOT modified. The finding
still appears in the report; it's flagged as context-sensitive so
reviewers know this was advice given in an educational frame, not in
production.

This is the only correlator that demotes. The demotion is **not a
severity reduction** — it's a priority/attention reduction. The
severity bound (§7.1) is preserved.

## 6. Calibration

This determines whether M2 is worth shipping. The four correlators
above are first-class examples; the architecture has to demonstrate
acceptable false-link and false-fire rates before more correlators
get added.

### 6.1 Required corpus

Three sources:

1. **Synthetic paired corpus**: ~20 fabricated test cases. Each
   carries a project tree with known static surface + a recorded
   session that exercised the surface. Ground truth: each pair
   should produce exactly one aggregate record.

2. **`corpus_lab` reuse for false-link rate**: the existing 500-repo
   regression suite. Pair each project with a synthetic forensic
   session that operates in **a different repo's context**. The
   linker should produce zero aggregate records; any aggregate is a
   false link.

3. **Real recorded sessions**: from the maintainer's own dev work,
   capture cases where a known SKILL.md change coincided with a
   session in that repo. Hard to assemble but high-fidelity.

### 6.2 Acceptance thresholds

**Linker quality** (does it correctly identify same-artifact pairs?):
- ≥95% true-link rate on the synthetic 20-pair corpus
- ≤2% false-link rate on the corpus_lab cross-pairing experiment

**Correlator quality** (do the named rules fire usefully?):
- Each correlator's true-positive rate measured on labeled cases
  per correlator (target: ≥80%)
- False-positive rate on benign repos (target: ≤5%)

Below these thresholds, M2 introduces more confusion than it
removes. Below 95% / 2%, ship in `experimental` flag-gated mode and
gather production data; below 80% / 5% on individual correlators,
defer those specific correlators rather than the whole release.

### 6.3 Honest unlinkable subset

Some signals are **fundamentally unlinkable** with available data:

- Session recorded without `cwd` (older Codex CLI versions)
- Skill body inlined into the user prompt with no name in context
- MCP manifest loaded from a global config, not from project tree

The linker must be honest about these. A `--report-unlinked-by-reason`
flag groups unlinked signals by why they didn't link. Users decide
whether to re-record sessions with better context or accept the
unlinkable subset.

## 7. Output policy

### 7.1 Severity invention is prohibited

Aggregate records NEVER have a higher severity than the maximum of
their components. Joining is for **confidence escalation**, not
severity invention. Two LOW signals on the same artifact stay LOW.
Two HIGH signals stay HIGH (do not escalate to CRITICAL).

This is a hard bound. The only modulation in the other direction is
correlator 5.4's context_demoted tag, which adjusts **priority**
(reviewer attention) without changing severity.

Why: severity is a stable communication channel between agent-audit
and downstream consumers (CI gates, dashboards, paper reports). Tools
that gate on `severity >= HIGH` shouldn't see joint-signal
escalation produce HIGH findings that wouldn't have existed
independently.

### 7.2 Three output flows

When the linker runs, three things happen:

1. **Aggregate signal records** emitted with origin_mode='aggregate'
   and supporting_signal_ids pointing to components. These appear in
   reports under a new `Cross-signal support` section, separate from
   primary findings.

2. **Component findings** stay in their original sections. Backwards
   compatible. Optionally `--suppress-paired-individual` hides them
   when an aggregate exists, but it's off by default.

3. **Verifier prompts** consume the aggregate context. When the LLM
   verifier evaluates a finding that has supporting cross-signals,
   the prompt includes the supporting context (repo tags, named
   artifacts, proximity tier). This is where M2 most directly
   improves false-positive suppression.

### 7.3 Backwards compatibility

The JSON output format gains optional fields on `Finding` / `SignalRecord`:

- `cross_signal_support: List[str]` — supporting signal IDs (empty for
  unjoined findings)
- `repo_context_tags: List[str]` — populated when `cwd` resolved to a
  repo with an inventory
- `proximity: int` — 0 (none) / 1 / 2 / 3, populated for cross-mode
  signals only

Old consumers ignoring unknown fields are unaffected. Pre-M2 reports
have no aggregate records and no new fields populated; nothing
breaks.

## 8. Phasing

### Phase 1 — Shared inventory, no new UX

- Factor `build_repo_signal_inventory` out of `project_scanner`.
- Add `resolve_session_repo` from `session.cwd`.
- Attach repo tags to forensic scan results internally.
- No report changes yet except an internal debug field.

**Risk gate**: Phase 1 ships invisibly. Smoke test: existing
`scan` output shouldn't change. Failure mode is a regression here, so
this is the most carefully-tested phase.

### Phase 2 — Cross-signal correlators

- Implement the four correlators in §5.
- Aggregate records render under `Cross-signal support` section.
- Severity invention prohibited; verification priority adjusted.
- Calibration corpus assembled; metrics measured.

**Risk gate**: §6.2 thresholds. Below them, defer the correlators
that fail individually, ship the rest in experimental mode.

### Phase 3 — Unified clustering

- Allow clustered issue instances to contain mixed
  static+dynamic+probe evidence.
- Report layer renders mixed clusters under existing canonical
  classes.
- No new output sections — the existing clustering UX absorbs the
  new evidence.

**Risk gate**: existing clustering tests must still pass. Adding
mixed-evidence support shouldn't change cluster identity for
single-mode findings.

### Phase 4 — Verifier integration

- LLM verifier prompts include cross-signal context (repo tags,
  supporting signals, proximity tier) for findings that have it.
- Most directly improves FP suppression for `advice.dangerous-recommendation`,
  `AI-06.indirect-prompt-injection-vector`, and exfiltration chains.

**Risk gate**: A/B comparison of verifier verdicts with vs. without
cross-signal context. If FP rate doesn't improve, deprioritize this
phase.

## 9. What M2 does NOT attempt

- **No CLI merge.** `scan` and `scan-project` stay separate
  user-facing commands.
- **No runtime hooks.** Linker is post-hoc on saved reports + live
  scans, not an agent-runtime callback.
- **No heuristic identity invention.** When data is genuinely
  ambiguous, signals stay unlinked. No guessing.
- **No retroactive linkage on saved reports.** Old report files
  don't have inventory/proximity fields; M2 does not re-run scans
  to add them.
- **No replacement for project-config overrides.** User-curated
  per-project FP suppressions in `agent-audit.yaml` apply BEFORE
  the linker's finding-to-finding join layer runs (D5 in §11).
  Structural inventory tags survive suppressions; suppressed
  findings do not participate as supporting components.
- **No severity invention from joining.** §7.1.

## 10. Risks

**R1 — Identity model too loose, false-link rate balloons.**
*Mitigation*: ship hash-only first (§3.3); name/path fallback gated
on §6.2 calibration.

**R2 — Identity model too tight, miss-link rate balloons.**
*Mitigation*: hash matching for new sessions (where runtime can log
artifact body); name fallback for sessions where body isn't logged.

**R3 — Severity inflation from cross-signal.** A LOW static + HIGH
dynamic on the same artifact could be reasoned as a stronger
finding, inflating noise.
*Mitigation*: §7.1 cap-at-max bound. Aggregate records add
**confidence**, not severity.

**R4 — Double counting in metrics.** If aggregate records count
toward the same totals as component findings, top-line counts inflate.
*Mitigation*: aggregate records counted separately under
`cross_signal_support`. Top-line counts use original findings only.

**R5 — Caching cost / latency.** Building inventories for every
forensic session that has cwd is expensive on large monorepos.
*Mitigation*: inventory cache keyed by `(repo_root, mtime_fingerprint)`.
Per-session cost is one stat call when the cache is warm.

**R6 — Calibration corpus too small to validate.** Paired
(static, forensic) cases are hard to fabricate cleanly.
*Mitigation*: synthetic 20-pair for true-link; corpus_lab cross-pairing
for false-link.

**R7 — User confusion from new section.** Adding a `Cross-signal
support` section on top of existing dynamic + static reports
increases cognitive load.
*Mitigation*: aggregate records render with explicit `[CROSS-SIGNAL]`
prefix and visible supporting_signal_ids. The section is
collapsible/optional in the markdown.

## 11. Settled decisions (D1–D5)

These decisions are settled for v1 of M2. Full rationale and
implementation consequences live in `docs/m2-d1-d5-decisions.md`;
this section is the inline reference.

- **D1 — Identity strategy scope at v1**: **hash-only matching.**
  Name fallback and path fallback are explicitly deferred to v1.1+
  pending calibration data. The package is internally consistent —
  M2 derives most of its value from repo tags + proximity tiers +
  correlators rather than from weak identity matching, so conservative
  hash-only joins are sufficient for v1.

- **D2 — Severity combination policy**: **strict cap-at-max.**
  Aggregate records carry `severity = max(component severities)`; no
  escalation. Cross-mode support raises priority (review queue,
  verifier queue, issue rank) — never severity. Mental model:
  *severity = maximum direct evidence; priority = severity plus
  corroboration*.

- **D3 — Educational-context demotion**: **priority only, never
  severity.** §5.4 correlator sets `context_demoted` tag and reduces
  ranking; the underlying severity label is preserved. M2 does not
  introduce a second severity-rewrite policy on top of the
  educational-context demotion that already exists in `scan-project`.

- **D4 — CLI surface**: **separate `cross-mode` subcommand over
  saved outputs.** No auto-invocation inside `scan` at v1. Explicit
  execution boundary aids debugging ("did the dynamic detector
  change, or did the linker change?") and makes rollout reversible.
  Recommended shape:
  `agent-audit cross-mode --forensic <bundle> --repo-root <path>`.
  Auto-invoke deferred to a later release once stability is
  established.

- **D5 — Project-config override interaction**: **two-layer model.**
  - **Finding-to-finding joins** run AFTER suppressions.
    Suppressed findings do NOT participate as supporting components
    of any aggregate record. User curation is sovereign; suppression
    rules cannot be bypassed via cross-mode resurrection.
  - **Structural inventory tags** (e.g. `has_skills`,
    `has_mcp_manifests`, `has_remote_fetch_instructions`) survive
    suppressions because they describe **structural facts** about
    the repository, not findings. A repo either has MCP manifests
    or it doesn't; suppressing a finding ABOUT one of those manifests
    doesn't change that fact. These tags can still inform forensic
    interpretation through tag-level correlators.
  - The hard rule: an aggregate record must NEVER cite a suppressed
    finding ID as support. It MAY cite structural tags. This
    preserves both user trust in suppression and the analytic value
    of structural context.

## 12. Effort estimate

- Phase 1 (inventory + resolver + caching): 1 week
- Phase 2 (correlators + calibration corpus): 2 weeks
- Phase 3 (mixed clustering): 1 week
- Phase 4 (verifier integration): 1 week + verifier A/B time

Realistic v0.18 ship target: phases 1-2 only, 3 weeks of focused
work. D1-D5 are settled (see §11), so the remaining gate is
calibration corpus assembly, which can run in parallel with Phase 1
implementation. Phases 3-4 in v0.19+.

---

End of design draft. The next step is the Phase 1 implementation
plan, which can begin now that D1-D5 are settled.

## Appendix — what each component draft contributed

For traceability:

- **Architecture spine** (unified signal inventory, four-phase plan,
  named correlators, verifier integration): unified-static-dynamic-design.md
- **Identity model rigor** (three strategies + confidence tiers):
  m2-cross-mode-design-draft.md
- **Proximity ladder** (repo_present / same_subtree /
  named_artifact_touched): unified-static-dynamic-design.md
- **Severity invention prohibition** (cap-at-max bound):
  m2-cross-mode-design-draft.md
- **Calibration acceptance thresholds** (≥95% / ≤2%):
  m2-cross-mode-design-draft.md
- **Educational-context demotion** (correlator 5.4):
  unified-static-dynamic-design.md
- **Caching by mtime fingerprint**:
  unified-static-dynamic-design.md
- **Honest unlinkable-subset framing**:
  m2-cross-mode-design-draft.md
- **Backwards-compat JSON contract**: both drafts agreed.
