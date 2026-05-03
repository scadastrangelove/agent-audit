# Unified Static + Dynamic Signal Design

## Status

`agent-audit` already has partial convergence between static repository scanning and dynamic forensic scanning, but it does **not** yet implement a fully unified signal model where static repository artifacts directly inform forensic reasoning.

Today:

- `scan` analyzes local agent sessions, configs, and optional environment probes.
- `scan-project` analyzes repository-local instruction surfaces such as `SKILL.md`, `AGENTS.md`, MCP manifests, plugin manifests, and agent-task YAML.
- Both modes already share:
  - the `Finding` / `Evidence` data model
  - severity and confidence enums
  - native-vs-imported signal distinction
  - `needs_llm_verification`
  - report-layer grouping and markdown/json outputs
  - canonical-class clustering on the project side

What is still missing:

- no first-class "repository signal inventory" is generated for forensic scans
- no join between `session.cwd` and static instruction surfaces in that repo
- no cross-mode scoring where static findings raise or lower dynamic suspicion
- no shared canonical issue instances spanning both repo artifacts and live session behavior

So the short answer is:

**Partially implemented, but not yet in the most useful way.**


## Problem

The current split is operationally convenient but analytically artificial.

A real agent session often depends on repository-local artifacts:

- `AGENTS.md`
- `CLAUDE.md`
- `SKILL.md`
- MCP manifests
- plugin manifests
- task YAML or prompt-bearing config

Those artifacts are static, but they change the meaning of runtime behavior.

Examples:

- A forensic session showing autonomous write loops is more concerning if the repo also contains broad approval-bypass or identity-rewrite instructions.
- A network egress chain is more concerning if the repo ships prompt-bearing remote template loads or fetch-on-run skills.
- A suspicious behavior cluster can become easier to explain if the repo includes explicit dangerous examples, benchmark content, or clearly labeled red-team skills.

Today these signals are inspected in different commands and different reports. That means the analyst has to manually correlate them.


## Design Goal

Keep `scan` and `scan-project` as separate user-facing modes, but make them run on top of one shared internal model:

- **artifact-backed static signals**
- **session-backed dynamic signals**
- **environment/probe signals**
- **cross-signal issue instances**

This should improve:

- forensic triage quality
- false-positive suppression
- confidence calibration
- explainability
- future verifier prompts


## Non-Goals

- Do not replace `scan-project` with session replay.
- Do not require a repo checkout for all forensic scans.
- Do not merge all findings into one giant undifferentiated list.
- Do not make static signals auto-escalate runtime findings without explanation.


## Current State

### Already shared

The following components are already usable across both modes:

- `Finding`, `Evidence`, `Severity`, `Confidence`
- report-side verification flags
- native detector semantics
- file-level evidence snippets
- clustering vocabulary through canonical classes
- markdown/json report emission patterns

### Static-only pieces

`scan-project` currently adds capabilities that `scan` does not consume:

- surface classification
- rule-pack routing by surface
- educational-context demotion
- canonical issue clustering
- collection-scale aggregation
- repo-level security profiles
- curated signature curation layers

### Dynamic-only pieces

`scan` currently adds capabilities that `scan-project` does not consume:

- session parsing
- autonomy-window segmentation
- taint-flow chains
- tool normalization
- behavior detectors
- environment probes
- LLM verifier workflow

### Missing bridge

The key missing layer is:

**a shared artifact inventory and signal graph that can be attached to a forensic session when its `cwd` points at a repository or workspace.**


## Proposed Architecture

Introduce a shared intermediate layer called:

## Unified Signal Inventory

This layer represents all machine-generated evidence in a common structure before final reporting.

Suggested model:

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
  scope_key
  evidence[]
  needs_llm_verification
  tags[]                     # e.g. educational, red-team, collection-scale
  supporting_signal_ids[]
```

This does not replace `Finding`. It is the normalized cross-mode layer that later becomes:

- report bundle entries
- clustered issue instances
- verifier packets
- reviewer packets


## Core Idea

When `scan` encounters a session with a meaningful `cwd`, it should optionally build a **static artifact inventory** for that workspace and attach it as contextual evidence.

That gives us:

1. dynamic findings from the session
2. static findings from repo-local instructions
3. cross-signal joins between them


## New Internal Components

### 1. Repository Inventory Builder

Add a lightweight internal function:

```text
build_repo_signal_inventory(repo_root) -> RepoSignalInventory
```

This is not the full public `scan-project` report. It is a smaller reusable internal product containing:

- artifact files discovered
- static findings
- native static findings
- canonical classes
- repo-level tags:
  - has_skills
  - has_remote_fetch_instructions
  - has_broad_action_without_approval
  - has_identity_rewrite
  - has_mcp_manifests
  - has_plugin_manifests
  - educational_heavy
  - red_team_heavy

It should reuse the current `project_scanner` machinery where possible, but skip heavy markdown/report rendering.


### 2. Session-to-Repo Join

Add a helper:

```text
resolve_session_repo(session.cwd) -> repo_root | None
```

Possible strategies:

- nearest ancestor containing `.git`
- fallback to current working directory if it contains instruction files
- optional override through explicit CLI flag later

If a repo root is found:

- build or load cached `RepoSignalInventory`
- attach repo tags to the session analysis context


### 3. Cross-Signal Correlators

Introduce a new family of rules that consume both static and dynamic inputs.

Examples:

#### Example A: static approval bypass raises dynamic autonomy risk

If:

- session has `C3.autonomy-with-exfil-chain`, `resource.unbounded-loop`, or destructive-without-backup
- repo inventory has `broad_external_action_without_approval`

Then:

- emit a supporting cross-signal record
- do not duplicate the base finding
- increase review priority / verification priority

#### Example B: static remote-fetch instruction strengthens indirect injection suspicion

If:

- dynamic session has `AI-06.indirect-prompt-injection-vector`
- repo inventory contains remote template loading, fetch-before-run, or plugin/tool poisoning signals

Then:

- attach a cross-signal explanation:
  - "runtime fetch behavior occurred in a repository that also ships fetch-mediated instruction surfaces"

#### Example C: static educational markers weaken dangerous recommendation severity

If:

- dynamic session has `advice.dangerous-recommendation`
- repo inventory is strongly educational / benchmark / red-team labeled

Then:

- reduce escalation priority
- keep the finding but flag it as context-sensitive


### 4. Shared Canonical Issue Instances

Extend clustering so an issue instance can contain mixed evidence:

- repo-file findings
- session-window findings
- probe findings

Example issue instance:

```text
canonical_class = remote_fetch_or_install_expands_trust_boundary
primary = AI-06.indirect-prompt-injection-vector (session)
supporting =
  - ATR fetch-on-run skill match (repo file)
  - MCP tool poisoning surface (repo file)
```

This is the main architectural payoff: issue instances become analytically stronger and less redundant.


## Execution Model

### `scan`

Current:

- discover agent homes
- parse sessions
- run config rules
- run session rules
- write bundle

Proposed:

- discover agent homes
- parse sessions
- run config rules
- run session rules
- for sessions with repo-like `cwd`:
  - resolve repo root
  - build/load repo signal inventory
  - run cross-signal correlators
- group into unified issue instances
- write bundle with:
  - confirmed / behavioral / context / probe
  - optional static-supporting context

### `scan-project`

Current:

- walk repo files
- run static rules and native file checks
- cluster findings
- build security profile

Proposed:

- keep same user behavior
- internally emit `SignalRecord` inventory
- optionally expose a machine-readable inventory sidecar for future reuse by `scan`


## Reporting Changes

### Forensic bundle

Add a new section:

- `Static repository context`

Possible contents:

- repo root
- instruction artifacts found
- top static canonical classes
- whether the session ran in a repo with:
  - approval bypass surfaces
  - identity rewrite surfaces
  - remote fetch/install surfaces
  - educational / red-team context

Add a new grouping:

- `cross_signal_support`

This keeps static support separate from primary dynamic findings.

### Project bundle

No major UX change required.

Optional later addition:

- emit `signal-inventory.json`


## Verification Changes

Once unified signals exist, verifier prompts can become much better.

Instead of asking an LLM only about one finding, we can give:

- the runtime finding
- the session excerpt
- the supporting static artifact summary
- the repo context tag set

This should help especially with:

- `advice.dangerous-recommendation`
- `AI-06.indirect-prompt-injection-vector`
- exfiltration chains


## Minimal Implementation Plan

### Phase 1: Shared inventory, no new UX

- factor a reusable repo-inventory builder out of `project_scanner`
- add repo-root resolution from `session.cwd`
- attach static repo tags to sessions
- no report changes yet except debug/internal fields

### Phase 2: Cross-signal correlators

- add 3-5 cross-signal rules
- emit supporting records, not primary alerts
- ensure no double counting

### Phase 3: Unified clustering

- allow clustered issue instances to include mixed static/dynamic evidence
- keep report groups separate

### Phase 4: Verifier integration

- use static-supporting context in forensic verification prompts
- optionally bring verifier-style triage to `scan-project`


## Suggested Initial Cross-Signal Rules

These are the best starting candidates:

1. `repo_approval_gap_supports_autonomy_risk`
- static: `broad_external_action_without_approval`
- dynamic: `C3.autonomy-with-exfil-chain`, destructive-without-backup

2. `repo_fetch_surface_supports_indirect_injection`
- static: remote fetch/install / remote template / MCP tool poisoning
- dynamic: `AI-06.indirect-prompt-injection-vector`

3. `repo_identity_surface_supports_persistence_risk`
- static: identity rewrite / persistent persona instructions
- dynamic: `AI-04.persistence-write`, config mutation, future-session effects

4. `repo_educational_context_demotes_runtime_advice`
- static: benchmark / red-team / educational heavy
- dynamic: dangerous recommendation


## Risks

### 1. Double counting

If cross-signal records are emitted as ordinary findings, counts will inflate.

Mitigation:

- mark them as `supporting`
- exclude from raw top-line counts
- include them in issue-instance support only

### 2. Over-escalation

Static instructions may be present in a repo but not actually used in the session.

Mitigation:

- distinguish:
  - `repo_present`
  - `repo_present_and_same_subtree`
  - `repo_present_and_named_artifact_touched`

### 3. Cost and latency

Running full `scan-project` logic for every session could be expensive.

Mitigation:

- build cached repo inventories keyed by repo root + mtime fingerprint
- scan only once per repo per run


## Recommendation

This is worth implementing.

The current split between `scan` and `scan-project` is fine as a CLI boundary, but it is leaving analytic value on the table. The strongest next step is not to merge the commands. It is to build a shared **repo signal inventory** and let forensic analysis consume it as context.

That gives us the best of both worlds:

- separate user workflows
- shared internal evidence model
- better triage
- better verifier prompts
- less manual analyst correlation


## Short Answer

Is this already implemented?

- **Partly:** shared finding objects, native/static detectors, common verification flags, and clustering vocabulary already exist.
- **Not yet:** static repository signals do not currently feed forensic reasoning as first-class inputs.

So the right next move is a **unified static + dynamic signal layer**, not a CLI merge.
