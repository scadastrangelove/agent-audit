# M2 Cross-mode calibration corpus

Synthetic paired test cases for M2 Phase 2 calibration. Each case
carries a project tree + a session.jsonl + a `case.json` with
expected ground truth in the `m2_expected` block.

**Status**: 20 cases (the §6.1 design target). Initial 7-case seed
shipped in v0.18 Phase 2 alongside the linker; expanded to 20 cases
in the same milestone with TPR robustness, FPR robustness, and
severity-propagation variants.

**Baseline metrics on the expanded 20-case corpus** (locked via
`test_calibration_baseline_metrics`):

- True-positive rate (TPR): 11/11 = 100% (≥95% §6.2 threshold)
- False-positive rate (FPR): 0/9 = 0% (≤2% §6.2 threshold)
- Per-correlator TP counts: approval_gap 5, fetch_surface 3,
  identity_persistence 2, educational_demotion 2

## Why synthetic

Real paired (static, forensic) cases are hard to assemble cleanly:

- a real session that exercises a known-bad SKILL.md, recorded with
  enough metadata to verify ground truth, is rare
- the maintainer would have to reproduce the issue on their own
  hardware to capture the trace
- privacy: real sessions often carry CWD paths that leak environment

Synthetic cases let us write the ground truth alongside the
fixture. They're not a replacement for real cases — Phase 2 should
add real cases as they become available — but they're sufficient
to exercise the four named correlators and the negative-case
guards.

## Layout

```
m2-calibration-corpus/
├── README.md                        ← this file
├── c1-approval-gap-autonomy-link/
│   ├── case.json                    ← metadata + m2_expected
│   ├── session.jsonl                ← Claude Code session log (fake)
│   └── project/                     ← fake project tree
│       ├── .git/HEAD                ← marker so resolver finds the repo
│       ├── AGENTS.md                ← instruction surface that triggers tags
│       └── (other files...)
├── c2-fetch-surface-injection-link/
└── ...
```

Each session.jsonl uses `cwd: "__CASE_PROJECT__"` as a placeholder.
The corpus loader substitutes the absolute path of the case's
`project/` subdirectory at load time so the resolver can find the
repo.

## Cases

20 cases ship in this corpus, organized by intent:

### Original seed: TPR primaries (4 cases)

One canonical true-link case per correlator. Each exercises the
primary pattern the correlator was designed for.

- **c1 — `repo_approval_gap_supports_autonomy_risk`**
  AGENTS.md ships approval-bypass language; session ran an
  autonomous write loop. Proximity 1.

- **c2 — `repo_fetch_surface_supports_indirect_injection`**
  SKILL.md tells agent to `curl | sh`; session was hijacked by an
  injection in the fetched content and exfiltrated SSH keys.
  Proximity 1.

- **c3 — `repo_identity_surface_supports_persistence_risk`**
  CLAUDE.md rewrites the agent's persona; session writes that
  persona to global settings.json (future-session-effect).
  Proximity 2.

- **c4 — `repo_educational_context_demotes_runtime_advice`**
  Repo is red-team training material; session contains a
  dangerous-recommendation finding. Per D3, severity preserved;
  priority demoted; finding gets `context_demoted` tag.

### Original seed: TN primaries (3 cases)

- **c5 — clean baseline.** Vanilla repo, vanilla pytest run. No
  tags, no findings, no correlator.

- **c6 — tags but no matching dynamic finding.** Repo has
  `has_broad_action_without_approval` tag, but session was a single
  benign `git status`. Static side fires; dynamic side doesn't.
  Correlator must require BOTH per design §5.1.

- **c7 — dynamic finding but no matching tag.** Autonomous write
  loop in a clean repo with no tags. Correlator must NOT invent a
  static partner.

### TPR robustness expansion (5 cases)

Pattern variants that exercise the same correlators with different
syntactic forms. If tag derivation is too literal, these cases catch
it.

- **c8 — approval_gap variant.** Uses "auto-approve" / "no approval
  is needed" language instead of "skip the approval prompt". Dynamic:
  resource.unbounded-loop. Verifies tag derivation handles syntactic
  variation; verifies the §5.1 rule set covers unbounded-loop.

- **c9 — fetch_surface variant.** Uses `wget -qO- | bash` instead of
  `curl | sh`. Verifies tag pattern set covers wget + bash + zsh +
  fish, not just curl + sh.

- **c10 — identity_rewrite variant.** Uses "act as" / "override your
  default role" patterns. Verifies the §5.3 tag pattern set covers
  multiple identity-override syntactic forms.

- **c11 — educational variant.** Uses `tutorials/` paths to trigger
  `educational_heavy` (the >50% threshold) instead of `red_team_heavy`.
  Verifies §5.4 fires on EITHER educational or red-team tags.

- **c12 — multi-correlator.** Single session triggers BOTH
  approval_gap AND fetch_surface as INDEPENDENT aggregate records.
  Verifies the linker doesn't merge them or skip one.

### FPR robustness expansion (4 cases)

Cases close to positive but NOT-quite. Catch over-eager correlators
that might fire on weakened conditions.

- **c13 — ambient curl|sh, no injection.** Repo's README has a
  legitimate `curl ... | sh` install instruction; session never
  produces an injection finding. Tag fires alone is not enough — §5.2
  must require both static AND dynamic conditions.

- **c14 — vendored SKILL.md.** A package inside `node_modules/` ships
  its own SKILL.md with bypass language. Vendor pruning must skip it
  so external dependencies don't contaminate the host repo's risk
  profile. Tags should be empty.

- **c15 — has_skills only.** Repo ships a benign formatter skill;
  session has an autonomy finding. The §5.1 correlator must
  specifically require `has_broad_action_without_approval`, NOT just
  any skill presence. Verifies precise tag selectivity.

- **c16 — identity tag + non-matching dynamic.** Identity-rewrite
  tag fires, but session's autonomy finding is
  C3.autonomy-with-exfil-chain (in §5.1's set, NOT §5.3's). Verifies
  precise per-correlator dynamic-side rule_id membership.

### Severity propagation expansion (4 cases)

D2 and D3 boundary cases. Verify severity invariants under joining.

- **c17 — D2: HIGH+HIGH stays HIGH.** Two HIGH dynamic findings
  + bypass tag → aggregate severity HIGH (NOT escalated to CRITICAL).
  Locks the cap-at-max invariant downstream CI gates rely on.

- **c18 — D2: LOW stays LOW.** A LOW unbounded-loop + bypass tag →
  aggregate severity LOW (NOT raised). Cross-mode joining cannot
  inflate severity even when corroboration is real.

- **c19 — D3: HIGH advice not demoted.** A HIGH dangerous-recommendation
  in red-team repo → §5.4 must NOT demote (severity gate ≤ medium).
  Verifies the gate prevents under-reporting of seriously bad advice.

- **c20 — D3: CRITICAL advice not demoted.** A CRITICAL dangerous-
  recommendation in red-team repo → §5.4 must NOT demote. Verifies
  the gate holds at the upper end of the severity ladder.

## Coverage

| Correlator                                              | TP cases             | TN cases               |
|---------------------------------------------------------|----------------------|------------------------|
| `repo_approval_gap_supports_autonomy_risk`              | c1, c8, c12, c17, c18 | c5, c6, c7, c14, c15  |
| `repo_fetch_surface_supports_indirect_injection`        | c2, c9, c12          | c5, c13                |
| `repo_identity_surface_supports_persistence_risk`       | c3, c10              | c5, c16                |
| `repo_educational_context_demotes_runtime_advice`       | c4, c11              | c5, c19, c20           |

Each true-negative is shared across correlators that don't apply.
This is appropriate — a clean baseline must not trigger ANY
correlator, regardless of which one we're measuring.

## Acceptance thresholds (from design §6.2)

- ≥95% true-link rate on the synthetic 20-pair corpus
- ≤2% false-link rate on the corpus_lab cross-pairing experiment
- ≥80% per-correlator TPR
- ≤5% per-correlator FPR on benign repos

The corpus reached the 20-case §6.1 target in v0.18 Phase 2 expansion.
Empirical measurement on the 20 cases: TPR=11/11=100%, FPR=0/9=0%.
Both well within thresholds. Future work: real recorded sessions
(per design §6.1) and `corpus_lab` cross-pairing for false-link
sampling at scale.

## Loading

The Phase 2 test suite consumes this corpus via
`agent_audit.cross_mode.calibration_corpus.load_calibration_cases()`.
Each loaded case produces a `CalibrationCase` dataclass with the
resolved project path, parsed session, and `m2_expected` ground
truth. See `tests/test_cross_mode_correlators_phase2.py` for usage.

## Adding new cases

1. Pick a deterministic `case_id` (kebab-case, prefixed with `c<N>-`).
2. Mkdir `case_id/project/.git/` and place a sentinel HEAD file.
3. Write the project tree — instruction files, skills, MCP manifests
   — that you want the static inventory to discover.
4. Write `session.jsonl` with `cwd: "__CASE_PROJECT__"` as the
   substituted placeholder.
5. Write `case.json` with the `m2_expected` block declaring expected
   correlator, link boolean, repo tags, dynamic-finding-kind label,
   minimum proximity, and rationale.

The `m2_expected.expected_dynamic_finding_kind` is a stable LABEL
chosen by the case author, not a real `rule_id` — Phase 2 uses
those labels to map cases onto the dynamic-side conditions of each
correlator. The mapping lives in the correlator definitions.

## Out of scope for the seed

- Variant cases per correlator (different injection styles, different
  persistence write patterns, different educational marker shapes).
- Cases that exercise proximity tier 3 (`named_artifact_touched`).
  The seed only exercises tier 1 and 2; tier 3 cases need session
  events that explicitly reference an artifact path, which is harder
  to fabricate cleanly without making the session feel scripted.
- Cases in non-Claude-Code formats. AgentDojo-style or Codex sessions
  would broaden coverage but the seed sticks to one format.
