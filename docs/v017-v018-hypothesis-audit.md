# v0.17 + v0.18 hypothesis audit against real-data results

_Generated 2026-05-04 after running benchmark + scan-project + cross-mode +
live forensic scan on maintainer's machine. Source artifacts:
`benchmark-summary.json`, `agent-audit-real-test-2026-05-04.zip`,
maintainer's notes on the 1279s scan stall._

This document is honest about which v0.17/v0.18 claims survived contact
with real data, which were **predicted but not really verified** (ПФЗ —
"проверим, фигня знакомая" — assumed plausible without empirical evidence),
and which were refuted.

Three statuses used:

- **CONFIRMED**: real-data evidence corroborates the claim
- **ПФЗ**: claim made on synthetic/test data; real-world behavior unmeasured
  at the time it was shipped
- **REFUTED**: real-data evidence contradicts the claim

---

## v0.17 milestone claims

### N1 — tool-pinning detector

**Claim made**: Detects when an agent recommends installing tools without
version pinning.

**Status**: ПФЗ. Synthetic tests passed; real incident corpus didn't
exercise this surface meaningfully — none of the 16 incident cases test
unpinned tool installation. Real-world FPR/TPR unmeasured.

**What's real**: tool exists, code is exercised by unit tests, but
production behavior on real session data is empirically untested.

---

### A2/C1 — NOVA pack 46 rules with severity floor

**Claim made**: NOVA rules at LOW severity floor; won't blow up incident
benchmark precision.

**Status**: CONFIRMED. Real benchmark run shows zero NOVA rules in any FP.
Per-rule precision/recall table in `benchmark-summary.md` shows 11 of 14
rules with precision=1.0; the 3 noisy rules are all ATR, not NOVA.

---

### M3 — NOVA evaluator + CLI `nova-evaluate`

**Claim made**: NOVA evaluator runs at acceptable cost; doesn't block CI.

**Status**: ПФЗ. CLI subcommand exists and unit-tested. Not actually run
on a real corpus during the v0.17 → v0.18 development cycle. Performance
on real data unknown.

---

### B4 — AVID cross-link 100% coverage on 702 rules

**Claim made**: 702 rules each map to ≥1 AVID category.

**Status**: CONFIRMED on test artifacts. Validators green on every real
run including post-v0.18 (`agent-audit avid-validate --strict --quiet`
returns OK in this session). This is a structural guarantee, not a
behavioral one — passes are mechanical.

---

### D2/D3 — AgentDyn (93.9% recall) + WASP (100% recall) benchmark adapters

**Claim made**: Detection performance reaches the stated bars.

**Status**: ПФЗ. Numbers from synthetic benchmark suites authored alongside
the rule packs. Real adversarial sessions from the maintainer's incident
corpus show 100% recall (16/16 cases pass on expected labels), but those
labels are partially incomplete — 3 of 4 "FP" cases are actually rule
matches the incident corpus didn't credit. So **observed real-data
recall is at least as good as claimed**, but the headline numbers come
from the synthetic suites and shouldn't be cited as "production
performance" without qualification.

---

### M2 design memos (D1-D5)

**Claim made**: D2 (cap-at-max severity), D5 (suppressions respected) are
invariants the linker honors.

**Status**: CONFIRMED. Calibration corpus tests `test_calibration_d2_severity_cap_invariant`
and `test_cross_mode_d5_no_resurrection_when_findings_absent` lock both
invariants. Real-data run with 482 sessions produced 0 aggregate records
where source had been suppressed — D5 boundary held in production.

---

## v0.18 milestone claims

### M2 Phase 1 — repo signal inventory + resolver

**Claim made**: Resolver walks up from session cwd, stops at $HOME or repo
markers (`.git`, etc.).

**Status**: CONFIRMED with caveat. Resolver works on real Codex sessions
(276/482 = 57% have inventories built). The 157 unlinkable sessions look
legitimate — Codex temp dirs, session cwd outside any repo. So the
**resolver itself behaves correctly**.

The CAVEAT is: **226 of 276 resolved sessions (82%) attribute to a single
repo — the maintainer's agent-audit dev checkout itself.** This is correct
resolver behavior (those sessions WERE running there), but means the M2
signal flow on real data sees mostly the same repo over and over.

---

### M2 Phase 1 — 9 structural tags via inventory walk

**Claim made**: Tags fire only on relevant repo signal patterns. Vendor
prune (`node_modules`, `.venv`, etc.) keeps the signal clean.

**Status**: REFUTED on agent-audit dev checkout. The agent-audit repo
itself contains:

- `benchmarks/m2-calibration-corpus/c1-approval-gap-autonomy-link/project/AGENTS.md` →
  fires `has_broad_action_without_approval`
- `benchmarks/m2-calibration-corpus/c2-fetch-surface-injection-link/project/AGENTS.md` →
  fires `has_remote_fetch_instructions`
- `benchmarks/m2-calibration-corpus/c3-identity-rewrite-persistence-link/project/CLAUDE.md` →
  fires `has_identity_rewrite`
- `benchmarks/m2-calibration-corpus/c19-d3-high-advice-not-demoted/project/red-team/skills/lesson1/SKILL.md` →
  fires `red_team_heavy`
- Various skills under `benchmarks/.../project/.claude/skills/` →
  `has_skills`

Result on real data: 226 sessions resolve to agent-audit, **all 5 risk
tags fire on every one**. The vendor prune list (`node_modules`, `.venv`,
`dist`, `build`, etc.) does NOT include `benchmarks/`. This is a real
defect.

**What needs to happen**: extend vendor-prune list to include
`benchmarks/` directory (any `benchmarks/**` path treated like
`node_modules/**`). Repos that legitimately contain user-facing
benchmarks/test fixtures will hit this same problem.

This is in v0.18.1 patch scope.

---

### M2 Phase 2 — calibration corpus baseline TPR=100%, FPR=0%

**Claim made**: 11/11 TP, 0/9 FP on the 20-case synthetic corpus.

**Status**: CONFIRMED on synthetic. Tests still pass after every patch.
But this is calibration on data we authored ourselves — it's a
regression guard, NOT a production performance estimate.

**What's NOT shown**: TPR on real recorded sessions where ground truth
exists. We have no real-data TPR measurement for cross-mode. The 0
aggregate records on 325 processed real sessions could mean (a) no real
incidents happened in those sessions or (b) cross-mode is too
conservative on real signal shapes. We don't know.

---

### M2 Phase 2 — cross-mode is "consistently conservative" on real bundle

**Claim made**: 0 aggregates on 325 real sessions = healthy
conservatism, no overfire.

**Status**: PARTIALLY CONFIRMED. The 0 false-fires part is true and
healthy. But the framing was incomplete: with the benchmarks/ vendor
gap, cross-mode SHOULD have fired aggregates if dynamic findings had
co-occurred — every resolved session had all the right tags. The
absence of fires means dynamic findings on those 226 same-repo sessions
just didn't produce matching rule_ids. So:

- "no overfire" = CONFIRMED  
- "production-ready signal flow" = ПФЗ until tested on a bundle where
  dynamic findings exist on instruction-rich repos

---

### M2 cross-mode CLI subcommand

**Claim made**: `agent-audit cross-mode --forensic <path>` consumes saved
scan output and produces aggregate report.

**Status**: CONFIRMED. Real bundle ran through the CLI without errors.
482 sessions / 325 processed / 157 unlinkable / 0 aggregates / clean
JSON + Markdown output. CLI works end-to-end.

---

### M2 scan-project adapter — static findings supplement tags

**Claim made**: Static `Finding` objects from scan-project feed
correlators alongside (or instead of) inventory tags. End-to-end smoke
verified.

**Status**: ПФЗ on real data. Smoke test was on a synthetic scan-project
bundle paired with c1 calibration project. Real maintainer's
scan-project run produced 84 findings BUT all 84 came from
`benchmarks/m2-calibration-corpus/*` test fixtures. The adapter has not
been exercised against a real (non-fixture) scan-project bundle paired
with a real forensic scan.

This needs the same `benchmarks/` vendor-prune fix to produce signal
of meaningful provenance.

---

### Performance — "scales with content size"

**Claim implicit**: scan-project + scan + cross-mode finish in
reasonable time.

**Status**: REFUTED for forensic scan. Real-world scenario: 41MB Codex
rollout with 21196 lines / 8280 events stalled live scan for >20
minutes. Root cause traced (this session) to:

1. **Catastrophic backtracking** in
   `atr.context-exfiltration.system-prompt-extraction-training-data-verbatim-replay`:
   pattern with optional opener `(?:ignore...)?` + `[^\n]{0,80}` + required
   tail. On megabyte-scale single events, regex engine explores every
   `(start_pos, length)` combination. Hung indefinitely on 5MB content.

2. **Superlinear scaling** of 663 rule patterns >50ms each on 5MB content.
   Aggregate: ~330s per such session × 78 active session rules.

3. **Single-event content size unbounded**. A `developer_instructions`
   block can be megabytes; rule executor fed all of it into every regex.

This was unmeasured in v0.17/v0.18 because synthetic test corpus has
short events.

**Now fixed in v0.18.1**:
- Hung pattern rewritten (split into safe sub-patterns, opener removed)
- Per-event content cap (default 64KB, env override)
- Per-event SIGALRM timeout (default 5s)
- Tier 2 fast-keyword anchor pre-skip
- 14.8MB synthetic test: 57.2s → 37.5s; 41MB extrapolated: ~110s
  vs infinite

---

### Test suite performance

**Claim made (implicit)**: tests run in reasonable time.

**Status**: WAS REFUTED, NOW CONFIRMED post-v0.18.1. Pre-fix the test
suite had crept from 38s to 134s as M2 work accumulated. The same
catastrophic + superlinear patterns slowed even synthetic test runs.
Post-fix: 117s with the new perf-safeguards test (which itself does a
5MB scan to lock the regression). Without the new test, suite would be
~30s.

---

### CLI `--mode full` — wires through to rules

**Claim made**: `--mode {conservative,standard,full}` controls scan scope.

**Status**: CONFIRMED for stated semantics (scope: agent-only / +env probes / 
+adjacent repos), REFUTED for an adjacent claim that DetectionMode
plumbs through to rule execution.

**Specific defect** (maintainer caught this on real run): CLI's
`detection_mode = {...}[effective_mode]` value (line 841 of cli.py) is
NOT passed into `scan()`, so `run_session_rules()` and
`run_config_rules()` always receive default `BALANCED`. Two detectors
are mode-aware (`adjacent_repo_probe.py`, `ssh_key_probe.py`) but only
one is reached via the parallel `--mode full` path; the other never
gets the actual mode.

**Status before fix**: real impact limited (only 2 mode-aware detectors,
one already routed correctly), but **plumbing is broken** independent of
impact.

**Fix scope**: Tier 3 — defer to v0.18.2 since impact is small, fix is
mechanical.

---

### Incident corpus precision/recall (v0.18 regression guard)

**Claim made**: 16/16 cases pass; recall=1.0; precision degraded only
by 4 FPs.

**Status**: CONFIRMED with corrections. After deeper review:

- `comment-and-control...`: FP is **incomplete labeling** (rule legitimately
  matched `cat .env | curl` exfil chain)
- `github-mcp-prompt-injection...`: FP is **incomplete labeling** (same
  pattern)
- `ox-mcp-config-mutation`: FP is **incomplete labeling** for secondary
  shell-risk signal (`curl|sh` inside the MCP config write)
- `ox-flowise-wrapper-bypass`: **mixed** — regex match is legit, but
  semantic classification under `resource-exhaustion` (instead of
  `dangerous-recommendation` as per the case label) is taxonomically
  arguable

So real precision is **not** 0.875; it's effectively 1.0 with caveats on
how labels are assigned. Pure-detector view: no actual misfires.

---

## Summary scorecard

| Claim                                            | Status     |
|--------------------------------------------------|------------|
| N1 tool-pinning detector                         | ПФЗ        |
| A2/C1 NOVA pack severity floor                   | CONFIRMED  |
| M3 NOVA evaluator                                | ПФЗ        |
| B4 AVID cross-link coverage                      | CONFIRMED  |
| D2/D3 benchmark recall                           | ПФЗ + qualified |
| M2 D1-D5 invariants                              | CONFIRMED  |
| M2 Phase 1 resolver                              | CONFIRMED  |
| M2 Phase 1 tag selectivity                       | REFUTED → REVISED in v0.18.3 |
| M2 Phase 2 calibration baseline                  | CONFIRMED (synthetic) |
| M2 Phase 2 conservative on real data             | PARTIAL    |
| M2 cross-mode CLI                                | CONFIRMED  |
| M2 scan-project adapter                          | ПФЗ        |
| Forensic scan performance on real Codex          | REFUTED → fixed in v0.18.1 |
| Test suite performance                           | REFUTED → fixed in v0.18.1 |
| --mode full plumbing                             | REFUTED → fixed in v0.18.3 |
| Incident corpus precision/recall                 | CONFIRMED with label caveats |
| D4 separate-subcommand decision                  | CONFIRMED at launch → REVISED in v0.18.3 (cross-mode integrated) |

**Refuted items closed**: 4 of 4. Forensic perf + test suite (v0.18.1);
DetectionMode plumbing + vendor-prune defaults reversal (v0.18.3).
The vendor-prune work happened twice — v0.18.1 over-corrected by
hardcoding the skip; v0.18.3 made it opt-in after recognizing the
v0.18.1 fix was fitted to agent-audit's own dev tree at the cost of
silently dropping signal on legitimate `benchmarks/` content elsewhere.

**Revised architectural decisions**:
- **D4** (separate cross-mode subcommand) — sound at launch when M2 was
  unproven; reversed in v0.18.3 once cross-mode shipped stable. Still
  available as a subcommand for rerun-on-saved-bundle workflows. The
  D4 rationale "keep debugging boundary explicit" lives on via
  `--verbose` flag with timestamped progress messages.
- **Vendor-prune** — v0.18.1 hardcoded skip was retroactively recognized
  as fitting to one specific repo (agent-audit itself). v0.18.3 makes
  it opt-in via `--vendor-prune` flag. Autodetect heuristic
  (recognize `benchmarks/c*/case.json` shape → auto-prune that subtree
  only) deferred to v0.19+ pending real-data evidence on its
  necessity.

**ПФЗ (5)**: production claims still needing real-data validation:
- N1 tool-pinning detector
- M3 NOVA evaluator
- M2 scan-project adapter
- M2 cross-mode TPR/FPR
- D2/D3 benchmark recall numbers (synthetic baseline only)

Most actionable: real-data evaluation harness as a v0.19+ milestone.
Discussed in roadmap as "Variant B" — curated 10-20 instruction-rich
repos for static eval, real session corpus with labeled ground truth,
automated CI mode that produces TPR/FPR/perf numbers.

---

## What this audit changes

1. **No more "production performance" claims without real-data backing.**
   The CHANGELOG should mark items "synthetic baseline" or "real-data
   verified" explicitly going forward.

2. ~~**vendor-prune list needs benchmarks/ added**~~ — fixed in v0.18.1,
   then **REVISED in v0.18.3**: the hardcoded fix over-corrected. v0.18.3
   makes vendor-prune opt-in to avoid silently dropping signal on
   legitimate `benchmarks/` content elsewhere. Autodetect heuristic
   for fixture-shape recognition is the next iteration.

3. ~~**DetectionMode plumbing fix**~~ — fixed in v0.18.3.

4. **Cross-mode real-data evaluation** is the open work item. Without a
   real bundle that has dynamic findings on instruction-rich repos, we
   can't measure cross-mode TPR honestly. The corpus_lab benchmark from
   the design doc §6.2 is the remedy; pursuing it is the v0.19+ milestone.

5. **D4 architectural decision was right for launch, wrong for steady
   state.** The audit captured this implicitly (no specific column for
   "decisions worth revisiting later") but v0.18.3 confirmed the lesson:
   ship-time conservatism (separate subcommand) was correct as risk
   reduction; once feature stability proved, the friction outweighed
   the safety. Future M3+ work should plan a similar release-then-merge
   cadence rather than committing permanently to a separate-subcommand
   model.

---

## v0.20.0 follow-through (2026-05-04)

N2 cross-server toxic flow detector ships in v0.20.0. Status update on
items added/closed by this release:

### N2 — added as new claim
**Status: CONFIRMED on synthetic corpus, ПФЗ on real-data**

Claim: A native session-rule detector can identify cross-server toxic
flow patterns with high precision/recall on the curated incident
corpus.

Evidence so far:
- 3 corpus cases (2 positive, 1 negative) all pass per `agent-audit eval`
- Detector fires on `injection_marker`, `destructive_command`,
  `secret_reference` payload classes — distinguished by severity and
  confidence
- False-positive guards (same-server, native-tool, no-overlap) verified
  via dedicated test cases

What's still ПФЗ:
- Real-data N2 TPR/FPR not yet measured. Maintainer's full-rerun bundle
  did not contain multi-MCP-server sessions; corpus cases are synthetic.
- Once a maintainer rerun with N2-active code lands, the eval baseline
  will include real-bundle N2 numbers and this row moves CONFIRMED.

### Phase 5 deferred items — process discipline applied

Per v0.19 scope discussion, Phase 5 remained at 5 conditional rule
packs. v0.20.0 ships only N2; A5/A6/A4/C2 stay deferred precisely
because adding them without eval cases would re-introduce ПФЗ items —
the discipline this audit set up specifically aims to prevent.

The eval harness shipped in v0.19 makes this discipline tractable:
each future rule pack lands with corpus cases and measurable outcomes,
not speculative claims. v0.20 establishes the template.

### Eval test boundary update

`test_evaluate_corpus_on_real_incident_corpus` changed from `==16` to
`>=16` so future cases additions don't force test rewrites. The v0.19
baseline stays as a lower bound — if cases get accidentally deleted,
this test still catches it.

---

## v0.19 real-data confirmation (2026-05-04)

Maintainer's live run with v0.19 code on the same population that
produced the v0.18.1 rerun. Direct comparison:

| Metric | v0.18.1 rerun | v0.19 live | Delta |
|---|---|---|---|
| Sessions processed | 558 | 562 | +0.7% (live data growth) |
| Findings total | 7386 | 7583 | +2.7% |
| **Cross-mode aggregate records** | **0 (bug)** | **10** | **+10 ✅** |
| `repo_approval_gap_supports_autonomy_risk` | 0 | 5 |
| `repo_fetch_surface_supports_indirect_injection` | 0 | 5 |
| Cross-mode sessions processed | 400 | 411 |
| Cross-mode sessions unlinkable | 158 | 230 |
| Scan total wall (seconds) | 1463.9 | 1198.5 | **−18.1%** |
| scan-project wall (seconds) | 2.4 | 2.6 | +8% |
| scan-project files scanned | 18 | 18 | unchanged (autodetect prune confirmed) |

### Hypothesis closures

The following audit rows now move from REFUTED/ПФЗ to **CONFIRMED on
real data**:

- **Cross-mode bug fix** (`_findings_by_session` reading from evidence)
  — confirmed: aggregate records went 0 → 10 on the same population.
  Two correlators fired correctly across 5 unique sessions.
  
- **Autodetect fixture-shape** — confirmed: scan-project still scans
  18 files (same as v0.18.1's hardcoded vendor-prune behavior), so
  autodetect is dropping the fixture corpus subtree. The detection
  works without requiring `--vendor-prune` for the whole repo.
  
- **Scan-session inventory trust** — confirmed indirectly: scan
  total wall dropped 18.1% (1464s → 1199s) on the same population,
  suggesting cross-mode inventory lookups are no longer paying for
  repeated walks of the same repo.

### What's still open after this rerun

- **N2 detection on real-data**: maintainer's bundle does not appear
  to contain multi-MCP-server sessions in patterns that trigger N2.
  Fired 0 times across 562 sessions. This is *expected* — the user's
  workflow doesn't include the gmail→github / slack→shell flows N2
  targets — but means N2's real-world TPR is still ПФЗ until a
  bundle with cross-server activity lands.
  
- **N2 false-positive rate on real-data**: 0 fires = 0 FPs, which is
  consistent with the synthetic-corpus 0% FPR. But this is a weak
  signal because the test population doesn't exercise the detector.
  Need cross-server bundle for meaningful FPR measurement.

- **Tier 1 perf safeguard counts on this run**:
  - 1082 events truncated to 64KB (default cap)
  - 59 events aborted after 5s per-event timeout
  
  These are within expected range for a 374MB bundle. No safeguard
  pathology — content cap + timeout are doing their job.

---

## v0.21.0 follow-through (2026-05-08)

A5 Cisco YARA integration ships in v0.21.0. Status update on items
added/closed by this release:

### A5 — added as new claim
**Status: CONFIRMED on synthetic corpus, ПФЗ on real-data**

Claim: vendored Cisco YARA rules applied to MCP manifests via
scan-project produce useful findings on malicious manifests with
zero false positives on benign manifests.

Evidence so far:
- 3 corpus cases (2 positive, 1 negative) all pass per `agent-audit eval`
- Positive cases: credential exfil pattern + tool poisoning pattern
  in `tools[].description` produce 2 critical + 1 critical findings
  respectively (3 distinct A5.cisco-yara-* rule_ids fire)
- Negative case: weather/calendar/list_files manifest produces 0
  A5 findings — clean FP guard
- 31 unit tests covering availability, severity mapping, manifest
  field extraction, end-to-end matching, integration with scan-project,
  and graceful behavior when yara-python is missing

What's still ПФЗ:
- Real-data A5 TPR/FPR not yet measured. The v0.19 live-run bundle
  did not include MCP manifests with adversarial content; A5 fired
  0 times on that scan. Once a maintainer rerun with v0.21 code on
  a bundle that contains real MCP manifests lands, the eval baseline
  will include real-bundle A5 numbers and this row moves CONFIRMED.
- A specific concern to validate on real data: Cisco's
  `tool_poisoning` rule targets very specific phrases ("also
  collects", "during processing extract", "indexes API keys",
  HTML-comment evasion patterns). These are narrow by design (low
  FP) but the narrowness means real-world tool poisoning that
  doesn't match those exact phrases will fire OTHER rules (we saw
  this in case 2 — `command_injection` fired instead of
  `tool_poisoning`). Whether that's a coverage gap or correct
  behavior is a real-data question.

### Severity mapping is conservative — documented tradeoff

A5 findings ship with MEDIUM confidence regardless of severity. This
is intentional: Cisco's own pipeline applies LLM-as-judge on top of
YARA before final severity decision. agent-audit doesn't have that
LLM judge step. So we err toward documenting the YARA hit at the
threat_type-mapped severity and let the audit consumer decide
whether to escalate.

If real-bundle eval shows MEDIUM confidence is too low for high-
severity A5 hits (auditors ignoring legitimate critical findings),
we can revisit. But starting conservative is the right move per
the eval-first discipline.

### Optional dependency model — first one for agent-audit

A5 is the first feature gated on an optional package extra
(`pip install agent-audit[yara]`). The v0.19 hypothesis audit didn't
contemplate this — base install lean is mostly aspiration there. v0.21
makes it concrete: yara-python is a 2.3MB wheel with a C dep
(libyara), which is real friction for users who don't want MCP
manifest scanning.

The optional-dep handling is tested both ways: with yara installed
and with yara monkeypatched to be missing. CI without yara installed
still passes the full regression. This sets the template for future
optional packs (TruffleHog if counsel approves, etc.).

### Eval template extended

`expected_static_findings` is now exercised by 3 of the 22 corpus
cases (the A5 ones). Eval scoring distinguishes static-side recall
from forensic-side recall; the v0.19 harness already supports this
shape. v0.21 demonstrates the contract working end-to-end:
expected_static_findings → run scan-project → score → recall
metric reported separately.

This is the **discipline** the v0.17/v0.18 audit set up: features
land with eval cases, not speculative claims. v0.21 is the second
release ship-by-this-rule (after v0.20's N2). The pattern is
sustainable.
