# M2 D1-D5 Decisions

**Context**: this memo settles the open questions from
[m2-cross-mode-design-draft.md](./m2-cross-mode-design-draft.md)
for the first implementation of cross-mode static + dynamic linking.

**Scope**: these decisions are for **v1 of M2**, not forever. They
optimize for correctness, explainability, and low surprise in the
first shipped version.


## D1 — Identity strategy scope at v1

**Decision**

Use **hash-only identity matching** in v1.

Do **not** ship name fallback or path fallback in the first release.
Keep both as explicitly deferred follow-ons after calibration.

**Rationale**

Cross-mode linking becomes dangerous the moment we produce false joins.
Hash equality is conservative and easy to explain:

- same normalized artifact body
- same repo-linked context
- no ambiguity about which artifact we mean

Name fallback sounds attractive but is much easier to get wrong:

- repeated skill names across repos
- copied templates
- refactored directories with unchanged names
- generic names like `git-tools`, `deploy`, `security-audit`

Path fallback has similar risks:

- common directory layouts across unrelated repos
- monorepo subtree reuse
- file movement without semantic continuity

The important point is that **M2 does not require weak identity matching
to be useful**. Even with hash-only matching, we still get strong value
from:

- repo-level tags
- proximity tiers
- supporting cross-signal correlators at the repo/subtree level

So v1 should prefer fewer, high-confidence joins over wider but noisier
coverage.

**Implementation consequence**

- ship exact artifact matching only
- keep name/path extraction code behind internal interfaces, but disabled
- add calibration harnesses for future v1.1 or v1.2 fallback work


## D2 — Severity combination policy

**Decision**

Use **strict cap-at-max severity**.

Cross-signal aggregate records may increase:

- review priority
- verifier priority
- issue-instance rank
- explanatory strength

But they must **not** raise severity above the highest component signal.

**Rationale**

Severity inflation would make v1 unpredictable and hard to trust.
Cross-mode support means:

- "this runtime signal is better explained"
- "this risk pattern is better grounded"

It does **not** mean:

- "we discovered a more severe event than either mode individually observed"

Allowing `HIGH + HIGH -> CRITICAL` would create a new semantics layer
that users did not explicitly author and cannot easily reason about.
That would also complicate:

- CI gating
- dashboards
- alert thresholds
- regression interpretation

The right mental model for v1 is:

- severity = maximum direct evidence severity
- priority = severity plus corroboration

**Implementation consequence**

- aggregate records carry `severity = max(component severities)`
- ranking may use a separate corroboration bonus
- rendered reports should say "cross-signal support" rather than imply
  escalation


## D3 — Educational-context demotion

**Decision**

Demote **priority, not severity**.

Educational or benchmark-heavy context may reduce how aggressively a
finding is surfaced, but it should not rewrite the underlying severity
label in M2.

**Rationale**

Educational context changes interpretation, not necessarily the nature
of the matched pattern.

If a dangerous pattern appears in:

- a benchmark
- red-team skill
- translation sample
- explanatory write-up

that may make it less urgent for triage, but it does not prove the
pattern itself is low severity. Conflating those two would blur:

- what the detector matched
- how urgently a human should look

Also, static educational-context logic already exists as a demotion
mechanism in `scan-project`; M2 should not introduce a second,
cross-mode-specific severity rewriting policy unless there is strong
evidence it is necessary.

The cleaner v1 policy is:

- keep severity stable
- lower queue position / verifier priority / review prominence
- visibly label the educational context as mitigating context

**Implementation consequence**

- aggregate correlators may set tags like `educational_context`
- ranking policy may downrank these issue instances
- report wording should explain that the context weakens interpretation,
  not that the raw pattern changed severity


## D4 — CLI surface

**Decision**

Ship v1 as a **separate `cross-mode` step/subcommand over saved outputs**,
not as implicit auto-invocation inside `scan`.

**Rationale**

This is the safest way to launch M2 because it keeps:

- the execution boundary explicit
- debugging simple
- rollout reversible
- output comparison easy

If M2 auto-runs inside `scan` on day one, it becomes much harder to
answer basic questions like:

- did the dynamic detector change, or did the linker change?
- is the cache working, or did repo resolution drift?
- did static support help, or just make the bundle noisier?

A separate step also makes calibration dramatically easier. We can run:

1. base forensic scan
2. cross-mode enrich
3. compare output deltas

without changing the core forensic experience for every user.

The separate-step model also matches the maturity of the feature:
M2 is initially an enrichment and correlation layer, not a mandatory
base primitive.

**Implementation consequence**

Recommended v1 shape:

- `agent-audit cross-mode --forensic <bundle> --repo-root <path>`
- or `agent-audit cross-mode --forensic <bundle> --inventory <inventory.json>`

Later, once stable:

- `scan --cross-mode` opt-in flag
- eventually optional default auto-run if operationally justified


## D5 — Project-config override interaction

**Decision**

Run the **finding-level linker after project-config suppressions**.

However, allow the **repo inventory tag layer** to remain available even
when individual findings were suppressed, as long as those tags are
clearly marked as structural context rather than live findings.

**Rationale**

User curation must remain sovereign.

If a project owner says:

- suppress this finding class
- demote or hide this pattern

then M2 should not reintroduce the same suppressed finding through a
back door and surprise them with a new aggregate alert.

At the same time, completely throwing away all structural repo context
would be too blunt. Some repo facts are not "findings" in the same
sense. For example:

- repo has skills
- repo has MCP manifests
- repo contains remote-fetch instruction surfaces

These are contextual properties of the repository. They can still inform
forensic interpretation even if a specific static finding was suppressed.

So the right split is:

- **suppressed findings do not participate as supporting findings**
- **inventory-level structural tags may still exist**
- **aggregate records must never cite a suppressed finding ID as support**

This preserves both:

- user trust in suppression rules
- the analytic value of repository structure

**Implementation consequence**

M2 should operate on two layers:

1. **suppressed/curated finding layer**
   - used for finding-to-finding joins
   - suppressed findings excluded

2. **structural inventory tag layer**
   - used for coarse repo context correlators
   - no hidden resurrection of suppressed evidence

In practice:

- a suppressed `broad_external_action_without_approval` finding should
  not appear as a supporting record
- but a coarse tag like `has_skills` or `has_mcp_manifests` may still
  be available if it comes from structural inventory rather than the
  suppressed finding itself


## Resulting v1 policy set

For clarity, the settled v1 M2 policy is:

- **Identity**: hash-only
- **Severity**: cap at max component severity
- **Educational context**: demote priority only
- **CLI**: separate explicit cross-mode step
- **Suppressions**: respect suppressed findings; keep only structural
  tags that do not resurrect suppressed evidence


## Why this package of decisions fits together

These decisions all follow one design principle:

**M2 v1 should be conservative, legible, and hard to misuse.**

That means:

- precise joins over broad joins
- corroboration over escalation
- explicit operator control over automatic magic
- user suppressions respected
- contextual mitigation separated from severity semantics

This makes the first implementation easier to calibrate and easier to
defend if reviewers ask why a given cross-mode issue was or was not
produced.
