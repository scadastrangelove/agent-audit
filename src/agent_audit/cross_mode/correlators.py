# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Cross-signal correlators — Phase 2 of M2.

Implements the four named correlators from design draft §5. Each
correlator declares:
  - the static-side condition (inventory tags or dynamic finding's
    canonical_class match)
  - the dynamic-side condition (set of rule_ids that count)
  - the proximity tier required (1 / 2 / 3)
  - the output policy (aggregate record severity + tags)

Per D2 (settled), aggregate records cap severity at max(components).
Per D3, the educational-context correlator §5.4 demotes priority via
a tag, not severity. Per D5, the linker layer (linker.py) handles
the suppression-respect contract; correlators here see only the
findings the linker passes them, which already excludes suppressed
ones.

## Why four named rules and not generic pattern matching

A small set of curated correlators is easier to calibrate, easier to
explain, and harder to misuse than a generic rule engine. Phase 2
ships these four because they have grounded support in real
rule_ids that already exist (`C3.autonomy-with-exfil-chain`,
`AI-06.indirect-prompt-injection-vector`, `AI-04.persistence-write`,
`advice.dangerous-recommendation`) and because each addresses a
distinct attack class. Adding new correlators requires the same
calibration discipline — TPR/FPR thresholds in §6.2.

## Proximity gate

Each correlator declares a minimum proximity tier. Phase 2 supports
tiers 1 and 2:
  - tier 1 (`repo_present`): the static surface lives somewhere in
    the resolved repo. Always satisfied if a repo was resolved.
  - tier 2 (`repo_present_and_same_subtree`): the session's cwd is at
    or under the directory that contains the static surface. Phase 2
    approximates this by checking whether the session cwd is under
    the repo's `.claude/`, `.cursor/`, or `.codex/` agent directory
    (per the persistence semantics in §5.3).
  - tier 3 (`named_artifact_touched`): not implemented in Phase 2.
    Requires session events that explicitly reference an artifact
    path. Deferred to a future correlator that needs it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from .policy import cap_severity, demote_priority_via_tag, lift_confidence
from .signal_record import SignalRecord, make_aggregate_record


# ----------------------------------------------------------------------------
# Inputs the correlator receives. The linker assembles these from a
# RepoSignalInventory + filtered list of dynamic findings.
# ----------------------------------------------------------------------------

@dataclass
class CorrelatorInput:
    """Per-session input bundle that the linker passes to each correlator.

    `inventory_tags` is the set of active tag names from the resolved
    repo's RepoSignalInventory. None when the session didn't resolve
    to any repo.

    `dynamic_findings` is a list of (rule_id, severity) tuples from
    the forensic scan, AFTER user-config suppressions have been
    applied per D5. Each tuple is enough for correlator decisions;
    we don't pass the full Finding objects to keep this layer
    decoupled from the Finding type.

    `static_findings` (added in v0.18 scan-project adapter milestone)
    is a list of (rule_id, severity, canonical_class) triples from a
    paired `scan-project` run on the same repo, AFTER user-config
    suppressions have been applied per D5. These supplement
    `inventory_tags` — a static finding is a SHARPER signal than a
    tag because it's a confirmed rule-pack match rather than coarse
    pattern derivation. Either source can satisfy a correlator's
    static-side condition; when both fire, the aggregate's confidence
    notes both.

    `session_id`, `session_cwd`, and `repo_root` carry context that
    correlators use to build aggregate records and (for tier 2) to
    gate on subtree proximity.
    """
    session_id: str
    session_cwd: Optional[str]
    repo_root: Optional[Path]
    inventory_tags: Optional[Set[str]]
    dynamic_findings: List[Tuple[str, str]]  # [(rule_id, severity), ...]
    static_findings: List[Tuple[str, str, str]] = field(default_factory=list)
    # [(rule_id, severity, canonical_class), ...]


# ----------------------------------------------------------------------------
# Rule_id sets per correlator. These are the dynamic-side conditions.
# All rule_ids verified to exist in the codebase as of v0.18-dev.
# ----------------------------------------------------------------------------

# §5.1: autonomy + destructive + unbounded loop
_AUTONOMY_RULES: Set[str] = {
    "C3.autonomy-with-exfil-chain",
    "C3.autonomy-with-persistence",
    "C3.autonomy-with-sensitive-sink",
    "AG-04.destructive-without-backup",
    "resource.unbounded-loop",
}

# §5.2: indirect injection vector
_INDIRECT_INJECTION_RULES: Set[str] = {
    "AI-06.indirect-prompt-injection-vector",
}

# §5.3: persistence write
_PERSISTENCE_RULES: Set[str] = {
    "AI-04.persistence-write",
    "C3.autonomy-with-persistence",
}

# §5.4: dangerous recommendation. Demoted only when severity ≤ medium —
# we don't demote critical/high recommendations regardless of context.
_DANGEROUS_RECOMMENDATION_RULES: Set[str] = {
    "advice.dangerous-recommendation",
}


# ----------------------------------------------------------------------------
# Static-side canonical class sets per correlator. A static finding
# whose canonical_class matches one of these constitutes a SHARPER
# version of the corresponding inventory tag — it's a confirmed
# rule-pack match rather than a coarse pattern derivation.
#
# Either source (tag OR static finding with matching canonical_class)
# can satisfy the correlator's static-side condition. When both fire,
# the aggregate's evidence cites both. Mapping mirrors design §5
# alongside the dynamic rule_id sets above.
#
# Canonical classes listed here come from
# `src/agent_audit/finding_dedup.py:CANONICAL_CLASS_PREFIXES`.
# ----------------------------------------------------------------------------

# §5.1 static-side: explicit broad-action / approval-bypass canonical class
_APPROVAL_GAP_STATIC_CLASSES: Set[str] = {
    "broad_external_action_without_approval",
    "autonomous_execution_or_looping",
}

# §5.2 static-side: remote-fetch / instruction-override / tool-poisoning
# canonical classes — these are all flavors of fetch-mediated trust
# expansion that align with the "fetch surface" concept.
_FETCH_SURFACE_STATIC_CLASSES: Set[str] = {
    "remote_fetch_or_install_expands_trust_boundary",
    "prompt_or_instruction_override_surface",
    "tool_or_skill_poisoning_surface",
}

# §5.3 static-side: identity-rewrite / role-manipulation canonical classes
_IDENTITY_PERSISTENCE_STATIC_CLASSES: Set[str] = {
    "identity_rewrite_with_persistent_effect",
    "agent_role_or_goal_manipulation",
}


def _matching_static_findings(
    findings: List[Tuple[str, str, str]],
    classes: Set[str],
) -> List[Tuple[str, str, str]]:
    """Filter static_findings to those whose canonical_class is in `classes`.

    Returns a list of (rule_id, severity, canonical_class) triples.
    Empty list when no static finding matches; correlator falls back
    to the inventory tag check.
    """
    return [(rid, sev, cls) for rid, sev, cls in findings if cls in classes]


# ----------------------------------------------------------------------------
# Proximity helpers
# ----------------------------------------------------------------------------

def _proximity_tier_1(inventory_tags: Optional[Set[str]], required_tag: str) -> bool:
    """Tier 1: the static surface (identified by tag) is present in
    the resolved repo. Cheapest check — just tag membership."""
    if inventory_tags is None:
        return False
    return required_tag in inventory_tags


def _proximity_tier_2(
    inventory_tags: Optional[Set[str]],
    required_tag: str,
    session_cwd: Optional[str],
    repo_root: Optional[Path],
) -> bool:
    """Tier 2: tier 1 satisfied AND the session's cwd is at or under
    a 'subtree' that hosts the static surface.

    Phase 2 approximation: check whether session_cwd is at or under
    the resolved repo. This is conservative — a more precise version
    would identify the specific directory hosting the static surface
    and check session_cwd against THAT subtree only. Phase 2's
    persistence correlator (§5.3) accepts the conservative
    approximation because the surface lives in CLAUDE.md / AGENTS.md
    at repo root, so 'under repo' is exactly 'under the surface's
    subtree'.
    """
    if not _proximity_tier_1(inventory_tags, required_tag):
        return False
    return _session_under_repo(session_cwd, repo_root)


def _session_under_repo(
    session_cwd: Optional[str],
    repo_root: Optional[Path],
) -> bool:
    """Check whether session_cwd is at or under repo_root, independent
    of any tag/finding check.

    Used by tier 2 correlators that can fire on EITHER inventory tag
    OR matching static finding — once one of those is satisfied, we
    still need the geographical proximity check separately.
    """
    if not session_cwd or repo_root is None:
        return False
    try:
        cwd = Path(session_cwd).resolve()
        root = repo_root.resolve()
    except (OSError, RuntimeError):
        return False
    try:
        cwd.relative_to(root)
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------------------
# Correlator definitions
# ----------------------------------------------------------------------------

@dataclass
class CorrelatorResult:
    """One aggregate record plus optional tags applied to component
    findings. Each correlator returns zero or one of these.

    `applied_tags` maps rule_id → list of tags that should be added
    to the matching dynamic finding. Used by §5.4 to attach the
    `context_demoted` tag without mutating severity.
    """
    record: Optional[SignalRecord]
    applied_tags: Dict[str, List[str]] = field(default_factory=dict)


def correlator_approval_gap_supports_autonomy_risk(
    inp: CorrelatorInput,
) -> CorrelatorResult:
    """§5.1: static `has_broad_action_without_approval` (or matching
    static finding) + dynamic autonomy/destructive finding →
    aggregate at proximity 1.

    The bypass instruction need only EXIST in the repo for the joint
    signal to matter; we don't require the session to demonstrably
    have read it. Per design, this is intentionally permissive on the
    proximity side because approval-bypass shapes the runtime
    behavior even when the session never re-reads AGENTS.md.

    A static finding from `scan-project` whose canonical_class falls
    in {broad_external_action_without_approval, autonomous_execution_or_looping}
    is a SHARPER signal than the inventory tag — it's a confirmed
    rule-pack match. Either source can satisfy the condition; both
    firing produces stronger evidence.
    """
    static_tag = "has_broad_action_without_approval"
    static_matches = _matching_static_findings(
        inp.static_findings, _APPROVAL_GAP_STATIC_CLASSES,
    )
    tag_present = _proximity_tier_1(inp.inventory_tags, static_tag)
    if not tag_present and not static_matches:
        return CorrelatorResult(record=None)
    matching = [
        (rid, sev) for rid, sev in inp.dynamic_findings if rid in _AUTONOMY_RULES
    ]
    if not matching:
        return CorrelatorResult(record=None)
    severity = cap_severity([sev for _, sev in matching])
    # Build evidence list — both sources cited when both fire
    evidence = []
    if tag_present:
        evidence.append(f"Repo tag: {static_tag}")
    for sf_rid, sf_sev, sf_cls in static_matches:
        evidence.append(f"Static finding: {sf_rid} ({sf_sev}, class={sf_cls})")
    evidence.extend(
        f"Dynamic finding: {rid} ({sev})" for rid, sev in matching
    )
    # Confidence lift: count tag (if present) + each static finding
    # + dynamic finding(s) as components. More corroboration = higher
    # confidence, capped at "high" by lift_confidence.
    components = (1 if tag_present else 0) + len(static_matches) + len(matching)
    record = make_aggregate_record(
        canonical_class="approval_gap_supports_autonomy_risk",
        severity=severity,
        confidence=lift_confidence(component_count=components),
        correlator="repo_approval_gap_supports_autonomy_risk",
        repo_root=inp.repo_root,
        session_id=inp.session_id,
        supporting_signal_ids=(
            [rid for rid, _ in matching]
            + [sf_rid for sf_rid, _, _ in static_matches]
        ),
        evidence=evidence,
        rationale=(
            "Repository ships approval-bypass instructions"
            + (" (confirmed by static finding)" if static_matches else "")
            + " and the session demonstrated autonomous or destructive "
            "activity. Cross-signal support raises priority; severity is "
            "capped at the dynamic finding's level per D2."
        ),
    )
    return CorrelatorResult(record=record)


def correlator_fetch_surface_supports_indirect_injection(
    inp: CorrelatorInput,
) -> CorrelatorResult:
    """§5.2: static `has_remote_fetch_instructions` (or matching static
    finding) + dynamic AI-06 → aggregate at proximity 1.

    Static-side canonical classes that satisfy the condition:
    `remote_fetch_or_install_expands_trust_boundary`,
    `prompt_or_instruction_override_surface`, and
    `tool_or_skill_poisoning_surface` — all express fetch-mediated
    trust expansion in different ways. A confirmed rule-pack match
    is sharper than the inventory tag's pattern derivation.
    """
    static_tag = "has_remote_fetch_instructions"
    static_matches = _matching_static_findings(
        inp.static_findings, _FETCH_SURFACE_STATIC_CLASSES,
    )
    tag_present = _proximity_tier_1(inp.inventory_tags, static_tag)
    if not tag_present and not static_matches:
        return CorrelatorResult(record=None)
    matching = [
        (rid, sev) for rid, sev in inp.dynamic_findings if rid in _INDIRECT_INJECTION_RULES
    ]
    if not matching:
        return CorrelatorResult(record=None)
    severity = cap_severity([sev for _, sev in matching])
    evidence = []
    if tag_present:
        evidence.append(f"Repo tag: {static_tag}")
    for sf_rid, sf_sev, sf_cls in static_matches:
        evidence.append(f"Static finding: {sf_rid} ({sf_sev}, class={sf_cls})")
    evidence.extend(
        f"Dynamic finding: {rid} ({sev})" for rid, sev in matching
    )
    components = (1 if tag_present else 0) + len(static_matches) + len(matching)
    record = make_aggregate_record(
        canonical_class="fetch_surface_supports_indirect_injection",
        severity=severity,
        confidence=lift_confidence(component_count=components),
        correlator="repo_fetch_surface_supports_indirect_injection",
        repo_root=inp.repo_root,
        session_id=inp.session_id,
        supporting_signal_ids=(
            [rid for rid, _ in matching]
            + [sf_rid for sf_rid, _, _ in static_matches]
        ),
        evidence=evidence,
        rationale=(
            "Runtime indirect-injection detection occurred in a "
            "repository that also ships fetch-mediated instruction "
            "surfaces"
            + (" (confirmed by static finding)" if static_matches else "")
            + ". The fetch surface explains the injection's delivery vector."
        ),
    )
    return CorrelatorResult(record=record)


def correlator_identity_surface_supports_persistence_risk(
    inp: CorrelatorInput,
) -> CorrelatorResult:
    """§5.3: static `has_identity_rewrite` (or matching static finding)
    + dynamic persistence write → aggregate at proximity 2.

    Tier 2 means the session was actually operating in the same
    subtree as the identity-rewrite instruction. We're more strict
    here than for §5.1 because persistent persona shaping matters
    most when the session is colocated with the surface. A persistence
    write under an unrelated repo doesn't get strengthened just
    because some OTHER repo has a CLAUDE.md persona override.

    Static-side canonical classes: `identity_rewrite_with_persistent_effect`
    or `agent_role_or_goal_manipulation`. Either tag or matching
    static finding satisfies, BUT proximity 2 is still required —
    session cwd must be at-or-under repo root regardless of which
    static signal type fires.
    """
    static_tag = "has_identity_rewrite"
    static_matches = _matching_static_findings(
        inp.static_findings, _IDENTITY_PERSISTENCE_STATIC_CLASSES,
    )
    tag_present = _proximity_tier_1(inp.inventory_tags, static_tag)
    if not tag_present and not static_matches:
        return CorrelatorResult(record=None)
    # Proximity 2: session cwd must be at/under repo root regardless
    # of which static-side type fired
    if not _session_under_repo(inp.session_cwd, inp.repo_root):
        return CorrelatorResult(record=None)
    matching = [
        (rid, sev) for rid, sev in inp.dynamic_findings if rid in _PERSISTENCE_RULES
    ]
    if not matching:
        return CorrelatorResult(record=None)
    severity = cap_severity([sev for _, sev in matching])
    evidence = []
    if tag_present:
        evidence.append(f"Repo tag: {static_tag}")
    for sf_rid, sf_sev, sf_cls in static_matches:
        evidence.append(f"Static finding: {sf_rid} ({sf_sev}, class={sf_cls})")
    evidence.extend(
        f"Dynamic finding: {rid} ({sev})" for rid, sev in matching
    )
    components = (1 if tag_present else 0) + len(static_matches) + len(matching)
    record = make_aggregate_record(
        canonical_class="identity_surface_supports_persistence_risk",
        severity=severity,
        confidence=lift_confidence(component_count=components),
        correlator="repo_identity_surface_supports_persistence_risk",
        repo_root=inp.repo_root,
        session_id=inp.session_id,
        supporting_signal_ids=(
            [rid for rid, _ in matching]
            + [sf_rid for sf_rid, _, _ in static_matches]
        ),
        evidence=evidence,
        rationale=(
            "Persistent persona rewriting in repository instructions"
            + (" (confirmed by static finding)" if static_matches else "")
            + " combined with a session that wrote persistent state. "
            "The static surface explains the runtime persistence pattern."
        ),
    )
    return CorrelatorResult(record=record)


def correlator_educational_context_demotes_runtime_advice(
    inp: CorrelatorInput,
) -> CorrelatorResult:
    """§5.4: educational/red-team repo + medium-or-below
    `advice.dangerous-recommendation` → demote priority (NOT
    severity) via tag.

    Per D3 (settled): severity stays unchanged. Confidence stays
    unchanged. The finding still appears in the report; it's flagged
    as context-sensitive via the `context_demoted` tag so reviewers
    know this was advice given in an educational frame, not in
    production.
    """
    educational = "educational_heavy" in (inp.inventory_tags or set())
    red_team = "red_team_heavy" in (inp.inventory_tags or set())
    if not (educational or red_team):
        return CorrelatorResult(record=None)
    matching = [
        (rid, sev)
        for rid, sev in inp.dynamic_findings
        if rid in _DANGEROUS_RECOMMENDATION_RULES
        and sev in ("info", "low", "medium")  # don't demote high/critical
    ]
    if not matching:
        return CorrelatorResult(record=None)

    # The tag attaches to each matching dynamic finding. We do NOT emit
    # a separate aggregate record with raised severity — instead, we
    # emit an INFO-severity record that explains the demotion and
    # stamps the dynamic findings with the context_demoted tag.
    demote_tag = demote_priority_via_tag()
    applied = {rid: [demote_tag] for rid, _ in matching}

    static_label = "red_team_heavy" if red_team else "educational_heavy"
    severity = cap_severity([sev for _, sev in matching])  # NEVER raised; preserved
    record = make_aggregate_record(
        canonical_class="educational_context_demotes_runtime_advice",
        severity=severity,  # preserved per D3
        confidence="low",   # explicitly low — this is a context note, not an alert
        correlator="repo_educational_context_demotes_runtime_advice",
        repo_root=inp.repo_root,
        session_id=inp.session_id,
        supporting_signal_ids=[rid for rid, _ in matching],
        evidence=[
            f"Repo tag: {static_label}",
            *[f"Dynamic finding (priority demoted): {rid} ({sev})" for rid, sev in matching],
        ],
        tags=[demote_tag],
        rationale=(
            "Repository is labeled educational/red-team training "
            "material. Dangerous-recommendation finding(s) have their "
            "priority demoted (severity preserved per D3) — the "
            "advice was given in a controlled-context frame."
        ),
    )
    return CorrelatorResult(record=record, applied_tags=applied)


# ----------------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------------

# Ordered list of correlators run by the linker. New correlators
# appended here go through the same calibration discipline.
_CORRELATORS: List[Callable[[CorrelatorInput], CorrelatorResult]] = [
    correlator_approval_gap_supports_autonomy_risk,
    correlator_fetch_surface_supports_indirect_injection,
    correlator_identity_surface_supports_persistence_risk,
    correlator_educational_context_demotes_runtime_advice,
]


def all_correlators() -> List[Callable[[CorrelatorInput], CorrelatorResult]]:
    """Return the registered correlators in deterministic order."""
    return list(_CORRELATORS)


def correlator_names() -> List[str]:
    """Return the names of all registered correlators. Used by tests
    and by the linker for deterministic iteration."""
    return [
        "repo_approval_gap_supports_autonomy_risk",
        "repo_fetch_surface_supports_indirect_injection",
        "repo_identity_surface_supports_persistence_risk",
        "repo_educational_context_demotes_runtime_advice",
    ]
