# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Linker — Phase 2 of M2.

Takes a `RepoSignalInventory` plus a list of (already-suppressed)
dynamic findings, runs every registered correlator, and returns:

  - new aggregate `SignalRecord` objects to add to the report
  - a `tag_applications` dict mapping rule_id → list of tags to
    attach to any matching dynamic finding (used by §5.4 demotion)

Per D5 (settled), this module assumes the caller has ALREADY filtered
dynamic findings against user-config suppressions. Suppressed findings
must NOT reach the linker — that's the call site's responsibility.

Per D2 (settled), aggregate severity is capped at
max(component severities). The correlators enforce that bound; the
linker just orchestrates.

Per D4 (settled), this module is invoked by a separate `cross-mode`
CLI subcommand (Phase 2 ships the underlying primitive; the CLI
surface is added in a follow-up commit). Phase 1's silent
inventory-attachment in `scanner.scan` is independent — that wiring
populates `ScanResult.repo_inventories` but does NOT auto-invoke the
linker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .correlators import CorrelatorInput, CorrelatorResult, all_correlators
from .inventory import RepoSignalInventory
from .signal_record import SignalRecord


@dataclass
class LinkerOutput:
    """Result of running the linker for one session.

    `aggregate_records` is the set of new `SignalRecord` objects with
    `origin_mode='aggregate'` produced by the correlators. Empty when
    no correlator fired.

    `tag_applications` maps `rule_id → list of tags` describing which
    dynamic findings should receive which tags. Used by §5.4
    educational-context demotion. Empty when no demotion applied.

    `unlinkable_reason` is set to a human-readable explanation when
    the linker couldn't run at all (e.g. session has no resolvable
    cwd, or no inventory). Per the design's honest unlinkable-subset
    contract, this is a normal outcome — most sessions in mixed
    corpora are unlinkable for legitimate reasons.
    """
    aggregate_records: List[SignalRecord] = field(default_factory=list)
    tag_applications: Dict[str, List[str]] = field(default_factory=dict)
    unlinkable_reason: Optional[str] = None


def link_signals(
    *,
    session_id: str,
    session_cwd: Optional[str],
    inventory: Optional[RepoSignalInventory],
    dynamic_findings: List[Tuple[str, str]],
    static_findings: Optional[List[Tuple[str, str, str]]] = None,
) -> LinkerOutput:
    """Run all correlators on a single session's data.

    Args:
        session_id: stable identifier for the session.
        session_cwd: the session's recorded cwd (may be None).
        inventory: the resolved repo's `RepoSignalInventory`, or
            None if the session didn't resolve to a repo.
        dynamic_findings: list of (rule_id, severity) tuples,
            ALREADY filtered against user-config suppressions per D5.
        static_findings: optional list of (rule_id, severity,
            canonical_class) triples from a paired `scan-project` run
            on the same repo, ALREADY filtered against suppressions
            per D5. When provided, correlators check static finding
            canonical_classes alongside inventory tags — a confirmed
            static finding match is a SHARPER signal than a tag.

    Returns:
        A `LinkerOutput` with aggregate records and any tag
        applications. Empty (no records, no tags) when no correlator
        fires — that's the common case for clean sessions and is NOT
        an error.

    Honest unlinkable contract: if either inventory is None or
    dynamic_findings is empty, return early with `unlinkable_reason`
    set. The caller can surface this for diagnostics; it's not a
    failure path. Static_findings being absent is not unlinkable —
    correlators fall back to the tag check.
    """
    if inventory is None:
        return LinkerOutput(
            unlinkable_reason="session did not resolve to a known repo",
        )
    if not dynamic_findings:
        return LinkerOutput(
            unlinkable_reason="session produced no dynamic findings",
        )

    # Build the input bundle once and pass to each correlator.
    inp = CorrelatorInput(
        session_id=session_id,
        session_cwd=session_cwd,
        repo_root=inventory.repo_root,
        inventory_tags=set(inventory.active_tags),
        dynamic_findings=list(dynamic_findings),
        static_findings=list(static_findings or []),
    )

    aggregate_records: List[SignalRecord] = []
    tag_applications: Dict[str, List[str]] = {}

    for correlator in all_correlators():
        result: CorrelatorResult
        try:
            result = correlator(inp)
        except Exception:  # noqa: BLE001
            # A buggy correlator must not break the linker for the
            # session. We swallow the exception and continue with
            # the next correlator. Phase 2 tests verify this.
            continue
        if result.record is not None:
            aggregate_records.append(result.record)
        for rule_id, tags in result.applied_tags.items():
            existing = tag_applications.setdefault(rule_id, [])
            for t in tags:
                if t not in existing:
                    existing.append(t)

    return LinkerOutput(
        aggregate_records=aggregate_records,
        tag_applications=tag_applications,
    )


# ----------------------------------------------------------------------------
# Convenience adapter — bridge between Finding objects and the linker's
# (rule_id, severity) tuple input. Useful for the CLI subcommand that
# operates on saved scan reports.
# ----------------------------------------------------------------------------

def findings_to_link_input(findings: list) -> List[Tuple[str, str]]:
    """Project a list of `Finding`-shaped objects (or dicts) into the
    (rule_id, severity) tuples the linker consumes.

    Accepts both Finding dataclasses and JSON-loaded dicts so callers
    can use the linker against saved JSON reports without first
    reconstructing Finding objects.
    """
    out: List[Tuple[str, str]] = []
    for f in findings:
        if isinstance(f, dict):
            rid = f.get("rule_id") or ""
            sev = f.get("severity") or "info"
        else:
            rid = getattr(f, "rule_id", "") or ""
            sev_obj = getattr(f, "severity", None)
            # Severity may be an enum with a `.value` attr, or a plain
            # string. Normalize both.
            sev = getattr(sev_obj, "value", sev_obj) or "info"
        if rid:
            out.append((str(rid), str(sev)))
    return out


def static_findings_to_link_input(
    findings: list,
) -> List[Tuple[str, str, str]]:
    """Project static `Finding`-shaped objects (or dicts) from a
    `scan-project` run into the (rule_id, severity, canonical_class)
    triples the linker's static-side check consumes.

    Accepts both Finding dataclasses and JSON-loaded dicts. The
    canonical_class is derived via `finding_dedup.canonical_class_for_rule`
    when not present on the input — that helper is the single source
    of truth for rule_id → canonical_class mapping in the codebase.

    Findings without a rule_id are skipped — the adapter is forgiving
    but doesn't propagate garbage.
    """
    # Lazy import to avoid an import cycle: finding_dedup imports from
    # other modules that may indirectly depend on cross_mode.
    from ..finding_dedup import canonical_class_for_rule

    out: List[Tuple[str, str, str]] = []
    for f in findings:
        if isinstance(f, dict):
            rid = f.get("rule_id") or ""
            sev = f.get("severity") or "info"
            cls = f.get("canonical_class") or ""
        else:
            rid = getattr(f, "rule_id", "") or ""
            sev_obj = getattr(f, "severity", None)
            sev = getattr(sev_obj, "value", sev_obj) or "info"
            cls = getattr(f, "canonical_class", "") or ""
        if not rid:
            continue
        # Derive canonical_class if absent. Most paths to this adapter
        # provide it (scan-project clusters by canonical_class), but
        # JSON readers from older bundles may not.
        if not cls:
            cls = canonical_class_for_rule(str(rid))
        out.append((str(rid), str(sev), str(cls)))
    return out
