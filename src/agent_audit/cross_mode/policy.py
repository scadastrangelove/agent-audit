# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Severity combination policy — Phase 2 of M2.

Implements the settled D2 decision: aggregate records cap severity at
`max(component severities)`. No escalation. Joining raises priority
(via the confidence field) — never severity.

Also implements D3: educational-context demotion adjusts priority,
not severity. The §5.4 correlator sets a `context_demoted` tag and
chooses lower confidence; severity is preserved.

This module is intentionally tiny. It exists so the policy is a single
named place reviewers can audit when they ask "why is this aggregate
HIGH and not CRITICAL?" — the answer is always: because we cap, per
D2.
"""
from __future__ import annotations

from typing import Iterable, List


# Severity ladder, from low to high. Used for max() comparisons.
_SEVERITY_ORDER: List[str] = ["info", "low", "medium", "high", "critical"]


def _severity_index(sev: str) -> int:
    try:
        return _SEVERITY_ORDER.index(sev.lower())
    except ValueError:
        # Unknown severity — treat as "info" (the floor) so it doesn't
        # accidentally inflate a max.
        return 0


def cap_severity(severities: Iterable[str]) -> str:
    """Return the maximum severity from the input list, capped at 'critical'.

    This is the D2 policy: aggregate records carry max(components).
    """
    severities_list = list(severities)
    if not severities_list:
        return "info"
    max_idx = max(_severity_index(s) for s in severities_list)
    return _SEVERITY_ORDER[max_idx]


def lift_confidence(component_count: int, base: str = "medium") -> str:
    """Choose a confidence level for an aggregate record.

    Aggregate records have higher confidence than their components —
    that's the point of joining; cross-mode support raises confidence
    even though severity is capped. Two-component aggregates are
    'high'; single-component aggregates fall back to base (which
    defaults to 'medium').

    For now, a simple count-based bump. Future iterations may consider
    proximity tier and per-correlator confidence weights.
    """
    if component_count >= 2:
        return "high"
    return base


def demote_priority_via_tag() -> str:
    """Return the tag used to mark a finding as priority-demoted.

    Used by the educational-context correlator §5.4. Per D3, severity
    is NOT modified; the tag is the signal that downstream consumers
    (report rendering, verifier scheduler) use to deprioritize.
    """
    return "context_demoted"
