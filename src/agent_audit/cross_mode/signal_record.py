# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""SignalRecord — the unified intermediate type per design §2.

`SignalRecord` is NOT a replacement for `Finding`. `Finding` remains the
public output type. `SignalRecord` is the internal normalized form
between scan execution and report rendering. The translation
`Finding → SignalRecord` is mechanical for single-mode findings;
cross-mode aggregate records (origin_mode='aggregate') are new
types that the linker emits.

Per the design draft §2, fields included:
  - id, origin_mode, source_kind, canonical_class
  - severity, confidence
  - repo_root, session_id, scope_key
  - evidence, needs_llm_verification, tags
  - supporting_signal_ids

Phase 2 ships the type and uses it for aggregate records produced by
`linker.link_signals`. Phase 3 will extend it to clustering; Phase 4
to verifier prompts.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional


OriginMode = Literal["static", "dynamic", "probe", "aggregate"]
SourceKind = Literal["repo_file", "session_window", "config", "env_probe", "cross_signal"]


@dataclass
class SignalRecord:
    """Normalized intermediate representation of a signal.

    Aggregate records (produced by Phase 2 correlators) have
    origin_mode='aggregate' and source_kind='cross_signal'; they
    reference their components via supporting_signal_ids.
    """

    id: str
    origin_mode: OriginMode
    source_kind: SourceKind
    canonical_class: str

    # Severity is capped at max(component severities) per D2 — never
    # invented by the linker. For aggregate records, equal to the max
    # severity of the components in supporting_signal_ids.
    severity: str  # "info" | "low" | "medium" | "high" | "critical"

    # Confidence is independent from severity. Aggregate records
    # have higher confidence than their components — that's the point
    # of joining; cross-mode support raises confidence.
    confidence: str  # "low" | "medium" | "high"

    # Optional context
    repo_root: Optional[Path] = None
    session_id: Optional[str] = None

    # Used for grouping in clustering (Phase 3). For Phase 2 records,
    # we set it to canonical_class so single-class records cluster
    # together.
    scope_key: str = ""

    # Free-text evidence pointing at where this signal came from. For
    # aggregate records, typically one item per component.
    evidence: List[str] = field(default_factory=list)

    needs_llm_verification: bool = False

    # Tags carry context modulation (e.g. "context_demoted" for the
    # educational-context demotion correlator §5.4).
    tags: List[str] = field(default_factory=list)

    # IDs of component records (only set when origin_mode='aggregate').
    # The linker fills these so consumers can trace how an aggregate
    # was built.
    supporting_signal_ids: List[str] = field(default_factory=list)

    # The correlator that produced this record (only set when
    # origin_mode='aggregate'). Used by report rendering and tests.
    correlator: Optional[str] = None

    # Human-readable rationale for the aggregation. Only meaningful on
    # aggregate records.
    rationale: str = ""


def _new_aggregate_id() -> str:
    """Generate a stable id for a fresh aggregate record. Short prefix
    so IDs are recognizable in test output."""
    return f"agg-{uuid.uuid4().hex[:12]}"


def make_aggregate_record(
    *,
    canonical_class: str,
    severity: str,
    confidence: str,
    correlator: str,
    repo_root: Optional[Path],
    session_id: Optional[str],
    supporting_signal_ids: List[str],
    evidence: List[str],
    rationale: str,
    tags: Optional[List[str]] = None,
) -> SignalRecord:
    """Constructor for aggregate signal records produced by correlators.

    Centralizes the field defaults so all aggregates share the same
    shape. Severity must already be capped at max(components) by the
    caller — this function does NOT enforce that bound; the linker is
    responsible per D2.
    """
    return SignalRecord(
        id=_new_aggregate_id(),
        origin_mode="aggregate",
        source_kind="cross_signal",
        canonical_class=canonical_class,
        severity=severity,
        confidence=confidence,
        repo_root=repo_root,
        session_id=session_id,
        scope_key=canonical_class,
        evidence=list(evidence),
        needs_llm_verification=False,
        tags=list(tags or []),
        supporting_signal_ids=list(supporting_signal_ids),
        correlator=correlator,
        rationale=rationale,
    )
