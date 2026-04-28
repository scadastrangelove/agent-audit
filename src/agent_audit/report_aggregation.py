"""v0.8.0 — Session aggregation for MD reports.

Problem: real data showed 95% of findings concentrated in 10 sessions
(one session = 445 findings from 10193 events). Flat list of 871
findings is not triageable. Users need session-first view.

Solution: three-layer aggregation that keeps full fidelity in JSON
but provides a collapsible hierarchy in MD.

  Layer 1 — session cards: top-level grouping by session. Each card
  shows session summary (total findings, top rule IDs, dominant
  severity, agent, cwd).

  Layer 2 — rule clusters within a session: if rule X fires N times
  in session Y, one cluster header + representative samples.

  Layer 3 — pattern groups within a cluster: findings are grouped
  by evidence shape (first 80 chars of snippet, hashed). Shows
  "3 representative examples, 266 more like this."

The JSON report is unchanged — full flat list preserved for
downstream tools. This is a reporting-layer change only.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .rules import Finding, Severity


@dataclass
class PatternGroup:
    """Group of findings with structurally similar evidence."""
    pattern_hash: str
    representative: Finding            # one exemplar, shown in MD
    similar_count: int = 0             # how many others match this pattern
    similar_samples: List[Finding] = field(default_factory=list)  # up to 2 more


@dataclass
class RuleCluster:
    """All findings with the same rule_id within a session."""
    rule_id: str
    severity_distribution: Counter     # {"critical": 2, "high": 5, ...}
    total_count: int
    patterns: List[PatternGroup] = field(default_factory=list)


@dataclass
class SessionCard:
    """One session's worth of findings, grouped and ranked."""
    session_id: str
    session_id_short: str              # first 16 chars
    agent: str                         # "claude_code" / "codex"
    cwd: Optional[str]
    total_findings: int
    rule_counts: Counter               # rule_id → count
    severity_counts: Counter           # severity → count
    top_severity: str                  # highest severity present
    clusters: List[RuleCluster] = field(default_factory=list)


# Thresholds
PATTERN_REPRESENTATIVE_LIMIT = 3      # show this many examples per pattern
CLUSTER_SAMPLE_LIMIT = 5              # show this many unique patterns per rule
SESSION_CARD_THRESHOLD = 3            # session gets a card if findings >= this
HEAVY_SESSION_THRESHOLD = 20          # above this, mark as "heavy" — show first


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _severity_rank(sev: str) -> int:
    try:
        return _SEVERITY_ORDER.index(sev)
    except ValueError:
        return 99


def _shape_of(snippet: str) -> str:
    """Compute a stable 'shape hash' for grouping structurally similar
    evidence. We normalize away varying numbers, paths with sprint
    numbers, /tmp/X_id suffixes — so 'rm -rf /tmp/zhet_sprintA' and
    'rm -rf /tmp/zhet_sprintB' hash to the same bucket.
    """
    if not snippet:
        return "<empty>"

    s = snippet[:300]  # look at first 300 chars only
    # Normalize varying tokens:
    s = re.sub(r"/tmp/[\w./-]+", "/tmp/X", s)
    s = re.sub(r"/Users/[^/\s]+/", "/Users/U/", s)
    s = re.sub(r"/home/[^/\s]+/", "/home/U/", s)
    s = re.sub(r"\bsprint[-_]?[a-z0-9']{1,6}\b", "sprintX", s, flags=re.IGNORECASE)
    s = re.sub(r"\brun_?\d+\b", "runN", s, flags=re.IGNORECASE)
    s = re.sub(r"\bv\d+(?:\.\d+)*\b", "vN", s)       # v13, v0.7.7
    s = re.sub(r"\b\d{4,}\b", "NNNN", s)              # 4+ digit numbers (PIDs, timestamps)
    s = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", s, flags=re.IGNORECASE)  # hashes, UUIDs
    s = re.sub(r"turns? \d+[-:]\d+", "turns N-N", s)

    return hashlib.md5(s.encode("utf-8")).hexdigest()[:12]


def _extract_session_id(finding: Finding) -> Optional[str]:
    """Pull the session_id from a finding's first evidence that has one."""
    for ev in finding.evidence:
        if ev.session_id:
            return ev.session_id
    return None


def build_session_cards(
    findings: List[Finding],
    sessions_meta: Optional[Dict[str, dict]] = None,
) -> Tuple[List[SessionCard], List[Finding]]:
    """Group findings by session and build aggregated cards.

    sessions_meta: optional map session_id → metadata dict (agent, cwd,
    event_count, etc). Used to enrich card info.

    Returns (session_cards, orphan_findings) where orphans are findings
    with no session_id (typically config-level rules).
    """
    meta = sessions_meta or {}

    # Group findings by session_id (None for orphans)
    by_session: Dict[Optional[str], List[Finding]] = defaultdict(list)
    for f in findings:
        sid = _extract_session_id(f)
        by_session[sid].append(f)

    orphans = by_session.pop(None, [])

    cards: List[SessionCard] = []
    for sid, sfindings in by_session.items():
        # Rule-level grouping
        by_rule: Dict[str, List[Finding]] = defaultdict(list)
        for f in sfindings:
            by_rule[f.rule_id].append(f)

        clusters: List[RuleCluster] = []
        for rule_id, rfindings in by_rule.items():
            # Pattern grouping within rule
            by_shape: Dict[str, List[Finding]] = defaultdict(list)
            for f in rfindings:
                snippet = ""
                for ev in f.evidence:
                    if ev.snippet:
                        snippet = ev.snippet
                        break
                shape = _shape_of(snippet)
                by_shape[shape].append(f)

            patterns: List[PatternGroup] = []
            for shape, group in by_shape.items():
                # Sort group by severity (critical first) then take rep
                group_sorted = sorted(
                    group,
                    key=lambda f: _severity_rank(f.severity.value),
                )
                pg = PatternGroup(
                    pattern_hash=shape,
                    representative=group_sorted[0],
                    similar_count=len(group) - 1,
                    similar_samples=group_sorted[1:3],  # up to 2 more
                )
                patterns.append(pg)

            # Sort patterns by size (largest cluster first)
            patterns.sort(key=lambda p: -p.similar_count - 1)

            sev_dist = Counter(f.severity.value for f in rfindings)
            clusters.append(RuleCluster(
                rule_id=rule_id,
                severity_distribution=sev_dist,
                total_count=len(rfindings),
                patterns=patterns[:CLUSTER_SAMPLE_LIMIT],
            ))

        # Sort clusters: critical rules first, then by volume
        def cluster_sort_key(c: RuleCluster) -> Tuple[int, int]:
            top_sev = min(
                (_severity_rank(s) for s in c.severity_distribution),
                default=99,
            )
            return (top_sev, -c.total_count)
        clusters.sort(key=cluster_sort_key)

        # Severity rollup across session
        sev_counts = Counter(f.severity.value for f in sfindings)
        top_sev = min(
            (s for s in sev_counts if sev_counts[s] > 0),
            key=_severity_rank,
            default="info",
        )

        m = meta.get(sid, {}) if isinstance(meta, dict) else {}
        cards.append(SessionCard(
            session_id=sid,
            session_id_short=sid[:16] if sid else "<unknown>",
            agent=m.get("agent", "?"),
            cwd=m.get("cwd"),
            total_findings=len(sfindings),
            rule_counts=Counter(f.rule_id for f in sfindings),
            severity_counts=sev_counts,
            top_severity=top_sev,
            clusters=clusters,
        ))

    # Sort cards: top severity first, then by total findings
    cards.sort(key=lambda c: (_severity_rank(c.top_severity), -c.total_findings))
    return cards, orphans
