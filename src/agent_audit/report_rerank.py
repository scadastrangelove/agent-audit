"""Report reranker — P0 B from grand-run analysis.

Native findings are the highest-signal part of the scanner. Default
severity-ordered rendering buries them inside hundreds of rule-pack
findings. This module rearranges the report view so that:

1. Native findings appear first, in their own section.
2. Files that carry native findings ("hot files") are surfaced as a
   summary block.
3. Rule-pack findings in hot files are promoted inside their severity
   section (they now ride on the context of a real signal).

The reranker is pure: it takes a list of Finding objects and returns
(native_findings, hot_files, remaining_by_severity). Callers decide
how to render. No side effects.
"""
from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


NATIVE_MARKER = "source:agent-audit-native"


def is_native(finding) -> bool:
    return NATIVE_MARKER in (finding.references or [])


def _source_of(finding) -> str:
    """Return canonical source path for a finding, or empty string."""
    for ev in finding.evidence:
        if ev.source:
            return str(ev.source)
    return ""


@dataclass
class RerankResult:
    """Structured output of reranking.

    - native_findings: all native findings, preserved in input order
    - hot_files: paths that have at least one native finding
    - by_severity: OrderedDict[str, List[Finding]] of non-native findings,
      within each severity list, hot-file findings come first
    """
    native_findings: List
    hot_files: List[str]
    by_severity: "OrderedDict[str, List]"


def rerank(findings: List, severity_order: Tuple[str, ...] = (
    "critical", "high", "medium", "low", "info",
)) -> RerankResult:
    """Rerank findings for native-centric presentation."""
    native: List = []
    others: List = []
    for f in findings:
        (native if is_native(f) else others).append(f)

    # Identify hot files — set of paths that carry at least one native finding
    hot = {_source_of(f) for f in native if _source_of(f)}

    # Group non-native by severity, with hot-file findings first in each group
    by_sev: Dict[str, List] = defaultdict(list)
    for f in others:
        by_sev[f.severity.value].append(f)
    for sev, group in by_sev.items():
        # Stable partition: hot-file findings first, then the rest
        group.sort(key=lambda f: 0 if _source_of(f) in hot else 1)

    ordered = OrderedDict()
    for sev in severity_order:
        if sev in by_sev and by_sev[sev]:
            ordered[sev] = by_sev[sev]

    # Hot files sorted by how many findings they carry, desc
    file_counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        src = _source_of(f)
        if src in hot:
            file_counts[src] += 1
    hot_files_sorted = sorted(hot, key=lambda p: -file_counts[p])

    return RerankResult(
        native_findings=native,
        hot_files=hot_files_sorted,
        by_severity=ordered,
    )


def native_summary_dict(result: RerankResult) -> dict:
    """Machine-readable summary suitable for JSON output."""
    from collections import Counter
    rule_counts = Counter(f.rule_id for f in result.native_findings)
    # by file
    by_file = defaultdict(list)
    for f in result.native_findings:
        src = _source_of(f)
        by_file[src].append({
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
        })
    return {
        "total_native": len(result.native_findings),
        "rule_counts": dict(rule_counts.most_common()),
        "hot_files": [
            {"file": p, "findings": by_file[p]}
            for p in result.hot_files
        ],
    }
