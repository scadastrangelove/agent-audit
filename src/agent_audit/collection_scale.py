"""Collection-scale aggregator — post-scan phase.

Takes a stream of per-file findings and collapses high-replication
patterns into a single aggregate finding per (rule_id, cohort) pair.

Motivation: when a capability template is replicated across a collection
of skills (example: composio-skills/ has 832 SKILL.md files where 817
fire the same rule), the architectural concern is ONE finding about
template replication — not 817 independent findings. Reporting 817 as
separate rows is noise that buries the signal.

A "cohort" is a directory that contains many sibling skill folders —
i.e., the grandparent of a SKILL.md. For `composio-skills/ably/SKILL.md`
the cohort is `composio-skills/`.

Aggregation rules:
  - cohort must have >= COHORT_MIN_SIZE siblings (default 10) to be
    eligible for aggregation; smaller cohorts stay as per-file findings
  - a (rule_id, cohort) pair aggregates when >= COHORT_MIN_HITS siblings
    fire the same rule (default 5) AND replication ratio >= COHORT_MIN_RATIO
    (default 0.10 = 10% of cohort)
  - when aggregation triggers, the aggregate finding replaces the
    individuals; severity preserved, confidence bumped to HIGH
  - the aggregate carries evidence listing up to 5 example files

The aggregator is a pure function: (findings, filesystem view) -> findings.
It does not touch the scanner or rule loader. Added as a post-processing
step in `scan_project`.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .rules import Confidence, Evidence, Finding, Severity


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# Adaptive thresholds — grand-run (v0.11.1 on 100 repos) showed that small
# curated skill-bundle repos (7-15 SKILL.md) produce template replication
# that the original (size>=10, hits>=5) threshold missed. Lowering the
# minimum cohort size catches secondsky/claude-skills and
# affaan-m/everything-claude-code.

COHORT_MIN_SIZE = 5          # was 10. Small skill bundles are cohorts too.
COHORT_MIN_HITS = 3          # was 5. With smaller cohorts, adjust floor.
COHORT_MIN_RATIO = 0.20      # was 0.10. Tighter ratio prevents noise at low N.

# Rationale: at size=5 with hits>=3, ratio 0.20 = 1/5, floor at 3/5=60%
# replication. At size=20 with hits>=3, ratio 0.20 = 4/20, floor at 20%.
# The two floors together mean: "either >=60% of a small cohort OR >=20%
# of a large cohort AND >=3 hits". This keeps large-cohort behavior intact
# while enabling small-cohort aggregation.


# -----------------------------------------------------------------------------
# Cohort discovery
# -----------------------------------------------------------------------------

def _find_cohort_for(path: Path, cohort_cache: Dict[Path, int]) -> Optional[Path]:
    """Return the cohort parent of a file, or None if no cohort qualifies.

    A file lives in a cohort if some ancestor directory has
    >= COHORT_MIN_SIZE sibling SKILL.md files directly under it (one
    level down into sub-directories).

    Walks up from the file's directory — first ancestor that qualifies
    is the cohort. Results memoized in cohort_cache per directory.
    """
    parent = path.parent
    while parent != parent.parent:
        if parent in cohort_cache:
            count = cohort_cache[parent]
        else:
            # Count SKILL.md under direct subdirs of `parent`
            count = 0
            try:
                for child in parent.iterdir():
                    if child.is_dir():
                        if (child / "SKILL.md").exists():
                            count += 1
            except OSError:
                count = 0
            cohort_cache[parent] = count
        if count >= COHORT_MIN_SIZE:
            return parent
        parent = parent.parent
    return None


# -----------------------------------------------------------------------------
# Aggregation
# -----------------------------------------------------------------------------

@dataclass
class _Group:
    cohort: Path
    rule_id: str
    findings: List[Finding]


def aggregate(findings: List[Finding]) -> List[Finding]:
    """Collapse high-replication (rule_id, cohort) pairs into aggregates."""
    if not findings:
        return findings

    # 1. Group findings by (rule_id, cohort)
    cohort_cache: Dict[Path, int] = {}
    groups: Dict[Tuple[str, Path], _Group] = {}
    orphans: List[Finding] = []  # findings not belonging to any cohort

    for f in findings:
        # Get the file the finding refers to
        src = None
        for ev in f.evidence:
            if ev.source:
                src = Path(str(ev.source))
                break
        if src is None:
            orphans.append(f)
            continue
        cohort = _find_cohort_for(src, cohort_cache)
        if cohort is None:
            orphans.append(f)
            continue
        key = (f.rule_id, cohort)
        if key not in groups:
            groups[key] = _Group(cohort=cohort, rule_id=f.rule_id, findings=[])
        groups[key].findings.append(f)

    # 2. For each group: if replication exceeds threshold, aggregate
    aggregated: List[Finding] = list(orphans)  # start with orphans untouched
    for (rule_id, cohort), group in groups.items():
        cohort_size = cohort_cache.get(cohort, 0)
        hit_count = len(group.findings)
        ratio = hit_count / max(1, cohort_size)
        if hit_count >= COHORT_MIN_HITS and ratio >= COHORT_MIN_RATIO:
            aggregated.append(_build_aggregate(group, cohort_size, ratio))
        else:
            # Replication too low — keep individuals
            aggregated.extend(group.findings)
    return aggregated


def _build_aggregate(group: _Group, cohort_size: int, ratio: float) -> Finding:
    """Build a single aggregate Finding from a group."""
    # Take the highest severity among the group's findings
    sev_order = {s: s.order for s in Severity}
    max_sev = max(group.findings, key=lambda f: sev_order[f.severity]).severity
    hit = len(group.findings)

    # Keep up to 5 example file paths + preserve a snippet
    examples = []
    example_snippet = ""
    for f in group.findings[:5]:
        for ev in f.evidence:
            if ev.source:
                examples.append(str(ev.source))
                if not example_snippet and ev.snippet:
                    example_snippet = ev.snippet
                break
    more = hit - len(examples)

    # Template the original rule title / summary from the first finding
    base = group.findings[0]
    cohort_name = group.cohort.name or str(group.cohort)

    summary = (
        f"[COLLECTION-SCALE] Same rule fires in {hit}/{cohort_size} "
        f"({ratio * 100:.0f}%) skills under cohort '{cohort_name}'. "
        f"This is an architectural replication pattern — the rule triggers "
        f"because a single template is reused across the collection. "
        f"Original rule: {base.title}"
    )
    description = (
        f"Cohort: {group.cohort}\n"
        f"Replication: {hit} / {cohort_size} skills ({ratio * 100:.1f}%)\n"
        f"Rule: {group.rule_id}\n"
        f"Example files:\n" +
        "\n".join(f"  - {e}" for e in examples) +
        (f"\n  ... and {more} more" if more > 0 else "")
    )

    # Severity floor — we don't want to downgrade a CRITICAL just because
    # it's replicated, but replication of a HIGH is arguably MORE severe
    # (architectural vs point issue). Keep original severity, bump confidence.

    return Finding(
        rule_id=f"{group.rule_id}#collection-scale",
        title=f"[collection-scale] {base.title}",
        severity=max_sev,
        confidence=Confidence.HIGH,  # replication IS the evidence
        summary=summary,
        evidence=[Evidence(
            description=description,
            source=group.cohort,
            snippet=example_snippet,
        )],
        remediation=(
            base.remediation or
            "Replicated pattern across a collection indicates shared template. "
            "Review the template source once; the fix propagates to all instances."
        ),
        references=list(base.references) + [
            f"aggregation:collection-scale",
            f"cohort-size:{cohort_size}",
            f"replication-ratio:{ratio:.2f}",
            f"aggregated-finding-count:{hit}",
        ],
        needs_llm_verification=base.needs_llm_verification,
    )
