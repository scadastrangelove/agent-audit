"""Unit tests for collection_scale aggregator.

Covers:
  - cohort discovery (min size, ancestor walking)
  - aggregation threshold (hits AND ratio)
  - severity preservation, confidence bump
  - non-cohort findings pass through unchanged
  - mixed cohort sizes in same scan
  - findings without source file are orphans

Style matches tests/smoke_test.py — plain python, run directly.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

# Add src to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit import collection_scale  # noqa: E402
from agent_audit.rules import Confidence, Evidence, Finding, Severity  # noqa: E402


def _make_finding(rule_id: str, source: Path, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Test finding for {rule_id}",
        severity=severity,
        confidence=Confidence.MEDIUM,
        summary="Test summary",
        evidence=[Evidence(
            description="test",
            source=source,
            snippet="snippet text",
        )],
        remediation="test remediation",
        references=["test:ref"],
        needs_llm_verification=False,
    )


def _build_cohort(root: Path, cohort_name: str, num_skills: int) -> list[Path]:
    """Create a cohort with N sub-directories each containing SKILL.md."""
    cohort = root / cohort_name
    cohort.mkdir(parents=True, exist_ok=True)
    skill_files = []
    for i in range(num_skills):
        sub = cohort / f"skill_{i:03d}"
        sub.mkdir()
        sf = sub / "SKILL.md"
        sf.write_text(f"# skill {i}\n")
        skill_files.append(sf)
    return skill_files


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def test_aggregation_triggers_on_high_replication():
    """Cohort of 20 skills, 15 hits same rule → 1 aggregate."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "big-cohort", 20)
        findings = [_make_finding("rule.A", s) for s in skills[:15]]
        # 5 other findings in smaller sub-cohort that doesn't qualify
        result = collection_scale.aggregate(findings)
        assert len(result) == 1, f"expected 1 aggregate, got {len(result)}"
        agg = result[0]
        assert "#collection-scale" in agg.rule_id
        assert agg.severity == Severity.HIGH
        assert agg.confidence == Confidence.HIGH  # bumped
        assert "15" in agg.summary and "20" in agg.summary
    print("  ✓ aggregation triggers on high replication")


def test_no_aggregation_below_threshold_hits():
    """Cohort of 20 skills, 2 hits → below COHORT_MIN_HITS=3, keep individuals."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "cohort", 20)
        findings = [_make_finding("rule.B", s) for s in skills[:2]]
        result = collection_scale.aggregate(findings)
        assert len(result) == 2, f"expected 2 individuals, got {len(result)}"
        assert all("#collection-scale" not in f.rule_id for f in result)
    print("  ✓ no aggregation below min hits")


def test_no_aggregation_below_threshold_ratio():
    """Cohort of 100 skills, 10 hits → 10% below 20% ratio, keep individuals."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "big-cohort", 100)
        findings = [_make_finding("rule.C", s) for s in skills[:10]]
        result = collection_scale.aggregate(findings)
        # 10 hits meets COHORT_MIN_HITS=3 but 10/100=10% fails COHORT_MIN_RATIO=20%
        assert len(result) == 10, f"expected 10 individuals, got {len(result)}"
    print("  ✓ no aggregation below min ratio")


def test_cohort_too_small():
    """Cohort of 4 skills < COHORT_MIN_SIZE=5 → all findings stay individual."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "tiny", 4)
        findings = [_make_finding("rule.D", s) for s in skills]  # 4 hits
        result = collection_scale.aggregate(findings)
        assert len(result) == 4, f"expected 4 individuals (no cohort), got {len(result)}"
    print("  ✓ cohort below min size — no aggregation")


def test_small_cohort_with_high_replication_aggregates():
    """New in v0.13: cohort of 5 with 4 hits (80%) should aggregate."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "small-bundle", 5)
        findings = [_make_finding("rule.SB", s) for s in skills[:4]]
        result = collection_scale.aggregate(findings)
        # 4/5=80% is well above 20%, 4 hits above min=3
        assert len(result) == 1, f"expected 1 aggregate, got {len(result)}"
        assert "#collection-scale" in result[0].rule_id
    print("  ✓ small cohort with high replication aggregates")


def test_orphan_findings_pass_through():
    """Findings with no evidence.source are orphans, kept as-is."""
    with tempfile.TemporaryDirectory() as td:
        f = Finding(
            rule_id="rule.E",
            title="no source",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            summary="no source",
            evidence=[Evidence(description="d", source=None, snippet="")],
            remediation="",
            references=[],
            needs_llm_verification=False,
        )
        result = collection_scale.aggregate([f])
        assert result == [f]
    print("  ✓ orphans pass through")


def test_severity_preserved_max():
    """Aggregate takes highest severity among group."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "c", 20)
        findings = (
            [_make_finding("rule.F", skills[i], Severity.MEDIUM) for i in range(10)] +
            [_make_finding("rule.F", skills[10], Severity.CRITICAL)]
        )
        result = collection_scale.aggregate(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL
    print("  ✓ severity preserved as max")


def test_mixed_rules_aggregate_separately():
    """Two different rules in same cohort → two aggregates, not one."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "c", 20)
        findings = (
            [_make_finding("rule.X", skills[i]) for i in range(12)] +
            [_make_finding("rule.Y", skills[i]) for i in range(12)]
        )
        result = collection_scale.aggregate(findings)
        assert len(result) == 2
        rule_ids = sorted(f.rule_id for f in result)
        assert rule_ids == ["rule.X#collection-scale", "rule.Y#collection-scale"]
    print("  ✓ different rules aggregate separately")


def test_mixed_cohorts():
    """Findings across two cohorts aggregate per-cohort."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills_a = _build_cohort(root, "cohort-a", 20)
        skills_b = _build_cohort(root, "cohort-b", 15)
        findings = (
            [_make_finding("rule.Z", s) for s in skills_a[:12]] +
            [_make_finding("rule.Z", s) for s in skills_b[:10]]
        )
        result = collection_scale.aggregate(findings)
        # 2 aggregates: one per cohort
        assert len(result) == 2, f"expected 2 aggregates, got {len(result)}"
        # Both tagged collection-scale
        assert all("#collection-scale" in f.rule_id for f in result)
        # Different cohort sources
        sources = {str(f.evidence[0].source) for f in result}
        assert len(sources) == 2
    print("  ✓ mixed cohorts aggregate independently")


def test_below_ratio_keeps_individuals_same_cohort_other_rule_aggregates():
    """In the same cohort: rule.A replicates widely (aggregates),
    rule.B fires only 2 times (below threshold, stays individual)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "c", 20)
        findings = (
            [_make_finding("rule.A", skills[i]) for i in range(15)] +  # aggregates
            [_make_finding("rule.B", skills[i]) for i in range(2)]     # below min hits=3
        )
        result = collection_scale.aggregate(findings)
        # 1 aggregate (rule.A) + 2 individuals (rule.B) = 3
        assert len(result) == 3
        agg_count = sum(1 for f in result if "#collection-scale" in f.rule_id)
        ind_count = sum(1 for f in result if "#collection-scale" not in f.rule_id)
        assert agg_count == 1
        assert ind_count == 2
    print("  ✓ same cohort: some rules aggregate, some don't")


def test_aggregate_references_carry_replication_stats():
    """Aggregate's references include cohort-size, replication-ratio, count."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skills = _build_cohort(root, "c", 20)
        findings = [_make_finding("rule.R", s) for s in skills[:18]]
        result = collection_scale.aggregate(findings)
        assert len(result) == 1
        refs = result[0].references
        assert any(r.startswith("cohort-size:20") for r in refs)
        assert any(r.startswith("replication-ratio:0.9") for r in refs)
        assert any(r.startswith("aggregated-finding-count:18") for r in refs)
        assert any(r == "aggregation:collection-scale" for r in refs)
    print("  ✓ aggregate carries replication stats in references")


def test_empty_input():
    """Empty input returns empty output."""
    assert collection_scale.aggregate([]) == []
    print("  ✓ empty input returns empty")


# -----------------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------------

def run_all():
    tests = [
        test_aggregation_triggers_on_high_replication,
        test_no_aggregation_below_threshold_hits,
        test_no_aggregation_below_threshold_ratio,
        test_cohort_too_small,
        test_small_cohort_with_high_replication_aggregates,
        test_orphan_findings_pass_through,
        test_severity_preserved_max,
        test_mixed_rules_aggregate_separately,
        test_mixed_cohorts,
        test_below_ratio_keeps_individuals_same_cohort_other_rule_aggregates,
        test_aggregate_references_carry_replication_stats,
        test_empty_input,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failed += 1
    print()
    print(f"Passed: {passed}/{len(tests)}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_all()
