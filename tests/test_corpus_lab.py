from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.corpus_lab import CorpusSnapshot, compare_snapshots  # noqa: E402


def _snapshot(**overrides):
    data = {
        "generated_at": "2026-04-25T12:00:00",
        "corpus_path": "/tmp/corpus",
        "min_severity": "medium",
        "aggregate_collections": True,
        "repos_scanned": 500,
        "files_scanned": 20000,
        "files_with_findings": 10000,
        "findings_total": 9000,
        "findings_shown": 4800,
        "by_severity": {"high": 100},
        "by_tool": {"atr": 1},
        "native_total": 88,
        "native_hot_files": 87,
        "native_rule_counts": {"asamm.AD-02.broad-action-without-approval": 64},
        "report_profiles": {"native": 88},
        "cluster_summary": {"clustered_issue_instances": 300, "multi_finding_clusters": 50, "cross_tool_clusters": 10},
        "security_profile": {"issue_instances": 300, "highest_issue_severity": "critical"},
        "top_canonical_classes": {"unsafe_command_or_execution_surface": 100},
        "top_rule_counts": {"r1": 10},
    }
    data.update(overrides)
    return CorpusSnapshot(**data)


def test_compare_snapshots_passes_when_metrics_hold():
    baseline = _snapshot()
    current = _snapshot(findings_shown=5000)

    comparison = compare_snapshots(baseline, current)

    assert comparison["passed"] is True
    assert comparison["failures"] == []


def test_compare_snapshots_warns_on_cluster_drop():
    baseline = _snapshot()
    current = _snapshot(cluster_summary={"clustered_issue_instances": 250, "multi_finding_clusters": 40, "cross_tool_clusters": 9})

    comparison = compare_snapshots(baseline, current)

    assert comparison["passed"] is True
    assert any("clustered_issue_instances regressed" in warning for warning in comparison["warnings"])


def test_compare_snapshots_fails_on_native_drop():
    baseline = _snapshot()
    current = _snapshot(native_total=80)

    comparison = compare_snapshots(baseline, current)

    assert comparison["passed"] is False
    assert any("native_total regressed" in failure for failure in comparison["failures"])
