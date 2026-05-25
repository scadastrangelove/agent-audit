# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for the v0.19 real-data evaluation harness.

Coverage:
  - End-to-end evaluate_corpus produces a summary
  - Static-side scoring (TP/FN, no FP penalty)
  - Correlator-side scoring
  - Drift detection against a baseline
  - Permissive handling of cases lacking v0.19 extension fields
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.eval_harness import (  # noqa: E402
    CorrelatorLabel,
    EvalSummary,
    StageTimings,
    _score_correlator_findings,
    _score_static_findings,
    detect_drift,
    evaluate_corpus,
)
from agent_audit.benchmark import FindingLabel  # noqa: E402


# ---------------------------------------------------------------------------
# Static scoring
# ---------------------------------------------------------------------------

def test_static_scoring_perfect_match():
    expected = [FindingLabel("X.foo", "high"), FindingLabel("Y.bar", "low")]
    actual = [FindingLabel("X.foo", "high"), FindingLabel("Y.bar", "low")]
    tp, fn = _score_static_findings(expected, actual)
    assert len(tp) == 2 and len(fn) == 0


def test_static_scoring_partial_match():
    expected = [FindingLabel("X.foo", "high"), FindingLabel("Y.bar", "low")]
    actual = [FindingLabel("X.foo", "high")]
    tp, fn = _score_static_findings(expected, actual)
    assert len(tp) == 1 and len(fn) == 1
    assert fn[0].rule_id == "Y.bar"


def test_static_scoring_severity_mismatch_counts_as_fn():
    """Severity must match exactly; rule_id alone is insufficient."""
    expected = [FindingLabel("X.foo", "high")]
    actual = [FindingLabel("X.foo", "low")]
    tp, fn = _score_static_findings(expected, actual)
    assert len(tp) == 0 and len(fn) == 1


def test_static_scoring_extra_actuals_not_penalized():
    """Real scan-project produces lots of findings the corpus doesn't
    explicitly label; harness counts recall, not precision."""
    expected = [FindingLabel("X.foo", "high")]
    actual = [
        FindingLabel("X.foo", "high"),
        FindingLabel("Z.unrelated", "low"),
        FindingLabel("W.also-unrelated", "info"),
    ]
    tp, fn = _score_static_findings(expected, actual)
    assert len(tp) == 1 and len(fn) == 0


# ---------------------------------------------------------------------------
# Correlator scoring
# ---------------------------------------------------------------------------

def test_correlator_scoring_match():
    expected = [CorrelatorLabel("repo_approval_gap_supports_autonomy_risk", "high")]
    aggregates = [{
        "correlator": "repo_approval_gap_supports_autonomy_risk",
        "severity": "high",
    }]
    pred, tp, fn = _score_correlator_findings(expected, aggregates)
    assert len(pred) == 1 and len(tp) == 1 and len(fn) == 0


def test_correlator_scoring_miss():
    expected = [CorrelatorLabel("xyz", "high")]
    aggregates = []
    pred, tp, fn = _score_correlator_findings(expected, aggregates)
    assert len(pred) == 0 and len(tp) == 0 and len(fn) == 1


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

def _make_summary(
    forensic_recall: float = 1.0,
    static_recall: float = 1.0,
    correlator_recall: float = 1.0,
    total_seconds: float = 5.0,
) -> EvalSummary:
    return EvalSummary(
        corpus_path="/x", generated_at="t",
        case_count=10, passed_cases=10, failed_cases=0, over_budget_cases=0,
        forensic_tp=10, forensic_fn=0, forensic_fp=0,
        forensic_precision=1.0, forensic_recall=forensic_recall,
        static_tp=5, static_fn=0, static_recall=static_recall,
        correlator_tp=2, correlator_fn=0, correlator_recall=correlator_recall,
        total_wall_seconds=total_seconds,
        median_case_seconds=0.5, max_case_seconds=1.0,
    )


def test_drift_no_change():
    """Equal numbers → no drift."""
    summary = _make_summary()
    baseline = summary.to_dict()
    assert detect_drift(summary, baseline) == []


def test_drift_recall_drop_flagged():
    summary = _make_summary(forensic_recall=0.95)
    baseline = _make_summary().to_dict()
    drifts = detect_drift(summary, baseline)
    assert len(drifts) == 1
    assert "forensic recall dropped" in drifts[0]


def test_drift_perf_regression_flagged():
    summary = _make_summary(total_seconds=20.0)
    baseline = _make_summary(total_seconds=5.0).to_dict()
    drifts = detect_drift(summary, baseline)
    assert any("wall time regression" in d for d in drifts)


def test_drift_perf_within_tolerance_no_flag():
    """1.4× slower is within the 1.5× default tolerance."""
    summary = _make_summary(total_seconds=7.0)
    baseline = _make_summary(total_seconds=5.0).to_dict()
    drifts = detect_drift(summary, baseline)
    assert not any("wall time regression" in d for d in drifts)


def test_drift_static_recall_drop_flagged():
    summary = _make_summary(static_recall=0.5)
    baseline = _make_summary().to_dict()
    drifts = detect_drift(summary, baseline)
    assert any("static recall" in d for d in drifts)


def test_drift_correlator_recall_drop_flagged():
    summary = _make_summary(correlator_recall=0.0)
    baseline = _make_summary().to_dict()
    drifts = detect_drift(summary, baseline)
    assert any("correlator recall" in d for d in drifts)


# ---------------------------------------------------------------------------
# End-to-end harness
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_evaluate_corpus_on_real_incident_corpus():
    """Run harness on the actual incident-corpus. Should pass every case
    on a healthy build.

    v0.19 baseline was 16 cases; v0.20 added 3 N2 cases (16 → 19).
    Future releases adding cases here should keep `>= 16` lower bound
    intact — that's the v0.19-shipped contract — and bump the equality
    check upward as they add cases. Using `>= 16` lets this test survive
    additions without forcing a rewrite, while still failing if cases
    get accidentally deleted.
    """
    corpus = Path(__file__).parent.parent / "benchmarks" / "incident-corpus"
    summary = evaluate_corpus(corpus)
    assert summary.case_count >= 16, (
        f"Corpus shrunk: expected ≥16 cases (the v0.19 baseline), got "
        f"{summary.case_count}. Did a case get accidentally deleted?"
    )
    assert summary.passed_cases == summary.case_count, (
        f"Some cases failed: "
        f"{[cr.case_id for cr in summary.case_results if not cr.passed]}"
    )
    # Recall should be 1.0
    assert summary.forensic_recall == 1.0
    assert summary.static_recall == 1.0
    assert summary.correlator_recall == 1.0
    # Performance: should complete reasonably fast
    assert summary.total_wall_seconds < 60.0, (
        f"Eval took {summary.total_wall_seconds:.1f}s — perf regression?"
    )


def test_evaluate_corpus_handles_empty_corpus(tmp_path):
    """Empty corpus → ValueError, not crash."""
    with pytest.raises(ValueError, match="No benchmark cases"):
        evaluate_corpus(tmp_path)


# ---------------------------------------------------------------------------
# Migration: v0.19 fields are optional
# ---------------------------------------------------------------------------

def test_load_v019_extensions_handles_missing_fields(tmp_path):
    """Cases without expected_static_findings / expected_correlators
    return empty lists, not crash."""
    from agent_audit.eval_harness import _load_v019_extensions
    from agent_audit.benchmark import BenchmarkCase

    case_dir = tmp_path / "minimal-case"
    case_dir.mkdir()
    (case_dir / "case.json").write_text(json.dumps({
        "id": "minimal", "title": "x", "agent": "claude_code",
        "expected_findings": [],
    }))

    case = BenchmarkCase(
        id="minimal", title="x", agent="claude_code",
        expected_findings=[], path=case_dir,
    )

    static_expected, corr_expected, budget = _load_v019_extensions(case)
    assert static_expected == []
    assert corr_expected == []
    assert budget is None


def test_load_v019_extensions_skips_a5_expectations_when_yara_unavailable(
    monkeypatch, tmp_path
):
    """Optional A5 YARA expectations should not fail the harness when the
    runtime lacks yara-python."""
    import agent_audit.eval_harness as eh
    from agent_audit.benchmark import BenchmarkCase

    case_dir = tmp_path / "a5-case"
    case_dir.mkdir()
    (case_dir / "case.json").write_text(
        json.dumps(
            {
                "id": "a5-case",
                "title": "A5 case",
                "agent": "claude_code",
                "expected_static_findings": [
                    {"rule_id": "A5.cisco-yara-credential-harvesting", "severity": "critical"},
                    {"rule_id": "aguara.mcp-attack.tool-description-injection", "severity": "critical"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "session.jsonl").write_text("", encoding="utf-8")

    monkeypatch.setattr(eh, "_static_rule_runtime_available", lambda rule_id: not rule_id.startswith("A5.cisco-yara-"))

    case = BenchmarkCase(
        id="a5-case",
        title="A5 case",
        agent="claude_code",
        expected_findings=[],
        path=case_dir,
    )
    static_expected, corr_expected, budget = eh._load_v019_extensions(case)
    assert static_expected == [
        FindingLabel("aguara.mcp-attack.tool-description-injection", "critical")
    ]
    assert corr_expected == []
    assert budget is None
