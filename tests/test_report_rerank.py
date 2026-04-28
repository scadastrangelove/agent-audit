"""Unit tests for report_rerank.py."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.report_rerank import (  # noqa: E402
    rerank, native_summary_dict, is_native,
)
from agent_audit.rules import Confidence, Evidence, Finding, Severity  # noqa: E402


def _make(rule_id, src, severity=Severity.HIGH, native=False, title=None):
    refs = ["source:agent-audit-native"] if native else [f"upstream:atr:{rule_id}"]
    return Finding(
        rule_id=rule_id,
        title=title or f"T {rule_id}",
        severity=severity,
        confidence=Confidence.MEDIUM,
        summary="summary",
        evidence=[Evidence(description="d", source=Path(src) if src else None, snippet="")],
        remediation="",
        references=refs,
        needs_llm_verification=False,
    )


def test_native_identification():
    nat = _make("asamm.x", "/p/a.md", native=True)
    pack = _make("atr.x", "/p/a.md", native=False)
    assert is_native(nat)
    assert not is_native(pack)
    print("  ✓ native identification")


def test_rerank_empty():
    r = rerank([])
    assert r.native_findings == []
    assert r.hot_files == []
    assert dict(r.by_severity) == {}
    print("  ✓ rerank empty")


def test_rerank_no_natives():
    findings = [
        _make("atr.A", "/p/x.md", Severity.HIGH),
        _make("atr.B", "/p/y.md", Severity.MEDIUM),
    ]
    r = rerank(findings)
    assert r.native_findings == []
    assert r.hot_files == []
    assert "high" in r.by_severity and "medium" in r.by_severity
    assert len(r.by_severity["high"]) == 1
    assert len(r.by_severity["medium"]) == 1
    print("  ✓ no natives — all go to by_severity")


def test_rerank_native_separated():
    nat = _make("asamm.AI", "/p/hot.md", Severity.CRITICAL, native=True)
    pack = _make("atr.X", "/p/other.md", Severity.CRITICAL)
    r = rerank([pack, nat])
    assert len(r.native_findings) == 1
    assert r.native_findings[0] is nat
    # Pack finding remains in by_severity, not in native
    assert len(r.by_severity["critical"]) == 1
    assert r.by_severity["critical"][0] is pack
    print("  ✓ native separated from pack findings")


def test_hot_files_identified():
    nat = _make("asamm.x", "/p/hot.md", native=True)
    pack_hot = _make("atr.y", "/p/hot.md", Severity.MEDIUM)
    pack_cold = _make("atr.z", "/p/cold.md", Severity.MEDIUM)
    r = rerank([nat, pack_hot, pack_cold])
    assert r.hot_files == ["/p/hot.md"]
    # In by_severity, hot-file finding comes first
    assert r.by_severity["medium"][0] is pack_hot
    assert r.by_severity["medium"][1] is pack_cold
    print("  ✓ hot files identified, hot-file findings promoted within severity")


def test_hot_files_sorted_by_count():
    """Hot file with more findings ranks first."""
    nat_a = _make("asamm.x", "/p/a.md", native=True)
    nat_b = _make("asamm.y", "/p/b.md", native=True)
    # /p/a.md has 4 findings total, /p/b.md has 2
    extras = [
        _make("atr.1", "/p/a.md", Severity.HIGH),
        _make("atr.2", "/p/a.md", Severity.MEDIUM),
        _make("atr.3", "/p/a.md", Severity.LOW),
        _make("atr.4", "/p/b.md", Severity.LOW),
    ]
    r = rerank([nat_a, nat_b] + extras)
    assert r.hot_files == ["/p/a.md", "/p/b.md"]
    print("  ✓ hot files sorted by total finding count desc")


def test_severity_order_preserved():
    findings = [
        _make("atr.low", "/p/a.md", Severity.LOW),
        _make("atr.med", "/p/a.md", Severity.MEDIUM),
        _make("atr.crit", "/p/a.md", Severity.CRITICAL),
        _make("atr.hi", "/p/a.md", Severity.HIGH),
    ]
    r = rerank(findings)
    keys = list(r.by_severity.keys())
    # Order: critical, high, medium, low
    assert keys == ["critical", "high", "medium", "low"]
    print("  ✓ severity ordering critical → low")


def test_native_summary_dict():
    nat1 = _make("asamm.AI-04", "/p/a.md", Severity.CRITICAL, native=True, title="Identity rewrite")
    nat2 = _make("asamm.AD-02", "/p/b.md", Severity.HIGH, native=True, title="Broad action")
    nat3 = _make("asamm.AD-02", "/p/a.md", Severity.HIGH, native=True, title="Broad action")
    r = rerank([nat1, nat2, nat3])
    summary = native_summary_dict(r)
    assert summary["total_native"] == 3
    assert summary["rule_counts"]["asamm.AD-02"] == 2
    assert summary["rule_counts"]["asamm.AI-04"] == 1
    # Hot files contain per-file native finding lists
    files = {entry["file"] for entry in summary["hot_files"]}
    assert files == {"/p/a.md", "/p/b.md"}
    print("  ✓ native_summary_dict structure")


def test_finding_without_source():
    """Findings with no evidence.source are handled (no crash, empty hot file)."""
    nat = Finding(
        rule_id="asamm.x",
        title="t", severity=Severity.HIGH, confidence=Confidence.LOW,
        summary="s",
        evidence=[Evidence(description="d", source=None, snippet="")],
        remediation="",
        references=["source:agent-audit-native"],
        needs_llm_verification=False,
    )
    r = rerank([nat])
    assert len(r.native_findings) == 1
    assert r.hot_files == []  # no source → no hot file
    print("  ✓ sourceless findings handled")


def run_all():
    tests = [
        test_native_identification,
        test_rerank_empty,
        test_rerank_no_natives,
        test_rerank_native_separated,
        test_hot_files_identified,
        test_hot_files_sorted_by_count,
        test_severity_order_preserved,
        test_native_summary_dict,
        test_finding_without_source,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: assertion failed: {e}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"Passed: {passed}/{len(tests)}")
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    run_all()
