# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

from __future__ import annotations

from pathlib import Path

from agent_audit.rules import Confidence, Evidence, Finding, Severity
from agent_audit.signature_curation import apply_curation_profile, available_profiles


def _finding(rule_id: str, severity: Severity, confidence: Confidence = Confidence.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=confidence,
        summary="test",
        evidence=[Evidence(description="e", source=Path("/tmp/demo.md"), snippet="demo")],
    )


def test_curated_profile_is_available():
    assert "curated-v1" in available_profiles()


def test_curated_profile_suppresses_collection_scale_findings():
    findings = [
        _finding("asamm.AD-02.autonomous-loop-with-writes#collection-scale", Severity.HIGH),
        _finding("asamm.AD-02.autonomous-loop-with-writes", Severity.HIGH),
    ]
    curated, summary = apply_curation_profile(findings, "curated-v1")
    assert len(curated) == 1
    assert summary.collection_scale_suppressed == 1
    assert curated[0].rule_id == "asamm.AD-02.autonomous-loop-with-writes"


def test_curated_profile_downgrades_identity_rewrite():
    findings = [_finding("asamm.AI-04.persistent-identity-rewrite", Severity.CRITICAL, Confidence.MEDIUM)]
    curated, summary = apply_curation_profile(findings, "curated-v1")
    assert curated[0].severity == Severity.MEDIUM
    assert curated[0].confidence == Confidence.LOW
    assert curated[0].needs_llm_verification is True
    assert "curation:bucket:downgrade_or_rework" in curated[0].references
    assert summary.severity_downgrades == 1


def test_curated_profile_marks_broad_action_for_verification():
    findings = [_finding("asamm.AD-02.broad-action-without-approval", Severity.HIGH)]
    curated, summary = apply_curation_profile(findings, "curated-v1")
    assert curated[0].severity == Severity.HIGH
    assert curated[0].needs_llm_verification is True
    assert "curation:needs-context" in curated[0].references
    assert summary.verify_recommended_marked == 1
