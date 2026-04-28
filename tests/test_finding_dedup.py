from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.finding_dedup import (  # noqa: E402
    build_security_profile,
    canonical_class_for_rule,
    choose_primary_finding,
    cluster_findings,
)
from agent_audit.rules import Confidence, Evidence, Finding, Severity  # noqa: E402


def _make(rule_id, src, *, severity=Severity.HIGH, confidence=Confidence.MEDIUM, refs=None):
    references = list(refs or [f"upstream:test:{rule_id}"])
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=confidence,
        summary="summary",
        evidence=[Evidence(description="d", source=Path(src), snippet="x")],
        references=references,
        needs_llm_verification=False,
    )


def test_canonical_mapping_merges_expected_cross_pack_classes():
    assert canonical_class_for_rule("asamm.AD-02.autonomous-loop-with-writes") == "autonomous_execution_or_looping"
    assert canonical_class_for_rule("atr.excessive-autonomy.loop") == "autonomous_execution_or_looping"
    assert canonical_class_for_rule("atr.skill-compromise.example") == "tool_or_skill_poisoning_surface"
    assert canonical_class_for_rule("aguara.ssrf-cloud.metadata") == "ssrf_or_internal_service_reachability"


def test_primary_selection_prefers_native_signal():
    native = _make(
        "asamm.AD-02.broad-action-without-approval",
        "/tmp/skill.md",
        severity=Severity.MEDIUM,
        refs=["source:agent-audit-native"],
    )
    pack = _make(
        "atr.excessive-autonomy",
        "/tmp/skill.md",
        severity=Severity.CRITICAL,
    )
    assert choose_primary_finding([pack, native]) is native


def test_clustering_groups_same_scope_and_canonical_class():
    native = _make(
        "asamm.AD-02.autonomous-loop-with-writes",
        "/tmp/skill.md",
        refs=["source:agent-audit-native"],
    )
    pack = _make("atr.excessive-autonomy.loop", "/tmp/skill.md")

    result = cluster_findings([native, pack]).to_dict()

    assert result["summary"]["clustered_issue_instances"] == 1
    assert result["summary"]["multi_finding_clusters"] == 1
    cluster = result["clusters"][0]
    assert cluster["canonical_class"] == "autonomous_execution_or_looping"
    assert cluster["primary_finding"]["rule_id"] == "asamm.AD-02.autonomous-loop-with-writes"
    assert cluster["raw_finding_count"] == 2
    assert sorted(cluster["source_tools"]) == ["agent-audit-native", "test"]


def test_clustering_keeps_distinct_classes_separate_on_same_file():
    autonomy = _make("atr.excessive-autonomy", "/tmp/skill.md")
    prompt = _make("atr.prompt-injection", "/tmp/skill.md")

    result = cluster_findings([autonomy, prompt]).to_dict()

    assert result["summary"]["clustered_issue_instances"] == 2
    classes = {cluster["canonical_class"] for cluster in result["clusters"]}
    assert classes == {
        "autonomous_execution_or_looping",
        "prompt_or_instruction_override_surface",
    }


def test_collection_scale_variant_normalizes_into_same_class():
    a = _make("asamm.AD-02.broad-action-without-approval", "/tmp/a.md", refs=["source:agent-audit-native"])
    b = _make("asamm.AD-02.broad-action-without-approval#collection-scale", "/tmp/a.md", refs=["source:agent-audit-native"])

    result = cluster_findings([a, b]).to_dict()

    assert result["summary"]["clustered_issue_instances"] == 1
    assert result["clusters"][0]["collection_scale_present"] is True


def test_security_profile_summarizes_canonical_issue_view():
    autonomy = _make(
        "asamm.AD-02.autonomous-loop-with-writes",
        "/tmp/skill.md",
        refs=["source:agent-audit-native"],
    )
    prompt = _make("atr.prompt-injection", "/tmp/skill.md")
    clustered = cluster_findings([autonomy, prompt])

    profile = build_security_profile(clustered)

    assert profile["issue_instances"] == 2
    assert profile["highest_issue_severity"] == "high"
    assert "autonomous_execution_or_looping" in profile["canonical_class_counts"]
    assert "prompt_or_instruction_override_surface" in profile["canonical_class_counts"]
    assert profile["canonical_classes_present"] == [
        "autonomous_execution_or_looping",
        "prompt_or_instruction_override_surface",
    ]
    assert profile["native_led_issue_instances"] == 1
