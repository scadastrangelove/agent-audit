from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.project_report import (  # noqa: E402
    build_files_of_concern,
    build_project_json,
    build_report_profiles,
    render_project_markdown,
)
from agent_audit.report_rerank import rerank  # noqa: E402
from agent_audit.rules import Confidence, Evidence, Finding, Severity  # noqa: E402
from agent_audit.finding_dedup import build_security_profile, cluster_findings  # noqa: E402


def _make(rule_id, src, *, native=False, verify=False, refs=None):
    references = list(refs or [])
    if native:
        references.append("source:agent-audit-native")
    elif not references:
        references.append(f"upstream:atr:{rule_id}")
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        summary="summary",
        evidence=[Evidence(description="d", source=Path(src), snippet="x")],
        references=references,
        needs_llm_verification=verify,
    )


def test_project_profiles_and_files_of_concern():
    findings = [
        _make("asamm.AD-02", "/tmp/hot.md", native=True),
        _make("atr.rule", "/tmp/hot.md", verify=True),
        _make("atr.other#collection-scale", "/tmp/cold.md"),
        _make("atr.edu", "/tmp/cold2.md", refs=["upstream:atr:atr.edu", "suppressor:educational-context"]),
    ]
    rerank_result = rerank(findings)
    clustered_result = cluster_findings(findings)
    security_profile = build_security_profile(clustered_result)

    profiles = build_report_profiles(findings, rerank_result, clustered_result, security_profile)
    files = build_files_of_concern(findings, rerank_result)

    assert profiles["native"] == 1
    assert profiles["rule_pack_in_hot_files"] == 1
    assert profiles["verification_recommended"] == 1
    assert profiles["collection_scale"] == 1
    assert profiles["educational_context_demoted"] == 1
    assert profiles["clustered_issue_instances"] == 4
    assert profiles["multi_signal_issue_instances"] == 0
    assert files[0]["file"] == "/tmp/hot.md"


def test_project_json_includes_clustered_view():
    findings = [
        _make("asamm.AD-02.autonomous-loop-with-writes", "/tmp/hot.md", native=True),
        _make("atr.excessive-autonomy", "/tmp/hot.md"),
        _make("atr.prompt-injection", "/tmp/hot.md"),
    ]
    rerank_result = rerank(findings)

    class _Result:
        repos_scanned = [Path("/tmp/repo")]
        files_scanned = 3
        files_with_findings = 1

    project_json = build_project_json(Path("/tmp/repo"), _Result(), findings, rerank_result)

    assert "clustered_findings" in project_json
    assert "cluster_summary" in project_json
    assert "security_profile" in project_json
    assert project_json["cluster_summary"]["clustered_issue_instances"] == 2
    assert project_json["security_profile"]["issue_instances"] == 2


def test_project_markdown_includes_security_profile_summary():
    findings = [
        _make("asamm.AD-02.autonomous-loop-with-writes", "/tmp/hot.md", native=True),
        _make("atr.excessive-autonomy", "/tmp/hot.md"),
        _make("atr.prompt-injection", "/tmp/hot.md"),
    ]
    rerank_result = rerank(findings)

    class _Result:
        repos_scanned = [Path("/tmp/repo")]
        files_scanned = 3
        files_with_findings = 1

    markdown = render_project_markdown(Path("/tmp/repo"), _Result(), "medium", findings, rerank_result)

    assert "## Security Profile" in markdown
    assert "## Canonical Issue Classes" in markdown
    assert "## Issue Instances To Review First" in markdown
    assert "autonomous_execution_or_looping" in markdown
