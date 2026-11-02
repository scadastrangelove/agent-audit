"""Calibration projects resolve within their own synthetic repository roots."""
import json
from types import SimpleNamespace

import pytest

from agent_audit.cross_mode import resolve_session_repo
from agent_audit.cross_mode import calibration_corpus as corpus


@pytest.mark.parametrize("source", corpus.list_calibration_case_dirs(), ids=lambda path: path.name)
def test_materialized_cases_resolve_to_their_own_project(source):
    with corpus.load_calibration_case(source) as case:
        assert resolve_session_repo(str(case.project_root)) == case.project_root.resolve()


def test_markerless_fixture_does_not_resolve_to_parent_repo(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    (parent / ".git").mkdir(parents=True)
    materialized = parent / "materialized"
    materialized.mkdir()
    monkeypatch.setattr(corpus, "tempfile", SimpleNamespace(mkdtemp=lambda **kwargs: str(materialized)))
    source = next(path for path in corpus.list_calibration_case_dirs()
                  if path.name == "c4-educational-demotes-advice")
    with corpus.load_calibration_case(source) as case:
        assert resolve_session_repo(str(case.project_root)) == case.project_root.resolve()


def test_existing_git_file_is_preserved(tmp_path):
    source = tmp_path / "fixture"
    project = source / "project"
    project.mkdir(parents=True)
    marker = "gitdir: ../synthetic-worktree\n"
    (project / ".git").write_text(marker)
    (source / "case.json").write_text(json.dumps({"id": "git-file", "m2_expected": {}}))
    (source / "session.jsonl").write_text('{"cwd": "__CASE_PROJECT__"}\n')
    with corpus.load_calibration_case(source) as case:
        assert (case.project_root / ".git").read_text() == marker
        assert resolve_session_repo(str(case.project_root)) == case.project_root.resolve()


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_educational_cli_context_keeps_high_severity_findings_undemoted(severity):
    from agent_audit.cli import _build_cross_mode_report

    source = next(path for path in corpus.list_calibration_case_dirs()
                  if path.name == "c4-educational-demotes-advice")
    with corpus.load_calibration_case(source) as case:
        raw = {"sessions": [{"session_id": "synthetic", "cwd": str(case.project_root)}],
               "findings": [{"session_id": "synthetic", "finding_id": "F00001",
                   "rule_id": "advice.dangerous-recommendation", "severity": severity}]}
        report = _build_cross_mode_report(raw)
        assert report["sessions_processed"] == 1
        assert "red_team_heavy" in report["inventories"]["synthetic"]["active_tags"]
        assert report["tag_applications"] == {}
        assert report["aggregate_records"] == []
        assert raw["findings"][0]["severity"] == severity
