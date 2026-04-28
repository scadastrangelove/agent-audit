from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.project_scanner import _discover_repos, _walk_project_files


def test_discover_repos_recurses_into_nested_corpus(tmp_path):
    root = tmp_path / "corpus"
    repo_a = root / "category1" / "repo-a"
    repo_b = root / "category2" / "repo-b"
    (repo_a / ".git").mkdir(parents=True)
    (repo_b / ".git").mkdir(parents=True)

    found = _discover_repos(root)

    assert found == sorted([repo_a, repo_b])


def test_walk_project_files_does_not_skip_root_named_build(tmp_path):
    root = tmp_path / "build" / "corpus"
    root.mkdir(parents=True)
    agents = root / "AGENTS.md"
    agents.write_text("agent instructions", encoding="utf-8")

    found = list(_walk_project_files(root))

    assert agents in found

