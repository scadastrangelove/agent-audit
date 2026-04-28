from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.detectors.config_audit import CodexConfigAudit  # noqa: E402


def test_codex_missing_approval_mode_does_not_fire(tmp_path):
    home = tmp_path / ".codex"
    home.mkdir()
    (home / "config.toml").write_text('sandbox = "workspace-write"\n', encoding="utf-8")

    findings = list(CodexConfigAudit().check_config(home))

    assert findings == []


def test_codex_explicit_full_auto_still_fires(tmp_path):
    home = tmp_path / ".codex"
    home.mkdir()
    (home / "config.toml").write_text(
        'approval_mode = "full_auto"\nsandbox = "none"\n',
        encoding="utf-8",
    )

    findings = list(CodexConfigAudit().check_config(home))

    assert len(findings) == 1
    assert findings[0].rule_id == "config.codex.permissive.full-auto"
