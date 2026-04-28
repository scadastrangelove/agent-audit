from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.patch_generator import _write_patch_artifacts


def test_apply_script_quotes_target_path(tmp_path):
    target = tmp_path / "dir with spaces" / "settings.json"
    meta = _write_patch_artifacts(
        tmp_path / "patches",
        "config.claude-code.permissive.no-secret-deny",
        target,
        '{"a":1}\n',
        '{"a":2}\n',
        "demo",
    )

    script = Path(meta["apply_script"]).read_text(encoding="utf-8")
    assert "TARGET='" in script or 'TARGET="/' in script
    assert "cp -- \"$TARGET\" \"$BACKUP\"" in script
    assert "cp -- \"$AFTER\" \"$TARGET\"" in script

