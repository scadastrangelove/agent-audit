from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.batch_verifier import CodexCLIBackend


class _Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_codex_backend_sends_prompt_via_stdin(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _Completed(returncode=0, stdout='[{"ok":true}]')

    monkeypatch.setattr("agent_audit.batch_verifier.subprocess.run", fake_run)

    backend = CodexCLIBackend()
    result = backend.call("verify this batch", timeout=12)

    assert result.ok is True
    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert cmd[-1] == "-"
    assert kwargs["input"] == "verify this batch"
    assert kwargs["text"] is True

