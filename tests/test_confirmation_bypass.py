"""Unit tests for behavior.confirmation-bypass.

Covers the severity categorization logic — each bypass class maps to
a specific severity level, and not every destructive command should fire.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.events import Event, EventType, AgentKind, Session
from agent_audit.detectors.confirmation_bypass import (
    ConfirmationBypass, _categorize_bypass, _DESTRUCTIVE_WITH_PROMPT,
    _BYPASS_FLAGS,
)
from agent_audit.rules import Severity


def mk_session(commands: list) -> Session:
    """Build a session with Bash tool_use events for each command."""
    events = []
    for i, cmd in enumerate(commands):
        events.append(Event(
            session_id="t", turn_index=i,
            timestamp=datetime(2026, 4, 19, 10, 0, i),
            agent=AgentKind.CLAUDE_CODE, type=EventType.TOOL_USE,
            role="assistant", tool_name="Bash",
            tool_input={"command": cmd},
        ))
    return Session(
        session_id="t", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 0, 10),
        events=events,
    )


# =============================================================================
# Categorization tests
# =============================================================================


def test_migration_bypass_is_critical():
    """drizzle-kit push --force and prisma migrate reset --force = CRITICAL."""
    sev, cat, _ = _categorize_bypass("drizzle-kit push --force")
    assert sev == Severity.CRITICAL
    assert cat == "migration_bypass"

    sev, cat, _ = _categorize_bypass("prisma migrate reset --force")
    assert sev == Severity.CRITICAL
    assert cat == "migration_bypass"


def test_accept_data_loss_is_critical():
    sev, cat, _ = _categorize_bypass("prisma db push --accept-data-loss")
    assert sev == Severity.CRITICAL
    assert cat == "explicit_data_loss"


def test_iac_auto_approve_is_critical():
    sev, cat, _ = _categorize_bypass("terraform destroy -auto-approve")
    assert sev == Severity.CRITICAL
    assert cat == "iac_destroy_bypass"

    sev, cat, _ = _categorize_bypass("tofu destroy --auto-approve")
    assert sev == Severity.CRITICAL
    assert cat == "iac_destroy_bypass"


def test_force_push_is_high():
    sev, cat, _ = _categorize_bypass("git push --force origin main")
    assert sev == Severity.HIGH
    assert cat == "force_push"

    sev, cat, _ = _categorize_bypass("git push -f")
    assert sev == Severity.HIGH
    assert cat == "force_push"


def test_windows_silent_wipe_is_high():
    sev, cat, _ = _categorize_bypass("rmdir /s /q C:\\temp")
    assert sev == Severity.HIGH
    assert cat == "windows_silent_wipe"


def test_kubectl_force_is_high():
    sev, cat, _ = _categorize_bypass("kubectl delete pod/mypod --force")
    assert sev == Severity.HIGH
    assert cat == "kubectl_force_delete"


def test_rm_force_is_low():
    """rm -rf is routine for ephemeral cleanup — LOW, not HIGH."""
    sev, cat, _ = _categorize_bypass("rm -rf /tmp/build")
    assert sev == Severity.LOW
    assert cat == "rm_force"


# =============================================================================
# Detector behavior tests
# =============================================================================


def test_fires_on_drizzle_force():
    session = mk_session(["drizzle-kit push --force"])
    rule = ConfirmationBypass()
    findings = list(rule.check_session(session))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "behavior.confirmation-bypass"


def test_does_not_fire_without_bypass_flag():
    """drizzle-kit push WITHOUT --force shouldn't fire."""
    session = mk_session(["drizzle-kit push"])
    findings = list(ConfirmationBypass().check_session(session))
    assert findings == []


def test_does_not_fire_on_non_destructive():
    """Bypass flag on a non-destructive command shouldn't fire."""
    session = mk_session(["ls -f", "echo --force"])
    findings = list(ConfirmationBypass().check_session(session))
    assert findings == []


def test_does_not_fire_on_safe_git_commands():
    """git status --force would be weird but not destructive in our sense."""
    session = mk_session(["git status", "git log -y"])
    findings = list(ConfirmationBypass().check_session(session))
    # These don't match _DESTRUCTIVE_WITH_PROMPT + _BYPASS_FLAGS combo
    assert all(f.rule_id != "behavior.confirmation-bypass" for f in findings)


def test_subagent_downgrade():
    """Sub-agent sessions get severity down one level."""
    events = [Event(
        session_id="sub", turn_index=0,
        timestamp=datetime(2026, 4, 19, 10, 0, 0),
        agent=AgentKind.CLAUDE_CODE, type=EventType.TOOL_USE,
        role="assistant", tool_name="Bash",
        tool_input={"command": "terraform destroy -auto-approve"},
    )]
    session = Session(
        session_id="sub", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 0, 10),
        events=events,
        is_subagent=True,
    )
    findings = list(ConfirmationBypass().check_session(session))
    assert len(findings) == 1
    # CRITICAL downgraded to HIGH for sub-agents
    assert findings[0].severity == Severity.HIGH


def test_regex_matchers_directly():
    """Sanity on the compiled regexes."""
    assert _DESTRUCTIVE_WITH_PROMPT.search("terraform destroy")
    assert _DESTRUCTIVE_WITH_PROMPT.search("drizzle-kit push")
    assert _DESTRUCTIVE_WITH_PROMPT.search("git push origin main")
    assert not _DESTRUCTIVE_WITH_PROMPT.search("echo hello")

    assert _BYPASS_FLAGS.search("--force")
    assert _BYPASS_FLAGS.search("--auto-approve")
    assert _BYPASS_FLAGS.search("-y")
    assert _BYPASS_FLAGS.search("--accept-data-loss")
    # Should NOT match words containing these strings
    assert not _BYPASS_FLAGS.search("--foo-bar")
    assert not _BYPASS_FLAGS.search("enforce")


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed = 0
    failed = []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed.append((t.__name__, traceback.format_exc()))
    print(f"\n{passed}/{len(tests)} tests passed")
    for name, tb in failed:
        print(f"\n  FAIL: {name}")
        print(f"    {tb.splitlines()[-1]}")
    if failed:
        sys.exit(1)
