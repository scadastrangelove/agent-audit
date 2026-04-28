"""Unit tests for behavior.hypothetical-executed.

Covers multi-language hypothetical framing detection, skip cases
(explicit go-ahead, analysis-only requests), and the intent-action
mismatch detection.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.events import Event, EventType, AgentKind, Session
from agent_audit.detectors.hypothetical_executed import (
    HypotheticalExecuted, _is_hypothetical, _destructive_event_signal,
)
from agent_audit.rules import Severity


def mk_user(turn, text):
    return Event(
        session_id="t", turn_index=turn,
        timestamp=datetime(2026, 4, 19, 10, 0, turn),
        agent=AgentKind.CLAUDE_CODE, type=EventType.USER_MESSAGE,
        role="user", text=text,
    )


def mk_tool(turn, tool, inp):
    return Event(
        session_id="t", turn_index=turn,
        timestamp=datetime(2026, 4, 19, 10, 0, turn),
        agent=AgentKind.CLAUDE_CODE, type=EventType.TOOL_USE,
        role="assistant", tool_name=tool, tool_input=inp,
    )


def mk_session(events):
    return Session(
        session_id="t", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 1, 0),
        events=events,
    )


# =============================================================================
# Hypothetical framing detection — multi-language
# =============================================================================


def test_english_hypotheticals():
    """English 'what if' patterns."""
    cases = [
        "what would happen if we deleted the database",
        "what if I removed these files",
        "what happens if the migration runs",
        "suppose we drop the table",
        "hypothetically, if we destroy prod",
        "just wondering what would happen",
        "in theory, would that break things?",
    ]
    for c in cases:
        assert _is_hypothetical(c), f"should be hypothetical: {c}"


def test_russian_hypotheticals():
    cases = [
        "что будет если удалить базу?",
        "что если дропнуть таблицу",
        "представь что мы снесём prod",
        "допустим, удалим всё",
        "гипотетически, что произойдёт",
        "а что если выполнить drop",
        "предположим, что reset пройдёт",
    ]
    for c in cases:
        assert _is_hypothetical(c), f"should be hypothetical: {c}"


def test_chinese_hypotheticals():
    cases = [
        "如果删除数据库会怎样",
        "假设我们重置数据库",
        "如果销毁生产环境会发生什么",
    ]
    for c in cases:
        assert _is_hypothetical(c), f"should be hypothetical: {c}"


def test_not_hypothetical_imperatives():
    """Direct imperative commands are NOT hypothetical."""
    cases = [
        "please delete the database",
        "drop the old table",
        "remove all temp files",
        "удали старую базу",
        "задеплой в прод",
        "删除数据库",
    ]
    for c in cases:
        assert not _is_hypothetical(c), f"should NOT be hypothetical: {c}"


def test_not_hypothetical_analysis_requests():
    """Analysis requests are not hypothetical framing."""
    cases = [
        "explain how the database works",
        "analyze the migration script",
        "describe the schema",
        "объясни что делает этот код",
    ]
    for c in cases:
        assert not _is_hypothetical(c), f"should NOT be hypothetical: {c}"


# =============================================================================
# Destructive event signal detection
# =============================================================================


def test_destructive_bash_detected():
    ev = mk_tool(1, "Bash", {"command": "rm /home/user/db.sqlite"})
    sig = _destructive_event_signal(ev)
    assert sig is not None
    assert sig[0] in ("destructive_cmd", "bash_delete")


def test_non_destructive_bash_not_detected():
    ev = mk_tool(1, "Bash", {"command": "ls -la"})
    sig = _destructive_event_signal(ev)
    assert sig is None


def test_persistence_write_detected():
    ev = mk_tool(1, "Write", {"file_path": "/home/user/.bashrc",
                               "content": "export FOO=bar"})
    sig = _destructive_event_signal(ev)
    assert sig is not None
    assert sig[0] == "persistence_write"


# =============================================================================
# Full detector behavior
# =============================================================================


def test_fires_on_hypothetical_followed_by_delete():
    """Attachment case — issue #28699: user asks hypothetically, agent deletes."""
    session = mk_session([
        mk_user(0, "What would happen if we deleted the database file?"),
        mk_tool(1, "Bash", {"command": "rm /home/user/app/database.db"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert len(findings) == 1
    assert findings[0].rule_id == "behavior.hypothetical-executed"
    assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_does_not_fire_on_explicit_imperative():
    """User explicitly asks to delete — not a hypothetical."""
    session = mk_session([
        mk_user(0, "Please delete the database file"),
        mk_tool(1, "Bash", {"command": "rm /home/user/app/database.db"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert findings == []


def test_does_not_fire_on_go_ahead_override():
    """If user says 'what if... go ahead', that's explicit permission."""
    session = mk_session([
        mk_user(0, "What if we deleted the db? Go ahead and do it"),
        mk_tool(1, "Bash", {"command": "rm /home/user/app/database.db"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert findings == []


def test_does_not_fire_on_analysis_request():
    """User asks to analyze, agent reads (non-destructive)."""
    session = mk_session([
        mk_user(0, "Explain what would happen in the migration"),
        mk_tool(1, "Read", {"file_path": "/home/user/app/migrate.py"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert findings == []


def test_fires_on_russian_hypothetical():
    """Russian hypothetical framing should trigger just like English."""
    session = mk_session([
        mk_user(0, "что будет если удалить базу данных?"),
        mk_tool(1, "Bash", {"command": "rm /home/user/app/database.db"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert len(findings) == 1
    assert findings[0].rule_id == "behavior.hypothetical-executed"


def test_fires_on_chinese_hypothetical():
    session = mk_session([
        mk_user(0, "如果删除数据库会发生什么"),
        mk_tool(1, "Bash", {"command": "rm /home/user/app/database.db"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert len(findings) == 1


def test_no_destructive_no_finding():
    """Hypothetical user message + only read/analysis by agent = no finding."""
    session = mk_session([
        mk_user(0, "What if we changed the config?"),
        mk_tool(1, "Read", {"file_path": "/etc/nginx/nginx.conf"}),
    ])
    findings = list(HypotheticalExecuted().check_session(session))
    assert findings == []


def test_subagent_downgrade():
    """Sub-agent downgrade applies."""
    events = [
        mk_user(0, "what would happen if we deleted the db?"),
        mk_tool(1, "Bash", {"command": "rm /home/user/db.sqlite"}),
    ]
    session = Session(
        session_id="sub", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 1, 0),
        events=events, is_subagent=True,
    )
    findings = list(HypotheticalExecuted().check_session(session))
    assert len(findings) == 1
    # CRITICAL/HIGH → HIGH/MEDIUM in subagent
    assert findings[0].severity in (Severity.HIGH, Severity.MEDIUM)


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
