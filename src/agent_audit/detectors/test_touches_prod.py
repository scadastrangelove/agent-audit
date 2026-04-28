"""AV-01 Test configuration touches production data paths.

Motivated by the orghound.db-wipe incident: `tests/conftest.py` imported
`orghound.database` BEFORE overriding DATABASE_URL. SQLAlchemy engine got
initialized on `./orghound.db` (the production path), and the test fixture
ran `drop_all/create_all` on it. Every `pytest` was a potential data wipe.

Detection logic:
  1. Find events where agent reads/edits a test configuration file
     (conftest.py, pytest.ini, jest.config.js, vitest.config.ts, etc.)
  2. Inspect the content (from Read tool_result or Write tool_input)
     for references to production-looking DB paths
  3. Flag if no environment-variable override is visible

This complements AG-04 — AG-04 catches the actual wipe happening, AV-01
catches the broken test isolation before a wipe ever occurs.

References:
  - ASAMM AV-01 (Evidence before action)
  - ASAMM AD-02 (Delegation Model)
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)

# Test config filenames. Read or Write of these is a trigger.
TEST_CONFIG_FILE = re.compile(
    r"""
    (?:^|/)
    (?:
        conftest\.py
        | pytest\.ini
        | tox\.ini
        | jest\.config\.(?:js|ts|mjs)
        | jest\.setup\.(?:js|ts)
        | vitest\.config\.(?:js|ts|mjs)
        | karma\.conf\.(?:js|ts)
        | playwright\.config\.(?:js|ts)
        | cypress\.config\.(?:js|ts)
        | \.mocharc\.(?:js|json|yml|yaml)
        | setup\.cfg                      # [tool:pytest] lives here
        | tests?/setup\.(?:py|js|ts)
        | tests?/conftest\.py
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Production-looking DB / storage paths in test config.
# These signal test suites that may write to prod artefacts.
PROD_PATH_IN_TEST = re.compile(
    r"""
    (?:
        # SQLite / generic DB files
        ["'`]?
        (?:\./|\.\\|/)?[\w./\\-]*?
        (?:\.db|\.sqlite3?|\.pgdata|\.rdb)
        ["'`]?
        | sqlite:///[^:\s]*?\.db\b
        | sqlite:///\./?[\w/\\-]+\.db

        # Explicit prod-looking DSN hints (hostname prod/production/live)
        | postgres(?:ql)?://[^/\s]*(?:prod|production|live|main)\b
        | mysql://[^/\s]*(?:prod|production|live|main)\b
        | mongodb://[^/\s]*(?:prod|production|live|main)\b

        # Well-known prod artefact names without env override
        | DATABASE_URL\s*=\s*["'][^"']*\.db["']       # hardcoded DATABASE_URL in test
        | database_url\s*=\s*["'][^"']*\.db["']
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Override patterns — the test config uses env vars for DB URLs.
# If ANY of these appear in the file, we consider the test properly isolated.
ENV_OVERRIDE = re.compile(
    r"""
    (?:
        os\.environ\[["']DATABASE_URL["']\]
        | os\.environ\.get\(["']DATABASE_URL["']
        | os\.environ\.setdefault\(["']DATABASE_URL["']
        | monkeypatch\.setenv\(["']DATABASE_URL["']
        | setenv\s*DATABASE_URL
        | process\.env\.DATABASE_URL

        # Destination is /tmp, :memory:, tmpfile
        | ["']sqlite:///:memory:["']
        | ["']sqlite:///\/tmp/
        | ["']sqlite:///\/var/folders/
        | tmp_path\s*[,)]
        | tmpdir\s*[,)]
        | tempfile\.NamedTemporaryFile
        | tempfile\.mkstemp
        | tempfile\.TemporaryDirectory
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _read_target(event: Event) -> Optional[str]:
    """If this is a Read event, return the path."""
    if event.type != EventType.TOOL_USE or not event.tool_input:
        return None
    tool = (event.tool_name or "").lower()
    if tool not in ("read", "view"):
        return None
    for key in ("file_path", "path", "filename", "file"):
        v = event.tool_input.get(key)
        if isinstance(v, str):
            return v
    return None


def _write_target_and_content(event: Event) -> Optional[Tuple[str, str]]:
    """If this is a Write/Edit event, return (path, new_content)."""
    if event.type != EventType.TOOL_USE or not event.tool_input:
        return None
    tool = (event.tool_name or "").lower()
    if tool not in ("write", "edit", "multiedit", "create_file", "str_replace"):
        return None
    path = None
    for key in ("file_path", "path", "filename", "file"):
        v = event.tool_input.get(key)
        if isinstance(v, str):
            path = v
            break
    if not path:
        return None
    content = (
        event.tool_input.get("content")
        or event.tool_input.get("new_str")
        or event.tool_input.get("file_text")
        or ""
    )
    return path, str(content)


def _find_read_result(session: Session, read_event: Event) -> Optional[str]:
    """Find the tool_result that matches a Read event by tool_use_id."""
    target_id = read_event.tool_use_id
    if not target_id:
        return None
    for event in session.events:
        if event.type == EventType.TOOL_RESULT and event.tool_use_id == target_id:
            return event.tool_result or ""
    return None


class TestTouchesProd(Rule):
    id = "AV-01.test-touches-prod"
    title = "Test configuration references production data paths"
    severity = Severity.HIGH
    references = [
        "ASAMM AV-01 (Evidence before action)",
        "ASAMM AD-02 (Delegation Model)",
    ]

    def check_session(self, session: Session, mode=None) -> Iterable[Finding]:
        seen_files: set = set()  # dedup per (path, session)

        for event in session.events:
            # Case 1 — agent reads a test config, we inspect the content
            read_path = _read_target(event)
            if read_path and TEST_CONFIG_FILE.search(read_path):
                content = _find_read_result(session, event) or ""
                yield from self._check_content(
                    session, event, read_path, content, seen_files,
                    action="read",
                )
                continue

            # Case 2 — agent writes/edits a test config, we inspect new content
            write = _write_target_and_content(event)
            if write:
                path, content = write
                if TEST_CONFIG_FILE.search(path):
                    yield from self._check_content(
                        session, event, path, content, seen_files,
                        action="modified",
                    )

    def _check_content(
        self,
        session: Session,
        event: Event,
        path: str,
        content: str,
        seen: set,
        *,
        action: str,
    ):
        if not content or not PROD_PATH_IN_TEST.search(content):
            return
        if ENV_OVERRIDE.search(content):
            return  # properly isolated
        key = (path, session.session_id)
        if key in seen:
            return
        seen.add(key)

        prod_match = PROD_PATH_IN_TEST.search(content)
        prod_snippet = prod_match.group(0) if prod_match else "(unknown)"

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,  # we're inferring from static content
            summary=(
                f"Test config {path} {action} — references a production-looking "
                f"path ({prod_snippet[:60]}) with no visible env-var override or "
                f"tempfile usage. Running this test suite may touch production data."
            ),
            evidence=[
                Evidence(
                    description=f"Test config {action} at turn {event.turn_index}",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(event.turn_index, event.turn_index),
                    snippet=f"file={path} match={prod_snippet[:150]}",
                ),
            ],
            remediation=(
                "Move test DB paths to environment overrides: os.environ['DATABASE_URL'] "
                "= 'sqlite:///:memory:' BEFORE importing any module that creates a DB "
                "engine. Better — use monkeypatch or tmp_path fixtures. Add an assert "
                "at the top of conftest.py that DATABASE_URL contains /tmp/ or :memory:."
            ),
            references=self.references,
            needs_llm_verification=True,  # context matters — LLM verifier helps here
        )


register_session_rule(TestTouchesProd())
