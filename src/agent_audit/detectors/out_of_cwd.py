"""Out-of-scope write detector — agent writes files outside its workspace.

If the session's `cwd` is `/Users/alice/project`, any write to `/Users/alice/.ssh/`
or `/etc/` is scope creep. Classic AD-02 (Delegation Model) violation — the
agent was given authority to work in one place but acted elsewhere.

References:
  - ASAMM AD-02 (Delegation Model)
  - ASAMM AO-02 (Intent–Action Gap)
"""
from __future__ import annotations

import os
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Iterable, List, Optional

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)

# Re-use the write target extractor from persistence_write
from .persistence_write import _extract_write_target

# Paths we explicitly allow even if outside cwd (agent tmpfiles, caches).
# Writes here are usually benign.
BENIGN_OUTSIDE = [
    "/tmp/",
    "/var/folders/",       # macOS tmpdir
    "/var/tmp/",
    "/private/tmp/",       # macOS canonical /tmp
    "/private/var/folders/",
]


def _is_inside(path_str: str, base: str) -> bool:
    """True if `path_str` is inside `base` (lexical check, no filesystem access)."""
    try:
        # Use the right path class based on whether this looks like a Windows path
        if ":" in base[:3] or base.startswith("\\\\"):
            P = PureWindowsPath
        else:
            P = PurePosixPath
        path = P(path_str)
        base_p = P(base)

        # Expand ~ at the start (lexical)
        # We can't resolve without filesystem, but ~ in the path clearly
        # points at the user's home — treat it as "outside cwd".
        if str(path).startswith("~"):
            return False

        # Absolute paths — simple prefix check
        if path.is_absolute():
            try:
                path.relative_to(base_p)
                return True
            except ValueError:
                return False

        # Relative paths — assume they resolve relative to cwd, so they're inside
        return True
    except Exception:  # noqa: BLE001
        return False


def _is_benign_outside(path_str: str) -> bool:
    """True if the path is outside cwd but in a known-benign location (/tmp etc)."""
    for prefix in BENIGN_OUTSIDE:
        if path_str.startswith(prefix):
            return True
    return False


class OutOfCwdWrite(Rule):
    id = "AD-02.out-of-cwd-write"
    title = "Agent wrote files outside its working directory"
    severity = Severity.HIGH
    references = ["ASAMM AD-02 (Delegation Model)", "ASAMM AO-02 (Intent–Action Gap)"]

    # Minimum number of out-of-cwd writes to produce a finding
    # (one-off writes are often config-related and handled by other rules)
    min_writes = 2

    def check_session(self, session: Session) -> Iterable[Finding]:
        cwd = session.cwd
        if not cwd:
            # No cwd known — can't check scope. Skip.
            return

        hits: List[tuple[int, str, Event]] = []

        for event in session.events:
            target = _extract_write_target(event)
            if not target:
                continue
            if _is_inside(target, cwd):
                continue
            if _is_benign_outside(target):
                continue
            hits.append((event.turn_index, target, event))

        if len(hits) < self.min_writes:
            return

        # Dedup by directory — we care about "wrote to ~/.ssh/" not each file
        unique_dirs = sorted({os.path.dirname(p) or p for _, p, _ in hits})

        severity = self.severity
        if len(hits) >= 10:
            severity = Severity.CRITICAL

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                f"{len(hits)} writes outside cwd `{cwd}`. "
                f"Directories touched: {', '.join(unique_dirs[:3])}"
                + ("..." if len(unique_dirs) > 3 else "")
            ),
            evidence=[
                Evidence(
                    description=f"Write to {path} (cwd={cwd})",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(turn, turn),
                    snippet=f"tool={event.tool_name} input={str(event.tool_input)[:180]}",
                )
                for turn, path, event in hits[:5]
            ],
            remediation=(
                "Restrict the agent's write scope to its workspace. For Claude Code, "
                "add explicit deny rules for paths outside the project directory."
            ),
            references=self.references,
        )


register_session_rule(OutOfCwdWrite())
