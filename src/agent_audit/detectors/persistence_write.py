"""Persistence-vector detector — writes to .git/hooks, CI configs, startup files.

These are classic persistence techniques: modify a file that runs automatically
later. Even a single write here is a significant blast-radius event, regardless
of context — an agent should never touch these without explicit user approval.

References:
  - ASAMM AI-04 (Self-Modification Governance)
  - OWASP AST10 A01 (Unauthorized Action)
"""
from __future__ import annotations

import re
from pathlib import Path
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

# Files/paths where a write is almost always a persistence event.
# Matched against the path the agent is writing to.
PERSISTENCE_TARGETS = re.compile(
    r"""
    (?:^|/|\\)
    (?:
        # Git hooks — run on commit/push/rebase
        \.git/hooks/(?:pre-commit|post-commit|pre-push|post-merge|pre-rebase|
                       prepare-commit-msg|commit-msg|pre-receive|post-receive)
        # v0.7.5 — Agent-tool hooks (Check Point CVE class)
        # These execute when the agent opens a project — same impact
        # as shell rc but specific to agent tooling.
        | \.claude/hooks/.+
        | \.cursor/hooks/.+
        | \.windsurf/hooks/.+
        | \.codex/hooks/.+
        | \.continue/hooks/.+
        # CI / CD configuration
        | \.github/workflows/.+\.ya?ml
        | \.gitlab-ci\.ya?ml
        | \.circleci/config\.ya?ml
        | Jenkinsfile
        | \.drone\.ya?ml
        | \.travis\.ya?ml
        # Shell startup files (persistence via shell init)
        | \.bashrc | \.bash_profile | \.zshrc | \.zprofile | \.profile
        | \.config/fish/config\.fish
        # Cron / systemd user services
        | \.config/systemd/user/.+\.service
        | crontab
        # Build / task runners that auto-execute
        | Makefile | makefile
        | package\.json               # npm hooks, scripts.postinstall
        | pyproject\.toml             # build hooks
        # OS-level autostart
        | \.config/autostart/.+\.desktop
        | Library/LaunchAgents/.+\.plist
        | Library/LaunchDaemons/.+\.plist
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Bash commands that write files. Matches `> path`, `>> path`, `tee path`,
# `echo ... > path`, `cat > path`, `cp src dst`, `mv src dst`, `sed -i`.
BASH_WRITE_CMD = re.compile(
    r"""
    (?:
        \s>{1,2}\s*(?P<redirect>\S+)                    # > path  or >> path
        | \btee(?:\s+-a)?\s+(?P<tee>\S+)                # tee path / tee -a path
        | \bcp\s+\S+\s+(?P<cp>\S+)                      # cp src dst
        | \bmv\s+\S+\s+(?P<mv>\S+)                      # mv src dst
        | \bsed\s+-i[^\s]*\s+(?:-e\s+\S+\s+)?(?P<sed>\S+)
        | \bcat\s+(?:<<-?\s*['"]?\w+['"]?\s+)?>\s*(?P<heredoc>\S+)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Write-style structured tool names (Claude Code). Codex shell writes caught via bash regex.
WRITE_TOOLS = {"write", "edit", "multiedit", "create_file", "str_replace"}


def _extract_write_target(event: Event) -> Optional[str]:
    """Return the path being written to, if this event writes a file."""
    if event.type != EventType.TOOL_USE or not event.tool_input:
        return None
    tool = (event.tool_name or "").lower()
    # v0.8.2: canonical_tool cross-agent — covers Codex apply_patch
    # (canonical "Patch"), create_file variants, etc.
    canonical = getattr(event, "canonical_tool", None)

    # Pattern 1 — structured write tool
    if tool in WRITE_TOOLS or canonical in ("Write", "Edit", "Patch"):
        for key in ("file_path", "path", "filename", "file"):
            value = event.tool_input.get(key)
            if isinstance(value, str):
                return value

    # Pattern 2 — shell redirect / cp / mv / sed -i
    if tool in ("bash", "shell") or canonical == "Bash":
        cmd = event.tool_input.get("command") or event.tool_input.get("cmd")
        if isinstance(cmd, str):
            m = BASH_WRITE_CMD.search(cmd)
            if m:
                # First non-None group is the target
                for name in ("redirect", "tee", "cp", "mv", "sed", "heredoc"):
                    val = m.group(name)
                    if val:
                        # Strip shell quoting
                        return val.strip(' "\'')
    return None


class PersistenceWrite(Rule):
    id = "AI-04.persistence-write"
    title = "Write to persistence-sensitive file"
    severity = Severity.CRITICAL
    references = ["ASAMM AI-04 (Self-Modification Governance)"]

    def check_session(self, session: Session) -> Iterable[Finding]:
        hits: List[tuple[int, str, Event]] = []  # (turn, path, event)

        for event in session.events:
            target = _extract_write_target(event)
            if not target:
                continue
            if PERSISTENCE_TARGETS.search(target):
                hits.append((event.turn_index, target, event))

        if not hits:
            return

        # Group hits into a single finding per session
        unique_targets = sorted({t for _, t, _ in hits})
        first_turn = hits[0][0]
        last_turn = hits[-1][0]

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            summary=(
                f"Agent wrote to {len(hits)} persistence-sensitive file(s): "
                f"{', '.join(unique_targets[:3])}"
                + ("..." if len(unique_targets) > 3 else "")
            ),
            evidence=[
                Evidence(
                    description=f"Write to {path}",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(turn, turn),
                    snippet=f"tool={event.tool_name} input={str(event.tool_input)[:200]}",
                )
                for turn, path, event in hits[:5]
            ],
            remediation=(
                "Review each write individually. Consider adding deny rules for "
                ".git/hooks, CI configs, and shell init files in your agent config."
            ),
            references=self.references,
            needs_llm_verification=False,
        )


register_session_rule(PersistenceWrite())
