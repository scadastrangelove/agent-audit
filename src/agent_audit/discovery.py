"""Discover installed AI coding agents on this host.

Works on macOS, Linux and Windows. Read-only — only checks file existence
and counts sessions/configs.

Two discovery tiers:
  1. Primary agents (claude_code, codex, openclaw) — we have parsers, they
     produce sessions we can fully analyse.
  2. Extended agents (Cursor, Aider, Ollama, LM Studio, 100+ others, via
     the Aegis agent database MIT-licensed and bundled under
     knowledge/aegis_agents.json). We detect their config directories,
     run config-level detectors, but have no session parsers for them yet.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .events import AgentKind
from .knowledge import aegis


@dataclass
class AgentInstallation:
    kind: AgentKind
    name: str  # human-readable
    home: Path  # agent's data directory
    sessions_glob: Optional[str] = None  # glob relative to home
    config_paths: List[Path] = field(default_factory=list)
    instruction_paths: List[Path] = field(default_factory=list)

    # Filled in during discovery
    session_count: int = 0
    total_bytes: int = 0
    last_activity: Optional[float] = None  # unix ts

    # v0.6 — for extended (Aegis-derived) agents
    aegis_id: Optional[str] = None  # e.g. "cursor-ai", "ollama"
    has_parser: bool = True  # False for extended agents without parsers

    @property
    def installed(self) -> bool:
        return self.home.exists()


def _home() -> Path:
    return Path.home()


def _claude_code() -> AgentInstallation:
    home = _home() / ".claude"
    return AgentInstallation(
        kind=AgentKind.CLAUDE_CODE,
        name="Claude Code",
        home=home,
        sessions_glob="projects/**/*.jsonl",
        config_paths=[
            home / "settings.json",
            home / "CLAUDE.md",
        ],
        instruction_paths=[home / "CLAUDE.md"],
        aegis_id="claude-code",
    )


def _codex() -> AgentInstallation:
    home = _home() / ".codex"
    return AgentInstallation(
        kind=AgentKind.CODEX,
        name="Codex CLI",
        home=home,
        sessions_glob="sessions/**/*.jsonl",
        config_paths=[
            home / "config.toml",
            home / "AGENTS.md",
        ],
        instruction_paths=[
            home / "AGENTS.md",
            home / "AGENTS.override.md",
        ],
        aegis_id="openai-codex-cli",
    )


def _openclaw() -> AgentInstallation:
    home = _home() / ".openclaw"
    return AgentInstallation(
        kind=AgentKind.OPENCLAW,
        name="OpenClaw",
        home=home,
        sessions_glob="workspace/sessions/**/*",
        config_paths=[home / "workspace" / "SOUL.md"],
        instruction_paths=[
            home / "workspace" / "SOUL.md",
            home / "workspace" / "MEMORY.md",
        ],
        aegis_id="openclaw",
    )


def primary_candidates() -> List[AgentInstallation]:
    """Agents with full session parsers."""
    return [_claude_code(), _codex(), _openclaw()]


# IDs of primary agents — skip them in extended discovery
_PRIMARY_AEGIS_IDS = {"claude-code", "openai-codex-cli", "openclaw"}


def _expand_config_path(raw: str) -> Optional[Path]:
    """Expand a raw Aegis configPath string to a concrete Path.

    Handles:
      - ~/ home expansion
      - %APPDATA% on Windows (returns None on non-Windows)
      - %LOCALAPPDATA%, other Windows env vars
      - Relative paths (skipped — we only check absolute paths in discovery)
    """
    if raw.startswith("~/") or raw.startswith("~\\"):
        return _home() / raw[2:]
    if raw.startswith("%"):
        # Windows env var — try to expand
        if os.name != "nt":
            # On non-Windows, APPDATA-style paths don't apply
            return None
        expanded = os.path.expandvars(raw)
        if "%" in expanded:
            return None  # unexpanded var
        return Path(expanded)
    # Relative path — not useful for home-directory discovery
    if not raw.startswith("/"):
        return None
    return Path(raw)


def extended_candidates() -> List[AgentInstallation]:
    """Build AgentInstallation records for every agent in the Aegis database
    that has at least one concrete config path we can check.

    Skips primary agents (already covered by full parsers).
    """
    out: List[AgentInstallation] = []
    for record in aegis.all_agents():
        agent_id = record["id"]
        if agent_id in _PRIMARY_AEGIS_IDS:
            continue
        cfg_paths = record.get("configPaths") or []
        if not cfg_paths:
            continue

        # Resolve paths; use first existing one as 'home' (or first as default)
        resolved: List[Path] = []
        for raw in cfg_paths:
            p = _expand_config_path(raw)
            if p is not None:
                resolved.append(p)
        if not resolved:
            continue

        # Use first resolved path as home — if it's a directory, treat as-is;
        # if it's a file, use its parent
        home_candidate = resolved[0]
        if home_candidate.exists() and home_candidate.is_file():
            home = home_candidate.parent
        else:
            home = home_candidate

        out.append(AgentInstallation(
            kind=AgentKind.UNKNOWN,
            name=record.get("displayName", agent_id),
            home=home,
            sessions_glob=None,
            config_paths=resolved,
            instruction_paths=[],
            aegis_id=agent_id,
            has_parser=False,
        ))
    return out


def candidates() -> List[AgentInstallation]:
    """All agents (primary + extended), populated or not.

    Kept for backwards compatibility — returns only primary candidates.
    Callers wanting extended discovery should use discover(extended=True).
    """
    return primary_candidates()


def discover(*, extended: bool = False) -> List[AgentInstallation]:
    """Find installed agents and populate their stats.

    Args:
        extended: If True, also checks for ~100 additional agent config dirs
            from the Aegis database. These agents won't have session data
            parsed (no parsers), but config-level detectors still run on them.
    """
    found: List[AgentInstallation] = []
    for agent in primary_candidates():
        if not agent.installed:
            continue
        if agent.sessions_glob:
            sessions = list(agent.home.glob(agent.sessions_glob))
            sessions = [s for s in sessions if s.is_file()]
            agent.session_count = len(sessions)
            agent.total_bytes = sum(s.stat().st_size for s in sessions)
            if sessions:
                agent.last_activity = max(s.stat().st_mtime for s in sessions)
        found.append(agent)

    if extended:
        for agent in extended_candidates():
            # An extended agent is "present" if ANY of its config paths exists
            if not any(p.exists() for p in agent.config_paths):
                continue
            # Filter to paths that actually exist
            agent.config_paths = [p for p in agent.config_paths if p.exists()]
            found.append(agent)

    return found

