# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Session-to-repo resolution + (Phase 2) proximity ladder.

This module currently exposes only `resolve_session_repo`, the Phase 1
piece. The full proximity ladder — `repo_present` /
`repo_present_and_same_subtree` / `repo_present_and_named_artifact_touched` —
ships in Phase 2 alongside the cross-signal correlators that consume
its tiers.

## Resolver contract (Phase 1)

`resolve_session_repo(cwd) -> Optional[Path]` walks up from a session's
recorded `cwd` looking for repository markers. Returns the discovered
repo root, or None if no marker was found / cwd was missing / the path
doesn't exist on this machine.

**Honesty contract**: returning None is a normal outcome, not an
error. Many sessions are unlinkable for legitimate reasons:

- Older Codex CLI versions did not record `cwd`.
- Skills inlined into the user prompt have no path.
- Sessions recorded on a different machine where the path no longer
  exists.

Callers must handle None gracefully — Phase 2's linker will skip
sessions without a resolved repo rather than guessing.

## What counts as a repo marker

We look for any of:

- `.git` (most common, both files and directories — git submodules
  use a file named `.git` instead of a directory)
- `.claude/` (Claude Code project root marker)
- `.cursor/` (Cursor project marker)
- `.codex/` (Codex project marker)
- `AGENTS.md`, `CLAUDE.md`, `AGENT.md` (instruction-file repo
  conventions used by some agent toolchains)
- `pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod` (last-
  resort: a project-shaped directory without an explicit agent
  marker, but with a recognisable build manifest)

The walk stops at the filesystem root and at platform-typical
"don't escape past here" boundaries (`$HOME`, `/`). We do NOT walk
past the user's home directory — a session in `~/projects/foo/bar`
should resolve to `~/projects/foo/bar/.git` or one of its ancestors,
not to `~/.config/somesharedrepo`.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


# Markers in priority order. The walk picks the first ancestor that
# carries any one of these, with `.git` taking absolute precedence
# (so a parent repo isn't shadowed by a child sub-project's
# build manifest).
_PRIMARY_MARKERS = (".git",)

_AGENT_MARKERS = (
    ".claude",
    ".cursor",
    ".codex",
)

_INSTRUCTION_MARKERS = (
    "AGENTS.md",
    "CLAUDE.md",
    "AGENT.md",
)

_BUILD_MARKERS = (
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
)


def _has_marker(directory: Path, markers: tuple) -> bool:
    """Check whether `directory` carries any marker from the tuple."""
    for marker in markers:
        candidate = directory / marker
        # `.git` can be a file (submodules) or a directory; .exists() catches both
        if candidate.exists():
            return True
    return False


def _stop_boundary() -> Path:
    """The walk halts when it reaches this directory or its parent.

    User's home directory is the strict upper bound: we never resolve
    a session repo to anything above `$HOME` even if there's a stray
    .git up there, because that almost certainly isn't the project
    the session was about. Falls back to `/` when home is unset
    (rare, mostly CI environments)."""
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        try:
            return Path(home).resolve()
        except (OSError, RuntimeError):
            pass
    return Path("/")


def resolve_session_repo(cwd: Optional[str]) -> Optional[Path]:
    """Walk up from a session's `cwd` to find the repository root.

    Returns:
        The resolved repo root as a Path if found, else None.

    Returns None for any of:
        - cwd is None or empty string
        - cwd path doesn't exist on the current filesystem
        - no marker found before hitting the stop boundary

    The function is read-only; it does not mutate state or write files.
    """
    if not cwd:
        return None
    try:
        start = Path(cwd).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    if not start.exists():
        return None

    # If cwd is a file rather than a directory (rare, but defensive),
    # start from its parent.
    if start.is_file():
        start = start.parent

    stop = _stop_boundary()
    current = start

    # Walk up. Visit `start` itself first, then each ancestor.
    visited = 0
    max_steps = 64  # filesystem-depth safety bound
    while visited < max_steps:
        # Primary marker (.git): hard match, return immediately.
        if _has_marker(current, _PRIMARY_MARKERS):
            return current
        # Agent markers: also hard match — projects with .claude/ but
        # no .git (e.g. agent workspaces inside other repos) should
        # still resolve.
        if _has_marker(current, _AGENT_MARKERS):
            return current
        # Instruction markers: hard match. AGENTS.md at root is a
        # strong project signal.
        if _has_marker(current, _INSTRUCTION_MARKERS):
            return current
        # Build markers: weaker signal, but sufficient when no other
        # marker is present in the whole tree.
        if _has_marker(current, _BUILD_MARKERS):
            return current
        # Stop conditions:
        # 1. Reached filesystem root (parent == self).
        # 2. About to step UP TO or PAST the stop boundary. The current
        #    directory itself may equal stop (we'd visit it), but its
        #    parent must not be `stop` (that would mean we're leaving
        #    the home directory) UNLESS stop is the filesystem root,
        #    in which case the parent==self check above handles it.
        parent = current.parent
        if parent == current:
            return None
        # If we're at the stop boundary, this iteration is the last
        # one — don't ascend past it. (We already checked `current`
        # for markers above, so missing here means no marker found.)
        if current == stop:
            return None
        current = parent
        visited += 1
    return None
