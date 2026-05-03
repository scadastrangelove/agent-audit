# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Repository signal inventory — Phase 1 of M2.

A `RepoSignalInventory` is a lightweight summary of the structural
properties of a repository that the static `scan-project` would
otherwise discover. It exists so forensic scans can consume static
context cheaply, without re-running the full project scan.

## What's in an inventory

Two kinds of fields:

1. **Structural tags** — repo-level booleans derived directly from
   file presence and shape. These are repo facts, NOT findings:
   - `has_skills`              — repo ships at least one SKILL.md
   - `has_mcp_manifests`       — at least one mcp.json / .mcp.json /
                                 claude_desktop_config.json
   - `has_plugin_manifests`    — at least one .claude-plugin/plugin.json
                                 or similar
   - `has_remote_fetch_instructions` — instruction surfaces ship
                                 patterns like "fetch X from <url>"
                                 or "curl | sh"
   - `has_broad_action_without_approval` — instruction surfaces
                                 contain "skip approval" / "no
                                 confirmation" patterns
   - `has_identity_rewrite`    — instruction surfaces try to rewrite
                                 the agent's persona ("You are now",
                                 "Forget previous instructions")
   - `educational_heavy`       — >50% of instruction files live in
                                 educational / translation paths
   - `red_team_heavy`          — repo path or top-level README signals
                                 red-team / benchmark / training
                                 material

2. **Counts** — how many artifacts of each kind:
   - `skill_count`, `mcp_manifest_count`, `plugin_manifest_count`,
     `instruction_file_count`

## What's NOT in an inventory

- **Findings.** The inventory is structural facts only. Findings come
  from running rule packs, which is the existing `scan_project` job;
  the inventory deliberately does NOT re-run them. Phase 2 correlators
  will combine inventory tags with already-produced findings from
  separate scans.

- **File contents.** We hash file paths, not bodies; tag-derivation
  reads at most the first ~8KB of each instruction file to look for
  pattern-shaped content. This keeps inventory builds cheap on large
  monorepos.

- **Per-file findings or paths.** The inventory is a repo-level
  summary; per-file detail belongs to `ProjectScanResult`.

## Caching

Inventories are cached per-process by `(repo_root, mtime_fingerprint)`.
The fingerprint is the maximum mtime over the manifest-shaped files
that contribute tags — if any of those files changes, the cache
invalidates. This keeps cost near-zero on repeated calls (e.g. when
multiple forensic sessions point to the same project).

## D5 compliance

Per the settled D5 decision: structural inventory tags survive user
suppressions. They describe **structural facts** about the repository
("this repo has MCP manifests"), not findings. A user suppressing a
finding ABOUT a manifest doesn't change the fact that the manifest
exists. Tags are computed without consulting `agent-audit.yaml`
suppressions; finding-level joins (Phase 2) will respect suppressions
separately.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Discovery patterns (mirror project_scanner._classify_file at a coarse level)
# ----------------------------------------------------------------------------

_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    "target", "out",
}

_SKILL_FILENAMES = {"SKILL.md"}

_MCP_FILENAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
_MCP_DIR_PATTERNS = (".claude/mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")

_PLUGIN_DIR_PATTERNS = (
    ".claude-plugin/plugin.json",
    ".codex-plugin/plugin.json",
    ".cursor-plugin/plugin.json",
)

_INSTRUCTION_FILENAMES = {"AGENTS.md", "CLAUDE.md", "AGENT.md"}


# ----------------------------------------------------------------------------
# Tag-derivation patterns. These are coarse — purpose is "repo has the SHAPE
# of <X> instructions", not "this is provably bad". Cross-signal correlators
# (Phase 2) consume tags as evidence; severity gating happens at finding
# level which the inventory does not produce.
# ----------------------------------------------------------------------------

# "Fetch X from URL" / "curl … | sh" / "wget … | bash" patterns.
_REMOTE_FETCH_PATTERNS = [
    re.compile(r"\bcurl\b[^|\n]+?\|\s*\b(?:sh|bash|zsh|fish)\b", re.IGNORECASE),
    re.compile(r"\bwget\b[^|\n]+?\|\s*\b(?:sh|bash|zsh|fish)\b", re.IGNORECASE),
    re.compile(r"\bfetch\b[^.\n]{0,80}\bfrom\b\s+https?://", re.IGNORECASE),
    re.compile(r"\bdownload[^.\n]{0,40}\bfrom\b\s+https?://", re.IGNORECASE),
]

# Approval-bypass / autonomy-grant patterns. Match instruction PROSE,
# not arbitrary code mentions.
_BROAD_ACTION_PATTERNS = [
    re.compile(r"\b(?:skip|bypass|disable|without)\s+(?:the\s+)?(?:approval|confirmation|prompt)", re.IGNORECASE),
    re.compile(r"\bno\s+(?:approval|confirmation)\s+(?:is\s+)?(?:needed|required)", re.IGNORECASE),
    re.compile(r"\bauto[- ]?approve\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+ask\s+(?:for|the)\s+(?:permission|approval)", re.IGNORECASE),
]

# Identity rewrite / role override patterns. We match the canonical
# attempt forms; precise wording is intentionally varied.
_IDENTITY_REWRITE_PATTERNS = [
    re.compile(r"\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+(?:are|will))", re.IGNORECASE),
    re.compile(r"\b(?:forget|ignore)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|messages)", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+different)", re.IGNORECASE),
    re.compile(r"\boverride\s+(?:your|the)\s+(?:default|original)\s+(?:role|persona|behavior)", re.IGNORECASE),
]

# Educational/red-team hints. These match path components, not prose.
_EDU_PATH_FRAGMENTS = re.compile(
    r"(?:^|/)(?:translations?|i18n|locales?|tutorial[s]?|lesson[s]?|labs?|"
    r"[\w-]*[-_]for[-_]beginners)(?:/|$)",
    re.IGNORECASE,
)
_RED_TEAM_PATH_FRAGMENTS = re.compile(
    r"(?:^|/)(?:red[-_]?team|adversarial|jailbreak|exploit[s]?|attacks?|"
    r"benchmark[s]?|injection[s]?|payloads?)(?:/|$)",
    re.IGNORECASE,
)


# Cap on body bytes read per file for tag derivation. Patterns are anchored at
# instruction-prose shape; full-file matching against a 1MB README would dominate
# scan cost without adding signal.
_PROSE_SCAN_BYTES = 8 * 1024


# ----------------------------------------------------------------------------
# Dataclass
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class RepoSignalInventory:
    """Structural summary of a repository, sufficient for cross-mode correlators.

    All tag fields are repo-level booleans. Counts give magnitude.
    `repo_root` is the canonical absolute path; `fingerprint` is the
    cache key used to detect when the repo changed since this inventory
    was built.
    """

    repo_root: Path
    fingerprint: str

    # Structural tags (per D5 — survive user suppressions, see module docstring)
    has_skills: bool = False
    has_mcp_manifests: bool = False
    has_plugin_manifests: bool = False
    has_instruction_files: bool = False
    has_remote_fetch_instructions: bool = False
    has_broad_action_without_approval: bool = False
    has_identity_rewrite: bool = False
    educational_heavy: bool = False
    red_team_heavy: bool = False

    # Counts
    skill_count: int = 0
    mcp_manifest_count: int = 0
    plugin_manifest_count: int = 0
    instruction_file_count: int = 0

    def to_dict(self) -> Dict[str, object]:
        """Serializable form for inclusion in scan results / debug output."""
        return {
            "repo_root": str(self.repo_root),
            "fingerprint": self.fingerprint,
            "tags": {
                "has_skills": self.has_skills,
                "has_mcp_manifests": self.has_mcp_manifests,
                "has_plugin_manifests": self.has_plugin_manifests,
                "has_instruction_files": self.has_instruction_files,
                "has_remote_fetch_instructions": self.has_remote_fetch_instructions,
                "has_broad_action_without_approval": self.has_broad_action_without_approval,
                "has_identity_rewrite": self.has_identity_rewrite,
                "educational_heavy": self.educational_heavy,
                "red_team_heavy": self.red_team_heavy,
            },
            "counts": {
                "skill_count": self.skill_count,
                "mcp_manifest_count": self.mcp_manifest_count,
                "plugin_manifest_count": self.plugin_manifest_count,
                "instruction_file_count": self.instruction_file_count,
            },
        }

    @property
    def active_tags(self) -> List[str]:
        """List of tag names that are True. Useful for compact rendering."""
        return [name for name, value in self.to_dict()["tags"].items() if value]


# ----------------------------------------------------------------------------
# Walking + classifying
# ----------------------------------------------------------------------------

def _walk_repo_files(repo_root: Path) -> Iterable[Path]:
    """Yield interesting files only — skip vendor / build directories.

    Mirrors project_scanner._walk_project_files but we filter aggressively
    to inventory-relevant kinds only. Files outside this filter never
    contribute to tags, so visiting them is pure overhead.
    """
    if repo_root.is_file():
        yield repo_root
        return
    for dirpath, dirnames, filenames in _walk(repo_root):
        # Prune common skip dirs in-place (os.walk supports this)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def _walk(root: Path):
    """Thin wrapper over os.walk; isolated for ease of mocking in tests."""
    import os
    yield from os.walk(root)


def _classify(path: Path, repo_root: Path) -> Set[str]:
    """Return the set of inventory categories this file belongs to.

    Coarser than `project_scanner._classify_file` — we only care which
    inventory bucket this file goes in, not whether each rule pack
    surface applies.
    """
    cats: Set[str] = set()
    name = path.name
    try:
        rel = path.relative_to(repo_root).as_posix()
    except ValueError:
        rel = path.as_posix()

    if name in _SKILL_FILENAMES:
        cats.add("skill")
        cats.add("instruction")
    if name in _MCP_FILENAMES:
        cats.add("mcp_manifest")
    if any(rel.endswith(p) for p in _MCP_DIR_PATTERNS):
        cats.add("mcp_manifest")
    if any(rel.endswith(p) for p in _PLUGIN_DIR_PATTERNS):
        cats.add("plugin_manifest")
    if name in _INSTRUCTION_FILENAMES:
        cats.add("instruction")
    # Markdown files inside .claude/, .cursor/, .codex/, or directly under
    # the repo root are instruction-shaped enough to scan for tag patterns.
    # Avoid scanning every random README — too noisy and not actually agent
    # instructions.
    if name.lower().endswith(".md"):
        if rel.startswith((".claude/", ".cursor/", ".codex/")) or "/" not in rel:
            cats.add("instruction")
    return cats


def _safe_read(path: Path, max_bytes: int) -> Optional[str]:
    """Read up to max_bytes of `path` as utf-8, returning None on error.

    Defensive against permission errors, binary files, and broken symlinks.
    Truncation at max_bytes is intentional — tag-derivation patterns are
    anchored on instruction-prose shape and don't benefit from full-file
    scanning.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes)
    except (OSError, PermissionError):
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None


# ----------------------------------------------------------------------------
# Tag derivation
# ----------------------------------------------------------------------------

def _has_any_pattern(text: str, patterns: List[re.Pattern]) -> bool:
    """Cheap any-match check. Returns on first hit."""
    for pat in patterns:
        if pat.search(text):
            return True
    return False


def _derive_tags(
    instruction_files: List[Path],
    repo_root: Path,
) -> Dict[str, bool]:
    """Read instruction-shaped files and derive prose-pattern tags.

    Each file is read once and checked against all three pattern groups
    (`remote_fetch`, `broad_action`, `identity_rewrite`). Files that fail
    to read are silently skipped — they can't contribute to a tag if we
    can't see them.
    """
    flags = {
        "has_remote_fetch_instructions": False,
        "has_broad_action_without_approval": False,
        "has_identity_rewrite": False,
    }
    edu_count = 0
    red_count = 0

    for path in instruction_files:
        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            rel = path.as_posix()
        # Path-only signals (don't need file body)
        if _EDU_PATH_FRAGMENTS.search(rel):
            edu_count += 1
        if _RED_TEAM_PATH_FRAGMENTS.search(rel):
            red_count += 1
        # Body-pattern tags: only read if at least one body tag isn't yet set
        if all(flags.values()):
            continue
        text = _safe_read(path, _PROSE_SCAN_BYTES)
        if text is None:
            continue
        if not flags["has_remote_fetch_instructions"] and _has_any_pattern(text, _REMOTE_FETCH_PATTERNS):
            flags["has_remote_fetch_instructions"] = True
        if not flags["has_broad_action_without_approval"] and _has_any_pattern(text, _BROAD_ACTION_PATTERNS):
            flags["has_broad_action_without_approval"] = True
        if not flags["has_identity_rewrite"] and _has_any_pattern(text, _IDENTITY_REWRITE_PATTERNS):
            flags["has_identity_rewrite"] = True

    total = max(1, len(instruction_files))
    flags["educational_heavy"] = (edu_count / total) > 0.5
    # red_team_heavy is more permissive — even one red-team-pathed file
    # counts because the marker is intentional ("we put this here on
    # purpose"), unlike educational/translation which is often incidental.
    flags["red_team_heavy"] = red_count > 0
    return flags


# ----------------------------------------------------------------------------
# Fingerprinting + caching
# ----------------------------------------------------------------------------

def _fingerprint(repo_root: Path, classified_files: Dict[str, List[Path]]) -> str:
    """Compute a cache key sensitive to:
    - the repo root path
    - the maximum mtime of all classified files
    - the count and identity of classified files

    A file added, removed, or modified bumps the fingerprint. A file
    edit that doesn't touch mtime (rare) won't — that's accepted; the
    cache trades absolute correctness for speed and is invalidated
    explicitly via `clear_inventory_cache()` when needed.
    """
    h = hashlib.sha1()
    h.update(str(repo_root).encode("utf-8"))
    # Sort for deterministic fingerprint independent of os.walk order
    all_paths: List[Tuple[str, float]] = []
    for paths in classified_files.values():
        for p in paths:
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0.0
            all_paths.append((str(p), mtime))
    all_paths.sort()
    for path_str, mtime in all_paths:
        h.update(path_str.encode("utf-8"))
        h.update(b"\x00")
        h.update(f"{mtime:.4f}".encode("ascii"))
        h.update(b"\x00")
    return h.hexdigest()


# Process-local cache. Keyed on (resolved_repo_root, fingerprint).
_CACHE: Dict[Tuple[str, str], RepoSignalInventory] = {}


def clear_inventory_cache() -> None:
    """Drop the process-local inventory cache.

    Useful for tests that build inventories on synthetic repos and want
    a clean slate. Production callers should not need this — the
    fingerprint catches genuine changes.
    """
    _CACHE.clear()


def _cache_key(repo_root: Path, fingerprint: str) -> Tuple[str, str]:
    return (str(repo_root), fingerprint)


# ----------------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------------

def build_repo_signal_inventory(repo_root: Path) -> Optional[RepoSignalInventory]:
    """Build (or fetch from cache) the inventory for a repo.

    Returns None if `repo_root` doesn't exist or isn't a directory —
    inventory has no meaning for missing repos. Returns an inventory
    even if it's "empty" (no instruction files at all): the absence
    of all tags is itself useful information for cross-signal
    correlators.
    """
    try:
        resolved = repo_root.resolve()
    except (OSError, RuntimeError):
        return None
    if not resolved.exists() or not resolved.is_dir():
        return None

    # Walk + classify
    classified: Dict[str, List[Path]] = {
        "skill": [], "mcp_manifest": [], "plugin_manifest": [], "instruction": [],
    }
    for path in _walk_repo_files(resolved):
        if not path.is_file():
            continue
        cats = _classify(path, resolved)
        for cat in cats:
            classified[cat].append(path)

    fingerprint = _fingerprint(resolved, classified)
    cache_key = _cache_key(resolved, fingerprint)
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Derive tags from instruction-shaped files
    instruction_files = classified["instruction"]
    derived = _derive_tags(instruction_files, resolved)

    inventory = RepoSignalInventory(
        repo_root=resolved,
        fingerprint=fingerprint,
        has_skills=bool(classified["skill"]),
        has_mcp_manifests=bool(classified["mcp_manifest"]),
        has_plugin_manifests=bool(classified["plugin_manifest"]),
        has_instruction_files=bool(classified["instruction"]),
        has_remote_fetch_instructions=derived["has_remote_fetch_instructions"],
        has_broad_action_without_approval=derived["has_broad_action_without_approval"],
        has_identity_rewrite=derived["has_identity_rewrite"],
        educational_heavy=derived["educational_heavy"],
        red_team_heavy=derived["red_team_heavy"],
        skill_count=len(classified["skill"]),
        mcp_manifest_count=len(classified["mcp_manifest"]),
        plugin_manifest_count=len(classified["plugin_manifest"]),
        instruction_file_count=len(classified["instruction"]),
    )
    _CACHE[cache_key] = inventory
    return inventory
