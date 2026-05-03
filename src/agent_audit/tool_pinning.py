# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tool-pinning / rug-pull state tracker — Roadmap item N1.

Detects the rug-pull attack class: an MCP server author publishes a benign
tool description, users install the server, and then a later update changes
the description to inject malicious instructions. The tool's name and
schema stay the same so users don't notice; only the description changes.

This is a stateful detector — it has to remember what tool descriptions
looked like on previous scans. We persist a per-project baseline under
~/.agent-audit/tool-pinning/<fingerprint>.json mapping each tool to the
hash and content of its last-observed description. On every subsequent
scan we compare and emit findings on changes.

## Threat model and bounds

What this detects:
- MCP tool description text changes between scans of the same project.
- Tool added/removed between scans (informational only).

What this does NOT detect:
- Server-side description changes when the project doesn't ship the
  manifest itself (a remote MCP server can change descriptions at
  runtime). That requires runtime probing, not file inspection.
- Schema changes (input args, output type). Schema-shape rug-pulls are a
  separate detector class — left for a follow-up native detector.
- First-scan baseline poisoning: if the very first scan sees an already-
  poisoned description, we record it as the baseline silently. Mitigation:
  pair this detector with the static tool-description rule pack scans
  (which DO catch poisoned text on first sight).

## Identity model

Each tool is identified by:
- manifest_path: path to the MCP manifest file, relative to project root
- server_name: key under "mcpServers" or equivalent
- tool_name: name of the tool inside the server's tool list

Identity = (server_name, tool_name) per manifest. We do NOT include the
description content in the identity — that's what we're tracking changes
in. We also do NOT include the tool schema, because schema changes
should trigger findings (and would change identity if we included them,
producing add/remove pairs instead of changes).

## Storage

Per-project baseline files live under:
    ~/.agent-audit/tool-pinning/<sha1(abspath)>.json

Format:
    {
      "schema_version": 1,
      "project_path": "/abs/path/to/project",
      "tools": {
        "manifest:rel/path/mcp.json::server-name::tool-name": {
          "description_hash": "sha256...",
          "description_preview": "first 200 chars",
          "first_seen": "2026-05-03T18:42:11Z",
          "last_seen": "2026-05-03T18:42:11Z",
          "scan_count": 1
        }
      }
    }

We don't persist full descriptions to keep state files small; the
description_preview is for human review on findings. The hash gate is
the source of truth for change detection.

## Invocation

The detector exposes `check_project(project_path) -> List[Finding]`.
The project_scanner integration calls it after the regular scan, so
all findings flow through the same reporting pipeline.

The detector is opt-in via a CLI flag rather than always-on: state
mutation on every scan is a footgun for users running ad-hoc scans on
arbitrary repos. The CLI guards with `--track-tool-pinning`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .rules import Confidence, Evidence, Finding, Severity

log = logging.getLogger(__name__)


_SCHEMA_VERSION = 1


# ----------------------------------------------------------------------------
# State file location
# ----------------------------------------------------------------------------

def _state_root() -> Path:
    """Where per-project tool-pinning baselines live.

    Honors $AGENT_AUDIT_STATE_DIR for testability; otherwise uses
    ~/.agent-audit/tool-pinning/.
    """
    override = os.environ.get("AGENT_AUDIT_STATE_DIR")
    if override:
        return Path(override) / "tool-pinning"
    return Path.home() / ".agent-audit" / "tool-pinning"


def _project_fingerprint(project_path: Path) -> str:
    """Deterministic fingerprint for a project path.

    Different paths → different fingerprints. Same path on different
    machines → same fingerprint (we don't include hostname). Symlinks
    are followed so /var/tmp/repo and /private/var/tmp/repo on macOS
    produce the same key.
    """
    canonical = str(project_path.resolve())
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:16]


def _state_file_for(project_path: Path) -> Path:
    return _state_root() / f"{_project_fingerprint(project_path)}.json"


# ----------------------------------------------------------------------------
# Baseline I/O
# ----------------------------------------------------------------------------

def load_baseline(project_path: Path) -> Optional[Dict]:
    """Read the existing baseline. Returns None if no prior scan exists.

    Caller can distinguish first scan (None) from corrupted state
    (raises) to decide whether to emit findings.
    """
    p = _state_file_for(project_path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("Tool-pinning baseline at %s unreadable: %s", p, e)
        return None


def save_baseline(project_path: Path, tools: Dict[str, Dict]) -> Path:
    """Write the new baseline atomically. Returns the file path."""
    state_dir = _state_root()
    state_dir.mkdir(parents=True, exist_ok=True)
    out = _state_file_for(project_path)
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "project_path": str(project_path.resolve()),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "tools": tools,
    }
    # Atomic write: tmp file + rename
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(out)
    return out


# ----------------------------------------------------------------------------
# MCP manifest discovery + tool extraction
# ----------------------------------------------------------------------------

_MCP_MANIFEST_PATTERNS = [
    "**/.claude/mcp.json",
    "**/.cursor/mcp.json",
    "**/.vscode/mcp.json",
    "**/claude_desktop_config.json",
    "**/mcp.json",
    "**/.mcp.json",
]


def _discover_mcp_manifests(project_path: Path) -> List[Path]:
    """Find all MCP manifests under the project."""
    seen: set = set()
    out: List[Path] = []
    for pattern in _MCP_MANIFEST_PATTERNS:
        for p in project_path.rglob(pattern.removeprefix("**/")):
            if p.is_file() and p.resolve() not in seen:
                seen.add(p.resolve())
                out.append(p)
    return sorted(out)


def _extract_tools_from_manifest(manifest_path: Path) -> List[Tuple[str, str, str]]:
    """Return list of (server_name, tool_name, description) tuples.

    Handles two manifest shapes:
    1. Cursor / Claude desktop style: { "mcpServers": { "name": { "command": ..., "args": ... } } }
       — these don't ship tool descriptions inline; tools come from runtime.
       We can still record (server_name, "_server_meta", description-equivalent)
       using stable fields like command + args, but that's noisier than
       useful. Skip these for now.
    2. Inline tool-list style: { "mcpServers": { "name": { ..., "tools": [{"name": ..., "description": ...}] } } }
       — used by some tooling that pre-imports tool metadata. Process these.
    """
    try:
        content = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(content, dict):
        return []

    out: List[Tuple[str, str, str]] = []
    servers = content.get("mcpServers", {}) or content.get("mcp_servers", {})
    if not isinstance(servers, dict):
        return []

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        # Inline tool-list (rare but explicit)
        tools_inline = server_cfg.get("tools")
        if isinstance(tools_inline, list):
            for tool in tools_inline:
                if not isinstance(tool, dict):
                    continue
                tname = str(tool.get("name", "")).strip()
                tdesc = str(tool.get("description", "")).strip()
                if tname and tdesc:
                    out.append((str(server_name), tname, tdesc))

        # Some manifests pre-cache the description as `description` on the
        # server itself (rare, but seen in MCP toolkits)
        desc = server_cfg.get("description")
        if isinstance(desc, str) and desc.strip() and not tools_inline:
            # Use server name as tool name in this case — there's no
            # tool-list to disambiguate against
            out.append((str(server_name), "_server_meta", desc.strip()))

    return out


def _normalize_description(desc: str) -> str:
    """Apply normalization before hashing.

    Whitespace collapse + Unicode NFC. We deliberately do NOT strip
    invisible characters: a rug-pull that smuggles zero-width spaces
    into the description IS the attack we want to detect, so the hash
    must be sensitive to it.
    """
    import unicodedata
    normalized = unicodedata.normalize("NFC", desc)
    # Collapse runs of regular whitespace (spaces, tabs, newlines) into
    # a single space. Non-whitespace invisible chars (ZWSP etc.) survive.
    normalized = re.sub(r"[ \t\r\n]+", " ", normalized).strip()
    return normalized


def _hash_description(desc: str) -> str:
    return hashlib.sha256(_normalize_description(desc).encode("utf-8")).hexdigest()


def _tool_key(manifest_path: Path, project_root: Path,
              server_name: str, tool_name: str) -> str:
    """Stable per-tool key used in the baseline JSON."""
    rel = manifest_path.relative_to(project_root)
    return f"manifest:{rel}::{server_name}::{tool_name}"


def _preview(desc: str, n: int = 200) -> str:
    """Short preview of description for human review on findings."""
    s = _normalize_description(desc)
    if len(s) <= n:
        return s
    return s[:n - 1] + "…"


# ----------------------------------------------------------------------------
# Comparison + finding emission
# ----------------------------------------------------------------------------

def _make_changed_finding(
    tool_key: str, server_name: str, tool_name: str,
    old_preview: str, new_preview: str,
    old_hash: str, new_hash: str,
) -> Finding:
    return Finding(
        rule_id="N1.tool-pinning.description-changed",
        title="MCP tool description changed since last scan",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        summary=(
            f"Tool '{tool_name}' on server '{server_name}' has a different "
            f"description than the last scan recorded — possible rug-pull."
        ),
        evidence=[Evidence(
            description=(
                f"Previous hash: {old_hash[:16]}…\n"
                f"Previous preview: {old_preview}\n\n"
                f"Current hash: {new_hash[:16]}…\n"
                f"Current preview: {new_preview}"
            ),
            snippet=new_preview[:200],
        )],
        remediation=(
            "Review the description change carefully. If it's a legitimate "
            "update, re-run with --track-tool-pinning to update the "
            "baseline. If it looks malicious (new instructions, hidden "
            "characters, role-override language), unpin the server or "
            "downgrade to the previous version."
        ),
        references=[
            "ASAMM:AD-02",        # Adversarial drift / state-change
            "owasp_mcp:MCP08 - Tool Squatting & Description Manipulation",
            "research:mcp-scan rug-pull (Invariant Labs)",
            "detector:tool-pinning",
        ],
    )


def _make_added_finding(server_name: str, tool_name: str, preview: str) -> Finding:
    return Finding(
        rule_id="N1.tool-pinning.tool-added",
        title="New MCP tool appeared since last scan",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        summary=(
            f"Tool '{tool_name}' on server '{server_name}' is new since the "
            f"last scan — informational."
        ),
        evidence=[Evidence(
            description=f"New tool description preview: {preview}",
            snippet=preview[:200],
        )],
        remediation=(
            "If this addition is expected (server upgrade, intentional "
            "install), re-run with --track-tool-pinning to update the "
            "baseline."
        ),
        references=["ASAMM:AD-02", "detector:tool-pinning"],
    )


def _make_removed_finding(server_name: str, tool_name: str) -> Finding:
    return Finding(
        rule_id="N1.tool-pinning.tool-removed",
        title="MCP tool disappeared since last scan",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        summary=(
            f"Tool '{tool_name}' on server '{server_name}' was present in the "
            f"last scan but is gone now — informational."
        ),
        remediation=(
            "If the removal is expected (server downgrade, manifest cleanup), "
            "re-run with --track-tool-pinning to update the baseline."
        ),
        references=["ASAMM:AD-02", "detector:tool-pinning"],
    )


# ----------------------------------------------------------------------------
# Top-level entry point
# ----------------------------------------------------------------------------

def check_project(
    project_path: Path,
    *,
    update_baseline: bool = False,
) -> List[Finding]:
    """Scan project for MCP tool-pinning drift.

    Args:
        project_path: root directory to scan.
        update_baseline: if True, write the current state to disk after
            comparison. If False (the default), the comparison runs but
            the baseline is not modified — useful for dry-runs and CI
            where you want to detect drift but not silently accept it.

    Returns:
        List of Finding objects. Empty on first scan (no baseline) or
        when nothing changed.
    """
    project_path = project_path.resolve()
    findings: List[Finding] = []

    # Collect current state
    manifests = _discover_mcp_manifests(project_path)
    current_tools: Dict[str, Dict] = {}
    now = datetime.now(timezone.utc).isoformat()
    for manifest in manifests:
        for server_name, tool_name, desc in _extract_tools_from_manifest(manifest):
            key = _tool_key(manifest, project_path, server_name, tool_name)
            current_tools[key] = {
                "server_name": server_name,
                "tool_name": tool_name,
                "manifest_path": str(manifest.relative_to(project_path)),
                "description_hash": _hash_description(desc),
                "description_preview": _preview(desc),
                "first_seen": now,
                "last_seen": now,
                "scan_count": 1,
            }

    baseline = load_baseline(project_path)

    if baseline is None:
        # First scan: silently record baseline if requested. No findings.
        if update_baseline and current_tools:
            save_baseline(project_path, current_tools)
        return findings

    baseline_tools = baseline.get("tools", {})
    if not isinstance(baseline_tools, dict):
        baseline_tools = {}

    # Compare — three cases per key
    current_keys = set(current_tools)
    baseline_keys = set(baseline_tools)

    # 1. Changed: in both, hash differs
    for key in current_keys & baseline_keys:
        cur = current_tools[key]
        old = baseline_tools[key]
        if cur["description_hash"] != old.get("description_hash"):
            findings.append(_make_changed_finding(
                tool_key=key,
                server_name=cur["server_name"],
                tool_name=cur["tool_name"],
                old_preview=old.get("description_preview", "<no preview>"),
                new_preview=cur["description_preview"],
                old_hash=old.get("description_hash", ""),
                new_hash=cur["description_hash"],
            ))
        # Carry forward first_seen and bump scan_count
        cur["first_seen"] = old.get("first_seen", now)
        cur["scan_count"] = int(old.get("scan_count", 0)) + 1

    # 2. Added: only in current
    for key in current_keys - baseline_keys:
        cur = current_tools[key]
        findings.append(_make_added_finding(
            cur["server_name"], cur["tool_name"], cur["description_preview"],
        ))

    # 3. Removed: only in baseline. Don't carry forward — they're gone.
    for key in baseline_keys - current_keys:
        old = baseline_tools[key]
        findings.append(_make_removed_finding(
            old.get("server_name", "?"), old.get("tool_name", "?"),
        ))

    # Write new baseline only if requested. This is the design point:
    # findings on a CI scan should NOT silently update state, because
    # then drift would only ever fire once per change.
    if update_baseline:
        save_baseline(project_path, current_tools)

    return findings


# ----------------------------------------------------------------------------
# Convenience helpers (used by tests + CLI)
# ----------------------------------------------------------------------------

def reset_baseline(project_path: Path) -> bool:
    """Delete the baseline file for this project. Returns True if a file
    was removed."""
    p = _state_file_for(project_path)
    if p.exists():
        p.unlink()
        return True
    return False
