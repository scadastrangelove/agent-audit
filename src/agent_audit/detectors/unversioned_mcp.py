"""AG-02 Unversioned MCP server dependency.

Motivated by SecOps audit F-3 / ASAMM framework gap:
  > MCP supply chain anti-patterns: `uvx xxx@latest` as common
  > unversioned dependency.

MCP servers configured with `@latest` or without version pins mean the agent
runs arbitrary code from whatever version is published at invocation time.
A supply-chain compromise of the MCP server package instantly affects the
user's next Claude session.

Detection:
  - Parse `~/.claude/mcp.json` / project-level `.mcp.json` / `settings.json`
    (claude.mcpServers key)
  - For each server, inspect `command` and `args`
  - Flag patterns: `uvx xxx@latest`, `npx package@latest`, `pipx run xxx`
    without a version, or `docker pull` without tag/digest

References:
  - ASAMM AG-02 (Agent supply chain)
  - SecOps audit sample §12 (framework gaps)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# Patterns for unversioned dependencies
UVX_LATEST = re.compile(r"\buvx\s+[\w.-]+(?:@latest|(?!\s+--))", re.IGNORECASE)
NPX_LATEST = re.compile(r"\bnpx\s+(?:-y\s+)?(?:@[\w-]+/)?[\w.-]+(?:@latest)?", re.IGNORECASE)
PIPX_RUN = re.compile(r"\bpipx\s+run\s+[\w.-]+(?!==)", re.IGNORECASE)
DOCKER_NO_TAG = re.compile(r"\bdocker\s+run[^$]*\s+([\w.-]+/)?[\w.-]+(?::latest)?$", re.IGNORECASE)

# Explicit version pin — these are safe
VERSION_PINNED = re.compile(r"(?:@|==|~|\^|>=|<=|>|<)\s*\d+\.\d+", re.IGNORECASE)
DIGEST_PINNED = re.compile(r"@sha256:[a-f0-9]{16,}", re.IGNORECASE)


def _collect_mcp_servers(config: dict) -> List[Tuple[str, dict]]:
    """Extract mcpServers entries from a config dict.

    Handles multiple possible locations:
      - top-level { "mcpServers": {...} }
      - nested { "claude.mcpServers": {...} }
      - Codex-style [mcp] section
    """
    candidates = []
    for key in ("mcpServers", "claude.mcpServers"):
        servers = config.get(key)
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    candidates.append((name, cfg))
    return candidates


def _analyze_command(cmd: str, args: List[str]) -> Optional[str]:
    """Check if a command+args invocation is unversioned. Returns reason if yes."""
    full = f"{cmd} {' '.join(args or [])}".strip()

    # Bypass if there's an explicit version pin anywhere in the invocation
    if VERSION_PINNED.search(full) or DIGEST_PINNED.search(full):
        return None

    if "@latest" in full:
        return f"explicit `@latest` tag in MCP invocation: `{full[:120]}`"

    # uvx without version pin (uvx takes package name directly)
    if cmd.strip().endswith("uvx") and args:
        pkg = args[0] if not args[0].startswith("-") else (args[1] if len(args) > 1 else "")
        if pkg and "@" not in pkg and "==" not in pkg:
            return f"uvx without version pin: `{full[:120]}`"

    # npx without version pin
    if cmd.strip().endswith("npx") and args:
        # find first non-flag arg
        pkg = next((a for a in args if not a.startswith("-")), "")
        if pkg and "@" not in pkg.lstrip("@"):  # allow @scope/ prefix
            return f"npx without version pin: `{full[:120]}`"

    return None


class UnversionedMCPDependency(Rule):
    id = "AG-02.unversioned-mcp"
    title = "MCP server configured without version pin"
    severity = Severity.MEDIUM
    references = [
        "ASAMM AG-02 (Agent supply chain)",
        "SecOps audit sample §12",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        """Look for MCP server configs and flag unversioned invocations."""
        candidate_paths = [
            agent_home / "mcp.json",
            agent_home / ".mcp.json",
            agent_home / "settings.json",
            agent_home.parent / ".mcp.json",
        ]

        seen: set = set()
        for path in candidate_paths:
            if not path.exists() or not path.is_file():
                continue
            try:
                config = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            servers = _collect_mcp_servers(config)
            for name, cfg in servers:
                cmd = cfg.get("command", "")
                args = cfg.get("args", []) or []
                reason = _analyze_command(cmd, args)
                if not reason:
                    continue
                key = (str(path), name)
                if key in seen:
                    continue
                seen.add(key)

                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"MCP server `{name}` in {path.name} uses an unversioned "
                        f"package invocation. A supply-chain compromise of the upstream "
                        f"package instantly affects the agent's next session."
                    ),
                    evidence=[
                        Evidence(
                            description=f"MCP server `{name}` config",
                            source=path,
                            snippet=f"command={cmd} args={args} — {reason}",
                        ),
                    ],
                    remediation=(
                        f"Pin the MCP server to a specific version or digest. Examples:\n"
                        f"  • uvx `package==1.2.3` instead of `uvx package`\n"
                        f"  • npx `package@1.2.3` instead of `npx package@latest`\n"
                        f"  • docker `image@sha256:<digest>` instead of `image:latest`"
                    ),
                    references=self.references,
                )


register_config_rule(UnversionedMCPDependency())
