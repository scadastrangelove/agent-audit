"""MCP-08 — poisoned MCP tool description / schema.

Detects tool poisoning patterns in MCP server configurations: hidden
instructions, invisible unicode, encoded payloads, role override attempts,
and suspicious schema fields.

Source: patterns adapted from Microsoft AGT
(github.com/microsoft/agent-governance-toolkit, MIT License). See
knowledge/agt_mcp_patterns.py for the imported rule content.

Applied to:
  - ~/.claude/mcp.json and .mcp.json
  - ~/.codex/config.toml mcp_servers section
  - Any agent config with mcpServers key (discovered via extended scan)

For each MCP server definition, we read the tool metadata (description,
args, env) and run AGT's patterns. We do NOT connect to the MCP server
at runtime — this is forensic on what's already declared.

References:
  - AGT MCP Security Scanner (MIT)
  - OWASP AST04 (Insecure Metadata)
  - OWASP AST01 (Malicious Skills)
  - Invariant Labs mcp-scan
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

from ..knowledge import agt_mcp_patterns as agt
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# Map AGT category -> our Severity enum
_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _collect_mcp_servers(config: dict) -> List[tuple]:
    """Extract (name, cfg) pairs from common config shapes."""
    out = []
    for key in ("mcpServers", "claude.mcpServers", "mcp_servers"):
        servers = config.get(key)
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    out.append((name, cfg))
    return out


def _scan_text_bundle(text: str) -> List[tuple]:
    """Run AGT pattern set on a text blob. Returns list of findings."""
    return agt.scan_description(text or "")


class MCPPoisonedToolDescription(Rule):
    id = "MCP-08.poisoned-tool-description"
    title = "MCP tool description contains poisoning patterns"
    severity = Severity.HIGH
    references = [
        "Microsoft AGT MCP Security Scanner (MIT License)",
        "OWASP AST04 (Insecure Metadata)",
        "OWASP AST01 (Malicious Skills)",
        "Invariant Labs mcp-scan",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        candidate_paths = [
            agent_home / "mcp.json",
            agent_home / ".mcp.json",
            agent_home / "settings.json",
            agent_home.parent / ".mcp.json",
        ]

        for path in candidate_paths:
            if not path.exists() or not path.is_file():
                continue
            try:
                config = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            servers = _collect_mcp_servers(config)
            for name, cfg in servers:
                # Bundle together all text fields from the server config:
                # - description (if declared)
                # - command + args
                # - env values
                # - any inline tool descriptions
                blobs: List[tuple] = []
                desc = cfg.get("description") or ""
                if desc:
                    blobs.append(("description", desc))
                cmd = cfg.get("command", "")
                args = " ".join(cfg.get("args", []) or [])
                invocation = f"{cmd} {args}".strip()
                if invocation:
                    blobs.append(("invocation", invocation))
                env = cfg.get("env") or {}
                if isinstance(env, dict):
                    for k, v in env.items():
                        if isinstance(v, str):
                            blobs.append((f"env.{k}", v))

                # Tool list (if cached in config — some servers expose this)
                tools = cfg.get("tools") or cfg.get("knownTools") or []
                if isinstance(tools, list):
                    for i, tool in enumerate(tools):
                        if isinstance(tool, dict):
                            t_desc = tool.get("description", "")
                            if t_desc:
                                blobs.append((
                                    f"tools[{i}].description",
                                    t_desc,
                                ))

                # Scan each blob
                for field_name, text in blobs:
                    hits = _scan_text_bundle(text)
                    for category, severity_str, preview in hits:
                        sev = _SEV_MAP.get(severity_str, Severity.MEDIUM)
                        yield Finding(
                            rule_id=self.id,
                            title=self.title,
                            severity=sev,
                            confidence=Confidence.HIGH if sev == Severity.CRITICAL else Confidence.MEDIUM,
                            summary=(
                                f"MCP server `{name}` in {path.name} has a "
                                f"{category} pattern in `{field_name}`. "
                                f"This may indicate tool poisoning — hidden "
                                f"instructions embedded in tool metadata that "
                                f"execute on the LLM but are invisible to the user."
                            ),
                            evidence=[
                                Evidence(
                                    description=f"MCP server `{name}`, field `{field_name}`",
                                    source=path,
                                    snippet=preview[:200],
                                ),
                            ],
                            remediation=(
                                "Review the flagged MCP server's tool descriptions. "
                                "Legitimate tools do not need hidden unicode, "
                                "HTML comments, base64 blobs, or role-override "
                                "phrasing in their metadata. If this is your own "
                                "server, strip the pattern. If it's third-party, "
                                "consider it untrusted until verified."
                            ),
                            references=self.references,
                        )

                # Check schema required fields separately
                schema = cfg.get("inputSchema") or cfg.get("schema")
                if isinstance(schema, dict):
                    required = schema.get("required") or []
                    if isinstance(required, list):
                        for field in required:
                            if isinstance(field, str) and agt.scan_schema_field_name(field):
                                yield Finding(
                                    rule_id=self.id + ".schema",
                                    title="MCP tool schema has suspicious required field",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    summary=(
                                        f"MCP server `{name}` requires field "
                                        f"`{field}` — the name suggests the tool "
                                        f"accepts arbitrary code/URLs/commands "
                                        f"rather than structured data."
                                    ),
                                    evidence=[
                                        Evidence(
                                            description=f"Required field in schema",
                                            source=path,
                                            snippet=f"required: [..., \"{field}\", ...]",
                                        ),
                                    ],
                                    remediation=(
                                        "Verify this MCP server is trusted. "
                                        "Fields like `command`, `exec`, `callback_url` "
                                        "expand agent capability significantly."
                                    ),
                                    references=self.references,
                                )


register_config_rule(MCPPoisonedToolDescription())
