"""Configuration audit — static analysis of agent config files.

Flags dangerous defaults:
  - Codex approval_mode = 'full_auto' without sandbox
  - Claude Code allowedTools = '*' or missing deny rules for secrets
  - Agents with broad permissions in their instructions
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)

try:  # py 3.11+
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[import-not-found, no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_toml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file() or tomllib is None:
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, Exception):  # noqa: BLE001
        return None


class ClaudeCodeConfigAudit(Rule):
    """Audit ~/.claude/settings.json."""

    id = "config.claude-code.permissive"
    title = "Claude Code configuration is overly permissive"
    severity = Severity.HIGH
    references = ["ASAMM AI-03 (Scoped Tool Authorization)"]

    def check_config(self, agent_home: Path) -> Iterable[Finding]:
        if agent_home.name != ".claude":
            return
        settings = _load_json(agent_home / "settings.json")
        if settings is None:
            return

        permissions = settings.get("permissions") or {}
        allow = permissions.get("allow") or []
        deny = permissions.get("deny") or []

        # Wildcard allow
        if any(rule == "*" or rule == "Bash(*)" for rule in allow):
            yield Finding(
                rule_id=f"{self.id}.wildcard-allow",
                title="Wildcard tool allow rule",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                summary="settings.json allows all tool invocations without restriction.",
                evidence=[
                    Evidence(
                        description="permissions.allow contains wildcard",
                        source=agent_home / "settings.json",
                        snippet=str(allow)[:200],
                    )
                ],
                remediation="Replace wildcard with explicit tool allowlist. Example: "
                '["Read", "Edit", "Bash(git:*)", "Bash(npm:*)"]',
                references=self.references,
            )

        # Missing deny rules for secrets
        secret_patterns = [".env", "secret", "credential", "id_rsa", ".ssh"]
        deny_lower = [str(r).lower() for r in deny]
        missing = [p for p in secret_patterns if not any(p in d for d in deny_lower)]
        if missing:
            yield Finding(
                rule_id=f"{self.id}.no-secret-deny",
                title="No deny rules for secret paths",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary=f"Claude Code config has no deny rules covering: {', '.join(missing)}",
                evidence=[
                    Evidence(
                        description="Missing secret-path denies",
                        source=agent_home / "settings.json",
                        snippet=f"current deny: {deny or '[]'}",
                    )
                ],
                remediation=(
                    "Add to permissions.deny: "
                    '"Read(~/.env*)", "Read(~/.ssh/**)", "Read(~/.aws/credentials)"'
                ),
                references=self.references,
            )

        # Dangerous-mode permission bypass — from claude-code-zhet audit
        if settings.get("skipDangerousModePermissionPrompt") is True:
            yield Finding(
                rule_id=f"{self.id}.dangerous-mode",
                title="Dangerous mode permission prompt disabled",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                summary=(
                    "settings.json has `skipDangerousModePermissionPrompt: true` — "
                    "the agent will execute dangerous commands without asking. "
                    "Equivalent to running every session with --dangerously-skip-permissions."
                ),
                evidence=[
                    Evidence(
                        description="skipDangerousModePermissionPrompt set",
                        source=agent_home / "settings.json",
                        snippet='"skipDangerousModePermissionPrompt": true',
                    )
                ],
                remediation=(
                    "Remove this flag from settings.json. If specific commands need to "
                    "run without prompting, add them explicitly to permissions.allow "
                    "(e.g. `Bash(git diff:*)`) with narrow scope."
                ),
                references=self.references + [
                    "ASAMM audit sample: claude-code-zhet/readme.md",
                ],
            )


class CodexConfigAudit(Rule):
    """Audit ~/.codex/config.toml."""

    id = "config.codex.permissive"
    title = "Codex configuration is overly permissive"
    severity = Severity.HIGH
    references = ["ASAMM AI-03 (Scoped Tool Authorization)", "ASAMM AD-02"]

    def check_config(self, agent_home: Path) -> Iterable[Finding]:
        if agent_home.name != ".codex":
            return
        config = _load_toml(agent_home / "config.toml")
        if config is None:
            return

        approval = str(config.get("approval_mode") or config.get("approval-mode") or "").lower()
        sandbox = str(config.get("sandbox") or config.get("sandbox_mode") or "").lower()

        # Missing approval_mode should not be treated as an explicit full-auto
        # configuration. We only flag clearly unsafe declared values.
        if approval in ("full_auto", "full-auto", "never"):
            sev = Severity.CRITICAL if not sandbox or sandbox in ("none", "disabled") else Severity.HIGH
            yield Finding(
                rule_id=f"{self.id}.full-auto",
                title="Codex running without approval prompts",
                severity=sev,
                confidence=Confidence.HIGH,
                summary=(
                    f"approval_mode = '{approval}' — agent executes all "
                    f"actions without user confirmation (sandbox={sandbox or 'unset'})."
                ),
                evidence=[
                    Evidence(
                        description="Codex config.toml approval settings",
                        source=agent_home / "config.toml",
                        snippet=f"approval_mode={approval!r} sandbox={sandbox!r}",
                    )
                ],
                remediation=(
                    "Set approval_mode = 'on-request' or 'on-failure' in config.toml. "
                    "Enable sandbox = 'workspace-write' at minimum."
                ),
                references=self.references,
            )


register_config_rule(ClaudeCodeConfigAudit())
register_config_rule(CodexConfigAudit())
