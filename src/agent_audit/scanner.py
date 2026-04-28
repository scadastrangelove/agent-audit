"""Scanner — orchestrates discovery, parsing, and rule execution.

This is a pure function of the filesystem — no consent prompts, no UI.
The CLI layer handles user interaction; this module does the work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import detectors  # noqa: F401 — side-effect: registers rules
from .audit_log import AuditLog
from .discovery import AgentInstallation, discover
from .events import AgentKind, Session
from .parsers import parse_claude_code_file, parse_codex_file
from .rules import Finding, run_config_rules, run_session_rules


@dataclass
class ScanResult:
    installations: List[AgentInstallation] = field(default_factory=list)
    sessions: List[Session] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.severity.value, []).append(f)
        return out


def _parse_for(kind: AgentKind, path: Path) -> Optional[Session]:
    if kind == AgentKind.CLAUDE_CODE:
        return parse_claude_code_file(path)
    if kind == AgentKind.CODEX:
        return parse_codex_file(path)
    # OpenClaw parser not yet implemented
    return None


def scan(
    *,
    installations: Optional[List[AgentInstallation]] = None,
    session_limit: Optional[int] = None,
    audit_log: Optional[AuditLog] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """Run a full audit.

    Args:
        installations: agents to scan. If None, uses discovery.
        session_limit: cap per-agent session files processed (most recent first).
        audit_log: optional transparent log of every action taken.
        on_progress: optional callback for status messages.
    """
    result = ScanResult()
    log = audit_log or AuditLog()

    def progress(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    result.installations = installations or discover()
    log.record("discover", "filesystem", found=len(result.installations))

    for agent in result.installations:
        progress(f"scanning {agent.name}...")

        # Config audit
        findings = run_config_rules(agent.home)
        log.record(
            "run_config_rules",
            str(agent.home),
            outcome="warn" if findings else "ok",
            findings=len(findings),
        )
        result.findings.extend(findings)

        # Session parsing + rules
        if not agent.sessions_glob:
            continue
        session_files = sorted(
            (p for p in agent.home.glob(agent.sessions_glob) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if session_limit:
            session_files = session_files[:session_limit]

        for sf in session_files:
            session = _parse_for(agent.kind, sf)
            if session is None:
                log.record("parse_session", str(sf), outcome="error")
                result.errors.append(f"Failed to parse: {sf}")
                continue
            log.record(
                "parse_session",
                str(sf),
                session_id=session.session_id,
                events=session.event_count,
            )
            # v0.8.2: apply canonical_tool normalization across all tool
            # events. This lets detectors cross-reference Codex's
            # exec_command and Claude Code's Bash under one name.
            _normalize_tool_names(session)
            result.sessions.append(session)

            session_findings = run_session_rules(session)
            if session_findings:
                log.record(
                    "session_findings",
                    session.session_id,
                    outcome="warn",
                    count=len(session_findings),
                )
                # v0.8.1: apply project-type config (severity overrides +
                # suppression) based on session's cwd. If no cwd → no
                # project config → findings pass through unchanged.
                session_findings = _apply_project_config(
                    session_findings, session.cwd
                )
                result.findings.extend(session_findings)

    # Sort findings: critical first, then high, etc.
    result.findings.sort(
        key=lambda f: (-f.severity.order, -f.confidence.value.__len__())
    )
    progress(
        f"done: {len(result.sessions)} sessions, {len(result.findings)} findings"
    )
    return result


def _normalize_tool_names(session):
    """v0.8.2: populate canonical_tool on every TOOL_USE event in
    session. Mutates in place. Safe no-op for unknown tool names."""
    from .tool_normalization import canonical_for
    from .events import EventType

    for ev in session.events:
        if ev.type != EventType.TOOL_USE:
            continue
        if ev.canonical_tool is None and ev.tool_name:
            canon = canonical_for(ev.tool_name)
            if canon:
                ev.canonical_tool = canon


def _apply_project_config(findings, cwd):
    """v0.8.1: filter findings list via project config — suppress
    rules listed in suppress_rules, override severity for rules with
    matching overrides."""
    from .project_config import get_project_config
    from .rules import Severity

    config = get_project_config(cwd)
    if not config.severity_overrides and not config.suppress_rules:
        return findings

    out = []
    for f in findings:
        if config.is_suppressed(f.rule_id):
            continue
        override = config.apply_severity_override(f.rule_id, f.severity.value)
        if override != f.severity.value:
            try:
                f.severity = Severity(override)
            except ValueError:
                pass  # invalid override, leave original
        out.append(f)
    return out
