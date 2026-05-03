# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

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
from .session_rule_executor import run_session_rule_packs


@dataclass
class ScanResult:
    installations: List[AgentInstallation] = field(default_factory=list)
    sessions: List[Session] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # M2 Phase 1 — internal-only: per-session repo signal inventory.
    # Keys are session_id; values are RepoSignalInventory (or absent
    # when the session's cwd didn't resolve to a known repo).
    #
    # This field is populated during scan() but not yet rendered
    # anywhere — it ships invisibly per the Phase 1 risk gate. Phase 2
    # correlators will consume these inventories. Kept off-bundle for
    # now so that backwards-compatible JSON output is unchanged.
    #
    # Type-erased to dict to avoid an import cycle with cross_mode.
    # Concrete type: Dict[str, RepoSignalInventory].
    repo_inventories: Dict[str, object] = field(default_factory=dict)

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

    # M1 — load rule-pack rules once and adapt for forensic-mode execution.
    # Pre-loading avoids re-walking the rule-pack directory for every
    # session. Failure here is non-fatal — forensic falls back to native
    # detectors only, which is the pre-M1 behavior.
    rule_pack_rules = None  # None signals "load lazily"
    try:
        from .knowledge.rule_pack_loader import load_all_rules as _load
        rule_pack_rules = _load()
        log.record(
            "load_rule_packs",
            "knowledge/rule_packs",
            count=len(rule_pack_rules),
        )
    except Exception as exc:  # noqa: BLE001
        log.record("load_rule_packs", "knowledge/rule_packs", error=str(exc))
        rule_pack_rules = []

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

            # M2 Phase 1 — silently build/cache the repo signal inventory
            # for this session if its cwd resolves to a known repo. This
            # data is not rendered anywhere yet; Phase 2 correlators will
            # consume it. Failures are swallowed — this is purely
            # additive and must not break the forensic scan.
            try:
                from .cross_mode import (
                    build_repo_signal_inventory, resolve_session_repo,
                )
                repo_root = resolve_session_repo(session.cwd)
                if repo_root is not None:
                    inv = build_repo_signal_inventory(repo_root)
                    if inv is not None:
                        result.repo_inventories[session.session_id] = inv
            except Exception:  # noqa: BLE001 — never let this break scan
                pass

            session_findings = run_session_rules(session)

            # M1 — additionally run any rule-pack rules whose audit_surface
            # includes a session_* value. These were previously only used
            # by the project scanner; M1 closes the diagonal so 78+ rules
            # now actually run in forensic mode. Errors are caught
            # internally — buggy rule-pack rules cannot abort the scan.
            if rule_pack_rules:
                pack_findings = run_session_rule_packs(
                    session, rules=rule_pack_rules
                )
                if pack_findings:
                    log.record(
                        "session_rule_pack_findings",
                        session.session_id,
                        outcome="warn",
                        count=len(pack_findings),
                    )
                session_findings = list(session_findings) + list(pack_findings)

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
