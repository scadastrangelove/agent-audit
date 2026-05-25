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
from .rules import DetectionMode, Finding, run_config_rules, run_session_rules
from .session_rule_executor import (
    _DEFAULT_CONTENT_CAP_BYTES,
    _DEFAULT_PER_EVENT_TIMEOUT_S,
    consume_safeguard_counters,
    reset_safeguard_counters,
    run_session_rule_packs,
)


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

    # v0.18.3 (was: D4 separate-subcommand model in v0.18.0): cross-mode
    # signal flow now runs by default as part of scan(). When populated,
    # this dict mirrors the shape produced by the standalone `cross-mode`
    # subcommand: aggregate_records, tag_applications, sessions_processed,
    # sessions_unlinkable, inventories. Empty dict when cross-mode was
    # disabled via cross_mode=False kwarg or when scan didn't process any
    # sessions.
    cross_mode_report: Dict[str, object] = field(default_factory=dict)

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
    mode: DetectionMode = DetectionMode.BALANCED,
    cross_mode: bool = True,
    vendor_prune: bool = False,
    verbose: bool = False,
) -> ScanResult:
    """Run a full audit.

    Args:
        installations: agents to scan. If None, uses discovery.
        session_limit: cap per-agent session files processed (most recent first).
        audit_log: optional transparent log of every action taken.
        on_progress: optional callback for status messages.
        mode: DetectionMode controlling precision/recall trade-off in
            mode-aware rules. CLI maps `--mode {conservative,standard,full}`
            to {CONSERVATIVE, BALANCED, AGGRESSIVE} and passes through.
            Pre-v0.18.2 this kwarg didn't exist and rules always saw
            BALANCED — `--mode full` reached scope decisions (filesystem
            probes) and verifier-auto-on, but never the rule engine.
        cross_mode: when True (default), run M2 cross-mode signal flow
            after rule execution. Output stored on result.cross_mode_report.
            v0.18.3 reversed the v0.18.0 D4 decision — cross-mode is
            sufficiently mature to ship as default behavior. The standalone
            `cross-mode` subcommand remains for rerun-on-saved-bundle workflows.
            Pass cross_mode=False (CLI: --no-cross-mode) to skip.
        vendor_prune: when True, the cross-mode inventory walk filters out
            test fixtures (benchmarks/, fixtures/) and documentation files
            (README.md, CHANGELOG.md, etc.) as instruction surfaces. Default
            False — scan everything. Opt-in for security-tooling repos
            whose own meta-content trips up tag derivation.
        verbose: when True, emits per-step timestamps via on_progress for
            debugging boundary visibility. Replaces the v0.18.0 rationale
            for keeping cross-mode in a separate subcommand: with
            timestamped logs in -v mode, a maintainer can still answer
            "did the dynamic detector change, or did the linker change?"
            without the two-step CLI dance.
    """
    import time

    result = ScanResult()
    log = audit_log or AuditLog()

    # v0.18.1: reset Tier 1 perf safeguard counters. After the scan,
    # we surface aggregated truncation/timeout counts as scan errors
    # so the maintainer can see when a scan hit pathological inputs.
    reset_safeguard_counters()

    # v0.19: enter scan-session trust mode for the inventory cache. Within
    # this block, repeated lookups for the same (repo_root, vendor_prune)
    # skip the canonical walk + fingerprint validation. Filesystem state
    # is assumed stable for the duration of one scan invocation.
    #
    # The try/finally below ensures we ALWAYS exit the trust mode even on
    # exception, otherwise subsequent calls (in tests or REPL) would
    # silently get stale inventories.
    from .cross_mode.inventory import enter_scan_session, exit_scan_session
    enter_scan_session()
    try:
        return _scan_body(
            result=result, log=log, installations=installations,
            session_limit=session_limit, on_progress=on_progress,
            mode=mode, cross_mode=cross_mode, vendor_prune=vendor_prune,
            verbose=verbose,
        )
    finally:
        exit_scan_session()


def _scan_body(
    *,
    result: ScanResult,
    log: AuditLog,
    installations: Optional[List[AgentInstallation]],
    session_limit: Optional[int],
    on_progress: Optional[Callable[[str], None]],
    mode: DetectionMode,
    cross_mode: bool,
    vendor_prune: bool,
    verbose: bool,
) -> ScanResult:
    """Body of scan() extracted so the outer wrapper can guarantee
    exit_scan_session() via try/finally. All state mutations happen on
    `result` and `log`; both are constructed by the caller.
    """
    import time

    def progress(msg: str) -> None:
        if on_progress:
            if verbose:
                on_progress(f"[{time.strftime('%H:%M:%S')}] {msg}")
            else:
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
        findings = run_config_rules(agent.home, mode=mode)
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
                    inv = build_repo_signal_inventory(repo_root, vendor_prune=vendor_prune)
                    if inv is not None:
                        result.repo_inventories[session.session_id] = inv
            except Exception:  # noqa: BLE001 — never let this break scan
                pass

            session_findings = run_session_rules(session, mode=mode)

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

    # v0.18.3 — cross-mode signal flow runs by default. Reverses D4
    # decision once feature is sufficiently mature. Keep boundary
    # observable via -v / --verbose timestamps; debugging trade-off
    # noted in scan() docstring.
    if cross_mode and result.sessions:
        progress("cross-mode: linking forensic findings to repo inventory signals")
        try:
            cm_t0 = time.perf_counter()
            result.cross_mode_report = _build_inline_cross_mode_report(
                result, log=log, vendor_prune=vendor_prune,
            )
            elapsed_ms = int((time.perf_counter() - cm_t0) * 1000)
            log.record(
                "cross_mode_complete",
                "scan",
                aggregate_records=len(result.cross_mode_report.get("aggregate_records") or []),
                tag_applications=len(result.cross_mode_report.get("tag_applications") or []),
                duration_ms=elapsed_ms,
            )
            if verbose:
                progress(
                    f"cross-mode: {len(result.cross_mode_report.get('aggregate_records') or [])} "
                    f"aggregate(s), {elapsed_ms} ms"
                )
        except Exception as e:  # noqa: BLE001
            # Never let cross-mode break scan. Record the error and
            # continue with empty cross_mode_report.
            log.record("cross_mode_failed", "scan", error=str(e))
            result.errors.append(f"cross-mode failed: {e}")

    # v0.18.1 — surface Tier 1 perf safeguard counters as scan errors.
    # Truncated and timed-out events represent reduced coverage on those
    # specific events; the maintainer should see this so a "0 findings"
    # result on a giant session isn't silently misleading.
    safeguards = consume_safeguard_counters()
    if safeguards.get("truncated_events", 0) > 0:
        n = safeguards["truncated_events"]
        result.errors.append(
            f"Truncated {n} oversized event(s) to {_DEFAULT_CONTENT_CAP_BYTES // 1024}KB "
            f"before regex (set AGENT_AUDIT_CONTENT_CAP_BYTES to override)."
        )
        log.record("safeguard_truncation", "session_rule_executor", count=n)
    if safeguards.get("timed_out_events", 0) > 0:
        n = safeguards["timed_out_events"]
        result.errors.append(
            f"Aborted regex on {n} event(s) after {_DEFAULT_PER_EVENT_TIMEOUT_S}s "
            f"per-event timeout (set AGENT_AUDIT_PER_EVENT_TIMEOUT_S to override)."
        )
        log.record("safeguard_timeout", "session_rule_executor", count=n)

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


def _build_inline_cross_mode_report(
    result: "ScanResult",
    *,
    log: AuditLog,
    vendor_prune: bool = False,
) -> Dict[str, object]:
    """Run cross-mode linker over the just-completed scan's sessions.

    This is the inline counterpart to the standalone `cross-mode` CLI
    subcommand. The two paths share the linker and policy, but this one:

    - reuses inventories already built during the scan loop (no second walk)
    - reads dynamic findings directly from result.findings (no JSON roundtrip)
    - matches the exact JSON shape produced by the CLI subcommand so
      downstream tooling that parses cross-mode-findings.json works against
      either path.

    Per D5: this honors the user's suppression boundary because findings
    in result.findings have already been filtered through
    _apply_project_config during the scan loop.
    """
    from .cross_mode import (
        findings_to_link_input,
        link_signals,
        resolve_session_repo,
    )

    # Group findings by session_id for fast lookup. Findings carry their
    # session id inside Evidence (not on the Finding itself); take the
    # first non-None evidence.session_id as authoritative.
    findings_by_session: Dict[str, List[Finding]] = {}
    for f in result.findings:
        sid = None
        for ev in f.evidence:
            if ev.session_id:
                sid = ev.session_id
                break
        if sid:
            findings_by_session.setdefault(sid, []).append(f)

    aggregate_records: List[dict] = []
    tag_applications: List[dict] = []
    sessions_unlinkable: List[dict] = []
    inventories_per_session: Dict[str, dict] = {}
    sessions_processed = 0

    for session in result.sessions:
        sid = session.session_id
        cwd = session.cwd
        # Reuse Phase 1 inventory if already built; fall back to building
        # one (this should be rare; Phase 1 already attempted it above).
        inv = result.repo_inventories.get(sid)
        if inv is None:
            if not cwd:
                sessions_unlinkable.append({
                    "session_id": sid, "reason": "no_cwd", "cwd": None,
                })
                continue
            try:
                from .cross_mode import build_repo_signal_inventory
                repo_root = resolve_session_repo(cwd)
                if repo_root is None:
                    sessions_unlinkable.append({
                        "session_id": sid, "reason": "no_repo_resolved", "cwd": cwd,
                    })
                    continue
                inv = build_repo_signal_inventory(repo_root, vendor_prune=vendor_prune)
                if inv is None:
                    sessions_unlinkable.append({
                        "session_id": sid, "reason": "inventory_build_failed",
                        "cwd": cwd, "repo_root": str(repo_root),
                    })
                    continue
            except Exception:  # noqa: BLE001
                sessions_unlinkable.append({
                    "session_id": sid, "reason": "inventory_exception", "cwd": cwd,
                })
                continue

        # Inventory is present
        inventories_per_session[sid] = {
            "repo_root": str(inv.repo_root),
            "active_tags": inv.active_tags,
        }

        sess_findings = findings_by_session.get(sid, [])
        link_input = findings_to_link_input(sess_findings)
        out = link_signals(
            session_id=sid,
            session_cwd=cwd,
            inventory=inv,
            dynamic_findings=link_input,
        )

        sessions_processed += 1

        # Map any tag_application back to a specific finding_id by rule_id
        for rec in out.aggregate_records:
            aggregate_records.append({
                "id": rec.id,
                "session_id": rec.session_id,
                "repo_root": str(rec.repo_root) if rec.repo_root else None,
                "correlator": rec.correlator,
                "canonical_class": rec.canonical_class,
                "severity": rec.severity,
                "confidence": rec.confidence,
                "supporting_signal_ids": list(rec.supporting_signal_ids),
                "evidence": list(rec.evidence),
                "rationale": rec.rationale,
                "tags": list(rec.tags),
            })
        # Map any tag_application back to a specific finding_id by rule_id.
        # Findings don't carry finding_id internally; we synthesize one
        # that matches the JSON-render path (F00001, F00002, ...).
        for ta in out.tag_applications:
            for finding in sess_findings:
                if finding.rule_id == ta.target_rule_id:
                    # Match the index-derived ID used in JSON output
                    fid_idx = result.findings.index(finding) + 1
                    tag_applications.append({
                        "session_id": sid,
                        "finding_id": f"F{fid_idx:05d}",
                        "rule_id": ta.target_rule_id,
                        "tag": ta.tag,
                        "rationale": ta.rationale,
                    })

        if out.unlinkable_reason:
            sessions_unlinkable.append({
                "session_id": sid,
                "reason": out.unlinkable_reason,
                "cwd": cwd,
                "repo_root": str(inv.repo_root) if inv else None,
            })

    return {
        "aggregate_records": aggregate_records,
        "tag_applications": tag_applications,
        "sessions_processed": sessions_processed,
        "sessions_total": len(result.sessions),
        "sessions_unlinkable": sessions_unlinkable,
        "inventories": inventories_per_session,
    }


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
