"""Report generation — Markdown for humans, JSON for machines."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import __version__
from .rules import Finding, Severity
from .scanner import ScanResult


SEVERITY_ICON = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED] ",
    Severity.LOW: "[LOW] ",
    Severity.INFO: "[INFO]",
}


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    data = {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "summary": f.summary,
        "remediation": f.remediation,
        "references": list(f.references),
        "created_at": f.created_at.isoformat(),
        "evidence": [
            {
                "description": e.description,
                "source": str(e.source) if e.source else None,
                "session_id": e.session_id,
                "turn_range": list(e.turn_range) if e.turn_range else None,
                "snippet": e.snippet,
            }
            for e in f.evidence
        ],
    }
    return data


def render_markdown(result: ScanResult, aggregated: bool = True) -> str:
    """Render findings as markdown. v0.8.0: `aggregated=True` (default)
    produces session-first collapsible format. `aggregated=False` falls
    back to the original flat list for backwards compatibility.
    """
    if aggregated:
        return _render_markdown_aggregated(result)
    return _render_markdown_flat(result)


def _render_snippet(snippet: str, indent: str = "  ") -> List[str]:
    """Render a snippet as a fenced code block with correct backtick
    escaping. Moved out of inline rendering so aggregated and flat
    versions share the logic."""
    import re as _re
    max_run = 0
    for m in _re.finditer(r'`+', snippet):
        max_run = max(max_run, len(m.group(0)))
    fence = '`' * max(3, max_run + 1)
    return [f"{indent}{fence}", f"{indent}{snippet}", f"{indent}{fence}"]


def _render_markdown_aggregated(result: ScanResult) -> str:
    """v0.8.0 session-first MD report."""
    from .report_aggregation import (
        build_session_cards,
        HEAVY_SESSION_THRESHOLD,
        SESSION_CARD_THRESHOLD,
        PATTERN_REPRESENTATIVE_LIMIT,
    )

    lines: List[str] = []
    lines.append("# Agent audit report")
    lines.append(f"_generated {datetime.now().isoformat(timespec='seconds')}_")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    for agent in result.installations:
        lines.append(
            f"- **{agent.name}** — {agent.session_count} sessions, "
            f"{agent.total_bytes // 1024} KB of logs"
        )
    if not result.installations:
        lines.append("- No agents discovered.")
    lines.append("")
    lines.append(f"- Sessions parsed: {len(result.sessions)}")
    lines.append(f"- Findings: {len(result.findings)}")
    by_sev = result.findings_by_severity
    for sev in ("critical", "high", "medium", "low", "info"):
        count = len(by_sev.get(sev, []))
        if count:
            lines.append(f"  - {sev}: {count}")
    lines.append("")

    if not result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("No issues detected. This does not mean there are none —")
        lines.append("the current rule set covers a limited subset of known risks.")
        lines.append("")
        return "\n".join(lines)

    # Build aggregation
    sessions_meta = {
        s.session_id: {
            "agent": s.agent.value,
            "cwd": s.cwd,
            "event_count": s.event_count,
            "source_file": str(s.source_file),
        }
        for s in result.sessions
    }
    cards, orphans = build_session_cards(result.findings, sessions_meta)

    # Split cards: "sessions of concern" (>= threshold) vs "quiet"
    heavy_cards = [c for c in cards if c.total_findings >= SESSION_CARD_THRESHOLD]
    quiet_cards = [c for c in cards if c.total_findings < SESSION_CARD_THRESHOLD]

    # Top-level: sessions of concern
    if heavy_cards:
        lines.append(f"## Sessions of concern ({len(heavy_cards)})")
        lines.append("")
        lines.append(
            "_Sessions with {0}+ findings. Within each, rules are listed with "
            "pattern grouping — identical-shape findings are counted together "
            "with representative samples._".format(SESSION_CARD_THRESHOLD)
        )
        lines.append("")

        for card in heavy_cards:
            _render_card(lines, card)
            lines.append("")

    # Quiet sessions (1-2 findings each): collapsed summary
    if quiet_cards:
        lines.append(f"## Quiet sessions ({len(quiet_cards)})")
        lines.append("")
        lines.append("_Sessions with fewer than {0} findings — one line each._".format(
            SESSION_CARD_THRESHOLD))
        lines.append("")
        for card in quiet_cards:
            rules = ", ".join(
                f"`{r}`×{n}" if n > 1 else f"`{r}`"
                for r, n in card.rule_counts.most_common()
            )
            lines.append(
                f"- **{card.session_id_short}** [{card.top_severity}] "
                f"({card.agent}) · {rules}"
            )
        lines.append("")

    # Orphan findings (config-level, no session)
    if orphans:
        lines.append(f"## Config & environment findings ({len(orphans)})")
        lines.append("")
        lines.append("_Findings not tied to a specific session — configuration "
                     "files, environment probes, version audits._")
        lines.append("")
        for f in orphans:
            _render_finding_inline(lines, f)
        lines.append("")

    # Appendix: flat list for reference
    lines.append("---")
    lines.append("")
    lines.append("## Full flat list (appendix)")
    lines.append("")
    lines.append(
        f"_Raw list of all {len(result.findings)} findings — provided for "
        f"search and machine processing. The JSON report has the canonical "
        f"data; this MD section is a convenience._"
    )
    lines.append("")
    lines.append("<details>")
    lines.append("<summary>Expand full flat list</summary>")
    lines.append("")
    for f in result.findings:
        _render_finding_inline(lines, f)
    lines.append("</details>")
    lines.append("")

    return "\n".join(lines)


def _render_card(lines: List[str], card) -> None:
    """Render a single SessionCard."""
    icon = SEVERITY_ICON.get(Severity(card.top_severity), "")
    lines.append(f"### {icon} Session `{card.session_id_short}` — "
                 f"{card.total_findings} findings")
    lines.append("")

    # Meta line
    meta_parts = [f"agent: `{card.agent}`"]
    if card.cwd:
        meta_parts.append(f"cwd: `{card.cwd}`")
    sev_summary = ", ".join(
        f"{s}={n}" for s in ("critical", "high", "medium", "low", "info")
        if (n := card.severity_counts.get(s, 0)) > 0
    )
    if sev_summary:
        meta_parts.append(f"severity: {sev_summary}")
    lines.append(" · ".join(meta_parts))
    lines.append("")

    # Rule cluster rollup
    for cluster in card.clusters:
        sev_str = ", ".join(
            f"{s}={n}" for s, n in cluster.severity_distribution.most_common()
        )
        lines.append(
            f"**`{cluster.rule_id}`** — {cluster.total_count} finding(s), "
            f"{sev_str}"
        )
        lines.append("")

        # Show up to N pattern samples per cluster
        for pg in cluster.patterns:
            rep = pg.representative
            # Condensed rep: summary truncated, first evidence snippet
            summary_short = rep.summary
            if len(summary_short) > 200:
                summary_short = summary_short[:200].rstrip() + "…"
            lines.append(f"- {summary_short}")

            # Representative evidence snippet (one)
            for ev in rep.evidence:
                if ev.snippet:
                    snippet_short = ev.snippet
                    if len(snippet_short) > 300:
                        snippet_short = snippet_short[:300].rstrip() + "…"
                    lines.extend(_render_snippet(snippet_short, indent="  "))
                    break

            # Similar count rollup
            if pg.similar_count > 0:
                lines.append(
                    f"  _+ {pg.similar_count} more finding(s) with the same "
                    f"evidence shape_"
                )
            lines.append("")


def _render_finding_inline(lines: List[str], f: Finding) -> None:
    """Render one finding in flat style (used for orphans and appendix)."""
    icon = SEVERITY_ICON.get(f.severity, "")
    lines.append(f"#### {icon} {f.title}")
    lines.append(
        f"_rule: `{f.rule_id}` · severity: **{f.severity.value}** · "
        f"confidence: {f.confidence.value}_"
    )
    lines.append("")
    lines.append(f.summary)
    lines.append("")
    if f.evidence:
        lines.append("**Evidence:**")
        for e in f.evidence:
            parts = [e.description]
            if e.session_id:
                parts.append(f"session `{e.session_id[:8]}`")
            if e.turn_range:
                parts.append(f"turns {e.turn_range[0]}..{e.turn_range[1]}")
            lines.append(f"- {' · '.join(parts)}")
            if e.snippet:
                lines.extend(_render_snippet(e.snippet, indent="  "))
        lines.append("")
    if f.remediation:
        lines.append(f"**Remediation:** {f.remediation}")
        lines.append("")
    if f.references:
        lines.append(f"_references: {', '.join(f.references)}_")
        lines.append("")


def _render_markdown_flat(result: ScanResult) -> str:
    """Legacy flat-list renderer — kept for backwards compatibility
    and for users who prefer no grouping."""
    lines: List[str] = []
    lines.append("# Agent audit report")
    lines.append(f"_generated {datetime.now().isoformat(timespec='seconds')}_")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    for agent in result.installations:
        lines.append(
            f"- **{agent.name}** — {agent.session_count} sessions, "
            f"{agent.total_bytes // 1024} KB of logs"
        )
    if not result.installations:
        lines.append("- No agents discovered.")
    lines.append("")
    lines.append(f"- Sessions parsed: {len(result.sessions)}")
    lines.append(f"- Findings: {len(result.findings)}")
    by_sev = result.findings_by_severity
    for sev in ("critical", "high", "medium", "low", "info"):
        count = len(by_sev.get(sev, []))
        if count:
            lines.append(f"  - {sev}: {count}")
    lines.append("")

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        for f in result.findings:
            _render_finding_inline(lines, f)
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No issues detected. This does not mean there are none —")
        lines.append("the current rule set covers a limited subset of known risks.")
        lines.append("")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    data = {
        "generated_at": datetime.now().isoformat(),
        "bundle_version": 2,
        "package_version": __version__,
        "installations": [
            {
                "kind": a.kind.value,
                "name": a.name,
                "home": str(a.home),
                "session_count": a.session_count,
                "total_bytes": a.total_bytes,
            }
            for a in result.installations
        ],
        "sessions": [
            {
                "session_id": s.session_id,
                "agent": s.agent.value,
                "source_file": str(s.source_file),
                "started_at": s.started_at.isoformat(),
                "event_count": s.event_count,
                "tool_call_count": len(s.tool_calls),
                "cwd": s.cwd,
                "git_branch": s.git_branch,
                "parent_session_id": s.parent_session_id,
                "is_subagent": s.is_subagent,
            }
            for s in result.sessions
        ],
        "findings": [
            {
                **_finding_to_dict(f),
                "finding_id": f"F{idx:05d}",
                "needs_llm_verification": f.needs_llm_verification,
            }
            for idx, f in enumerate(result.findings, start=1)
        ],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2, default=str)


def write_reports(result: ScanResult, output_dir: Path) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    md_path = output_dir / f"audit-{stamp}.md"
    json_path = output_dir / f"audit-{stamp}.json"
    md_path.write_text(render_markdown(result), encoding="utf-8")
    json_path.write_text(render_json(result), encoding="utf-8")
    return md_path, json_path
