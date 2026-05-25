# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Command-line interface.

Consent-first flow:
  1. Discover agents (no permission needed — just checks file existence)
  2. Ask permission to read logs
  3. Run static analysis (rules, no LLM, free)
  4. Offer to verify findings via LLM (optional, with budget cap)
  5. Write reports
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import __version__
from .audit_log import AuditLog, default_log_path
from .discovery import discover
from .report import render_markdown, write_reports
from .rules import Severity
from .scanner import scan

console = Console()

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _print_discovery(installations) -> None:
    if not installations:
        console.print("[dim]No AI agents found on this machine.[/dim]")
        console.print()
        console.print("Primary paths checked: [cyan]~/.claude[/cyan], [cyan]~/.codex[/cyan], [cyan]~/.openclaw[/cyan]")
        console.print("Try [cyan]agent-audit list --extended[/cyan] to also check 100+ other agents.")
        return

    # Split into primary (with parsers) and extended (config-only)
    primary = [a for a in installations if getattr(a, "has_parser", True)]
    extended = [a for a in installations if not getattr(a, "has_parser", True)]

    if primary:
        table = Table(title="Discovered agents (with session parsers)", show_lines=False)
        table.add_column("Agent", style="cyan")
        table.add_column("Home")
        table.add_column("Sessions", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Last activity")
        for a in primary:
            last = "—"
            if a.last_activity:
                from datetime import datetime
                last = datetime.fromtimestamp(a.last_activity).strftime("%Y-%m-%d %H:%M")
            size = f"{a.total_bytes / 1024:.0f} KB" if a.total_bytes else "—"
            table.add_row(a.name, str(a.home), str(a.session_count), size, last)
        console.print(table)

    if extended:
        table2 = Table(
            title=f"Extended agents (config-only, {len(extended)} found)",
            show_lines=False,
        )
        table2.add_column("Agent", style="cyan")
        table2.add_column("Aegis ID", style="dim")
        table2.add_column("Config paths")
        for a in extended:
            paths_shown = ", ".join(str(p) for p in a.config_paths[:2])
            if len(a.config_paths) > 2:
                paths_shown += f" (+{len(a.config_paths) - 2} more)"
            table2.add_row(a.name, a.aegis_id or "", paths_shown)
        console.print(table2)
        console.print(
            "[dim]Extended agents are discovered via Aegis database (MIT) — "
            "config audits run, but session analysis requires a parser.[/dim]"
        )


def _print_summary(result) -> None:
    by_sev = result.findings_by_severity
    if not result.findings:
        console.print()
        console.print("[green]No issues detected by current rule set.[/green]")
        return
    console.print()
    console.print("[bold]Findings:[/bold]")
    for sev_name in ("critical", "high", "medium", "low", "info"):
        items = by_sev.get(sev_name, [])
        if not items:
            continue
        style = SEVERITY_STYLES[sev_name]
        console.print(f"  [{style}]{sev_name:10s}[/{style}] {len(items)}")

    console.print()
    console.print("[bold]Top findings:[/bold]")
    for finding in result.findings[:10]:
        style = SEVERITY_STYLES[finding.severity.value]
        console.print(f"  [{style}]•[/{style}] {finding.title}")
        console.print(f"    [dim]{finding.summary}[/dim]")
        if finding.remediation:
            console.print(f"    [cyan]↪ {finding.remediation}[/cyan]")


@click.group()
@click.version_option(version=__version__, prog_name="agent-audit")
def main() -> None:
    """Forensic auditor for local AI coding agents (Claude Code, Codex, OpenClaw)."""


def _interactive_pick_backend(backends_to_try, working_names):
    """If >1 backend is working and --verifier=auto, prompt user to pick.

    Per v0.7: when multiple verifiers are available, ask which to use rather
    than silently picking the first. Returns the chosen backend object.
    """
    available = [b for b in backends_to_try if b.name in working_names]
    if not available:
        return None
    if len(available) == 1:
        return available[0]

    console.print()
    console.print("[bold]Multiple verifiers available:[/bold]")
    label_to_backend = {}
    for i, b in enumerate(available, 1):
        label = str(i)
        label_to_backend[label] = b
        console.print(f"  [cyan]{label}[/cyan]  {b.name}")
    # Default to first — that matches v0.6 silent pick behaviour
    choice = Prompt.ask(
        "Which verifier?",
        choices=list(label_to_backend.keys()),
        default="1",
    )
    return label_to_backend[choice]


@main.command("verify")
@click.option(
    "--report",
    "-r",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to a JSON report produced by `agent-audit scan`.",
)
@click.option(
    "--budget",
    type=float,
    default=0.50,
    help="Max USD to spend on verification (stops before exceeding).",
)
@click.option(
    "--verifier",
    type=click.Choice(["auto", "claude", "codex", "anthropic", "openai", "openrouter", "ollama", "custom"]),
    default="auto",
    help="Which verifier to use. 'auto' picks first working. API backends require env vars: "
         "ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / OLLAMA_MODEL / AGENT_AUDIT_OPENAI_*.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="medium",
    help="Verify findings at this severity or above.",
)
@click.option(
    "--batch-size",
    type=int,
    default=25,
    help="Findings per batch call (higher = cheaper but longer prompts). Default 25 in v0.7.4.",
)
@click.option(
    "--concurrency",
    type=int,
    default=4,
    help="Number of batches to verify in parallel (v0.7.4). "
         "Set to 1 for sequential (original v0.7.3 behavior). "
         "Higher values speed up large runs but may hit rate limits.",
)
@click.option(
    "--timeout",
    type=int,
    default=240,
    help="Per-batch timeout in seconds (v0.7.6). Default 240s. "
         "Integrity review uses 1.5x this value since its prompts are "
         "larger. Slow backends (codex-cli with big batches under "
         "concurrency > 1) may need to raise this.",
)
@click.option(
    "--claude-model",
    type=str,
    default="sonnet",
    show_default=True,
    help="Model to use when the verifier is Claude CLI (v0.7.6). "
         "Sonnet is ~2x faster and ~3x cheaper than Opus for verify work. "
         "Use 'opus' if you want maximum reasoning or 'haiku' for cheapest. "
         "Explicit model names like 'claude-sonnet-4-5-20250929' also work.",
)
@click.option(
    "--proxy",
    type=str,
    default=None,
    envvar="AGENT_AUDIT_PROXY",
    help="HTTP/HTTPS proxy URL to forward to CLI subprocesses (e.g. http://127.0.0.1:12334). "
         "Also reads AGENT_AUDIT_PROXY env var. Useful when CLI doesn't pick up system proxy.",
)
@click.option(
    "--skip-preflight",
    is_flag=True,
    help="Skip the preflight check (useful if you already know what works).",
)
@click.option(
    "--integrity-review",
    is_flag=True,
    help=(
        "After initial verification, run a second pass asking the verifier to "
        "review its own verdicts — catches both over- and under-credited findings. "
        "Roughly doubles cost but catches ~85%% of agent errors (based on ASAMM "
        "dual-agent experiment). Will prompt for consent and show expected cost."
    ),
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip consent prompts.",
)
def verify_cmd(
    report: Path,
    budget: float,
    verifier: str,
    severity: str,
    batch_size: int,
    concurrency: int,
    timeout: int,
    claude_model: str,
    proxy: Optional[str],
    skip_preflight: bool,
    integrity_review: bool,
    yes: bool,
) -> None:
    """Verify scan findings using an installed agent CLI (batched).

    v0.3: findings are verified in batches (10 at a time by default) to save
    5-10x on cost/time. A preflight check probes each CLI with a trivial
    prompt before real verification starts, so problems (e.g. Claude API
    returning 403) are surfaced up front.
    """
    from .audit_log import AuditLog, default_log_path
    from .batch_verifier import (
        all_backends,
        available_backends,
        build_byo_backends,
        preflight,
        verify_all_batched,
        ClaudeCodeBackend,
        CodexCLIBackend,
    )
    from .rules import Evidence, Finding, Severity as SeverityEnum, Confidence

    log_path = default_log_path()
    audit_log = AuditLog(log_path)
    console.print(f"[dim]auditor log: {log_path}[/dim]")

    # Auto-detect system proxy if not explicitly set
    if not proxy:
        import os
        for env_var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
            val = os.environ.get(env_var)
            if val:
                console.print(
                    f"[dim]Detected {env_var}={val} — using as proxy. "
                    f"Override with --proxy '' to disable.[/dim]"
                )
                proxy = val
                break
    console.print()

    # --- Load report and filter by severity ---
    data = json.loads(report.read_text(encoding="utf-8"))
    all_findings_raw = data.get("findings", [])
    sev_order = SeverityEnum(severity).order
    eligible_raw = [f for f in all_findings_raw if SeverityEnum(f["severity"]).order >= sev_order]

    console.print(f"[bold]Report:[/bold] {report}")
    console.print(f"  Total findings: {len(all_findings_raw)}")
    console.print(f"  Eligible (>= {severity}): {len(eligible_raw)}")

    if not eligible_raw:
        console.print("[yellow]No eligible findings to verify.[/yellow]")
        return

    # --- Select backends based on --verifier flag ---
    backends_to_try = all_backends(proxy=proxy, claude_model=claude_model)
    if verifier == "claude":
        backends_to_try = [b for b in backends_to_try if b.name == "claude-cli"]
    elif verifier == "codex":
        backends_to_try = [b for b in backends_to_try if b.name == "codex-cli"]
    elif verifier == "anthropic":
        backends_to_try = [b for b in backends_to_try if b.name == "anthropic-api"]
    elif verifier == "openai":
        backends_to_try = [b for b in backends_to_try if b.name == "openai-compat:openai"]
    elif verifier == "openrouter":
        backends_to_try = [b for b in backends_to_try if b.name == "openai-compat:openrouter"]
    elif verifier == "ollama":
        backends_to_try = [b for b in backends_to_try if b.name == "openai-compat:ollama"]
    elif verifier == "custom":
        backends_to_try = [b for b in backends_to_try if b.name == "openai-compat:custom"]

    if not backends_to_try:
        console.print(f"[red]No backend matches --verifier {verifier}.[/red]")
        if verifier == "anthropic":
            console.print("Set ANTHROPIC_API_KEY env var.")
        elif verifier == "openai":
            console.print("Set OPENAI_API_KEY env var.")
        elif verifier == "openrouter":
            console.print("Set OPENROUTER_API_KEY env var (great for restricted regions).")
        elif verifier == "ollama":
            console.print("Start Ollama locally and set OLLAMA_MODEL=<model-name>.")
        elif verifier == "custom":
            console.print("Set AGENT_AUDIT_OPENAI_BASE_URL and AGENT_AUDIT_OPENAI_MODEL.")
        sys.exit(1)

    if proxy:
        console.print(f"[dim]Proxy: {proxy} (forwarded to all backends)[/dim]")

    # --- Preflight ---
    chosen = None
    if skip_preflight:
        for b in backends_to_try:
            if b.available():
                chosen = b
                break
        if not chosen:
            console.print("[red]No verifier backends installed. Try `brew install codex` or install Claude Code.[/red]")
            sys.exit(1)
        console.print(f"[yellow]Skipping preflight — using {chosen.name} without probe.[/yellow]")
    else:
        console.print()
        console.print("[bold]Preflight check[/bold] — probing available verifiers...")
        preflight_results = preflight(backends_to_try)

        working = []
        for r in preflight_results:
            if r.available:
                console.print(f"  [green]✓[/green] {r.backend} — OK ({r.latency_ms}ms)")
                working.append(r.backend)
            else:
                console.print(f"  [red]✗[/red] {r.backend} — {r.error}")
                if r.hint:
                    console.print(f"      [dim]hint: {r.hint}[/dim]")

        if not working:
            console.print()
            console.print("[red]No working verifiers. See hints above.[/red]")
            console.print()
            console.print("Options:")
            console.print("  • Fix the CLIs shown above and retry")
            console.print("  • Install Codex CLI: [cyan]npm i -g @openai/codex[/cyan]")
            console.print("  • Use a direct API key:")
            console.print("      [cyan]export ANTHROPIC_API_KEY=sk-ant-...[/cyan]")
            console.print("      [cyan]export OPENROUTER_API_KEY=sk-or-...[/cyan]  (works in restricted regions)")
            console.print("  • Use a local LLM via Ollama:")
            console.print("      [cyan]export OLLAMA_MODEL=llama3.3[/cyan]")
            sys.exit(1)

        # Pick working backend: silent first-match if only 1, interactive if >1
        if verifier == "auto":
            chosen = _interactive_pick_backend(backends_to_try, set(working))
        else:
            # Explicit --verifier specified, honour first match from filtered list
            for b in backends_to_try:
                if b.name in working:
                    chosen = b
                    break

    if not chosen:
        console.print("[red]Could not select a verifier.[/red]")
        sys.exit(1)

    # --- Confirm with user ---
    n_batches = (len(eligible_raw) + batch_size - 1) // batch_size
    console.print()
    console.print(f"[bold]Ready to verify[/bold] {len(eligible_raw)} findings")
    console.print(f"  Verifier: [cyan]{chosen.name}[/cyan]")
    console.print(f"  Batches: {n_batches} × up to {batch_size} findings")
    console.print(f"  Concurrency: {concurrency} parallel batches")
    console.print(f"  Timeout: {timeout}s per batch")
    console.print(f"  Budget cap: ${budget:.2f}")

    if not yes and not Confirm.ask("Proceed?", default=True):
        console.print("[yellow]Aborted.[/yellow]")
        sys.exit(0)

    # --- Rehydrate Finding objects ---
    rehydrated = []
    for f in eligible_raw:
        rehydrated.append(Finding(
            rule_id=f["rule_id"],
            title=f["title"],
            severity=SeverityEnum(f["severity"]),
            confidence=Confidence(f["confidence"]),
            summary=f["summary"],
            remediation=f.get("remediation"),
            references=f.get("references", []),
            evidence=[
                Evidence(
                    description=e["description"],
                    source=Path(e["source"]) if e.get("source") else None,
                    session_id=e.get("session_id"),
                    turn_range=tuple(e["turn_range"]) if e.get("turn_range") else None,
                    snippet=e.get("snippet"),
                )
                for e in f.get("evidence", [])
            ],
        ))

    # --- Run batched verification ---
    console.print()
    results_by_finding: dict = {}

    def on_batch(batch_idx: int, total: int, batch_result) -> None:
        if batch_result.error:
            console.print(
                f"[dim]  [batch {batch_idx}/{total}][/dim] "
                f"[red]error:[/red] {batch_result.error[:120]}"
            )
            return
        console.print(
            f"[dim]  [batch {batch_idx}/{total}][/dim] "
            f"{len(batch_result.verdicts)} verdicts "
            f"[dim](${batch_result.cost_usd:.4f})[/dim]"
        )

    batches = verify_all_batched(
        rehydrated,
        chosen,
        batch_size=batch_size,
        budget_usd=budget,
        audit_log=audit_log,
        on_batch_complete=on_batch,
        concurrency=concurrency,
        timeout=timeout,
    )

    # --- Map verdicts back to findings ---
    # Verdicts inside each batch reference their local finding_index (0 to batch_size-1)
    flat_verdicts = []  # parallel with findings we actually verified
    verified_findings = []
    for i, batch in enumerate(batches):
        batch_findings = rehydrated[i * batch_size:(i + 1) * batch_size]
        if batch.error:
            # Mark all findings in this batch as uncertain with the error
            for f in batch_findings:
                verified_findings.append(f)
                flat_verdicts.append({
                    "verdict": "uncertain",
                    "adjusted_severity": None,
                    "rationale": f"batch error: {batch.error[:150]}",
                    "error": batch.error,
                    "cost_usd": 0.0,
                })
            continue

        # Index verdicts by their finding_index (from model response)
        verdicts_by_idx = {v.finding_index: v for v in batch.verdicts}
        per_finding_cost = batch.cost_usd / max(len(batch_findings), 1)
        for local_idx, f in enumerate(batch_findings):
            verified_findings.append(f)
            v = verdicts_by_idx.get(local_idx)
            if v:
                flat_verdicts.append({
                    "verdict": v.verdict,
                    "adjusted_severity": v.adjusted_severity.value if v.adjusted_severity else None,
                    "rationale": v.rationale,
                    "error": None,
                    "cost_usd": per_finding_cost,
                })
            else:
                flat_verdicts.append({
                    "verdict": "uncertain",
                    "adjusted_severity": None,
                    "rationale": "verifier returned no verdict for this finding",
                    "error": None,
                    "cost_usd": per_finding_cost,
                })

    # --- Optional integrity review (v0.5) ---
    integrity_changes: dict = {}  # finding_index -> new verdict
    integrity_total_cost = 0.0
    if integrity_review:
        from .batch_verifier import integrity_review as run_integrity_review

        # Estimate cost — roughly same as primary verify
        primary_cost_so_far = sum(b.cost_usd for b in batches)
        estimated_integrity_cost = primary_cost_so_far  # ~equal cost

        console.print()
        console.print("[bold]Integrity review[/bold] — second-pass self-check")
        console.print(
            f"[yellow]This runs the verifier again to catch both over- and "
            f"under-credited verdicts.[/yellow]"
        )
        console.print(
            f"[yellow]Expected additional cost: ~${estimated_integrity_cost:.4f} "
            f"(similar to primary verification).[/yellow]"
        )

        if not yes and not Confirm.ask("Run integrity review?", default=True):
            console.print("[dim]Skipping integrity review.[/dim]")
        else:
            # v0.7.4: run integrity review batches in parallel via threads.
            # Each batch is independent, so we just submit all of them and
            # collect results by index.
            # v0.7.6: throttle integrity concurrency to min(concurrency, 2)
            # and bump timeout 1.5x. Integrity prompts are ~2x larger than
            # primary verify prompts (they include original findings +
            # verdicts + self-review instructions) and running 4 in parallel
            # against codex-cli was hitting 120s timeouts. 2 parallel ×
            # 1.5x timeout gives reliable completion.
            from concurrent.futures import ThreadPoolExecutor, as_completed

            eligible_batches = [
                (i, batch) for i, batch in enumerate(batches)
                if not batch.error
            ]
            n_eligible = len(eligible_batches)
            integrity_concurrency = min(concurrency, 2)
            integrity_timeout = int(timeout * 1.5)
            console.print(
                f"[dim]  Integrity: {integrity_concurrency} parallel × "
                f"{integrity_timeout}s timeout (throttled from primary "
                f"concurrency={concurrency})[/dim]"
            )

            def run_one(i_batch):
                i, batch = i_batch
                batch_findings = rehydrated[i * batch_size:(i + 1) * batch_size]
                review_result = run_integrity_review(
                    batch_findings,
                    batch.verdicts,
                    chosen,
                    audit_log=audit_log,
                    timeout=integrity_timeout,
                )
                return i, review_result

            completed = 0
            with ThreadPoolExecutor(max_workers=integrity_concurrency) as ex:
                futures = {ex.submit(run_one, ib): ib[0] for ib in eligible_batches}
                for fut in as_completed(futures):
                    i = futures[fut]
                    try:
                        _, review_result = fut.result()
                    except Exception as exc:
                        console.print(
                            f"[dim]  [integrity batch {i+1}] exception: "
                            f"{str(exc)[:100]}[/dim]"
                        )
                        continue
                    completed += 1
                    integrity_total_cost += review_result.cost_usd

                    if review_result.error:
                        console.print(
                            f"[dim]  [batch {i+1}/{n_eligible}] integrity review errored: "
                            f"{review_result.error[:100]}[/dim]"
                        )
                        continue

                    # Apply changes — map each change to its flat_verdicts index
                    for change in review_result.verdicts:
                        flat_idx = i * batch_size + change.finding_index
                        if 0 <= flat_idx < len(flat_verdicts):
                            old = flat_verdicts[flat_idx]
                            integrity_changes[flat_idx] = {
                                "old_verdict": old["verdict"],
                                "old_severity": old["adjusted_severity"],
                                "new_verdict": change.verdict,
                                "new_severity": change.adjusted_severity.value if change.adjusted_severity else None,
                                "rationale": change.rationale,
                            }
                            # Apply the change to flat_verdicts
                            flat_verdicts[flat_idx] = {
                                "verdict": change.verdict,
                                "adjusted_severity": change.adjusted_severity.value if change.adjusted_severity else None,
                                "rationale": change.rationale,
                                "error": None,
                                "cost_usd": old["cost_usd"],
                                "integrity_revised": True,
                                "original_verdict": old["verdict"],
                            }

                    console.print(
                        f"[dim]  [batch {i+1}/{n_eligible}] "
                        f"{len(review_result.verdicts)} verdict(s) changed "
                        f"(${review_result.cost_usd:.4f})[/dim]"
                    )

            console.print(
                f"[cyan]Integrity review:[/cyan] {len(integrity_changes)} verdict(s) "
                f"changed across all batches. Cost: ${integrity_total_cost:.4f}"
            )

    # --- Summary ---
    total_spent = sum(b.cost_usd for b in batches) + integrity_total_cost
    tp = sum(1 for v in flat_verdicts if v["verdict"] == "true_positive")
    fp = sum(1 for v in flat_verdicts if v["verdict"] == "false_positive")
    unc = sum(1 for v in flat_verdicts if v["verdict"] == "uncertain")
    errored = sum(1 for v in flat_verdicts if v["error"])

    console.print()
    console.print("[bold]Verification summary:[/bold]")
    console.print(f"  True positive:  [red]{tp}[/red]")
    console.print(f"  False positive: [green]{fp}[/green]")
    console.print(f"  Uncertain:      [yellow]{unc}[/yellow]")
    if errored:
        console.print(f"  [red]Errored:        {errored}[/red]")
    if integrity_changes:
        console.print(f"  [cyan]Revised by review: {len(integrity_changes)}[/cyan]")
    console.print(f"  Total spend:    ${total_spent:.4f}")
    console.print(f"  Verified:       {len(verified_findings)} of {len(eligible_raw)} eligible")

    # --- Write verified report ---
    out_path = report.with_name(report.stem + "-verified.json")
    integrity_revisions = []
    for flat_idx, change in sorted(integrity_changes.items()):
        finding = verified_findings[flat_idx]
        integrity_revisions.append(
            {
                "finding_id": data.get("findings", [{}])[flat_idx].get("finding_id", f"F{flat_idx+1:05d}"),
                "finding_index": flat_idx,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "original_severity": finding.severity.value,
                "old_verdict": change["old_verdict"],
                "old_adjusted_severity": change["old_severity"],
                "new_verdict": change["new_verdict"],
                "new_adjusted_severity": change["new_severity"],
                "rationale": change["rationale"],
            }
        )

    verified_doc = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_report": str(report),
        "verifier": chosen.name,
        "mode": "batch",
        "integrity_review": integrity_review,
        "integrity_policy": "second-pass-self-review" if integrity_review else "not-run",
        "integrity_applied": bool(integrity_changes),
        "integrity_changes_count": len(integrity_changes),
        "integrity_review_revisions": len(integrity_changes),
        "integrity_revisions": integrity_revisions,
        "reviewed_findings": len(verified_findings),
        "true_positive": tp,
        "false_positive": fp,
        "uncertain": unc,
        "batch_size": batch_size,
        "results": [
            {
                "finding_id": eligible_raw[idx].get("finding_id", f"F{idx+1:05d}"),
                "finding_index": idx,
                "rule_id": f.rule_id,
                "title": f.title,
                "original_severity": f.severity.value,
                "raw_severity": f.severity.value,
                "final_severity": v.get("adjusted_severity") or f.severity.value,
                **v,
            }
            for idx, (f, v) in enumerate(zip(verified_findings, flat_verdicts))
        ],
        "total_spend_usd": round(total_spent, 4),
    }
    out_path.write_text(json.dumps(verified_doc, indent=2), encoding="utf-8")
    console.print()
    console.print(f"[green]Verified report: {out_path}[/green]")
    try:
        from .report_bundle import write_scan_bundle

        bundle_paths = write_scan_bundle(
            report.parent,
            data,
            verified_doc=verified_doc,
            patches_dir=(report.parent / "patches"),
        )
        console.print(f"[green]Updated bundle:[/green] {bundle_paths['readme']}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Bundle update skipped:[/yellow] {exc}")

@main.command("list")
@click.option(
    "--extended",
    is_flag=True,
    help="Also check for ~100 additional agents from the Aegis database "
         "(Cursor, Aider, Ollama, LM Studio, Warp, Goose, etc.). "
         "These agents don't have session parsers, but config audits still run.",
)
def list_agents(extended: bool) -> None:
    """List AI agents found on this machine without reading anything."""
    installations = discover(extended=extended)
    _print_discovery(installations)


@main.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Write report files to this directory.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Max sessions to parse per agent (most recent first).",
)
@click.option(
    "--mode",
    type=click.Choice(["conservative", "standard", "full"]),
    default="conservative",
    help=(
        "Scan scope. 'conservative' (default) = agent logs + configs only. "
        "'standard' = + environment probes (SSH keys). "
        "'full' = + adjacent-repo scan (reads ~/Documents etc.). "
        "Each step expands trust boundary and requires consent."
    ),
)
@click.option(
    "--scan-adjacent-repos",
    is_flag=True,
    help="Scan for writable adjacent git repos even in conservative mode. Same consent as --mode full.",
)
@click.option(
    "--patches",
    is_flag=True,
    help=(
        "Generate ready-to-apply patches for config findings alongside the report. "
        "Patches are written to <output>/patches/ — never auto-applied. "
        "Requires --output."
    ),
)
@click.option(
    "--extended",
    is_flag=True,
    help=(
        "Also run config audits on ~100 additional agents from the Aegis database "
        "(Cursor, Aider, Ollama, LM Studio, Warp, Goose, Windsurf, etc.). "
        "No session parsing for these — configs only."
    ),
)
@click.option(
    "--verify/--no-verify",
    "verify_after",
    default=None,
    help=(
        "Run LLM verification after scan finishes. Default: on for --mode full, "
        "off for conservative/standard. Pass --no-verify to disable in full mode, "
        "or --verify to enable in conservative/standard mode."
    ),
)
@click.option(
    "--verifier",
    type=click.Choice(
        ["auto", "claude", "codex", "anthropic", "openai", "openrouter", "ollama", "custom"]
    ),
    default="auto",
    help=(
        "Which verifier to use (only with --verify or --mode full). "
        "'auto' detects installed CLIs and API keys; if multiple are available "
        "you will be prompted. Explicit choices: claude, codex, anthropic, "
        "openai, openrouter, ollama, custom."
    ),
)
@click.option(
    "--integrity-review/--no-integrity-review",
    "integrity_review",
    default=None,
    help=(
        "Second-pass self-check where verifier reviews its own verdicts. "
        "Catches ~85%% of agent errors (from ASAMM dual-agent experiment). "
        "Default: on in --mode full, off otherwise. Roughly doubles verify cost."
    ),
)
@click.option(
    "--budget",
    type=float,
    default=1.0,
    help="Max USD cap for LLM verification (default $1.00). Stops early if exceeded.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip consent prompts — use in scripts.",
)
@click.option(
    "--cross-mode/--no-cross-mode", "cross_mode", default=True,
    help="Run M2 cross-mode signal flow as part of the scan (default: ON). "
         "Cross-mode links forensic findings to repository structural signals "
         "via the per-correlator design. Pass --no-cross-mode to skip — "
         "useful for back-to-back scans against giant rollouts where the "
         "cross-mode pass adds latency, or when isolating a forensic-only "
         "regression. v0.18.3 reversed the v0.18.0 D4 separate-subcommand "
         "default; the standalone `cross-mode` subcommand stays for rerun-on-"
         "saved-bundle workflows.",
)
@click.option(
    "--vendor-prune", "vendor_prune", is_flag=True, default=False,
    help="Filter test-fixture and documentation surfaces from the cross-mode "
         "inventory walk: skip benchmarks/, fixtures/, test_data/, "
         "test_fixtures/ directories AND README.md / CHANGELOG.md / etc. as "
         "instruction surfaces. Off by default — README of a project IS "
         "frequently the agent contract, and benchmarks/ on legitimate "
         "projects can carry real signal. Turn on for security-tooling repos "
         "and other projects whose meta-content trips up tag derivation.",
)
@click.option(
    "--verbose", "-v", "verbose", is_flag=True, default=False,
    help="Emit per-step timestamps in progress output. Useful for "
         "diagnosing where time is being spent (forensic rules vs "
         "cross-mode linker vs verify), especially after the v0.18.3 "
         "merge of cross-mode into the default scan path.",
)
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    output: Optional[Path],
    limit: Optional[int],
    mode: str,
    scan_adjacent_repos: bool,
    patches: bool,
    extended: bool,
    verify_after: Optional[bool],
    verifier: str,
    integrity_review: Optional[bool],
    budget: float,
    yes: bool,
    cross_mode: bool,
    vendor_prune: bool,
    verbose: bool,
) -> None:
    """Scan discovered agents and produce a report."""
    from .rules import DetectionMode

    log_path = default_log_path()
    audit_log = AuditLog(log_path)
    console.print(f"[dim]auditor log: {log_path}[/dim]")
    console.print()

    # Normalize mode — scan-adjacent-repos flag upgrades to full
    effective_mode = mode
    if scan_adjacent_repos and mode == "conservative":
        effective_mode = "full"
    # Map to internal DetectionMode enum (aggressive is our 'full')
    detection_mode = {
        "conservative": DetectionMode.CONSERVATIVE,
        "standard": DetectionMode.BALANCED,
        "full": DetectionMode.AGGRESSIVE,
    }[effective_mode]

    # Consent for expanded modes
    if effective_mode in ("standard", "full") and not yes:
        console.print("[bold yellow]Expanded scan mode requested.[/bold yellow]")
        if effective_mode == "standard":
            console.print(
                "[yellow]'standard' mode adds environment probes outside agent directories:[/yellow]"
            )
            console.print("  • Reads first ~5 lines of ~/.ssh/id_* to check for passphrase")
            console.print("  • Runs `ssh-keygen -y -P '' -f <key>` to verify encryption status")
            console.print("  • Does NOT read private key contents or transmit anything")
        elif effective_mode == "full":
            console.print(
                "[yellow]'full' mode ALSO runs filesystem probes in your home directory:[/yellow]"
            )
            console.print("  • `find ~/Documents ~/code ~/src ~/dev ~/projects -maxdepth 5 -name .git`")
            console.print("  • `git remote get-url origin` on each repo found")
            console.print("  • Checks write permissions (os.access) — no content read")
            console.print("  • Override roots: AGENT_AUDIT_SCAN_ROOTS env var (colon-separated)")

        if not Confirm.ask(f"Proceed with {effective_mode} mode?", default=True):
            console.print("[yellow]Aborted. Re-run without --mode to use conservative scan.[/yellow]")
            sys.exit(0)

    # Step 1 — discovery
    console.print("[bold]Step 1.[/bold] Discovering agents (read-only metadata)...")
    installations = discover(extended=extended)
    _print_discovery(installations)
    if not installations:
        sys.exit(0)

    # Step 2 — consent
    total_sessions = sum(a.session_count for a in installations)
    total_bytes = sum(a.total_bytes for a in installations)
    console.print()
    console.print("[bold]Step 2.[/bold] Request to read session logs")
    console.print(
        f"  Will read [cyan]{total_sessions}[/cyan] session files "
        f"([cyan]{total_bytes / 1024:.0f} KB[/cyan] total)."
    )
    console.print("  Analysis is local — no data sent to any server.")
    if not yes and not Confirm.ask("  Proceed?", default=True):
        console.print("[yellow]Aborted by user.[/yellow]")
        sys.exit(0)

    # Step 3 — scan
    console.print()
    console.print("[bold]Step 3.[/bold] Static analysis (rules, no LLM)...")
    result = scan(
        installations=installations,
        session_limit=limit,
        audit_log=audit_log,
        on_progress=lambda msg: console.print(f"  [dim]{msg}[/dim]"),
        mode=detection_mode,
        cross_mode=cross_mode,
        vendor_prune=vendor_prune,
        verbose=verbose,
    )

    _print_summary(result)

    # Step 4 — reports
    if output:
        md_path, json_path = write_reports(result, output)
        console.print()
        console.print(f"[green]Report written:[/green]")
        console.print(f"  {md_path}")
        console.print(f"  {json_path}")

        # v0.5 — optional patch generation
        patches_dir = None
        if patches:
            from .patch_generator import generate_all_patches
            patches_dir = output / "patches"
            # Load findings from the just-written JSON report
            report_data = json.loads(json_path.read_text(encoding="utf-8"))
            all_findings = report_data.get("findings", [])
            count, index_path = generate_all_patches(all_findings, patches_dir)
            if count:
                console.print(f"  [cyan]{count} patch(es):[/cyan] {patches_dir}")
                console.print(f"    Review: {index_path}")
                console.print(f"    [dim](patches are NOT auto-applied — run apply.sh manually)[/dim]")
            else:
                console.print(
                    f"  [dim]No auto-fixable config findings — no patches generated.[/dim]"
                )

        try:
            from .report_bundle import write_scan_bundle

            bundle_paths = write_scan_bundle(
                output,
                json.loads(json_path.read_text(encoding="utf-8")),
                patches_dir=patches_dir,
            )
            console.print(f"  [green]Bundle:[/green] {bundle_paths['readme']}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [yellow]Bundle write skipped:[/yellow] {exc}")

        # Step 5 — optional LLM verification
        # Default: on for --mode full, off otherwise. Overridable via --verify/--no-verify.
        should_verify = verify_after
        if should_verify is None:
            should_verify = (effective_mode == "full")
        # Same default logic for integrity_review
        should_review = integrity_review
        if should_review is None:
            should_review = (effective_mode == "full")

        if should_verify:
            if not result.findings:
                console.print()
                console.print("[dim]No findings to verify — skipping LLM step.[/dim]")
            else:
                console.print()
                console.print("[bold]Step 5.[/bold] LLM verification...")
                if effective_mode == "full" and verify_after is None:
                    console.print(
                        "[dim]  (auto-enabled by --mode full; pass --no-verify to skip)[/dim]"
                    )
                try:
                    ctx.invoke(
                        verify_cmd,
                        report=json_path,
                        budget=budget,
                        verifier=verifier,
                        severity="medium",
                        batch_size=25,
                        concurrency=4,
                        timeout=240,
                        claude_model="sonnet",
                        proxy=None,   # verify_cmd will auto-detect from env
                        skip_preflight=False,
                        integrity_review=should_review,
                        yes=yes,
                    )
                except SystemExit as e:
                    # verify_cmd calls sys.exit on no working backends — don't
                    # nuke the scan results. Just report and continue.
                    if e.code and e.code != 0:
                        console.print()
                        console.print(
                            "[yellow]LLM verification did not complete. "
                            "Scan report is still valid above.[/yellow]"
                        )
                        console.print(
                            f"[dim]To retry verify later: "
                            f"agent-audit verify -r {json_path}[/dim]"
                        )
    else:
        console.print()
        console.print(
            "[dim]Pass --output DIR to write full Markdown + JSON reports.[/dim]"
        )
        if patches:
            console.print(
                "[yellow]--patches requires --output. No patches generated.[/yellow]"
            )


@main.command("scan-project")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Write Markdown + JSON report to this directory.",
)
@click.option(
    "--tool",
    type=click.Choice(["all", "atr", "aguara", "cisco-promptguard", "gitleaks", "nova"]),
    default="all",
    help="Filter rules by source tool. Default: all.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Suppress findings below this severity.",
)
@click.option(
    "--yes", "-y", is_flag=True,
    help="Skip the consent prompt — use in scripts.",
)
@click.option(
    "--no-aggregate", is_flag=True,
    help="Disable collection-scale aggregation (show every finding individually).",
)
@click.option(
    "--curation-profile",
    type=click.Choice(["none", "curated-v1"]),
    default="none",
    help="Apply an adjudication-backed post-processing profile before severity filtering.",
)
@click.option(
    "--track-tool-pinning/--no-track-tool-pinning",
    default=False,
    help="Compare MCP tool descriptions against the saved baseline and emit "
         "rug-pull findings on changes. First scan records the baseline silently.",
)
@click.option(
    "--update-pinning-baseline",
    is_flag=True,
    help="Together with --track-tool-pinning, update the baseline after "
         "comparison. Without this flag, the baseline stays unchanged so "
         "the same drift fires on every subsequent scan (CI-friendly).",
)
def scan_project_cmd(path: Path, output: Optional[Path], tool: str,
                     min_severity: str, yes: bool, no_aggregate: bool,
                     curation_profile: str,
                     track_tool_pinning: bool,
                     update_pinning_baseline: bool) -> None:
    """Scan a repo or directory of repos with rule packs.

    PATH may be a single repository (contains .git), a directory of repositories,
    or any directory containing instruction files / skill packs / MCP manifests.

    Uses static-file-applicable bundled rules from three open-source packs
    (ATR, Aguara, Cisco PromptGuard).
    See src/agent_audit/knowledge/rule_packs/*/README.md for attribution.
    """
    from .project_scanner import scan_project
    from .knowledge.rule_pack_loader import load_all_rules, pack_summary
    from .finding_dedup import build_security_profile, cluster_findings
    from .project_report import (
        build_files_of_concern,
        build_project_json,
        build_report_profiles,
        render_project_markdown,
    )
    from .rules import Severity
    from .signature_curation import apply_curation_profile

    abs_path = path.resolve()

    # Consent prompt — this is a filesystem read, we name what we read.
    console.print(f"[bold]About to scan:[/bold] {abs_path}")
    summary = pack_summary()
    console.print(
        f"[dim]Using {summary['total']} rules from: "
        + ", ".join(f"{k}={v}" for k, v in summary["by_tool"].items())
        + "[/dim]"
    )
    if not yes and not Confirm.ask("Proceed?", default=True):
        console.print("[yellow]Aborted.[/yellow]")
        return

    all_rules = load_all_rules()
    if tool != "all":
        all_rules = [r for r in all_rules if r.source_tool == tool]
        console.print(f"[dim]Filtered to --tool {tool}: {len(all_rules)} rules[/dim]")

    # Run
    result = scan_project(
        abs_path,
        rules=all_rules,
        on_progress=lambda msg: console.print(f"[dim]  {msg}[/dim]"),
        aggregate_collections=not no_aggregate,
    )

    # N1 — tool-pinning state-tracking detector. Opt-in because mutating
    # state on every scan would surprise users running ad-hoc scans.
    # When enabled, runs after scan_project and merges its findings into
    # the result so they flow through the same reporting pipeline.
    if track_tool_pinning:
        from .tool_pinning import check_project as check_tool_pinning
        try:
            pinning_findings = check_tool_pinning(
                abs_path, update_baseline=update_pinning_baseline,
            )
        except Exception as e:  # noqa: BLE001
            console.print(
                f"[yellow]  tool-pinning detector failed: {e}[/yellow]"
            )
            pinning_findings = []
        if pinning_findings:
            result.findings.extend(pinning_findings)
            console.print(
                f"[dim]  tool-pinning: {len(pinning_findings)} finding(s)[/dim]"
            )
        elif update_pinning_baseline:
            console.print("[dim]  tool-pinning: baseline updated, no drift[/dim]")
        else:
            console.print("[dim]  tool-pinning: no drift detected[/dim]")

    curation_summary = None
    if curation_profile != "none":
        curated_findings, curated_summary_obj = apply_curation_profile(result.findings, curation_profile)
        result.findings = curated_findings
        curation_summary = curated_summary_obj.to_dict()

    # Severity filter
    min_sev = Severity(min_severity)
    kept = [f for f in result.findings if f.severity.order >= min_sev.order]
    dropped = len(result.findings) - len(kept)
    clustered_result = cluster_findings(kept)
    security_profile = build_security_profile(clustered_result)

    # Render summary table
    console.print()
    table = Table(title="Scan summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Repos scanned", str(len(result.repos_scanned)))
    table.add_row("Files scanned", str(result.files_scanned))
    table.add_row("Files with findings", str(result.files_with_findings))
    table.add_row("Findings (total)", str(len(result.findings)))
    if curation_summary is not None:
        table.add_row("Curation profile", curation_summary["profile"])
        table.add_row("Curation suppressed", str(curation_summary["suppressed_findings"]))
        table.add_row("Curation downgraded", str(curation_summary["severity_downgrades"]))
    if dropped:
        table.add_row(f"Suppressed (< {min_severity})", str(dropped))
    table.add_row("Findings (shown)", str(len(kept)))
    console.print(table)

    # Breakdown by severity + by tool
    if kept:
        by_sev: dict = {}
        by_tool: dict = {}
        for f in kept:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            # source_tool is in references as "upstream:<tool>:<id>"
            for ref in f.references:
                if ref.startswith("upstream:"):
                    t = ref.split(":", 2)[1]
                    by_tool[t] = by_tool.get(t, 0) + 1
                    break

        sev_line = ", ".join(
            f"[{SEVERITY_STYLES.get(k,'')}]{k}={v}[/]"
            for k, v in sorted(by_sev.items(), key=lambda kv: -Severity(kv[0]).order)
        )
        console.print(f"By severity: {sev_line}")
        console.print("By tool:     " + ", ".join(f"{k}={v}" for k, v in sorted(by_tool.items())))
        console.print(
            "Issue view:  "
            + ", ".join(
                [
                    f"instances={security_profile['issue_instances']}",
                    f"highest={security_profile['highest_issue_severity'] or 'none'}",
                    f"multi_signal={security_profile['multi_signal_issue_instances']}",
                    f"cross_tool={security_profile['cross_tool_issue_instances']}",
                    f"native_led={security_profile['native_led_issue_instances']}",
                ]
            )
        )
        if security_profile["canonical_class_counts"]:
            top_issue_classes = ", ".join(
                f"{canonical_class}={count}"
                for canonical_class, count in list(security_profile["canonical_class_counts"].items())[:5]
            )
            console.print("Issue classes: " + top_issue_classes)

        # Top findings
        console.print()
        top = sorted(kept, key=lambda f: -f.severity.order)[:10]
        console.print("[bold]Top findings:[/bold]")
        for f in top:
            style = SEVERITY_STYLES.get(f.severity.value, "")
            console.print(f"  [{style}]{f.severity.value.upper():<8}[/] {f.rule_id}")
            console.print(f"           [dim]{f.summary}[/dim]")

    # Write reports if requested
    if output:
        from .report_rerank import rerank, native_summary_dict
        rerank_result = rerank(kept)

        output.mkdir(parents=True, exist_ok=True)
        # JSON
        json_out = output / "project-findings.json"
        project_json = build_project_json(abs_path, result, kept, rerank_result, curation_summary=curation_summary)
        project_json["native_summary"] = native_summary_dict(rerank_result)
        json_out.write_text(json.dumps(project_json, indent=2, default=str))

        # Markdown — native-first rendering with profile summary
        md_out = output / "project-findings.md"
        md_out.write_text(
            render_project_markdown(abs_path, result, min_severity, kept, rerank_result, curation_summary=curation_summary)
        )
        files_of_concern = build_files_of_concern(kept, rerank_result)
        (output / "files-of-concern.json").write_text(
            json.dumps(files_of_concern, indent=2),
            encoding="utf-8",
        )
        # Compatibility alias retained because older validation expected it.
        (output / "sessions-of-concern.json").write_text(
            json.dumps(files_of_concern, indent=2),
            encoding="utf-8",
        )
        (output / "report-profiles.json").write_text(
            json.dumps(build_report_profiles(kept, rerank_result, clustered_result, security_profile), indent=2),
            encoding="utf-8",
        )
        (output / "clustered-findings.json").write_text(
            json.dumps(clustered_result.to_dict(), indent=2),
            encoding="utf-8",
        )
        (output / "security-profile.json").write_text(
            json.dumps(security_profile, indent=2),
            encoding="utf-8",
        )
        console.print()
        console.print(f"[green]Wrote[/green] {json_out}")
        console.print(f"[green]Wrote[/green] {md_out}")
        console.print(f"[green]Wrote[/green] {output / 'files-of-concern.json'}")
        console.print(f"[green]Wrote[/green] {output / 'report-profiles.json'}")
        console.print(f"[green]Wrote[/green] {output / 'clustered-findings.json'}")
        console.print(f"[green]Wrote[/green] {output / 'security-profile.json'}")


@main.command("corpus-lab")
@click.option(
    "--corpus",
    "-c",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
    help="Corpus root containing cloned repos.",
)
@click.option(
    "--baseline",
    "-b",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional baseline corpus-snapshot.json to compare against.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    required=True,
    help="Write snapshot/compare reports here.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    show_default=True,
)
@click.option("--no-aggregate", is_flag=True, help="Disable collection-scale aggregation.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def corpus_lab_cmd(
    corpus: Path,
    baseline: Optional[Path],
    output: Path,
    min_severity: str,
    no_aggregate: bool,
    yes: bool,
) -> None:
    """Run the 500-repo project corpus as a regression gate."""
    from .corpus_lab import compare_snapshots, create_snapshot, write_reports

    abs_corpus = corpus.resolve()
    console.print(f"[bold]About to scan corpus:[/bold] {abs_corpus}")
    if baseline:
        console.print(f"[dim]Baseline:[/dim] {baseline.resolve()}")
    if not yes and not Confirm.ask("Proceed?", default=True):
        console.print("[yellow]Aborted.[/yellow]")
        return

    snapshot = create_snapshot(
        abs_corpus,
        min_severity=min_severity,
        aggregate_collections=not no_aggregate,
    )

    comparison = None
    if baseline:
        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        from .corpus_lab import CorpusSnapshot

        baseline_snapshot = CorpusSnapshot(**baseline_data)
        comparison = compare_snapshots(baseline_snapshot, snapshot)

    paths = write_reports(output.resolve(), snapshot, comparison)
    console.print(f"[green]Wrote[/green] {paths['snapshot']}")
    console.print(f"[green]Wrote[/green] {paths['markdown']}")
    if comparison is not None:
        console.print(f"[green]Wrote[/green] {paths['compare']}")
        if not comparison["passed"]:
            raise SystemExit(1)


@main.command("eval")
@click.option(
    "--corpus", "-c",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=Path("benchmarks/incident-corpus"),
    show_default=True,
    help="Curated incident corpus directory.",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Write eval JSON + Markdown summary to this directory.",
)
@click.option(
    "--baseline",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a prior eval-*.json baseline. When set, the harness "
         "compares current results against it and exits non-zero on drift.",
)
@click.option(
    "--ci", is_flag=True,
    help="CI mode: terse output, exit non-zero on any failed case or drift.",
)
@click.option(
    "--yes", "-y", is_flag=True,
    help="Skip the confirmation prompt.",
)
def eval_cmd(
    corpus: Path,
    output: Optional[Path],
    baseline: Optional[Path],
    ci: bool,
    yes: bool,
) -> None:
    """Run end-to-end real-data eval (scan + scan-project + cross-mode).

    \b
    Extends `benchmark` with:
    - scan-project run on each case's project/ subtree
    - cross-mode aggregate-record scoring
    - per-stage perf timings
    - drift detection vs an optional baseline (CI mode)

    \b
    Each case in the corpus may declare:
    - expected_findings (existing): forensic-side rules
    - expected_static_findings: scan-project rules (v0.19+)
    - expected_correlators: cross-mode aggregates (v0.19+)
    - expected_runtime_budget_seconds: perf budget (v0.19+)

    \b
    Cases without v0.19 fields run permissively (no static/correlator
    expectations). Use this command in CI to catch regressions across
    release cycles.
    """
    from .eval_harness import (
        detect_drift, evaluate_corpus, write_eval_reports,
    )

    abs_corpus = corpus.resolve()
    if not ci:
        console.print(f"[bold]About to eval:[/bold] {abs_corpus}")
        if not yes and not Confirm.ask("Proceed?", default=True):
            console.print("[yellow]Aborted.[/yellow]")
            return

    progress_cb = None
    if not ci:
        progress_cb = lambda msg: console.print(f"[dim]  {msg}[/dim]")

    summary = evaluate_corpus(abs_corpus, on_progress=progress_cb)

    # Console summary
    if ci:
        # Terse one-liner per case + final score
        for cr in summary.case_results:
            mark = "PASS" if cr.passed else "FAIL"
            budget = " (OVER BUDGET)" if cr.over_budget else ""
            console.print(f"{mark} {cr.case_id}{budget}")
        console.print(
            f"\nforensic recall={summary.forensic_recall:.4f} "
            f"static recall={summary.static_recall:.4f} "
            f"correlator recall={summary.correlator_recall:.4f} "
            f"wall={summary.total_wall_seconds:.1f}s"
        )
    else:
        table = Table(title="Eval summary")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Cases", str(summary.case_count))
        table.add_row("Passed end-to-end", str(summary.passed_cases))
        table.add_row("Failed", str(summary.failed_cases))
        table.add_row("Over budget", str(summary.over_budget_cases))
        table.add_row("Forensic precision", f"{summary.forensic_precision:.4f}")
        table.add_row("Forensic recall", f"{summary.forensic_recall:.4f}")
        table.add_row("Static recall", f"{summary.static_recall:.4f}")
        table.add_row("Correlator recall", f"{summary.correlator_recall:.4f}")
        table.add_row("Total wall (s)", f"{summary.total_wall_seconds:.1f}")
        table.add_row("Median case (s)", f"{summary.median_case_seconds:.2f}")
        console.print()
        console.print(table)

    # Drift detection
    drift_msgs: list = []
    if baseline:
        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        drift_msgs = detect_drift(summary, baseline_data)
        if drift_msgs:
            console.print()
            console.print("[bold red]Drift detected:[/bold red]")
            for msg in drift_msgs:
                console.print(f"  - {msg}")
        else:
            console.print()
            console.print("[green]No drift detected vs baseline.[/green]")

    if output:
        json_path, md_path = write_eval_reports(summary, output)
        console.print()
        console.print(f"Wrote {json_path}")
        console.print(f"Wrote {md_path}")

    # Exit code
    if ci:
        if summary.failed_cases > 0 or drift_msgs:
            raise SystemExit(1)


@main.command("benchmark")
@click.option(
    "--corpus", "-c",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=Path("benchmarks/incident-corpus"),
    show_default=True,
    help="Curated incident corpus directory.",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Write benchmark JSON + Markdown summary to this directory.",
)
@click.option(
    "--yes", "-y",
    is_flag=True,
    help="Skip the confirmation prompt.",
)
def benchmark_cmd(corpus: Path, output: Optional[Path], yes: bool) -> None:
    """Run the curated incident benchmark and score precision/recall."""
    from .benchmark import run_benchmark, write_reports

    abs_corpus = corpus.resolve()
    console.print(f"[bold]About to benchmark:[/bold] {abs_corpus}")
    if not yes and not Confirm.ask("Proceed?", default=True):
        console.print("[yellow]Aborted.[/yellow]")
        return

    summary = run_benchmark(abs_corpus)

    table = Table(title="Benchmark summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Cases", str(summary.case_count))
    table.add_row("Passed", str(summary.passed_cases))
    table.add_row("Failed", str(summary.failed_cases))
    table.add_row("Expected labels", str(summary.expected_total))
    table.add_row("Predicted labels", str(summary.predicted_total))
    table.add_row("True positives", str(summary.true_positives))
    table.add_row("False negatives", str(summary.false_negatives))
    table.add_row("False positives", str(summary.false_positives))
    table.add_row("Precision", f"{summary.precision:.4f}")
    table.add_row("Recall", f"{summary.recall:.4f}")
    console.print()
    console.print(table)

    if summary.per_rule:
        console.print()
        console.print("[bold]Per-rule:[/bold]")
        for rule_id, stats in summary.per_rule.items():
            console.print(
                f"  {rule_id}: precision={stats['precision']:.4f}, "
                f"recall={stats['recall']:.4f}, tp={stats['tp']}, "
                f"fn={stats['fn']}, fp={stats['fp']}"
            )

    failing = [case for case in summary.case_results if not case.passed]
    if failing:
        console.print()
        console.print("[bold red]Failing cases:[/bold red]")
        for case in failing:
            console.print(f"  - {case.case_id}: {case.title}")
            if case.false_negatives:
                console.print(
                    "    missing: " + ", ".join(
                        f"{label.rule_id}:{label.severity}" for label in case.false_negatives
                    )
                )
            if case.false_positives:
                console.print(
                    "    extra:   " + ", ".join(
                        f"{label.rule_id}:{label.severity}" for label in case.false_positives
                    )
                )

    if output:
        json_path, md_path = write_reports(summary, output.resolve())
        console.print()
        console.print(f"[green]Wrote[/green] {json_path}")
        console.print(f"[green]Wrote[/green] {md_path}")

    if summary.failed_cases:
        raise SystemExit(1)


@main.command("packs")
@click.option("--all", "show_all", is_flag=True, help="Include session-event rules (otherwise only static-file-applicable rules are shown).")
def packs_cmd(show_all: bool) -> None:
    """Show what rule packs are loaded."""
    from .knowledge.rule_pack_loader import pack_summary
    s = pack_summary(static_only=not show_all)
    mode_note = "all (including session-event rules)" if show_all else "static-file-applicable only"
    console.print(f"[bold]Total rules:[/bold] {s['total']}  [dim]({mode_note})[/dim]")
    if not show_all:
        full = pack_summary(static_only=False)
        console.print(f"[dim]  pass --all to see all {full['total']} rules incl. session-only.[/dim]")
    console.print()
    console.print("[bold]By tool:[/bold]")
    for k, v in s["by_tool"].items():
        console.print(f"  {k}: {v}")
    console.print()
    console.print("[bold]By category:[/bold]")
    for k, v in s["by_category"].items():
        console.print(f"  {k}: {v}")
    console.print()
    console.print("[bold]By severity:[/bold]")
    for k, v in s["by_severity"].items():
        style = SEVERITY_STYLES.get(k, "")
        console.print(f"  [{style}]{k}[/]: {v}")


@main.command("atlas-validate")
@click.option(
    "--strict",
    is_flag=True,
    help="Exit 1 on ANY issue (including name drift). Default exits 1 only on unknown/deprecated IDs.",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Emit JSON instead of text report.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Print nothing; rely on exit code only.",
)
def atlas_validate_cmd(strict: bool, as_json: bool, quiet: bool) -> None:
    """Validate mitre_atlas:* references against the vendored ATLAS snapshot.

    Walks every rule pack YAML plus native detectors, collects mitre_atlas
    references, and checks each against the bundled MITRE ATLAS data.
    Catches three drift classes: unknown ID, deprecated/revoked technique,
    and name-mismatch (e.g. ATLAS renamed 'ML Supply Chain' → 'AI Supply Chain').

    Useful as a CI guardrail. Snapshot lives under
    src/agent_audit/data/atlas/ATLAS.yaml — refresh procedure documented
    next to it.
    """
    from .tools.atlas_validate import main as atlas_main
    argv = []
    if strict:
        argv.append("--strict")
    if as_json:
        argv.append("--json")
    if quiet:
        argv.append("--quiet")
    raise SystemExit(atlas_main(argv))


@main.command("owasp-mcp-validate")
@click.option(
    "--strict",
    is_flag=True,
    help="Exit 1 on ANY issue (including name drift). Default exits 1 only on unknown IDs.",
)
@click.option(
    "--include-missing",
    is_flag=True,
    help="Also list rules whose category has a known MCP mapping but no explicit owasp_mcp ref yet (informational, never affects exit code).",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Emit JSON instead of text report.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress stdout output.",
)
def owasp_mcp_validate_cmd(strict: bool, include_missing: bool, as_json: bool, quiet: bool) -> None:
    """Validate owasp_mcp:* references against the vendored OWASP MCP Top 10 index.

    Same shape as atlas-validate (see Roadmap B3). Catches three drift classes:
    unknown MCP IDs, name mismatch with upstream titles, and rules whose
    category has a known MCP mapping but haven't yet exposed it in YAML
    references.

    The rule-pack loader enriches references with derived owasp_mcp refs
    automatically at load time — explicit YAML refs are not required.
    """
    from .tools.owasp_mcp_validate import main as owasp_mcp_main
    argv = []
    if strict:
        argv.append("--strict")
    if include_missing:
        argv.append("--include-missing")
    if as_json:
        argv.append("--json")
    if quiet:
        argv.append("--quiet")
    raise SystemExit(owasp_mcp_main(argv))


@main.command("owasp-agentic-validate")
@click.option("--strict", is_flag=True,
              help="Exit 1 on ANY issue (including name drift). Default exits 1 only on unknown IDs.")
@click.option("--include-missing", is_flag=True,
              help="Also list rules with mappable category but no explicit owasp_agentic ref (informational, never affects exit code).")
@click.option("--json", "as_json", is_flag=True,
              help="Emit JSON instead of text report.")
@click.option("--quiet", is_flag=True,
              help="Suppress stdout output.")
def owasp_agentic_validate_cmd(strict: bool, include_missing: bool, as_json: bool, quiet: bool) -> None:
    """Validate owasp_agentic:* references against the vendored ASI Top 10 index.

    Same shape as atlas-validate (B3) and owasp-mcp-validate (B1). Catches
    unknown ASI IDs, name mismatch with the upstream titles, and rules whose
    category has a known ASI mapping but haven't yet exposed it in YAML.

    The references_rewrite mechanism in rule_pack_overrides.yaml absorbs
    upstream draft → release name drift; this validator measures runtime
    state, not raw YAML text.
    """
    from .tools.owasp_agentic_validate import main as agentic_main
    argv = []
    if strict:
        argv.append("--strict")
    if include_missing:
        argv.append("--include-missing")
    if as_json:
        argv.append("--json")
    if quiet:
        argv.append("--quiet")
    raise SystemExit(agentic_main(argv))


@main.command("avid-validate")
@click.option(
    "--strict",
    is_flag=True,
    help="Exit 1 on ANY issue (including name drift). Default exits 1 only on unknown SEP IDs.",
)
@click.option(
    "--include-missing",
    is_flag=True,
    help="Also list rules whose category has a known AVID mapping but no explicit avid: ref yet (informational, never affects exit code).",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Emit JSON instead of text report.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress stdout output.",
)
def avid_validate_cmd(strict: bool, include_missing: bool, as_json: bool, quiet: bool) -> None:
    """Validate avid:* references against the canonical SEP subcategory list.

    AVID (AI Vulnerability Database) ships ~weekly releases of records
    plus a slowly-evolving SEP (Security/Ethics/Performance) taxonomy.
    We cross-link rules to SEP subcategories at the (tool, category)
    layer rather than per-record because record IDs are less stable
    across the 2026 GPAI rebuild.

    Catches drift classes mirroring atlas-validate, owasp-mcp-validate,
    and owasp-agentic-validate: unknown SEP ID, name mismatch with
    upstream, and rules whose category has a known SEP mapping but
    haven't yet exposed it in references.
    """
    from .tools.avid_validate import main as avid_main
    argv = []
    if strict:
        argv.append("--strict")
    if include_missing:
        argv.append("--include-missing")
    if as_json:
        argv.append("--json")
    if quiet:
        argv.append("--quiet")
    raise SystemExit(avid_main(argv))


@main.command("injection-benchmark")
@click.option(
    "--agentdyn",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Path to a clone of github.com/SaFo-Lab/AgentDyn (D2 corpus).",
)
@click.option(
    "--wasp",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Path to a clone of github.com/facebookresearch/wasp (D3 corpus, "
         "CC-BY-NC).",
)
@click.option(
    "--output", "-o",
    type=click.Path(file_okay=True, path_type=Path),
    help="Write JSON report to this file. Default: print summary to stdout.",
)
@click.option(
    "--show-undetected",
    is_flag=True,
    help="Print every case where no rule fired. Useful for finding "
         "uncovered injection styles.",
)
def injection_benchmark_cmd(
    agentdyn: Optional[Path], wasp: Optional[Path],
    output: Optional[Path], show_undetected: bool,
) -> None:
    """Measure rule-pack recall on AgentDyn and WASP injection corpora.

    \b
    These benchmarks are NOT bundled with agent-audit:
      - AgentDyn (D2): MIT license; clone github.com/SaFo-Lab/AgentDyn
      - WASP      (D3): CC-BY-NC; clone github.com/facebookresearch/wasp

    \b
    For each cloned corpus, the adapter:
      1. Walks the upstream tree and harvests injection text strings.
      2. Runs every loaded rule pack pattern against each string.
      3. Reports recall (cases with ≥1 rule firing / total) and per-rule
         contribution.

    The benchmark measures recall ONLY. Precision needs a paired benign
    corpus, which lives separately. High recall on adversarial cases
    paired with high FP rate on benign docs (which calibration showed
    for some NOVA rules) is the actionable signal — it tells us which
    rules need M3 evaluator gating to lift severity safely.
    """
    if not agentdyn and not wasp:
        click.echo(
            "Pass --agentdyn PATH and/or --wasp PATH. See `injection-benchmark --help`."
        )
        raise SystemExit(2)

    from .injection_benchmarks import (
        load_agentdyn_cases, load_wasp_cases, run_benchmark,
    )
    from .knowledge.rule_pack_loader import load_all_rules

    rules = load_all_rules()
    reports = []

    if agentdyn:
        click.echo(f"Loading AgentDyn cases from {agentdyn}...")
        cases = load_agentdyn_cases(agentdyn)
        click.echo(f"  {len(cases)} cases")
        report = run_benchmark(cases, rules=rules, suite_label="agentdyn")
        reports.append(report)
        _print_report(report, show_undetected)

    if wasp:
        click.echo(f"\nLoading WASP cases from {wasp}...")
        cases = load_wasp_cases(wasp)
        click.echo(f"  {len(cases)} cases")
        report = run_benchmark(cases, rules=rules, suite_label="wasp")
        reports.append(report)
        _print_report(report, show_undetected)

    if output:
        import json as _json
        out_data = {"reports": [r.to_dict() for r in reports]}
        output.write_text(_json.dumps(out_data, indent=2, default=str))
        click.echo(f"\nWrote {output}")


def _print_report(report, show_undetected: bool) -> None:
    """Pretty-print a single benchmark report."""
    click.echo(f"\n=== {report.suite.upper()} ===")
    click.echo(f"  Total cases:    {report.total_cases}")
    click.echo(f"  Detected:       {report.detected_cases}")
    click.echo(f"  Recall:         {report.recall:.1%}")
    if report.per_rule_hits:
        click.echo(f"\n  Top 10 rules by contribution:")
        for rid, c in sorted(
            report.per_rule_hits.items(), key=lambda kv: -kv[1]
        )[:10]:
            click.echo(f"    {c:4} {rid}")
    if show_undetected and report.undetected:
        click.echo(f"\n  Undetected cases ({len(report.undetected)}):")
        for r in report.undetected[:20]:
            click.echo(f"    [{r.case_id}] {r.text_preview}")
        if len(report.undetected) > 20:
            click.echo(f"    ... +{len(report.undetected) - 20} more")


@main.command("nova-evaluate")
@click.option(
    "--report", "report_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Path to a project-findings.json produced by scan-project.",
)
@click.option(
    "--verifier",
    default="claude-cli",
    type=click.Choice(["claude-cli", "codex-cli", "anthropic-api", "openai-api"]),
    help="LLM backend for the llm gate. Same choices as `verify`.",
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Skip the llm gate. Run semantics-only (requires sentence-transformers).",
)
@click.option(
    "--no-semantics",
    is_flag=True,
    help="Skip the semantics gate. Run llm-only.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print verdicts but don't update the report file in place.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress per-finding output. Print summary only.",
)
def nova_evaluate_cmd(
    report_path: Path,
    verifier: str,
    no_llm: bool,
    no_semantics: bool,
    dry_run: bool,
    quiet: bool,
) -> None:
    """Run NOVA semantics+llm gates on findings to lift severity (M3).

    NOVA rules import at LOW severity because the keyword-only signal is
    too weak without the upstream semantics + llm gates. This command
    runs those gates after the fact:

    \b
      - semantics gate: cosine similarity between matched snippet and
        upstream prose patterns (requires sentence-transformers).
      - llm gate:      yes/no question to a configured LLM backend.

    \b
    Severity policy:
      both gates available, both pass     → upstream severity
      one gate available, that passes     → partial lift (one notch up)
      gate fails                          → demote to INFO
      no gates available                  → leave at LOW (no-op)

    Updates the report file in place unless --dry-run is given.
    """
    import json as _json
    from .nova_evaluator import (
        _EmbeddingModelHandle,
        apply_verdict,
        evaluate_batch,
        filter_nova_findings,
    )
    from .knowledge.rule_pack_loader import load_all_rules

    data = _json.loads(report_path.read_text())
    raw_findings = data.get("findings", [])

    # Reconstruct minimal Finding objects for evaluator. We only need
    # rule_id, severity, summary, and evidence[0].snippet — that's what
    # the evaluator reads. We don't round-trip everything; the apply step
    # mutates the dict directly.
    from .rules import Confidence, Evidence, Finding, Severity
    findings = []
    for entry in raw_findings:
        rid = entry.get("rule_id", "")
        if not rid.startswith("nova."):
            continue
        sev = Severity(entry.get("severity", "low"))
        evidence = []
        for ev_dict in entry.get("evidence", []) or []:
            evidence.append(Evidence(
                description=ev_dict.get("description", ""),
                snippet=ev_dict.get("snippet"),
            ))
        findings.append((entry, Finding(
            rule_id=rid,
            title=entry.get("title", rid),
            severity=sev,
            confidence=Confidence(entry.get("confidence", "medium")),
            summary=entry.get("summary", ""),
            evidence=evidence,
            references=list(entry.get("references", []) or []),
        )))

    if not findings:
        click.echo("No NOVA findings in report — nothing to do.")
        raise SystemExit(0)

    rules = load_all_rules()

    embedder = None if no_semantics else _EmbeddingModelHandle.get()
    backend = None
    if not no_llm:
        from .batch_verifier import (
            ClaudeCodeBackend, CodexCLIBackend,
            AnthropicAPIBackend, OpenAICompatibleBackend,
        )
        backend_map = {
            "claude-cli": ClaudeCodeBackend,
            "codex-cli": CodexCLIBackend,
            "anthropic-api": AnthropicAPIBackend,
            "openai-api": OpenAICompatibleBackend,
        }
        backend = backend_map[verifier]()
        if not backend.available():
            click.echo(
                f"WARNING: {verifier} backend unavailable; skipping llm gate.",
                err=True,
            )
            backend = None

    only_findings = [f for _, f in findings]
    verdicts = evaluate_batch(only_findings, embedder=embedder, backend=backend, rules=rules)

    promoted = demoted = unchanged = 0
    for (entry, _f), verdict in zip(findings, verdicts):
        if verdict.new_severity is None:
            unchanged += 1
            continue
        if not quiet:
            click.echo(
                f"  {verdict.finding.rule_id}: "
                f"{verdict.finding.severity.value} → {verdict.new_severity.value}  "
                f"({verdict.rationale})"
            )
        if verdict.new_severity.order > verdict.finding.severity.order:
            promoted += 1
        else:
            demoted += 1
        if not dry_run:
            entry["severity"] = verdict.new_severity.value
            entry.setdefault("references", []).append(
                f"nova-evaluator:{verdict.rationale}"
            )

    click.echo(
        f"\nNOVA evaluator: {len(verdicts)} findings — "
        f"promoted={promoted}, demoted={demoted}, unchanged={unchanged}"
    )
    if not dry_run:
        report_path.write_text(_json.dumps(data, indent=2, default=str))
        click.echo(f"Updated {report_path}")


# ---------------------------------------------------------------------------
# cross-mode subcommand — M2 Phase 2 entry point.
#
# Per D4 (settled): separate subcommand over saved scan outputs, NOT
# auto-invoked inside `scan`. This keeps the execution boundary
# explicit so debugging "did the dynamic detector change, or did the
# linker change?" is a one-step bisect.
#
# Per D5 (settled): the linker assumes findings have ALREADY been
# filtered against user-config suppressions. Findings produced by
# `scan` go through `_apply_project_config()` before being written
# to the JSON report — so a saved `audit-*.json` carries
# already-suppressed findings and is safe to feed to the linker
# directly.
# ---------------------------------------------------------------------------


def _load_forensic_bundle(forensic_path: Path) -> dict:
    """Read a saved scan JSON. Validates the minimal shape we need."""
    if not forensic_path.exists():
        raise click.ClickException(
            f"Forensic report not found: {forensic_path}\n"
            f"Pass the path to a JSON file produced by `agent-audit scan --output DIR`."
        )
    try:
        raw = json.loads(forensic_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Could not parse {forensic_path} as JSON: {exc}"
        )
    if not isinstance(raw, dict):
        raise click.ClickException(
            f"{forensic_path} does not look like a scan report (expected object at top)."
        )
    if "sessions" not in raw or "findings" not in raw:
        raise click.ClickException(
            f"{forensic_path} is missing `sessions` or `findings` — does not look "
            f"like a scan JSON. Generate one with `agent-audit scan --output DIR`."
        )
    return raw


def _findings_by_session(findings: list) -> dict:
    """Group findings by session_id. Findings without a session_id (e.g.
    config-level) are grouped under empty-string key so callers can ignore.

    v0.19 fix: in saved scan JSON, session_id lives INSIDE the evidence
    array, not at the top level of the finding dict. Pre-fix this helper
    only checked the top level, so every saved-bundle finding ended up in
    the empty-string bucket and the linker never saw them. Cross-mode
    produced 0 aggregate records on real bundles even when matching
    dynamic findings + risk tags both fired. Discovered during real-data
    investigation with maintainer's full-rerun bundle 2026-05-04: 5 of 6
    risk-tagged sessions had matching dynamic findings (C3.autonomy-with-
    exfil-chain, AI-06.indirect-prompt-injection-vector) but cross-mode
    emitted 0 aggregates. Direct linker call on the same data produced
    correct records — bug was specifically in this helper.
    """
    out: dict = {}
    for f in findings:
        # First check top-level (in case scoring/normalization put it there)
        sid = f.get("session_id") or ""
        # Fall back to evidence — this is where the saved JSON actually
        # carries it (Finding.evidence: List[Evidence], each Evidence has
        # an optional session_id). Take the first non-empty one.
        if not sid:
            for ev in f.get("evidence", []):
                if isinstance(ev, dict) and ev.get("session_id"):
                    sid = ev["session_id"]
                    break
        out.setdefault(sid, []).append(f)
    return out


def _build_cross_mode_report(
    raw: dict,
    *,
    repo_root_override: Optional[Path] = None,
    static_findings_by_repo: Optional[dict] = None,
    vendor_prune: bool = False,
) -> dict:
    """Run cross-mode linker over every session in the saved scan.

    Args:
        raw: parsed forensic scan JSON.
        repo_root_override: if provided, force every session to be
            analyzed against this single repo.
        static_findings_by_repo: optional dict keyed by repo_root
            (str) → list of (rule_id, severity, canonical_class) triples
            from a paired `scan-project` run on that repo. The linker
            consults these alongside the inventory tags.
        vendor_prune: pass through to inventory builder. When True,
            additionally skip benchmarks/, fixtures/, test_data/,
            test_fixtures/ directories and README/CHANGELOG/etc.
            documentation files. Default False — scan everything.

    Returns a dict with:
      - aggregate_records: list of aggregate records, one entry per
        firing of any correlator across all sessions
      - tag_applications: per-finding-id list of tags to apply (e.g.
        `context_demoted`)
      - sessions_processed: count of sessions we actually attempted
      - sessions_unlinkable: count + reasons
      - inventories: per-session resolved repo path + active tags
      - static_findings_used: count of static findings that fed into
        the linker, for diagnostics

    The linker contract is honest about unlinkable sessions; this
    output preserves that honesty for downstream consumers.
    """
    from .cross_mode import (
        build_repo_signal_inventory,
        clear_inventory_cache,
        findings_to_link_input,
        link_signals,
        resolve_session_repo,
    )

    findings_by_session = _findings_by_session(raw.get("findings", []))
    sessions = raw.get("sessions", [])
    static_findings_by_repo = static_findings_by_repo or {}

    # finding_id lookup so tag_applications can resolve from rule_id back
    # to specific finding IDs in the saved bundle. Per the linker
    # contract, tag_applications are keyed by rule_id; the CLI maps to
    # finding_id for the report so users know exactly which finding got
    # demoted.
    findings_by_session_and_rule: dict = {}
    for f in raw.get("findings", []):
        sid = f.get("session_id") or ""
        rid = f.get("rule_id") or ""
        fid = f.get("finding_id") or ""
        findings_by_session_and_rule.setdefault((sid, rid), []).append(fid)

    aggregate_records: list = []
    tag_applications: dict = {}  # finding_id -> list of tags
    inventories_per_session: dict = {}
    unlinkable_reasons: list = []

    # Cache stays warm across sessions in the same repo — common case
    # in monorepos with multiple agent sessions per project.
    clear_inventory_cache()

    for session in sessions:
        sid = session.get("session_id") or ""
        cwd = session.get("cwd")
        repo_root = repo_root_override if repo_root_override else resolve_session_repo(cwd)

        if repo_root is None:
            unlinkable_reasons.append({
                "session_id": sid,
                "reason": "no_repo_resolved",
                "cwd": cwd,
            })
            continue

        inv = build_repo_signal_inventory(repo_root, vendor_prune=vendor_prune)
        if inv is None:
            unlinkable_reasons.append({
                "session_id": sid,
                "reason": "inventory_build_failed",
                "cwd": cwd,
                "repo_root": str(repo_root),
            })
            continue

        inventories_per_session[sid] = {
            "repo_root": str(inv.repo_root),
            "active_tags": inv.active_tags,
        }

        session_findings = findings_by_session.get(sid, [])
        link_input = findings_to_link_input(session_findings)

        # Look up static findings keyed by repo_root. Multiple sessions
        # in the same repo share the same static findings list.
        static_for_repo = static_findings_by_repo.get(str(inv.repo_root), [])

        out = link_signals(
            session_id=sid,
            session_cwd=cwd,
            inventory=inv,
            dynamic_findings=link_input,
            static_findings=static_for_repo,
        )

        for record in out.aggregate_records:
            aggregate_records.append({
                "id": record.id,
                "correlator": record.correlator,
                "canonical_class": record.canonical_class,
                "severity": record.severity,
                "confidence": record.confidence,
                "session_id": record.session_id,
                "repo_root": str(record.repo_root) if record.repo_root else None,
                "supporting_signal_ids": record.supporting_signal_ids,
                "evidence": record.evidence,
                "tags": record.tags,
                "rationale": record.rationale,
            })

        # Map rule_id-keyed tag applications back to finding_ids
        for rule_id, tags in out.tag_applications.items():
            for fid in findings_by_session_and_rule.get((sid, rule_id), []):
                existing = tag_applications.setdefault(fid, [])
                for t in tags:
                    if t not in existing:
                        existing.append(t)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "package_version": __version__,
        "aggregate_records": aggregate_records,
        "tag_applications": tag_applications,
        "sessions_processed": len(sessions) - len(unlinkable_reasons),
        "sessions_total": len(sessions),
        "sessions_unlinkable": unlinkable_reasons,
        "inventories": inventories_per_session,
        "static_findings_provided_for_repos": list(static_findings_by_repo.keys()),
        "static_findings_total": sum(
            len(v) for v in static_findings_by_repo.values()
        ),
    }


def _render_cross_mode_markdown(report: dict) -> str:
    """Human-readable summary of cross-mode results.

    Keep it short — this is supplementary, not a replacement for the
    main forensic bundle.
    """
    lines: list = []
    lines.append("# Cross-mode signal report")
    lines.append("")
    lines.append(f"_Generated: {report['generated_at']}_")
    lines.append(f"_agent-audit {report['package_version']}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Sessions processed: {report['sessions_processed']} / {report['sessions_total']}")
    lines.append(f"- Sessions unlinkable: {len(report['sessions_unlinkable'])}")
    lines.append(f"- Aggregate records produced: {len(report['aggregate_records'])}")
    lines.append(f"- Findings with priority demotion: {len(report['tag_applications'])}")
    lines.append("")

    if not report["aggregate_records"] and not report["tag_applications"]:
        lines.append("_No cross-mode signals fired. This is a normal outcome — most "
                     "sessions don't have static + dynamic correlation. The "
                     "absence of aggregate records is itself information._")
        lines.append("")
        return "\n".join(lines) + "\n"

    if report["aggregate_records"]:
        # Group by correlator for readability
        by_correlator: dict = {}
        for rec in report["aggregate_records"]:
            by_correlator.setdefault(rec["correlator"], []).append(rec)

        lines.append("## Aggregate records (by correlator)")
        lines.append("")
        for correlator, recs in sorted(by_correlator.items()):
            lines.append(f"### `{correlator}` — {len(recs)} record(s)")
            lines.append("")
            for r in recs:
                lines.append(f"- **{r['id']}** "
                             f"severity=`{r['severity']}` "
                             f"confidence=`{r['confidence']}` "
                             f"session=`{r['session_id']}`")
                lines.append(f"    - Class: `{r['canonical_class']}`")
                lines.append(f"    - Supporting: {', '.join(f'`{s}`' for s in r['supporting_signal_ids'])}")
                lines.append(f"    - Rationale: {r['rationale']}")
                lines.append("")

    if report["tag_applications"]:
        lines.append("## Priority demotions")
        lines.append("")
        lines.append("Per D3, severity is preserved; only priority/attention is demoted.")
        lines.append("")
        for fid, tags in sorted(report["tag_applications"].items()):
            lines.append(f"- `{fid}` → tags: {', '.join(f'`{t}`' for t in tags)}")
        lines.append("")

    if report["sessions_unlinkable"]:
        lines.append(f"## Unlinkable sessions ({len(report['sessions_unlinkable'])})")
        lines.append("")
        lines.append("_Per design §6.3 — unlinkable is a normal outcome, not an error._")
        lines.append("")
        # Group by reason
        by_reason: dict = {}
        for u in report["sessions_unlinkable"]:
            by_reason.setdefault(u["reason"], []).append(u)
        for reason, items in sorted(by_reason.items()):
            lines.append(f"- **{reason}**: {len(items)} session(s)")
        lines.append("")

    return "\n".join(lines) + "\n"


def _load_scan_project_bundle(scan_project_path: Path) -> dict:
    """Read a saved scan-project JSON output. Validates minimal shape.

    The file is produced by `agent-audit scan-project --output <dir>`
    and contains a `findings` array plus repo metadata. We accept the
    same lenient shape as the forensic loader — missing optional fields
    are tolerated.
    """
    if not scan_project_path.exists():
        raise click.ClickException(
            f"scan-project bundle not found: {scan_project_path}\n"
            f"Pass the path to a JSON file produced by "
            f"`agent-audit scan-project --output DIR`."
        )
    try:
        raw = json.loads(scan_project_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Could not parse {scan_project_path} as JSON: {exc}"
        )
    if not isinstance(raw, dict):
        raise click.ClickException(
            f"{scan_project_path} does not look like a scan-project report."
        )
    if "findings" not in raw:
        raise click.ClickException(
            f"{scan_project_path} is missing `findings` — does not look "
            f"like a scan-project bundle."
        )
    return raw


def _extract_static_findings_by_repo(
    scan_project_raw: dict,
    *,
    repo_root_override: Optional[Path] = None,
) -> dict:
    """Project a scan-project JSON into the dict shape the cross-mode
    builder expects: {repo_root_str: [(rule_id, severity, canonical_class), ...]}.

    A scan-project run can cover multiple repos (`repos_scanned` field).
    Each finding has a `source_paths` field that points back to the
    file it came from; we use the longest common prefix among those
    paths that matches a `repos_scanned` entry to determine which
    repo the finding belongs to.

    When `repo_root_override` is set, all findings are attributed to
    that single repo path — matches the CLI's repo-root override
    semantics.
    """
    from .cross_mode import static_findings_to_link_input

    findings = scan_project_raw.get("findings") or []
    repos_scanned = scan_project_raw.get("repos_scanned") or []

    triples = static_findings_to_link_input(findings)

    # Map each (rule_id, severity, canonical_class) triple → repo_root
    # by associating it with the original finding's source_paths.
    out: dict = {}

    if repo_root_override is not None:
        # Single-repo override: all findings go to one bucket
        out[str(repo_root_override.resolve())] = triples
        return out

    # Multi-repo case: attribute each finding to its repo via source paths.
    # When a finding's source paths don't match any repo (rare, e.g.
    # config findings from outside a repo), fall back to the first
    # repos_scanned entry; if none, drop the finding from cross-mode.
    triples_by_idx = {idx: t for idx, t in enumerate(triples)}
    for idx, finding in enumerate(findings):
        if idx not in triples_by_idx:
            continue  # adapter dropped it (no rule_id)
        triple = triples_by_idx[idx]
        sources = finding.get("source_paths") or []
        # Find the repo that contains this finding's source paths
        attributed = None
        for repo_str in repos_scanned:
            if any(str(s).startswith(str(repo_str)) for s in sources):
                attributed = str(repo_str)
                break
        if attributed is None and repos_scanned:
            attributed = str(repos_scanned[0])
        if attributed is None:
            continue
        # Resolve to absolute path so it matches what the resolver produces
        try:
            attributed = str(Path(attributed).resolve())
        except (OSError, RuntimeError):
            pass
        out.setdefault(attributed, []).append(triple)

    return out


@main.command("cross-mode")
@click.option(
    "--forensic", "forensic_path", type=click.Path(path_type=Path), required=True,
    help="Path to a saved scan JSON (e.g. audit-2026-04-01-120000.json from `agent-audit scan --output DIR`).",
)
@click.option(
    "--scan-project", "scan_project_path", type=click.Path(path_type=Path),
    default=None,
    help="Optional path to a saved scan-project JSON. When provided, "
         "static findings from the project scan supplement inventory "
         "tags as the static-side condition for correlators. A "
         "rule-pack-confirmed match is a sharper signal than a tag.",
)
@click.option(
    "--repo-root", "repo_root_override", type=click.Path(path_type=Path),
    default=None,
    help="Override repo root resolution. By default, each session's "
         "cwd is used to walk up to a repo marker. Pass a path to force "
         "every session to be analyzed against this single repo.",
)
@click.option(
    "--output", "output_dir", type=click.Path(path_type=Path),
    default=None,
    help="Directory to write cross-mode-findings.json + cross-mode-report.md. "
         "If omitted, results print to stdout only.",
)
@click.option(
    "--format", "output_format", type=click.Choice(["json", "md", "both"]),
    default="both",
    help="When --output is set, choose what files to write.",
)
@click.option(
    "--quiet", is_flag=True, help="Suppress progress output to stdout.",
)
@click.option(
    "--vendor-prune", "vendor_prune", is_flag=True, default=False,
    help="Filter test-fixture and documentation surfaces from the inventory "
         "walk: skip benchmarks/, fixtures/, test_data/, test_fixtures/ "
         "directories AND README.md / CHANGELOG.md / etc. as instruction "
         "surfaces. Off by default — README of a project IS frequently the "
         "agent contract, and benchmarks/ on legitimate projects can carry "
         "real signal. Turn on for security-tooling repos and other "
         "projects whose meta-content trips up tag derivation.",
)
def cross_mode_cmd(
    forensic_path: Path,
    scan_project_path: Optional[Path],
    repo_root_override: Optional[Path],
    output_dir: Optional[Path],
    output_format: str,
    quiet: bool,
    vendor_prune: bool,
) -> None:
    """Run cross-mode signal flow over a saved scan report (M2 Phase 2).

    \b
    USAGE NOTE (v0.18.3+): cross-mode now runs by default as part of
    `agent-audit scan`. This subcommand stays for the rerun-on-saved-bundle
    workflow:
      - Re-run cross-mode against an existing forensic bundle without
        re-scanning agent home
      - Pair with --scan-project to add static-side findings post-hoc
      - Test cross-mode behavior changes (linker tweaks, new correlators)
        against a stable forensic bundle

    \b
    For fresh scans, simply run `agent-audit scan` and look for
    cross-mode-*.json/.md files in the output directory. Use
    `agent-audit scan --no-cross-mode` to opt out.

    \b
    The linker takes findings AS RECORDED in the scan JSON. Per D5,
    those findings have already been filtered against user-config
    suppressions during the original scan; the linker honors that
    filter by not consulting suppression machinery itself.

    \b
    Per D2, aggregate records cap severity at max(component severities).
    No invention; cross-mode support raises priority, not severity.

    \b
    When --scan-project is provided, static findings supplement
    inventory tags. A rule-pack-confirmed match is a SHARPER signal
    than a coarse pattern-derived tag — both can satisfy a correlator's
    static-side condition; both firing produces stronger evidence.
    """
    raw = _load_forensic_bundle(forensic_path)

    if not quiet:
        console.print(f"[dim]Loading scan: {forensic_path}[/dim]")
        n_sessions = len(raw.get("sessions", []))
        n_findings = len(raw.get("findings", []))
        console.print(f"[dim]  {n_sessions} session(s), {n_findings} finding(s)[/dim]")
        if repo_root_override:
            console.print(f"[dim]Repo root override: {repo_root_override}[/dim]")
        if vendor_prune:
            console.print(
                f"[dim]Vendor prune: ON (skipping benchmarks/, fixtures/, "
                f"test_data/, README/CHANGELOG/etc. as instruction surfaces)[/dim]"
            )

    if repo_root_override:
        try:
            repo_root_override = repo_root_override.resolve()
        except (OSError, RuntimeError):
            raise click.ClickException(f"--repo-root path invalid: {repo_root_override}")
        if not repo_root_override.exists():
            raise click.ClickException(f"--repo-root does not exist: {repo_root_override}")

    # Load optional scan-project bundle and project to per-repo static findings
    static_findings_by_repo: Optional[dict] = None
    if scan_project_path:
        sp_raw = _load_scan_project_bundle(scan_project_path)
        static_findings_by_repo = _extract_static_findings_by_repo(
            sp_raw, repo_root_override=repo_root_override,
        )
        if not quiet:
            sp_count = sum(len(v) for v in static_findings_by_repo.values())
            n_repos = len(static_findings_by_repo)
            console.print(f"[dim]Loading scan-project: {scan_project_path}[/dim]")
            console.print(f"[dim]  {sp_count} static finding(s) across {n_repos} repo(s)[/dim]")

    report = _build_cross_mode_report(
        raw,
        repo_root_override=repo_root_override,
        static_findings_by_repo=static_findings_by_repo,
        vendor_prune=vendor_prune,
    )

    # Console summary
    if not quiet:
        console.print()
        console.print(f"[bold]Cross-mode results[/bold]")
        console.print(f"  Sessions processed: {report['sessions_processed']} / {report['sessions_total']}")
        console.print(f"  Aggregate records:  {len(report['aggregate_records'])}")
        console.print(f"  Priority demotions: {len(report['tag_applications'])}")
        console.print(f"  Unlinkable:         {len(report['sessions_unlinkable'])}")
        if report.get("static_findings_total", 0) > 0:
            console.print(
                f"  Static findings fed in: {report['static_findings_total']} "
                f"across {len(report.get('static_findings_provided_for_repos', []))} repo(s)"
            )
        if report["aggregate_records"]:
            console.print()
            console.print("  [bold]By correlator:[/bold]")
            counts: dict = {}
            for rec in report["aggregate_records"]:
                counts[rec["correlator"]] = counts.get(rec["correlator"], 0) + 1
            for correlator, n in sorted(counts.items()):
                console.print(f"    {correlator}: {n}")
        else:
            # v0.19 diagnostic: 0 aggregates on a populated bundle is a
            # *suspicious* outcome, not necessarily a healthy one. Pre-v0.19
            # bug in _findings_by_session caused all findings to land under
            # an empty-string key, so the linker never saw them and we
            # silently produced 0 aggregates on every real bundle. The
            # warning below catches a recurrence of that class of bug —
            # if findings exist and were grouped to specific sessions but
            # NO aggregates fired, the user should know.
            n_findings = len(raw.get("findings", []))
            n_sessions_with_findings = sum(
                1 for sid in (report.get("inventories") or {})
                if any(
                    any(ev.get("session_id") == sid for ev in f.get("evidence", []))
                    for f in raw.get("findings", [])
                )
            )
            if n_findings > 0 and report["sessions_processed"] > 0:
                console.print()
                console.print(
                    f"  [yellow]Note:[/yellow] {n_findings} forensic finding(s) present, "
                    f"{report['sessions_processed']} session(s) had inventories built, "
                    f"but no aggregates fired. Possible explanations: (a) findings "
                    f"genuinely don't co-occur with risk tags on these sessions, "
                    f"(b) inventory tag coverage too narrow for this corpus, "
                    f"(c) bug in finding→session grouping (see v0.18.3 → v0.19 "
                    f"fix history). Re-run with -v to see per-stage timings."
                )

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        if output_format in ("json", "both"):
            json_path = output_dir / "cross-mode-findings.json"
            json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            if not quiet:
                console.print(f"  [green]Wrote:[/green] {json_path}")
        if output_format in ("md", "both"):
            md_path = output_dir / "cross-mode-report.md"
            md_path.write_text(_render_cross_mode_markdown(report), encoding="utf-8")
            if not quiet:
                console.print(f"  [green]Wrote:[/green] {md_path}")


if __name__ == "__main__":
    main()