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
    type=click.Choice(["all", "atr", "aguara", "cisco-promptguard"]),
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
def scan_project_cmd(path: Path, output: Optional[Path], tool: str, min_severity: str, yes: bool, no_aggregate: bool) -> None:
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
        project_json = build_project_json(abs_path, result, kept, rerank_result)
        project_json["native_summary"] = native_summary_dict(rerank_result)
        json_out.write_text(json.dumps(project_json, indent=2, default=str))

        # Markdown — native-first rendering with profile summary
        md_out = output / "project-findings.md"
        md_out.write_text(
            render_project_markdown(abs_path, result, min_severity, kept, rerank_result)
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


if __name__ == "__main__":
    main()
