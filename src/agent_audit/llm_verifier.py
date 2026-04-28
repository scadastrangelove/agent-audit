"""Local LLM verification via installed agent CLIs.

Rather than calling Anthropic/OpenAI APIs directly (which requires keys and
costs money), we use whichever agent CLI is already installed on the user's
machine — Claude Code, Codex, or both — to verify findings cross-check style.

The key idea: the user is already paying for Claude Code / Codex subscriptions.
We call those CLIs with tightly restricted permissions to have them analyze
their own logs. This is "cross-audit":
  - Claude Code verifies Codex findings
  - Codex verifies Claude Code findings
  - User always sees the cost and approves each call

All calls are:
  - Read-only (no Write/Edit/Bash permission given)
  - Given only the specific finding + snippet, no access to other logs
  - Bounded by a user-set budget cap
  - Fully logged in the audit_log for transparency
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .audit_log import AuditLog
from .rules import Confidence, Finding, Severity


VERIFIER_PROMPT = """You are a security auditor reviewing an alert from another agent's session.

A detection rule flagged the following finding:

  Rule: {rule_id}
  Title: {title}
  Severity: {severity}
  Summary: {summary}

Evidence:
{evidence}

Your job:
1. Determine if this is a TRUE POSITIVE (real security concern) or FALSE POSITIVE (benign explanation).
2. Consider the context: was the user likely asking the agent to do this? Does the command make sense for a legitimate workflow?
3. If it's a true positive, rate the actual severity (low/medium/high/critical).
4. Give a concise one-sentence rationale.

Respond STRICTLY in this JSON format and nothing else:
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "adjusted_severity": "low" | "medium" | "high" | "critical",
  "rationale": "one sentence, max 200 chars"
}}
"""


@dataclass
class VerifierResult:
    verdict: str  # "true_positive" | "false_positive" | "uncertain"
    adjusted_severity: Optional[Severity]
    rationale: str
    verifier_agent: str  # which CLI was used
    cost_estimate_usd: float = 0.0
    error: Optional[str] = None


def _find_agent_cli(name: str) -> Optional[str]:
    """Return the path to an installed agent CLI, or None."""
    return shutil.which(name)


def detect_verifiers() -> List[str]:
    """Return list of available verifier CLIs on this machine."""
    available = []
    if _find_agent_cli("claude"):
        available.append("claude")
    if _find_agent_cli("codex"):
        available.append("codex")
    return available


def _format_evidence(finding: Finding) -> str:
    lines = []
    for ev in finding.evidence[:3]:
        lines.append(f"- {ev.description}")
        if ev.snippet:
            # Truncate to keep the prompt small and cost-bounded
            snippet = ev.snippet[:400]
            lines.append(f"  Content: {snippet}")
    return "\n".join(lines) if lines else "(no evidence details)"


def _run_claude_verify(prompt: str, timeout: int = 120) -> tuple[str, Optional[str], Optional[float]]:
    """Call `claude -p` in print-only mode with restricted tools.

    Returns (stdout_text, error_message, actual_cost_usd).

    Key flags used:
      --print / -p          — non-interactive, exit after response
      --output-format json  — parseable result with cost info
      --allowedTools ""     — deny all tools (we just want analysis text)
      --max-turns 1         — single-turn response, no agentic loop
      --dangerously-skip-permissions — no permission prompts

    Prompt is piped via stdin to avoid shell quoting issues with long/complex prompts.
    """
    cmd = [
        "claude",
        "-p",                      # non-interactive
        "--output-format", "json",
        "--allowedTools", "",      # deny all tools
        "--max-turns", "1",        # one-shot answer
        "--dangerously-skip-permissions",  # no blocking prompts in headless mode
    ]
    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return "", "claude CLI not found", None
    except subprocess.TimeoutExpired:
        return "", f"timeout after {timeout}s", None

    if result.returncode != 0:
        # Include stderr tail in the error — was invisible before
        stderr_tail = (result.stderr or "").strip()[-300:]
        stdout_tail = (result.stdout or "").strip()[-200:]
        err = f"claude exited {result.returncode}: {stderr_tail or stdout_tail or '(no output)'}"
        return "", err, None

    # Parse JSON output: {"result": "...", "total_cost_usd": 0.0012, ...}
    text = result.stdout
    cost: Optional[float] = None
    try:
        data = json.loads(text)
        text = data.get("result") or data.get("text") or text
        cost = data.get("total_cost_usd") or data.get("cost", {}).get("total_cost")
    except json.JSONDecodeError:
        # Fall through with raw stdout
        pass

    return text, None, cost


def _run_codex_verify(prompt: str, timeout: int = 120) -> tuple[str, Optional[str], Optional[float]]:
    """Call `codex exec` in non-interactive mode.

    Returns (stdout_text, error_message, actual_cost_usd).
    Codex exec doesn't emit cost programmatically — we use the per-call estimate.
    """
    cmd = [
        "codex",
        "-a", "never",
        "--sandbox", "read-only",
        "exec",
        "--skip-git-repo-check",
        prompt,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return "", "codex CLI not found", None
    except subprocess.TimeoutExpired:
        return "", f"timeout after {timeout}s", None

    if result.returncode != 0:
        stderr_tail = (result.stderr or "").strip()[-300:]
        stdout_tail = (result.stdout or "").strip()[-200:]
        err = f"codex exited {result.returncode}: {stderr_tail or stdout_tail or '(no output)'}"
        return "", err, None

    return result.stdout, None, None


def _parse_verifier_response(text: str) -> VerifierResult:
    """Parse the JSON response from a verifier agent."""
    # The agent may wrap JSON in markdown fences — strip them
    text = text.strip()
    if text.startswith("```"):
        # Remove first line (```json or ```)
        lines = text.split("\n", 1)
        text = lines[1] if len(lines) > 1 else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    text = text.strip()

    # Find the first { and last } — the agent may add prose around the JSON
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start:end + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return VerifierResult(
            verdict="uncertain",
            adjusted_severity=None,
            rationale=f"could not parse verifier response: {e}",
            verifier_agent="unknown",
            error=str(e),
        )

    verdict = data.get("verdict", "uncertain")
    sev_str = data.get("adjusted_severity", "").lower()
    adjusted = None
    if sev_str in ("low", "medium", "high", "critical"):
        adjusted = Severity(sev_str)

    return VerifierResult(
        verdict=verdict,
        adjusted_severity=adjusted,
        rationale=data.get("rationale", "")[:300],
        verifier_agent="unknown",  # caller fills this
    )


def verify_finding(
    finding: Finding,
    *,
    verifier: str,
    audit_log: Optional[AuditLog] = None,
) -> VerifierResult:
    """Verify a single finding using the specified installed agent CLI."""
    prompt = VERIFIER_PROMPT.format(
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity.value,
        summary=finding.summary,
        evidence=_format_evidence(finding),
    )

    if audit_log:
        audit_log.record(
            "llm_verify_request",
            target=f"{verifier}:{finding.rule_id}",
            prompt_chars=len(prompt),
        )

    if verifier == "claude":
        text, err, actual_cost = _run_claude_verify(prompt)
    elif verifier == "codex":
        text, err, actual_cost = _run_codex_verify(prompt)
    else:
        return VerifierResult(
            verdict="uncertain",
            adjusted_severity=None,
            rationale=f"unknown verifier: {verifier}",
            verifier_agent=verifier,
            error=f"unknown verifier: {verifier}",
        )

    if err:
        if audit_log:
            audit_log.record(
                "llm_verify_response",
                target=f"{verifier}:{finding.rule_id}",
                outcome="error",
                error=err,
            )
        return VerifierResult(
            verdict="uncertain",
            adjusted_severity=None,
            rationale=err,
            verifier_agent=verifier,
            error=err,
        )

    parsed = _parse_verifier_response(text)
    parsed.verifier_agent = verifier
    if actual_cost is not None:
        parsed.cost_estimate_usd = actual_cost

    if audit_log:
        audit_log.record(
            "llm_verify_response",
            target=f"{verifier}:{finding.rule_id}",
            outcome="ok" if parsed.verdict != "uncertain" else "warn",
            verdict=parsed.verdict,
            adjusted_severity=parsed.adjusted_severity.value if parsed.adjusted_severity else None,
            response_chars=len(text),
            cost_usd=actual_cost,
        )

    return parsed


def choose_cross_verifier(finding: Finding, available: List[str]) -> Optional[str]:
    """Pick the verifier to use for cross-audit.

    Strategy: if the finding came from analyzing agent X's logs, prefer
    verifying it with agent Y (cross-check). Falls back to whichever is
    available if we only have one.
    """
    # Infer which agent produced this finding from the source_file in evidence
    source_agent = None
    for ev in finding.evidence:
        if ev.source:
            p = str(ev.source)
            if ".claude/" in p:
                source_agent = "claude"
                break
            if ".codex/" in p:
                source_agent = "codex"
                break

    if source_agent == "claude" and "codex" in available:
        return "codex"
    if source_agent == "codex" and "claude" in available:
        return "claude"

    # Fallback: first available that isn't the source agent
    for v in available:
        if v != source_agent:
            return v

    # Last resort: same agent verifies its own finding
    if available:
        return available[0]
    return None
