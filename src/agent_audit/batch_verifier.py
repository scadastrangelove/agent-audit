"""Batch LLM verification via installed agent CLIs.

v0.3 improvements over llm_verifier.py:
  - Batch mode: verify 10-20 findings in a single CLI call (5-10x cheaper)
  - Preflight: probe each CLI with a minimal test before real work
  - Honest errors: parse actual API error status out of CLI JSON output
    (no more mysterious "claude exited 1")
  - No silent fallbacks: user always sees what's working and chooses

v0.7.4 improvements:
  - Parallel batch execution (concurrency=4 by default)
  - Larger default batch size (25) — codex-cli handles 30-50 easily

Architecture uses an abstract VerifierBackend so v0.4+ can add Anthropic API,
OpenAI SDK, Ollama, etc. without changing the orchestration layer.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .audit_log import AuditLog
from .rules import Finding, Severity


# =============================================================================
# Data types
# =============================================================================

@dataclass
class BatchFindingVerdict:
    """Verdict for a single finding inside a batch response."""
    finding_index: int          # index within the batch
    verdict: str                # true_positive | false_positive | uncertain
    adjusted_severity: Optional[Severity]
    rationale: str
    # Source finding is filled in by the caller from the original list


@dataclass
class BatchResult:
    """Result of one batch call (may contain multiple finding verdicts)."""
    verifier: str               # which backend was used
    verdicts: List[BatchFindingVerdict] = field(default_factory=list)
    cost_usd: float = 0.0
    error: Optional[str] = None
    raw_response: str = ""      # kept for debugging


@dataclass
class PreflightResult:
    """Result of a preflight health check for one backend."""
    backend: str
    available: bool
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    hint: Optional[str] = None  # human-readable suggestion if not available


# =============================================================================
# Prompts
# =============================================================================

BATCH_PROMPT = """You are a security auditor reviewing alerts from an AI coding agent's session logs.

Below is a batch of {n} findings. For EACH, decide:
  - verdict: "true_positive" (real concern), "false_positive" (benign), or "uncertain"
  - adjusted_severity: "low" | "medium" | "high" | "critical" (what it really is)
  - rationale: one sentence, max 150 chars

Context to apply:
  - Legitimate workflows: deploy scripts running scp/ssh to *known* user servers, reading local .env files for API keys the user is actively using, writing to their own project's config.
  - Real concerns: writes to .git/hooks, CI configs, or shell init files the user didn't explicitly request; unsolicited scp of private keys; credential reads followed by POSTing data to unknown hosts; writes far outside the project directory.

FINDINGS:
{findings}

Respond STRICTLY as a JSON array. One object per finding in the same order.
Do not include any prose before or after the JSON. Example format:

[
  {{"index": 0, "verdict": "true_positive", "adjusted_severity": "high", "rationale": "..."}},
  {{"index": 1, "verdict": "false_positive", "adjusted_severity": "low", "rationale": "..."}}
]
"""


PREFLIGHT_PROMPT = "Respond with exactly this JSON and nothing else: {\"ok\": true}"


# =============================================================================
# Backend interface
# =============================================================================

class VerifierBackend(ABC):
    """Abstract verifier backend. Subclass to add new providers."""

    name: str = ""  # short identifier, e.g. "claude-cli"

    @abstractmethod
    def available(self) -> bool:
        """Quick check: is this backend installable/usable on this machine?
        Does not make any network calls."""
        ...

    @abstractmethod
    def call(self, prompt: str, timeout: int = 120) -> "RawCallResult":
        """Send a single prompt, return raw result.

        Should NOT raise — wrap exceptions into RawCallResult.error.
        """
        ...


@dataclass
class RawCallResult:
    """Raw output from a backend invocation before parsing."""
    ok: bool
    text: str = ""          # stdout / response body
    cost_usd: float = 0.0   # if backend reports cost
    error: Optional[str] = None
    error_status: Optional[int] = None  # HTTP status if known (403, 429, etc.)
    hint: Optional[str] = None          # actionable hint for the user


# =============================================================================
# Claude Code CLI backend
# =============================================================================

class ClaudeCodeBackend(VerifierBackend):
    name = "claude-cli"

    # v0.7.6: default model is Sonnet — ~2x faster and ~3x cheaper than
    # Opus for our verifier prompts, and verify workload doesn't need
    # Opus-level reasoning. Override via `ClaudeCodeBackend(model=...)`
    # or CLI flag `--claude-model`.
    DEFAULT_MODEL = "sonnet"

    def __init__(
        self,
        proxy: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        """proxy: optional HTTP/HTTPS proxy URL to forward via env vars.

        Example: ClaudeCodeBackend(proxy="http://127.0.0.1:12334")
        This propagates HTTPS_PROXY/HTTP_PROXY to the subprocess — useful
        when Claude CLI doesn't pick up system proxy settings in headless
        mode (e.g. behind regional blocks).

        model: model alias or name to pass via `--model` (e.g. "sonnet",
        "opus", "haiku", or explicit "claude-sonnet-4-5-20250929").
        Defaults to "sonnet" — faster/cheaper than Opus for this workload.
        """
        self.proxy = proxy
        self.model = model or self.DEFAULT_MODEL

    def available(self) -> bool:
        return shutil.which("claude") is not None

    def _subprocess_env(self) -> Optional[Dict[str, str]]:
        """Build env for subprocess. Returns None to inherit parent env."""
        if not self.proxy:
            return None
        import os
        env = dict(os.environ)
        env["HTTPS_PROXY"] = self.proxy
        env["HTTP_PROXY"] = self.proxy
        # lowercase variants are used by some Node HTTP clients
        env["https_proxy"] = self.proxy
        env["http_proxy"] = self.proxy
        return env

    def call(self, prompt: str, timeout: int = 120) -> RawCallResult:
        cmd = [
            "claude", "-p",
            "--output-format", "json",
            "--allowedTools", "",
            "--max-turns", "1",
            "--dangerously-skip-permissions",
            "--model", self.model,
        ]
        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._subprocess_env(),
            )
        except FileNotFoundError:
            return RawCallResult(ok=False, error="claude CLI not found in PATH")
        except subprocess.TimeoutExpired:
            return RawCallResult(ok=False, error=f"timeout after {timeout}s")

        # Claude CLI may return exit 0 even on API errors — the error lives in
        # the JSON body. So we parse first, then check for api_error_status.
        text_out = ""
        cost = 0.0
        api_error: Optional[int] = None
        err_msg: Optional[str] = None
        hint: Optional[str] = None

        try:
            data = json.loads(result.stdout)
            text_out = data.get("result", "") or ""
            cost = float(data.get("total_cost_usd") or 0.0)
            api_error = data.get("api_error_status")
            if api_error:
                err_msg = f"Claude API returned {api_error}: {text_out[:200]}"
                if api_error == 403:
                    hint = (
                        "Possible causes: regional block on api.anthropic.com, "
                        "OAuth session expired (try /login in claude TUI), "
                        "or subscription issue."
                    )
                elif api_error == 401:
                    hint = "Authentication failed. Run `claude /login` to re-authenticate."
                elif api_error == 429:
                    hint = "Rate limit hit. Wait a few minutes or reduce batch size."
            if data.get("is_error") and not err_msg:
                err_msg = f"Claude CLI reported error: {text_out[:200]}"
        except json.JSONDecodeError:
            # Fall through — use raw stdout if available
            text_out = result.stdout

        if result.returncode != 0 and not err_msg:
            stderr_tail = (result.stderr or "").strip()[-200:]
            err_msg = f"claude exited {result.returncode}: {stderr_tail or '(no stderr)'}"

        if err_msg:
            return RawCallResult(
                ok=False,
                text=text_out,
                cost_usd=cost,
                error=err_msg,
                error_status=api_error,
                hint=hint,
            )

        return RawCallResult(ok=True, text=text_out, cost_usd=cost)


# =============================================================================
# Codex CLI backend
# =============================================================================

class CodexCLIBackend(VerifierBackend):
    name = "codex-cli"

    def __init__(self, proxy: Optional[str] = None) -> None:
        self.proxy = proxy

    def available(self) -> bool:
        return shutil.which("codex") is not None

    def _subprocess_env(self) -> Optional[Dict[str, str]]:
        if not self.proxy:
            return None
        env = dict(os.environ)
        env["HTTPS_PROXY"] = self.proxy
        env["HTTP_PROXY"] = self.proxy
        env["https_proxy"] = self.proxy
        env["http_proxy"] = self.proxy
        return env

    def call(self, prompt: str, timeout: int = 120) -> RawCallResult:
        # Codex flag placement changed between versions. Older versions (per
        # alexfazio's v0.114.0 experiment) require GLOBAL flags BEFORE the
        # `exec` subcommand. Newer CLI docs show flags AFTER the subcommand
        # (e.g. `codex exec --oss ...`). We try both.
        #
        # Pass prompt via stdin (`-`) instead of argv:
        # - avoids leaking large evidence payloads in process listings
        # - avoids argv length limits on big verify batches
        # - matches current Codex CLI contract (`codex exec -`)
        variants = [
            # Variant A — global flags first (works on 0.114.0 research preview)
            ["codex", "-a", "never", "--sandbox", "read-only",
             "exec", "--skip-git-repo-check", "-"],
            # Variant B — flags after subcommand (newer docs)
            ["codex", "exec", "--skip-git-repo-check",
             "-a", "never", "--sandbox", "read-only", "-"],
        ]
        last_error = None
        for cmd in variants:
            try:
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=self._subprocess_env(),
                )
            except FileNotFoundError:
                return RawCallResult(
                    ok=False,
                    error="codex CLI not found in PATH",
                    hint="Install with: npm i -g @openai/codex (not the desktop app)",
                )
            except subprocess.TimeoutExpired:
                return RawCallResult(ok=False, error=f"timeout after {timeout}s")

            if result.returncode == 0:
                return RawCallResult(ok=True, text=result.stdout)

            stderr = result.stderr or ""
            # Detect the specific "unexpected argument" / unknown-flag error —
            # means we should try the OTHER flag placement
            if ("unexpected argument" in stderr.lower()
                or "error: unrecognized" in stderr.lower()
                or "tip: to pass" in stderr.lower()):
                last_error = stderr.strip()[-200:]
                continue  # try next variant

            # Real error (auth, etc.) — return immediately, no point trying B
            stderr_tail = stderr.strip()[-200:]
            err = f"codex exited {result.returncode}: {stderr_tail or '(no stderr)'}"
            hint = None
            if "authenticate" in stderr.lower() or "login" in stderr.lower():
                hint = "Run `codex login` to authenticate."
            return RawCallResult(ok=False, error=err, hint=hint)

        # Both variants failed with flag-placement errors
        return RawCallResult(
            ok=False,
            error=f"codex rejects our flag placement in both positions: {last_error}",
            hint="Your codex version may have changed its CLI. Try `codex exec --help` and report the issue.",
        )


# =============================================================================
# Preflight
# =============================================================================

def preflight(backends: List[VerifierBackend]) -> List[PreflightResult]:
    """Probe each backend with a trivial prompt, report availability.

    Each probe costs roughly $0.0005 on paid backends. On failure we include
    the actual error so the user can fix it or choose another backend.
    """
    import time

    results: List[PreflightResult] = []
    for backend in backends:
        if not backend.available():
            results.append(PreflightResult(
                backend=backend.name,
                available=False,
                error="not installed",
                hint=_install_hint(backend.name),
            ))
            continue

        start = time.monotonic()
        timeout = 60 if backend.name == "codex-cli" else 30
        raw = backend.call(PREFLIGHT_PROMPT, timeout=timeout)
        latency = int((time.monotonic() - start) * 1000)

        if raw.ok:
            results.append(PreflightResult(
                backend=backend.name,
                available=True,
                latency_ms=latency,
            ))
        else:
            results.append(PreflightResult(
                backend=backend.name,
                available=False,
                latency_ms=latency,
                error=raw.error,
                hint=raw.hint,
            ))
    return results


def _install_hint(backend_name: str) -> str:
    return {
        "claude-cli": "Install Claude Code: https://claude.com/product/claude-code",
        "codex-cli": "Install Codex CLI: npm i -g @openai/codex (the desktop app won't work)",
    }.get(backend_name, "")


# =============================================================================
# Batch verification
# =============================================================================

DEFAULT_BATCH_SIZE = 25
DEFAULT_CONCURRENCY = 4


def _format_batch_findings(findings: List[Finding]) -> str:
    """Render a list of findings into the batch prompt body."""
    lines = []
    for i, f in enumerate(findings):
        lines.append(f"--- Finding {i} ---")
        lines.append(f"Rule: {f.rule_id}")
        lines.append(f"Original severity: {f.severity.value}")
        lines.append(f"Summary: {f.summary}")
        # Evidence — truncate snippets to keep prompt size bounded
        for ev in f.evidence[:2]:
            if ev.snippet:
                lines.append(f"Evidence: {ev.description}")
                lines.append(f"  > {ev.snippet[:250]}")
            else:
                lines.append(f"Evidence: {ev.description}")
        lines.append("")
    return "\n".join(lines)


def _parse_batch_response(text: str, expected_count: int) -> List[BatchFindingVerdict]:
    """Parse a batch JSON array response into verdict objects.

    Tolerant of markdown fences and surrounding prose — finds the JSON array
    by locating the outermost [ and ].
    """
    text = text.strip()

    # Strip markdown fences
    if text.startswith("```"):
        lines = text.split("\n", 1)
        text = lines[1] if len(lines) > 1 else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]

    # Find outermost JSON array
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end > start:
        text = text[start:end + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    verdicts: List[BatchFindingVerdict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        if not isinstance(idx, int):
            idx = len(verdicts)

        sev_str = str(item.get("adjusted_severity", "")).lower()
        adjusted = None
        if sev_str in ("low", "medium", "high", "critical"):
            adjusted = Severity(sev_str)

        verdicts.append(BatchFindingVerdict(
            finding_index=idx,
            verdict=str(item.get("verdict", "uncertain")),
            adjusted_severity=adjusted,
            rationale=str(item.get("rationale", ""))[:300],
        ))
    return verdicts


def verify_batch(
    findings: List[Finding],
    backend: VerifierBackend,
    *,
    audit_log: Optional[AuditLog] = None,
    timeout: int = 240,
) -> BatchResult:
    """Verify a list of findings in a single call to the backend.

    Returns a BatchResult. If parsing fails or the backend errors, the
    BatchResult.error is set and verdicts may be empty.

    v0.7.6: default timeout bumped from backend's implicit 120s to 240s.
    Under concurrency > 1, slow backends (codex-cli in particular) can
    take longer than 120s per batch on 25-finding prompts. Caller can
    override via the `timeout` param.
    """
    prompt = BATCH_PROMPT.format(
        n=len(findings),
        findings=_format_batch_findings(findings),
    )

    if audit_log:
        audit_log.record(
            "llm_verify_batch_request",
            target=f"{backend.name}:{len(findings)}findings",
            prompt_chars=len(prompt),
        )

    raw = backend.call(prompt, timeout=timeout)

    if not raw.ok:
        if audit_log:
            audit_log.record(
                "llm_verify_batch_response",
                target=backend.name,
                outcome="error",
                error=raw.error,
                error_status=raw.error_status,
            )
        return BatchResult(
            verifier=backend.name,
            error=raw.error,
            raw_response=raw.text,
            cost_usd=raw.cost_usd,
        )

    verdicts = _parse_batch_response(raw.text, expected_count=len(findings))

    if audit_log:
        audit_log.record(
            "llm_verify_batch_response",
            target=backend.name,
            outcome="ok" if verdicts else "warn",
            verdicts_parsed=len(verdicts),
            expected=len(findings),
            cost_usd=raw.cost_usd,
        )

    return BatchResult(
        verifier=backend.name,
        verdicts=verdicts,
        cost_usd=raw.cost_usd,
        raw_response=raw.text,
    )


def verify_all_batched(
    findings: List[Finding],
    backend: VerifierBackend,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    budget_usd: float = 1.0,
    audit_log: Optional[AuditLog] = None,
    on_batch_complete=None,  # optional callback(batch_idx, total_batches, result)
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: int = 240,
) -> List[BatchResult]:
    """Split findings into batches and verify in parallel.

    v0.7.4: runs up to `concurrency` batches simultaneously via a
    ThreadPoolExecutor (CLI calls are I/O-bound — threads work fine).
    Budget check happens after each batch completes — we may slightly
    overshoot by up to `concurrency - 1` batches worth of cost when the
    budget runs out mid-burst, but this is a fair trade for the 4x
    speedup on large runs.

    v0.7.6: `timeout` parameter threaded through to each backend.call —
    per-batch ceiling. Under concurrency=4 on codex-cli, 120s default
    wasn't enough for 25-finding batches; new default is 240s.

    Ordering of the returned list matches input batch order, not
    completion order. Callers can safely rely on positional indexing
    through to Finding source objects.

    Stops submitting new batches if budget_usd is exceeded.
    """
    if not findings:
        return []

    # Pre-split into batches
    all_batches: List[List[Finding]] = [
        findings[i:i + batch_size]
        for i in range(0, len(findings), batch_size)
    ]
    n_batches = len(all_batches)

    # Sequential fallback for concurrency <= 1 (preserves original behavior)
    if concurrency <= 1:
        batches: List[BatchResult] = []
        spent = 0.0
        for i, batch in enumerate(all_batches):
            if spent >= budget_usd:
                break
            result = verify_batch(batch, backend, audit_log=audit_log, timeout=timeout)
            batches.append(result)
            spent += result.cost_usd
            if on_batch_complete:
                on_batch_complete(len(batches), n_batches, result)
        return batches

    # Parallel path
    results_by_idx: Dict[int, BatchResult] = {}
    spent = 0.0
    completed_count = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        # Submit up to `concurrency` initial batches, then refill as each
        # completes. This way if budget runs out we don't keep a big queue.
        pending = {}
        next_to_submit = 0

        def submit_next():
            nonlocal next_to_submit
            if next_to_submit < n_batches and spent < budget_usd:
                idx = next_to_submit
                fut = executor.submit(
                    verify_batch, all_batches[idx], backend,
                    audit_log=audit_log,
                    timeout=timeout,
                )
                pending[fut] = idx
                next_to_submit += 1

        for _ in range(min(concurrency, n_batches)):
            submit_next()

        while pending:
            # Wait for any to complete
            done = next(as_completed(pending))
            idx = pending.pop(done)
            try:
                result = done.result()
            except Exception as exc:
                result = BatchResult(
                    verifier=backend.name,
                    error=f"exception: {exc}",
                )
            results_by_idx[idx] = result
            spent += result.cost_usd
            completed_count += 1
            if on_batch_complete:
                on_batch_complete(completed_count, n_batches, result)
            submit_next()

    # Return in original batch order, omitting trailing None slots if budget
    # caused us to skip tail batches.
    ordered = [results_by_idx[i] for i in sorted(results_by_idx.keys())]
    return ordered


# =============================================================================
# Integrity review (v0.5)
# =============================================================================
#
# Motivated by the ASAMM dual-agent experiment (Claude Sonnet + ChatGPT):
#   > The mandatory self-review step caught real errors in both sessions.
#   > 11 of 13 non-L1 grades were withdrawn after integrity review.
#   > Without it, multiple wrong findings would have appeared as
#   > authoritative conclusions.
#
# The exact phrasing "did not jump to conclusions, either positive or
# negative" was load-bearing — without "either positive or negative" the
# model only catches over-harsh verdicts, not over-credit.

INTEGRITY_REVIEW_PROMPT = """You just produced these verdicts for a batch of security findings. \
Review them from an integrity perspective.

Original findings and your verdicts:
{verdicts_recap}

Review each verdict and check, for each one, whether you:
  1. Did NOT cut corners on evidence ({{verdict}} requires {{evidence}})
  2. Did NOT jump to conclusions — EITHER positive or negative
  3. Applied the context rules from the original prompt correctly
  4. Did not over-credit positive signals (self-report as evidence, etc.)
  5. Did not over-discount real concerns just because context might explain them

For each finding where your original verdict should change, list the index \
and the corrected verdict. Keep rationale under 150 chars per change.

Respond as a STRICT JSON array (same schema as the original verdicts) \
containing ONLY the findings you want to change. Do not include findings \
whose original verdict stands. Empty array means everything was correct:

[
  {{"index": 0, "verdict": "true_positive", "adjusted_severity": "high", "rationale": "was marked FP but evidence shows..."}},
  {{"index": 3, "verdict": "false_positive", "adjusted_severity": "low", "rationale": "context from original prompt explains..."}}
]
"""


def _format_verdicts_recap(
    findings: List[Finding],
    verdicts: List[BatchFindingVerdict],
) -> str:
    """Build a compact recap for the integrity review prompt."""
    lines = []
    # Build index -> verdict map for fast lookup
    by_idx = {v.finding_index: v for v in verdicts}
    for i, f in enumerate(findings):
        v = by_idx.get(i)
        if v:
            sev = v.adjusted_severity.value if v.adjusted_severity else "?"
            lines.append(
                f"[{i}] rule={f.rule_id}  verdict={v.verdict}  "
                f"severity={sev}  rationale={v.rationale[:120]}"
            )
        else:
            lines.append(f"[{i}] rule={f.rule_id}  (no verdict returned)")
    return "\n".join(lines)


def integrity_review(
    findings: List[Finding],
    original_verdicts: List[BatchFindingVerdict],
    backend: VerifierBackend,
    *,
    audit_log: Optional[AuditLog] = None,
    timeout: int = 300,
) -> BatchResult:
    """Ask the verifier to review its own verdicts for over/under-credit.

    Returns a BatchResult whose .verdicts contain ONLY the findings the model
    decided to change. Callers merge these over the original verdicts.

    v0.7.5/v0.7.6: default timeout bumped from 120s (the implicit default
    in backend.call) to 300s. Integrity review prompts are larger than
    primary verify prompts — they include the full findings AND the
    original verdicts — and under concurrent execution on slow backends
    (codex-cli in particular) 120s was hitting timeouts on large batches.
    """
    prompt = INTEGRITY_REVIEW_PROMPT.format(
        verdicts_recap=_format_verdicts_recap(findings, original_verdicts)
    )

    if audit_log:
        audit_log.record(
            "llm_integrity_review_request",
            target=backend.name,
            findings_count=len(findings),
            prompt_chars=len(prompt),
        )

    raw = backend.call(prompt, timeout=timeout)
    if not raw.ok:
        if audit_log:
            audit_log.record(
                "llm_integrity_review_response",
                target=backend.name,
                outcome="error",
                error=raw.error,
            )
        return BatchResult(
            verifier=backend.name,
            error=raw.error,
            raw_response=raw.text,
            cost_usd=raw.cost_usd,
        )

    changes = _parse_batch_response(raw.text, expected_count=len(findings))

    if audit_log:
        audit_log.record(
            "llm_integrity_review_response",
            target=backend.name,
            outcome="ok",
            changes=len(changes),
            cost_usd=raw.cost_usd,
        )

    return BatchResult(
        verifier=backend.name,
        verdicts=changes,
        cost_usd=raw.cost_usd,
        raw_response=raw.text,
    )


# =============================================================================
# Backend discovery
# =============================================================================

def available_backends(
    proxy: Optional[str] = None,
    *,
    claude_model: Optional[str] = None,
) -> List[VerifierBackend]:
    """Return a list of backend instances, regardless of whether they work.

    Use preflight() to check which actually respond. If proxy is provided,
    it will be forwarded via HTTPS_PROXY/HTTP_PROXY env vars to all CLI
    subprocess calls.

    claude_model: optional model alias/name for ClaudeCodeBackend.
    Defaults to "sonnet" (faster/cheaper than Opus).
    """
    return [
        ClaudeCodeBackend(proxy=proxy, model=claude_model),
        CodexCLIBackend(proxy=proxy),
    ]


def default_batch_verifier(proxy: Optional[str] = None) -> Optional[VerifierBackend]:
    """Return the first installed backend, or None if none available.
    Does NOT probe — callers should run preflight() for that."""
    for b in available_backends(proxy=proxy):
        if b.available():
            return b
    return None


# =============================================================================
# BYO API backends (v0.4) — direct HTTP calls, no CLI required
# =============================================================================

# We deliberately don't depend on anthropic/openai SDKs — direct HTTP keeps
# the package dependency-free and works behind any proxy.
import urllib.error
import urllib.request


def _http_post_json(
    url: str,
    payload: dict,
    headers: dict,
    *,
    timeout: int = 120,
    proxy: Optional[str] = None,
) -> tuple[int, str, Optional[str]]:
    """POST JSON, return (http_status, body_text, error_message).

    Uses urllib — no third-party HTTP client required. Supports HTTPS proxy
    via ProxyHandler.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    if proxy:
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy,
            "https": proxy,
        })
        opener = urllib.request.build_opener(proxy_handler)
    else:
        opener = urllib.request.build_opener()

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, None
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        return e.code, body, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return 0, "", f"network error: {e.reason}"
    except TimeoutError:
        return 0, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 0, "", f"unexpected error: {e}"


# Rough cost estimates for budget tracking (USD per call for a ~3k token batch)
# Actual costs vary by provider/model — these are midpoints.
_MODEL_COST_ESTIMATES = {
    # Anthropic (claude-sonnet-4-5 pricing: $3/MTok in, $15/MTok out)
    "claude-sonnet-4-5-20250929": 0.012,
    "claude-opus-4-5": 0.06,
    "claude-haiku-4-5": 0.002,
    # OpenAI
    "gpt-4o": 0.015,
    "gpt-4o-mini": 0.001,
    "gpt-5": 0.030,
    # OpenRouter passthrough — varies
    "default": 0.010,
}


class AnthropicAPIBackend(VerifierBackend):
    """Direct Anthropic API backend using ANTHROPIC_API_KEY env var.

    Use when claude CLI is unavailable (regional block, expired session,
    or running in CI without OAuth).
    """

    name = "anthropic-api"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5-20250929",
        proxy: Optional[str] = None,
        base_url: str = "https://api.anthropic.com",
    ) -> None:
        import os
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.proxy = proxy
        self.base_url = base_url.rstrip("/")

    def available(self) -> bool:
        return bool(self.api_key)

    def call(self, prompt: str, timeout: int = 120) -> RawCallResult:
        if not self.api_key:
            return RawCallResult(
                ok=False,
                error="No API key. Set ANTHROPIC_API_KEY or pass --api-key.",
                hint="Export ANTHROPIC_API_KEY or use --api-key flag.",
            )

        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        status, body, err = _http_post_json(
            f"{self.base_url}/v1/messages",
            payload,
            headers,
            timeout=timeout,
            proxy=self.proxy,
        )

        if err and status == 0:
            return RawCallResult(ok=False, error=err)

        if status != 200:
            # Try to parse error from body
            err_msg = f"Anthropic API {status}"
            hint = None
            try:
                data = json.loads(body)
                api_err = data.get("error") or {}
                err_msg = f"Anthropic API {status}: {api_err.get('message', body[:200])}"
                if status == 401:
                    hint = "Invalid API key. Check ANTHROPIC_API_KEY value."
                elif status == 403:
                    hint = "Key valid but access forbidden. Check org/region restrictions."
                elif status == 429:
                    hint = "Rate limited. Wait a minute or reduce batch size."
                elif status == 529:
                    hint = "API overloaded. Retry in a moment."
            except json.JSONDecodeError:
                pass
            return RawCallResult(ok=False, error=err_msg, error_status=status, hint=hint)

        # Parse successful response
        try:
            data = json.loads(body)
            # content is a list of blocks; concatenate text blocks
            content_blocks = data.get("content") or []
            text = "\n".join(
                b.get("text", "") for b in content_blocks if isinstance(b, dict) and b.get("type") == "text"
            )
            # Approximate cost: we don't have exact usage breakdown in old SDK style,
            # but the response has usage.input_tokens and usage.output_tokens
            usage = data.get("usage") or {}
            in_tok = int(usage.get("input_tokens") or 0)
            out_tok = int(usage.get("output_tokens") or 0)
            cost = self._estimate_cost(in_tok, out_tok)
            return RawCallResult(ok=True, text=text, cost_usd=cost)
        except json.JSONDecodeError as e:
            return RawCallResult(
                ok=False,
                error=f"malformed API response: {e}",
                text=body[:500],
            )

    def _estimate_cost(self, in_tok: int, out_tok: int) -> float:
        # Claude Sonnet 4.5: $3/MTok in, $15/MTok out
        # Opus: $15/$75, Haiku: $0.80/$4
        rates = {
            "sonnet": (3.0, 15.0),
            "opus": (15.0, 75.0),
            "haiku": (0.80, 4.0),
        }
        for key, (rin, rout) in rates.items():
            if key in self.model.lower():
                return (in_tok * rin + out_tok * rout) / 1_000_000
        return (in_tok * 3.0 + out_tok * 15.0) / 1_000_000


class OpenAICompatibleBackend(VerifierBackend):
    """OpenAI-compatible HTTP backend.

    Works with:
      - OpenAI (api.openai.com)
      - OpenRouter (openrouter.ai/api) — good for regions where direct API blocked
      - Ollama (localhost:11434/v1) — fully local, free
      - LM Studio, vLLM, llama.cpp server — any OpenAI-compatible endpoint

    Picks base_url based on the environment variable that's set.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        proxy: Optional[str] = None,
        name_suffix: Optional[str] = None,
    ) -> None:
        import os
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.proxy = proxy
        # name includes provider hint for display
        host = base_url.replace("https://", "").replace("http://", "").split("/")[0]
        self.name = f"openai-compat:{name_suffix or host}"

    def available(self) -> bool:
        # Local endpoints (ollama/lm-studio) don't need an api key
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key)

    def call(self, prompt: str, timeout: int = 120) -> RawCallResult:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,
        }

        status, body, err = _http_post_json(
            f"{self.base_url}/chat/completions",
            payload,
            headers,
            timeout=timeout,
            proxy=self.proxy,
        )

        if err and status == 0:
            hint = None
            if "connection" in err.lower() and ("localhost" in self.base_url or "127.0.0.1" in self.base_url):
                hint = f"Local server not running at {self.base_url}. Start Ollama/LM Studio first."
            return RawCallResult(ok=False, error=err, hint=hint)

        if status != 200:
            err_msg = f"API {status}"
            hint = None
            try:
                data = json.loads(body)
                api_err = data.get("error") or {}
                if isinstance(api_err, dict):
                    err_msg = f"API {status}: {api_err.get('message', body[:200])}"
                if status == 401:
                    hint = "Invalid API key. Check your OPENAI_API_KEY or endpoint."
                elif status == 429:
                    hint = "Rate limited. Wait or reduce batch size."
                elif status == 404:
                    hint = f"Model '{self.model}' not found. Check --model or use one available on your endpoint."
            except json.JSONDecodeError:
                pass
            return RawCallResult(ok=False, error=err_msg, error_status=status, hint=hint)

        try:
            data = json.loads(body)
            choices = data.get("choices") or []
            if not choices:
                return RawCallResult(ok=False, error="empty response from API")
            text = choices[0].get("message", {}).get("content", "")
            # Cost estimation
            usage = data.get("usage") or {}
            in_tok = int(usage.get("prompt_tokens") or 0)
            out_tok = int(usage.get("completion_tokens") or 0)
            cost = self._estimate_cost(in_tok, out_tok)
            return RawCallResult(ok=True, text=text, cost_usd=cost)
        except (json.JSONDecodeError, KeyError) as e:
            return RawCallResult(
                ok=False,
                error=f"malformed API response: {e}",
                text=body[:500],
            )

    def _estimate_cost(self, in_tok: int, out_tok: int) -> float:
        # Rough rates per Mtok
        rates = {
            "gpt-4o-mini": (0.15, 0.60),
            "gpt-4o":      (2.50, 10.0),
            "gpt-5":       (5.0,  20.0),
            "llama":       (0.0,  0.0),   # local
            "qwen":        (0.0,  0.0),
        }
        for key, (rin, rout) in rates.items():
            if key in self.model.lower():
                return (in_tok * rin + out_tok * rout) / 1_000_000
        # Default to mid-tier pricing
        return (in_tok * 1.0 + out_tok * 4.0) / 1_000_000


def build_byo_backends(proxy: Optional[str] = None) -> List[VerifierBackend]:
    """Build BYO backends from environment variables.

    Detection priorities:
      1. ANTHROPIC_API_KEY → AnthropicAPIBackend
      2. OPENAI_API_KEY → OpenAICompatibleBackend at OpenAI's default URL
      3. OPENROUTER_API_KEY → OpenRouter endpoint (good for restricted regions)
      4. Ollama auto-detect at localhost:11434 (no key needed)
    """
    import os
    backends: List[VerifierBackend] = []

    if os.environ.get("ANTHROPIC_API_KEY"):
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
        backends.append(AnthropicAPIBackend(model=model, proxy=proxy))

    if os.environ.get("OPENAI_API_KEY"):
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        backends.append(OpenAICompatibleBackend(
            base_url="https://api.openai.com/v1",
            model=model,
            proxy=proxy,
            name_suffix="openai",
        ))

    if os.environ.get("OPENROUTER_API_KEY"):
        model = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5")
        backends.append(OpenAICompatibleBackend(
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            model=model,
            proxy=proxy,
            name_suffix="openrouter",
        ))

    # Ollama — check if running locally (no key needed)
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.environ.get("OLLAMA_MODEL")
    if ollama_model:
        # Only include if user specified a model — otherwise we'd have to probe /api/tags
        backends.append(OpenAICompatibleBackend(
            api_key=None,
            base_url=f"{ollama_url}/v1",
            model=ollama_model,
            proxy=proxy,
            name_suffix="ollama",
        ))

    # Custom OpenAI-compatible endpoint (LM Studio, vLLM, llama.cpp, etc.)
    custom_url = os.environ.get("AGENT_AUDIT_OPENAI_BASE_URL")
    custom_model = os.environ.get("AGENT_AUDIT_OPENAI_MODEL")
    if custom_url and custom_model:
        backends.append(OpenAICompatibleBackend(
            api_key=os.environ.get("AGENT_AUDIT_OPENAI_API_KEY"),
            base_url=custom_url,
            model=custom_model,
            proxy=proxy,
            name_suffix="custom",
        ))

    return backends


def all_backends(
    proxy: Optional[str] = None,
    *,
    claude_model: Optional[str] = None,
) -> List[VerifierBackend]:
    """Return CLI backends + any BYO backends from environment."""
    return (
        available_backends(proxy=proxy, claude_model=claude_model)
        + build_byo_backends(proxy=proxy)
    )
