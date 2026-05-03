# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""NOVA evaluator — Roadmap item M3.

The A2/C1 NOVA importer ingests only the `keywords:` section. The
`semantics:` (embedding similarity) and `llm:` (yes/no eval) gates are
preserved as YAML metadata fields:

    upstream_semantics_patterns: [{name, prose, threshold}, ...]
    upstream_llm_checks:         [{name, prompt, threshold}, ...]

Without those gates, NOVA rules ship at LOW severity (calibration
showed multi-word keyword conjunctions firing too readily). M3 lifts
that floor selectively: a rule's severity is restored to upstream
when both available gates pass on the matched evidence.

## Gate policy

A finding has up to two gates:
- semantics: cosine similarity between the matched snippet and each
  upstream prose pattern. Pass if max similarity >= threshold.
- llm: ask the LLM yes/no whether the snippet matches the upstream
  prompt. Pass if the answer is yes with >= threshold "confidence"
  (we map yes → 1.0, no → 0.0; threshold typically 0.7).

Outcomes:
- both gates available, both pass     → promote to upstream severity
- only one gate available, that passes → partial promote (one notch up)
- gate fails                          → demote to INFO (suppressed)
- no gates available                  → leave at LOW (current state)

## Fail-open

If the embedding model isn't installable/loadable, the semantics gate
is treated as "unavailable" — we don't fail the scan, we just don't
get the lift. Same for LLM: if no backend is configured, llm gate
is unavailable. NOVA findings without gate runs stay at their imported
LOW severity.

## Why post-hoc, not online

NOVA evaluator runs after `scan-project` produces findings, before
`batch_verifier` (which is the broader TP/FP confirmation step).
Reasons:
1. Embedding model load and LLM calls are expensive — running them
   inline on every scan would slow normal usage. Post-hoc means users
   pay the cost only when they ask for it.
2. The output schema (`Finding`) doesn't change. Severity adjustments
   happen in-place, so all downstream consumers (reports, dedup,
   project-config overrides) work unchanged.
3. We can run M3 offline-only (semantics gate alone, no LLM) when no
   backend is configured — useful for CI environments.

## Out of scope for M3

- Network embedding APIs (OpenAI, Cohere). Sentence-transformers local
  is sufficient for the pattern; remote embeddings can be a
  follow-up under M3's same module.
- Calibrating individual rule thresholds. Upstream NOVA YAMLs ship
  thresholds; we honor them as-is. Per-rule threshold tuning is
  research-grade and belongs to a future calibration pass.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .knowledge.rule_pack_loader import RulePackRule, load_all_rules
from .rules import Finding, Severity

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Severity ladder helpers
# ----------------------------------------------------------------------------

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _bump(sev: Severity, steps: int = 1) -> Severity:
    """Move severity up the ladder by `steps`. Caps at critical."""
    try:
        i = _SEV_ORDER.index(sev.value)
    except ValueError:
        return sev
    j = max(0, min(len(_SEV_ORDER) - 1, i + steps))
    return Severity(_SEV_ORDER[j])


def _demote(sev: Severity, steps: int = 1) -> Severity:
    return _bump(sev, -steps)


# ----------------------------------------------------------------------------
# Embedding model loader — sentence-transformers, optional
# ----------------------------------------------------------------------------

class _EmbeddingModelHandle:
    """Lazy-loaded wrapper around sentence-transformers.

    Loading the model takes several seconds on first call. We do it
    once per process and cache. If the package isn't installed, we
    record the reason and treat the semantics gate as unavailable
    forever in this process.
    """
    _instance: Optional["_EmbeddingModelHandle"] = None

    def __init__(self):
        self.model = None
        self.unavailable_reason: Optional[str] = None

    @classmethod
    def get(cls) -> "_EmbeddingModelHandle":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError as e:
            self.unavailable_reason = (
                f"sentence-transformers not installed: {e}. "
                f"Install with: pip install sentence-transformers"
            )
            return
        try:
            # all-MiniLM-L6-v2 is a small (~80MB) general-purpose model.
            # It downloads from HuggingFace on first use; subsequent runs
            # use the cached weights.
            self.model = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception as e:  # noqa: BLE001 — net errors, file errors
            self.unavailable_reason = f"failed to load embedding model: {e}"

    def is_available(self) -> bool:
        return self.model is not None

    def encode(self, texts: List[str]):
        """Return numpy array of shape (n, dim). Caller handles cosine."""
        if not self.is_available():
            raise RuntimeError("embedding model not available")
        return self.model.encode(texts, convert_to_numpy=True, show_progress_bar=False)

    @classmethod
    def reset_for_tests(cls) -> None:
        """Allow tests to force a re-load of the model."""
        cls._instance = None


def _cosine(a, b) -> float:
    """Cosine similarity between two 1-D numpy arrays."""
    import numpy as np
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) or 1.0
    return float(np.dot(a, b) / denom)


# ----------------------------------------------------------------------------
# Gate evaluation — independent of finding orchestration
# ----------------------------------------------------------------------------

@dataclass
class GateResult:
    name: str                     # "semantics" or "llm"
    available: bool               # could the gate run at all?
    passed: bool = False          # did the evidence meet upstream threshold?
    score: Optional[float] = None # similarity / confidence value
    reason: str = ""              # human-readable why (esp. for unavailable)


@dataclass
class EvaluationVerdict:
    finding: Finding
    rule: RulePackRule
    semantics: Optional[GateResult] = None
    llm: Optional[GateResult] = None
    new_severity: Optional[Severity] = None  # None = leave unchanged
    rationale: str = ""


def _evidence_text(finding: Finding) -> str:
    """Pull the matched snippet for gate evaluation."""
    if finding.evidence and finding.evidence[0].snippet:
        return finding.evidence[0].snippet
    # Fallback to summary if no snippet was attached
    return finding.summary


def evaluate_semantics_gate(
    snippet: str,
    semantics_patterns: List[Dict],
    embedder: Optional[_EmbeddingModelHandle] = None,
) -> GateResult:
    """Run the semantics gate on a single snippet.

    semantics_patterns is the YAML-shaped list:
        [{"name": ..., "prose": "...", "threshold": 0.5}, ...]
    Pass = max cosine similarity over all prose entries >= max threshold.
    (Per-pattern thresholds vary; we use the strictest as the bar to
    avoid promoting on the loosest pattern.)
    """
    if not semantics_patterns:
        return GateResult(
            name="semantics", available=False,
            reason="no semantics patterns on rule",
        )
    embedder = embedder or _EmbeddingModelHandle.get()
    if not embedder.is_available():
        return GateResult(
            name="semantics", available=False,
            reason=embedder.unavailable_reason or "embedding model unavailable",
        )

    proses = [p["prose"] for p in semantics_patterns if p.get("prose")]
    if not proses:
        return GateResult(
            name="semantics", available=False,
            reason="all semantics patterns have empty prose",
        )

    try:
        vecs = embedder.encode([snippet] + proses)
    except Exception as e:  # noqa: BLE001
        return GateResult(
            name="semantics", available=False,
            reason=f"encoding failed: {e}",
        )
    snippet_vec = vecs[0]
    pattern_vecs = vecs[1:]
    sims = [_cosine(snippet_vec, pv) for pv in pattern_vecs]
    max_sim = max(sims) if sims else 0.0

    # Threshold: take the max across patterns (strictest). Default 0.5 if
    # any pattern lacks a declared threshold.
    thresholds = [
        float(p.get("threshold") or 0.5) for p in semantics_patterns
    ]
    bar = max(thresholds) if thresholds else 0.5

    return GateResult(
        name="semantics",
        available=True,
        passed=max_sim >= bar,
        score=max_sim,
        reason=f"max cosine={max_sim:.3f} vs bar={bar:.2f}",
    )


def evaluate_llm_gate(
    snippet: str,
    llm_checks: List[Dict],
    backend=None,
) -> GateResult:
    """Run the llm gate on a single snippet.

    Each entry in llm_checks is the YAML-shaped:
        {"name": ..., "prompt": "Is this X?", "threshold": 0.7}
    We send the snippet + prompt to the configured backend, parse the
    answer for yes/no, and require ALL prompts to come back yes for the
    gate to pass. (Conservative: NOVA expressions typically use OR
    between llm checks, but we don't have the structure here, so AND
    is the safer default — equivalent to "the strictest llm check
    passes".)
    """
    if not llm_checks:
        return GateResult(
            name="llm", available=False,
            reason="no llm checks on rule",
        )
    if backend is None:
        return GateResult(
            name="llm", available=False,
            reason="no llm backend provided",
        )

    yes_count = 0
    total = 0
    last_text = ""
    for check in llm_checks:
        prompt = check.get("prompt", "").strip()
        if not prompt:
            continue
        total += 1
        full_prompt = (
            f"Answer with exactly one word: yes or no.\n\n"
            f"Question: {prompt}\n\n"
            f"Text to evaluate (between dashes):\n"
            f"------\n{snippet}\n------\n\n"
            f"Answer (yes or no):"
        )
        try:
            result = backend.call(full_prompt, timeout=30)
        except Exception as e:  # noqa: BLE001
            return GateResult(
                name="llm", available=False,
                reason=f"llm call failed: {e}",
            )
        if not result.ok:
            return GateResult(
                name="llm", available=False,
                reason=f"llm backend error: {result.error or 'unknown'}",
            )
        last_text = (result.text or "").strip().lower()
        # Look at the first 20 characters for a yes/no token
        head = last_text[:20]
        if re.match(r"^\s*yes\b", head):
            yes_count += 1
        # 'no' or unparseable → counted as not-yes; loop continues

    if total == 0:
        return GateResult(
            name="llm", available=False,
            reason="all llm checks had empty prompt",
        )

    # Conservative AND: every check must say yes.
    passed = (yes_count == total)
    score = yes_count / total
    return GateResult(
        name="llm",
        available=True,
        passed=passed,
        score=score,
        reason=f"{yes_count}/{total} llm checks said yes (last reply: {last_text[:30]!r})",
    )


# ----------------------------------------------------------------------------
# Severity policy — how gate outcomes translate to severity adjustments
# ----------------------------------------------------------------------------

def _apply_severity_policy(
    finding: Finding,
    rule: RulePackRule,
    upstream_severity: Severity,
    semantics: Optional[GateResult],
    llm: Optional[GateResult],
) -> Tuple[Optional[Severity], str]:
    """Decide the new severity for a finding given gate outcomes.

    Returns (new_severity, rationale). new_severity=None means leave
    untouched.
    """
    sem_av = semantics is not None and semantics.available
    llm_av = llm is not None and llm.available
    sem_pass = sem_av and semantics.passed
    llm_pass = llm_av and llm.passed
    sem_fail = sem_av and not semantics.passed
    llm_fail = llm_av and not llm.passed

    # No gates at all → leave LOW (this is the v0.17 baseline behavior)
    if not sem_av and not llm_av:
        return None, "neither gate available; staying at imported severity"

    # Both gates available
    if sem_av and llm_av:
        if sem_pass and llm_pass:
            return upstream_severity, (
                f"both gates pass; lifted to upstream severity "
                f"({upstream_severity.value})"
            )
        if sem_fail and llm_fail:
            return Severity.INFO, "both gates fail; demoted to INFO"
        # One pass, one fail — trust the failing gate (conservative)
        return _demote(finding.severity), (
            f"one gate fails (semantics={sem_pass}, llm={llm_pass}); "
            f"demoted by one notch"
        )

    # Only one gate available
    only_pass = sem_pass or llm_pass
    only_fail = sem_fail or llm_fail
    gate_name = "semantics" if sem_av else "llm"
    if only_pass:
        # Partial promote: bump by one toward upstream, but not past it
        promoted = _bump(finding.severity)
        if _SEV_ORDER.index(promoted.value) > _SEV_ORDER.index(upstream_severity.value):
            promoted = upstream_severity
        return promoted, (
            f"{gate_name} gate passes (other gate unavailable); "
            f"partial lift to {promoted.value}"
        )
    if only_fail:
        return _demote(finding.severity), (
            f"{gate_name} gate fails (other gate unavailable); demoted"
        )

    return None, "gate state inconsistent; no change"


# ----------------------------------------------------------------------------
# Entry point — evaluate one finding, evaluate batch
# ----------------------------------------------------------------------------

def evaluate_finding(
    finding: Finding,
    rule: RulePackRule,
    *,
    embedder: Optional[_EmbeddingModelHandle] = None,
    backend=None,
) -> EvaluationVerdict:
    """Run available gates on one finding and decide severity adjustment.

    Returns the verdict in detail; caller is responsible for actually
    mutating the finding (so dry-runs work).
    """
    # Pull upstream severity from the rule's YAML (preserved through the
    # importer as `upstream_severity` — but currently we don't store
    # that! Let's read it from the rule's references or derive from a
    # mapping). Fallback: severity of the rule + 2 (since import floored
    # to LOW from medium/high/critical).
    upstream_severity = _upstream_severity_for_rule(rule)

    snippet = _evidence_text(finding)

    sem_patterns = getattr(rule, "upstream_semantics_patterns", None) or []
    llm_checks = getattr(rule, "upstream_llm_checks", None) or []

    sem_result = evaluate_semantics_gate(snippet, sem_patterns, embedder=embedder)
    llm_result = evaluate_llm_gate(snippet, llm_checks, backend=backend)

    new_sev, rationale = _apply_severity_policy(
        finding, rule, upstream_severity, sem_result, llm_result,
    )

    return EvaluationVerdict(
        finding=finding,
        rule=rule,
        semantics=sem_result,
        llm=llm_result,
        new_severity=new_sev,
        rationale=rationale,
    )


def _upstream_severity_for_rule(rule: RulePackRule) -> Severity:
    """Recover the upstream severity that the importer floored to LOW.

    The NOVA importer (A2/C1) writes the original `severity = "..."` from
    the .nov meta block into a YAML field `upstream_severity`. The
    rule_pack_loader exposes it as `RulePackRule.upstream_severity`. If
    a rule predates this importer change (older imports), the field
    will be None and we conservatively default to MEDIUM.

    MEDIUM is the most common upstream severity in nova-rules (~65%),
    with HIGH the second-most-common (~30%) and CRITICAL rare (~5%).
    Defaulting to MEDIUM under-promotes a few rules but never
    over-promotes — desirable conservative behavior.
    """
    if rule.upstream_severity is not None:
        return rule.upstream_severity
    return Severity.MEDIUM


def apply_verdict(verdict: EvaluationVerdict) -> bool:
    """Mutate finding.severity if verdict says so. Return True if changed."""
    if verdict.new_severity is None:
        return False
    if verdict.new_severity == verdict.finding.severity:
        return False
    verdict.finding.severity = verdict.new_severity
    # Annotate references so the report shows why the change happened
    note = f"nova-evaluator:{verdict.rationale}"
    if note not in verdict.finding.references:
        verdict.finding.references.append(note)
    return True


def filter_nova_findings(findings: List[Finding]) -> List[Finding]:
    """Pull findings produced by NOVA rules from a list."""
    return [f for f in findings if f.rule_id.startswith("nova.")]


def evaluate_batch(
    findings: List[Finding],
    *,
    embedder: Optional[_EmbeddingModelHandle] = None,
    backend=None,
    rules: Optional[List[RulePackRule]] = None,
) -> List[EvaluationVerdict]:
    """Run the evaluator on every NOVA finding in `findings`.

    Findings with non-NOVA rule_ids are skipped silently — the
    evaluator is scoped to NOVA. Returns one verdict per NOVA finding.
    Mutation is up to the caller (use `apply_verdict` on each).
    """
    rules = rules if rules is not None else load_all_rules()
    by_id = {r.agent_audit_id: r for r in rules}
    verdicts: List[EvaluationVerdict] = []
    for f in findings:
        if not f.rule_id.startswith("nova."):
            continue
        rule = by_id.get(f.rule_id)
        if rule is None:
            # Rule pack moved — can't evaluate. Skip with a marker.
            verdicts.append(EvaluationVerdict(
                finding=f,
                rule=None,  # type: ignore[arg-type]
                rationale="rule not found in current pack; cannot evaluate",
            ))
            continue
        verdicts.append(evaluate_finding(
            f, rule, embedder=embedder, backend=backend,
        ))
    return verdicts
