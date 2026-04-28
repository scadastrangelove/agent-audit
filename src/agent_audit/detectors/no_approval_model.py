"""No-approval-model detector — native agent-audit rule, not from a rule pack.

Derived from v5 corpus audit + v3 retained finding COM-V3-P1-01
("broad external-action surface without scoping or per-action approval").

This detector produces two finding classes addressing the same ASAMM
control family (AD-02 — Action Surface and Approval Boundaries) but
representing different attack patterns:

  AD-02.broad-action-without-approval  (HIGH)
    Skill declares broad external-action capabilities (send emails,
    post messages, create issues across many services) with no
    approval / scoping / consent language anywhere in the file.
    Paradigm case: ComposioHQ connect-apps SKILL.md.

  AD-02.autonomous-loop-with-writes  (HIGH)
    Skill describes an autonomous loop that performs write actions
    (commit, push, patch code locally) with autonomy language
    dominating over approval language. Paradigm case:
    codex/.codex/skills/babysit-pr SKILL.md.

Unlike text-based ATR rules which fire on documentation mentions of
"send_email", this detector is *absence-based*: it requires both
presence of capability signal AND absence of approval framing.

The detector is precision-tuned — calibrated against 5-target mix to
give 0 false positives on anthropic/skills (10 skills) and
jaktestowac (second-tier negative control).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..knowledge.capability_lexicon import (
    AUTONOMY_LOOP,
    EXTERNAL_REPLY,
    REMOTE_ACTION_SURFACE,
    WRITE_ACTION,
    classify_capabilities,
    first_match,
)
from ..knowledge.markdown_features import extract as extract_md_features
from ..rules import Confidence, Evidence, Finding, Severity


# Files this detector applies to — instruction-bearing files only.
_APPLIES_TO_NAMES = {
    "SKILL.md", "AGENTS.md", "CLAUDE.md", "GEMINI.md",
    "OPENCLAW.md", "COPILOT.md",
}


def applies_to(path: Path) -> bool:
    return path.name in _APPLIES_TO_NAMES


def _snippet_around_match(text: str, match, context: int = 80) -> str:
    import re
    if match is None:
        return ""
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    s = text[start:end].replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return (("…" + s) if start > 0 else s) + (("…") if end < len(text) else "")


@dataclass
class ApprovalFinding:
    """Intermediate representation."""
    rule_id: str
    severity: Severity
    title: str
    summary: str
    file: Path
    snippet: str
    details: dict


def check_file(
    path: Path,
    text: Optional[str] = None,
    bypass_applies_to: bool = False,
) -> List[ApprovalFinding]:
    """Classify a file and emit zero, one, or two findings (one per class).

    v0.12: uses AST-filtered prose (code fences removed) when
    markdown-it-py is available. Falls back to raw text otherwise.
    Rationale — approval/action language in code fences (variable names
    like `confirm`, `approve`, comments about `send_email`) is usually
    documentation-style, not a behavior signal for this detector.

    v0.14.4 (D-9): when bypass_applies_to=True and text is supplied
    directly, skip the file-name gate. Used by project_scanner when an
    agent-task YAML has already been identified and prompt text extracted.
    """
    if not bypass_applies_to and not applies_to(path):
        return []
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

    # AST prefilter — classify on prose, keep snippet references to raw text
    features = extract_md_features(text)
    analysis_text = features.text_without_code if features.ast_available else text
    prof = classify_capabilities(analysis_text)
    findings: List[ApprovalFinding] = []

    # Class 1: broad external action surface with no approval framing
    if prof["broad_action_without_approval"]:
        m = first_match(REMOTE_ACTION_SURFACE, analysis_text)
        findings.append(ApprovalFinding(
            rule_id="asamm.AD-02.broad-action-without-approval",
            severity=Severity.HIGH,
            title="Broad external-action surface without approval model",
            summary=(
                f"Skill declares broad external-action capabilities "
                f"(remote_action phrases total={prof['remote_action_surface_total']}, "
                f"external_reply={prof['external_reply_distinct']}, "
                f"write_action={prof['write_action_distinct']}) with no "
                f"approval / scoping / consent language in the same file. "
                f"Actions will execute without per-action user confirmation."
            ),
            file=path,
            snippet=_snippet_around_match(analysis_text, m),
            details=prof,
        ))

    # Class 2: autonomous loop with writes, autonomy dominates approval
    if prof["autonomous_loop_with_writes"]:
        m = first_match(AUTONOMY_LOOP, analysis_text)
        ratio = (prof["autonomy_loop_total"] /
                 max(1, prof["approval_marker_total"]))
        findings.append(ApprovalFinding(
            rule_id="asamm.AD-02.autonomous-loop-with-writes",
            severity=Severity.HIGH,
            title="Autonomous loop performs write actions with weak approval framing",
            summary=(
                f"Skill describes continuous/automatic loop "
                f"(autonomy markers={prof['autonomy_loop_distinct']} "
                f"distinct, {prof['autonomy_loop_total']} total) that "
                f"performs write actions (commit/push/patch, "
                f"{prof['write_action_distinct']} distinct). "
                f"Autonomy framing dominates approval framing "
                f"({ratio:.1f}:1 ratio). Review stop conditions and "
                f"per-write confirmation gates."
            ),
            file=path,
            snippet=_snippet_around_match(analysis_text, m),
            details=prof,
        ))

    return findings


def convert_to_finding(f: ApprovalFinding) -> Finding:
    """Convert ApprovalFinding to the main Finding type."""
    refs = [
        "ASAMM:AD-02",
        "ASAMM:AI-03",  # excessive agency secondary
        "source:agent-audit-native",
        "derived-from:v3-retained-COM-V3-P1-01",
        "derived-from:v5-lexicon-v2",
        "owasp_agentic:ASI03 - Identity and Privilege Abuse",
        "owasp_agentic:ASI06 - Excessive Agency",
    ]
    return Finding(
        rule_id=f.rule_id,
        title=f.title,
        severity=f.severity,
        confidence=Confidence.MEDIUM,
        summary=f.summary,
        evidence=[Evidence(
            description=(
                f"ras_total={f.details['remote_action_surface_total']} "
                f"autonomy_dist={f.details['autonomy_loop_distinct']} "
                f"write_dist={f.details['write_action_distinct']} "
                f"extrep_dist={f.details['external_reply_distinct']} "
                f"appr={f.details['approval_marker_distinct']}"
            ),
            source=f.file,
            snippet=f.snippet,
        )],
        remediation=(
            "Add explicit per-action approval, scope narrowing, or "
            "deny-by-default semantics. Examples: prompt user before each "
            "write, document a dry-run mode, declare allowed action scopes, "
            "add stop conditions for autonomous loops. If this is a "
            "deliberately high-autonomy tool, document the undo path and "
            "consent model in the SKILL.md header."
        ),
        references=refs,
        needs_llm_verification=True,
    )
