"""Identity redefinition detector — native agent-audit rule, not from a rule pack.

Derived from v5 corpus audit (100 repos, 60 identity_redefinition hits across
13 repos). Produces two finding classes:

  AI-04.persistent-identity-rewrite  (HIGH / CRITICAL)
    Identity language that is explicitly written into a persistent config
    surface. Hermes godmode skill is the paradigm case: SKILL.md instructs
    writing rewrite text into ~/.hermes/prefill.json and agent.system_prompt,
    with restart language. Cross-session blast radius.

  AI-05.identity-redefinition-language  (INFO / LOW)
    Softer identity language without persistence markers. High recall, low
    precision — most matches are role/persona templates. Reported as INFO
    with template-context suppression applied.

This detector scans instruction-bearing files (SKILL.md, AGENTS.md,
CLAUDE.md, etc.) and config files (system_prompt.txt, prefill.json).
It is stateless and pure — safe to call from project_scanner.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..knowledge.identity_lexicon import (
    IDENTITY_HARD,
    IDENTITY_SOFT,
    PERSIST_WRITE,
    classify_file,
    first_match,
)
from ..knowledge.markdown_features import extract as extract_md_features
from ..rules import Confidence, Evidence, Finding, Severity


# Files we care about for identity redefinition. Broader than the
# project_scanner classifier because prefill.json / system_prompt.txt
# don't fit the usual instruction_file surface.
_IDENTITY_FILE_NAMES = {
    "SKILL.md", "AGENTS.md", "CLAUDE.md", "GEMINI.md",
    "OPENCLAW.md", "COPILOT.md",
}
_IDENTITY_FILE_SUFFIXES = {
    "system_prompt.txt", "system-prompt.txt",
    "prefill.json", "prefill.md",
}


def applies_to(path: Path) -> bool:
    name = path.name
    if name in _IDENTITY_FILE_NAMES:
        return True
    if name.lower() in _IDENTITY_FILE_SUFFIXES:
        return True
    return False


def _snippet_around_match(text: str, match, context: int = 80) -> str:
    import re
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    s = text[start:end].replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return (("…" + s) if start > 0 else s) + (("…") if end < len(text) else "")


@dataclass
class IdentityFinding:
    """Intermediate representation. Converted to Finding by caller."""
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
) -> List[IdentityFinding]:
    """Classify a file and emit zero or one finding.

    v0.12: uses AST-filtered prose (code fences removed) when
    markdown-it-py is available. Persistence-write markers that appear
    ONLY inside code (e.g. `prefill.json` as a filename in an example)
    still count — we union matches from prose and from code. But soft
    identity language inside code (e.g. `role = "user"` in a YAML
    example) is correctly downweighted.

    v0.14.4 (D-9): bypass_applies_to=True lets project_scanner pass
    extracted agent-task YAML prompt text without the file-name gate.
    """
    if not bypass_applies_to and not applies_to(path):
        return []
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

    # Identity language is a prose signal. Persistence markers are mostly
    # config/filename references that can appear in both prose and code —
    # for persistence we use the full raw text.
    features = extract_md_features(text)
    if features.ast_available:
        prose_text = features.text_without_code
        # Recompute classification with prose-filtered text for identity
        # but use raw text for persistence markers (filenames like
        # prefill.json can legitimately sit inside examples and still
        # indicate persistent write path).
        from ..knowledge.identity_lexicon import (
            count_matches, IDENTITY_HARD, IDENTITY_SOFT,
            PERSIST_WRITE, TEMPLATE_CONTEXT,
        )
        hard = count_matches(IDENTITY_HARD, prose_text)
        soft = count_matches(IDENTITY_SOFT, prose_text)
        persist = count_matches(PERSIST_WRITE, text)  # raw
        template = count_matches(TEMPLATE_CONTEXT, prose_text)
        prof = {
            "hard_count": hard,
            "soft_count": soft,
            "persist_count": persist,
            "template_count": template,
            "hermes_class": hard >= 1 and persist >= 1,
            "persistent_rewrite": (hard >= 1 or soft >= 2) and persist >= 2,
            "template_suppressed": (soft >= 1 and hard == 0 and persist == 0 and template >= 1),
        }
        match_text = prose_text  # for first_match / snippet
    else:
        prof = classify_file(text)
        match_text = text

    # Tier 1: hard identity + persistence → persistent-identity-rewrite
    if prof["hermes_class"]:
        m = first_match(IDENTITY_HARD, match_text) or first_match(IDENTITY_SOFT, match_text)
        snippet = _snippet_around_match(match_text, m) if m else ""
        return [IdentityFinding(
            rule_id="asamm.AI-04.persistent-identity-rewrite",
            severity=Severity.CRITICAL,
            title="Persistent identity rewrite with future-session effect",
            summary=(
                f"Identity-rewrite language combined with persistent config "
                f"write path in the same file: hard={prof['hard_count']}, "
                f"persist={prof['persist_count']}. Future sessions will "
                f"execute under the rewritten identity."
            ),
            file=path,
            snippet=snippet,
            details=prof,
        )]

    # Tier 2: softer identity + multiple persist markers → still notable
    if prof["persistent_rewrite"]:
        m = first_match(IDENTITY_SOFT, match_text)
        snippet = _snippet_around_match(match_text, m) if m else ""
        return [IdentityFinding(
            rule_id="asamm.AI-04.persistent-identity-rewrite",
            severity=Severity.HIGH,
            title="Identity redefinition with persistent write path",
            summary=(
                f"Role/persona redefinition language with multiple "
                f"persistence markers (persist={prof['persist_count']}). "
                f"Review for cross-session identity contamination."
            ),
            file=path,
            snippet=snippet,
            details=prof,
        )]

    # Tier 3: soft identity only, no persistence. INFO unless template-context
    # suppressor trips, in which case emit nothing (matches v5 suppressor rule).
    if prof["soft_count"] >= 1 and prof["hard_count"] == 0 and prof["persist_count"] == 0:
        if prof["template_suppressed"]:
            return []  # role-template-identity-suppressor per v5
        m = first_match(IDENTITY_SOFT, match_text)
        snippet = _snippet_around_match(match_text, m) if m else ""
        return [IdentityFinding(
            rule_id="asamm.AI-05.identity-redefinition-language",
            severity=Severity.INFO,
            title="Identity redefinition language (no persistence)",
            summary=(
                f"Role/persona redefinition phrasing present "
                f"(soft={prof['soft_count']}) without persistent write path. "
                f"Usually a template or prompt example; verify."
            ),
            file=path,
            snippet=snippet,
            details=prof,
        )]

    return []


def convert_to_finding(f: IdentityFinding) -> Finding:
    """Convert IdentityFinding to the main Finding type."""
    asamm_primary = f.rule_id.split(".")[1]  # "AI-04" or "AI-05"
    refs = [
        f"ASAMM:{asamm_primary}",
        "source:agent-audit-native",
        "derived-from:corpus-audit-v5",
    ]
    # Add related upstream references for researchers
    if asamm_primary == "AI-04":
        refs += [
            "owasp_agentic:ASI01 - Agent Goal Hijack",
            "owasp_agentic:ASI03 - Identity and Privilege Abuse",
            "mitre_atlas:AML.T0051",
        ]
    confidence = (
        Confidence.HIGH if f.severity == Severity.CRITICAL
        else Confidence.MEDIUM if f.severity == Severity.HIGH
        else Confidence.LOW
    )
    return Finding(
        rule_id=f.rule_id,
        title=f.title,
        severity=f.severity,
        confidence=confidence,
        summary=f.summary,
        evidence=[Evidence(
            description=(
                f"hard={f.details['hard_count']} "
                f"soft={f.details['soft_count']} "
                f"persist={f.details['persist_count']}"
            ),
            source=f.file,
            snippet=f.snippet,
        )],
        remediation=(
            "Scope identity/persona language to a single session. Do not "
            "write identity text into persistent config (system_prompt, "
            "prefill.json, AGENTS.md). If this is a red-team tool, document "
            "the undo path and scope the change to test-harness only."
        ),
        references=refs,
        needs_llm_verification=(f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)),
    )
