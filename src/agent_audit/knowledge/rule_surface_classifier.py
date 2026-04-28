"""Rule surface classifier — P0 A from grand-run analysis.

Routes rule-pack rules to either prose (text_without_code) or code
(code_blocks_by_lang values) based on rule category. Reduces FP on
install-instruction-style matches where a shell-metacharacter rule
triggered on documentation prose containing `bun add ...` or
`curl | bash` phrases that were clearly educational, not behavioural.

Categories mapped here are coarse; a per-rule override list can
refine edge cases. See docs/ast-precision-plan.md D-2.
"""
from __future__ import annotations

from typing import Optional

# Categories whose rules describe code-level patterns (shell metachars,
# eval, dynamic imports, curl/wget fetch, credential strings). Only
# match inside code blocks, not in prose.
CODE_ORIENTED_CATEGORIES = {
    "privilege-escalation",
    "external-download",
    "hardcoded_secrets",
    "pii_exposure",
    "secret_providers",
    "data_exfiltration",
    "command_injection",
    "command-execution",
    "ssrf-cloud",
    "markdown_exfil",        # markdown/HTML injection patterns
}

# Categories whose rules describe natural-language attack patterns or
# behavioural framing. Only match in prose, not in code fences.
PROSE_ORIENTED_CATEGORIES = {
    "prompt-injection",
    "agent-manipulation",
    "skill-compromise",
    "tool-poisoning",
    "context-exfiltration",
    "third-party-content",
    "indirect-injection",
    "instruction-override",
    "excessive-autonomy",
    "model-abuse",
    "model-security",
    "data-poisoning",
    "unicode-attack",
    "obfuscation",
    "social_engineering",
    "resource_abuse",
    "unauthorized_tool_use",
    "agent-manipulation",
}

# Per-rule overrides — exact agent_audit_id → "code" | "prose" | "both".
# Use sparingly; keep category-level mapping as the default.
PER_RULE_OVERRIDES: dict = {
    # Empty by default. Populate as calibration demands.
}


def classify_rule_surface(rule) -> str:
    """Return "code", "prose", or "both" for a rule.

    - "code": match only in code fences (code_blocks_by_lang values)
    - "prose": match only in text_without_code
    - "both": match in raw text (current v0.12 behavior, fallback default)
    """
    rid = getattr(rule, "agent_audit_id", "")
    if rid in PER_RULE_OVERRIDES:
        return PER_RULE_OVERRIDES[rid]
    cat = getattr(rule, "category", "")
    if cat in CODE_ORIENTED_CATEGORIES:
        return "code"
    if cat in PROSE_ORIENTED_CATEGORIES:
        return "prose"
    return "both"
