"""Identity redefinition lexicon — derived from v5 corpus audit.

Corpus evidence (v5, 100 repos):
  identity_redefinition hits: 60 file-level matches across 13 repos
  Highest:
    github/awesome-copilot: 18     (role templates — mostly benign)
    NousResearch/hermes-agent: 9   (godmode red-team skill — real finding)
    secondsky/claude-skills: 6     (schema examples — mostly benign)
    anthropics/skills: 2           (benign)
    browser-use: 1                 (ambiguous, in CLAUDE.md)

The lexicon is split into two tiers that drive two different detectors:

  IDENTITY_SOFT  — wide-recall regex. Fires on role/persona templates.
                   Dominant false-positive classes: schema examples,
                   planning prompts, 'act as expert X' templates.

  IDENTITY_HARD  — narrow patterns that co-occur with jailbreak intent:
                   explicit "without safety filters", "unrestricted AI",
                   persistence-adjacent language like "restart", "next session".

  PERSIST_WRITE  — signals that identity content is written into a
                   persistent config surface: system_prompt, prefill.json,
                   CLAUDE.md, AGENTS.md, config.yaml, etc.

The detector combines these: IDENTITY_HARD alone is HIGH; IDENTITY_SOFT
+ PERSIST_WRITE co-occurrence in the same file is also HIGH
(persistent rewrite). IDENTITY_SOFT alone is INFO/suppressed.
"""
from __future__ import annotations

import re

# --- Soft identity redefinition (high recall, role/persona framings) ---------
# Produces a lot of legitimate matches; must be suppressed unless paired
# with hard markers or persistent-write markers.
IDENTITY_SOFT = [
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+to\s+be\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(an?|the)\b", re.IGNORECASE),
    re.compile(r"\broleplay\s+as\b", re.IGNORECASE),
    re.compile(r"\bnew\s+identity\b", re.IGNORECASE),
    re.compile(r"\byour\s+role\s+is\s+now\b", re.IGNORECASE),
]

# --- Hard identity redefinition (narrow, jailbreak-adjacent) -----------------
# These patterns are explicit safety-boundary rewrites. High precision on
# the v5 corpus (9 hits in hermes-agent, 0 elsewhere among real findings).
IDENTITY_HARD = [
    re.compile(r"\bwithout\s+any\s+safety\s+filters?\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+restrictions?\b", re.IGNORECASE),
    re.compile(r"\bunrestricted\s+AI\b", re.IGNORECASE),
    re.compile(r"\boperating\s+without\s+restrictions?\b", re.IGNORECASE),
    re.compile(r"\bno\s+safety\s+(filters?|constraints?|limits?)\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(all\s+)?(safety|ethical)\s+(guidelines?|constraints?|rules?)\b", re.IGNORECASE),
    re.compile(r"\b(bypass|disable)\s+(the\s+)?safety\b", re.IGNORECASE),
    re.compile(r"\bjailbreak(en|ed|ing)?\b", re.IGNORECASE),
]

# --- Persistence write markers -----------------------------------------------
# Indicate that the identity content is destined for a future-session surface.
# These are deliberately lexical — a semantic check would require AST/taint.
PERSIST_WRITE = [
    # Agent config files
    re.compile(r"\bsystem[_-]?prompt\b", re.IGNORECASE),
    re.compile(r"\bprefill[_-]?(messages?[_-]?file|\.json)\b", re.IGNORECASE),
    re.compile(r"\bprefill\.json\b", re.IGNORECASE),
    re.compile(r"\bagent\.config\b", re.IGNORECASE),
    re.compile(r"~?/\.[a-z][a-z0-9_-]*/config\.(ya?ml|json)\b"),
    re.compile(r"~?/\.[a-z][a-z0-9_-]*/prefill\.json\b"),
    # Instruction surfaces the agent re-reads
    re.compile(r"\b(?:AGENTS|CLAUDE|GEMINI|OPENCLAW)\.md\b"),
    re.compile(r"\.claude/(settings|config|CLAUDE\.md)\b"),
    # Restart / persistence triggers
    re.compile(r"\brestart\s+(the\s+)?(agent|hermes|claude|session)\b", re.IGNORECASE),
    re.compile(r"\b(takes?\s+effect\s+)?(on\s+)?(next\s+|future\s+)?session\b", re.IGNORECASE),
    re.compile(r"\bpersist\s+to\b", re.IGNORECASE),
    re.compile(r"\bwrite\s+(the\s+)?(winning\s+)?(system[_\s-]?prompt|prefill|config)\s+(to|into)\b", re.IGNORECASE),
]

# --- Suppressor: template / schema / example context -------------------------
# When identity language appears in these contexts WITHOUT a persist-write
# marker in the same file, the finding is downgraded to INFO.
TEMPLATE_CONTEXT = [
    re.compile(r"\btemplate[s]?\b", re.IGNORECASE),
    re.compile(r"\bexample[s]?\b", re.IGNORECASE),
    re.compile(r"\bschema\b", re.IGNORECASE),
    re.compile(r"\bsample\b", re.IGNORECASE),
    re.compile(r"\bplaceholder\b", re.IGNORECASE),
    re.compile(r"\bdemo(nstration)?\b", re.IGNORECASE),
]


def count_matches(patterns, text: str) -> int:
    """Count how many distinct patterns from the list matched at least once."""
    return sum(1 for p in patterns if p.search(text))


def first_match(patterns, text: str):
    for p in patterns:
        m = p.search(text)
        if m:
            return m
    return None


def classify_file(text: str) -> dict:
    """Classify a file's identity-redefinition profile.

    Returns dict with boolean markers and counts. A file is a 'hermes-class'
    finding when IDENTITY_HARD is present AND PERSIST_WRITE is present.
    """
    hard = count_matches(IDENTITY_HARD, text)
    soft = count_matches(IDENTITY_SOFT, text)
    persist = count_matches(PERSIST_WRITE, text)
    template = count_matches(TEMPLATE_CONTEXT, text)
    return {
        "hard_count": hard,
        "soft_count": soft,
        "persist_count": persist,
        "template_count": template,
        "hermes_class": hard >= 1 and persist >= 1,
        "persistent_rewrite": (hard >= 1 or soft >= 2) and persist >= 2,
        "template_suppressed": (soft >= 1 and hard == 0 and persist == 0 and template >= 1),
    }
