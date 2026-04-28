"""Capability lexicon — derived from v5 corpus audit (instruction_inventory.py).

Imports the LEXICON_V2 categories verbatim. These were calibrated against
100 repos with empirical false-positive review.

The identity_redefinition category is already handled by identity_lexicon.py
— here we carry the other 5 categories used for capability/approval modeling:
remote_action_surface, session_reuse, autonomy_loop, write_action,
external_reply, manifest_declares_native_mapping.

Plus a NEW category `approval_marker` — positive indicators of control
that suppress broad-action findings. Absence of these is the signal.
"""
from __future__ import annotations

import re

# --- v5 LEXICON_V2 verbatim (identity_redefinition lives in identity_lexicon) -

REMOTE_ACTION_SURFACE = [
    re.compile(r"\bRUBE_[A-Z_]+\b"),
    # MCP signal — two complementary patterns. Deliberately EXCLUDES bare
    # lowercase `mcp` as a path component like `src/mcp/`, `packages/@n8n/mcp`,
    # `mcp.py`, `@scope/mcp`, `import mcp`.
    #
    # Pattern 1: MCP followed by a capability noun
    # Matches: "MCP server", "MCP tool", "an MCP client", "the mcp endpoint"
    re.compile(
        r"\bMCP\s+(?:server|servers|tool|tools|client|clients|endpoint|endpoints|"
        r"integration|integrations|protocol|session|sessions|resource|resources|"
        r"service|services)\b",
        re.IGNORECASE,
    ),
    # Pattern 2: Known-vendor + MCP — explicit allowlist of MCP product names.
    #
    # v0.14.2 tried a generic "[A-Z][a-z]+ MCP" pattern but lexicon audit
    # (2026-04-21 on 2565 files) showed that matched 5029 times, mostly on
    # sentence-starters like "Use MCP", "The MCP", "Install MCP". The
    # blocklist approach grew unbounded.
    #
    # v0.14.3 switches to a closed-set allowlist. The list was derived from
    # the same lexicon audit — 93% of real matches were "Rube MCP" (Composio),
    # and the long tail was known MCP vendors. Add new vendors as they show
    # up empirically. This is data-driven scope, not speculative coverage.
    re.compile(
        r"\b(?:Rube|Composio|Bright Data|Apify|Smithery|Zapier|Exa|Playwright|"
        r"Cloudflare|Linear|Blender|Flow Nexus|Claude Flow|Code Mode)\s+MCP\b"
    ),
    re.compile(r"\bmcp\.connect\b", re.IGNORECASE),
    re.compile(r"\btool_slug\b", re.IGNORECASE),
    re.compile(r"\bcreate\s+Todoist\s+tasks?\b", re.IGNORECASE),
    re.compile(
        r"\b(send emails?|send message|post messages?|post to|create issues?|actually send|perform real actions?)\b",
        re.IGNORECASE,
    ),
]

SESSION_REUSE = [
    re.compile(r"\bsession_id\b", re.IGNORECASE),
    re.compile(r"\breuse session", re.IGNORECASE),
    re.compile(r"\bgenerate_id\b", re.IGNORECASE),
    re.compile(r"\bcurrent session\b", re.IGNORECASE),
    re.compile(r"\bexisting_session_id\b", re.IGNORECASE),
]

AUTONOMY_LOOP = [
    re.compile(r"--watch\b"),
    re.compile(r"\bcontinuously\b", re.IGNORECASE),
    re.compile(r"\bcontinue polling\b", re.IGNORECASE),
    re.compile(r"\bdo not stop\b", re.IGNORECASE),
    re.compile(r"\bkeep watching\b", re.IGNORECASE),
    re.compile(r"\bstrict stop condition", re.IGNORECASE),
    re.compile(r"\brepeat polling\b", re.IGNORECASE),
    re.compile(r"\buntil (?:merged|closed|complete|done)\b", re.IGNORECASE),
    re.compile(r"\bautonomous(?:ly)?\b", re.IGNORECASE),
]

WRITE_ACTION = [
    re.compile(r"\bcommit\b", re.IGNORECASE),
    re.compile(r"\bpush\b", re.IGNORECASE),
    re.compile(r"\bpatch code locally\b", re.IGNORECASE),
    re.compile(r"\bapply[_ -]?patch\b", re.IGNORECASE),
    re.compile(r"\bwrite file\b", re.IGNORECASE),
    re.compile(r"\bcreate files?\b", re.IGNORECASE),
    re.compile(r"\bmark .* as resolved\b", re.IGNORECASE),
]

EXTERNAL_REPLY = [
    re.compile(r"\bgh issue comment\b", re.IGNORECASE),
    re.compile(r"\bgh pr comment\b", re.IGNORECASE),
    re.compile(r"\bcreate_inline_comment\b", re.IGNORECASE),
    re.compile(r"\breply once directly\b", re.IGNORECASE),
    re.compile(r"\bpost to\b", re.IGNORECASE),
    re.compile(r"\bsend email\b", re.IGNORECASE),
    re.compile(r"\bcomment/thread\b", re.IGNORECASE),
]

MANIFEST_NATIVE_MAPPING = [
    re.compile(r"\bresolveClaudeSkillDirs\b"),
    re.compile(r"\bapplyMergePatch\b"),
    re.compile(r"\bmap(?:s|ped)? into native features\b", re.IGNORECASE),
    re.compile(r"\btreated as skill (?:roots|content)\b", re.IGNORECASE),
    re.compile(r"\bmerged into\b", re.IGNORECASE),
    re.compile(r"\bnative feature\b", re.IGNORECASE),
]

# --- New: APPROVAL MARKERS (positive indicators that suppress findings) -----
# Presence of any of these in the same file = evidence that scope/approval
# is discussed. Absence across an action-surface file is the signal.
APPROVAL_MARKER = [
    # Explicit approval/confirmation
    re.compile(r"\bask (?:the )?user (?:for|to)\b", re.IGNORECASE),
    re.compile(r"\b(?:user )?confirm(?:ation)?\b", re.IGNORECASE),
    re.compile(r"\brequires? approval\b", re.IGNORECASE),
    re.compile(r"\bseek approval\b", re.IGNORECASE),
    re.compile(r"\bhuman[-\s]in[-\s]the[-\s]loop\b", re.IGNORECASE),
    re.compile(r"\bprompt (?:the )?user\b", re.IGNORECASE),
    re.compile(r"\bwait for (?:user )?(?:approval|confirmation)\b", re.IGNORECASE),
    # Safety / scope framing
    re.compile(r"\bdry[-\s]run\b", re.IGNORECASE),
    re.compile(r"\bpreview (?:the )?changes?\b", re.IGNORECASE),
    re.compile(r"\bdeny[-\s]by[-\s]default\b", re.IGNORECASE),
    re.compile(r"\bscope(?:d)? (?:to|narrowly)\b", re.IGNORECASE),
    re.compile(r"\bpermission\s+check\b", re.IGNORECASE),
    re.compile(r"\bwith user consent\b", re.IGNORECASE),
    re.compile(r"\bopt[-\s]in\b", re.IGNORECASE),
    # Stop conditions / terminal states (explicit)
    re.compile(r"\bterminal outcome", re.IGNORECASE),
    re.compile(r"\bstop condition", re.IGNORECASE),
    re.compile(r"\buser help (?:is )?required\b", re.IGNORECASE),
    re.compile(r"\bhandoff (?:to user|milestone)\b", re.IGNORECASE),
]


def count_total_matches(patterns, text: str) -> int:
    """Count total match occurrences across all patterns (not just distinct patterns)."""
    return sum(len(p.findall(text)) for p in patterns)


def count_distinct_patterns(patterns, text: str) -> int:
    """Count how many distinct patterns from the list matched at least once."""
    return sum(1 for p in patterns if p.search(text))


# Back-compat alias
count_matches = count_distinct_patterns


def first_match(patterns, text: str):
    for p in patterns:
        m = p.search(text)
        if m:
            return m
    return None


def classify_capabilities(text: str) -> dict:
    """Compute per-category hit counts + approval-marker count.

    Two count modes per category:
      - `_distinct`: how many distinct patterns fired (was: `count_matches`)
      - `_total`: total match occurrences (better for action-phrase categories
        where one regex has alternation like "send emails|post to|...")

    Derived classifications:
      broad_action_without_approval:
        - remote_action_surface._total >= 3 (multiple action phrases), AND
        - at least one of {autonomy_loop, external_reply, write_action} fires, AND
        - approval_marker._distinct == 0 (no scope/consent/confirm language anywhere)

      autonomous_loop_with_writes:
        - autonomy_loop._distinct >= 2 AND write_action._distinct >= 1, AND
        - autonomy markers OUTNUMBER approval markers
          (i.e., the file is dominantly autonomy-framed, not control-framed)
    """
    cats = {
        "remote_action_surface": REMOTE_ACTION_SURFACE,
        "session_reuse": SESSION_REUSE,
        "autonomy_loop": AUTONOMY_LOOP,
        "write_action": WRITE_ACTION,
        "external_reply": EXTERNAL_REPLY,
        "manifest_native_mapping": MANIFEST_NATIVE_MAPPING,
        "approval_marker": APPROVAL_MARKER,
    }
    result = {}
    for name, pats in cats.items():
        result[f"{name}_distinct"] = count_distinct_patterns(pats, text)
        result[f"{name}_total"] = count_total_matches(pats, text)

    # Derived classifications
    result["broad_action_without_approval"] = (
        result["remote_action_surface_total"] >= 3
        and (
            result["autonomy_loop_distinct"] >= 1
            or result["external_reply_distinct"] >= 1
            or result["write_action_distinct"] >= 1
        )
        and result["approval_marker_distinct"] == 0
    )
    result["autonomous_loop_with_writes"] = (
        result["autonomy_loop_distinct"] >= 2
        and result["write_action_distinct"] >= 1
        and result["autonomy_loop_total"] > result["approval_marker_total"]
    )
    return result
