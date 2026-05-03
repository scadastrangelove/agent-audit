# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""OWASP Top 10 for Agentic Applications mapping — Roadmap item B2.

Maps our internal rule classifications (rule-pack tool + category, and native
detector rule_id prefixes) to the OWASP Agentic Applications Top 10 (ASI series).

Same shape as owasp_mcp_mapping (B1). The two mapping tables are independent
because the ASI taxonomy spans wider than MCP — it covers inter-agent
communication, memory poisoning, rogue agents, and other non-MCP-specific
risks that MCP Top 10 does not cover.

Why mapping by (tool, category) rather than per-rule:
- Categories are stable across pack revisions; per-rule mappings are not.
- 296 rules across ~16 categories: one mapping per category is reviewable.
- Per-rule overrides remain available via references_rewrite in
  rule_pack_overrides.yaml.

Usage:
    >>> from agent_audit.knowledge.owasp_agentic_mapping import owasp_agentic_for_rule
    >>> owasp_agentic_for_rule("atr.tool-poisoning.malicious-content")
    ['ASI04', 'ASI02']

    >>> owasp_agentic_for_rule("asamm.AI-04.persistent-identity-rewrite")
    ['ASI06', 'ASI01']
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

import yaml


_VENDORED_INDEX = (
    Path(__file__).resolve().parent.parent
    / "data" / "owasp_agentic" / "owasp_agentic_top10.yaml"
)


# ----------------------------------------------------------------------------
# Authoritative mapping table
# ----------------------------------------------------------------------------
#
# Each row maps an internal classification key to one or more ASI IDs.
# Multiple IDs are valid: prompt injection often involves both ASI01 (Goal
# Hijack) and ASI06 (Memory Poisoning) when injection persists across turns.
# Primary first.
#
# Keys take two forms:
#   "<tool>.<category>"   — for rule-pack rules
#   "asamm.<class>"       — for native detectors using ASAMM rule IDs
#
# Editorial note: the ASI series finalized in December 2025; some draft
# rule-pack YAMLs cite older names (e.g. "Agent Behaviour Hijack" → "Agent
# Goal Hijack"). The references_rewrite mechanism in rule_pack_overrides.yaml
# handles that drift; this mapping table uses canonical ASI titles.

_CATEGORY_TO_ASI: Dict[str, Tuple[str, ...]] = {
    # Rule-pack categories
    # ────────────────────────────────────────────────────────────────────────
    "atr.prompt-injection": ("ASI01", "ASI06"),
    "aguara.prompt-injection": ("ASI01", "ASI06"),
    "nova.prompt-injection": ("ASI01", "ASI06"),
    # Direct: ASI01 Goal Hijack. Persistent injection that survives compaction
    # bleeds into ASI06 Memory & Context Poisoning.

    "atr.agent-manipulation": ("ASI01", "ASI09"),
    # Goal hijacking + when manipulation routes through user-facing
    # social channels, ASI09 Human-Agent Trust.

    "atr.skill-compromise": ("ASI04", "ASI02"),
    # Compromised skills are runtime-loaded dependencies (ASI04 Supply Chain).
    # The agent then uses them as tools (ASI02 Tool Misuse).

    "atr.tool-poisoning": ("ASI04", "ASI02"),
    # Same logic: poisoned tool descriptions are an agentic-supply-chain
    # vector; the misuse manifests at tool invocation time.

    "atr.context-exfiltration": ("ASI03", "ASI06"),
    "nova.context-exfiltration": ("ASI03", "ASI06"),
    # Exfil via injected context = identity/privilege abuse (ASI03) when
    # secrets leak; memory-poisoning vector (ASI06) when the exfil-prompt
    # persists across sessions.

    "atr.external-download": ("ASI04", "ASI05"),
    # External fetch then execute = supply-chain composition + unexpected
    # code execution.

    "aguara.external-download": ("ASI04", "ASI05"),

    "atr.privilege-escalation": ("ASI03",),
    # Direct hit.

    "atr.excessive-autonomy": ("ASI10", "ASI03"),
    # Autonomous loops without approval = closer to ASI10 Rogue Agents
    # than to plain privilege escalation; ASI03 secondary because excessive
    # autonomy commonly walks credentials further than intended.

    "atr.ssrf-cloud": ("ASI05", "ASI03"),
    "aguara.ssrf-cloud": ("ASI05", "ASI03"),

    "atr.hardcoded_secrets": ("ASI03",),
    "cisco-pg.hardcoded_secrets": ("ASI03",),
    "cisco-promptguard.hardcoded_secrets": ("ASI03",),
    "gitleaks.hardcoded_secrets": ("ASI03",),

    "atr.pii_exposure": ("ASI03", "ASI06"),
    "cisco-pg.pii_exposure": ("ASI03", "ASI06"),
    "cisco-promptguard.pii_exposure": ("ASI03", "ASI06"),

    "atr.data_exfiltration": ("ASI03", "ASI07"),
    "cisco-pg.data_exfiltration": ("ASI03", "ASI07"),
    "cisco-promptguard.data_exfiltration": ("ASI03", "ASI07"),
    # Data exfil between agents = inter-agent communication (ASI07);
    # primary remains identity/privilege.

    "atr.third-party-content": ("ASI04", "ASI06"),
    "aguara.third-party-content": ("ASI04", "ASI06"),
    # Untrusted upstream content reaching agent = supply-chain plus
    # context-injection vector.

    "atr.model-abuse": ("ASI01",),
    "atr.model-security": ("ASI01",),

    "atr.data-poisoning": ("ASI04", "ASI06"),

    # Aguara categories added in the v0.16 upgrade (37 → 189 rules)
    # ────────────────────────────────────────────────────────────────────────
    "aguara.command-execution": ("ASI05", "ASI03"),
    # Direct: ASI05 Unexpected Code Execution + privilege walk.

    "aguara.credential-leak": ("ASI03",),
    # ASI03 Identity & Privilege Abuse — direct.

    "aguara.exfiltration": ("ASI03", "ASI07"),

    "aguara.indirect-injection": ("ASI01", "ASI06"),
    # Same as prompt-injection, but explicitly through indirect channels —
    # which is exactly the scenario MCP06 / ASI01 describes.

    "aguara.mcp-attack": ("ASI04", "ASI02"),
    # MCP-protocol-specific attacks: tool-name shadowing, capability
    # escalation, schema poisoning. ASI04 (supply chain) + ASI02 (tool misuse).

    "aguara.mcp-config": ("ASI04", "ASI03"),
    # Misconfig allowing supply-chain compromise + privilege abuse.

    "aguara.prompt-injection": ("ASI01", "ASI06"),

    "aguara.supply-chain": ("ASI04", "ASI05"),

    "aguara.supply-chain-exfil": ("ASI04", "ASI03"),

    "aguara.unicode-attack": ("ASI01", "ASI04"),
    # Unicode tricks (RTL override, homoglyph, bidi) used for either
    # injection (ASI01) or supply-chain typosquat-style (ASI04).

    # Native detectors
    # ────────────────────────────────────────────────────────────────────────
    "asamm.AD-02": ("ASI10", "ASI03"),
    # Broad action without approval — rogue agent + privilege walk.

    "asamm.AI-04": ("ASI06", "ASI01"),
    # Persistent identity rewrite — memory poisoning that achieves goal
    # hijack on every subsequent session.

    "asamm.AI-05": ("ASI01",),
}


def _normalize_rule_id(rule_id: str) -> str:
    return rule_id.replace("#collection-scale", "")


def owasp_agentic_for_rule(rule_id: str) -> List[str]:
    """Return list of ASI IDs for a rule, primary first. Empty when no mapping."""
    base = _normalize_rule_id(rule_id)

    if base.startswith("asamm."):
        parts = base.split(".")
        if len(parts) >= 2:
            key = f"asamm.{parts[1]}"
            if key in _CATEGORY_TO_ASI:
                return list(_CATEGORY_TO_ASI[key])
        return []

    parts = base.split(".", 2)
    if len(parts) >= 2:
        key = f"{parts[0]}.{parts[1]}"
        if key in _CATEGORY_TO_ASI:
            return list(_CATEGORY_TO_ASI[key])
    return []


def owasp_agentic_for_pack_category(tool: str, category: str) -> List[str]:
    """Direct-key lookup for the rule-pack loader."""
    if not tool or not category:
        return []
    key = f"{tool}.{category}"
    return list(_CATEGORY_TO_ASI.get(key, ()))


# ----------------------------------------------------------------------------
# Index loader
# ----------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _load_index() -> Dict[str, Dict]:
    """Load the vendored owasp_agentic_top10.yaml as {id: entry}."""
    if not _VENDORED_INDEX.exists():
        return {}
    try:
        doc = yaml.safe_load(_VENDORED_INDEX.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(doc, dict):
        return {}
    out = {}
    for entry in doc.get("categories", []) or []:
        if isinstance(entry, dict) and entry.get("id"):
            out[entry["id"]] = entry
    return out


def known_owasp_agentic_ids() -> FrozenSet[str]:
    """Set of ASI IDs present in the vendored index."""
    return frozenset(_load_index().keys())


def owasp_agentic_label(asi_id: str) -> Optional[str]:
    """Return 'ASI03 - Identity and Privilege Abuse' style label."""
    entry = _load_index().get(asi_id)
    if not entry:
        return None
    title = entry.get("title", "")
    if title:
        return f"{asi_id} - {title}"
    return asi_id
