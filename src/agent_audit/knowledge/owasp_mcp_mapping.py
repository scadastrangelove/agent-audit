# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""OWASP MCP Top 10 mapping — Rules Expansion Roadmap item B1.

Maps our internal rule classifications (rule_pack tool + category, and native
detector rule_id prefixes) to OWASP MCP Top 10 categories.

The mapping is derived from our own analysis of which rule categories
correspond to which MCP risks. It is NOT derived from OWASP prose text —
that lives separately in src/agent_audit/data/owasp_mcp/MCP*.md, under
its CC BY-SA 4.0 license. This module is MIT under the project license.

Why mapping by (tool, category) rather than per-rule:
- Categories are stable across pack revisions; per-rule mappings are not.
- ATR ships ~225 rules across ~16 categories; one mapping per category
  is reviewable. Per-rule mappings would be tedious and error-prone.
- Fine-grained per-rule overrides remain possible via the upcoming
  references override mechanism in rule_pack_overrides.yaml.

Usage:
    >>> from agent_audit.knowledge.owasp_mcp_mapping import owasp_mcp_for_rule
    >>> owasp_mcp_for_rule("atr.tool-poisoning.malicious-content")
    ['MCP03']

    >>> owasp_mcp_for_rule("asamm.AI-04.persistent-identity-rewrite")
    ['MCP06']

    >>> owasp_mcp_for_rule("atr.hardcoded_secrets.aws-key")
    ['MCP01']
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

import yaml


# Vendored index path — written by tools/owasp_mcp_index_build.py
_VENDORED_INDEX = (
    Path(__file__).resolve().parent.parent
    / "data" / "owasp_mcp" / "owasp_mcp_top10.yaml"
)


# ----------------------------------------------------------------------------
# Authoritative mapping table
# ----------------------------------------------------------------------------
#
# Each row maps an internal classification key to one or more OWASP MCP IDs.
# Multiple IDs are valid: tool poisoning (MCP03) often co-occurs with command
# injection (MCP05), and so on. The first ID is treated as the *primary* MCP
# class for clustering; the rest are secondary references.
#
# Keys take two forms:
#   "<tool>.<category>"         — for rule-pack rules, e.g. "atr.tool-poisoning"
#   "asamm.<class>"             — for native detectors using ASAMM rule IDs
#
# Editorial note: the OWASP MCP Top 10 is in v0.1-beta. Mappings here may shift
# as the framework matures. Update by editing this dict, not the vendored
# markdown.

_CATEGORY_TO_MCP: Dict[str, Tuple[str, ...]] = {
    # Rule-pack categories (ATR / Aguara / Cisco PromptGuard normalize to these)
    # ────────────────────────────────────────────────────────────────────────
    "atr.prompt-injection": ("MCP06", "MCP10"),
    "aguara.prompt-injection": ("MCP06", "MCP10"),
    "nova.prompt-injection": ("MCP06", "MCP10"),
    # Prompt injection is squarely MCP06 (Intent Flow Subversion). Many ATR
    # prompt-injection rules also touch MCP10 (Context Injection & Over-Sharing)
    # because injection often arrives via context.

    "atr.agent-manipulation": ("MCP06", "MCP02"),
    # Goal hijacking and manipulation = MCP06; the typical outcome is broader
    # privilege use than intended (MCP02).

    "atr.skill-compromise": ("MCP03", "MCP04"),
    # Skill manifests are tools to the agent. Modification = MCP03 (Tool
    # Poisoning). Skills installed via supply chain = MCP04.

    "atr.tool-poisoning": ("MCP03",),
    # Direct hit.

    "atr.context-exfiltration": ("MCP10", "MCP01"),
    "nova.context-exfiltration": ("MCP10", "MCP01"),
    # Exfiltrating context data = MCP10 (Context Over-Sharing). When tokens or
    # secrets are in that context, MCP01 too.

    "atr.external-download": ("MCP04", "MCP05"),
    # External fetch + execute = supply chain (MCP04) followed by command
    # injection paths (MCP05).

    "aguara.external-download": ("MCP04", "MCP05"),

    "atr.privilege-escalation": ("MCP02", "MCP07"),
    # Scope creep is MCP02; insufficient authentication enables it (MCP07).

    "atr.excessive-autonomy": ("MCP02", "MCP08"),
    # Autonomous loops without approval = scope creep (MCP02). Often invisible
    # in audit logs (MCP08).

    "atr.ssrf-cloud": ("MCP05", "MCP02"),
    "aguara.ssrf-cloud": ("MCP05", "MCP02"),
    # Server-side request forgery against cloud metadata = command/network
    # injection class (MCP05); used to escalate scope (MCP02).

    "atr.hardcoded_secrets": ("MCP01",),
    "cisco-pg.hardcoded_secrets": ("MCP01",),
    "cisco-promptguard.hardcoded_secrets": ("MCP01",),
    "gitleaks.hardcoded_secrets": ("MCP01",),
    # Direct hit. All four sources share the category name.

    "atr.pii_exposure": ("MCP10", "MCP01"),
    "cisco-pg.pii_exposure": ("MCP10", "MCP01"),
    "cisco-promptguard.pii_exposure": ("MCP10", "MCP01"),

    "atr.data_exfiltration": ("MCP10", "MCP01"),
    "cisco-pg.data_exfiltration": ("MCP10", "MCP01"),
    "cisco-promptguard.data_exfiltration": ("MCP10", "MCP01"),

    "atr.third-party-content": ("MCP04", "MCP10"),
    "aguara.third-party-content": ("MCP04", "MCP10"),
    # Untrusted upstream content reaching the agent = supply chain (MCP04)
    # plus context injection vector (MCP10).

    "atr.model-abuse": ("MCP03",),
    "atr.model-security": ("MCP03",),
    # Treating prompt-induced model manipulation as a tool-poisoning analog.

    "atr.data-poisoning": ("MCP04", "MCP03"),
    # Poisoned training/RAG data = supply chain (MCP04). Tool definitions
    # derived from that = MCP03.

    # Aguara categories added in the v0.16 upgrade (37 → 189 rules)
    # ────────────────────────────────────────────────────────────────────────
    "aguara.command-execution": ("MCP05", "MCP02"),
    # Direct hit on MCP05 Command Injection & Execution. Scope creep follows.

    "aguara.credential-leak": ("MCP01",),
    # Token Mismanagement & Secret Exposure — direct hit.

    "aguara.exfiltration": ("MCP10", "MCP01"),
    # Context oversharing primary; MCP01 when secrets exfil.

    "aguara.indirect-injection": ("MCP06", "MCP10"),
    # Indirect injection routes via context channels — same as ATR's prompt-injection.

    "aguara.mcp-attack": ("MCP03", "MCP04"),
    # Tool-name shadowing, description injection, capability escalation —
    # MCP03 Tool Poisoning is the umbrella; MCP04 supply chain when rug-pull.

    "aguara.mcp-config": ("MCP09", "MCP07"),
    # Misconfigured MCP servers, shadow servers, missing pins — MCP09;
    # insufficient authn often co-occurs.

    "aguara.prompt-injection": ("MCP06", "MCP10"),

    "aguara.supply-chain": ("MCP04", "MCP05"),

    "aguara.supply-chain-exfil": ("MCP04", "MCP01"),
    # Supply-chain attacks where the payload is credential exfiltration —
    # MCP04 + MCP01.

    "aguara.unicode-attack": ("MCP06", "MCP10"),
    # Bidi / homoglyph / RTL override — these are injection-presentation
    # tricks, not their own MCP class. Fold into MCP06.

    # Native detectors (rule_id starts with "asamm.")
    # ────────────────────────────────────────────────────────────────────────
    "asamm.AD-02": ("MCP02", "MCP08"),
    # Broad action without approval — scope creep + audit gap.

    "asamm.AI-04": ("MCP06", "MCP03"),
    # Persistent identity rewrite — intent flow subversion + tool poisoning
    # (the rewrite often persists as a tool description).

    "asamm.AI-05": ("MCP06",),
    # Identity redefinition — intent flow subversion.
}


def _normalize_rule_id(rule_id: str) -> str:
    """Strip rendering-only suffixes (e.g. collection-scale)."""
    return rule_id.replace("#collection-scale", "")


def owasp_mcp_for_rule(rule_id: str) -> List[str]:
    """Return list of OWASP MCP IDs for a rule, primary first.

    Empty list when no mapping is known. Callers treat empty as "skip" — do
    not invent a mapping.
    """
    base = _normalize_rule_id(rule_id)

    # Native detectors: asamm.<class>.<rest>
    if base.startswith("asamm."):
        # Match longest prefix first ("asamm.AD-02" before "asamm.AD")
        parts = base.split(".")
        if len(parts) >= 2:
            key = f"asamm.{parts[1]}"
            if key in _CATEGORY_TO_MCP:
                return list(_CATEGORY_TO_MCP[key])
        return []

    # Rule-pack rules: <tool>.<category>.<rest>
    parts = base.split(".", 2)
    if len(parts) >= 2:
        key = f"{parts[0]}.{parts[1]}"
        if key in _CATEGORY_TO_MCP:
            return list(_CATEGORY_TO_MCP[key])
    return []


def owasp_mcp_for_pack_category(tool: str, category: str) -> List[str]:
    """Direct-key lookup, used by rule-loader at parse time.

    Same return shape as owasp_mcp_for_rule — primary first, empty when no
    mapping exists.
    """
    if not tool or not category:
        return []
    key = f"{tool}.{category}"
    return list(_CATEGORY_TO_MCP.get(key, ()))


# ----------------------------------------------------------------------------
# Index loader
# ----------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _load_index() -> Dict[str, Dict]:
    """Load the vendored owasp_mcp_top10.yaml as {id: entry}."""
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


def known_owasp_mcp_ids() -> FrozenSet[str]:
    """Set of MCP IDs present in the vendored index. Used by the validator."""
    return frozenset(_load_index().keys())


def owasp_mcp_label(mcp_id: str) -> Optional[str]:
    """Return 'MCP03 - Tool Poisoning' style label, or None when unknown."""
    entry = _load_index().get(mcp_id)
    if not entry:
        return None
    title = entry.get("title", "")
    if title:
        return f"{mcp_id} - {title}"
    return mcp_id
