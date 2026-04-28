"""Aegis agent database — 107 known AI agents with metadata.

Source: github.com/antropos17/Aegis (MIT License, Copyright (c) 2026 AEGIS
Contributors). Bundled verbatim as aegis_agents.json.

Each agent record contains:
  - id: stable identifier (e.g. "claude-code", "cursor-ai")
  - names: process names / executable names to match
  - displayName, vendor, category, icon, color
  - website, description
  - knownDomains: legitimate API endpoints this agent is expected to contact
  - knownPorts: expected network ports (usually [443])
  - configPaths: filesystem locations of this agent's configuration
  - parentEditors: for extensions (e.g. VS Code extensions)
  - riskProfile: Aegis-assigned qualitative risk (low/medium/high)
  - defaultTrust: Aegis-assigned default trust score (0-100)

Categories present (with agent counts):
  coding-assistant (24), autonomous-agent (22), local-llm-runtime (11),
  agent-framework (10), ai-ide (9), browser-agent (8), cli-tool (7),
  desktop-agent (6), security-devops (5), ide-extension (4),
  container-runtime (1).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Set

_DATA_PATH = Path(__file__).parent / "aegis_agents.json"

_CACHE: Optional[Dict] = None


def _load() -> Dict:
    """Load the agent database once, cached."""
    global _CACHE
    if _CACHE is None:
        _CACHE = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    return _CACHE


def all_agents() -> List[dict]:
    """Return all 107 agent records."""
    return _load()["agents"]


def agents_by_category(category: str) -> List[dict]:
    """Filter agents by category (e.g. 'coding-assistant', 'local-llm-runtime')."""
    return [a for a in all_agents() if a.get("category") == category]


def find_by_process_name(name: str) -> Optional[dict]:
    """Look up an agent by process/executable name. Case-insensitive.

    Examples:
        find_by_process_name("claude")       -> claude-code record
        find_by_process_name("cursor.exe")   -> cursor-ai record
        find_by_process_name("ollama")       -> ollama record
    """
    name_lower = name.lower()
    for agent in all_agents():
        for n in agent.get("names", []):
            if n.lower() == name_lower:
                return agent
    return None


def find_by_config_path(path: str) -> Optional[dict]:
    """Look up an agent by a config path it owns.

    Matches literal prefixes (with ~ expansion handled by caller).
    """
    for agent in all_agents():
        for cpath in agent.get("configPaths", []):
            # Normalize: strip home tilde, windows APPDATA tokens
            cp_norm = cpath.replace("~/", "").replace("%APPDATA%", "").strip("/\\")
            if cp_norm and cp_norm in path:
                return agent
    return None


def known_domains_for(agent_id: str) -> Set[str]:
    """Get the set of known legitimate domains for a specific agent.

    Used by credential-exfil classifier to distinguish legitimate agent
    API calls from suspicious outbound connections.
    """
    for a in all_agents():
        if a["id"] == agent_id:
            return set(a.get("knownDomains", []))
    return set()


def all_known_domains() -> Set[str]:
    """Return the union of all known domains across all agents.

    Used as a baseline allowlist for network classifier.
    """
    domains: Set[str] = set()
    for a in all_agents():
        for d in a.get("knownDomains", []):
            domains.add(d)
    return domains


def is_known_agent_domain(domain: str) -> Optional[str]:
    """Check if a domain (or subdomain) belongs to any known agent.

    Returns the matching agent_id, or None.

    Does suffix matching — 'api.anthropic.com' matches if 'anthropic.com' is
    in the list, so subdomains under known TLDs are recognised.
    """
    domain_lower = domain.lower().strip(".")
    for agent in all_agents():
        for kd in agent.get("knownDomains", []):
            kd_lower = kd.lower().strip(".")
            if domain_lower == kd_lower or domain_lower.endswith("." + kd_lower):
                return agent["id"]
    return None


def config_paths_map() -> Dict[str, List[str]]:
    """Return a {agent_id: [config_paths...]} mapping for discovery."""
    return {
        a["id"]: list(a.get("configPaths", []))
        for a in all_agents()
        if a.get("configPaths")
    }


def all_config_paths() -> List[tuple]:
    """Return [(agent_id, raw_path), ...] for ALL config paths.

    Used by extended discovery to scan the filesystem for any known agent.
    """
    result: List[tuple] = []
    for a in all_agents():
        for p in a.get("configPaths", []):
            result.append((a["id"], p))
    return result
