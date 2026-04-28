"""External knowledge imports.

This module bundles third-party reference data used by detectors, with
clear attribution for each source.

Sources:
  - aegis_agents.json: 107 AI agent profiles from antropos17/Aegis
    (github.com/antropos17/Aegis, MIT License, Copyright (c) 2026 AEGIS
    Contributors). Used for agent discovery, known-domain classification,
    config path detection.
  - aegis_rules/*.yaml: 70 sensitive path detection rules in 8 categories,
    same source. Used by sensitive-path helper in detectors.
  - agt_mcp_patterns.py (to be added): MCP tool poisoning regex patterns
    from microsoft/agent-governance-toolkit (MIT License).

All bundled data kept verbatim; selection/filtering is done in the helper
modules, not by modifying the source files.
"""
from . import aegis
from . import aegis_paths
from . import agt_mcp_patterns

__all__ = ["aegis", "aegis_paths", "agt_mcp_patterns"]
