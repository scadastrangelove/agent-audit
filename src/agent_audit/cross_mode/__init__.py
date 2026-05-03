# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Cross-mode signal flow — Roadmap item M2.

Phase 1 (v0.18.0-dev): inventory builder + session-to-repo resolver +
caching. NO new user-visible behavior; the inventory builder is
internal-only and the resolver is wired in for future Phase 2 use.

Phase 2 (this commit): named cross-signal correlators + linker
contract + SignalRecord type + severity policy. Still no CLI surface
— a separate `cross-mode` subcommand follows in a subsequent commit.

See docs/m2-cross-mode-design-draft.md for the architecture and
docs/m2-d1-d5-decisions.md for the settled decisions D1-D5.

Phase 3+: mixed clustering, verifier integration. Deferred.

Design constraint per D5: this package's `inventory` module produces
**structural inventory tags** that survive user suppressions. The
`finding-to-finding` join layer (linker.py) respects suppressions by
contract — the caller must pass already-filtered findings. The two
layers are deliberately split so a suppressed static finding cannot
resurface as a supporting cross-signal record.
"""
from __future__ import annotations

from .correlators import (
    CorrelatorInput,
    CorrelatorResult,
    all_correlators,
    correlator_names,
)
from .inventory import (
    RepoSignalInventory,
    build_repo_signal_inventory,
    clear_inventory_cache,
)
from .linker import (
    LinkerOutput,
    findings_to_link_input,
    link_signals,
    static_findings_to_link_input,
)
from .policy import cap_severity, demote_priority_via_tag, lift_confidence
from .proximity import resolve_session_repo
from .signal_record import SignalRecord, make_aggregate_record

__all__ = [
    # Phase 1
    "RepoSignalInventory",
    "build_repo_signal_inventory",
    "clear_inventory_cache",
    "resolve_session_repo",
    # Phase 2: types
    "SignalRecord",
    "make_aggregate_record",
    "CorrelatorInput",
    "CorrelatorResult",
    "LinkerOutput",
    # Phase 2: API
    "all_correlators",
    "correlator_names",
    "link_signals",
    "findings_to_link_input",
    "static_findings_to_link_input",
    "cap_severity",
    "lift_confidence",
    "demote_priority_via_tag",
]
