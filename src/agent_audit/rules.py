"""Rule engine — base class and registry for detectors.

Each rule analyzes a Session or agent config and returns zero or more Findings.
Rules are pure functions of their input — no side effects, no LLM calls.
LLM verification is a separate stage that operates on already-flagged findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from .events import Session


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def order(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    LOW = "low"       # likely false positive, needs LLM verification
    MEDIUM = "medium"
    HIGH = "high"     # almost certainly a true positive


class DetectionMode(str, Enum):
    """Detection mode — trades precision for recall.

    - CONSERVATIVE: high precision, low recall. Defaults for CI/show-your-manager.
    - BALANCED:     mid precision, mid recall. Default for scan without verify.
    - AGGRESSIVE:   low precision, high recall. Use with `--verify` — LLM filters FPs.
    """
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


@dataclass
class Evidence:
    """Supporting data for a finding. Keep it short and human-readable."""

    description: str
    source: Optional[Path] = None
    session_id: Optional[str] = None
    turn_range: Optional[Tuple[int, int]] = None
    snippet: Optional[str] = None


@dataclass
class Finding:
    """A single security observation."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str              # one-line human description
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None  # short action the user can take
    references: List[str] = field(default_factory=list)  # ASAMM control IDs, CVEs, etc
    created_at: datetime = field(default_factory=datetime.now)

    # Hints for later stages
    needs_llm_verification: bool = False


class Rule:
    """Base class for all detection rules."""

    id: str = ""           # e.g. "C2.credential-exfil"
    title: str = ""
    severity: Severity = Severity.MEDIUM
    references: List[str] = []

    def check_session(self, session: Session, mode: DetectionMode = DetectionMode.BALANCED) -> Iterable[Finding]:
        """Override to analyze a single session."""
        return []

    def check_config(self, agent_home: Path, mode: DetectionMode = DetectionMode.BALANCED) -> Iterable[Finding]:
        """Override to analyze agent configuration files."""
        return []


# Global registry
_SESSION_RULES: List[Rule] = []
_CONFIG_RULES: List[Rule] = []


def register_session_rule(rule: Rule) -> Rule:
    _SESSION_RULES.append(rule)
    return rule


def register_config_rule(rule: Rule) -> Rule:
    _CONFIG_RULES.append(rule)
    return rule


def session_rules() -> List[Rule]:
    return list(_SESSION_RULES)


def config_rules() -> List[Rule]:
    return list(_CONFIG_RULES)


def run_session_rules(session: Session, mode: DetectionMode = DetectionMode.BALANCED) -> List[Finding]:
    findings = []
    for rule in _SESSION_RULES:
        try:
            findings.extend(rule.check_session(session, mode=mode))
        except TypeError:
            # Rule doesn't accept mode kwarg — call legacy signature
            findings.extend(rule.check_session(session))
        except Exception as exc:  # noqa: BLE001 — rules shouldn't crash the scan
            findings.append(
                Finding(
                    rule_id=f"{rule.id}.error",
                    title=f"Rule {rule.id} failed",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    summary=f"Internal error during rule execution: {exc}",
                )
            )
    return findings


def run_config_rules(agent_home: Path, mode: DetectionMode = DetectionMode.BALANCED) -> List[Finding]:
    findings = []
    for rule in _CONFIG_RULES:
        try:
            findings.extend(rule.check_config(agent_home, mode=mode))
        except TypeError:
            findings.extend(rule.check_config(agent_home))
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    rule_id=f"{rule.id}.error",
                    title=f"Rule {rule.id} failed",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    summary=f"Internal error during rule execution: {exc}",
                )
            )
    return findings
