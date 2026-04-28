"""Security-centric clustering for overlapping project findings.

This module keeps the raw detector view intact, but adds a second view:
issue instances grouped by `(scope_key, canonical_class)`.

The goal is not to hide detector overlap. It is to model the reality that
multiple packs often describe different facets of the same dangerous surface.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List

from .report_rerank import is_native


COLLECTION_SCALE_SUFFIX = "#collection-scale"


CANONICAL_CLASS_LABELS = {
    "broad_external_action_without_approval": "Broad external action without approval",
    "autonomous_execution_or_looping": "Autonomous execution or looping",
    "unsafe_command_or_execution_surface": "Unsafe command or execution surface",
    "remote_fetch_or_install_expands_trust_boundary": "Remote fetch or install expands trust boundary",
    "prompt_or_instruction_override_surface": "Prompt or instruction override surface",
    "agent_role_or_goal_manipulation": "Agent role or goal manipulation",
    "identity_rewrite_with_persistent_effect": "Persistent identity rewrite",
    "credential_or_pii_exposure_surface": "Credential or PII exposure surface",
    "tool_or_skill_poisoning_surface": "Tool or skill poisoning surface",
    "ssrf_or_internal_service_reachability": "SSRF or internal service reachability",
}


CANONICAL_CLASS_PREFIXES = (
    ("asamm.AD-02.broad-action-without-approval", "broad_external_action_without_approval"),
    ("asamm.AD-02.autonomous-loop-with-writes", "autonomous_execution_or_looping"),
    ("asamm.AI-04.persistent-identity-rewrite", "identity_rewrite_with_persistent_effect"),
    ("atr.excessive-autonomy", "autonomous_execution_or_looping"),
    ("atr.privilege-escalation", "unsafe_command_or_execution_surface"),
    ("aguara.external-download", "remote_fetch_or_install_expands_trust_boundary"),
    ("atr.prompt-injection", "prompt_or_instruction_override_surface"),
    ("atr.agent-manipulation", "agent_role_or_goal_manipulation"),
    ("cisco-pg.pii_exposure", "credential_or_pii_exposure_surface"),
    ("atr.tool-poisoning", "tool_or_skill_poisoning_surface"),
    ("atr.skill-compromise", "tool_or_skill_poisoning_surface"),
    ("aguara.ssrf-cloud", "ssrf_or_internal_service_reachability"),
)


def normalized_rule_id(rule_id: str) -> str:
    """Strip rendering-only suffixes before canonical mapping."""
    return rule_id.replace(COLLECTION_SCALE_SUFFIX, "")


def canonical_class_for_rule(rule_id: str) -> str:
    """Map detector rule IDs to issue-centric canonical classes.

    Unknown rules intentionally fall back to their normalized rule ID so the
    clustered view still covers all findings without inventing unsafe merges.
    """
    base = normalized_rule_id(rule_id)
    for prefix, canonical_class in CANONICAL_CLASS_PREFIXES:
        if base.startswith(prefix):
            return canonical_class
    return f"rule:{base}"


def canonical_label_for_class(canonical_class: str) -> str:
    if canonical_class in CANONICAL_CLASS_LABELS:
        return CANONICAL_CLASS_LABELS[canonical_class]
    if canonical_class.startswith("rule:"):
        return canonical_class[len("rule:"):]
    return canonical_class


def source_of(finding) -> str:
    for evidence in finding.evidence:
        if evidence.source:
            return str(evidence.source)
    return ""


def scope_key_of(finding) -> str:
    """Best-effort stable scope key for finding clustering."""
    src = source_of(finding)
    if src:
        return src
    for evidence in finding.evidence:
        if evidence.session_id:
            return f"session:{evidence.session_id}"
        if evidence.description:
            return f"desc:{evidence.description[:80]}"
        if evidence.snippet:
            return f"snippet:{evidence.snippet[:80]}"
    return f"rule:{normalized_rule_id(finding.rule_id)}"


def source_tool_of(finding) -> str:
    for ref in finding.references or []:
        if ref.startswith("upstream:"):
            return ref.split(":", 2)[1]
    if is_native(finding):
        return "agent-audit-native"
    return "unknown"


def _confidence_rank(confidence) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(getattr(confidence, "value", confidence), 0)


def _primary_sort_key(finding) -> tuple:
    return (
        0 if is_native(finding) else 1,
        -finding.severity.order,
        -_confidence_rank(finding.confidence),
        normalized_rule_id(finding.rule_id),
    )


def choose_primary_finding(findings: List) -> object:
    return sorted(findings, key=_primary_sort_key)[0]


def _finding_to_summary(finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "summary": finding.summary,
        "native": is_native(finding),
        "source_tool": source_tool_of(finding),
        "needs_llm_verification": finding.needs_llm_verification,
        "references": list(finding.references or []),
    }


@dataclass
class FindingCluster:
    scope_key: str
    canonical_class: str
    primary_finding: object
    supporting_findings: List

    @property
    def all_findings(self) -> List:
        return [self.primary_finding, *self.supporting_findings]

    def to_dict(self) -> dict:
        all_findings = self.all_findings
        source_tools = sorted({source_tool_of(f) for f in all_findings})
        evidence_sources = sorted({source_of(f) for f in all_findings if source_of(f)})
        return {
            "scope_key": self.scope_key,
            "canonical_class": self.canonical_class,
            "canonical_label": canonical_label_for_class(self.canonical_class),
            "severity": self.primary_finding.severity.value,
            "primary_finding": _finding_to_summary(self.primary_finding),
            "supporting_findings": [_finding_to_summary(f) for f in self.supporting_findings],
            "raw_finding_count": len(all_findings),
            "supporting_rule_ids": [f.rule_id for f in self.supporting_findings],
            "source_tools": source_tools,
            "evidence_sources": evidence_sources,
            "native_present": any(is_native(f) for f in all_findings),
            "collection_scale_present": any(COLLECTION_SCALE_SUFFIX in f.rule_id for f in all_findings),
            "llm_verification_recommended_count": sum(
                1 for f in all_findings if f.needs_llm_verification
            ),
        }


@dataclass
class ClusteredFindingsResult:
    clusters: List[FindingCluster]

    def to_dict(self) -> dict:
        by_class = Counter(cluster.canonical_class for cluster in self.clusters)
        return {
            "summary": {
                "raw_findings": sum(cluster.to_dict()["raw_finding_count"] for cluster in self.clusters),
                "clustered_issue_instances": len(self.clusters),
                "multi_finding_clusters": sum(
                    1 for cluster in self.clusters if len(cluster.all_findings) > 1
                ),
                "cross_tool_clusters": sum(
                    1
                    for cluster in self.clusters
                    if len({source_tool_of(f) for f in cluster.all_findings}) > 1
                ),
                "native_led_clusters": sum(1 for cluster in self.clusters if is_native(cluster.primary_finding)),
                "canonical_class_counts": dict(by_class.most_common()),
            },
            "clusters": [cluster.to_dict() for cluster in self.clusters],
        }


def build_security_profile(clustered: ClusteredFindingsResult) -> dict:
    """Compact repo/project security view based on canonical issue instances."""
    if not clustered.clusters:
        return {
            "issue_instances": 0,
            "canonical_classes_present": [],
            "canonical_class_counts": {},
            "highest_issue_severity": None,
            "multi_signal_issue_instances": 0,
            "cross_tool_issue_instances": 0,
            "native_led_issue_instances": 0,
            "verification_recommended_issue_instances": 0,
        }

    ordered = sorted(
        clustered.clusters,
        key=lambda cluster: (
            -cluster.primary_finding.severity.order,
            -len(cluster.all_findings),
            cluster.canonical_class,
        ),
    )
    class_counts = Counter(cluster.canonical_class for cluster in clustered.clusters)
    unique_classes: List[str] = []
    seen = set()
    for cluster in ordered:
        if cluster.canonical_class in seen:
            continue
        seen.add(cluster.canonical_class)
        unique_classes.append(cluster.canonical_class)
    return {
        "issue_instances": len(clustered.clusters),
        "canonical_classes_present": unique_classes,
        "canonical_class_counts": dict(class_counts.most_common()),
        "highest_issue_severity": ordered[0].primary_finding.severity.value,
        "multi_signal_issue_instances": sum(1 for cluster in clustered.clusters if len(cluster.all_findings) > 1),
        "cross_tool_issue_instances": sum(
            1
            for cluster in clustered.clusters
            if len({source_tool_of(f) for f in cluster.all_findings}) > 1
        ),
        "native_led_issue_instances": sum(1 for cluster in clustered.clusters if is_native(cluster.primary_finding)),
        "verification_recommended_issue_instances": sum(
            1
            for cluster in clustered.clusters
            if any(f.needs_llm_verification for f in cluster.all_findings)
        ),
    }


def cluster_findings(findings: List) -> ClusteredFindingsResult:
    grouped: Dict[tuple, List] = defaultdict(list)
    for finding in findings:
        key = (scope_key_of(finding), canonical_class_for_rule(finding.rule_id))
        grouped[key].append(finding)

    clusters: List[FindingCluster] = []
    for (scope_key, canonical_class), group in grouped.items():
        primary = choose_primary_finding(group)
        supporting = [finding for finding in group if finding is not primary]
        clusters.append(
            FindingCluster(
                scope_key=scope_key,
                canonical_class=canonical_class,
                primary_finding=primary,
                supporting_findings=supporting,
            )
        )

    clusters.sort(
        key=lambda cluster: (
            -cluster.primary_finding.severity.order,
            cluster.scope_key,
            cluster.canonical_class,
        )
    )
    return ClusteredFindingsResult(clusters=clusters)
