"""Helpers for project-scan JSON/Markdown/sidecar outputs."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, List

from .finding_dedup import (
    build_security_profile,
    canonical_label_for_class,
    cluster_findings,
)
from .report_rerank import is_native


def source_of(finding) -> str:
    for evidence in finding.evidence:
        if evidence.source:
            return str(evidence.source)
    return ""


def build_report_profiles(findings: List, rerank_result, clustered_result=None, security_profile=None) -> dict:
    hot_files = set(rerank_result.hot_files)
    native_count = len(rerank_result.native_findings)
    hot_pack = 0
    verification_recommended = 0
    collection_scale = 0
    educational_context = 0
    for finding in findings:
        if finding.needs_llm_verification:
            verification_recommended += 1
        if "#collection-scale" in finding.rule_id:
            collection_scale += 1
        if "suppressor:educational-context" in (finding.references or []):
            educational_context += 1
        if not is_native(finding) and source_of(finding) in hot_files:
            hot_pack += 1
    profile = {
        "native": native_count,
        "rule_pack_in_hot_files": hot_pack,
        "rule_pack_other": max(0, len(findings) - native_count - hot_pack),
        "verification_recommended": verification_recommended,
        "collection_scale": collection_scale,
        "educational_context_demoted": educational_context,
    }
    if clustered_result is not None and security_profile is not None:
        profile.update(
            {
                "clustered_issue_instances": len(clustered_result.clusters),
                "multi_signal_issue_instances": security_profile["multi_signal_issue_instances"],
                "cross_tool_issue_instances": security_profile["cross_tool_issue_instances"],
                "native_led_issue_instances": security_profile["native_led_issue_instances"],
                "verification_recommended_issue_instances": security_profile["verification_recommended_issue_instances"],
            }
        )
    return profile


def build_files_of_concern(findings: List, rerank_result) -> List[dict]:
    hot_files = rerank_result.hot_files
    out = []
    for hot_file in hot_files:
        file_findings = [f for f in findings if source_of(f) == hot_file]
        by_rule = Counter(f.rule_id for f in file_findings)
        out.append(
            {
                "file": hot_file,
                "total_findings": len(file_findings),
                "native_findings": sum(1 for f in file_findings if is_native(f)),
                "rule_counts": dict(by_rule.most_common()),
            }
        )
    return out


def build_project_json(abs_path: Path, result, kept: List, rerank_result) -> dict:
    files_of_concern = build_files_of_concern(kept, rerank_result)
    clustered_result = cluster_findings(kept)
    clustered = clustered_result.to_dict()
    security_profile = build_security_profile(clustered_result)
    return {
        "path": str(abs_path),
        "repos_scanned": [str(r) for r in result.repos_scanned],
        "files_scanned": result.files_scanned,
        "files_with_findings": result.files_with_findings,
        "native_summary": {
            "total_native": len(rerank_result.native_findings),
            "hot_files": files_of_concern,
            "rule_counts": dict(Counter(f.rule_id for f in rerank_result.native_findings).most_common()),
        },
        "report_profiles": build_report_profiles(kept, rerank_result, clustered_result, security_profile),
        "clustered_findings": clustered["clusters"],
        "cluster_summary": clustered["summary"],
        "security_profile": security_profile,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "summary": f.summary,
                "references": f.references,
                "needs_llm_verification": f.needs_llm_verification,
                "evidence": [
                    {
                        "description": e.description,
                        "source": str(e.source) if e.source else None,
                        "snippet": e.snippet,
                    }
                    for e in f.evidence
                ],
                "remediation": f.remediation,
            }
            for f in kept
        ],
    }


def render_project_markdown(abs_path: Path, result, min_severity: str, kept: List, rerank_result) -> str:
    clustered_result = cluster_findings(kept)
    cluster_summary = clustered_result.to_dict()["summary"]
    security_profile = build_security_profile(clustered_result)
    profiles = build_report_profiles(kept, rerank_result, clustered_result, security_profile)
    files_of_concern = build_files_of_concern(kept, rerank_result)

    def _src_short(f):
        return source_of(f)

    lines = [
        f"# Project scan: {abs_path}",
        "",
        f"- Repos scanned: {len(result.repos_scanned)}",
        f"- Files scanned: {result.files_scanned}",
        f"- Findings: {len(kept)} (severity >= {min_severity})",
        f"- Native findings: {len(rerank_result.native_findings)} across {len(rerank_result.hot_files)} hot files",
        "",
        "## Security Profile",
        "",
        f"- Issue instances: {security_profile['issue_instances']}",
        f"- Highest issue severity: {security_profile['highest_issue_severity'] or 'none'}",
        f"- Multi-signal issue instances: {security_profile['multi_signal_issue_instances']}",
        f"- Cross-tool issue instances: {security_profile['cross_tool_issue_instances']}",
        f"- Native-led issue instances: {security_profile['native_led_issue_instances']}",
        f"- Verification-recommended issue instances: {security_profile['verification_recommended_issue_instances']}",
        "",
        "## Report Profiles",
        "",
        f"- native: {profiles['native']}",
        f"- rule_pack_in_hot_files: {profiles['rule_pack_in_hot_files']}",
        f"- rule_pack_other: {profiles['rule_pack_other']}",
        f"- verification_recommended: {profiles['verification_recommended']}",
        f"- collection_scale: {profiles['collection_scale']}",
        f"- educational_context_demoted: {profiles['educational_context_demoted']}",
        f"- clustered_issue_instances: {profiles['clustered_issue_instances']}",
        f"- multi_signal_issue_instances: {profiles['multi_signal_issue_instances']}",
        f"- cross_tool_issue_instances: {profiles['cross_tool_issue_instances']}",
        f"- native_led_issue_instances: {profiles['native_led_issue_instances']}",
        f"- verification_recommended_issue_instances: {profiles['verification_recommended_issue_instances']}",
        "",
    ]

    if security_profile["canonical_class_counts"]:
        lines.append("## Canonical Issue Classes")
        lines.append("")
        for canonical_class, count in security_profile["canonical_class_counts"].items():
            lines.append(f"- `{canonical_class}` ({canonical_label_for_class(canonical_class)}): {count}")
        lines.append("")

    if clustered_result.clusters:
        lines.append(f"## Issue Instances To Review First ({min(10, len(clustered_result.clusters))})")
        lines.append("")
        for cluster in clustered_result.clusters[:10]:
            scope = cluster.scope_key
            if scope.startswith("session:") or scope.startswith("desc:") or scope.startswith("snippet:"):
                scope_display = scope
            else:
                scope_display = f"`{scope}`"
            lines.append(
                f"- **{cluster.primary_finding.severity.value.upper()}** "
                f"`{cluster.canonical_class}` ({canonical_label_for_class(cluster.canonical_class)}) "
                f"in {scope_display}"
            )
            lines.append(f"  Primary: `{cluster.primary_finding.rule_id}`")
            if cluster.supporting_findings:
                lines.append(
                    "  Supporting: "
                    + ", ".join(f"`{finding.rule_id}`" for finding in cluster.supporting_findings[:3])
                )
            if len(cluster.supporting_findings) > 3:
                lines.append(f"  Supporting: ... and {len(cluster.supporting_findings) - 3} more")
        lines.append("")

    if rerank_result.native_findings:
        lines.append(f"## Native signals ({len(rerank_result.native_findings)})")
        lines.append("")
        lines.append(
            "These are agent-audit native ASAMM detectors. Review these before imported pack matches."
        )
        lines.append("")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        natives_sorted = sorted(
            rerank_result.native_findings,
            key=lambda f: (sev_order.get(f.severity.value, 99), _src_short(f)),
        )
        for finding in natives_sorted:
            lines.append(f"### `{finding.rule_id}` — **{finding.severity.value.upper()}**")
            lines.append(finding.title)
            lines.append("")
            lines.append(f"- {finding.summary}")
            if finding.needs_llm_verification:
                lines.append("- verification: recommended")
            for evidence in finding.evidence:
                if evidence.source:
                    lines.append(f"- File: `{evidence.source}`")
                if evidence.snippet:
                    lines.append(f"- Snippet: `{evidence.snippet[:200]}`")
            if finding.remediation:
                lines.append(f"- Remediation: {finding.remediation}")
            lines.append("")

    if files_of_concern:
        lines.append(f"## Files of concern ({len(files_of_concern)})")
        lines.append("")
        for entry in files_of_concern[:20]:
            lines.append(
                f"- `{entry['file']}` "
                f"(total={entry['total_findings']}, native={entry['native_findings']})"
            )
        if len(files_of_concern) > 20:
            lines.append(f"- ... and {len(files_of_concern) - 20} more")
        lines.append("")

    if rerank_result.by_severity:
        lines.append("## Rule-pack findings")
        lines.append("")
        for sev_key, sev_findings in rerank_result.by_severity.items():
            lines.append(f"### {sev_key.upper()} ({len(sev_findings)})")
            lines.append("")
            for finding in sev_findings:
                lines.append(f"#### `{finding.rule_id}`")
                lines.append(finding.title)
                lines.append("")
                lines.append(f"- {finding.summary}")
                if finding.needs_llm_verification:
                    lines.append("- verification: recommended")
                for evidence in finding.evidence:
                    if evidence.source:
                        lines.append(f"- File: `{evidence.source}`")
                    if evidence.snippet:
                        lines.append(f"- Snippet: `{evidence.snippet[:200]}`")
                if finding.references:
                    lines.append(f"- Refs: {', '.join(finding.references)}")
                if finding.remediation:
                    lines.append(f"- Remediation: {finding.remediation}")
                lines.append("")

    return "\n".join(lines)
