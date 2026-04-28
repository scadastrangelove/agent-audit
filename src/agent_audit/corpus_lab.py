"""Regression lab for large project-scan corpora."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .knowledge.rule_pack_loader import load_all_rules
from .project_report import build_project_json
from .project_scanner import scan_project
from .report_rerank import rerank
from .rules import Severity


@dataclass
class CorpusSnapshot:
    generated_at: str
    corpus_path: str
    min_severity: str
    aggregate_collections: bool
    repos_scanned: int
    files_scanned: int
    files_with_findings: int
    findings_total: int
    findings_shown: int
    by_severity: Dict[str, int]
    by_tool: Dict[str, int]
    native_total: int
    native_hot_files: int
    native_rule_counts: Dict[str, int]
    report_profiles: Dict[str, int]
    cluster_summary: Dict[str, int]
    security_profile: Dict[str, object]
    top_canonical_classes: Dict[str, int]
    top_rule_counts: Dict[str, int]

    def to_dict(self) -> dict:
        return asdict(self)


def create_snapshot(
    corpus_path: Path,
    *,
    min_severity: str = "medium",
    aggregate_collections: bool = True,
) -> CorpusSnapshot:
    corpus_path = corpus_path.resolve()
    rules = load_all_rules()
    result = scan_project(corpus_path, rules=rules, aggregate_collections=aggregate_collections)
    min_sev = Severity(min_severity)
    kept = [finding for finding in result.findings if finding.severity.order >= min_sev.order]
    rerank_result = rerank(kept)
    project_json = build_project_json(corpus_path, result, kept, rerank_result)

    by_severity = Counter(finding.severity.value for finding in kept)
    by_tool = Counter()
    for finding in kept:
        for ref in finding.references:
            if ref.startswith("upstream:"):
                by_tool[ref.split(":", 2)[1]] += 1
                break

    return CorpusSnapshot(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        corpus_path=str(corpus_path),
        min_severity=min_severity,
        aggregate_collections=aggregate_collections,
        repos_scanned=len(result.repos_scanned),
        files_scanned=result.files_scanned,
        files_with_findings=result.files_with_findings,
        findings_total=len(result.findings),
        findings_shown=len(kept),
        by_severity=dict(sorted(by_severity.items())),
        by_tool=dict(sorted(by_tool.items())),
        native_total=project_json["native_summary"]["total_native"],
        native_hot_files=len(project_json["native_summary"]["hot_files"]),
        native_rule_counts=project_json["native_summary"]["rule_counts"],
        report_profiles=project_json["report_profiles"],
        cluster_summary=project_json["cluster_summary"],
        security_profile=project_json["security_profile"],
        top_canonical_classes=project_json["security_profile"]["canonical_class_counts"],
        top_rule_counts=dict(Counter(f.rule_id for f in kept).most_common(25)),
    )


def compare_snapshots(baseline: CorpusSnapshot, current: CorpusSnapshot) -> dict:
    failures: List[str] = []
    warnings: List[str] = []

    if current.repos_scanned < baseline.repos_scanned:
        failures.append(
            f"repos_scanned regressed: {current.repos_scanned} < {baseline.repos_scanned}"
        )
    if current.native_total < baseline.native_total:
        failures.append(
            f"native_total regressed: {current.native_total} < {baseline.native_total}"
        )
    if current.native_hot_files < baseline.native_hot_files:
        failures.append(
            f"native_hot_files regressed: {current.native_hot_files} < {baseline.native_hot_files}"
        )
    if current.cluster_summary.get("clustered_issue_instances", 0) < baseline.cluster_summary.get("clustered_issue_instances", 0):
        warnings.append(
            "clustered_issue_instances regressed: "
            f"{current.cluster_summary.get('clustered_issue_instances', 0)} < "
            f"{baseline.cluster_summary.get('clustered_issue_instances', 0)}"
        )

    for rule_id, baseline_count in baseline.native_rule_counts.items():
        current_count = current.native_rule_counts.get(rule_id, 0)
        if current_count < baseline_count:
            failures.append(
                f"native rule regressed: {rule_id} {current_count} < {baseline_count}"
            )

    if current.findings_shown > baseline.findings_shown * 1.25:
        warnings.append(
            f"findings_shown increased sharply: {current.findings_shown} vs {baseline.findings_shown}"
        )

    return {
        "baseline": baseline.to_dict(),
        "current": current.to_dict(),
        "delta": {
            "repos_scanned": current.repos_scanned - baseline.repos_scanned,
            "native_total": current.native_total - baseline.native_total,
            "native_hot_files": current.native_hot_files - baseline.native_hot_files,
            "clustered_issue_instances": current.cluster_summary.get("clustered_issue_instances", 0)
            - baseline.cluster_summary.get("clustered_issue_instances", 0),
            "findings_shown": current.findings_shown - baseline.findings_shown,
        },
        "failures": failures,
        "warnings": warnings,
        "passed": not failures,
    }


def render_markdown(snapshot: CorpusSnapshot, comparison: Optional[dict] = None) -> str:
    lines = [
        "# Corpus regression lab",
        f"_generated {snapshot.generated_at}_",
        "",
        "## Snapshot",
        "",
        f"- Corpus: `{snapshot.corpus_path}`",
        f"- Repos scanned: {snapshot.repos_scanned}",
        f"- Files scanned: {snapshot.files_scanned}",
        f"- Findings shown: {snapshot.findings_shown}",
        f"- Native findings: {snapshot.native_total}",
        f"- Native hot files: {snapshot.native_hot_files}",
        "",
        "## Native rule counts",
        "",
    ]
    for rule_id, count in snapshot.native_rule_counts.items():
        lines.append(f"- `{rule_id}`: {count}")
    lines.append("")
    lines.extend(
        [
            "## Canonical issue classes",
            "",
            f"- Clustered issue instances: {snapshot.cluster_summary.get('clustered_issue_instances', 0)}",
            f"- Distinct canonical classes: {len(snapshot.top_canonical_classes)}",
            f"- Highest issue severity: {snapshot.security_profile.get('highest_issue_severity')}",
            f"- Multi-signal issue instances: {snapshot.cluster_summary.get('multi_finding_clusters', 0)}",
            f"- Cross-tool issue instances: {snapshot.cluster_summary.get('cross_tool_clusters', 0)}",
            "",
        ]
    )
    for canonical_class, count in snapshot.top_canonical_classes.items():
        lines.append(f"- `{canonical_class}`: {count}")
    lines.append("")

    if comparison:
        lines.append("## Comparison")
        lines.append("")
        lines.append(f"- Passed: {comparison['passed']}")
        for failure in comparison["failures"]:
            lines.append(f"- FAIL: {failure}")
        for warning in comparison["warnings"]:
            lines.append(f"- WARN: {warning}")
        lines.append("")

    return "\n".join(lines)


def write_reports(
    output_dir: Path,
    snapshot: CorpusSnapshot,
    comparison: Optional[dict] = None,
) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = output_dir / "corpus-snapshot.json"
    compare_path = output_dir / "corpus-compare.json"
    markdown_path = output_dir / "corpus-summary.md"

    snapshot_path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
    if comparison is not None:
        compare_path.write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(snapshot, comparison), encoding="utf-8")

    return {
        "snapshot": snapshot_path,
        "compare": compare_path,
        "markdown": markdown_path,
    }
