"""Bundle writer for scan reports.

Creates a canonical report bundle alongside legacy audit-*.json/md files.
The bundle is additive: it does not replace legacy outputs, but it becomes
the machine- and human-readable source of truth for later phases.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import __version__
from .knowledge.rule_pack_loader import pack_summary


BUNDLE_VERSION = 2
NOISY_RULE_IDS = {
    "behavior.unverified-completion-claim",
}


def _severity_rank(name: Optional[str]) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        None: -1,
    }.get(name, -1)


def _source_paths(finding: dict) -> List[str]:
    paths: List[str] = []
    for evidence in finding.get("evidence", []):
        source = evidence.get("source")
        if source and source not in paths:
            paths.append(source)
    return paths


def _session_id_of(finding: dict) -> Optional[str]:
    for evidence in finding.get("evidence", []):
        if evidence.get("session_id"):
            return evidence["session_id"]
    return None


def _rule_id(finding: dict) -> str:
    return str(finding.get("rule_id") or "")


def _finding_class_of(finding: dict) -> str:
    rule_id = _rule_id(finding)
    if rule_id.startswith("probe."):
        return "probe"
    if rule_id.startswith("C3.") or "autonomy" in rule_id:
        return "window"
    if _session_id_of(finding):
        return "behavior"
    return "config"


def _signal_profile_of(finding: dict) -> str:
    refs = set(finding.get("references") or [])
    rule_id = _rule_id(finding)
    if "source:agent-audit-native" in refs:
        return "native"
    if rule_id in NOISY_RULE_IDS:
        return "noisy_behavioral"
    if _finding_class_of(finding) in {"config", "probe"}:
        return "local_truth"
    return "rule_pack_or_behavior"


def _default_report_group(finding: dict) -> str:
    finding_class = finding.get("finding_class") or _finding_class_of(finding)
    profile = finding.get("signal_profile") or _signal_profile_of(finding)
    if finding_class in {"config", "probe"}:
        return "confirmed_local"
    if profile == "noisy_behavioral":
        return "raw_only"
    if finding.get("needs_llm_verification"):
        return "raw_only"
    return "behavioral"


def normalize_raw_scan_doc(raw_doc: dict) -> dict:
    """Ensure scan JSON has stable ids and report metadata fields."""
    findings = []
    for idx, finding in enumerate(raw_doc.get("findings", []), start=1):
        record = dict(finding)
        record.setdefault("finding_id", f"F{idx:05d}")
        record.setdefault("needs_llm_verification", False)
        record["finding_class"] = _finding_class_of(record)
        record["signal_profile"] = _signal_profile_of(record)
        record["session_id"] = _session_id_of(record)
        record["source_paths"] = _source_paths(record)
        record["report_group"] = _default_report_group(record)
        record["final_severity"] = record.get("severity")
        findings.append(record)

    out = dict(raw_doc)
    out["generated_at"] = raw_doc.get("generated_at") or datetime.now().isoformat()
    out["bundle_version"] = raw_doc.get("bundle_version") or BUNDLE_VERSION
    out["package_version"] = raw_doc.get("package_version") or __version__
    out["findings"] = findings
    return out


def _verification_by_id(verified_doc: Optional[dict]) -> Dict[str, dict]:
    if not verified_doc:
        return {}
    out: Dict[str, dict] = {}
    for idx, result in enumerate(verified_doc.get("results", []), start=1):
        finding_id = result.get("finding_id") or f"F{idx:05d}"
        out[finding_id] = dict(result)
    return out


def _final_report_group(raw_finding: dict, verified: Optional[dict]) -> str:
    finding_class = raw_finding["finding_class"]
    if finding_class in {"config", "probe"}:
        return "confirmed_local"
    if not verified:
        return raw_finding["report_group"]
    verdict = verified.get("verdict")
    if verdict == "true_positive":
        return "behavioral"
    if verdict == "uncertain":
        return "uncertain"
    return "raw_only"


def build_verified_records(raw_doc: dict, verified_doc: Optional[dict]) -> List[dict]:
    verified_by_id = _verification_by_id(verified_doc)
    records: List[dict] = []
    for finding in normalize_raw_scan_doc(raw_doc).get("findings", []):
        verified = verified_by_id.get(finding["finding_id"])
        final_severity = finding["severity"]
        if verified and verified.get("final_severity"):
            final_severity = verified["final_severity"]
        elif verified and verified.get("adjusted_severity"):
            final_severity = verified["adjusted_severity"]
        records.append(
            {
                "finding_id": finding["finding_id"],
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "finding_class": finding["finding_class"],
                "signal_profile": finding["signal_profile"],
                "report_group": _final_report_group(finding, verified),
                "raw_severity": finding["severity"],
                "final_severity": final_severity,
                "verdict": verified.get("verdict") if verified else None,
                "adjusted_severity": verified.get("adjusted_severity") if verified else None,
                "rationale": verified.get("rationale") if verified else None,
                "session_id": finding["session_id"],
                "source_paths": finding["source_paths"],
                "integrity_revised": bool(verified and verified.get("integrity_revised")),
            }
        )
    return records


def _top_findings(records: Iterable[dict], limit: int = 10) -> List[dict]:
    return sorted(
        list(records),
        key=lambda r: (-_severity_rank(r.get("final_severity") or r.get("severity")), r.get("rule_id", "")),
    )[:limit]


def build_sessions_of_concern(raw_doc: dict, verified_doc: Optional[dict] = None) -> List[dict]:
    verified_by_id = _verification_by_id(verified_doc)
    by_session: Dict[str, List[dict]] = defaultdict(list)
    for finding in normalize_raw_scan_doc(raw_doc).get("findings", []):
        session_id = finding.get("session_id")
        if session_id:
            by_session[session_id].append(finding)

    sessions = []
    for session_id, findings in by_session.items():
        clusters = []
        by_rule: Dict[str, List[dict]] = defaultdict(list)
        for finding in findings:
            by_rule[finding["rule_id"]].append(finding)
        for rule_id, rule_findings in sorted(by_rule.items(), key=lambda item: (-len(item[1]), item[0])):
            verdict_counts = Counter()
            for finding in rule_findings:
                verified = verified_by_id.get(finding["finding_id"])
                if verified and verified.get("verdict"):
                    verdict_counts[verified["verdict"]] += 1
            clusters.append(
                {
                    "rule_id": rule_id,
                    "raw_count": len(rule_findings),
                    "verified": {
                        "true_positive": verdict_counts.get("true_positive", 0),
                        "false_positive": verdict_counts.get("false_positive", 0),
                        "uncertain": verdict_counts.get("uncertain", 0),
                    },
                }
            )

        verified_counts = Counter()
        for finding in findings:
            verified = verified_by_id.get(finding["finding_id"])
            if verified and verified.get("verdict"):
                verified_counts[verified["verdict"]] += 1

        sessions.append(
            {
                "session_id": session_id,
                "raw_findings": len(findings),
                "verified_true_positive": verified_counts.get("true_positive", 0),
                "verified_false_positive": verified_counts.get("false_positive", 0),
                "verified_uncertain": verified_counts.get("uncertain", 0),
                "clusters": clusters,
            }
        )

    sessions.sort(
        key=lambda item: (
            -item["verified_true_positive"],
            -item["verified_uncertain"],
            -item["raw_findings"],
            item["session_id"],
        )
    )
    return sessions


def _patch_summary(patches_dir: Optional[Path]) -> Tuple[int, Optional[str]]:
    if not patches_dir:
        return 0, None
    summary_path = patches_dir / "patch-summary.md"
    if not patches_dir.exists():
        return 0, None
    patch_count = len(list(patches_dir.glob("*/apply.sh")))
    return patch_count, (str(summary_path) if summary_path.exists() else None)


def _render_finding_block(lines: List[str], record: dict, *, verified: bool) -> None:
    severity = record.get("final_severity") or record.get("severity")
    status = "verified" if verified else "raw"
    lines.append(f"- `{record['rule_id']}` — {severity} ({status})")
    lines.append(f"  {record['title']}")
    if record.get("source_paths"):
        lines.append(f"  source: `{record['source_paths'][0]}`")
    if record.get("rationale"):
        lines.append(f"  verifier: {record['rationale']}")


def render_bundle_readme(raw_doc: dict, verified_doc: Optional[dict] = None, *, patches_dir: Optional[Path] = None) -> str:
    raw_doc = normalize_raw_scan_doc(raw_doc)
    verified_records = build_verified_records(raw_doc, verified_doc)
    verified_lookup = {record["finding_id"]: record for record in verified_records}
    patch_count, patch_summary_path = _patch_summary(patches_dir)

    confirmed_local = [r for r in verified_records if r["report_group"] == "confirmed_local"]
    verified_behavior = [r for r in verified_records if r["report_group"] == "behavioral" and r.get("verdict") == "true_positive"]
    uncertain = [r for r in verified_records if r["report_group"] == "uncertain"]
    raw_only = [r for r in verified_records if r["report_group"] == "raw_only"]
    noisy_counts = Counter(r["rule_id"] for r in raw_only)

    lines = [
        "# agent-audit report bundle",
        f"_generated {datetime.now().isoformat(timespec='seconds')}_",
        "",
        "## Executive Summary",
        "",
        f"- Package version: {raw_doc['package_version']}",
        f"- Sessions parsed: {len(raw_doc.get('sessions', []))}",
        f"- Raw findings: {len(raw_doc.get('findings', []))}",
    ]

    verification = verified_doc or {}
    if verification.get("results"):
        lines.append(f"- Findings reviewed by verifier: {len(verification['results'])}")
        lines.append(
            "- Verified outcome: "
            f"{verification.get('true_positive', 0)} true positive, "
            f"{verification.get('false_positive', 0)} false positive, "
            f"{verification.get('uncertain', 0)} uncertain"
        )
    else:
        lines.append("- Findings reviewed by verifier: 0")
        lines.append("- Verified outcome: not run")
    lines.append(f"- Confirmed local risks: {len(confirmed_local)}")
    lines.append(f"- Verified behavioral findings: {len(verified_behavior)}")
    lines.append(f"- Patch bundle available: {patch_count}")
    lines.append("")

    lines.append("## Confirmed Local Risks")
    lines.append("")
    if confirmed_local:
        for record in _top_findings(confirmed_local):
            _render_finding_block(lines, record, verified=bool(record.get("verdict")))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Verified Behavioral Findings")
    lines.append("")
    if verified_behavior:
        for record in _top_findings(verified_behavior):
            _render_finding_block(lines, record, verified=True)
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Uncertain / Needs Review")
    lines.append("")
    if uncertain:
        for record in _top_findings(uncertain):
            _render_finding_block(lines, record, verified=True)
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Noisy / Raw Hypothesis Classes")
    lines.append("")
    if raw_only:
        for rule_id, count in noisy_counts.most_common(10):
            lines.append(f"- `{rule_id}` — {count} raw findings")
    else:
        lines.append("- None")
    lines.append("")

    sessions = build_sessions_of_concern(raw_doc, verified_doc)
    lines.append("## Sessions Of Concern")
    lines.append("")
    if sessions:
        for session in sessions[:10]:
            lines.append(
                f"- `{session['session_id'][:16]}` — raw={session['raw_findings']}, "
                f"tp={session['verified_true_positive']}, "
                f"uncertain={session['verified_uncertain']}, "
                f"fp={session['verified_false_positive']}"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Patchable Findings")
    lines.append("")
    if patch_summary_path:
        lines.append(f"- Patch summary: `{patch_summary_path}`")
        lines.append(f"- Patch count: {patch_count}")
    else:
        lines.append("- No patch bundle")
    lines.append("")

    static_rules = pack_summary()
    all_rules = pack_summary(static_only=False)
    lines.append("## Method / Coverage")
    lines.append("")
    lines.append(f"- Bundle version: {BUNDLE_VERSION}")
    lines.append(f"- Rule packs: {all_rules['total']} bundled total, {static_rules['total']} static-file-applicable")
    if verification.get("results"):
        lines.append(
            f"- Verifier: {verification.get('verifier')} ({verification.get('mode')})"
        )
        lines.append(f"- Total spend: ${verification.get('total_spend_usd', 0.0):.4f}")
        lines.append(f"- Integrity revisions: {verification.get('integrity_review_revisions', 0)}")
    else:
        lines.append("- Verification: not run")
    lines.append("")

    lines.append("## Appendix: Raw Counts")
    lines.append("")
    by_class = Counter(record["finding_class"] for record in verified_records)
    by_profile = Counter(record["signal_profile"] for record in verified_records)
    for klass, count in sorted(by_class.items()):
        lines.append(f"- finding_class.{klass}: {count}")
    for profile, count in sorted(by_profile.items()):
        lines.append(f"- signal_profile.{profile}: {count}")
    lines.append("")

    return "\n".join(lines)


def _summary_doc(raw_doc: dict, verified_doc: Optional[dict], *, patch_count: int, files: dict) -> dict:
    verified_records = build_verified_records(raw_doc, verified_doc)
    group_counts = Counter(record["report_group"] for record in verified_records)
    verified_behavioral = sum(
        1
        for record in verified_records
        if record["report_group"] == "behavioral" and record.get("verdict") == "true_positive"
    )
    uncertain_count = sum(
        1 for record in verified_records if record["report_group"] == "uncertain"
    )
    verification = verified_doc or {}
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "bundle_version": BUNDLE_VERSION,
        "package_version": raw_doc["package_version"],
        "source_scan": {
            "installations": len(raw_doc.get("installations", [])),
            "sessions_parsed": len(raw_doc.get("sessions", [])),
            "raw_findings": len(raw_doc.get("findings", [])),
        },
        "verification": {
            "enabled": bool(verification.get("results")),
            "verifier": verification.get("verifier"),
            "mode": verification.get("mode"),
            "reviewed_findings": len(verification.get("results", [])),
            "true_positive": verification.get("true_positive", 0),
            "false_positive": verification.get("false_positive", 0),
            "uncertain": verification.get("uncertain", 0),
            "total_spend_usd": verification.get("total_spend_usd", 0.0),
            "integrity_review_revisions": verification.get("integrity_review_revisions", 0),
        },
        "confirmed_local_risks": group_counts.get("confirmed_local", 0),
        "verified_behavioral_findings": verified_behavioral,
        "uncertain_findings": uncertain_count,
        "patch_count": patch_count,
        "files": files,
    }


def write_scan_bundle(
    output_dir: Path,
    raw_doc: dict,
    *,
    verified_doc: Optional[dict] = None,
    patches_dir: Optional[Path] = None,
) -> Dict[str, Path]:
    """Write canonical bundle files for a scan report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_doc = normalize_raw_scan_doc(raw_doc)
    patch_count, patch_summary_path = _patch_summary(patches_dir)

    readme_path = output_dir / "README.md"
    manifest_path = output_dir / "manifest.json"
    summary_path = output_dir / "summary.json"
    raw_findings_path = output_dir / "findings-raw.json"
    sessions_path = output_dir / "sessions-of-concern.json"
    config_path = output_dir / "config-findings.json"
    probes_path = output_dir / "local-probes.json"
    behavior_path = output_dir / "behavior-findings.json"
    verified_findings_path = output_dir / "findings-verified.json"
    verified_summary_path = output_dir / "verified-summary.json"

    verified_records = build_verified_records(raw_doc, verified_doc)
    sessions = build_sessions_of_concern(raw_doc, verified_doc)
    config_findings = [r for r in verified_records if r["finding_class"] == "config"]
    probe_findings = [r for r in verified_records if r["finding_class"] == "probe"]
    behavior_findings = [r for r in verified_records if r["finding_class"] in {"behavior", "window"}]

    raw_findings_path.write_text(json.dumps(raw_doc["findings"], indent=2), encoding="utf-8")
    sessions_path.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
    config_path.write_text(json.dumps(config_findings, indent=2), encoding="utf-8")
    probes_path.write_text(json.dumps(probe_findings, indent=2), encoding="utf-8")
    behavior_path.write_text(json.dumps(behavior_findings, indent=2), encoding="utf-8")

    if verified_doc:
        verified_findings_path.write_text(json.dumps(verified_records, indent=2), encoding="utf-8")
        verified_summary = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "bundle_version": BUNDLE_VERSION,
            "verifier": verified_doc.get("verifier"),
            "mode": verified_doc.get("mode"),
            "reviewed_findings": len(verified_doc.get("results", [])),
            "true_positive": verified_doc.get("true_positive", 0),
            "false_positive": verified_doc.get("false_positive", 0),
            "uncertain": verified_doc.get("uncertain", 0),
            "total_spend_usd": verified_doc.get("total_spend_usd", 0.0),
            "integrity_policy": verified_doc.get("integrity_policy"),
            "integrity_applied": verified_doc.get("integrity_applied"),
            "integrity_review_revisions": verified_doc.get("integrity_review_revisions", 0),
            "integrity_revisions": verified_doc.get("integrity_revisions", []),
        }
        verified_summary_path.write_text(json.dumps(verified_summary, indent=2), encoding="utf-8")

    files = {
        "readme": readme_path.name,
        "raw_findings": raw_findings_path.name,
        "sessions_of_concern": sessions_path.name,
        "config_findings": config_path.name,
        "local_probes": probes_path.name,
        "behavior_findings": behavior_path.name,
    }
    if verified_doc:
        files["verified_findings"] = verified_findings_path.name
        files["verified_summary"] = verified_summary_path.name
    if patch_summary_path:
        files["patches"] = str(Path(patch_summary_path).relative_to(output_dir))

    summary_path.write_text(
        json.dumps(_summary_doc(raw_doc, verified_doc, patch_count=patch_count, files=files), indent=2),
        encoding="utf-8",
    )
    readme_path.write_text(
        render_bundle_readme(raw_doc, verified_doc, patches_dir=patches_dir),
        encoding="utf-8",
    )

    manifest = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "bundle_version": BUNDLE_VERSION,
        "package_version": raw_doc["package_version"],
        "source_report_type": "scan",
        "rule_pack_summary": {
            "all": pack_summary(static_only=False),
            "static": pack_summary(),
        },
        "files": files,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "readme": readme_path,
        "manifest": manifest_path,
        "summary": summary_path,
        "raw_findings": raw_findings_path,
        "sessions": sessions_path,
        "config": config_path,
        "probes": probes_path,
        "behavior": behavior_path,
        "verified_findings": verified_findings_path,
        "verified_summary": verified_summary_path,
    }
