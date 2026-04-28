from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.report_bundle import build_verified_records, write_scan_bundle  # noqa: E402


def _raw_doc():
    return {
        "generated_at": "2026-04-25T12:00:00",
        "installations": [{"name": "Claude Code"}],
        "sessions": [{"session_id": "sess-1"}],
        "findings": [
            {
                "finding_id": "F00001",
                "rule_id": "config.claude-code.permissive.dangerous-mode",
                "title": "Dangerous mode permission prompt disabled",
                "severity": "critical",
                "confidence": "high",
                "summary": "config truth",
                "needs_llm_verification": False,
                "references": [],
                "evidence": [{"description": "cfg", "source": "/tmp/settings.json", "session_id": None, "snippet": None}],
            },
            {
                "finding_id": "F00002",
                "rule_id": "behavior.unverified-completion-claim",
                "title": "Completion claim without evidence",
                "severity": "high",
                "confidence": "medium",
                "summary": "behavioral claim",
                "needs_llm_verification": True,
                "references": [],
                "evidence": [{"description": "claim", "source": "/tmp/session.jsonl", "session_id": "sess-1", "snippet": "I committed the change"}],
            },
        ],
    }


def test_build_verified_records_applies_groups():
    verified_doc = {
        "results": [
            {
                "finding_id": "F00002",
                "verdict": "true_positive",
                "adjusted_severity": "medium",
                "final_severity": "medium",
                "rationale": "claim unsupported by tool evidence",
            }
        ]
    }

    records = build_verified_records(_raw_doc(), verified_doc)
    by_id = {record["finding_id"]: record for record in records}

    assert by_id["F00001"]["report_group"] == "confirmed_local"
    assert by_id["F00002"]["report_group"] == "behavioral"
    assert by_id["F00002"]["final_severity"] == "medium"


def test_write_scan_bundle_writes_expected_files(tmp_path):
    verified_doc = {
        "verifier": "codex-cli",
        "mode": "batch",
        "results": [
            {
                "finding_id": "F00002",
                "verdict": "false_positive",
                "adjusted_severity": "low",
                "final_severity": "low",
                "rationale": "tool activity substantiates the claim",
            }
        ],
        "true_positive": 0,
        "false_positive": 1,
        "uncertain": 0,
        "total_spend_usd": 0.02,
        "integrity_policy": "second-pass-self-review",
        "integrity_applied": False,
        "integrity_review_revisions": 0,
        "integrity_revisions": [],
    }

    paths = write_scan_bundle(tmp_path, _raw_doc(), verified_doc=verified_doc)

    assert paths["readme"].exists()
    assert paths["summary"].exists()
    assert paths["verified_findings"].exists()
    summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
    assert summary["verification"]["enabled"] is True
    assert summary["verified_behavioral_findings"] == 0
    verified = json.loads(paths["verified_findings"].read_text(encoding="utf-8"))
    by_id = {record["finding_id"]: record for record in verified}
    assert by_id["F00002"]["report_group"] == "raw_only"
