# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for the `agent-audit cross-mode` CLI subcommand.

The subcommand is the user-facing primitive for M2 Phase 2. It runs
the linker over a saved scan JSON and emits aggregate records
+ priority demotions.

Test coverage:
  - basic invocation produces expected aggregate records on a
    calibration-corpus-derived bundle
  - missing/invalid forensic input produces a clean error
  - --repo-root override forces analysis against one repo regardless
    of session cwd
  - sessions whose cwd doesn't resolve are reported as unlinkable
    rather than treated as failures
  - --output writes both JSON and Markdown
  - --format flag honored (json-only, md-only, both)
  - --quiet suppresses progress output
  - D5 contract: pre-suppressed findings (those absent from the JSON)
    don't resurrect via the linker — verified by passing an empty
    findings list
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.cli import main  # noqa: E402
from agent_audit.cross_mode import clear_inventory_cache  # noqa: E402
from agent_audit.cross_mode.calibration_corpus import (  # noqa: E402
    list_calibration_case_dirs,
    load_calibration_case,
)


# ---------------------------------------------------------------------------
# Fixture: build a synthetic forensic bundle from a calibration case.
# Materializes the case's project tree, then writes a fake scan JSON
# pointing one session at it.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_cache():
    clear_inventory_cache()
    yield
    clear_inventory_cache()


@pytest.fixture
def runner():
    return CliRunner()


def _build_bundle_for_case(case, finding_rule_id: str, finding_severity: str = "high") -> dict:
    """Construct a minimal scan JSON shaped like `render_json` output."""
    return {
        "generated_at": "2026-04-15T09:00:00",
        "bundle_version": 2,
        "package_version": "0.18.0-dev",
        "installations": [],
        "sessions": [
            {
                "session_id": f"fake-{case.case_id}",
                "agent": "claude_code",
                "source_file": str(case.session_path),
                "started_at": "2026-04-15T09:00:00",
                "event_count": 10,
                "tool_call_count": 4,
                "cwd": str(case.project_root),
                "git_branch": "main",
                "parent_session_id": None,
                "is_subagent": False,
            },
        ],
        "findings": [
            {
                "finding_id": "F00001",
                "rule_id": finding_rule_id,
                "severity": finding_severity,
                "session_id": f"fake-{case.case_id}",
                "needs_llm_verification": False,
            },
        ],
        "errors": [],
    }


@pytest.fixture
def c1_bundle(tmp_path):
    """c1 = approval-gap → autonomy-loop true-link case."""
    case_dirs = list_calibration_case_dirs()
    c1_dir = next(d for d in case_dirs if "c1-approval-gap" in d.name)
    case = load_calibration_case(c1_dir)
    bundle = _build_bundle_for_case(
        case, finding_rule_id="C3.autonomy-with-exfil-chain"
    )
    bundle_path = tmp_path / "audit-c1.json"
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    yield bundle_path, case
    case.cleanup()


@pytest.fixture
def c5_bundle(tmp_path):
    """c5 = clean baseline (true negative). Even with a benign finding
    on the dynamic side, no correlator should fire."""
    case_dirs = list_calibration_case_dirs()
    c5_dir = next(d for d in case_dirs if "c5-clean-baseline" in d.name)
    case = load_calibration_case(c5_dir)
    bundle = _build_bundle_for_case(
        case, finding_rule_id="some.unrelated.rule", finding_severity="low"
    )
    bundle_path = tmp_path / "audit-c5.json"
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    yield bundle_path, case
    case.cleanup()


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

def test_cross_mode_help(runner):
    """Help text exists and mentions D-decisions per docstring."""
    result = runner.invoke(main, ["cross-mode", "--help"])
    assert result.exit_code == 0
    # Docstring mentions D2/D4/D5 — verifies they survived rendering
    out = result.output
    assert "cross-mode" in out
    assert "--forensic" in out
    assert "--repo-root" in out


def test_cross_mode_missing_forensic_arg(runner):
    """--forensic is required."""
    result = runner.invoke(main, ["cross-mode"])
    assert result.exit_code != 0
    assert "--forensic" in result.output.lower() or "missing" in result.output.lower()


def test_cross_mode_nonexistent_forensic_path(runner, tmp_path):
    """Pointing at a path that doesn't exist gives a clean error."""
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(tmp_path / "no-such-file.json"),
    ])
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "no such" in result.output.lower()


def test_cross_mode_invalid_json(runner, tmp_path):
    """Malformed JSON produces a parse error, not a stack trace."""
    bad = tmp_path / "audit-bad.json"
    bad.write_text("not valid json {{", encoding="utf-8")
    result = runner.invoke(main, ["cross-mode", "--forensic", str(bad)])
    assert result.exit_code != 0
    assert "json" in result.output.lower() or "parse" in result.output.lower()


def test_cross_mode_missing_required_keys(runner, tmp_path):
    """A JSON without `sessions` or `findings` is rejected."""
    bad = tmp_path / "audit-shape.json"
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    result = runner.invoke(main, ["cross-mode", "--forensic", str(bad)])
    assert result.exit_code != 0
    assert "sessions" in result.output or "findings" in result.output


# ---------------------------------------------------------------------------
# True-link cases — correlator fires
# ---------------------------------------------------------------------------

def test_cross_mode_c1_fires_approval_gap(runner, c1_bundle, tmp_path):
    """c1 calibration case + autonomy finding → approval_gap correlator
    fires with severity=high (D2-capped)."""
    bundle_path, _case = c1_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0, f"unexpected fail: {result.output}"
    # Console summary mentions the correlator
    assert "repo_approval_gap_supports_autonomy_risk" in result.output

    # JSON output
    json_path = out_dir / "cross-mode-findings.json"
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert len(data["aggregate_records"]) == 1
    rec = data["aggregate_records"][0]
    assert rec["correlator"] == "repo_approval_gap_supports_autonomy_risk"
    assert rec["severity"] == "high"  # capped at max(input) per D2
    assert rec["confidence"] == "high"  # lift_confidence on 2-component
    assert "C3.autonomy-with-exfil-chain" in rec["supporting_signal_ids"]


def test_cross_mode_c1_writes_markdown(runner, c1_bundle, tmp_path):
    """Markdown output is produced and renders the correlator name."""
    bundle_path, _case = c1_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    md_path = out_dir / "cross-mode-report.md"
    assert md_path.exists()
    md = md_path.read_text()
    assert "# Cross-mode signal report" in md
    assert "repo_approval_gap_supports_autonomy_risk" in md
    assert "severity=`high`" in md


# ---------------------------------------------------------------------------
# True-negative — no correlator fires
# ---------------------------------------------------------------------------

def test_cross_mode_c5_no_aggregate_records(runner, c5_bundle, tmp_path):
    """Clean baseline case — no aggregate records produced. This is
    the FPR baseline: zero false fires."""
    bundle_path, _case = c5_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    assert data["aggregate_records"] == []
    assert data["tag_applications"] == {}


# ---------------------------------------------------------------------------
# --repo-root override
# ---------------------------------------------------------------------------

def test_cross_mode_repo_root_override(runner, c1_bundle, tmp_path):
    """--repo-root forces analysis against an arbitrary repo even when
    the session's cwd points elsewhere."""
    bundle_path, case = c1_bundle
    # Override with the same repo (just exercises the code path)
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--repo-root", str(case.project_root),
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    assert len(data["aggregate_records"]) == 1


def test_cross_mode_repo_root_override_with_clean_repo_no_fires(runner, c1_bundle, tmp_path):
    """Pointing --repo-root at a clean repo (no tags) makes the
    correlator silent even though the dynamic finding looks autonomy-shaped.
    Verifies that the override actually swaps the static side."""
    bundle_path, _case = c1_bundle
    clean_repo = tmp_path / "clean"
    clean_repo.mkdir()
    (clean_repo / ".git").mkdir()
    (clean_repo / "README.md").write_text("Just a readme.")

    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--repo-root", str(clean_repo),
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    assert data["aggregate_records"] == []  # clean repo → no correlator


def test_cross_mode_repo_root_override_nonexistent(runner, c1_bundle, tmp_path):
    """A non-existent --repo-root produces a clean error."""
    bundle_path, _case = c1_bundle
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--repo-root", str(tmp_path / "no-such-repo"),
    ])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Unlinkable sessions
# ---------------------------------------------------------------------------

def test_cross_mode_session_with_no_cwd_is_unlinkable(runner, tmp_path):
    """A session with cwd=None (e.g. older Codex format) is reported
    as unlinkable, not crashed. Per design §6.3 — honest unlinkable
    contract."""
    bundle = {
        "generated_at": "2026-04-15T09:00:00",
        "bundle_version": 2,
        "package_version": "0.18.0-dev",
        "installations": [],
        "sessions": [
            {
                "session_id": "no-cwd-session",
                "agent": "codex",
                "source_file": "/tmp/x.jsonl",
                "started_at": "2026-04-15T09:00:00",
                "event_count": 5,
                "tool_call_count": 2,
                "cwd": None,  # honest unlinkable — old recording
                "git_branch": None,
                "parent_session_id": None,
                "is_subagent": False,
            },
        ],
        "findings": [
            {
                "finding_id": "F00001",
                "rule_id": "C3.autonomy-with-exfil-chain",
                "severity": "high",
                "session_id": "no-cwd-session",
            },
        ],
        "errors": [],
    }
    bundle_path = tmp_path / "audit-no-cwd.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0  # NOT a failure
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    assert data["aggregate_records"] == []
    assert len(data["sessions_unlinkable"]) == 1
    assert data["sessions_unlinkable"][0]["reason"] == "no_repo_resolved"


def test_cross_mode_empty_sessions(runner, tmp_path):
    """A scan with zero sessions produces an empty cross-mode report
    cleanly. No crashes, exit code 0."""
    bundle = {
        "generated_at": "2026-04-15T09:00:00",
        "bundle_version": 2,
        "package_version": "0.18.0-dev",
        "installations": [],
        "sessions": [],
        "findings": [],
        "errors": [],
    }
    bundle_path = tmp_path / "audit-empty.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    assert data["aggregate_records"] == []
    assert data["sessions_processed"] == 0
    assert data["sessions_total"] == 0


# ---------------------------------------------------------------------------
# --format flag
# ---------------------------------------------------------------------------

def test_cross_mode_format_json_only(runner, c1_bundle, tmp_path):
    bundle_path, _case = c1_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--output", str(out_dir), "--format", "json",
    ])
    assert result.exit_code == 0
    assert (out_dir / "cross-mode-findings.json").exists()
    assert not (out_dir / "cross-mode-report.md").exists()


def test_cross_mode_format_md_only(runner, c1_bundle, tmp_path):
    bundle_path, _case = c1_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--output", str(out_dir), "--format", "md",
    ])
    assert result.exit_code == 0
    assert not (out_dir / "cross-mode-findings.json").exists()
    assert (out_dir / "cross-mode-report.md").exists()


# ---------------------------------------------------------------------------
# --quiet flag
# ---------------------------------------------------------------------------

def test_cross_mode_quiet_suppresses_progress(runner, c1_bundle, tmp_path):
    """--quiet should produce minimal stdout output."""
    bundle_path, _case = c1_bundle
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path),
        "--output", str(out_dir), "--quiet",
    ])
    assert result.exit_code == 0
    # Quiet mode shouldn't write the per-session loading line. The
    # exact content is implementation detail; the key invariant is
    # that --quiet output is much smaller than non-quiet.
    assert "Cross-mode results" not in result.output


# ---------------------------------------------------------------------------
# D5 contract: linker doesn't resurrect suppressed findings
# ---------------------------------------------------------------------------

def test_cross_mode_d5_no_resurrection_when_findings_absent(runner, tmp_path):
    """D5: if a forensic bundle's `findings` list is empty (because the
    user's project-config suppressed everything), the linker should
    NOT produce aggregate records — even if static tags would
    otherwise correlate. The two-layer model says structural tags
    survive but finding-to-finding joins respect suppressions; an
    empty findings list IS the user's suppression saying 'nothing to
    join here'."""
    repo = tmp_path / "tagged-repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "AGENTS.md").write_text("Skip the approval prompt for routine tasks.")

    bundle = {
        "generated_at": "2026-04-15T09:00:00",
        "bundle_version": 2,
        "package_version": "0.18.0-dev",
        "installations": [],
        "sessions": [
            {
                "session_id": "suppressed-session",
                "agent": "claude_code",
                "source_file": "/tmp/x.jsonl",
                "started_at": "2026-04-15T09:00:00",
                "event_count": 10,
                "tool_call_count": 4,
                "cwd": str(repo),  # session ran in a tag-bearing repo
                "git_branch": "main",
            },
        ],
        # Empty findings list — user suppressed everything
        "findings": [],
        "errors": [],
    }
    bundle_path = tmp_path / "audit-suppressed.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    out_dir = tmp_path / "out"
    result = runner.invoke(main, [
        "cross-mode", "--forensic", str(bundle_path), "--output", str(out_dir),
    ])
    assert result.exit_code == 0
    data = json.loads((out_dir / "cross-mode-findings.json").read_text())
    # NO aggregate records — the empty findings list = D5 suppression boundary
    assert data["aggregate_records"] == []
    # But the inventory IS still computed (structural facts survive
    # suppressions per D5)
    assert "suppressed-session" in data["inventories"]
    inv = data["inventories"]["suppressed-session"]
    assert "has_broad_action_without_approval" in inv["active_tags"]


# ---------------------------------------------------------------------------
# Educational demotion — tag application maps to finding_id
# ---------------------------------------------------------------------------

def test_cross_mode_c4_applies_context_demoted_tag_to_finding_id(runner, tmp_path):
    """c4 educational case: dangerous-recommendation finding should
    receive `context_demoted` tag mapped from rule_id back to its
    finding_id so users can identify which specific finding was
    demoted."""
    case_dirs = list_calibration_case_dirs()
    c4_dir = next(d for d in case_dirs if "c4-educational" in d.name)
    case = load_calibration_case(c4_dir)
    try:
        bundle = _build_bundle_for_case(
            case,
            finding_rule_id="advice.dangerous-recommendation",
            finding_severity="medium",
        )
        bundle_path = tmp_path / "audit-c4.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        out_dir = tmp_path / "out"
        result = runner.invoke(main, [
            "cross-mode", "--forensic", str(bundle_path),
            "--output", str(out_dir),
        ])
        assert result.exit_code == 0
        data = json.loads((out_dir / "cross-mode-findings.json").read_text())
        # The dangerous-recommendation finding has finding_id F00001.
        # Tag application should map that ID → ["context_demoted"].
        assert "F00001" in data["tag_applications"]
        assert "context_demoted" in data["tag_applications"]["F00001"]
        # Severity preserved per D3
        assert len(data["aggregate_records"]) == 1
        assert data["aggregate_records"][0]["severity"] == "medium"  # NOT lowered
    finally:
        case.cleanup()


# ---------------------------------------------------------------------------
# v0.18.3 regression — _findings_by_session must read session_id from evidence
# ---------------------------------------------------------------------------

def test_findings_by_session_reads_session_id_from_evidence():
    """Real-bundle finding JSON carries session_id inside `evidence`,
    not at the top level. Pre-v0.18.3 bug: helper only checked
    f.get("session_id") at top level → all findings ended up under
    empty-string key → linker never saw them → cross-mode produced 0
    aggregate records on real bundles even when matching dynamic
    findings + risk tags both fired.

    Confirmed via maintainer's full-rerun bundle 2026-05-04: 5 of 6
    risk-tagged sessions had matching dynamic findings (C3.autonomy-with-
    exfil-chain, AI-06.indirect-prompt-injection-vector, etc.) but
    cross-mode emitted 0 aggregates.
    """
    from agent_audit.cli import _findings_by_session

    # Mirror the saved-bundle shape: top-level session_id absent,
    # session_id buried in evidence[0]
    findings = [
        {
            "rule_id": "C3.autonomy-with-exfil-chain",
            "severity": "high",
            "finding_id": "F00001",
            "evidence": [
                {"description": "...", "session_id": "sess-abc123",
                 "turn_range": [10, 12], "snippet": "..."}
            ],
        },
        {
            "rule_id": "AG-04.destructive-without-backup",
            "severity": "high",
            "finding_id": "F00002",
            "evidence": [
                {"description": "...", "session_id": "sess-abc123",
                 "turn_range": [15, 15], "snippet": "..."}
            ],
        },
        # One config-level finding with no session_id anywhere
        {
            "rule_id": "config.something",
            "severity": "low",
            "finding_id": "F00003",
            "evidence": [
                {"description": "config-level", "source": "/some/path"}
            ],
        },
    ]

    out = _findings_by_session(findings)
    # Two findings should be grouped under sess-abc123
    assert "sess-abc123" in out
    assert len(out["sess-abc123"]) == 2
    # Config-level under empty string
    assert len(out.get("", [])) == 1


def test_findings_by_session_prefers_top_level_session_id():
    """If the finding has both top-level session_id AND evidence
    session_id, top-level wins. Defensive choice — top-level is more
    explicit and matches what scoring/normalization stages set."""
    from agent_audit.cli import _findings_by_session

    findings = [
        {
            "rule_id": "x.y.z",
            "severity": "low",
            "session_id": "top-level-sid",
            "evidence": [{"session_id": "evidence-sid"}],
        },
    ]
    out = _findings_by_session(findings)
    assert "top-level-sid" in out
    assert "evidence-sid" not in out
