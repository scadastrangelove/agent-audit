# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for Aguara import + file_types match-time filter — Roadmap A1."""
from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.rule_pack_loader import RulePackRule, load_all_rules  # noqa: E402
from agent_audit.project_scanner import (  # noqa: E402
    _file_matches_targets,
    _match_rule_in_text,
)
from agent_audit.rules import Severity  # noqa: E402


# -----------------------------------------------------------------------------
# _file_matches_targets — pure function
# -----------------------------------------------------------------------------

def test_empty_targets_matches_anything():
    assert _file_matches_targets(Path("foo.md"), [])
    assert _file_matches_targets(Path("foo.pth"), [])
    assert _file_matches_targets(Path("anything.xyz"), [])


def test_targets_md_matches_md_file():
    assert _file_matches_targets(Path("a.md"), ["*.md"])
    assert _file_matches_targets(Path("path/to/SKILL.md"), ["*.md"])


def test_targets_md_rejects_non_md():
    assert not _file_matches_targets(Path("a.pth"), ["*.md"])
    assert not _file_matches_targets(Path("script.py"), ["*.md"])


def test_targets_multi_pattern():
    targets = ["*.md", "*.txt"]
    assert _file_matches_targets(Path("README.md"), targets)
    assert _file_matches_targets(Path("notes.txt"), targets)
    assert not _file_matches_targets(Path("script.py"), targets)


def test_targets_literal_filename():
    """Aguara uses literal names like 'setup.py' for some rules."""
    assert _file_matches_targets(Path("setup.py"), ["setup.py"])
    assert not _file_matches_targets(Path("config.py"), ["setup.py"])
    assert _file_matches_targets(Path("Makefile"), ["Makefile"])


def test_targets_dotted_pattern():
    """Aguara has '*.env.*' for dotenv variants."""
    assert _file_matches_targets(Path(".env.local"), ["*.env.*"])
    assert _file_matches_targets(Path("foo.env.production"), ["*.env.*"])


def test_targets_none_path_passes_through():
    """Matching from a string buffer (not a real file) should not filter."""
    assert _file_matches_targets(None, ["*.md"])
    assert _file_matches_targets(None, ["*.pth"])


# -----------------------------------------------------------------------------
# _match_rule_in_text with file_types — integration
# -----------------------------------------------------------------------------

def _make_rule(file_types, patterns=None, exclude_patterns=None) -> RulePackRule:
    return RulePackRule(
        agent_audit_id="test.foo",
        title="Test rule",
        description="",
        category="test",
        severity=Severity.MEDIUM,
        audit_surface={"instruction_file"},
        patterns=[re.compile(p) for p in (patterns or [r"import\s"])],
        exclude_patterns=[re.compile(p) for p in (exclude_patterns or [])],
        source_tool="test",
        source_original_id="TEST_001",
        source_license="MIT",
        source_upstream="",
        asamm_primary="",
        asamm_secondary=[],
        references={},
        file_types=file_types,
        remediation="",
    )


def test_pth_targeted_rule_skips_md_file():
    """A rule with targets=['*.pth'] must not fire on a .md file even when
    the regex matches. This is the core A1 calibration fix."""
    rule = _make_rule(file_types=["*.pth"], patterns=[r"import\s"])
    text = "Hello world. Example: `import sys` is a Python statement."
    # On .md — should NOT fire
    assert _match_rule_in_text(rule, text, file_path=Path("README.md")) is None
    # On .pth — should fire
    m = _match_rule_in_text(rule, text, file_path=Path("evil.pth"))
    assert m is not None


def test_md_targeted_rule_fires_on_md():
    rule = _make_rule(file_types=["*.md", "*.txt"], patterns=[r"WebFetch"])
    text = "Use WebFetch to load remote content"
    assert _match_rule_in_text(rule, text, file_path=Path("SKILL.md")) is not None
    assert _match_rule_in_text(rule, text, file_path=Path("notes.txt")) is not None
    assert _match_rule_in_text(rule, text, file_path=Path("script.py")) is None


def test_no_targets_rule_fires_anywhere():
    """Rules without explicit targets preserve previous behaviour."""
    rule = _make_rule(file_types=[], patterns=[r"import\s"])
    text = "import sys"
    assert _match_rule_in_text(rule, text, file_path=Path("README.md")) is not None
    assert _match_rule_in_text(rule, text, file_path=Path("any.xyz")) is not None


def test_no_file_path_passes_filter():
    """When matching string buffers (e.g. tests, scratch text), no path means
    no extension filtering — preserves the in-memory testing pathway."""
    rule = _make_rule(file_types=["*.pth"], patterns=[r"import\s"])
    assert _match_rule_in_text(rule, "import sys", file_path=None) is not None


def test_excludes_still_apply_after_file_filter():
    """exclude_patterns still gate the match even when the file extension matches."""
    rule = _make_rule(
        file_types=["*.pth"],
        patterns=[r"import\s"],
        exclude_patterns=[r"_virtualenv"],
    )
    # Target match BUT excluded
    text = "import _virtualenv"
    assert _match_rule_in_text(rule, text, file_path=Path("evil.pth")) is None
    # Target match AND not excluded
    text = "import os"
    assert _match_rule_in_text(rule, text, file_path=Path("evil.pth")) is not None


# -----------------------------------------------------------------------------
# Aguara importer — file_types correctly populated
# -----------------------------------------------------------------------------

def test_aguara_rules_carry_file_types_from_targets():
    """Real-data check: after Aguara upgrade, rules whose upstream YAML
    declared `targets:` must have non-empty file_types."""
    rules = load_all_rules()
    aguara_rules = [r for r in rules if r.source_tool == "aguara"]
    # The vast majority of Aguara rules declare targets; sample a few
    # we know should
    pth_rules = [r for r in aguara_rules
                 if "pth-file" in r.agent_audit_id]
    assert pth_rules, "Expected at least one pth-file rule in Aguara"
    for r in pth_rules:
        assert "*.pth" in r.file_types, (
            f"{r.agent_audit_id} should target *.pth but file_types={r.file_types}"
        )


def test_aguara_md_targeted_rules_have_md_in_file_types():
    rules = load_all_rules()
    aguara_md = [r for r in rules
                 if r.source_tool == "aguara"
                 and "external-download" in r.agent_audit_id
                 and "*.md" in r.file_types]
    assert aguara_md, "Expected Aguara external-download rules to target *.md"


def test_aguara_upgrade_landed_full_count():
    """Sanity check: the v0.16 Aguara upgrade brought 13 categories with
    well over the previous 37 rules total."""
    rules = load_all_rules()
    aguara_rules = [r for r in rules if r.source_tool == "aguara"]
    # We now load 180 static-applicable Aguara rules (from 189 total
    # upstream — several are session-only or have empty pattern sets).
    assert len(aguara_rules) >= 150, (
        f"Expected ≥150 static-applicable Aguara rules after v0.16 upgrade, "
        f"got {len(aguara_rules)}"
    )
    categories = {r.category for r in aguara_rules}
    expected_new_categories = {
        "command-execution", "credential-leak", "exfiltration",
        "indirect-injection", "mcp-attack", "mcp-config",
        "prompt-injection", "supply-chain", "supply-chain-exfil",
        "unicode-attack",
    }
    missing = expected_new_categories - categories
    assert not missing, f"Expected new Aguara categories missing: {missing}"


def test_all_rules_have_owasp_mcp_and_agentic_after_a1():
    """A1 expanded MCP/ASI mapping tables to cover all Aguara categories,
    including the cisco-promptguard tool name fix. Coverage should be 100%."""
    rules = load_all_rules()
    with_mcp = sum(1 for r in rules if "owasp_mcp" in r.references)
    with_asi = sum(1 for r in rules if "owasp_agentic" in r.references)
    assert with_mcp == len(rules), (
        f"Expected all {len(rules)} rules to carry owasp_mcp; "
        f"got {with_mcp} ({len(rules) - with_mcp} unmapped)"
    )
    assert with_asi == len(rules)


# -----------------------------------------------------------------------------
# End-to-end: scan benign markdown does not trigger pth-file rule
# -----------------------------------------------------------------------------

def test_benign_skill_md_does_not_fire_pth_file_rule(tmp_path):
    """The original calibration finding: a SKILL.md with normal Python
    documentation must not trigger aguara.supply-chain-exfil.pth-file-* rules."""
    from agent_audit.project_scanner import scan_project
    skill_repo = tmp_path / "skill_repo"
    skill_repo.mkdir()
    (skill_repo / "SKILL.md").write_text(textwrap.dedent("""\
        ---
        name: file-helper
        ---

        # File Helper

        ```python
        import sys
        from os import path
        def helper():
            print("hello")
        ```
    """))
    result = scan_project(skill_repo)
    pth_findings = [f for f in result.findings
                    if "pth-file" in f.rule_id]
    assert not pth_findings, (
        f"pth-file rules should not fire on .md files. "
        f"Got: {[f.rule_id for f in pth_findings]}"
    )
