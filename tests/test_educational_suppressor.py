"""Unit tests for knowledge/educational_suppressor.py."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.educational_suppressor import (  # noqa: E402
    is_educational_context,
    demote_severity,
)


def test_translations_dir_triggers():
    assert is_educational_context(Path("/project/translations/en/README.md"), "text")
    assert is_educational_context(Path("/project/translations/zh-CN/docs/intro.md"), "")
    print("  ✓ translations/* triggers")


def test_i18n_dir_triggers():
    assert is_educational_context(Path("/project/i18n/ru/about.md"), "text")
    print("  ✓ i18n/ triggers")


def test_locale_dir_triggers():
    assert is_educational_context(Path("/project/locales/fr/file.md"), "")
    assert is_educational_context(Path("/project/locale/de/file.md"), "")
    print("  ✓ locale[s]/ triggers")


def test_docs_lang_subdir_triggers():
    assert is_educational_context(Path("/project/docs/zh-CN/guide.md"), "")
    assert is_educational_context(Path("/project/docs/fr/guide.md"), "")
    assert is_educational_context(Path("/project/docs/pt-BR/guide.md"), "")
    print("  ✓ docs/<lang>/ triggers")


def test_tutorial_lesson_lab_triggers():
    assert is_educational_context(Path("/project/tutorial/01-intro.md"), "")
    assert is_educational_context(Path("/project/tutorials/01-intro.md"), "")
    assert is_educational_context(Path("/project/lessons/A/intro.md"), "")
    assert is_educational_context(Path("/project/labs/session-1/walkthrough.md"), "")
    print("  ✓ tutorial/lesson/lab triggers")


def test_for_beginners_trigger():
    assert is_educational_context(
        Path("/repos/microsoft/generative-ai-for-beginners/01-intro/readme.md"), ""
    )
    assert is_educational_context(Path("/ml-for-beginners/04-lesson/file.md"), "")
    print("  ✓ *-for-beginners triggers")


def test_regular_docs_do_not_trigger():
    assert not is_educational_context(Path("/project/docs/api-reference.md"), "")
    assert not is_educational_context(Path("/project/README.md"), "")
    assert not is_educational_context(Path("/project/src/main.py"), "")
    print("  ✓ regular docs/README do not trigger")


def test_skills_dir_does_not_trigger():
    # A real agent skill under /skills/ must not be suppressed
    assert not is_educational_context(Path("/project/skills/my-skill/SKILL.md"), "")
    assert not is_educational_context(
        Path("/project/.claude/skills/my-skill/SKILL.md"), ""
    )
    print("  ✓ /skills/ and .claude/ do not trigger suppression")


def test_structural_marker_overrides_path():
    """If SKILL.md has frontmatter, even under /translations/ it's treated as real."""
    # Path would suggest suppression, but frontmatter overrides
    skill_with_frontmatter = """---
name: localised-skill
description: A skill translated to French
---

# Main content
"""
    result = is_educational_context(
        Path("/project/translations/fr/SKILL.md"), skill_with_frontmatter
    )
    assert not result, "Frontmatter should override path-based suppression"
    print("  ✓ SKILL.md frontmatter overrides path suppression")


def test_mcp_manifest_overrides_path():
    mcp_config = '{"mcpServers": {"my-server": {"command": "node"}}}'
    result = is_educational_context(
        Path("/project/translations/mcp.json"), mcp_config
    )
    assert not result
    print("  ✓ MCP manifest structure overrides path")


def test_demote_severity():
    assert demote_severity("critical") == "high"
    assert demote_severity("high") == "medium"
    assert demote_severity("medium") == "low"
    assert demote_severity("low") == "info"
    assert demote_severity("info") == "info"  # floor
    assert demote_severity("unknown") == "unknown"  # unchanged
    print("  ✓ demote_severity ladder")


def test_case_insensitive_path_matching():
    assert is_educational_context(Path("/project/Translations/EN/doc.md"), "")
    assert is_educational_context(Path("/project/TUTORIAL/x.md"), "")
    print("  ✓ case-insensitive path match")


def run_all():
    tests = [
        test_translations_dir_triggers,
        test_i18n_dir_triggers,
        test_locale_dir_triggers,
        test_docs_lang_subdir_triggers,
        test_tutorial_lesson_lab_triggers,
        test_for_beginners_trigger,
        test_regular_docs_do_not_trigger,
        test_skills_dir_does_not_trigger,
        test_structural_marker_overrides_path,
        test_mcp_manifest_overrides_path,
        test_demote_severity,
        test_case_insensitive_path_matching,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: assertion failed: {e}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"Passed: {passed}/{len(tests)}")
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    run_all()
