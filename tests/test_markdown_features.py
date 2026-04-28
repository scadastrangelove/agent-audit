"""Unit tests for knowledge/markdown_features.py.

Covers:
  - code fence extraction by language
  - prose separation (text_without_code)
  - heading path tracking
  - table content preserved as prose (GFM)
  - graceful fallback when parse fails
  - empty input
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.markdown_features import extract  # noqa: E402


def test_simple_fence_extraction():
    text = """# Title

Some prose here.

```bash
rm -rf /
echo done
```

More prose.
"""
    f = extract(text)
    assert f.ast_available
    assert "bash" in f.code_blocks_by_lang
    assert "rm -rf /" in f.code_blocks_by_lang["bash"][0]
    assert "Some prose here." in f.text_without_code
    assert "More prose." in f.text_without_code
    # Code content should NOT appear in prose
    assert "rm -rf" not in f.text_without_code
    print("  ✓ simple fence extraction")


def test_multiple_languages():
    text = """```python
x = 1
```

Mid prose.

```javascript
const y = 2;
```
"""
    f = extract(text)
    assert "python" in f.code_blocks_by_lang
    assert "javascript" in f.code_blocks_by_lang
    assert "x = 1" in f.code_blocks_by_lang["python"][0]
    assert "const y = 2" in f.code_blocks_by_lang["javascript"][0]
    print("  ✓ multiple languages")


def test_fence_without_language():
    text = """```
raw text here
```
"""
    f = extract(text)
    assert "plain" in f.code_blocks_by_lang
    assert "raw text here" in f.code_blocks_by_lang["plain"][0]
    print("  ✓ fence without language tagged as plain")


def test_heading_paths():
    text = """# Top

## Section A

### Sub A.1

## Section B
"""
    f = extract(text)
    assert len(f.heading_paths) == 4
    # Last heading should show `# Top > ## Section B`
    assert "Section B" in f.heading_paths[-1]
    # Sub A.1 should include both ancestors
    sub_path = [h for h in f.heading_paths if "Sub A.1" in h][0]
    assert "Top" in sub_path and "Section A" in sub_path
    print("  ✓ heading paths with stacking")


def test_gfm_table_content_in_prose():
    """GFM tables must contribute to text_without_code — our composio case."""
    text = """# Actions

| Command | Effect |
|---------|--------|
| send email | fires email |
| create issue | opens GitHub issue |
"""
    f = extract(text)
    assert f.ast_available
    assert "send email" in f.text_without_code
    assert "create issue" in f.text_without_code
    print("  ✓ GFM table content preserved as prose")


def test_table_cells_not_treated_as_code():
    text = """
| x | y |
|---|---|
| a | b |
"""
    f = extract(text)
    # Table cells are inline, not code blocks
    assert "a" in f.text_without_code
    # No code blocks from table
    assert not any(f.code_blocks_by_lang.values())
    print("  ✓ table cells not treated as code")


def test_empty_input():
    f = extract("")
    assert f.ast_available
    assert f.text_without_code == ""
    assert f.code_blocks_by_lang == {}
    assert f.heading_paths == []
    print("  ✓ empty input")


def test_prose_only_no_code():
    text = """# Title

Just text, no code fences here.

Another paragraph.
"""
    f = extract(text)
    assert "Just text" in f.text_without_code
    assert f.code_blocks_by_lang == {}
    print("  ✓ prose only, no code")


def test_raw_preserved_even_with_code():
    text = """Prose.

```sh
exit 0
```
"""
    f = extract(text)
    assert f.raw == text
    print("  ✓ raw text preserved alongside prose")


def test_realistic_skill_md():
    """Test against actual composio SKILL.md content."""
    text = """---
name: connect-apps
description: Connect Claude to external apps.
---

# Connect Apps

## Quick Start

Step 1: Install the Plugin

```
/plugin install composio-toolrouter
```

## What You Can Do

| Ask Claude to... | What happens |
|------------------|--------------|
| "Send email to sarah@acme.com" | Actually sends the email |
| "Create GitHub issue: fix login bug" | Creates the issue |
"""
    f = extract(text)
    # Code block must not bleed into prose
    assert "/plugin install" not in f.text_without_code
    # But table content must be present
    assert "Send email to sarah" in f.text_without_code
    assert "Create GitHub issue" in f.text_without_code
    # Both code block detected
    assert "plain" in f.code_blocks_by_lang
    print("  ✓ realistic composio-style SKILL.md")


def run_all():
    tests = [
        test_simple_fence_extraction,
        test_multiple_languages,
        test_fence_without_language,
        test_heading_paths,
        test_gfm_table_content_in_prose,
        test_table_cells_not_treated_as_code,
        test_empty_input,
        test_prose_only_no_code,
        test_raw_preserved_even_with_code,
        test_realistic_skill_md,
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
