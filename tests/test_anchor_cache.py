"""Anchor caches must not confuse discarded regex objects with new expressions."""
import re

from agent_audit import session_rule_executor as executor


def test_discarded_regex_objects_cannot_supply_anchors_to_new_patterns(monkeypatch):
    monkeypatch.setattr(executor, "_anchor_cache", {})
    for index in range(200):
        re.purge()
        pattern = re.compile(f"(?:word{index:06d}a|word{index:06d}b)")
        text = f"word{index:06d}b"
        assert pattern.search(text)
        assert executor._passes_anchor_check(text, executor._anchors_for_pattern(pattern))
        del pattern


def test_anchor_cache_remains_bounded(monkeypatch):
    monkeypatch.setattr(executor, "_anchor_cache", {})
    monkeypatch.setattr(executor, "_ANCHOR_CACHE_LIMIT", 8)
    for index in range(50):
        executor._anchors_for_pattern(re.compile(f"(?:item{index}a|item{index}b)"))
    assert len(executor._anchor_cache) <= 8
