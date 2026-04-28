"""Lightweight natural-language understanding utilities.

Pure stdlib, no external dependencies (no spaCy, no transformers). These
modules handle sentence-level tasks that go beyond regex but don't warrant
a full NLP stack:

- claim_detector: score-based completion claim detection
- taint: source/sink classification for events in autonomy windows
- filters: quote/log/code block detection to skip non-content

Built from real false-positive feedback on the v0.7.0 release scan
(108 sessions, 256 findings verified by codex-cli).
"""
from . import claim_detector, taint, filters

__all__ = ["claim_detector", "taint", "filters"]
