"""Behavioral signal — user interruptions.

When the user repeatedly says "stop", "no", "undo" etc., that's direct ground
truth that the agent was doing something the user didn't want. Unique signal
— no other security tool uses it because it requires looking at chat history.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from ..events import EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)

# Phrases in user messages that indicate the user is stopping / correcting the agent.
# Both English and Russian — our initial audience is bilingual.
INTERRUPT_PHRASES = [
    # English
    r"\bstop\b",
    r"\bwait\b",
    r"\bhold on\b",
    r"\bundo\b",
    r"\brevert\b",
    r"\bno,? don'?t\b",
    r"\bthat'?s not (?:what|right)\b",
    r"\bwhy did you\b",
    r"\bwhy are you\b",
    r"\bdon'?t do that\b",
    r"\brollback\b",
    # Russian
    r"\bстоп\b",
    r"\bподожди\b",
    r"\bверни\b",
    r"\bне надо\b",
    r"\bне то\b",
    r"\bзачем ты\b",
    r"\bпочему ты\b",
    r"\bотмени\b",
    r"\bостановись\b",
    r"\bне так\b",
]

INTERRUPT_PATTERN = re.compile("|".join(INTERRUPT_PHRASES), re.IGNORECASE)

DEFAULT_MIN_COUNT = 3


class UserInterruptions(Rule):
    id = "behavior.user-interruptions"
    title = "User repeatedly interrupted or corrected the agent"
    severity = Severity.MEDIUM
    references = ["ASAMM AO-02 (Intent–Action Gap)"]

    def __init__(self, min_count: int = DEFAULT_MIN_COUNT) -> None:
        self.min_count = min_count

    def check_session(self, session: Session) -> Iterable[Finding]:
        matches: List[Tuple[int, str]] = []
        user_msg_count = 0

        for event in session.events:
            if event.type != EventType.USER_MESSAGE or not event.text:
                continue
            user_msg_count += 1
            text = event.text.strip()
            if not text or len(text) > 500:
                # Long messages are probably not interruptions; focus on short corrective ones
                continue
            m = INTERRUPT_PATTERN.search(text)
            if m:
                matches.append((event.turn_index, text[:120]))

        # Require both:
        #   1. At least min_count matches (absolute)
        #   2. At least 10% of user messages are interruptions (relative)
        # Or: 3+ interruptions in a cluster of 5 consecutive user messages
        if len(matches) < self.min_count:
            return

        # Ratio check — avoids false positives in long sessions
        ratio = len(matches) / user_msg_count if user_msg_count else 0
        has_cluster = self._has_cluster(matches, cluster_size=5, min_in_cluster=3)

        if ratio < 0.1 and not has_cluster:
            return

        severity = Severity.HIGH if ratio >= 0.3 or len(matches) >= self.min_count * 2 else Severity.MEDIUM

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                f"Found {len(matches)} user interruptions out of {user_msg_count} "
                f"user messages ({int(ratio * 100)}%)"
                + (" with clusters" if has_cluster else "")
                + " — agent's behavior didn't match user's intent."
            ),
            evidence=[
                Evidence(
                    description=f"Interruption at turn {turn}",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(turn, turn),
                    snippet=snippet,
                )
                for turn, snippet in matches[:5]
            ],
            remediation=(
                "Review recent sessions for the triggering actions. Consider "
                "narrowing the agent's tool scope or adding deny rules for the "
                "patterns that led to the interruptions."
            ),
            references=self.references,
        )

    @staticmethod
    def _has_cluster(matches: List[Tuple[int, str]], cluster_size: int, min_in_cluster: int) -> bool:
        """True if any window of `cluster_size` consecutive turns contains
        at least `min_in_cluster` interruption matches."""
        if len(matches) < min_in_cluster:
            return False
        turns = sorted(t for t, _ in matches)
        for i in range(len(turns) - min_in_cluster + 1):
            # Are `min_in_cluster` matches within `cluster_size * 2` turns of each other?
            # We use *2 because between user messages there are agent turns too.
            window = turns[i + min_in_cluster - 1] - turns[i]
            if window <= cluster_size * 4:  # heuristic: 4 turns per user message avg
                return True
        return False


register_session_rule(UserInterruptions())
