"""BEC-003: Thread Participant Anomaly detection."""

from __future__ import annotations

from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class ThreadParticipantAnomalyRule(DetectionRule):
    """Detect unexpected participants in an email conversation."""

    rule_id = "BEC-003"
    rule_name = "Thread Participant Anomaly"
    severity = "HIGH"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate the current thread against known participants."""

        current_participants = context.participants
        known_participants = context.known_participants

        known = {
            participant.lower()
            for participant in known_participants
        }

        new_participants = sorted(
            participant
            for participant in current_participants
            if participant.lower() not in known
        )

        indicators: list[str] = []

        if new_participants:
            indicators.append(
                "Unexpected participant detected in conversation"
            )

        matched = bool(new_participants)

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "new_participants": new_participants,
            "known_participants": sorted(known),
        }
