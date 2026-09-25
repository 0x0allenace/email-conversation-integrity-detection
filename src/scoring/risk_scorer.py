"""Risk scoring for Email Conversation Integrity Detection."""

from __future__ import annotations

from typing import Any


class RiskScorer:
    """Calculate explainable risk scores."""

    def score(
        self,
        *,
        rule_matched: bool,
        domain_mismatch: bool = False,
        display_name_match: bool = False,
        authentication_failure: bool = False,
        unexpected_participant: bool = False,
        infrastructure_anomaly: bool = False,
        thread_reuse_anomaly: bool = False,
        behavioral_anomaly: bool = False,
    ) -> int:
        """Calculate a risk score from detection indicators."""

        if not rule_matched:
            return 0

        score = 0

        if domain_mismatch:
            score += 50

        if display_name_match:
            score += 20

        if authentication_failure:
            score += 30

        if unexpected_participant:
            score += 30

        if infrastructure_anomaly:
            score += 20

        if thread_reuse_anomaly:
            score += 20

        if behavioral_anomaly:
            score += 20

        return min(score, 100)

    def score_detection(
        self,
        detection: dict[str, Any],
        *,
        authentication_failure: bool = False,
    ) -> int:
        """Calculate a risk score from a detection result."""

        rule_id = detection["rule_id"]

        if rule_id == "BEC-001":
            return self.score(
                rule_matched=detection["matched"],
                domain_mismatch=(
                    detection["observed_domain"].lower()
                    != detection["known_domain"].lower()
                ),
                display_name_match=(
                    "Display name matches known participant"
                    in detection["indicators"]
                ),
                authentication_failure=authentication_failure,
            )

        if rule_id == "BEC-002":
            return self.score(
                rule_matched=detection["matched"],
                domain_mismatch=(
                    detection["from_domain"]
                    != detection["reply_to_domain"]
                ),
            )

        if rule_id == "BEC-003":
            return self.score(
                rule_matched=detection["matched"],
                unexpected_participant=(
                    "Unexpected participant detected in conversation"
                    in detection["indicators"]
                ),
            )

        if rule_id == "BEC-004":
            return self.score(
                rule_matched=detection["matched"],
                authentication_failure=authentication_failure,
            )

        if rule_id == "BEC-005":
            return self.score(
                rule_matched=detection["matched"],
                infrastructure_anomaly=detection["matched"],
            )

        if rule_id == "BEC-006":
            return self.score(
                rule_matched=detection["matched"],
                thread_reuse_anomaly=(
                    "Message contains existing conversation thread headers"
                    in detection["indicators"]
                ),
            )

        if rule_id == "BEC-007":
            return self.score(
                rule_matched=detection["matched"],
                behavioral_anomaly=detection["matched"],
            )

        return 0
