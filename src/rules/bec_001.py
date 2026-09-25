"""BEC-001: Lookalike Domain detection."""

from __future__ import annotations

from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule
from src.identity.domain_similarity import is_lookalike_domain


class LookalikeDomainRule(DetectionRule):
    """Detect possible sender impersonation through domain similarity."""

    rule_id = "BEC-001"
    rule_name = "Lookalike Domain"
    severity = "HIGH"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate a sender against a known trusted identity."""

        identity = context.identity
        known_domain = context.known_domain
        known_display_name = context.known_display_name

        observed_domain = identity.get("domain", "")
        observed_name = identity.get("display_name", "")

        indicators: list[str] = []

        display_name_match = (
            bool(known_display_name)
            and observed_name.lower()
            == known_display_name.lower()
        )

        domain_mismatch = (
            bool(observed_domain)
            and bool(known_domain)
            and observed_domain.lower()
            != known_domain.lower()
        )

        lookalike = is_lookalike_domain(
            observed_domain,
            known_domain,
        )

        if display_name_match:
            indicators.append(
                "Display name matches known participant"
            )

        if domain_mismatch:
            indicators.append(
                "Sender domain differs from known domain"
            )

        if lookalike:
            indicators.append(
                "Sender domain is visually similar to known domain"
            )

        matched = display_name_match and lookalike

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "observed_domain": observed_domain,
            "known_domain": known_domain,
        }
