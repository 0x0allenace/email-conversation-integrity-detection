"""BEC-002: Reply-To Mismatch detection."""

from __future__ import annotations

from email.utils import parseaddr
from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class ReplyToMismatchRule(DetectionRule):
    """Detect a mismatch between From and Reply-To identities."""

    rule_id = "BEC-002"
    rule_name = "Reply-To Mismatch"
    severity = "HIGH"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate the From and Reply-To addresses."""

        email_data = context.email_data

        from_header = email_data.get("from", "")
        reply_to_header = email_data.get("reply_to", "")

        _, from_address = parseaddr(from_header)
        _, reply_to_address = parseaddr(reply_to_header)

        from_domain = ""
        reply_to_domain = ""

        if "@" in from_address:
            _, from_domain = from_address.rsplit("@", 1)

        if "@" in reply_to_address:
            _, reply_to_domain = reply_to_address.rsplit("@", 1)

        from_domain = from_domain.lower()
        reply_to_domain = reply_to_domain.lower()

        indicators: list[str] = []

        if from_address and reply_to_address:
            if from_address.lower() != reply_to_address.lower():
                indicators.append(
                    "Reply-To address differs from From address"
                )

        if from_domain and reply_to_domain:
            if from_domain != reply_to_domain:
                indicators.append(
                    "Reply-To domain differs from From domain"
                )

        matched = (
            bool(from_address)
            and bool(reply_to_address)
            and from_address.lower() != reply_to_address.lower()
        )

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "from_address": from_address,
            "reply_to_address": reply_to_address,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
        }
