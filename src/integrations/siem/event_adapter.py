"""Convert ECID detection results into normalized SIEM events."""

from __future__ import annotations

from typing import Any

from src.detection.result import DetectionResult
from src.integrations.siem.event import SIEMEvent


class SIEMEventAdapter:
    """Convert existing ECID analysis data into SIEM events."""

    def from_detection(
        self,
        *,
        detection: DetectionResult,
        email: dict[str, Any],
        authentication: dict[str, Any] | None = None,
        infrastructure: dict[str, Any] | None = None,
        conversation: dict[str, Any] | None = None,
    ) -> SIEMEvent:
        """Create a SIEM event from one detection result."""

        sender_email = email.get("from_email")
        sender_domain = email.get("from_domain")

        recipients = email.get("to", [])
        if isinstance(recipients, str):
            recipients = [recipients]

        return SIEMEvent.create(
            event_type="email_detection",
            message_id=email.get("message_id"),
            sender_email=sender_email,
            sender_domain=sender_domain,
            recipient_emails=list(recipients),
            subject=email.get("subject"),
            rule_id=detection.rule_id,
            rule_name=detection.rule_name,
            severity=detection.severity,
            matched=detection.matched,
            risk_score=detection.risk_score,
            indicators=detection.indicators,
            details=detection.details,
            authentication=authentication,
            infrastructure=infrastructure,
            conversation=conversation,
        )
