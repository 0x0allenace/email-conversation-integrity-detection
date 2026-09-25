"""Normalized SIEM event model for Email Conversation Integrity Detection."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SIEMEvent:
    """Represent a normalized security event for SIEM integrations."""

    event_type: str
    timestamp: str
    message_id: str | None = None
    sender_email: str | None = None
    sender_domain: str | None = None
    recipient_emails: list[str] = field(default_factory=list)
    subject: str | None = None

    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    matched: bool = False
    risk_score: int = 0

    indicators: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    authentication: dict[str, Any] = field(default_factory=dict)
    infrastructure: dict[str, Any] = field(default_factory=dict)
    conversation: dict[str, Any] = field(default_factory=dict)

    source: str = "email-conversation-integrity-detection"
    schema_version: str = "1.0"

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        message_id: str | None = None,
        sender_email: str | None = None,
        sender_domain: str | None = None,
        recipient_emails: list[str] | None = None,
        subject: str | None = None,
        rule_id: str | None = None,
        rule_name: str | None = None,
        severity: str | None = None,
        matched: bool = False,
        risk_score: int = 0,
        indicators: list[str] | None = None,
        details: dict[str, Any] | None = None,
        authentication: dict[str, Any] | None = None,
        infrastructure: dict[str, Any] | None = None,
        conversation: dict[str, Any] | None = None,
    ) -> "SIEMEvent":
        """Create a normalized SIEM event with a UTC timestamp."""

        return cls(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_id=message_id,
            sender_email=sender_email,
            sender_domain=sender_domain,
            recipient_emails=list(recipient_emails or []),
            subject=subject,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            matched=matched,
            risk_score=risk_score,
            indicators=list(indicators or []),
            details=dict(details or {}),
            authentication=dict(authentication or {}),
            infrastructure=dict(infrastructure or {}),
            conversation=dict(conversation or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the SIEM event into a serializable dictionary."""

        return asdict(self)
