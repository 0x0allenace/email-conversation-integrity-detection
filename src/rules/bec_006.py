"""BEC-006: Conversation Hijacking detection."""

from __future__ import annotations

from email.utils import parseaddr
from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class ConversationHijackingRule(DetectionRule):
    """Detect suspicious reuse of an existing email conversation."""

    rule_id = "BEC-006"
    rule_name = "Conversation Hijacking"
    severity = "HIGH"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate whether an existing thread may have been hijacked."""

        email_data = context.email_data
        known_participants = context.known_participants

        from_header = email_data.get("from", "")
        in_reply_to = email_data.get("in_reply_to", "")
        references = email_data.get("references", "")

        _, sender_address = parseaddr(from_header)

        sender_address = sender_address.lower().strip()

        known = {
            participant.lower().strip()
            for participant in known_participants
        }

        indicators: list[str] = []

        thread_headers_present = bool(
            in_reply_to or references
        )

        sender_is_known = (
            bool(sender_address)
            and sender_address in known
        )

        if thread_headers_present:
            indicators.append(
                "Message contains existing conversation thread headers"
            )

        if thread_headers_present and not sender_is_known:
            indicators.append(
                "Sender is not a known participant in the conversation"
            )

        matched = (
            thread_headers_present
            and bool(sender_address)
            and not sender_is_known
        )

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "sender_address": sender_address,
            "sender_is_known": sender_is_known,
            "in_reply_to": in_reply_to,
            "references": references,
        }
