"""Conversation participant analysis for Email Conversation Integrity Detection."""

from __future__ import annotations

from email.utils import getaddresses
from typing import Any


class ParticipantAnalyzer:
    """Analyze participants in an email conversation."""

    def extract_participants(
        self,
        email_data: dict[str, Any],
    ) -> list[str]:
        """Extract unique email addresses from message participants."""

        headers: list[str] = []

        sender = email_data.get("from", "")
        reply_to = email_data.get("reply_to", "")

        headers.append(sender)
        headers.append(reply_to)

        headers.extend(email_data.get("to", []))
        headers.extend(email_data.get("cc", []))

        participants: set[str] = set()

        for _, address in getaddresses(headers):
            if address:
                participants.add(address.lower())

        return sorted(participants)

    def find_new_participants(
        self,
        current_participants: list[str],
        known_participants: list[str],
    ) -> list[str]:
        """Identify participants not present in the conversation baseline."""

        known = {
            participant.lower()
            for participant in known_participants
        }

        return sorted(
            participant
            for participant in current_participants
            if participant.lower() not in known
        )
