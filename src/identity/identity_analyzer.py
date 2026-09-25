"""Identity analysis for Email Conversation Integrity Detection."""

from __future__ import annotations

from email.utils import parseaddr
from typing import Any


class IdentityAnalyzer:
    """Extract security-relevant sender identity information."""

    def analyze(self, email_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze the sender identity of a normalized email."""

        sender = email_data.get("from", "")

        display_name, email_address = parseaddr(sender)

        username = ""
        domain = ""

        if "@" in email_address:
            username, domain = email_address.rsplit("@", 1)

        return {
            "display_name": display_name,
            "email_address": email_address,
            "username": username,
            "domain": domain.lower(),
        }
