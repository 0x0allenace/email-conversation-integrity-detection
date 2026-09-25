"""Infrastructure analysis for Email Conversation Integrity Detection."""

from __future__ import annotations

import re
from typing import Any


class InfrastructureAnalyzer:
    """Extract sending infrastructure from email headers."""

    IPV4_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    def analyze(
        self,
        email_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze Received headers for infrastructure indicators."""

        received_headers = email_data.get(
            "received",
            [],
        )

        hosts: list[str] = []
        ip_addresses: list[str] = []

        for header in received_headers:
            header_text = str(header)

            host = self._extract_host(header_text)

            if host and host not in hosts:
                hosts.append(host)

            for ip_address in self.IPV4_PATTERN.findall(
                header_text
            ):
                if ip_address not in ip_addresses:
                    ip_addresses.append(ip_address)

        return {
            "received_count": len(received_headers),
            "hosts": hosts,
            "ip_addresses": ip_addresses,
        }

    @staticmethod
    def _extract_host(header: str) -> str:
        """Extract a hostname from a Received header."""

        match = re.search(
            r"\bfrom\s+([^\s(]+)",
            header,
            re.IGNORECASE,
        )

        if not match:
            return ""

        return match.group(1).strip()
