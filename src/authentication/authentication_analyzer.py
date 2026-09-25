"""Authentication analysis for Email Conversation Integrity Detection."""

from __future__ import annotations

import re
from typing import Any


class AuthenticationAnalyzer:
    """Analyze SPF, DKIM, and DMARC authentication results."""

    AUTHENTICATION_PATTERN = re.compile(
        r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        re.IGNORECASE,
    )

    def analyze(
        self,
        email_data: dict[str, Any],
    ) -> dict[str, str]:
        """Extract authentication results from normalized email data."""

        authentication_results = email_data.get(
            "authentication_results",
            "",
        )

        results = {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
        }

        matches = self.AUTHENTICATION_PATTERN.findall(
            authentication_results
        )

        for method, result in matches:
            results[method.lower()] = result.lower()

        return results
