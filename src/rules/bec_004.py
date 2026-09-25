"""BEC-004: Authentication Anomaly detection."""

from __future__ import annotations

from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class AuthenticationAnomalyRule(DetectionRule):
    """Detect authentication failures in an email."""

    rule_id = "BEC-004"
    rule_name = "Authentication Anomaly"
    severity = "HIGH"

    AUTHENTICATION_FAILURES = {
        "fail",
        "softfail",
        "permerror",
        "temperror",
    }

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate SPF, DKIM, and DMARC authentication results."""

        authentication_results = context.authentication

        failed_methods: list[str] = []
        unknown_methods: list[str] = []

        for method in ("spf", "dkim", "dmarc"):
            result = authentication_results.get(
                method,
                "unknown",
            ).lower()

            if result in self.AUTHENTICATION_FAILURES:
                failed_methods.append(method)

            elif result == "unknown":
                unknown_methods.append(method)

        indicators: list[str] = []

        if failed_methods:
            indicators.append(
                "Email authentication failure detected"
            )

        if len(failed_methods) >= 2:
            indicators.append(
                "Multiple email authentication methods failed"
            )

        matched = bool(failed_methods)

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "failed_methods": failed_methods,
            "unknown_methods": unknown_methods,
            "authentication_results": authentication_results,
        }
