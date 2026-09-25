"""BEC-005: Sender Infrastructure Anomaly detection."""

from __future__ import annotations

from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class SenderInfrastructureAnomalyRule(DetectionRule):
    """Detect unexpected sender infrastructure."""

    rule_id = "BEC-005"
    rule_name = "Sender Infrastructure Anomaly"
    severity = "MEDIUM"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate sender infrastructure against a known baseline."""

        infrastructure = context.infrastructure
        known_hosts = context.known_hosts
        known_ip_addresses = context.known_ip_addresses

        observed_hosts = {
            host.lower()
            for host in infrastructure.get("hosts", [])
        }

        observed_ips = set(
            infrastructure.get("ip_addresses", [])
        )

        trusted_hosts = {
            host.lower()
            for host in known_hosts
        }

        trusted_ips = set(known_ip_addresses)

        new_hosts = sorted(
            observed_hosts - trusted_hosts
        )

        new_ip_addresses = sorted(
            observed_ips - trusted_ips
        )

        indicators: list[str] = []

        if new_hosts:
            indicators.append(
                "Unexpected sending host detected"
            )

        if new_ip_addresses:
            indicators.append(
                "Unexpected sending IP address detected"
            )

        matched = bool(
            new_hosts or new_ip_addresses
        )

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "new_hosts": new_hosts,
            "new_ip_addresses": new_ip_addresses,
            "known_hosts": sorted(trusted_hosts),
            "known_ip_addresses": sorted(trusted_ips),
        }
