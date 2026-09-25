"""Application-level SIEM event dispatch service."""

from __future__ import annotations

from typing import Any

from src.detection.result import DetectionResult
from src.integrations.siem.event_adapter import SIEMEventAdapter
from src.integrations.siem.manager import SIEMIntegrationManager


class SIEMService:
    """Convert detection results into SIEM events and dispatch them."""

    def __init__(
        self,
        *,
        manager: SIEMIntegrationManager,
        adapter: SIEMEventAdapter | None = None,
    ) -> None:
        """Initialize the SIEM service."""

        self.manager = manager
        self.adapter = (
            adapter
            if adapter is not None
            else SIEMEventAdapter()
        )

    def dispatch_detections(
        self,
        *,
        detections: list[dict[str, Any]],
        email: dict[str, Any],
        authentication: dict[str, Any] | None = None,
        infrastructure: dict[str, Any] | None = None,
        conversation: dict[str, Any] | None = None,
        integration_names: list[str] | None = None,
        matched_only: bool = True,
    ) -> dict[str, dict[str, Any]]:
        """Dispatch detection results to selected SIEM integrations."""

        results: dict[str, dict[str, Any]] = {}

        selected_names = (
            integration_names
            if integration_names is not None
            else self.manager.list_integrations()
        )

        for detection_data in detections:
            if matched_only and not detection_data.get(
                "matched",
                False,
            ):
                continue

            detection = DetectionResult(
                rule_id=detection_data["rule_id"],
                rule_name=detection_data["rule_name"],
                severity=detection_data["severity"],
                matched=detection_data["matched"],
                risk_score=detection_data["risk_score"],
                indicators=detection_data.get(
                    "indicators",
                    [],
                ),
                details=detection_data.get(
                    "details",
                    {},
                ),
            )

            event = self.adapter.from_detection(
                detection=detection,
                email=email,
                authentication=authentication,
                infrastructure=infrastructure,
                conversation=conversation,
            )

            for integration_name in selected_names:
                results.setdefault(
                    integration_name,
                    {},
                )

                results[integration_name][
                    detection.rule_id
                ] = self.manager.send(
                    integration_name,
                    event,
                )

        return results
