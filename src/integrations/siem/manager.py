"""Manage registered SIEM integrations."""

from __future__ import annotations

from typing import Any

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent


class SIEMIntegrationManager:
    """Register and dispatch events to SIEM integrations."""

    def __init__(
        self,
        integrations: list[SIEMIntegration] | None = None,
    ) -> None:
        """Initialize the manager with optional integrations."""

        self._integrations: dict[str, SIEMIntegration] = {}

        for integration in integrations or []:
            self.register(integration)

    def register(self, integration: SIEMIntegration) -> None:
        """Register a SIEM integration by name."""

        name = integration.name

        if name in self._integrations:
            raise ValueError(
                f"SIEM integration already registered: {name}"
            )

        self._integrations[name] = integration

    def get(self, name: str) -> SIEMIntegration:
        """Return a registered SIEM integration by name."""

        try:
            return self._integrations[name]
        except KeyError as exc:
            raise KeyError(
                f"SIEM integration not registered: {name}"
            ) from exc

    def list_integrations(self) -> list[str]:
        """Return the names of all registered integrations."""

        return list(self._integrations.keys())

    def send(
        self,
        name: str,
        event: SIEMEvent,
    ) -> dict[str, Any]:
        """Send an event to one registered integration."""

        integration = self.get(name)

        return integration.send(event)

    def broadcast(
        self,
        event: SIEMEvent,
    ) -> dict[str, dict[str, Any]]:
        """Send an event to all registered integrations."""

        return {
            name: integration.send(event)
            for name, integration in self._integrations.items()
        }
