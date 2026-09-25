"""Base contract for SIEM integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.integrations.siem.event import SIEMEvent


class SIEMIntegration(ABC):
    """Define the common contract for SIEM integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the integration name."""

        raise NotImplementedError

    @abstractmethod
    def send(self, event: SIEMEvent) -> dict[str, Any]:
        """Send a normalized SIEM event to the integration."""

        raise NotImplementedError
