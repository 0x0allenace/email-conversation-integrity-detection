"""Wazuh API integration."""

from __future__ import annotations

import json
from urllib import error, request
from typing import Any

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent


class WazuhIntegration(SIEMIntegration):
    """Send normalized SIEM events to Wazuh."""

    def __init__(
        self,
        *,
        url: str,
        username: str,
        password: str,
        index: str = "ecid-events",
        timeout: float = 10.0,
    ) -> None:
        """Initialize the Wazuh integration."""

        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.index = index
        self.timeout = timeout

    @property
    def name(self) -> str:
        """Return the integration name."""

        return "wazuh"

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for Wazuh."""

        import base64

        credentials = (
            f"{self.username}:{self.password}"
        ).encode("utf-8")

        encoded_credentials = base64.b64encode(
            credentials
        ).decode("ascii")

        return {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
        }

    def send(self, event: SIEMEvent) -> dict[str, Any]:
        """Send a normalized SIEM event to Wazuh."""

        payload = {
            "index": self.index,
            "event": event.to_dict(),
        }

        body = json.dumps(payload).encode("utf-8")

        http_request = request.Request(
            f"{self.url}/events",
            data=body,
            method="POST",
            headers=self._build_headers(),
        )

        try:
            with request.urlopen(
                http_request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read().decode("utf-8")

        except error.HTTPError as exc:
            return {
                "integration": self.name,
                "status": "error",
                "status_code": exc.code,
                "error": exc.reason,
            }

        except error.URLError as exc:
            return {
                "integration": self.name,
                "status": "error",
                "error": str(exc.reason),
            }

        return {
            "integration": self.name,
            "status": "accepted",
            "status_code": response.status,
            "response": response_body,
        }
