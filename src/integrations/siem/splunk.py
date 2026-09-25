"""Splunk HTTP Event Collector integration."""

from __future__ import annotations

import json
from urllib import error, request
from typing import Any

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent


class SplunkIntegration(SIEMIntegration):
    """Send normalized SIEM events to Splunk HEC."""

    def __init__(
        self,
        *,
        url: str,
        token: str,
        index: str | None = None,
        source: str | None = None,
        sourcetype: str = "ecid:event",
        timeout: float = 10.0,
    ) -> None:
        """Initialize the Splunk HEC integration."""

        self.url = url.rstrip("/")
        self.token = token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.timeout = timeout

    @property
    def name(self) -> str:
        """Return the integration name."""

        return "splunk"

    def send(self, event: SIEMEvent) -> dict[str, Any]:
        """Send a normalized SIEM event to Splunk HEC."""

        payload: dict[str, Any] = {
            "event": event.to_dict(),
            "sourcetype": self.sourcetype,
        }

        if self.index:
            payload["index"] = self.index

        if self.source:
            payload["source"] = self.source

        body = json.dumps(payload).encode("utf-8")

        http_request = request.Request(
            f"{self.url}/services/collector/event",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
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
