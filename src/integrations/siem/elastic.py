"""Elastic Security / Elasticsearch integration."""

from __future__ import annotations

import json
from urllib import error, request
from typing import Any

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent


class ElasticIntegration(SIEMIntegration):
    """Send normalized SIEM events to Elasticsearch."""

    def __init__(
        self,
        *,
        url: str,
        index: str = "ecid-events",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize the Elasticsearch integration."""

        self.url = url.rstrip("/")
        self.index = index
        self.api_key = api_key
        self.username = username
        self.password = password
        self.timeout = timeout

    @property
    def name(self) -> str:
        """Return the integration name."""

        return "elastic"

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for Elasticsearch."""

        headers = {
            "Content-Type": "application/json",
        }

        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        elif self.username is not None and self.password is not None:
            import base64

            credentials = (
                f"{self.username}:{self.password}"
            ).encode("utf-8")

            encoded_credentials = base64.b64encode(
                credentials
            ).decode("ascii")

            headers["Authorization"] = (
                f"Basic {encoded_credentials}"
            )

        return headers

    def send(self, event: SIEMEvent) -> dict[str, Any]:
        """Send a normalized SIEM event to Elasticsearch."""

        payload = event.to_dict()

        body = json.dumps(payload).encode("utf-8")

        http_request = request.Request(
            f"{self.url}/{self.index}/_doc",
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
