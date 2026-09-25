"""Email parser for Email Conversation Integrity Detection."""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr
from pathlib import Path
from typing import Any


class EmailParser:
    """Parse and normalize .eml email messages."""

    def parse_file(self, file_path: str | Path) -> dict[str, Any]:
        """Parse an email from an .eml file."""

        path = Path(file_path)

        if not path.is_file():
            raise FileNotFoundError(
                f"Email file not found: {path}"
            )

        try:
            with path.open("rb") as email_file:
                message = BytesParser(
                    policy=policy.default
                ).parse(email_file)
        except Exception as exc:
            raise ValueError(
                f"Unable to parse email: {path}"
            ) from exc

        self._validate_message(
            message,
            path,
        )

        return self._normalize_message(message)

    @staticmethod
    def _validate_message(
        message: EmailMessage,
        path: Path,
    ) -> None:
        """Validate that the parsed message has a usable email structure."""

        sender = message.get("From")

        if not sender:
            raise ValueError(
                f"Unable to parse email: {path}"
            )

    def _normalize_message(
        self,
        message: EmailMessage,
    ) -> dict[str, Any]:
        """Convert an EmailMessage into normalized data."""

        sender = self._normalize_single_address(
            message["From"]
        )

        reply_to = self._normalize_single_address(
            message["Reply-To"]
        )

        return_path = self._normalize_single_address(
            message["Return-Path"]
        )

        to_addresses = self._normalize_addresses(
            message.get_all("To", [])
        )

        cc_addresses = self._normalize_addresses(
            message.get_all("Cc", [])
        )

        return {
            "from": sender,
            "to": to_addresses,
            "cc": cc_addresses,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": message.get("Subject", ""),
            "date": message.get("Date", ""),
            "message_id": message.get("Message-ID", ""),
            "in_reply_to": message.get("In-Reply-To", ""),
            "references": message.get("References", ""),
            "authentication_results": message.get(
                "Authentication-Results",
                "",
            ),
            "received": message.get_all("Received", []),
        }

    @staticmethod
    def _normalize_single_address(header: Any) -> str:
        """Normalize a single email address header."""

        if header is None:
            return ""

        addresses = getattr(header, "addresses", None)

        if addresses:
            address = addresses[0]

            return formataddr(
                (
                    address.display_name,
                    address.addr_spec,
                )
            )

        return str(header)

    @staticmethod
    def _normalize_addresses(
        headers: list[Any],
    ) -> list[str]:
        """Normalize email address headers into a list."""

        addresses: list[str] = []

        for header in headers:
            parsed_addresses = getattr(
                header,
                "addresses",
                None,
            )

            if parsed_addresses:
                for address in parsed_addresses:
                    addresses.append(
                        formataddr(
                            (
                                address.display_name,
                                address.addr_spec,
                            )
                        )
                    )

        return addresses
