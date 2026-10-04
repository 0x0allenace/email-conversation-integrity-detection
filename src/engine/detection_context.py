"""Shared analysis context for Email Conversation Integrity Detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionContext:
    """Store normalized data used by detection rules."""

    email_data: dict[str, Any]
    identity: dict[str, Any]
    participants: list[str]
    authentication: dict[str, str]
    infrastructure: dict[str, Any]
    known_domain: str
    known_display_name: str
    known_participants: list[str]
    known_hosts: list[str]
    known_ip_addresses: list[str]
    recipients: list[str] = field(
        default_factory=list
    )
    attachments: list[dict[str, Any]] = field(
        default_factory=list
    )
    known_behavior: dict[str, Any] = field(
        default_factory=dict
    )
    historical_observations: list[dict[str, Any]] = field(
        default_factory=list
    )
