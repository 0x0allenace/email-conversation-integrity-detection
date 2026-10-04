"""API request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    """Request parameters for email analysis."""

    known_domain: str = Field(
        ...,
        description="Trusted sender domain.",
    )

    known_display_name: str = Field(
        ...,
        description="Trusted sender display name.",
    )

    known_participants: list[str] = Field(
        default_factory=list,
        description="Known participants in the conversation.",
    )

    known_hosts: list[str] = Field(
        default_factory=list,
        description="Known sender infrastructure hosts.",
    )

    known_ip_addresses: list[str] = Field(
        default_factory=list,
        description="Known sender infrastructure IP addresses.",
    )

    known_behavior: dict[str, Any] = Field(
        default_factory=dict,
        description="Known behavioral baseline.",
    )


class DetectionResponse(BaseModel):
    """Represent a single detection result."""

    rule_id: str
    rule_name: str
    severity: str
    matched: bool
    risk_score: int
    indicators: list[str | dict[str, Any]] = Field(
        default_factory=list,
    )

    model_config = {
        "extra": "allow",
    }


class IdentityResponse(BaseModel):
    """Represent analyzed sender identity."""

    display_name: str
    email_address: str
    username: str
    domain: str


class AuthenticationResponse(BaseModel):
    """Represent email authentication results."""

    spf: str
    dkim: str
    dmarc: str


class InfrastructureResponse(BaseModel):
    """Represent analyzed sender infrastructure."""

    received_count: int
    hosts: list[str] = Field(
        default_factory=list,
    )
    ip_addresses: list[str] = Field(
        default_factory=list,
    )


class EmailAnalysisResponse(BaseModel):
    """Represent the complete email analysis response."""

    email: dict[str, Any]
    identity: IdentityResponse
    participants: list[str] = Field(
        default_factory=list,
    )
    authentication: AuthenticationResponse
    infrastructure: InfrastructureResponse
    detections: list[DetectionResponse] = Field(
        default_factory=list,
    )


class PersistedDetectionResponse(BaseModel):
    """Represent a persisted detection result."""

    id: int
    rule_id: str
    rule_name: str
    severity: str
    matched: bool
    risk_score: int
    indicators: list[str | dict[str, Any]] = Field(
        default_factory=list,
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
    )


class AnalysisSummaryResponse(BaseModel):
    """Represent a persisted analysis summary."""

    id: int
    analyzed_at: datetime
    email_sent_at: datetime | None
    email_message_id: str | None
    sender_email: str
    sender_domain: str
    subject: str | None
    known_domain: str
    known_display_name: str
    risk_score: int


class AnalysisResponse(AnalysisSummaryResponse):
    """Represent a persisted analysis with detections."""

    result: dict[str, Any]
    detections: list[PersistedDetectionResponse] = Field(
        default_factory=list,
    )
