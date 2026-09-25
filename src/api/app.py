"""FastAPI application for Email Conversation Integrity Detection."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from src.api.config import settings
from src.api.models import (
    AnalysisResponse,
    AnalysisSummaryResponse,
    AuthenticationResponse,
    DetectionResponse,
    EmailAnalysisResponse,
    IdentityResponse,
    InfrastructureResponse,
)
from src.api.service import AnalysisService
from src.database.session import get_db
from src.integrations.siem.factory import (
    create_siem_integration,
)
from src.integrations.siem.manager import (
    SIEMIntegrationManager,
)
from src.integrations.siem.service import SIEMService


def _create_analysis_service() -> AnalysisService:
    """Create the application analysis service."""

    integration = create_siem_integration(
        settings,
    )

    if integration is None:
        return AnalysisService()

    manager = SIEMIntegrationManager(
        integrations=[integration],
    )

    siem_service = SIEMService(
        manager=manager,
    )

    return AnalysisService(
        siem_service=siem_service,
    )


app = FastAPI(
    title=settings.title,
    description=settings.description,
    version=settings.version,
)

analysis_service = _create_analysis_service()


def _validate_required_text(
    value: str,
    field_name: str,
) -> str:
    """Validate and normalize a required text field."""

    if not value.strip():
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must not be empty.",
        )

    return value.strip()


def _validate_non_empty_value(
    value: str | None,
    field_name: str,
) -> str:
    """Validate that a required form value was provided."""

    if value is None or not value:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} is required.",
        )

    return value


def _validate_email_file(
    email_file: UploadFile,
) -> None:
    """Validate the uploaded email file."""

    if not email_file.filename:
        raise HTTPException(
            status_code=422,
            detail="email_file must have a filename.",
        )

    if Path(email_file.filename).suffix.lower() != ".eml":
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported email file type. "
                "Only .eml files are supported."
            ),
        )


def _build_response(
    result: dict,
) -> EmailAnalysisResponse:
    """Convert a detection engine result into the API response model."""

    return EmailAnalysisResponse(
        email=result["email"],
        identity=IdentityResponse(
            **result["identity"],
        ),
        participants=result["participants"],
        authentication=AuthenticationResponse(
            **result["authentication"],
        ),
        infrastructure=InfrastructureResponse(
            **result["infrastructure"],
        ),
        detections=[
            DetectionResponse(
                **detection,
            )
            for detection in result["detections"]
        ],
    )


def _build_analysis_response(
    result: dict,
) -> AnalysisResponse:
    """Convert a persisted analysis into an API response."""

    return AnalysisResponse(
        id=result["id"],
        analyzed_at=result["analyzed_at"],
        email_message_id=result["email_message_id"],
        sender_email=result["sender_email"],
        sender_domain=result["sender_domain"],
        subject=result["subject"],
        known_domain=result["known_domain"],
        known_display_name=result["known_display_name"],
        risk_score=result["risk_score"],
        result=result["result"],
        detections=result["detections"],
    )


def _build_analysis_summary_response(
    result: dict,
) -> AnalysisSummaryResponse:
    """Convert a persisted analysis into a summary response."""

    return AnalysisSummaryResponse(
        id=result["id"],
        analyzed_at=result["analyzed_at"],
        email_message_id=result["email_message_id"],
        sender_email=result["sender_email"],
        sender_domain=result["sender_domain"],
        subject=result["subject"],
        known_domain=result["known_domain"],
        known_display_name=result["known_display_name"],
        risk_score=result["risk_score"],
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the API health status."""

    return {
        "status": "ok",
        "service": "email-conversation-integrity-detection",
    }


@app.get("/ready")
def readiness_check() -> dict[str, str]:
    """Return the API readiness status."""

    return {
        "status": "ready",
        "service": "email-conversation-integrity-detection",
    }


@app.get(
    "/analyses",
    response_model=list[AnalysisSummaryResponse],
)
def list_analyses(
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[AnalysisSummaryResponse]:
    """Return recent persisted analyses."""

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 100.",
        )

    results = analysis_service.list_analyses(
        db=db,
        limit=limit,
    )

    return [
        _build_analysis_summary_response(
            result
        )
        for result in results
    ]


@app.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisResponse,
)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    """Return one persisted analysis by ID."""

    if analysis_id < 1:
        raise HTTPException(
            status_code=400,
            detail="analysis_id must be greater than 0.",
        )

    result = analysis_service.get_analysis(
        db=db,
        analysis_id=analysis_id,
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis {analysis_id} not found.",
        )

    return _build_analysis_response(
        result
    )


@app.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
)
async def analyze_email(
    email_file: UploadFile = File(...),
    known_domain: str | None = Form(default=None),
    known_display_name: str | None = Form(default=None),
    known_participants: list[str] = Form(default=[]),
    known_hosts: list[str] = Form(default=[]),
    known_ip_addresses: list[str] = Form(default=[]),
    known_behavior: str = Form(default="{}"),
    db: Session = Depends(get_db),
) -> EmailAnalysisResponse:
    """Analyze an uploaded email and persist the analysis result."""

    _validate_non_empty_value(
        known_domain,
        "known_domain",
    )

    _validate_non_empty_value(
        known_display_name,
        "known_display_name",
    )

    known_domain = _validate_required_text(
        known_domain,
        "known_domain",
    )

    known_display_name = _validate_required_text(
        known_display_name,
        "known_display_name",
    )

    _validate_email_file(email_file)

    try:
        behavior_data = (
            json.loads(known_behavior)
            if known_behavior.strip()
            else {}
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="known_behavior must contain valid JSON.",
        ) from exc

    temporary_path: str | None = None

    try:
        suffix = Path(
            email_file.filename
        ).suffix.lower()

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temporary_file:
            temporary_path = temporary_file.name

            content = await email_file.read()

            if not content:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded email file is empty.",
                )

            temporary_file.write(content)

        result = analysis_service.analyze_email(
            db=db,
            email_file=temporary_path,
            known_domain=known_domain,
            known_display_name=known_display_name,
            known_participants=known_participants,
            known_hosts=known_hosts,
            known_ip_addresses=known_ip_addresses,
            known_behavior=behavior_data,
        )

        return _build_response(result)

    except HTTPException:
        raise

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Internal server error.",
        ) from exc

    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
