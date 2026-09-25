"""Tests for the application-level SIEM service."""

from __future__ import annotations

from unittest.mock import Mock

from src.integrations.siem.manager import SIEMIntegrationManager
from src.integrations.siem.service import SIEMService


def create_email() -> dict:
    """Create representative email data."""

    return {
        "message_id": "<message-001@example.com>",
        "from_email": "attacker@example.net",
        "from_domain": "example.net",
        "to": ["alice@company.com"],
        "subject": "Invoice Update",
    }


def create_detections() -> list[dict]:
    """Create representative detection results."""

    return [
        {
            "rule_id": "BEC-001",
            "rule_name": "Lookalike Domain Detection",
            "severity": "high",
            "matched": True,
            "risk_score": 70,
            "indicators": [
                "Lookalike domain detected",
            ],
            "details": {
                "observed_domain": "example.net",
            },
        },
        {
            "rule_id": "BEC-002",
            "rule_name": "Reply-To Mismatch",
            "severity": "medium",
            "matched": False,
            "risk_score": 0,
            "indicators": [],
            "details": {},
        },
    ]


def create_manager() -> SIEMIntegrationManager:
    """Create a manager with mocked integrations."""

    splunk = Mock()
    splunk.name = "splunk"

    elastic = Mock()
    elastic.name = "elastic"

    return SIEMIntegrationManager(
        integrations=[
            splunk,
            elastic,
        ],
    )


def test_siem_service_dispatches_matched_detections_only():
    """Test that only matched detections are dispatched by default."""

    manager = create_manager()

    manager.send = Mock(
        return_value={
            "status": "accepted",
        },
    )

    service = SIEMService(
        manager=manager,
    )

    results = service.dispatch_detections(
        detections=create_detections(),
        email=create_email(),
    )

    assert set(results) == {
        "splunk",
        "elastic",
    }

    assert results["splunk"]["BEC-001"] == {
        "status": "accepted",
    }

    assert results["elastic"]["BEC-001"] == {
        "status": "accepted",
    }

    assert "BEC-002" not in results["splunk"]
    assert "BEC-002" not in results["elastic"]

    assert manager.send.call_count == 2


def test_siem_service_can_dispatch_to_selected_integrations():
    """Test dispatching to a selected integration only."""

    manager = create_manager()

    manager.send = Mock(
        return_value={
            "status": "accepted",
        },
    )

    service = SIEMService(
        manager=manager,
    )

    results = service.dispatch_detections(
        detections=create_detections(),
        email=create_email(),
        integration_names=["elastic"],
    )

    assert results == {
        "elastic": {
            "BEC-001": {
                "status": "accepted",
            },
        },
    }

    assert manager.send.call_count == 1
    manager.send.assert_called_once()

    assert manager.send.call_args.args[0] == "elastic"


def test_siem_service_can_dispatch_unmatched_detections():
    """Test dispatching all detections when matched_only is disabled."""

    manager = create_manager()

    manager.send = Mock(
        return_value={
            "status": "accepted",
        },
    )

    service = SIEMService(
        manager=manager,
    )

    results = service.dispatch_detections(
        detections=create_detections(),
        email=create_email(),
        matched_only=False,
    )

    assert set(results["splunk"]) == {
        "BEC-001",
        "BEC-002",
    }

    assert set(results["elastic"]) == {
        "BEC-001",
        "BEC-002",
    }

    assert manager.send.call_count == 4


def test_siem_service_passes_analysis_context_to_adapter():
    """Test that authentication and infrastructure context are forwarded."""

    manager = create_manager()

    manager.send = Mock(
        return_value={
            "status": "accepted",
        },
    )

    adapter = Mock()

    event = Mock()

    adapter.from_detection.return_value = event

    service = SIEMService(
        manager=manager,
        adapter=adapter,
    )

    authentication = {
        "spf": "fail",
        "dkim": "pass",
        "dmarc": "fail",
    }

    infrastructure = {
        "sending_host": "mail.example.net",
    }

    conversation = {
        "thread_id": "<thread-001@example.com>",
    }

    service.dispatch_detections(
        detections=create_detections(),
        email=create_email(),
        authentication=authentication,
        infrastructure=infrastructure,
        conversation=conversation,
    )

    adapter.from_detection.assert_called_once()

    call_kwargs = adapter.from_detection.call_args.kwargs

    assert call_kwargs["email"] == create_email()
    assert call_kwargs["authentication"] == authentication
    assert call_kwargs["infrastructure"] == infrastructure
    assert call_kwargs["conversation"] == conversation


def test_siem_service_returns_empty_results_when_no_detections_match():
    """Test that no SIEM events are sent when nothing matches."""

    manager = create_manager()

    manager.send = Mock()

    service = SIEMService(
        manager=manager,
    )

    detections = [
        {
            "rule_id": "BEC-001",
            "rule_name": "Lookalike Domain Detection",
            "severity": "high",
            "matched": False,
            "risk_score": 0,
            "indicators": [],
            "details": {},
        },
    ]

    results = service.dispatch_detections(
        detections=detections,
        email=create_email(),
    )

    assert results == {}
    manager.send.assert_not_called()
