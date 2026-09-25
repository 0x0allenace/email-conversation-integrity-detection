"""Tests for the SIEM integration manager."""

import pytest

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent
from src.integrations.siem.manager import SIEMIntegrationManager


class ExampleSIEMIntegration(SIEMIntegration):
    """Minimal SIEM integration used for manager tests."""

    def __init__(self, integration_name: str) -> None:
        """Initialize the example integration."""

        self._name = integration_name

    @property
    def name(self) -> str:
        """Return the integration name."""

        return self._name

    def send(self, event: SIEMEvent) -> dict[str, object]:
        """Return a deterministic result for testing."""

        return {
            "integration": self.name,
            "event_type": event.event_type,
            "status": "accepted",
        }


def test_manager_registers_integration():
    """Test registration of a SIEM integration."""

    integration = ExampleSIEMIntegration("example")

    manager = SIEMIntegrationManager()

    manager.register(integration)

    assert manager.list_integrations() == ["example"]
    assert manager.get("example") is integration


def test_manager_accepts_integrations_during_initialization():
    """Test initialization with preconfigured integrations."""

    first = ExampleSIEMIntegration("first")
    second = ExampleSIEMIntegration("second")

    manager = SIEMIntegrationManager(
        integrations=[first, second]
    )

    assert manager.list_integrations() == [
        "first",
        "second",
    ]
    assert manager.get("first") is first
    assert manager.get("second") is second


def test_manager_rejects_duplicate_integration_name():
    """Test that duplicate integration names are rejected."""

    first = ExampleSIEMIntegration("example")
    second = ExampleSIEMIntegration("example")

    manager = SIEMIntegrationManager()

    manager.register(first)

    with pytest.raises(
        ValueError,
        match="SIEM integration already registered: example",
    ):
        manager.register(second)


def test_manager_rejects_unknown_integration():
    """Test that unknown integrations cannot be retrieved."""

    manager = SIEMIntegrationManager()

    with pytest.raises(
        KeyError,
        match="SIEM integration not registered: missing",
    ):
        manager.get("missing")


def test_manager_sends_event_to_selected_integration():
    """Test sending an event to one selected integration."""

    integration = ExampleSIEMIntegration("example")
    manager = SIEMIntegrationManager([integration])

    event = SIEMEvent.create(
        event_type="email_detection",
        rule_id="BEC-001",
        matched=True,
        risk_score=70,
    )

    result = manager.send("example", event)

    assert result == {
        "integration": "example",
        "event_type": "email_detection",
        "status": "accepted",
    }


def test_manager_broadcasts_event_to_all_integrations():
    """Test broadcasting an event to every registered integration."""

    first = ExampleSIEMIntegration("first")
    second = ExampleSIEMIntegration("second")

    manager = SIEMIntegrationManager(
        integrations=[first, second]
    )

    event = SIEMEvent.create(
        event_type="email_detection",
        rule_id="BEC-004",
        matched=True,
        risk_score=30,
    )

    result = manager.broadcast(event)

    assert result == {
        "first": {
            "integration": "first",
            "event_type": "email_detection",
            "status": "accepted",
        },
        "second": {
            "integration": "second",
            "event_type": "email_detection",
            "status": "accepted",
        },
    }


def test_manager_broadcasts_empty_result_when_no_integrations():
    """Test broadcasting when no integrations are registered."""

    manager = SIEMIntegrationManager()

    event = SIEMEvent.create(
        event_type="email_detection",
    )

    assert manager.broadcast(event) == {}
