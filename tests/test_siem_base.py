"""Tests for the SIEM integration contract."""

import pytest

from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.event import SIEMEvent


class ExampleSIEMIntegration(SIEMIntegration):
    """Minimal implementation used to test the SIEM contract."""

    @property
    def name(self) -> str:
        """Return the example integration name."""

        return "example"

    def send(self, event: SIEMEvent) -> dict[str, object]:
        """Return a deterministic result for testing."""

        return {
            "integration": self.name,
            "event_type": event.event_type,
            "status": "accepted",
        }


def test_siem_integration_requires_name_and_send():
    """Test that the SIEM integration contract is abstract."""

    assert SIEMIntegration.__abstractmethods__ == {
        "name",
        "send",
    }


def test_example_integration_implements_contract():
    """Test that a concrete integration can implement the contract."""

    integration = ExampleSIEMIntegration()

    assert integration.name == "example"


def test_example_integration_sends_siem_event():
    """Test that a concrete integration accepts a SIEM event."""

    event = SIEMEvent.create(
        event_type="email_detection",
        rule_id="BEC-001",
        matched=True,
        risk_score=70,
    )

    integration = ExampleSIEMIntegration()

    result = integration.send(event)

    assert result == {
        "integration": "example",
        "event_type": "email_detection",
        "status": "accepted",
    }


def test_incomplete_integration_cannot_be_instantiated():
    """Test that abstract SIEM integrations cannot be instantiated."""

    class IncompleteIntegration(SIEMIntegration):
        """Intentionally incomplete SIEM integration."""

        pass

    with pytest.raises(TypeError):
        IncompleteIntegration()
