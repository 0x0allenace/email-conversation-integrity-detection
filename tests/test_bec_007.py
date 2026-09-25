from src.engine.detection_context import DetectionContext
from src.rules.bec_007 import BehavioralCommunicationAnomalyRule


def build_context(
    *,
    date: str,
    typical_hours: list[int],
) -> DetectionContext:
    """Build a detection context for BEC-007 tests."""

    return DetectionContext(
        email_data={
            "date": date,
        },
        identity={
            "display_name": "Bob Supplier",
            "email_address": "bob@supplier.com",
            "username": "bob",
            "domain": "supplier.com",
        },
        participants=[
            "bob@supplier.com",
            "alice@company.com",
        ],
        authentication={
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
        infrastructure={
            "received_count": 1,
            "hosts": ["mail.supplier.com"],
            "ip_addresses": ["192.0.2.10"],
        },
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "bob@supplier.com",
            "alice@company.com",
        ],
        known_hosts=[
            "mail.supplier.com",
        ],
        known_ip_addresses=[
            "192.0.2.10",
        ],
        known_behavior={
            "typical_hours": typical_hours,
        },
    )


def test_bec_007_detects_unusual_sending_hour():
    """BEC-007 should detect a message sent outside normal hours."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 02:30:00 +0100",
        typical_hours=list(range(8, 18)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["rule_name"] == "Behavioral Communication Anomaly"
    assert result["severity"] == "MEDIUM"
    assert result["matched"] is True

    assert (
        "Message sent outside established communication hours"
        in result["indicators"]
    )

    assert result["observed_hour"] == 2


def test_bec_007_allows_normal_sending_hour():
    """BEC-007 should not flag a message sent during normal hours."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []

    assert result["observed_hour"] == 10


def test_bec_007_handles_missing_behavior_baseline():
    """BEC-007 should not flag an email without a behavior baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 02:30:00 +0100",
        typical_hours=[],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []
