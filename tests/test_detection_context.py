from src.engine.detection_context import DetectionContext


def test_detection_context_stores_analysis_data():
    """Test that detection context stores normalized analysis data."""

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
        },
        identity={
            "email_address": "bob@supplier.com",
            "domain": "supplier.com",
        },
        participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        authentication={
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
        infrastructure={
            "hosts": [
                "mail.supplier.com",
            ],
            "ip_addresses": [
                "192.0.2.10",
            ],
        },
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        known_hosts=[
            "mail.supplier.com",
        ],
        known_ip_addresses=[
            "192.0.2.10",
        ],
    )

    assert context.identity["domain"] == "supplier.com"
    assert "bob@supplier.com" in context.participants
    assert context.authentication["spf"] == "pass"
    assert context.infrastructure["hosts"] == [
        "mail.supplier.com",
    ]


def test_detection_context_stores_historical_observations():
    """Test that historical behavioral observations are preserved."""

    historical_observations = [
        {
            "id": 1,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-20T09:30:00+00:00",
        },
        {
            "id": 2,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-22T14:00:00+00:00",
        },
    ]

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
        },
        identity={
            "email_address": "bob@supplier.com",
            "domain": "supplier.com",
        },
        participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        authentication={
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
        infrastructure={
            "hosts": [
                "mail.supplier.com",
            ],
            "ip_addresses": [
                "192.0.2.10",
            ],
        },
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        known_hosts=[
            "mail.supplier.com",
        ],
        known_ip_addresses=[
            "192.0.2.10",
        ],
        historical_observations=historical_observations,
    )

    assert context.historical_observations == historical_observations
    assert len(context.historical_observations) == 2
