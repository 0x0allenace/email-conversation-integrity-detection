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
