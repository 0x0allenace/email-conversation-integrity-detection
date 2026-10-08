from src.engine.detection_context import DetectionContext
from src.rules.bec_005 import SenderInfrastructureAnomalyRule


KNOWN_HOSTS = [
    "mail.supplier.com",
    "relay.supplier.com",
]

KNOWN_IP_ADDRESSES = [
    "192.0.2.10",
    "192.0.2.20",
]


def build_context(
    infrastructure: dict,
) -> DetectionContext:
    """Build a detection context for infrastructure testing."""

    return DetectionContext(
        email_data={},
        identity={},
        participants=[],
        authentication={},
        infrastructure=infrastructure,
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )


def test_known_infrastructure_does_not_trigger_bec_005():
    """Known infrastructure should not trigger BEC-005."""

    context = build_context(
        {
            "hosts": [
                "mail.supplier.com",
                "relay.supplier.com",
            ],
            "ip_addresses": [
                "192.0.2.10",
                "192.0.2.20",
            ],
        }
    )

    rule = SenderInfrastructureAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["new_hosts"] == []
    assert result["new_ip_addresses"] == []


def test_unexpected_host_triggers_bec_005():
    """An unexpected sending host should trigger BEC-005."""

    context = build_context(
        {
            "hosts": [
                "suspicious-mail.example",
            ],
            "ip_addresses": [
                "192.0.2.10",
            ],
        }
    )

    rule = SenderInfrastructureAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["new_hosts"] == [
        "suspicious-mail.example",
    ]
    assert result["new_ip_addresses"] == []

    assert (
        "Unexpected sending host detected"
        in result["indicators"]
    )


def test_unexpected_ip_address_triggers_bec_005():
    """An unexpected sending IP should trigger BEC-005."""

    context = build_context(
        {
            "hosts": [
                "mail.supplier.com",
            ],
            "ip_addresses": [
                "203.0.113.50",
            ],
        }
    )

    rule = SenderInfrastructureAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["new_hosts"] == []
    assert result["new_ip_addresses"] == [
        "203.0.113.50",
    ]

    assert (
        "Unexpected sending IP address detected"
        in result["indicators"]
    )


def test_unexpected_host_and_ip_are_both_reported():
    """Unexpected host and IP should both be reported."""

    context = build_context(
        {
            "hosts": [
                "suspicious-mail.example",
            ],
            "ip_addresses": [
                "203.0.113.50",
            ],
        }
    )

    rule = SenderInfrastructureAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["new_hosts"] == [
        "suspicious-mail.example",
    ]
    assert result["new_ip_addresses"] == [
        "203.0.113.50",
    ]

    assert (
        "Unexpected sending host detected"
        in result["indicators"]
    )

    assert (
        "Unexpected sending IP address detected"
        in result["indicators"]
    )


def test_known_host_matching_is_case_insensitive():
    """Known host comparison should ignore hostname casing."""

    context = build_context(
        {
            "hosts": [
                "MAIL.SUPPLIER.COM",
                "RELAY.SUPPLIER.COM",
            ],
            "ip_addresses": [
                "192.0.2.10",
                "192.0.2.20",
            ],
        }
    )

    rule = SenderInfrastructureAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["new_hosts"] == []
    assert result["new_ip_addresses"] == []
