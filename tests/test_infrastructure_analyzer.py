from src.infrastructure.infrastructure_analyzer import (
    InfrastructureAnalyzer,
)


def test_extract_received_host_and_ip():
    """Test extraction of host and IP from Received headers."""

    analyzer = InfrastructureAnalyzer()

    result = analyzer.analyze(
        {
            "received": [
                "from mail.supplier.com "
                "(mail.supplier.com [192.0.2.10]) "
                "by mx.company.com",
            ],
        }
    )

    assert result["received_count"] == 1
    assert result["hosts"] == ["mail.supplier.com"]
    assert result["ip_addresses"] == ["192.0.2.10"]


def test_multiple_received_headers():
    """Test multiple Received headers."""

    analyzer = InfrastructureAnalyzer()

    result = analyzer.analyze(
        {
            "received": [
                "from mail.supplier.com "
                "(mail.supplier.com [192.0.2.10]) "
                "by mx.company.com",

                "from relay.supplier.com "
                "(relay.supplier.com [192.0.2.20]) "
                "by mail.supplier.com",
            ],
        }
    )

    assert result["received_count"] == 2

    assert result["hosts"] == [
        "mail.supplier.com",
        "relay.supplier.com",
    ]

    assert result["ip_addresses"] == [
        "192.0.2.10",
        "192.0.2.20",
    ]


def test_duplicate_infrastructure_is_removed():
    """Test that duplicate hosts and IPs are removed."""

    analyzer = InfrastructureAnalyzer()

    result = analyzer.analyze(
        {
            "received": [
                "from mail.supplier.com "
                "(mail.supplier.com [192.0.2.10]) "
                "by mx.company.com",

                "from mail.supplier.com "
                "(mail.supplier.com [192.0.2.10]) "
                "by relay.company.com",
            ],
        }
    )

    assert result["hosts"] == [
        "mail.supplier.com",
    ]

    assert result["ip_addresses"] == [
        "192.0.2.10",
    ]


def test_missing_received_headers():
    """Test that missing Received headers return empty results."""

    analyzer = InfrastructureAnalyzer()

    result = analyzer.analyze(
        {
            "received": [],
        }
    )

    assert result["received_count"] == 0
    assert result["hosts"] == []
    assert result["ip_addresses"] == []
