from src.engine.detection_context import DetectionContext
from src.rules.bec_004 import AuthenticationAnomalyRule


def build_context(
    authentication_results: dict[str, str],
) -> DetectionContext:
    """Build a detection context for authentication testing."""

    return DetectionContext(
        email_data={},
        identity={},
        participants=[],
        authentication=authentication_results,
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        known_hosts=[],
        known_ip_addresses=[],
    )


def test_successful_authentication_does_not_trigger_bec_004():
    """Passing authentication results should not trigger BEC-004."""

    context = build_context(
        {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }
    )

    rule = AuthenticationAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["failed_methods"] == []
    assert result["unknown_methods"] == []


def test_authentication_failure_triggers_bec_004():
    """An authentication failure should trigger BEC-004."""

    context = build_context(
        {
            "spf": "fail",
            "dkim": "pass",
            "dmarc": "pass",
        }
    )

    rule = AuthenticationAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["failed_methods"] == ["spf"]

    assert (
        "Email authentication failure detected"
        in result["indicators"]
    )


def test_multiple_authentication_failures_are_reported():
    """Multiple authentication failures should be identified."""

    context = build_context(
        {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "pass",
        }
    )

    rule = AuthenticationAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["failed_methods"] == [
        "spf",
        "dkim",
    ]

    assert (
        "Email authentication failure detected"
        in result["indicators"]
    )

    assert (
        "Multiple email authentication methods failed"
        in result["indicators"]
    )


def test_unknown_authentication_results_are_reported():
    """Missing authentication results should be reported as unknown."""

    context = build_context(
        {
            "spf": "unknown",
            "dkim": "pass",
            "dmarc": "unknown",
        }
    )

    rule = AuthenticationAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["failed_methods"] == []
    assert result["unknown_methods"] == [
        "spf",
        "dmarc",
    ]


def test_all_supported_authentication_failure_states_trigger_bec_004():
    """All supported authentication failure states should trigger BEC-004."""

    for failure_state in (
        "softfail",
        "permerror",
        "temperror",
    ):
        context = build_context(
            {
                "spf": failure_state,
                "dkim": "pass",
                "dmarc": "pass",
            }
        )

        rule = AuthenticationAnomalyRule()

        result = rule.evaluate(
            context=context,
        )

        assert result["matched"] is True
        assert result["failed_methods"] == ["spf"]
        assert (
            "Email authentication failure detected"
            in result["indicators"]
        )
