from src.engine.detection_context import DetectionContext
from src.rules.bec_007 import BehavioralCommunicationAnomalyRule


def build_context(
    *,
    date: str,
    typical_hours: list[int],
    typical_days: list[int] | None = None,
    typical_timezone_offsets: list[int] | None = None,
    historical_observations: list[dict] | None = None,
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
            "typical_days": (
                typical_days
                if typical_days is not None
                else []
            ),
            "typical_timezone_offsets": (
                typical_timezone_offsets
                if typical_timezone_offsets is not None
                else []
            ),
        },
        historical_observations=(
            historical_observations
            if historical_observations is not None
            else []
        ),
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
    assert result["observed_weekday"] == 2


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
    assert result["observed_weekday"] == 2


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


def test_bec_007_detects_unusual_sending_day():
    """BEC-007 should detect a message sent outside normal days."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Sun, 27 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_days=list(range(5)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is True

    assert (
        "Message sent outside established communication days"
        in result["indicators"]
    )

    assert result["observed_hour"] == 10
    assert result["observed_weekday"] == 6
    assert result["typical_days"] == list(range(5))


def test_bec_007_allows_normal_sending_day():
    """BEC-007 should not flag a message sent during normal days."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_days=list(range(5)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []

    assert result["observed_hour"] == 10
    assert result["observed_weekday"] == 2
    assert result["typical_days"] == list(range(5))


def test_bec_007_detects_multiple_behavioral_anomalies():
    """BEC-007 should report both hour and day anomalies."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Sun, 27 Sep 2026 02:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_days=list(range(5)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is True

    assert (
        "Message sent outside established communication hours"
        in result["indicators"]
    )

    assert (
        "Message sent outside established communication days"
        in result["indicators"]
    )

    assert result["observed_hour"] == 2
    assert result["observed_weekday"] == 6


def test_bec_007_detects_unexpected_timezone_offset():
    """BEC-007 should detect an unexpected timezone offset."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 -0500",
        typical_hours=list(range(8, 18)),
        typical_timezone_offsets=[60],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is True

    assert (
        "Message sent from an unexpected timezone offset"
        in result["indicators"]
    )

    assert result["observed_timezone_offset"] == -300
    assert result["typical_timezone_offsets"] == [60]


def test_bec_007_allows_expected_timezone_offset():
    """BEC-007 should allow an established timezone offset."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_timezone_offsets=[60],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []

    assert result["observed_timezone_offset"] == 60
    assert result["typical_timezone_offsets"] == [60]


def test_bec_007_handles_missing_timezone_baseline():
    """BEC-007 should not flag an email without a timezone baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 -0500",
        typical_hours=list(range(8, 18)),
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []

    assert result["observed_timezone_offset"] == -300
    assert result["typical_timezone_offsets"] == []


def test_bec_007_ignores_invalid_hour_baseline_values():
    """BEC-007 should ignore an invalid hour-only baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[25],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["observed_hour"] == 10


def test_bec_007_ignores_invalid_day_baseline_values():
    """BEC-007 should ignore an invalid weekday-only baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_days=[7],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["observed_weekday"] == 2


def test_bec_007_ignores_invalid_timezone_baseline_values():
    """BEC-007 should ignore an invalid timezone-only baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=list(range(8, 18)),
        typical_timezone_offsets=[9999],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["observed_timezone_offset"] == 60


def test_bec_007_detects_historical_sending_hour_anomaly():
    """BEC-007 should detect a current hour outside historical behavior."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 03:30:00 +0100",
        typical_hours=[],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-007"
    assert result["matched"] is True

    assert (
        "Message sent outside historically observed communication hours"
        in result["indicators"]
    )

    assert result["historical_hours"] == [9, 10, 14]
    assert result["historical_hour_range"] == (9, 14)
    assert result["observed_hour"] == 3


def test_bec_007_allows_hour_inside_historical_range():
    """BEC-007 should allow a current hour inside historical behavior."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 12:30:00 +0100",
        typical_hours=[],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["historical_hours"] == [9, 10, 14]
    assert result["historical_hour_range"] == (9, 14)
    assert result["observed_hour"] == 12


def test_bec_007_requires_minimum_historical_observations():
    """BEC-007 should not use an undersized historical baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 03:30:00 +0100",
        typical_hours=[],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["historical_hours"] == [9, 10]
    assert result["historical_hour_range"] is None


def test_bec_007_ignores_invalid_historical_timestamps():
    """BEC-007 should ignore invalid historical timestamps."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 03:30:00 +0100",
        typical_hours=[],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
            },
            {
                "email_sent_at": "not-a-timestamp",
            },
            {},
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert result["historical_hours"] == [9, 10, 14]
    assert result["historical_hour_range"] == (9, 14)
