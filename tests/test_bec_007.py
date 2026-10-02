from src.engine.detection_context import DetectionContext
from src.rules.bec_007 import BehavioralCommunicationAnomalyRule


def build_context(
    *,
    date: str,
    typical_hours: list[int],
    recipients: list[str] | None = None,
    to_recipients: list[str] | None = None,
    cc_recipients: list[str] | None = None,
    typical_days: list[int] | None = None,
    typical_timezone_offsets: list[int] | None = None,
    historical_observations: list[dict] | None = None,
) -> DetectionContext:
    """Build a detection context for BEC-007 tests."""

    email_data = {
        "date": date,
    }

    if to_recipients is not None:
        email_data["to"] = to_recipients

    if cc_recipients is not None:
        email_data["cc"] = cc_recipients

    return DetectionContext(
        email_data=email_data,
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
        recipients=(
            recipients
            if recipients is not None
            else []
        ),
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


def test_bec_007_builds_behavioral_feature_vector():
    """BEC-007 should expose normalized behavioral anomaly features."""

    context = build_context(
        date="2026-01-05T10:00:00+00:00",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "result": {
                    "email": {
                        "date": "2026-01-01T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-02T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-03T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
        ],
    )

    result = BehavioralCommunicationAnomalyRule().evaluate(context)

    assert result["behavioral_features"] == {
        "sending_hour_anomaly": 0,
        "sending_day_anomaly": 0,
        "timezone_anomaly": 0,
        "historical_hour_anomaly": 0,
        "frequency_anomaly": 0,
        "recipient_novelty": 0,
        "recipient_frequency_anomaly": 0,
        "recipient_relationship_anomaly": 0,
        "recipient_role_anomaly": 0,
        "recipient_group_anomaly": 0,
        "recipient_recency_anomaly": 0,
        "recipient_sequence_anomaly": 0,
    }


def test_bec_007_exposes_behavioral_deviation_metrics():
    """BEC-007 should expose continuous behavioral deviation metrics."""

    context = build_context(
        date="Mon, 05 Jan 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-01-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "email_sent_at": "2026-01-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "email_sent_at": "2026-01-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
        ],
    )

    result = BehavioralCommunicationAnomalyRule().evaluate(context)

    assert result["behavioral_metrics"] == {
        "frequency_interval_ratio": 2.0,
        "recipient_historical_frequencies": {
            "alice@company.com": 1.0,
        },
        "recipient_group_frequency": 1.0,
        "recipient_pair_frequencies": {},
        "recipient_role_frequencies": {
            (
                "alice@company.com",
                "To",
            ): 1.0,
        },
        "recipient_transition_frequency": 1.0,
        "recipient_recency_ratios": {
            "alice@company.com": 2.0,
        },
    }


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


def test_bec_007_detects_unusual_historical_recipient():
    """BEC-007 should detect a previously unseen recipient."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        typical_days=[1],
        typical_timezone_offsets=[60],
        recipients=[
            "alice@company.com",
            "attacker@evil.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert "attacker@evil.com" in result["unusual_recipients"]
    assert (
        "Message sent to a previously unseen recipient"
        in result["indicators"]
    )


def test_bec_007_allows_historically_observed_recipients():
    """BEC-007 should allow recipients seen in sender history."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["unusual_recipients"] == []


def test_bec_007_requires_minimum_historical_observations_for_recipients():
    """BEC-007 should require three observations for recipient detection."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "attacker@evil.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["unusual_recipients"] == []


def test_bec_007_detects_historically_infrequent_recipient():
    """BEC-007 should detect a recipient with unusually low historical frequency."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                            "finance@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:15:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:20:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:25:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:28:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert result["infrequent_recipients"] == [
        "finance@company.com"
    ]
    assert (
        "Message sent to a historically infrequent recipient"
        in result["indicators"]
    )

    assert (
        result["historical_recipient_frequencies"][
            "finance@company.com"
        ]
        == 0.1
    )


def test_bec_007_allows_normally_frequent_recipient():
    """BEC-007 should allow a recipient with normal historical frequency."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["infrequent_recipients"] == []
    assert (
        result["historical_recipient_frequencies"][
            "alice@company.com"
        ]
        == 1.0
    )


def test_bec_007_requires_minimum_historical_observations_for_recipient_frequency():
    """BEC-007 should require three observations for recipient frequency detection."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                            "finance@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["infrequent_recipients"] == []
    assert result["historical_recipient_frequencies"] == {}


def test_bec_007_detects_unusually_high_sending_frequency():
    """BEC-007 should detect a sudden increase in sending frequency."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T10:00:00+00:00",
            },
            {
                "email_sent_at": "2026-09-21T10:00:00+00:00",
            },
            {
                "email_sent_at": "2026-09-22T10:00:00+00:00",
            },
            {
                "email_sent_at": "2026-09-23T08:00:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert (
        "Message sent at an unusually high communication frequency"
        in result["indicators"]
    )
    assert result["historical_frequency_interval"] == 1440.0
    assert result["current_frequency_interval"] == 120.0


def test_bec_007_allows_normal_sending_frequency():
    """BEC-007 should allow a current interval near the historical baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T10:00:00+00:00",
            },
            {
                "email_sent_at": "2026-09-21T10:00:00+00:00",
            },
            {
                "email_sent_at": "2026-09-22T10:00:00+00:00",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["historical_frequency_interval"] == 1440.0
    assert result["current_frequency_interval"] == 1440.0


def test_bec_007_detects_unusual_recipient_cooccurrence():
    """BEC-007 should detect an unusual relationship between known recipients."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "ceo@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["ceo@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:15:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:20:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:25:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-23T10:28:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert result["unusual_recipient_pairs"] == [
        (
            "alice@company.com",
            "ceo@company.com",
        )
    ]
    assert (
        "Message contains a historically unusual recipient relationship"
        in result["indicators"]
    )

    assert result["historical_recipient_cooccurrences"] == {}


def test_bec_007_allows_established_recipient_cooccurrence():
    """BEC-007 should allow a recipient relationship seen historically."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["unusual_recipient_pairs"] == []

    assert (
        result["historical_recipient_cooccurrences"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )

    assert (
        result["behavioral_metrics"]["recipient_pair_frequencies"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )


def test_bec_007_combines_to_and_cc_for_recipient_cooccurrence():
    """BEC-007 should treat To and Cc recipients as one relationship set."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["unusual_recipient_pairs"] == []

    assert (
        result["historical_recipient_cooccurrences"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )


def test_bec_007_does_not_use_cooccurrence_for_unseen_recipient():
    """BEC-007 should use the existing unseen-recipient signal for new recipients."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "attacker@evil.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-22T14:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert result["unusual_recipients"] == [
        "attacker@evil.com"
    ]
    assert result["unusual_recipient_pairs"] == []

    assert (
        "Message sent to a previously unseen recipient"
        in result["indicators"]
    )

    assert (
        "Message contains a historically unusual recipient relationship"
        not in result["indicators"]
    )


def test_bec_007_requires_minimum_historical_observations_for_cooccurrence():
    """BEC-007 should require three recipient-bearing observations for co-occurrence detection."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 23 Sep 2026 10:30:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "ceo@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-20T09:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-21T10:30:00+00:00",
                "result": {
                    "email": {
                        "to": ["ceo@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []
    assert result["historical_recipient_cooccurrences"] == {}
    assert result["unusual_recipient_pairs"] == []


def test_bec_007_detects_unusual_recipient_role_relationship():
    """BEC-007 should detect an established pair appearing in unusual roles."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        cc_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-15T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-16T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-17T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert (
        "Message contains a historically unusual recipient role relationship"
        in result["indicators"]
    )
    assert result["unusual_recipient_role_pairs"] == [
        (
            "alice@company.com",
            "cc",
            "finance@company.com",
            "to",
        )
    ]


def test_bec_007_allows_established_recipient_role_relationship():
    """BEC-007 should allow a recipient pair in its established roles."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-15T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-16T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-17T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["unusual_recipient_role_pairs"] == []


def test_bec_007_handles_to_and_cc_roles_correctly():
    """BEC-007 should preserve To and Cc roles when building history."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 11:00:00 +0100",
        typical_hours=[11],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-15T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-16T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-17T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_role_frequencies"] == {
        (
            "alice@company.com",
            "to",
            "finance@company.com",
            "cc",
        ): 1.0
    }

    assert result["unusual_recipient_role_pairs"] == []


def test_bec_007_does_not_use_role_anomaly_for_unseen_recipient_pair():
    """BEC-007 should leave unseen recipient pairs to co-occurrence detection."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 11:00:00 +0100",
        typical_hours=[11],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-15T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-16T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-17T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["unusual_recipient_role_pairs"] == []


def test_bec_007_requires_minimum_historical_observations_for_recipient_roles():
    """BEC-007 should require three observations for recipient role detection."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 11:00:00 +0100",
        typical_hours=[11],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        cc_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-15T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-16T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": ["finance@company.com"],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["historical_recipient_role_frequencies"] == {}
    assert result["unusual_recipient_role_pairs"] == []


def test_bec_007_calculates_recipient_role_frequency_within_established_pair():
    """BEC-007 should calculate role frequency within the recipient relationship."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "finance@company.com",
                        ],
                        "cc": [
                            "alice@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-06T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "other1@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-07T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "other2@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-08T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "other3@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-09T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "other4@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-10T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "other5@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        result["historical_recipient_role_frequencies"][
            (
                "alice@company.com",
                "to",
                "finance@company.com",
                "cc",
            )
        ]
        == 0.8
    )

    assert (
        result["historical_recipient_role_frequencies"][
            (
                "alice@company.com",
                "cc",
                "finance@company.com",
                "to",
            )
        ]
        == 0.2
    )


def test_bec_007_calculates_historical_recipient_group_frequency():
    """BEC-007 should calculate frequency for complete recipient groups."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        result["historical_recipient_group_frequencies"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )


def test_bec_007_detects_unusual_recipient_group():
    """BEC-007 should identify a recipient group not seen historically."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
            "ceo@company.com",
        ],
        to_recipients=[
            "alice@company.com",
            "ceo@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        (
            "alice@company.com",
            "ceo@company.com",
            "finance@company.com",
        )
        in result["unusual_recipient_groups"]
    )


def test_bec_007_recipient_group_is_order_independent():
    """BEC-007 should treat recipient ordering as irrelevant."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
            "alice@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        cc_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "finance@company.com",
                        ],
                        "cc": [
                            "alice@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        result["historical_recipient_group_frequencies"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )


def test_bec_007_recipient_group_ignores_duplicate_recipients():
    """BEC-007 should not count duplicate recipients as separate group members."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        result["historical_recipient_group_frequencies"][
            (
                "alice@company.com",
                "finance@company.com",
            )
        ]
        == 1.0
    )


def test_bec_007_requires_minimum_historical_observations_for_recipient_groups():
    """BEC-007 should require minimum history before building recipient groups."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        cc_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [
                            "finance@company.com",
                        ],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_group_frequencies"] == {}
    assert result["unusual_recipient_groups"] == []


def test_bec_007_calculates_individual_recipient_role_frequency():
    """BEC-007 should calculate historical To/Cc frequency per recipient."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [],
                        "cc": [
                            "alice@company.com",
                        ],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        result["historical_individual_recipient_role_frequencies"][
            (
                "alice@company.com",
                "to",
            )
        ]
        == 0.75
    )

    assert (
        result["historical_individual_recipient_role_frequencies"][
            (
                "alice@company.com",
                "cc",
            )
        ]
        == 0.25
    )


def test_bec_007_detects_unusual_individual_recipient_role():
    """BEC-007 should detect an unusual To/Cc role for a known recipient."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
        ],
        to_recipients=[],
        cc_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        (
            "alice@company.com",
            "cc",
        )
        in result["unusual_recipient_roles"]
    )


def test_bec_007_allows_established_individual_recipient_role():
    """BEC-007 should allow a historically established recipient role."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
        ],
        to_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["unusual_recipient_roles"] == []


def test_bec_007_requires_minimum_historical_observations_for_individual_recipient_roles():
    """BEC-007 should require minimum history before analyzing recipient roles."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Fri, 18 Sep 2026 10:00:00 +0100",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
        ],
        to_recipients=[],
        cc_recipients=[
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T09:00:00+00:00",
                "result": {
                    "email": {
                        "to": [
                            "alice@company.com",
                        ],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_role_frequencies"] == {}
    assert result["unusual_recipient_roles"] == []
def test_bec_007_calculates_recipient_specific_interval_statistics():
    """BEC-007 should calculate communication intervals separately for each recipient."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 28 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com", "bob@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-07T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-10T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-19T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_interval_statistics"] == {
        "alice@company.com": {
            "median_interval_minutes": 2880.0,
            "interval_count": 3,
        },
        "bob@company.com": {
            "median_interval_minutes": 12960.0,
            "interval_count": 2,
        },
    }


def test_bec_007_detects_unusually_long_recipient_recency():
    """BEC-007 should detect an unusually long gap for a known recipient."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 28 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-07T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert (
        "Message sent after an unusually long recipient communication gap"
        in result["indicators"]
    )
    assert result["unusual_recipient_recency"] == ["alice@company.com"]


def test_bec_007_allows_normal_recipient_recency():
    """BEC-007 should allow a recipient gap near the historical baseline."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Wed, 09 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-07T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["unusual_recipient_recency"] == []
    assert result["indicators"] == []


def test_bec_007_requires_minimum_historical_observations_for_recipient_recency():
    """BEC-007 should require enough recipient history before calculating recency."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 28 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["unusual_recipient_recency"] == []
    assert result["historical_recipient_interval_statistics"] == {}


def test_bec_007_ignores_other_recipient_messages_when_calculating_recency():
    """BEC-007 should calculate Alice's recency independently of Bob's activity."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Tue, 15 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=["alice@company.com"],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["bob@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-06T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_interval_statistics"]["alice@company.com"] == {
        "median_interval_minutes": 3600.0,
        "interval_count": 2,
    }

    assert result["matched"] is False


def test_bec_007_calculates_historical_recipient_transition_frequency():

    """BEC-007 should calculate frequency for adjacent recipient groups."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(

        date="Mon, 14 Sep 2026 10:00:00 +0000",

        typical_hours=[10],

        recipients=[

            "alice@company.com",

        ],

        to_recipients=[

            "alice@company.com",

        ],

        historical_observations=[

            {

                "email_sent_at": "2026-09-01T10:00:00+00:00",

                "result": {

                    "email": {

                        "to": ["alice@company.com"],

                        "cc": [],

                    },

                },

            },

            {

                "email_sent_at": "2026-09-02T10:00:00+00:00",

                "result": {

                    "email": {

                        "to": ["finance@company.com"],

                        "cc": [],

                    },

                },

            },

            {

                "email_sent_at": "2026-09-03T10:00:00+00:00",

                "result": {

                    "email": {

                        "to": ["alice@company.com"],

                        "cc": [],

                    },

                },

            },

            {

                "email_sent_at": "2026-09-04T10:00:00+00:00",

                "result": {

                    "email": {

                        "to": ["finance@company.com"],

                        "cc": [],

                    },

                },

            },

        ],

    )

    result = rule.evaluate(context)

    assert (

        result["historical_recipient_transition_frequencies"][

            (

                ("alice@company.com",),

                ("finance@company.com",),

            )

        ]

        == 2 / 3

    )

    assert (

        result["historical_recipient_transition_frequencies"][

            (

                ("finance@company.com",),

                ("alice@company.com",),

            )

        ]

        == 1 / 3

    )



def test_bec_007_calculates_current_recipient_transition():

    """BEC-007 should expose the latest historical group to current group transition."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["current_recipient_transition"] == (
        ("alice@company.com",),
        ("finance@company.com",),
    )


def test_bec_007_detects_unusual_recipient_transition():

    """BEC-007 should detect a recipient transition that is historically unusual."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "hr@company.com",
        ],
        to_recipients=[
            "hr@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["current_recipient_transition"] == (
        ("alice@company.com",),
        ("hr@company.com",),
    )

    assert result["behavioral_metrics"]["recipient_transition_frequency"] == 0.0

    assert (
        (
            ("alice@company.com",),
            ("hr@company.com",),
        )
        in result["unusual_recipient_transitions"]
    )

    assert (
        "Message follows an unusual recipient communication sequence"
        in result["indicators"]
    )




def test_bec_007_does_not_flag_common_recipient_transition():

    """BEC-007 should not flag a historically common recipient transition."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-05T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["current_recipient_transition"] == (
        ("alice@company.com",),
        ("finance@company.com",),
    )

    assert (
        result["historical_recipient_transition_frequencies"][
            (
                ("alice@company.com",),
                ("finance@company.com",),
            )
        ]
        == 2 / 4
    )

    assert result["unusual_recipient_transitions"] == []

    assert (
        "Message follows an unusual recipient communication sequence"
        not in result["indicators"]
    )


def test_bec_007_requires_minimum_history_for_recipient_transitions():

    """BEC-007 should not calculate recipient transitions with insufficient history."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["historical_recipient_transition_frequencies"] == {}
    assert result["current_recipient_transition"] is None
    assert result["unusual_recipient_transitions"] == []




def test_bec_007_recipient_transition_is_independent_of_recipient_order():

    """BEC-007 should normalize recipient-group ordering before sequence analysis."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
            "alice@company.com",
        ],
        to_recipients=[
            "finance@company.com",
            "alice@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["hr@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["current_recipient_transition"] == (
        (
            ("alice@company.com",),
            (
                "alice@company.com",
                "finance@company.com",
            ),
        )
    )

    assert (
        (
            (
                "alice@company.com",
            ),
            (
                "alice@company.com",
                "finance@company.com",
            ),
        )
        in result["unusual_recipient_transitions"]
    )


def test_bec_007_recipient_transition_ignores_duplicate_recipients():

    """BEC-007 should remove duplicate recipients before sequence analysis."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "alice@company.com",
            "alice@company.com",
            "finance@company.com",
        ],
        to_recipients=[
            "alice@company.com",
            "alice@company.com",
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["hr@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["hr@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["current_recipient_transition"] == (
        (
            ("hr@company.com",),
            (
                "alice@company.com",
                "finance@company.com",
            ),
        )
    )

    assert (
        (
            (
                "hr@company.com",
            ),
            (
                "alice@company.com",
                "finance@company.com",
            ),
        )
        in result["unusual_recipient_transitions"]
    )


def test_bec_007_invalid_recipient_observation_breaks_transition_sequence():

    """BEC-007 should not connect recipient groups across an invalid observation."""

    rule = BehavioralCommunicationAnomalyRule()

    context = build_context(
        date="Mon, 14 Sep 2026 10:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "finance@company.com",
        ],
        to_recipients=[
            "finance@company.com",
        ],
        historical_observations=[
            {
                "email_sent_at": "2026-09-01T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-02T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": [],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-03T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["finance@company.com"],
                        "cc": [],
                    },
                },
            },
            {
                "email_sent_at": "2026-09-04T10:00:00+00:00",
                "result": {
                    "email": {
                        "to": ["alice@company.com"],
                        "cc": [],
                    },
                },
            },
        ],
    )

    result = rule.evaluate(context)

    assert (
        (
            ("alice@company.com",),
            ("finance@company.com",),
        )
        not in result["historical_recipient_transition_frequencies"]
    )

    assert (
        (
            ("finance@company.com",),
            ("alice@company.com",),
        )
        in result["historical_recipient_transition_frequencies"]
    )

def test_bec_007_builds_behavioral_summary():
    """BEC-007 should summarize active behavioral anomaly features."""

    context = build_context(
        date="Mon, 05 Jan 2026 23:00:00 +0000",
        typical_hours=[10],
        recipients=[
            "new@company.com",
        ],
        to_recipients=[
            "new@company.com",
        ],
        historical_observations=[
            {
                "result": {
                    "email": {
                        "date": "2026-01-01T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-02T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-03T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
        ],
    )

    result = BehavioralCommunicationAnomalyRule().evaluate(context)

    assert result["behavioral_features"]["sending_hour_anomaly"] == 1
    assert result["behavioral_features"]["recipient_novelty"] == 1

    assert result["behavioral_anomaly_count"] == 5
    assert result["behavioral_anomaly_ratio"] == 5 / 12
    assert result["anomalous_behavioral_features"] == [
        "sending_hour_anomaly",
        "historical_hour_anomaly",
        "recipient_novelty",
        "recipient_group_anomaly",
        "recipient_sequence_anomaly",
    ]


def test_bec_007_exposes_behavioral_evidence():
    """BEC-007 should expose evidence behind active behavioral features."""

    context = build_context(
        date="Mon, 05 Jan 2026 23:00:00 +0000",
        typical_hours=[10],
        typical_days=[1],
        typical_timezone_offsets=[60],
        recipients=[
            "new@company.com",
        ],
        to_recipients=[
            "new@company.com",
        ],
        historical_observations=[
            {
                "result": {
                    "email": {
                        "date": "2026-01-01T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-02T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
            {
                "result": {
                    "email": {
                        "date": "2026-01-03T10:00:00+00:00",
                        "to": ["alice@company.com"],
                        "cc": [],
                    }
                }
            },
        ],
    )

    result = BehavioralCommunicationAnomalyRule().evaluate(context)

    assert result["behavioral_evidence"] == {
        "sending_hour_anomaly": {
            "detected": 1,
            "evidence": {
                "observed_hour": 23,
                "typical_hours": [10],
            },
        },
        "sending_day_anomaly": {
            "detected": 1,
            "evidence": {
                "observed_weekday": 0,
                "typical_days": [1],
            },
        },
        "timezone_anomaly": {
            "detected": 1,
            "evidence": {
                "observed_timezone_offset": 0,
                "typical_timezone_offsets": [60],
            },
        },
        "historical_hour_anomaly": {
            "detected": 1,
            "evidence": {
                "observed_hour": 23,
                "historical_hour_range": [10, 10],
            },
        },
        "recipient_novelty": {
            "detected": 1,
            "evidence": {
                "recipients": ["new@company.com"],
            },
        },
        "recipient_group_anomaly": {
            "detected": 1,
            "evidence": {
                "groups": [
                    ["new@company.com"],
                ],
            },
        },
        "recipient_sequence_anomaly": {
            "detected": 1,
            "evidence": {
                "transitions": [
                    (
                        ("alice@company.com",),
                        ("new@company.com",),
                    ),
                ],
            },
        },
    }
