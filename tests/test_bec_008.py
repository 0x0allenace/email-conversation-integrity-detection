from src.rules.bec_008 import MessageContentAnomalyRule
from src.engine.detection_context import DetectionContext


def test_normalize_subject_removes_reply_prefix():
    rule = MessageContentAnomalyRule()

    result = rule._normalize_subject(
        "  Re:   RE: Invoice Update  "
    )

    assert result == "invoice update"


def test_normalize_subject_handles_forward_prefix():
    rule = MessageContentAnomalyRule()

    result = rule._normalize_subject(
        "Fwd: FWD: Supplier Update"
    )

    assert result == "supplier update"


def test_normalize_subject_normalizes_case_and_whitespace():
    rule = MessageContentAnomalyRule()

    result = rule._normalize_subject(
        "  INVOICE   Update   Required "
    )

    assert result == "invoice update required"


def test_normalize_body_normalizes_case_and_whitespace():
    rule = MessageContentAnomalyRule()

    result = rule._normalize_body(
        "Hello   Alice,\n\nPlease review\n"
        "the updated invoice."
    )

    assert result == (
        "hello alice, please review the updated invoice."
    )


def test_normalize_body_handles_empty_value():
    rule = MessageContentAnomalyRule()

    assert rule._normalize_body("") == ""


def test_normalize_body_handles_none():
    rule = MessageContentAnomalyRule()

    assert rule._normalize_body(None) == ""


def test_calculate_similarity_identical_strings():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_similarity(
        "invoice update",
        "invoice update",
    )

    assert result == 1.0


def test_calculate_similarity_empty_strings():
    rule = MessageContentAnomalyRule()

    assert rule._calculate_similarity("", "") == 1.0


def test_calculate_similarity_one_empty_string():
    rule = MessageContentAnomalyRule()

    assert rule._calculate_similarity(
        "invoice update",
        "",
    ) == 0.0


def test_calculate_similarity_similar_strings():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_similarity(
        "invoice update",
        "invoice updated",
    )

    assert 0.8 < result < 1.0


def test_calculate_similarity_different_strings():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_similarity(
        "invoice update",
        "quarterly security report",
    )

    assert result < 0.5


def test_calculate_subject_similarity_requires_minimum_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_subject_similarity(
        "Invoice Update",
        [
            {"subject": "Invoice Update"},
            {"subject": "Invoice Update"},
        ],
    )

    assert result["available"] is False
    assert result["historical_count"] == 2
    assert result["max_similarity"] is None


def test_calculate_subject_similarity_with_matching_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_subject_similarity(
        "Re: Invoice Update",
        [
            {"subject": "Invoice Update"},
            {"subject": "Invoice Update"},
            {"subject": "Invoice Update"},
        ],
    )

    assert result["available"] is True
    assert result["current_subject"] == "invoice update"
    assert result["historical_count"] == 3
    assert result["max_similarity"] == 1.0


def test_calculate_subject_similarity_finds_closest_historical_subject():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_subject_similarity(
        "Invoice Updated",
        [
            {"subject": "Invoice Update"},
            {"subject": "Quarterly Security Report"},
            {"subject": "Supplier Payment"},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] > 0.8


def test_calculate_subject_similarity_detects_low_similarity():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_subject_similarity(
        "Urgent Password Reset",
        [
            {"subject": "Invoice Update"},
            {"subject": "Invoice Update"},
            {"subject": "Supplier Payment"},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] < 0.5


def test_calculate_subject_similarity_ignores_missing_subjects():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_subject_similarity(
        "Invoice Update",
        [
            {},
            {"subject": ""},
            {"subject": None},
            {"subject": "Invoice Update"},
            {"subject": "Supplier Payment"},
            {"subject": "Invoice Update"},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] == 1.0


def test_subject_similarity_anomaly_requires_available_analysis():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": False,
            "current_subject": "invoice update",
            "max_similarity": 0.10,
        }
    ) is False


def test_subject_similarity_anomaly_requires_current_subject():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": True,
            "current_subject": "",
            "max_similarity": 0.10,
        }
    ) is False


def test_subject_similarity_anomaly_requires_similarity_value():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": True,
            "current_subject": "invoice update",
            "max_similarity": None,
        }
    ) is False


def test_subject_similarity_anomaly_detects_low_similarity():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": True,
            "current_subject": "urgent password reset",
            "max_similarity": 0.49,
        }
    ) is True


def test_subject_similarity_anomaly_boundary_is_not_anomalous():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": True,
            "current_subject": "invoice update",
            "max_similarity": 0.50,
        }
    ) is False


def test_subject_similarity_anomaly_above_threshold_is_not_anomalous():
    rule = MessageContentAnomalyRule()

    assert rule._is_subject_similarity_anomaly(
        {
            "available": True,
            "current_subject": "invoice update",
            "max_similarity": 0.75,
        }
    ) is False


def test_calculate_body_similarity_requires_minimum_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_similarity(
        "Please review the invoice.",
        [
            {"body": "Please review the invoice."},
            {"body": "Please review the invoice."},
        ],
    )

    assert result["available"] is False
    assert result["historical_count"] == 2
    assert result["max_similarity"] is None


def test_calculate_body_similarity_with_matching_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_similarity(
        "Hello Alice, Please review the invoice.",
        [
            {"body": "Hello Alice, Please review the invoice."},
            {"body": "Hello Alice, Please review the invoice."},
            {"body": "Hello Alice, Please review the invoice."},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] == 1.0


def test_calculate_body_similarity_finds_closest_historical_body():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_similarity(
        "Please review the updated invoice.",
        [
            {"body": "Please review the invoice."},
            {"body": "Quarterly security report attached."},
            {"body": "Supplier payment confirmation."},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] > 0.8


def test_calculate_body_similarity_detects_low_similarity():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_similarity(
        "Your password will expire immediately. Reset it now.",
        [
            {"body": "Please review the invoice."},
            {"body": "Please review the invoice."},
            {"body": "Supplier payment confirmation."},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] < 0.5


def test_calculate_body_similarity_ignores_missing_bodies():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_similarity(
        "Please review the invoice.",
        [
            {},
            {"body": ""},
            {"body": None},
            {"body": "Please review the invoice."},
            {"body": "Supplier payment confirmation."},
            {"body": "Please review the invoice."},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["max_similarity"] == 1.0


def test_body_similarity_anomaly_requires_available_analysis():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": False,
            "current_body": "urgent password reset",
            "max_similarity": 0.10,
        }
    ) is False


def test_body_similarity_anomaly_requires_current_body():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": True,
            "current_body": "",
            "max_similarity": 0.10,
        }
    ) is False


def test_body_similarity_anomaly_requires_similarity_value():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": True,
            "current_body": "urgent password reset",
            "max_similarity": None,
        }
    ) is False


def test_body_similarity_anomaly_detects_low_similarity():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": True,
            "current_body": "urgent password reset",
            "max_similarity": 0.49,
        }
    ) is True


def test_body_similarity_anomaly_boundary_is_not_anomalous():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": True,
            "current_body": "invoice update",
            "max_similarity": 0.50,
        }
    ) is False


def test_body_similarity_anomaly_above_threshold_is_not_anomalous():
    rule = MessageContentAnomalyRule()

    assert rule._is_body_similarity_anomaly(
        {
            "available": True,
            "current_body": "invoice update",
            "max_similarity": 0.75,
        }
    ) is False


def test_calculate_body_length_requires_minimum_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_length(
        "Current message",
        [
            {"body": "First message"},
            {"body": "Second message"},
        ],
    )

    assert result["available"] is False
    assert result["current_length"] == len("current message")
    assert result["historical_count"] == 2
    assert result["historical_median_length"] is None


def test_calculate_body_length_uses_median_for_odd_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_length(
        "Current message",
        [
            {"body": "a" * 10},
            {"body": "b" * 20},
            {"body": "c" * 30},
        ],
    )

    assert result["available"] is True
    assert result["current_length"] == len("current message")
    assert result["historical_count"] == 3
    assert result["historical_median_length"] == 20


def test_calculate_body_length_uses_middle_average_for_even_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_length(
        "Current message",
        [
            {"body": "a" * 10},
            {"body": "b" * 20},
            {"body": "c" * 30},
            {"body": "d" * 40},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 4
    assert result["historical_median_length"] == 25.0


def test_calculate_body_length_normalizes_body_before_measurement():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_length(
        "Hello   Alice",
        [
            {"body": "a  b"},
            {"body": "hello\nalice"},
            {"body": "hello   alice"},
        ],
    )

    assert result["available"] is True
    assert result["current_length"] == len("hello alice")
    assert result["historical_count"] == 3
    assert result["historical_median_length"] == 11


def test_calculate_body_length_ignores_missing_bodies():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_body_length(
        "Current message",
        [
            {},
            {"body": ""},
            {"body": None},
            {"body": "a" * 10},
            {"body": "b" * 20},
            {"body": "c" * 30},
        ],
    )

    assert result["available"] is True
    assert result["historical_count"] == 3
    assert result["historical_median_length"] == 20

def test_body_length_anomaly_requires_available_analysis():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": False,
            "current_length": 100,
            "historical_median_length": 50,
        }
    )

    assert result is False


def test_body_length_anomaly_handles_missing_lengths():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": None,
            "historical_median_length": 50,
        }
    )

    assert result is False


def test_body_length_anomaly_detects_body_twice_as_long():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 101,
            "historical_median_length": 50,
        }
    )

    assert result is True


def test_body_length_anomaly_detects_body_half_as_long():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 24,
            "historical_median_length": 50,
        }
    )

    assert result is True


def test_body_length_anomaly_accepts_upper_boundary():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 100,
            "historical_median_length": 50,
        }
    )

    assert result is False


def test_body_length_anomaly_accepts_lower_boundary():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 25,
            "historical_median_length": 50,
        }
    )

    assert result is False


def test_body_length_anomaly_detects_against_fractional_median():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 11,
            "historical_median_length": 10.5,
        }
    )

    assert result is False


def test_body_length_anomaly_handles_zero_historical_median():
    rule = MessageContentAnomalyRule()

    result = rule._is_body_length_anomaly(
        {
            "available": True,
            "current_length": 1,
            "historical_median_length": 0,
        }
    )

    assert result is True

def test_evaluate_returns_no_match_without_sufficient_history():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "Please review the updated invoice.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["rule_id"] == "BEC-008"
    assert result["rule_name"] == "Message Content Anomaly"
    assert result["severity"] == "MEDIUM"
    assert result["matched"] is False
    assert result["indicators"] == []


def test_evaluate_returns_no_match_for_normal_content():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "Please review the updated invoice.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is False
    assert result["indicators"] == []


def test_evaluate_detects_subject_similarity_anomaly():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Urgent Security Notification",
            "body": "Please review the updated invoice.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["type"] == "subject_similarity_anomaly"
    assert "evidence" in result["indicators"][0]


def test_evaluate_detects_body_similarity_anomaly():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "Quarterly access review completed.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["type"] == "body_similarity_anomaly"
    assert "evidence" in result["indicators"][0]


def test_evaluate_detects_body_length_anomaly():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "A" * 101,
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "A" * 50,
            },
            {
                "subject": "Invoice Update",
                "body": "B" * 50,
            },
            {
                "subject": "Invoice Update",
                "body": "C" * 50,
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True
    assert len(result["indicators"]) >= 1

    indicator_types = {
        indicator["type"]
        for indicator in result["indicators"]
    }

    assert "body_length_anomaly" in indicator_types


def test_evaluate_returns_multiple_content_anomalies():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Urgent Security Notification",
            "body": "A" * 101,
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "B" * 50,
            },
            {
                "subject": "Invoice Update",
                "body": "C" * 50,
            },
            {
                "subject": "Invoice Update",
                "body": "D" * 50,
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True

    indicator_types = {
        indicator["type"]
        for indicator in result["indicators"]
    }

    assert "subject_similarity_anomaly" in indicator_types
    assert "body_similarity_anomaly" in indicator_types
    assert "body_length_anomaly" in indicator_types


def test_evaluate_indicator_evidence_contains_analysis():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Urgent Security Notification",
            "body": "Please review the quarterly security report immediately.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True

    for indicator in result["indicators"]:
        assert "type" in indicator
        assert "evidence" in indicator
        assert isinstance(indicator["evidence"], dict)

def test_normalize_attachment_filename():
    rule = MessageContentAnomalyRule()

    assert (
        rule._normalize_attachment_filename(
            "  Invoice.PDF  "
        )
        == "invoice.pdf"
    )


def test_normalize_attachment_filename_normalizes_internal_whitespace():
    rule = MessageContentAnomalyRule()

    assert (
        rule._normalize_attachment_filename(
            "bank   details.pdf"
        )
        == "bank details.pdf"
    )


def test_calculate_attachment_novelty_requires_minimum_history():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_novelty(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 9,
            }
        ],
        [
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
        ],
    )

    assert result["available"] is False
    assert result["historical_observation_count"] == 2
    assert result["novel_filenames"] == []


def test_calculate_attachment_novelty_matches_historical_filename():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_novelty(
        [
            {
                "filename": "Invoice.PDF",
                "content_type": "application/pdf",
                "size_bytes": 9,
            }
        ],
        [
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
        ],
    )

    assert result["available"] is True
    assert result["current_filenames"] == ["invoice.pdf"]
    assert result["historical_filenames"] == ["invoice.pdf"]
    assert result["novel_filenames"] == []


def test_calculate_attachment_novelty_detects_new_filename():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_novelty(
        [
            {
                "filename": "bank-details.pdf",
                "content_type": "application/pdf",
                "size_bytes": 100,
            }
        ],
        [
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
        ],
    )

    assert result["available"] is True
    assert result["current_filenames"] == ["bank-details.pdf"]
    assert result["historical_filenames"] == ["invoice.pdf"]
    assert result["novel_filenames"] == ["bank-details.pdf"]


def test_calculate_attachment_novelty_ignores_missing_historical_metadata():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_novelty(
        [
            {"filename": "bank-details.pdf"}
        ],
        [
            {},
            {"subject": "Invoice Update"},
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
            {"attachments": [{"filename": "invoice.pdf"}]},
        ],
    )

    assert result["available"] is True
    assert result["historical_observation_count"] == 3
    assert result["novel_filenames"] == ["bank-details.pdf"]


def test_attachment_novelty_anomaly_requires_available_analysis():
    assert (
        MessageContentAnomalyRule._is_attachment_novelty_anomaly(
            {
                "available": False,
                "novel_filenames": ["invoice.pdf"],
            }
        )
        is False
    )


def test_attachment_novelty_anomaly_detects_novel_filename():
    assert (
        MessageContentAnomalyRule._is_attachment_novelty_anomaly(
            {
                "available": True,
                "novel_filenames": ["bank-details.pdf"],
            }
        )
        is True
    )


def test_attachment_novelty_anomaly_accepts_historical_filename():
    assert (
        MessageContentAnomalyRule._is_attachment_novelty_anomaly(
            {
                "available": True,
                "novel_filenames": [],
            }
        )
        is False
    )


def test_calculate_attachment_size_detects_larger_than_historical_median():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 201,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 201,
        }
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 201,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 100.0,
        }
    ]


def test_calculate_attachment_size_detects_smaller_than_historical_median():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 49,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 49,
        }
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 49,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 100.0,
        }
    ]


def test_calculate_attachment_size_accepts_upper_boundary():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 200,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 200,
        }
    ]
    assert result["anomalies"] == []




def test_calculate_attachment_size_accepts_lower_boundary():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 50,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 50,
        }
    ]
    assert result["anomalies"] == []




def test_calculate_attachment_size_detects_positive_size_against_zero_median():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 1,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 1,
        }
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 1,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 0.0,
        }
    ]





def test_calculate_attachment_size_accepts_zero_size_against_zero_median():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 0,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 0,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 0,
        }
    ]
    assert result["anomalies"] == []





def test_calculate_attachment_size_ignores_invalid_historical_sizes():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 201,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": "100",
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": True,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 201,
        }
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 201,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 100.0,
        }
    ]


def test_calculate_attachment_size_ignores_invalid_current_attachments():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 201,
            },
            {
                "filename": "invalid-string-size.pdf",
                "content_type": "application/pdf",
                "size_bytes": "201",
            },
            {
                "filename": "invalid-bool-size.pdf",
                "content_type": "application/pdf",
                "size_bytes": True,
            },
            {
                "content_type": "application/pdf",
                "size_bytes": 201,
            },
            {
                "filename": "missing-size.pdf",
                "content_type": "application/pdf",
            },
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 201,
        }
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 201,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 100.0,
        }
    ]


def test_calculate_attachment_size_uses_per_filename_historical_baselines():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 201,
            },
            {
                "filename": "contract.pdf",
                "content_type": "application/pdf",
                "size_bytes": 1500,
            },
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    },
                    {
                        "filename": "contract.pdf",
                        "size_bytes": 1000,
                    },
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    },
                    {
                        "filename": "contract.pdf",
                        "size_bytes": 1000,
                    },
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    },
                    {
                        "filename": "contract.pdf",
                        "size_bytes": 1000,
                    },
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 201,
        },
        {
            "filename": "contract.pdf",
            "size_bytes": 1500,
        },
    ]
    assert result["anomalies"] == [
        {
            "filename": "invoice.pdf",
            "current_size_bytes": 201,
            "historical_observation_count": 3,
            "historical_median_size_bytes": 100.0,
        }
    ]


def test_calculate_attachment_size_requires_minimum_historical_observations():
    rule = MessageContentAnomalyRule()

    result = rule._calculate_attachment_size_anomaly(
        [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 201,
            }
        ],
        [
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
            {
                "attachments": [
                    {
                        "filename": "invoice.pdf",
                        "size_bytes": 100,
                    }
                ]
            },
        ],
    )

    assert result["available"] is True
    assert result["current_attachments"] == [
        {
            "filename": "invoice.pdf",
            "size_bytes": 201,
        }
    ]
    assert result["anomalies"] == []



def test_evaluate_detects_attachment_novelty_anomaly():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "Please review the updated invoice.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        attachments=[
            {
                "filename": "bank-details.pdf",
                "content_type": "application/pdf",
                "size_bytes": 100,
            }
        ],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
        ],
    )

    result = rule.evaluate(context)

    assert result["matched"] is True

    indicator_types = {
        indicator["type"]
        for indicator in result["indicators"]
    }

    assert "attachment_novelty_anomaly" in indicator_types


def test_evaluate_does_not_flag_historical_attachment_as_novel():
    rule = MessageContentAnomalyRule()

    context = DetectionContext(
        email_data={
            "subject": "Invoice Update",
            "body": "Please review the updated invoice.",
        },
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[],
        known_hosts=[],
        known_ip_addresses=[],
        attachments=[
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 9,
            }
        ],
        historical_observations=[
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
            {
                "subject": "Invoice Update",
                "body": "Please review the updated invoice.",
                "attachments": [{"filename": "invoice.pdf"}],
            },
        ],
    )

    result = rule.evaluate(context)

    indicator_types = {
        indicator["type"]
        for indicator in result["indicators"]
    }

    assert "attachment_novelty_anomaly" not in indicator_types
