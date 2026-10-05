from pathlib import Path

from src.engine.detection_engine import DetectionEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]

LEGITIMATE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)

SUSPICIOUS_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "lookalike-domain"
    / "supplier-lookalike.eml"
)

REPLY_TO_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "reply-to-manipulation"
    / "reply-to-mismatch.eml"
)

THREAD_HIJACKING_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "thread-hijacking"
    / "thread-hijacking.eml"
)

INFRASTRUCTURE_ANOMALY_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "thread-hijacking"
    / "infrastructure-anomaly.eml"
)


KNOWN_PARTICIPANTS = [
    "alice@company.com",
    "bob@supplier.com",
]


KNOWN_HOSTS = [
    "mail.supplier.com",
    "relay.supplier.com",
]


KNOWN_IP_ADDRESSES = [
    "192.0.2.10",
    "192.0.2.20",
]


KNOWN_BEHAVIOR = {
    "typical_hours": list(range(8, 18)),
}


def test_legitimate_email_has_no_detection():
    """Test that a legitimate email produces no detections."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    assert all(
        detection["matched"] is False
        for detection in result["detections"]
    )


def test_suspicious_email_triggers_bec_001():
    """Test that a lookalike domain triggers BEC-001."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(SUSPICIOUS_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_001 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-001"
    )

    assert bec_001["matched"] is True
    assert bec_001["risk_score"] == 100


def test_reply_to_email_triggers_bec_002():
    """Test that Reply-To manipulation triggers BEC-002."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(REPLY_TO_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_002 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-002"
    )

    assert bec_002["matched"] is True
    assert bec_002["risk_score"] == 50


def test_thread_hijacking_triggers_bec_003():
    """Test that an unexpected participant triggers BEC-003."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(THREAD_HIJACKING_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_003 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-003"
    )

    assert bec_003["matched"] is True
    assert bec_003["risk_score"] == 30

    assert (
        "Unexpected participant detected in conversation"
        in bec_003["indicators"]
    )


def test_suspicious_email_triggers_bec_004():
    """Test that authentication failures trigger BEC-004."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(SUSPICIOUS_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_004 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-004"
    )

    assert bec_004["matched"] is True
    assert bec_004["risk_score"] == 30

    assert (
        "Email authentication failure detected"
        in bec_004["indicators"]
    )

    assert (
        "Multiple email authentication methods failed"
        in bec_004["indicators"]
    )


def test_authentication_results_are_returned():
    """Test that authentication analysis is included in engine output."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    assert result["authentication"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    }


def test_infrastructure_anomaly_triggers_bec_005():
    """Test that unexpected infrastructure triggers BEC-005."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(INFRASTRUCTURE_ANOMALY_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_005 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-005"
    )

    assert bec_005["matched"] is True
    assert bec_005["risk_score"] == 20

    assert (
        "Unexpected sending host detected"
        in bec_005["indicators"]
    )

    assert (
        "Unexpected sending IP address detected"
        in bec_005["indicators"]
    )


def test_legitimate_email_does_not_trigger_bec_006():
    """Test that a known participant does not trigger BEC-006."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_006 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-006"
    )

    assert bec_006["matched"] is False
    assert bec_006["risk_score"] == 0


def test_thread_hijacking_triggers_bec_006():
    """Test that conversation hijacking triggers BEC-006."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(THREAD_HIJACKING_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
    )

    bec_006 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-006"
    )

    assert bec_006["matched"] is True
    assert bec_006["risk_score"] == 20

    assert (
        "Message contains existing conversation thread headers"
        in bec_006["indicators"]
    )

    assert (
        "Sender is not a known participant in the conversation"
        in bec_006["indicators"]
    )


def test_legitimate_email_does_not_trigger_bec_007():
    """Test that normal communication hours do not trigger BEC-007."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    bec_007 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-007"
    )

    assert bec_007["matched"] is False
    assert bec_007["risk_score"] == 0
    assert bec_007["observed_hour"] == 10


def test_bec_007_detects_unusual_sending_hour_through_engine():
    """Test BEC-007 through the complete DetectionEngine pipeline."""

    engine = DetectionEngine()

    result = engine.analyze(
        str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior={
            "typical_hours": [2, 3, 4],
        },
    )

    bec_007 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-007"
    )

    assert bec_007["matched"] is True
    assert bec_007["risk_score"] == 20
    assert bec_007["observed_hour"] == 10

    assert (
        "Message sent outside established communication hours"
        in bec_007["indicators"]
    )


def test_detection_engine_passes_historical_observations_to_bec_007(
    tmp_path,
):
    """Test historical observations through the DetectionEngine."""

    email_file = tmp_path / "historical-behavior.eml"

    email_file.write_text(
        """From: bob@supplier.com
To: alice@company.com
Subject: Historical behavior test
Date: Wed, 23 Sep 2026 03:30:00 +0100
Message-ID: <historical-behavior@example.com>

This message is outside the sender's historically observed
communication hours.
""",
        encoding="utf-8",
    )

    historical_observations = [
        {
            "id": 1,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-20T09:30:00+00:00",
        },
        {
            "id": 2,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-21T10:30:00+00:00",
        },
        {
            "id": 3,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-22T14:00:00+00:00",
        },
    ]

    engine = DetectionEngine()

    result = engine.analyze(
        file_path=str(email_file),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        historical_observations=historical_observations,
    )

    bec_007 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-007"
    )

    assert bec_007["matched"] is True
    assert bec_007["historical_hours"] == [
        9,
        10,
        14,
    ]
    assert bec_007["historical_hour_range"] == (
        9,
        14,
    )
    assert (
        "Message sent outside historically observed "
        "communication hours"
        in bec_007["indicators"]
    )


def test_detection_engine_passes_attachment_usage_to_bec_007():
    """Test BEC-007 attachment usage through the DetectionEngine."""

    engine = DetectionEngine()

    email_data = {
        "from": "Bob Supplier <bob@supplier.com>",
        "to": [
            "Alice Company <alice@company.com>",
        ],
        "cc": [],
        "reply_to": "",
        "return_path": "bob@supplier.com",
        "subject": "Invoice",
        "body": "Please find the invoice attached.",
        "attachments": [
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size_bytes": 1024,
            }
        ],
        "attachment_count": 1,
        "date": "Wed, 23 Sep 2026 10:00:00 +0000",
        "message_id": "<attachment-usage@example.com>",
        "in_reply_to": "",
        "references": "",
        "authentication_results": "",
        "received": [],
    }

    historical_observations = [
        {
            "result": {
                "email": {
                    "attachments": [],
                }
            }
        },
        {
            "result": {
                "email": {
                    "attachments": [],
                }
            }
        },
        {
            "result": {
                "email": {
                    "attachments": [],
                }
            }
        },
    ]

    result = engine.analyze(
        file_path="unused.eml",
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        historical_observations=historical_observations,
        email_data=email_data,
    )

    bec_007 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-007"
    )

    assert bec_007["matched"] is True
    assert bec_007["risk_score"] == 20
    assert bec_007["behavioral_features"]["attachment_usage_anomaly"] == 1
    assert (
        bec_007["behavioral_evidence"][
            "attachment_usage_anomaly"
        ]["evidence"]["historical_attachment_usage_rate"]
        == 0.0
    )
    assert bec_007["behavioral_evidence"]["attachment_usage_anomaly"] == {
        "detected": 1,
        "evidence": {
            "attachment_present": 1,
            "historical_attachment_usage_rate": 0.0,
        },
    }
    assert (
        "Message contains an unusual attachment usage pattern"
        in bec_007["indicators"]
    )


def test_detection_engine_extracts_recipients_from_to_and_cc():
    """Test that recipients contain To and Cc but exclude From and Reply-To."""

    engine = DetectionEngine()

    email_data = {
        "from": "Bob Supplier <bob@supplier.com>",
        "to": [
            "Alice Company <alice@company.com>",
        ],
        "cc": [
            "Finance Team <finance@company.com>",
        ],
        "reply_to": "Attacker <attacker@example.com>",
        "return_path": "Bob Supplier <bob@supplier.com>",
        "subject": "Invoice Update",
        "date": "Wed, 23 Sep 2026 10:30:00 +0000",
        "message_id": "<test-recipient@example.com>",
        "in_reply_to": "",
        "references": "",
        "authentication_results": "",
        "received": [],
    }

    result = engine.analyze(
        "unused.eml",
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        email_data=email_data,
    )

    assert result["recipients"] == [
        "Alice Company <alice@company.com>",
        "Finance Team <finance@company.com>",
    ]

    assert "Bob Supplier <bob@supplier.com>" not in result["recipients"]
    assert "Attacker <attacker@example.com>" not in result["recipients"]


def test_detection_engine_passes_attachment_metadata_to_context():
    """Test that parsed attachment metadata reaches detection context."""

    engine = DetectionEngine()

    captured = {}

    class ContextCaptureRule:
        def evaluate(self, context):
            captured["attachments"] = context.attachments

            return {
                "rule_id": "TEST-CONTEXT",
                "rule_name": "Context Capture",
                "severity": "LOW",
                "matched": False,
                "indicators": [],
            }

    engine.rules = [ContextCaptureRule()]

    result = engine.analyze(
        str(
            PROJECT_ROOT
            / "samples"
            / "attachments"
            / "attachment-conversation.eml"
        ),
        known_domain="company.com",
        known_display_name="Alice Johnson",
        known_participants=[
            "alice@company.com",
            "bob@company.com",
        ],
        known_hosts=[],
        known_ip_addresses=[],
    )

    assert captured["attachments"] == [
        {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
            "size_bytes": 9,
        }
    ]

    assert result["email"]["attachment_count"] == 1
