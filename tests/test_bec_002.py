from pathlib import Path

from src.engine.detection_context import DetectionContext
from src.parser.email_parser import EmailParser
from src.rules.bec_002 import ReplyToMismatchRule


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
    / "reply-to-manipulation"
    / "reply-to-mismatch.eml"
)


def build_context(file_path: Path) -> DetectionContext:
    """Parse an email and build its detection context."""

    parser = EmailParser()
    email_data = parser.parse_file(file_path)

    return DetectionContext(
        email_data=email_data,
        identity={},
        participants=[],
        authentication={},
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


def test_legitimate_email_does_not_trigger_bec_002():
    """A legitimate Reply-To should not trigger BEC-002."""

    context = build_context(LEGITIMATE_EMAIL)

    rule = ReplyToMismatchRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["from_address"] == "bob@supplier.com"
    assert result["reply_to_address"] == "bob@supplier.com"


def test_reply_to_mismatch_triggers_bec_002():
    """A different Reply-To address should trigger BEC-002."""

    context = build_context(SUSPICIOUS_EMAIL)

    rule = ReplyToMismatchRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["from_address"] == "bob@supplier.com"
    assert result["reply_to_address"] == "bob@external-mail.com"

    assert (
        "Reply-To address differs from From address"
        in result["indicators"]
    )

    assert (
        "Reply-To domain differs from From domain"
        in result["indicators"]
    )
