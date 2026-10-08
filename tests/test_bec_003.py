from pathlib import Path

from src.engine.detection_context import DetectionContext
from src.parser.email_parser import EmailParser
from src.rules.bec_003 import ThreadParticipantAnomalyRule


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
    / "thread-hijacking"
    / "thread-hijacking.eml"
)


KNOWN_PARTICIPANTS = [
    "alice@company.com",
    "bob@supplier.com",
]


def build_context(file_path: Path) -> DetectionContext:
    """Parse an email and build its detection context."""

    parser = EmailParser()
    email_data = parser.parse_file(file_path)

    current_participants = [
        "alice@company.com",
        "bob@supplier.com",
    ]

    if file_path == SUSPICIOUS_EMAIL:
        current_participants.append(
            "attacker@external-mail.com"
        )

    return DetectionContext(
        email_data=email_data,
        identity={},
        participants=current_participants,
        authentication={},
        infrastructure={},
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=[],
        known_ip_addresses=[],
    )


def test_legitimate_thread_has_no_new_participants():
    """A known participant should not trigger BEC-003."""

    context = build_context(LEGITIMATE_EMAIL)

    rule = ThreadParticipantAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["new_participants"] == []


def test_thread_hijacking_detects_new_participant():
    """An unexpected participant should trigger BEC-003."""

    context = build_context(SUSPICIOUS_EMAIL)

    rule = ThreadParticipantAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["new_participants"] == [
        "attacker@external-mail.com",
    ]

    assert (
        "Unexpected participant detected in conversation"
        in result["indicators"]
    )


def test_participant_matching_is_case_insensitive():
    """Participant comparison should ignore email address casing."""

    context = build_context(LEGITIMATE_EMAIL)

    context.participants = [
        "Alice@Company.com",
        "Bob@Supplier.com",
    ]

    rule = ThreadParticipantAnomalyRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["new_participants"] == []
