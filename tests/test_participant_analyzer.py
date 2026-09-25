from pathlib import Path

from src.conversation.participant_analyzer import ParticipantAnalyzer
from src.parser.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)


def test_extract_participants():
    """Test that email participants are extracted correctly."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)

    analyzer = ParticipantAnalyzer()

    participants = analyzer.extract_participants(
        email_data
    )

    assert "bob@supplier.com" in participants
    assert "alice@company.com" in participants


def test_duplicate_participants_are_removed():
    """Test that duplicate addresses are removed."""

    email_data = {
        "from": "Bob Supplier <bob@supplier.com>",
        "reply_to": "bob@supplier.com",
        "to": [
            "Alice Company <alice@company.com>",
        ],
        "cc": [],
    }

    analyzer = ParticipantAnalyzer()

    participants = analyzer.extract_participants(
        email_data
    )

    assert participants.count("bob@supplier.com") == 1


def test_find_new_participants():
    """Test that unexpected participants are identified."""

    analyzer = ParticipantAnalyzer()

    current_participants = [
        "alice@company.com",
        "bob@supplier.com",
        "attacker@example.com",
    ]

    known_participants = [
        "alice@company.com",
        "bob@supplier.com",
    ]

    new_participants = analyzer.find_new_participants(
        current_participants,
        known_participants,
    )

    assert new_participants == [
        "attacker@example.com",
    ]
