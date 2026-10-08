from src.engine.detection_context import DetectionContext
from src.parser.email_parser import EmailParser
from src.rules.bec_006 import ConversationHijackingRule


LEGITIMATE_EMAIL = (
    "samples/legitimate/normal-conversation.eml"
)

SUSPICIOUS_EMAIL = (
    "samples/thread-hijacking/thread-hijacking.eml"
)


def build_context(
    email_data: dict,
    known_participants: list[str],
) -> DetectionContext:
    """Build a detection context for BEC-006 tests."""

    return DetectionContext(
        email_data=email_data,
        identity={},
        participants=[],
        authentication={},
        infrastructure={},
        known_domain="",
        known_display_name="",
        known_participants=known_participants,
        known_hosts=[],
        known_ip_addresses=[],
    )


def test_legitimate_thread_does_not_trigger_bec_006():
    """A known participant continuing a thread should not trigger."""

    parser = EmailParser()
    email_data = parser.parse_file(LEGITIMATE_EMAIL)

    context = build_context(
        email_data=email_data,
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
    )

    rule = ConversationHijackingRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["sender_address"] == "bob@supplier.com"
    assert result["sender_is_known"] is True


def test_thread_hijacking_triggers_bec_006():
    """An unknown sender reusing a thread should trigger."""

    parser = EmailParser()
    email_data = parser.parse_file(SUSPICIOUS_EMAIL)

    context = build_context(
        email_data=email_data,
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
    )

    rule = ConversationHijackingRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["sender_address"] == "attacker@external-mail.com"
    assert result["sender_is_known"] is False
    assert (
        "Message contains existing conversation thread headers"
        in result["indicators"]
    )
    assert (
        "Sender is not a known participant in the conversation"
        in result["indicators"]
    )


def test_references_only_with_unknown_sender_triggers_bec_006():
    """An unknown sender with only References should trigger."""

    email_data = {
        "from": "attacker@external-mail.com",
        "in_reply_to": "",
        "references": "<original-message-id@example.com>",
    }

    context = build_context(
        email_data=email_data,
        known_participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
    )

    rule = ConversationHijackingRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["sender_address"] == "attacker@external-mail.com"
    assert result["sender_is_known"] is False
    assert (
        "Message contains existing conversation thread headers"
        in result["indicators"]
    )
    assert (
        "Sender is not a known participant in the conversation"
        in result["indicators"]
    )
