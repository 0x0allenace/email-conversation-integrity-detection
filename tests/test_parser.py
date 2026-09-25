from pathlib import Path

from src.parser.email_parser import EmailParser

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)


def test_parse_legitimate_email():
    """Test that a legitimate .eml file is parsed correctly."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)
    assert email_data["from"] == "Bob Supplier <bob@supplier.com>"
    assert email_data["subject"] == "Invoice Update"
    assert email_data["reply_to"] == "bob@supplier.com"
    assert email_data["message_id"] == "<invoice-update-001@supplier.com>"


def test_parse_recipients():
    """Test that recipient information is extracted."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)
    assert len(email_data["to"]) == 1
    assert email_data["to"][0] == "Alice Company <alice@company.com>"


def test_parse_authentication_results():
    """Test that authentication results are extracted."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)
    assert "spf=pass" in email_data["authentication_results"]
    assert "dkim=pass" in email_data["authentication_results"]
    assert "dmarc=pass" in email_data["authentication_results"]
