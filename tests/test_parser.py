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


def test_parse_body():
    """Test that plain-text email body is extracted."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)

    assert email_data["body"] == (
        "Hello Alice,\n\n"
        "Please find the updated invoice attached.\n\n"
        "Regards,\n"
        "Bob Supplier"
    )


def test_parse_multipart_body_prefers_plain_text(tmp_path):
    """Test that multipart email parsing prefers plain text."""

    email_file = tmp_path / "multipart.eml"

    email_file.write_text(
        "From: Sender <sender@example.com>\n"
        "To: Recipient <recipient@example.com>\n"
        "Subject: Test Message\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/alternative; boundary=\"boundary\"\n"
        "\n"
        "--boundary\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "\n"
        "Plain text body\n"
        "--boundary\n"
        "Content-Type: text/html; charset=\"utf-8\"\n"
        "\n"
        "<html><body>HTML body</body></html>\n"
        "--boundary--\n"
    )

    parser = EmailParser()
    email_data = parser.parse_file(email_file)

    assert email_data["body"] == "Plain text body"


def test_parse_html_only_body(tmp_path):
    """Test that HTML is used when no plain-text body exists."""

    email_file = tmp_path / "html-only.eml"

    email_file.write_text(
        "From: Sender <sender@example.com>\n"
        "To: Recipient <recipient@example.com>\n"
        "Subject: Test Message\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/html; charset=\"utf-8\"\n"
        "\n"
        "<html><body>HTML body</body></html>\n"
    )

    parser = EmailParser()
    email_data = parser.parse_file(email_file)

    assert email_data["body"] == (
        "<html><body>HTML body</body></html>\n"
    )


def test_parse_email_without_body(tmp_path):
    """Test that an email without textual content returns an empty body."""

    email_file = tmp_path / "empty-body.eml"

    email_file.write_text(
        "From: Sender <sender@example.com>\n"
        "To: Recipient <recipient@example.com>\n"
        "Subject: Test Message\n"
        "\n"
    )

    parser = EmailParser()
    email_data = parser.parse_file(email_file)

    assert email_data["body"] == ""


def test_parser_extracts_attachment_metadata():
    attachment_email = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "attachments"
        / "attachment-conversation.eml"
    )

    parser = EmailParser()
    email_data = parser.parse_file(attachment_email)

    assert email_data["attachment_count"] == 1
    assert email_data["attachments"] == [
        {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
            "size_bytes": 9,
        }
    ]


def test_parser_does_not_store_attachment_payload():
    attachment_email = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "attachments"
        / "attachment-conversation.eml"
    )

    parser = EmailParser()
    email_data = parser.parse_file(attachment_email)

    attachment = email_data["attachments"][0]

    assert "payload" not in attachment
    assert "content" not in attachment
    assert "data" not in attachment


def test_parser_returns_empty_attachment_metadata_when_no_attachments():
    sample_email = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "legitimate"
        / "normal-conversation.eml"
    )

    parser = EmailParser()
    email_data = parser.parse_file(sample_email)

    assert email_data["attachments"] == []
    assert email_data["attachment_count"] == 0
