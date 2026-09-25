from pathlib import Path

from src.identity.identity_analyzer import IdentityAnalyzer
from src.parser.email_parser import EmailParser


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)


def test_analyze_sender_identity():
    """Test that sender identity is extracted correctly."""

    parser = EmailParser()
    email_data = parser.parse_file(SAMPLE_EMAIL)

    analyzer = IdentityAnalyzer()
    identity = analyzer.analyze(email_data)

    assert identity["display_name"] == "Bob Supplier"
    assert identity["email_address"] == "bob@supplier.com"
    assert identity["username"] == "bob"
    assert identity["domain"] == "supplier.com"
