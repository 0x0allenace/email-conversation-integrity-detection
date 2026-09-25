from pathlib import Path

from src.authentication.authentication_analyzer import (
    AuthenticationAnalyzer,
)
from src.parser.email_parser import EmailParser


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


def test_legitimate_authentication_results():
    """Test authentication results from a legitimate email."""

    parser = EmailParser()
    email_data = parser.parse_file(LEGITIMATE_EMAIL)

    analyzer = AuthenticationAnalyzer()

    results = analyzer.analyze(email_data)

    assert results["spf"] == "pass"
    assert results["dkim"] == "pass"
    assert results["dmarc"] == "pass"


def test_failed_authentication_results():
    """Test authentication failures from a suspicious email."""

    parser = EmailParser()
    email_data = parser.parse_file(SUSPICIOUS_EMAIL)

    analyzer = AuthenticationAnalyzer()

    results = analyzer.analyze(email_data)

    assert results["spf"] == "fail"
    assert results["dkim"] == "fail"
    assert results["dmarc"] == "fail"


def test_missing_authentication_results():
    """Test that missing authentication results become unknown."""

    analyzer = AuthenticationAnalyzer()

    results = analyzer.analyze(
        {
            "authentication_results": "",
        }
    )

    assert results["spf"] == "unknown"
    assert results["dkim"] == "unknown"
    assert results["dmarc"] == "unknown"
