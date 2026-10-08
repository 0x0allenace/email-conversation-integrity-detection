from pathlib import Path

from src.engine.detection_context import DetectionContext
from src.identity.identity_analyzer import IdentityAnalyzer
from src.parser.email_parser import EmailParser
from src.rules.bec_001 import LookalikeDomainRule
from src.scoring.risk_scorer import RiskScorer


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


def build_context(file_path: Path) -> DetectionContext:
    """Parse an email and build its detection context."""

    parser = EmailParser()
    email_data = parser.parse_file(file_path)

    analyzer = IdentityAnalyzer()
    identity = analyzer.analyze(email_data)

    return DetectionContext(
        email_data=email_data,
        identity=identity,
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


def test_legitimate_sender_does_not_trigger_bec_001():
    """A trusted sender should not trigger BEC-001."""

    context = build_context(LEGITIMATE_EMAIL)

    rule = LookalikeDomainRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False


def test_lookalike_domain_triggers_bec_001():
    """A lookalike sender domain should trigger BEC-001."""

    context = build_context(SUSPICIOUS_EMAIL)

    rule = LookalikeDomainRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is True
    assert result["observed_domain"] == "supp1ier.com"
    assert result["known_domain"] == "supplier.com"

    scorer = RiskScorer()

    risk_score = scorer.score(
        rule_matched=result["matched"],
        domain_mismatch=True,
        display_name_match=True,
        authentication_failure=True,
    )

    assert risk_score == 100


def test_matching_display_name_with_unrelated_domain_does_not_trigger_bec_001():
    """A matching display name alone should not trigger BEC-001."""

    context = build_context(LEGITIMATE_EMAIL)

    context.identity["domain"] = "unrelated-example.net"
    context.identity["display_name"] = "Bob Supplier"

    rule = LookalikeDomainRule()

    result = rule.evaluate(
        context=context,
    )

    assert result["matched"] is False
    assert result["observed_domain"] == "unrelated-example.net"
    assert result["known_domain"] == "supplier.com"
