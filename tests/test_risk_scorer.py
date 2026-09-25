from src.scoring.risk_scorer import RiskScorer


def test_unmatched_rule_has_zero_risk():
    """An unmatched rule should always have zero risk."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=False,
        unexpected_participant=True,
    ) == 0


def test_unexpected_participant_adds_risk():
    """An unexpected participant should add 30 risk points."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        unexpected_participant=True,
    ) == 30


def test_infrastructure_anomaly_adds_risk():
    """An infrastructure anomaly should add 20 risk points."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        infrastructure_anomaly=True,
    ) == 20


def test_multiple_indicators_are_combined():
    """Multiple risk indicators should be combined."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        domain_mismatch=True,
        display_name_match=True,
        authentication_failure=True,
    ) == 100


def test_risk_score_is_capped_at_100():
    """Risk scores should never exceed 100."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        domain_mismatch=True,
        display_name_match=True,
        authentication_failure=True,
        unexpected_participant=True,
        infrastructure_anomaly=True,
    ) == 100


def test_thread_reuse_anomaly_adds_risk():
    """Thread reuse by a suspicious sender should add 20 risk points."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        thread_reuse_anomaly=True,
    ) == 20


def test_thread_hijacking_evidence_combines_without_double_counting():
    """Thread reuse and participant anomaly should combine independently."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        unexpected_participant=True,
        thread_reuse_anomaly=True,
    ) == 50


def test_behavioral_anomaly_adds_risk():
    """A behavioral communication anomaly should add 20 risk points."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        behavioral_anomaly=True,
    ) == 20


def test_behavioral_anomaly_combines_with_other_indicators():
    """Behavioral anomaly should combine with other risk indicators."""

    scorer = RiskScorer()

    assert scorer.score(
        rule_matched=True,
        unexpected_participant=True,
        behavioral_anomaly=True,
    ) == 50
