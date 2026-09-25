from src.engine.rule_registry import RuleRegistry


def test_all_registered_rules_satisfy_detection_rule_contract():
    """Every registered rule should satisfy the DetectionRule contract."""

    registry = RuleRegistry()
    rules = registry.get_rules()

    assert rules

    for rule in rules:
        assert isinstance(rule.rule_id, str)
        assert rule.rule_id

        assert isinstance(rule.rule_name, str)
        assert rule.rule_name

        assert isinstance(rule.severity, str)
        assert rule.severity

        assert callable(rule.evaluate)
