from src.engine.rule_registry import RuleRegistry


def test_registry_loads_all_default_rules():
    """The default registry should load all active detection rules."""

    registry = RuleRegistry()

    rule_ids = [
        rule.rule_id
        for rule in registry.get_rules()
    ]

    assert rule_ids == [
        "BEC-001",
        "BEC-002",
        "BEC-003",
        "BEC-004",
        "BEC-005",
        "BEC-006",
        "BEC-007",
        "BEC-008",
    ]


def test_registry_returns_rule_instances():
    """The registry should return initialized rule instances."""

    registry = RuleRegistry()

    rules = registry.get_rules()

    assert len(rules) == 8

    for rule in rules:
        assert hasattr(rule, "evaluate")
        assert hasattr(rule, "rule_id")
        assert hasattr(rule, "rule_name")
        assert hasattr(rule, "severity")


def test_registry_can_use_custom_rules():
    """The registry should support a custom rule configuration."""

    class CustomRule:
        """Minimal test rule."""

        rule_id = "TEST-001"
        rule_name = "Test Rule"
        severity = "LOW"

        def evaluate(self, context):
            """Return a minimal test detection."""

            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "matched": False,
                "indicators": [],
            }

    registry = RuleRegistry(
        rule_types=(CustomRule,)
    )

    rules = registry.get_rules()

    assert len(rules) == 1
    assert rules[0].rule_id == "TEST-001"
