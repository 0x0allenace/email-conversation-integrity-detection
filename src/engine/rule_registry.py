"""Detection rule registry."""

from __future__ import annotations

from typing import TypeAlias

from src.engine.detection_rule import DetectionRule
from src.rules.bec_001 import LookalikeDomainRule
from src.rules.bec_002 import ReplyToMismatchRule
from src.rules.bec_003 import ThreadParticipantAnomalyRule
from src.rules.bec_004 import AuthenticationAnomalyRule
from src.rules.bec_005 import SenderInfrastructureAnomalyRule
from src.rules.bec_006 import ConversationHijackingRule
from src.rules.bec_007 import BehavioralCommunicationAnomalyRule


RuleType: TypeAlias = type[DetectionRule]


class RuleRegistry:
    """Register and expose active detection rules."""

    DEFAULT_RULES: tuple[RuleType, ...] = (
        LookalikeDomainRule,
        ReplyToMismatchRule,
        ThreadParticipantAnomalyRule,
        AuthenticationAnomalyRule,
        SenderInfrastructureAnomalyRule,
        ConversationHijackingRule,
        BehavioralCommunicationAnomalyRule,
    )

    def __init__(
        self,
        rule_types: tuple[RuleType, ...] | None = None,
    ) -> None:
        """Initialize the registry with active detection rule types."""

        if rule_types is None:
            rule_types = self.DEFAULT_RULES

        self._rule_types = rule_types
        self._rules: list[DetectionRule] = []

        self._register_default_rules()

    def _register_default_rules(self) -> None:
        """Register the configured detection rule types."""

        for rule_type in self._rule_types:
            self.register(rule_type)

    def register(self, rule_type: RuleType) -> None:
        """Register a detection rule type."""

        self._rules.append(rule_type())

    def get_rules(self) -> list[DetectionRule]:
        """Return the active detection rule instances."""

        return self._rules
