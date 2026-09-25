"""Detection rule contract for Email Conversation Integrity Detection."""

from __future__ import annotations

from typing import Any, Protocol

from src.engine.detection_context import DetectionContext


class DetectionRule(Protocol):
    """Define the interface required by every detection rule."""

    rule_id: str
    rule_name: str
    severity: str

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate the rule against a detection context."""
        ...
