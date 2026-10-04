"""Detection result structure."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionResult:
    """Represent a detection finding."""

    rule_id: str
    rule_name: str
    severity: str
    matched: bool
    risk_score: int
    indicators: list[str | dict[str, Any]] = field(
        default_factory=list
    )
    details: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert the result to a dictionary."""

        result = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": self.matched,
            "risk_score": self.risk_score,
            "indicators": self.indicators,
        }

        result.update(self.details)

        return result
