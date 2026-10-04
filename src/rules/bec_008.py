"""BEC-008: Message Content Anomaly detection."""

from __future__ import annotations

import re
from statistics import median
from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class MessageContentAnomalyRule(DetectionRule):
    """Detect unusual message content against historical baselines."""

    rule_id = "BEC-008"
    rule_name = "Message Content Anomaly"
    severity = "MEDIUM"
    MIN_HISTORICAL_OBSERVATIONS = 3
    SUBJECT_SIMILARITY_THRESHOLD = 0.50
    BODY_SIMILARITY_THRESHOLD = 0.50
    BODY_LENGTH_RATIO_THRESHOLD = 2.0

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate message content against historical observations."""

        email_data = context.email_data
        historical_observations = context.historical_observations

        subject_analysis = self._calculate_subject_similarity(
            email_data.get("subject"),
            historical_observations,
        )

        body_analysis = self._calculate_body_similarity(
            email_data.get("body"),
            historical_observations,
        )

        body_length_analysis = self._calculate_body_length(
            email_data.get("body"),
            historical_observations,
        )

        attachment_analysis = self._calculate_attachment_novelty(
            context.attachments,
            historical_observations,
        )

        attachment_size_analysis = self._calculate_attachment_size_anomaly(
            context.attachments,
            historical_observations,
        )

        subject_anomaly = self._is_subject_similarity_anomaly(
            subject_analysis,
        )

        body_anomaly = self._is_body_similarity_anomaly(
            body_analysis,
        )

        body_length_anomaly = self._is_body_length_anomaly(
            body_length_analysis,
        )

        attachment_anomaly = self._is_attachment_novelty_anomaly(
            attachment_analysis,
        )

        attachment_size_anomaly = self._is_attachment_size_anomaly(
            attachment_size_analysis,
        )

        indicators: list[dict[str, Any]] = []

        if subject_anomaly:
            indicators.append(
                {
                    "type": "subject_similarity_anomaly",
                    "evidence": subject_analysis,
                }
            )

        if body_anomaly:
            indicators.append(
                {
                    "type": "body_similarity_anomaly",
                    "evidence": body_analysis,
                }
            )

        if body_length_anomaly:
            indicators.append(
                {
                    "type": "body_length_anomaly",
                    "evidence": body_length_analysis,
                }
            )

        if attachment_anomaly:
            indicators.append(
                {
                    "type": "attachment_novelty_anomaly",
                    "evidence": attachment_analysis,
                }
            )

        if attachment_size_anomaly:
            indicators.append(
                {
                    "type": "attachment_size_anomaly",
                    "evidence": attachment_size_analysis,
                }
            )

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": bool(indicators),
            "indicators": indicators,
        }

    @staticmethod
    def _normalize_subject(subject: Any) -> str:
        """Normalize a subject for content comparison."""

        if subject is None:
            return ""

        normalized = str(subject).strip().lower()

        normalized = re.sub(
            r"^(?:(?:re|fw|fwd)\s*:\s*)+",
            "",
            normalized,
        )

        normalized = re.sub(
            r"\s+",
            " ",
            normalized,
        )

        return normalized.strip()

    @staticmethod
    def _normalize_body(body: Any) -> str:
        """Normalize a message body for content comparison."""

        if body is None:
            return ""

        normalized = str(body).lower()

        normalized = re.sub(
            r"\s+",
            " ",
            normalized,
        )

        return normalized.strip()

    @staticmethod
    def _calculate_similarity(
        current: str,
        historical: str,
    ) -> float:
        """Calculate normalized similarity between two strings."""

        from difflib import SequenceMatcher

        if not current and not historical:
            return 1.0

        if not current or not historical:
            return 0.0

        return SequenceMatcher(
            None,
            current,
            historical,
        ).ratio()

    def _calculate_subject_similarity(
        self,
        current_subject: Any,
        historical_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare the current subject against historical subjects."""

        current = self._normalize_subject(current_subject)

        historical_subjects: list[str] = []

        for observation in historical_observations:
            subject = self._normalize_subject(
                observation.get("subject")
            )

            if subject:
                historical_subjects.append(subject)

        if len(historical_subjects) < self.MIN_HISTORICAL_OBSERVATIONS:
            return {
                "available": False,
                "current_subject": current,
                "historical_count": len(historical_subjects),
                "max_similarity": None,
            }

        similarities = [
            self._calculate_similarity(
                current,
                historical,
            )
            for historical in historical_subjects
        ]

        max_similarity = max(similarities)

        return {
            "available": True,
            "current_subject": current,
            "historical_count": len(historical_subjects),
            "max_similarity": max_similarity,
        }

    def _is_subject_similarity_anomaly(
        self,
        analysis: dict[str, Any],
    ) -> bool:
        """Determine whether subject similarity is anomalous."""

        if not analysis.get("available"):
            return False

        current_subject = analysis.get(
            "current_subject",
            "",
        )

        max_similarity = analysis.get(
            "max_similarity"
        )

        if not current_subject or max_similarity is None:
            return False

        return (
            max_similarity
            < self.SUBJECT_SIMILARITY_THRESHOLD
        )

    def _calculate_body_similarity(
        self,
        current_body: Any,
        historical_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare the current body against historical bodies."""

        current = self._normalize_body(current_body)

        historical_bodies: list[str] = []

        for observation in historical_observations:
            body = self._normalize_body(
                observation.get("body")
            )

            if body:
                historical_bodies.append(body)

        if len(historical_bodies) < self.MIN_HISTORICAL_OBSERVATIONS:
            return {
                "available": False,
                "current_body": current,
                "historical_count": len(historical_bodies),
                "max_similarity": None,
            }

        similarities = [
            self._calculate_similarity(
                current,
                historical,
            )
            for historical in historical_bodies
        ]

        max_similarity = max(similarities)

        return {
            "available": True,
            "current_body": current,
            "historical_count": len(historical_bodies),
            "max_similarity": max_similarity,
        }

    def _is_body_similarity_anomaly(
        self,
        analysis: dict[str, Any],
    ) -> bool:
        """Determine whether body similarity is anomalous."""

        if not analysis.get("available"):
            return False

        current_body = analysis.get(
            "current_body",
            "",
        )

        max_similarity = analysis.get(
            "max_similarity"
        )

        if not current_body or max_similarity is None:
            return False

        return (
            max_similarity
            < self.BODY_SIMILARITY_THRESHOLD
        )

    @staticmethod
    def _normalize_attachment_filename(filename: Any) -> str:
        """Normalize an attachment filename for comparison."""

        if filename is None:
            return ""

        normalized = str(filename).strip().lower()

        normalized = re.sub(
            r"\s+",
            " ",
            normalized,
        )

        return normalized.strip()

    def _calculate_attachment_novelty(
        self,
        current_attachments: list[dict[str, Any]],
        historical_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare current attachment filenames against historical filenames."""

        current_filenames = {
            normalized
            for attachment in current_attachments
            if isinstance(attachment, dict)
            for normalized in [
                self._normalize_attachment_filename(
                    attachment.get("filename")
                )
            ]
            if normalized
        }

        historical_attachments: list[list[dict[str, Any]]] = []

        for observation in historical_observations:
            attachments = observation.get("attachments")

            if not isinstance(attachments, list):
                continue

            historical_attachments.append(attachments)

        if len(historical_attachments) < self.MIN_HISTORICAL_OBSERVATIONS:
            return {
                "available": False,
                "current_filenames": sorted(current_filenames),
                "historical_observation_count": len(
                    historical_attachments
                ),
                "historical_filenames": [],
                "novel_filenames": [],
            }

        historical_filenames = {
            normalized
            for attachments in historical_attachments
            for attachment in attachments
            if isinstance(attachment, dict)
            for normalized in [
                self._normalize_attachment_filename(
                    attachment.get("filename")
                )
            ]
            if normalized
        }

        novel_filenames = sorted(
            current_filenames - historical_filenames
        )

        return {
            "available": True,
            "current_filenames": sorted(current_filenames),
            "historical_observation_count": len(
                historical_attachments
            ),
            "historical_filenames": sorted(historical_filenames),
            "novel_filenames": novel_filenames,
        }

    @staticmethod
    def _is_attachment_novelty_anomaly(
        analysis: dict[str, Any],
    ) -> bool:
        """Determine whether current attachments are historically novel."""

        if not analysis.get("available"):
            return False

        return bool(analysis.get("novel_filenames"))

    def _calculate_attachment_size_anomaly(
        self,
        current_attachments: list[dict[str, Any]],
        historical_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare attachment sizes against per-filename historical baselines."""

        historical_sizes: dict[str, list[float]] = {}

        for observation in historical_observations:
            attachments = observation.get("attachments")

            if not isinstance(attachments, list):
                continue

            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue

                filename = self._normalize_attachment_filename(
                    attachment.get("filename")
                )

                size = attachment.get("size_bytes")

                if (
                    not filename
                    or isinstance(size, bool)
                    or not isinstance(size, (int, float))
                ):
                    continue

                historical_sizes.setdefault(
                    filename,
                    [],
                ).append(float(size))

        current_sizes: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []

        for attachment in current_attachments:
            if not isinstance(attachment, dict):
                continue

            filename = self._normalize_attachment_filename(
                attachment.get("filename")
            )

            size = attachment.get("size_bytes")

            if (
                not filename
                or isinstance(size, bool)
                or not isinstance(size, (int, float))
            ):
                continue

            current_sizes.append(
                {
                    "filename": filename,
                    "size_bytes": size,
                }
            )

            sizes = historical_sizes.get(filename, [])

            if len(sizes) < self.MIN_HISTORICAL_OBSERVATIONS:
                continue

            historical_median_size = median(sizes)

            if historical_median_size == 0:
                is_anomalous = size > 0
            else:
                upper_bound = (
                    historical_median_size
                    * self.BODY_LENGTH_RATIO_THRESHOLD
                )

                lower_bound = (
                    historical_median_size
                    / self.BODY_LENGTH_RATIO_THRESHOLD
                )

                is_anomalous = (
                    size > upper_bound
                    or size < lower_bound
                )

            if is_anomalous:
                anomalies.append(
                    {
                        "filename": filename,
                        "current_size_bytes": size,
                        "historical_observation_count": len(sizes),
                        "historical_median_size_bytes": historical_median_size,
                    }
                )

        return {
            "available": bool(historical_sizes),
            "current_attachments": current_sizes,
            "anomalies": anomalies,
        }

    @staticmethod
    def _is_attachment_size_anomaly(
        analysis: dict[str, Any],
    ) -> bool:
        """Determine whether attachment size is historically anomalous."""

        if not analysis.get("available"):
            return False

        return bool(analysis.get("anomalies"))

    def _is_body_length_anomaly(
        self,
        analysis: dict[str, Any],
    ) -> bool:
        """Determine whether body length is anomalous."""

        if not analysis.get("available"):
            return False

        current_length = analysis.get(
            "current_length"
        )

        historical_median_length = analysis.get(
            "historical_median_length"
        )

        if (
            current_length is None
            or historical_median_length is None
        ):
            return False

        if historical_median_length == 0:
            return current_length > 0

        upper_bound = (
            historical_median_length
            * self.BODY_LENGTH_RATIO_THRESHOLD
        )

        lower_bound = (
            historical_median_length
            / self.BODY_LENGTH_RATIO_THRESHOLD
        )

        return (
            current_length > upper_bound
            or current_length < lower_bound
        )

    def _calculate_body_length(
        self,
        current_body: Any,
        historical_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare current body length against historical observations."""

        current = self._normalize_body(current_body)

        historical_lengths: list[int] = []

        for observation in historical_observations:
            body = self._normalize_body(
                observation.get("body")
            )

            if body:
                historical_lengths.append(len(body))

        if len(historical_lengths) < self.MIN_HISTORICAL_OBSERVATIONS:
            return {
                "available": False,
                "current_length": len(current),
                "historical_count": len(historical_lengths),
                "historical_median_length": None,
            }

        sorted_lengths = sorted(historical_lengths)
        middle = len(sorted_lengths) // 2

        if len(sorted_lengths) % 2 == 0:
            historical_median_length = (
                sorted_lengths[middle - 1]
                + sorted_lengths[middle]
            ) / 2
        else:
            historical_median_length = sorted_lengths[middle]

        return {
            "available": True,
            "current_length": len(current),
            "historical_count": len(historical_lengths),
            "historical_median_length": historical_median_length,
        }
