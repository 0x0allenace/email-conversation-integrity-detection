"""Domain similarity utilities for email identity analysis."""

from __future__ import annotations


HOMOGLYPH_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
    }
)


def normalize_domain(domain: str) -> str:
    """Normalize a domain for comparison."""

    return domain.lower().strip().translate(HOMOGLYPH_MAP)


def is_lookalike_domain(
    observed_domain: str,
    known_domain: str,
) -> bool:
    """Determine whether two domains may be visually similar."""

    observed = observed_domain.lower().strip()
    known = known_domain.lower().strip()

    if not observed or not known:
        return False

    if observed == known:
        return False

    normalized_observed = normalize_domain(observed)
    normalized_known = normalize_domain(known)

    return normalized_observed == normalized_known
