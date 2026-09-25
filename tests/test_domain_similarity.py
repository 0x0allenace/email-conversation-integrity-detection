from src.identity.domain_similarity import (
    is_lookalike_domain,
    normalize_domain,
)


def test_normalize_domain():
    """Test common lookalike character normalization."""

    assert normalize_domain("supp1ier.com") == "supplier.com"


def test_detect_lookalike_domain():
    """Test that a visually similar domain is detected."""

    assert is_lookalike_domain(
        "supp1ier.com",
        "supplier.com",
    )


def test_legitimate_domain_is_not_lookalike():
    """Test that the legitimate domain does not trigger."""

    assert not is_lookalike_domain(
        "supplier.com",
        "supplier.com",
    )


def test_unrelated_domain_is_not_lookalike():
    """Test that an unrelated domain does not trigger."""

    assert not is_lookalike_domain(
        "amazon.com",
        "supplier.com",
    )
