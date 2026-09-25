"""Tests for API application startup."""

from unittest.mock import patch

from src.api.app import app
from src.api.config import settings
from src.api.run import main


def test_main_starts_uvicorn_with_configured_settings():
    """Test that startup passes the configured port to Uvicorn."""

    with patch("src.api.run.uvicorn.run") as mock_run:
        main()

    mock_run.assert_called_once_with(
        app,
        host="0.0.0.0",
        port=settings.port,
    )
