"""Application startup for Email Conversation Integrity Detection."""

from __future__ import annotations

import uvicorn

from src.api.app import app
from src.api.config import settings


def main() -> None:
    """Start the FastAPI application with configured host and port."""

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.port,
    )


if __name__ == "__main__":
    main()
