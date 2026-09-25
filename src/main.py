"""Command-line entry point for Email Conversation Integrity Detection."""

from __future__ import annotations

import argparse
import json

from .parser.email_parser import EmailParser


def main() -> None:
    """Parse an .eml file and display normalized email data."""

    argument_parser = argparse.ArgumentParser(
        description="Email Conversation Integrity Detection",
    )

    argument_parser.add_argument(
        "email_file",
        help="Path to the .eml file to analyze.",
    )

    args = argument_parser.parse_args()

    parser = EmailParser()
    email_data = parser.parse_file(args.email_file)

    print(json.dumps(email_data, indent=4))


if __name__ == "__main__":
    main()
