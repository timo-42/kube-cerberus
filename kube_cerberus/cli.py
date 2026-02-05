"""Command line utilities for kube-cerberus."""

from __future__ import annotations

import argparse

from .registry import REGISTRY
from .webhook_config import generate_webhook_configuration_yaml


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cerberus")
    subparsers = parser.add_subparsers(dest="command")

    generate_parser = subparsers.add_parser(
        "generate-webhook",
        help="Generate Kubernetes webhook configuration YAML from registered hooks.",
    )
    generate_parser.add_argument("--url", required=True, help="Webhook service URL.")
    generate_parser.add_argument(
        "--name",
        default="cerberus-webhook",
        help="Base name for generated webhook configuration resources.",
    )
    generate_parser.add_argument(
        "--mode",
        choices=["validating", "mutating", "both"],
        default="validating",
        help="Which webhook configuration type(s) to generate.",
    )
    generate_parser.add_argument(
        "--ca-bundle",
        default=None,
        help="Optional base64-encoded CA bundle.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-webhook":
        yaml_output = generate_webhook_configuration_yaml(
            registry=REGISTRY,
            url=args.url,
            name=args.name,
            mode=args.mode,
            ca_bundle=args.ca_bundle,
        )
        print(yaml_output, end="")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
