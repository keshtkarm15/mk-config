"""Command-line interface for collecting safe configuration metadata."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .collector import Source, collect
from .core import DEFAULT_RETENTION_LIMIT


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mkconfig")
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh = subparsers.add_parser(
        "refresh", help="fetch configured HTTPS sources and print a metadata report"
    )
    refresh.add_argument("--sources", type=Path, default=Path("sources.json"))
    refresh.add_argument(
        "--limit",
        type=int,
        help="maximum number of retained configurations (default: config value or 40)",
    )
    refresh.add_argument("--timeout", type=float, default=15)
    refresh.add_argument("--max-response-bytes", type=int, default=1_048_576)
    refresh.add_argument("--concurrency", type=int, default=5)
    return parser


async def _refresh(args: argparse.Namespace) -> int:
    try:
        settings = json.loads(args.sources.read_text(encoding="utf-8"))
        if not isinstance(settings, dict):
            raise TypeError("source configuration must be a JSON object")
        source_items = settings.get("sources", [])
        if not isinstance(source_items, list):
            raise TypeError("sources must be a JSON array")
        sources = [Source(str(item["name"]), str(item["url"])) for item in source_items]
        limit = (
            args.limit
            if args.limit is not None
            else int(settings.get("retention_limit", DEFAULT_RETENTION_LIMIT))
        )
        report = await collect(
            sources,
            retention_limit=limit,
            timeout_seconds=args.timeout,
            max_response_bytes=args.max_response_bytes,
            max_concurrency=args.concurrency,
        )
    except FileNotFoundError:
        print(
            f"Source configuration not found: {args.sources}. Copy sources.example.json and configure authorized HTTPS sources.",
            file=sys.stderr,
        )
        return 2
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(
            f"Invalid source configuration or collection limits: {error}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = _parser().parse_args()
    if args.command == "refresh":
        return asyncio.run(_refresh(args))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
