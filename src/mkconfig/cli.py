"""Command-line interface for collecting safe configuration metadata."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from .collector import Source, collect
from .core import (
    DEFAULT_RETENTION_LIMIT,
    V2RAYNG_PROTOCOLS,
    decode_subscription,
    encode_subscription,
    parse_subscription,
    rank_configurations,
)
from .tester_client import TesterClientError, test_configurations

MAX_TEST_CANDIDATES = 200


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
    refresh.add_argument(
        "--output",
        type=Path,
        help="atomically write a Base64 subscription file when valid results exist",
    )
    return parser


def _write_subscription(
    configurations, output: Path, limit: int = DEFAULT_RETENTION_LIMIT
) -> int:
    encoded = encode_subscription(configurations, limit=limit)
    if not encoded:
        return 0
    decoded = decode_subscription(encoded)
    validated, invalid_count = parse_subscription(decoded)
    lines = [line for line in decoded.splitlines() if line.strip()]
    if invalid_count or len(validated) != len(lines) or len(lines) > limit:
        raise ValueError("encoded_subscription_validation_failed")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", dir=output.parent, delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(encoded)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        temporary_path.replace(output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return len(lines)


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
        if limit < 0:
            raise ValueError("retention_limit_must_be_nonnegative")
        candidate_limit = min(limit * 5, MAX_TEST_CANDIDATES)
        report = await collect(
            sources,
            retention_limit=candidate_limit,
            timeout_seconds=args.timeout,
            max_response_bytes=args.max_response_bytes,
            max_concurrency=args.concurrency,
        )
        tester_available = False
        tested_count = 0
        failed_test_count = 0
        test_error = None
        if args.output is not None:
            if any(source.status == "error" for source in report.sources):
                test_error = "source_failure"
            else:
                tester_url = os.getenv("MKCONFIG_TESTER_URL", "")
                tester_token = os.getenv("MKCONFIG_TESTER_TOKEN", "")
                if not tester_url or not tester_token:
                    test_error = "tester_not_configured"
                else:
                    try:
                        tested = await test_configurations(
                            report.configurations, tester_url, tester_token
                        )
                    except TesterClientError as error:
                        test_error = str(error)
                    else:
                        successful = [
                            configuration
                            for configuration in tested
                            if configuration.status == "tested"
                            and configuration.healthy is True
                        ]
                        tested_count = len(tested)
                        failed_test_count = tested_count - len(successful)
                        ranked = rank_configurations(successful, limit)
                        report = replace(
                            report,
                            configurations=ranked,
                            retained_count=len(ranked),
                            tester_available=True,
                        )
                        tester_available = True
    except FileNotFoundError:
        print(
            f"Source configuration not found: {args.sources}. Copy sources.example.json and configure authorized HTTPS sources.",
            file=sys.stderr,
        )
        return 2
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(
            f"Refresh failed safely: {error}",
            file=sys.stderr,
        )
        return 2
    result = report.to_dict()
    result["last_updated_at"] = report.refreshed_at
    result["successful_source_count"] = sum(
        source.status == "ok" for source in report.sources
    )
    result["invalid_count"] = sum(source.invalid_count for source in report.sources)
    result["duplicate_count"] = max(
        0,
        sum(source.count for source in report.sources) - report.discovered_count,
    )
    result["connection_test_status"] = "tested" if tester_available else "untested"
    result["tested_count"] = tested_count
    result["failed_test_count"] = failed_test_count
    if args.output is not None:
        published_count = (
            0
            if test_error is not None
            else _write_subscription(report.configurations, args.output, limit)
        )
        result["published_count"] = published_count
        result["publication_status"] = (
            "updated" if published_count else "preserved_previous"
        )
        if test_error is not None:
            result["test_error"] = test_error
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if args.output is not None and not published_count else 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = _parser().parse_args()
    if args.command == "refresh":
        return asyncio.run(_refresh(args))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
