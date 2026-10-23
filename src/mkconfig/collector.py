"""Bounded HTTPS subscription fetching with DNS-based SSRF protections."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import aiohttp

from .core import Configuration, is_reserved_hostname, parse_subscription, rank_configurations

logger = logging.getLogger("mkconfig")
MAX_TIMEOUT_SECONDS = 300
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_CONCURRENCY = 20
MAX_SOURCES = 100


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class SourceStatus:
    name: str
    status: str
    count: int
    invalid_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "count": self.count,
            "invalid_count": self.invalid_count,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class CollectionReport:
    refreshed_at: str
    configurations: list[Configuration]
    sources: list[SourceStatus]
    discovered_count: int
    retained_count: int
    tester_available: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "refreshed_at": self.refreshed_at,
            "discovered_count": self.discovered_count,
            "retained_count": self.retained_count,
            "tester": {
                "available": self.tester_available,
                "limitation": "No real protocol tester configured; configurations are untested.",
            },
            "sources": [source.to_dict() for source in self.sources],
            "configurations": [
                configuration.to_dict() for configuration in self.configurations
            ],
        }


def validate_source_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise ValueError("unsafe_source_url")
        if is_reserved_hostname(host):
            raise ValueError("unsafe_source_url")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if not address.is_global:
            raise ValueError("unsafe_source_url")
    except (UnicodeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error) == "unsafe_source_url":
            raise
        raise ValueError("unsafe_source_url") from error


class PublicResolver(aiohttp.abc.AbstractResolver):
    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, object]]:
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM
        )
        resolved: list[dict[str, object]] = []
        for record_family, _, proto, _, sockaddr in records:
            address = ipaddress.ip_address(sockaddr[0])
            if not address.is_global:
                raise OSError("unsafe_source_address")
            resolved.append(
                {
                    "hostname": host,
                    "host": address.compressed,
                    "port": port,
                    "family": record_family,
                    "proto": proto,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not resolved:
            raise OSError("source_unresolved")
        return resolved

    async def close(self) -> None:
        return None


async def _read_limited(
    response: aiohttp.ClientResponse, max_response_bytes: int
) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_response_bytes:
                raise ValueError("response_too_large")
        except ValueError as error:
            if str(error) == "response_too_large":
                raise
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.content.iter_chunked(16_384):
        total += len(chunk)
        if total > max_response_bytes:
            raise ValueError("response_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


async def collect(
    sources: list[Source],
    retention_limit: int = 40,
    timeout_seconds: float = 15,
    max_response_bytes: int = 1_048_576,
    max_concurrency: int = 5,
    session: object | None = None,
) -> CollectionReport:
    if (
        retention_limit < 0
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
        or not 1 <= max_concurrency <= MAX_CONCURRENCY
        or len(sources) > MAX_SOURCES
    ):
        raise ValueError("invalid_collection_limits")
    own_session = session is None
    if own_session:
        timeout = aiohttp.ClientTimeout(
            total=timeout_seconds, connect=min(timeout_seconds, 5)
        )
        connector = aiohttp.TCPConnector(
            limit=max_concurrency, resolver=PublicResolver(), use_dns_cache=False
        )
        session = aiohttp.ClientSession(
            timeout=timeout, connector=connector, trust_env=False
        )

    semaphore = asyncio.Semaphore(max_concurrency)

    async def fetch(
        index: int, source: Source
    ) -> tuple[list[Configuration], SourceStatus]:
        safe_name = f"source-{index + 1}"
        try:
            validate_source_url(source.url)
        except ValueError:
            return [], SourceStatus(safe_name, "error", 0, error="unsafe_source_url")
        try:
            async with (
                semaphore,
                session.get(source.url, allow_redirects=False) as response,
            ):
                if response.status < 200 or response.status >= 300:
                    return [], SourceStatus(safe_name, "error", 0, error="http_error")
                body = await _read_limited(response, max_response_bytes)
            text = body.decode("utf-8", errors="strict")
            configurations, invalid_count = parse_subscription(text)
            status = "ok" if configurations else "empty"
            logger.info(
                json.dumps(
                    {
                        "event": "source_fetch",
                        "source": safe_name,
                        "status": status,
                        "count": len(configurations),
                        "invalid_count": invalid_count,
                    }
                )
            )
            return configurations, SourceStatus(
                safe_name, status, len(configurations), invalid_count
            )
        except TimeoutError:
            return [], SourceStatus(safe_name, "error", 0, error="timeout")
        except ValueError as error:
            safe_error = (
                str(error)
                if str(error)
                in {
                    "response_too_large",
                    "invalid_base64",
                    "unsupported_subscription_encoding",
                }
                else "invalid_response"
            )
            return [], SourceStatus(safe_name, "error", 0, error=safe_error)
        except (aiohttp.ClientError, OSError, UnicodeError, TypeError, RuntimeError):
            return [], SourceStatus(safe_name, "error", 0, error="source_unavailable")

    try:
        results = await asyncio.gather(
            *(fetch(index, source) for index, source in enumerate(sources))
        )
    finally:
        if own_session:
            await session.close()

    unique: dict[str, Configuration] = {}
    statuses: list[SourceStatus] = []
    for configurations, status in results:
        statuses.append(status)
        for configuration in configurations:
            unique.setdefault(configuration.id, configuration)
    ordered = rank_configurations(list(unique.values()), retention_limit)
    return CollectionReport(
        refreshed_at=datetime.now(UTC).isoformat(),
        configurations=ordered,
        sources=statuses,
        discovered_count=len(unique),
        retained_count=len(ordered),
    )
