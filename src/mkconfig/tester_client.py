"""Authenticated client for the MK.CONFIG protocol tester service."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import math
from dataclasses import replace
from datetime import datetime
from urllib.parse import urlsplit

import aiohttp

from .collector import PublicResolver
from .core import Configuration, is_reserved_hostname

MAX_TESTER_TIMEOUT_SECONDS = 20
MAX_TESTER_RESPONSE_BYTES = 4_096
MAX_TESTER_CONCURRENCY = 2
TESTER_REQUEST_INTERVAL_SECONDS = 8


class TesterClientError(ValueError):
    """Safe tester failure code; never contains a URL, token, or config URI."""


def _validate_tester_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or 443
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or port != 443
            or is_reserved_hostname(host)
        ):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return f"https://{host}"
        if not address.is_global:
            raise ValueError
        return f"https://{address.compressed}"
    except (UnicodeError, ValueError) as error:
        raise TesterClientError("invalid_tester_url") from error


async def _read_response(response: aiohttp.ClientResponse) -> dict[str, object]:
    body = await response.content.read(MAX_TESTER_RESPONSE_BYTES + 1)
    if len(body) > MAX_TESTER_RESPONSE_BYTES:
        raise TesterClientError("tester_response_too_large")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise TesterClientError("invalid_tester_response") from error
    if not isinstance(value, dict):
        raise TesterClientError("invalid_tester_response")
    return value


async def test_configurations(
    configurations: list[Configuration],
    tester_url: str,
    token: str,
    session: object | None = None,
) -> list[Configuration]:
    if len(token) < 32:
        raise TesterClientError("tester_authentication_not_configured")
    endpoint = _validate_tester_url(tester_url) + "/test"
    own_session = session is None
    if own_session:
        timeout = aiohttp.ClientTimeout(
            total=MAX_TESTER_TIMEOUT_SECONDS,
            connect=5,
            sock_read=MAX_TESTER_TIMEOUT_SECONDS,
        )
        connector = aiohttp.TCPConnector(
            limit=MAX_TESTER_CONCURRENCY,
            resolver=PublicResolver(),
            use_dns_cache=False,
        )
        session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            trust_env=False,
            raise_for_status=False,
        )
    semaphore = asyncio.Semaphore(MAX_TESTER_CONCURRENCY)
    request_lock = asyncio.Lock()
    next_request_at = 0.0

    async def pace_request() -> None:
        nonlocal next_request_at
        async with request_lock:
            delay = next_request_at - asyncio.get_running_loop().time()
            if delay > 0:
                await asyncio.sleep(delay)
            next_request_at = asyncio.get_running_loop().time() + TESTER_REQUEST_INTERVAL_SECONDS

    async def test_one(configuration: Configuration) -> Configuration:
        if configuration.subscription_uri is None:
            raise TesterClientError("configuration_uri_missing")
        try:
            await pace_request()
            async with semaphore:
                async with session.post(
                    endpoint,
                    json={"uri": configuration.subscription_uri},
                    headers={"Authorization": f"Bearer {token}"},
                    allow_redirects=False,
                ) as response:
                    if response.status == 401:
                        raise TesterClientError("tester_authentication_failed")
                    if response.status == 429:
                        raise TesterClientError("tester_rate_limited")
                    if response.status != 200:
                        raise TesterClientError("tester_unavailable")
                    result = await _read_response(response)
        except TesterClientError:
            raise
        except (TimeoutError, aiohttp.ClientError, OSError):
            raise TesterClientError("tester_unavailable") from None

        if (
            result.get("configuration_id") != configuration.id
            or result.get("protocol") != configuration.protocol
            or not isinstance(result.get("success"), bool)
        ):
            raise TesterClientError("tester_result_mismatch")
        expected_candidate_id = hmac.new(
            token.encode("utf-8"),
            configuration.subscription_uri.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(
            str(result.get("candidate_id", "")), expected_candidate_id
        ):
            raise TesterClientError("tester_result_mismatch")
        tested_at = result.get("tested_at")
        if not isinstance(tested_at, str):
            raise TesterClientError("invalid_tester_response")
        try:
            timestamp = datetime.fromisoformat(tested_at)
        except ValueError as error:
            raise TesterClientError("invalid_tester_response") from error
        if timestamp.tzinfo is None:
            raise TesterClientError("invalid_tester_response")

        if result["success"]:
            latency = result.get("latency_ms")
            if (
                isinstance(latency, bool)
                or not isinstance(latency, (int, float))
                or not math.isfinite(latency)
                or latency < 0
                or latency > MAX_TESTER_TIMEOUT_SECONDS * 1000
                or result.get("error_code") is not None
            ):
                raise TesterClientError("invalid_tester_response")
            return replace(
                configuration,
                status="tested",
                latency_ms=float(latency),
                healthy=True,
            )
        if result.get("latency_ms") is not None or not isinstance(
            result.get("error_code"), str
        ):
            raise TesterClientError("invalid_tester_response")
        return replace(
            configuration,
            status="tested",
            latency_ms=None,
            healthy=False,
        )

    tasks = [asyncio.create_task(test_one(item)) for item in configurations]
    try:
        return list(await asyncio.gather(*tasks))
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if own_session:
            await session.close()