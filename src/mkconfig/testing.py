"""Pluggable real-protocol tester contract and destination safety checks."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .core import Configuration


@dataclass(frozen=True, slots=True)
class TestResult:
    status: str
    latency_ms: float | None = None
    error: str | None = None


class ProtocolTester(Protocol):
    @property
    def available(self) -> bool: ...

    async def test(
        self, configuration: Configuration, target_url: str
    ) -> TestResult: ...


class UnavailableTester:
    available = False

    async def test(self, configuration: Configuration, target_url: str) -> TestResult:
        return TestResult("untested", error="tester_unavailable")


async def validate_test_target(target_url: str, allowed_hosts: set[str]) -> str:
    """Require an allowlisted HTTPS target whose resolved addresses are all public."""
    try:
        parsed = urlsplit(target_url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise ValueError("unsafe_test_target")
        if host not in {entry.rstrip(".").lower() for entry in allowed_hosts}:
            raise ValueError("test_target_not_allowlisted")
        if host == "localhost" or host.endswith(
            (".localhost", ".local", ".internal", ".home")
        ):
            raise ValueError("unsafe_test_target")
        try:
            address = ipaddress.ip_address(host)
            addresses = [address]
        except ValueError:
            results = await asyncio.get_running_loop().getaddrinfo(
                host, parsed.port or 443, type=socket.SOCK_STREAM
            )
            addresses = [ipaddress.ip_address(result[4][0]) for result in results]
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("unsafe_test_target")
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith(
            ("unsafe_", "test_target_")
        ):
            raise
        raise ValueError("unsafe_test_target") from error
    return host
