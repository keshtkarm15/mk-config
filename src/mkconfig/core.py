"""Parsing, metadata validation, stable identifiers, and deterministic ranking."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SUPPORTED_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "socks",
    "socks5",
    "socks5h",
    "http",
    "https",
}
_SCHEME_LINE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_HOST_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
DEFAULT_RETENTION_LIMIT = 40
V2RAYNG_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "ss"})


@dataclass(frozen=True, slots=True)
class Configuration:
    id: str
    protocol: str
    host: str
    port: int
    status: str = "untested"
    latency_ms: float | None = None
    healthy: bool | None = None
    subscription_uri: str | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "healthy": self.healthy,
        }


def _decode_b64(value: str) -> bytes:
    compact = re.sub(r"\s+", "", value)
    padded = compact + "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid_base64") from error


def decode_subscription(text: str) -> str:
    """Decode a base64-wrapped list of links, or retain an ordinary link list."""
    stripped = text.strip()
    if not stripped:
        return ""
    if any(_SCHEME_LINE.match(line.strip()) for line in stripped.splitlines()):
        return stripped
    decoded = _decode_b64(stripped).decode("utf-8", errors="strict")
    if not any(_SCHEME_LINE.match(line.strip()) for line in decoded.splitlines()):
        raise ValueError("unsupported_subscription_encoding")
    return decoded


def _validate_host(host: str) -> str:
    normalized = host.strip().rstrip(".").lower()
    if (
        not normalized
        or normalized == "localhost"
        or normalized.endswith((".localhost", ".local", ".internal", ".home"))
    ):
        raise ValueError("unsafe_target")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        if len(normalized) > 253 or any(
            not _HOST_LABEL.fullmatch(label) for label in normalized.split(".")
        ):
            raise ValueError("invalid_host")
    else:
        if not address.is_global:
            raise ValueError("unsafe_target")
        normalized = address.compressed
    return normalized


def _parse_vmess(uri: str) -> tuple[str, int, str | None]:
    payload = uri.removeprefix("vmess://")
    try:
        data = json.loads(_decode_b64(payload))
        host = str(data["add"])
        port = int(data["port"])
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("invalid_vmess") from error
    return host, port, None


def _parse_ss(uri: str) -> tuple[str, int, str | None]:
    remainder = uri.removeprefix("ss://")
    if "@" not in remainder.split("#", 1)[0]:
        encoded = remainder.split("?", 1)[0].split("#", 1)[0]
        try:
            decoded = _decode_b64(encoded).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("invalid_shadowsocks") from error
        if "@" not in decoded:
            raise ValueError("invalid_shadowsocks")
        uri = (
            "ss://"
            + decoded
            + ("#" + remainder.split("#", 1)[1] if "#" in remainder else "")
        )
    parsed = urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise ValueError("invalid_shadowsocks")
    return parsed.hostname, parsed.port, None


def parse_configuration(uri: str) -> Configuration:
    """Parse a supported proxy link and return metadata without credentials."""
    value = uri.strip()
    if not value or len(value) > 16_384:
        raise ValueError("invalid_uri")
    scheme = value.split(":", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError("unsupported_protocol")

    if scheme == "vmess":
        host, port, _ = _parse_vmess(value)
    elif scheme == "ss":
        host, port, _ = _parse_ss(value)
    else:
        try:
            parsed = urlsplit(value)
            host = parsed.hostname or ""
            port = parsed.port or 0
        except ValueError as error:
            raise ValueError("invalid_uri") from error
        if not host or port == 0:
            raise ValueError("invalid_uri")

    safe_host = _validate_host(host)
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    protocol = "socks" if scheme in {"socks", "socks5", "socks5h"} else scheme
    identity = f"{protocol}\0{safe_host}\0{port}"
    identifier = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return Configuration(identifier, protocol, safe_host, port, subscription_uri=value)


def parse_subscription(text: str) -> tuple[list[Configuration], int]:
    decoded = decode_subscription(text)
    configurations: dict[str, Configuration] = {}
    invalid_count = 0
    for line in decoded.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            configuration = parse_configuration(candidate)
        except ValueError:
            invalid_count += 1
            continue
        configurations.setdefault(configuration.id, configuration)
    return list(configurations.values()), invalid_count


def encode_subscription(configurations: list[Configuration]) -> str:
    """Encode validated source URIs as a v2rayNG-compatible Base64 subscription."""
    uris = [
        configuration.subscription_uri
        for configuration in configurations
        if configuration.subscription_uri is not None
        and configuration.protocol in V2RAYNG_PROTOCOLS
    ]
    if not uris:
        return ""
    payload = "\n".join(uris).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def rank_configurations(
    configurations: list[Configuration], limit: int = DEFAULT_RETENTION_LIMIT
) -> list[Configuration]:
    if limit < 0:
        raise ValueError("retention_limit_must_be_nonnegative")

    def ranking_key(item: Configuration) -> tuple[bool, float, str]:
        verified = item.status == "tested" and item.healthy is True
        latency = (
            item.latency_ms
            if verified and item.latency_ms is not None
            else float("inf")
        )
        return not verified, latency, item.id

    ordered = sorted(
        configurations,
        key=ranking_key,
    )
    return ordered[:limit]


def load_configurations(records: list[dict[str, object]]) -> list[Configuration]:
    """Construct metadata records from test or external tester output."""
    return [Configuration(**record) for record in records]
