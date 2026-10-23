"""Parsing, metadata validation, stable identifiers, and deterministic ranking."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

MAX_URI_LENGTH = 16_384
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
_RESERVED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home",
    ".lan",
    ".corp",
    ".invalid",
    ".test",
    ".onion",
    ".arpa",
)
DEFAULT_RETENTION_LIMIT = 40
V2RAYNG_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "ss"})
CONFIG_NAME_PREFIX = "MK.CONFIG | "


def _contains_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def is_reserved_hostname(host: str) -> bool:
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        return False
    if normalized == "localhost":
        return True
    return any(
        normalized == suffix[1:] or normalized.endswith(suffix)
        for suffix in _RESERVED_HOST_SUFFIXES
    )


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
    if not normalized or is_reserved_hostname(normalized):
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
    if not payload or _contains_control_chars(payload):
        raise ValueError("invalid_vmess")
    try:
        data = json.loads(_decode_b64(payload))
        if not isinstance(data, dict):
            raise ValueError("invalid_vmess")
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
    if _contains_control_chars(remainder):
        raise ValueError("invalid_shadowsocks")
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


def _parse_universal_uri(value: str) -> tuple[str, int]:
    if _contains_control_chars(value):
        raise ValueError("invalid_uri")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise ValueError("invalid_uri") from error
    host = parsed.hostname or ""
    port = parsed.port or 0
    if not host or port == 0:
        raise ValueError("invalid_uri")
    if parsed.scheme in {"vless", "trojan"} and parsed.username is None:
        raise ValueError("invalid_uri")
    return host, port


def parse_configuration(uri: str) -> Configuration:
    """Parse a supported proxy link and return metadata without credentials."""
    value = uri.strip()
    if not value or len(value) > MAX_URI_LENGTH:
        raise ValueError("invalid_uri")
    if "\r" in value or "\n" in value:
        raise ValueError("invalid_uri")
    scheme = value.split(":", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError("unsupported_protocol")

    if scheme == "vmess":
        host, port, _ = _parse_vmess(value)
    elif scheme == "ss":
        host, port, _ = _parse_ss(value)
    else:
        host, port = _parse_universal_uri(value)

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


def _branded_uri(uri: str) -> str:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri.removeprefix("vmess://")
        try:
            data = json.loads(_decode_b64(payload))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid_vmess") from error
        if not isinstance(data, dict):
            raise ValueError("invalid_vmess")
        original_name = data.get("ps") or "Unnamed"
        if not isinstance(original_name, str):
            raise ValueError("invalid_vmess")
        if not original_name.startswith(CONFIG_NAME_PREFIX):
            data["ps"] = CONFIG_NAME_PREFIX + original_name
        encoded = base64.b64encode(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        ).decode("ascii")
        return f"vmess://{encoded}"

    base_uri, _, raw_name = uri.partition("#")
    try:
        original_name = unquote(raw_name, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("invalid_configuration_name") from error
    display_name = original_name or "Unnamed"
    if not display_name.startswith(CONFIG_NAME_PREFIX):
        display_name = CONFIG_NAME_PREFIX + display_name
    return f"{base_uri}#{quote(display_name, safe='')}"


def encode_subscription(
    configurations: list[Configuration], limit: int = DEFAULT_RETENTION_LIMIT
) -> str:
    """Encode branded, deduplicated URIs as a bounded v2rayNG Base64 subscription."""
    if limit < 0:
        raise ValueError("retention_limit_must_be_nonnegative")
    unique: dict[str, Configuration] = {}
    for configuration in configurations:
        if (
            configuration.protocol in V2RAYNG_PROTOCOLS
            and configuration.subscription_uri is not None
        ):
            unique.setdefault(configuration.id, configuration)
    uris = [
        _branded_uri(configuration.subscription_uri)
        for configuration in list(unique.values())[:limit]
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

    ordered = sorted(configurations, key=ranking_key)
    return ordered[:limit]


def load_configurations(records: list[dict[str, object]]) -> list[Configuration]:
    """Construct metadata records from test or external tester output."""
    return [Configuration(**record) for record in records]
