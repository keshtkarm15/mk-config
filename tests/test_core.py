import base64
import json

import pytest

from mkconfig.core import (
    DEFAULT_RETENTION_LIMIT,
    Configuration,
    decode_subscription,
    parse_configuration,
    parse_subscription,
    rank_configurations,
)


@pytest.mark.parametrize(
    ("uri", "protocol", "host", "port"),
    [
        (
            "vless://uuid@edge.example:443?encryption=none#node",
            "vless",
            "edge.example",
            443,
        ),
        ("trojan://secret@edge.example:443#node", "trojan", "edge.example", 443),
        ("socks5://user:pass@edge.example:1080", "socks", "edge.example", 1080),
        ("http://user:pass@edge.example:8080", "http", "edge.example", 8080),
        ("https://edge.example:443", "https", "edge.example", 443),
        ("ss://method:secret@edge.example:8388#node", "ss", "edge.example", 8388),
    ],
)
def test_parse_supported_uris_without_retaining_credentials(uri, protocol, host, port):
    configuration = parse_configuration(uri)
    assert (configuration.protocol, configuration.host, configuration.port) == (
        protocol,
        host,
        port,
    )
    assert "secret" not in repr(configuration)
    assert configuration.status == "untested"
    assert configuration.latency_ms is None
    assert configuration.healthy is None


def test_parse_vmess_and_legacy_shadowsocks():
    vmess_payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "add": "node.example",
                    "port": "443",
                    "id": "credential",
                    "ps": "vmess node",
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    vmess = parse_configuration(f"vmess://{vmess_payload}")
    legacy = (
        base64.urlsafe_b64encode(b"method:password@node.example:8388")
        .decode()
        .rstrip("=")
    )
    shadowsocks = parse_configuration(f"ss://{legacy}#legacy")
    assert (vmess.host, vmess.port) == ("node.example", 443)
    assert (shadowsocks.host, shadowsocks.port) == ("node.example", 8388)


def test_base64_subscription_and_malformed_input():
    links = "vless://one@one.example:443\ntrojan://two@two.example:443"
    encoded = base64.b64encode(links.encode()).decode()
    assert decode_subscription(encoded) == links
    parsed, invalid = parse_subscription(encoded)
    assert len(parsed) == 2 and invalid == 0
    with pytest.raises(ValueError, match="invalid_base64"):
        decode_subscription("%%%not-base64%%")


def test_invalid_uri_and_unsafe_targets_are_rejected():
    for uri in (
        "vless://missing-port",
        "ftp://host.example:21",
        "http://127.0.0.1:8080",
        "socks5://localhost:1080",
        "http://192.168.1.2:8080",
    ):
        with pytest.raises(ValueError):
            parse_configuration(uri)


def test_deduplication_and_stable_identifiers():
    uri = "trojan://secret@edge.example:443#main"
    first, invalid = parse_subscription(
        f"{uri}\ntrojan://different@edge.example:443#other\nnot-a-link"
    )
    second = parse_configuration(uri)
    assert len(first) == 1 and invalid == 1
    assert first[0].id == second.id
    assert "secret" not in first[0].id


def test_default_retention_and_explicit_limit():
    assert DEFAULT_RETENTION_LIMIT == 40
    records = [
        Configuration(str(index), "vless", "edge.example", 443) for index in range(45)
    ]
    assert len(rank_configurations(records)) == 40
    assert len(rank_configurations(records, 3)) == 3


def test_ranking_never_fabricates_health_or_latency():
    unknown = Configuration("b", "vless", "edge.example", 443)
    unverified = Configuration(
        "d", "vless", "edge.example", 443, latency_ms=1, healthy=True
    )
    slower = Configuration(
        "a", "vless", "edge.example", 443, status="tested", latency_ms=20, healthy=True
    )
    faster = Configuration(
        "c", "vless", "edge.example", 443, status="tested", latency_ms=10, healthy=True
    )
    ranked = rank_configurations([unknown, slower, faster, unverified])
    assert [item.id for item in ranked] == ["c", "a", "b", "d"]
    assert (
        unknown.latency_ms is None
        and unknown.healthy is None
        and unknown.status == "untested"
    )
