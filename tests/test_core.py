import base64
import json
from urllib.parse import unquote

import pytest

from mkconfig.core import (
    DEFAULT_RETENTION_LIMIT,
    CONFIG_NAME_PREFIX,
    Configuration,
    decode_subscription,
    encode_subscription,
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
        "http://metadata.google.internal:80",
        "https://example.invalid/",
    ):
        with pytest.raises(ValueError):
            parse_configuration(uri)


def test_special_use_hostnames_are_rejected_even_when_not_private_ip_literals():
    for uri in (
        "vless://uuid@example.invalid:443",
        "vless://uuid@host.example.test:443",
        "vless://uuid@node.onion:443",
        "vless://uuid@node.localdomain:443",
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


def test_subscription_encoder_caps_output_and_never_adds_advertisement_lines():
    links = "\n".join(
        f"vless://uuid@node-{index}.example:443?type=ws#node-{index}"
        for index in range(45)
    )
    configurations, invalid = parse_subscription(links)
    assert invalid == 0

    for limit, expected in ((40, 40), (7, 7)):
        encoded = encode_subscription(configurations, limit=limit)
        decoded = decode_subscription(encoded)
        lines = decoded.splitlines()
        assert len(lines) == expected
        assert all(line.startswith("vless://") for line in lines)
        parsed, invalid_count = parse_subscription(decoded)
        assert invalid_count == 0
        assert len(parsed) == expected
        assert all(
            line.rsplit("#", 1)[1].startswith("MK.CONFIG%20%7C%20")
            for line in lines
        )


@pytest.mark.parametrize(
    ("uri", "protocol", "original_name"),
    [
        (
            "vless://uuid@edge.example:443?encryption=none&type=ws&security=tls#"
            "Edge%20%23%20%D9%86%D9%88%D8%AF",
            "vless",
            "Edge # \u0646\u0648\u062f",
        ),
        (
            "trojan://secret@edge.example:443?sni=origin.example&type=tcp#main",
            "trojan",
            "main",
        ),
        (
            "ss://YWVzLTI1Ni1nY206cGFzcw@edge.example:8388?plugin=obfs#ss-node",
            "ss",
            "ss-node",
        ),
    ],
)
def test_uri_protocol_branding_preserves_connection_data(uri, protocol, original_name):
    configuration = parse_configuration(uri)
    encoded = encode_subscription([configuration])
    branded = decode_subscription(encoded).strip()
    original_base, _, _ = uri.partition("#")
    branded_base, _, raw_name = branded.partition("#")

    assert configuration.protocol == protocol
    assert branded_base == original_base
    assert unquote(raw_name) == CONFIG_NAME_PREFIX + original_name
    reparsed = parse_configuration(branded)
    assert reparsed.id == configuration.id
    assert encode_subscription([reparsed]) == encoded


def test_vmess_branding_changes_only_display_name_and_is_idempotent():
    original_data = {
        "add": "vmess.example",
        "port": "443",
        "id": "credential",
        "net": "ws",
        "tls": "tls",
        "path": "/special?x=1",
        "host": "origin.example",
        "ps": "Node # \u0646\u0648\u062f",
        "aid": "0",
        "v": "2",
    }
    payload = base64.urlsafe_b64encode(json.dumps(original_data).encode()).decode()
    configuration = parse_configuration(f"vmess://{payload}")

    encoded = encode_subscription([configuration])
    branded_uri = decode_subscription(encoded).strip()
    branded_data = json.loads(
        base64.b64decode(branded_uri.removeprefix("vmess://"), validate=True)
    )
    assert branded_data["ps"] == CONFIG_NAME_PREFIX + original_data["ps"]
    assert {key: value for key, value in branded_data.items() if key != "ps"} == {
        key: value for key, value in original_data.items() if key != "ps"
    }
    assert encode_subscription([parse_configuration(branded_uri)]) == encoded


def test_subscription_encoder_deduplicates_by_original_configuration_identity():
    configurations, invalid = parse_subscription(
        "vless://uuid@edge.example:443?type=ws#original\n"
        "vless://uuid@edge.example:443?type=tcp#MK.CONFIG%20%7C%20existing"
    )
    assert invalid == 0
    assert len(configurations) == 1
    output = decode_subscription(encode_subscription(configurations))
    assert len(output.splitlines()) == 1


@pytest.mark.parametrize(
    ("uri", "expected_name"),
    [
        ("trojan://secret@edge.example:443", "MK.CONFIG | Unnamed"),
        (
            "trojan://secret@edge.example:443#MK.CONFIG%20%7C%20existing",
            "MK.CONFIG | existing",
        ),
    ],
)
def test_missing_and_existing_names_get_exactly_one_brand_prefix(uri, expected_name):
    configuration = parse_configuration(uri)
    output = decode_subscription(encode_subscription([configuration])).strip()
    assert unquote(output.partition("#")[2]) == expected_name


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
