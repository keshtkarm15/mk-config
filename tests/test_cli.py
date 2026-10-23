import argparse
import asyncio
import base64
import json
from dataclasses import replace

from mkconfig import cli
from mkconfig.collector import CollectionReport, SourceStatus
from mkconfig.core import parse_subscription


def _sample_configurations():
    vmess = base64.b64encode(
        json.dumps(
            {
                "add": "vmess.example",
                "port": 443,
                "id": "00000000-0000-0000-0000-000000000001",
                "net": "ws",
                "tls": "tls",
                "path": "/",
                "host": "vmess.example",
                "ps": "vmess",
                "aid": "0",
                "v": "2",
            }
        ).encode()
    ).decode()
    links = "\n".join(
        [
            "vless://uuid@vless.example:443?encryption=none&type=ws&security=tls#vless",
            f"vmess://{vmess}",
            "trojan://password@trojan.example:443?sni=trojan.example#trojan",
            "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388#shadowsocks",
            "vless://uuid@vless.example:443?encryption=none&type=ws&security=tls#duplicate",
        ]
    )
    return parse_subscription(links)[0]


def test_subscription_output_is_base64_of_valid_deduplicated_uris(tmp_path):
    configurations = _sample_configurations()
    unsupported, _ = parse_subscription(
        "socks5://user:password@socks.example:1080\n"
        "http://user:password@proxy.example:8080"
    )
    configurations.extend(unsupported)
    output = tmp_path / "subscription.txt"
    output.write_text("previous-subscription", encoding="ascii")

    assert len(configurations) == 6
    assert cli._write_subscription(configurations, output)
    encoded = output.read_text(encoding="ascii")
    decoded = base64.b64decode(encoded, validate=True).decode()
    output_configurations, invalid_count = parse_subscription(decoded)

    assert invalid_count == 0
    assert len(output_configurations) == 4
    assert {configuration.protocol for configuration in output_configurations} == {
        "vless",
        "vmess",
        "trojan",
        "ss",
    }
    assert "password" not in str([item.to_dict() for item in configurations])


def test_subscription_writer_limit_and_repeat_output(tmp_path):
    configurations = _sample_configurations()
    output = tmp_path / "subscription.txt"
    assert cli._write_subscription(configurations, output, limit=2) == 2
    first = output.read_text(encoding="ascii")
    assert len(base64.b64decode(first, validate=True).decode().splitlines()) == 2

    assert cli._write_subscription(configurations, output, limit=2) == 2
    assert output.read_text(encoding="ascii") == first


def test_empty_refresh_preserves_previous_subscription(tmp_path):
    output = tmp_path / "subscription.txt"
    previous = base64.b64encode(b"previous-valid-subscription").decode("ascii")
    output.write_text(previous, encoding="ascii")

    assert cli._write_subscription([], output) == 0
    assert output.read_text(encoding="ascii") == previous


def _arguments(source_file, output_file):
    return argparse.Namespace(
        sources=source_file,
        limit=None,
        timeout=15,
        max_response_bytes=1_048_576,
        concurrency=5,
        output=output_file,
    )


def test_refresh_reports_publication_and_source_metrics(tmp_path, monkeypatch, capsys):
    source_file = tmp_path / "sources.json"
    source_file.write_text('{"retention_limit": 40, "sources": []}', encoding="utf-8")
    output = tmp_path / "subscription.txt"
    configurations = _sample_configurations()
    report = CollectionReport(
        refreshed_at="2026-10-22T00:00:00+00:00",
        configurations=configurations,
        sources=[
            SourceStatus("source-1", "ok", 4),
            SourceStatus("source-2", "empty", 0),
        ],
        discovered_count=4,
        retained_count=4,
    )

    async def fake_collect(*args, **kwargs):
        return report

    async def fake_test_configurations(configs, tester_url, token):
        assert tester_url == "https://tester.example"
        assert token == "test-token-value-that-is-at-least-32-characters"
        return [
            replace(item, status="tested", healthy=True, latency_ms=10.0)
            for item in configs
        ]

    monkeypatch.setattr(cli, "collect", fake_collect)
    monkeypatch.setattr(cli, "test_configurations", fake_test_configurations)
    monkeypatch.setenv("MKCONFIG_TESTER_URL", "https://tester.example")
    monkeypatch.setenv(
        "MKCONFIG_TESTER_TOKEN", "test-token-value-that-is-at-least-32-characters"
    )
    exit_code = asyncio.run(cli._refresh(_arguments(source_file, output)))
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert result["published_count"] == 4
    assert result["successful_source_count"] == 1
    assert result["last_updated_at"] == report.refreshed_at
    assert result["connection_test_status"] == "tested"
    assert result["tested_count"] == 4
    assert result["publication_status"] == "updated"


def test_empty_refresh_reports_preserved_output_and_failure(
    tmp_path, monkeypatch, capsys
):
    source_file = tmp_path / "sources.json"
    source_file.write_text('{"retention_limit": 40, "sources": []}', encoding="utf-8")
    output = tmp_path / "subscription.txt"
    previous = base64.b64encode(b"previous-valid-subscription").decode("ascii")
    output.write_text(previous, encoding="ascii")
    report = CollectionReport(
        refreshed_at="2026-10-22T00:00:00+00:00",
        configurations=[],
        sources=[SourceStatus("source-1", "error", 0, error="source_unavailable")],
        discovered_count=0,
        retained_count=0,
    )

    async def fake_collect(*args, **kwargs):
        return report

    monkeypatch.setattr(cli, "collect", fake_collect)
    exit_code = asyncio.run(cli._refresh(_arguments(source_file, output)))
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert result["published_count"] == 0
    assert result["successful_source_count"] == 0
    assert result["publication_status"] == "preserved_previous"
    assert output.read_text(encoding="ascii") == previous


def test_source_failure_preserves_previous_subscription(tmp_path, monkeypatch, capsys):
    source_file = tmp_path / "sources.json"
    source_file.write_text('{"retention_limit": 40, "sources": []}', encoding="utf-8")
    output = tmp_path / "subscription.txt"
    previous = base64.b64encode(b"previous-valid-subscription").decode("ascii")
    output.write_text(previous, encoding="ascii")
    configurations = _sample_configurations()
    report = CollectionReport(
        refreshed_at="2026-10-22T00:00:00+00:00",
        configurations=configurations,
        sources=[
            SourceStatus("source-1", "ok", 4),
            SourceStatus("source-2", "error", 0, error="timeout"),
        ],
        discovered_count=4,
        retained_count=4,
    )

    async def fake_collect(*args, **kwargs):
        return report

    monkeypatch.setattr(cli, "collect", fake_collect)
    exit_code = asyncio.run(cli._refresh(_arguments(source_file, output)))
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert result["publication_status"] == "preserved_previous"
    assert output.read_text(encoding="ascii") == previous


def test_missing_tester_configuration_preserves_previous_subscription(
    tmp_path, monkeypatch, capsys
):
    source_file = tmp_path / "sources.json"
    source_file.write_text('{"retention_limit": 40, "sources": []}', encoding="utf-8")
    output = tmp_path / "subscription.txt"
    previous = base64.b64encode(b"previous-valid-subscription").decode("ascii")
    output.write_text(previous, encoding="ascii")
    report = CollectionReport(
        refreshed_at="2026-10-22T00:00:00+00:00",
        configurations=_sample_configurations(),
        sources=[SourceStatus("source-1", "ok", 4)],
        discovered_count=4,
        retained_count=4,
    )

    async def fake_collect(*args, **kwargs):
        return report

    monkeypatch.setattr(cli, "collect", fake_collect)
    monkeypatch.delenv("MKCONFIG_TESTER_URL", raising=False)
    monkeypatch.delenv("MKCONFIG_TESTER_TOKEN", raising=False)
    exit_code = asyncio.run(cli._refresh(_arguments(source_file, output)))
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert result["test_error"] == "tester_not_configured"
    assert result["publication_status"] == "preserved_previous"
    assert output.read_text(encoding="ascii") == previous


def test_custom_retention_tests_candidate_pool_before_selecting_fastest(
    tmp_path, monkeypatch, capsys
):
    source_file = tmp_path / "sources.json"
    source_file.write_text('{"retention_limit": 40, "sources": []}', encoding="utf-8")
    output = tmp_path / "subscription.txt"
    configurations = parse_subscription(
        "\n".join(
            f"vless://uuid@node-{index}.example:443#node-{index}"
            for index in range(45)
        )
    )[0]
    report = CollectionReport(
        refreshed_at="2026-10-22T00:00:00+00:00",
        configurations=configurations[:35],
        sources=[SourceStatus("source-1", "ok", 45)],
        discovered_count=45,
        retained_count=35,
    )

    async def fake_collect(sources, **kwargs):
        assert kwargs["retention_limit"] == 35
        return report

    async def fake_test(configs, tester_url, token):
        return [
            replace(item, status="tested", healthy=True, latency_ms=float(index))
            for index, item in enumerate(reversed(configs))
        ]

    monkeypatch.setattr(cli, "collect", fake_collect)
    monkeypatch.setattr(cli, "test_configurations", fake_test)
    monkeypatch.setenv("MKCONFIG_TESTER_URL", "https://tester.example")
    monkeypatch.setenv(
        "MKCONFIG_TESTER_TOKEN", "test-token-value-that-is-at-least-32-characters"
    )
    args = _arguments(source_file, output)
    args.limit = 7

    exit_code = asyncio.run(cli._refresh(args))
    result = json.loads(capsys.readouterr().out)
    decoded = base64.b64decode(output.read_text(encoding="ascii"), validate=True).decode()

    assert exit_code == 0
    assert result["tested_count"] == 35
    assert result["published_count"] == 7
    assert len(decoded.splitlines()) == 7
