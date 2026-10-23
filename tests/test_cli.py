import argparse
import asyncio
import base64
import json

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

    monkeypatch.setattr(cli, "collect", fake_collect)
    exit_code = asyncio.run(cli._refresh(_arguments(source_file, output)))
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert result["published_count"] == 4
    assert result["successful_source_count"] == 1
    assert result["last_updated_at"] == report.refreshed_at
    assert result["connection_test_status"] == "untested"
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
