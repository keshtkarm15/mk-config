import asyncio
import logging
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from mkconfig.collector import Source, collect, validate_source_url
from mkconfig.testing import (
    TehranWindowTester,
    TestResult as ProtocolTestResult,
    UnavailableTester,
    is_tehran_test_window,
    validate_test_target,
)


class FakeContent:
    def __init__(self, body):
        self.body = body

    async def iter_chunked(self, chunk_size):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset : offset + chunk_size]


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def get(self, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        if self.error:
            raise self.error
        return self.response


def run(coro):
    return asyncio.run(coro)


def test_collect_deduplicates_and_reports_untested():
    link = b"vless://uuid@edge.example:443"
    response = FakeResponse(body=link + b"\n" + link)
    report = run(
        collect(
            [
                Source(
                    "https://source.example/sub",
                    "https://source.example/sub",
                )
            ],
            session=FakeSession(response),
        )
    )
    assert report.discovered_count == 1
    assert report.configurations[0].status == "untested"
    assert report.configurations[0].latency_ms is None
    assert report.sources[0].status == "ok"
    assert report.sources[0].name == "source-1"
    assert "private" not in str(report.to_dict())


def test_collection_retention_defaults_to_40_and_accepts_override():
    links = "\n".join(f"vless://id@node-{index}.example:443" for index in range(45))
    source = Source("sample", "https://source.example/sub")

    default_report = run(
        collect([source], session=FakeSession(FakeResponse(body=links.encode())))
    )
    limited_report = run(
        collect(
            [source],
            retention_limit=7,
            session=FakeSession(FakeResponse(body=links.encode())),
        )
    )

    assert default_report.discovered_count == 45
    assert default_report.retained_count == len(default_report.configurations) == 40
    assert limited_report.retained_count == len(limited_report.configurations) == 7


@pytest.mark.parametrize(
    ("response", "error", "expected"),
    [
        (FakeResponse(status=503), None, "http_error"),
        (FakeResponse(body=b""), None, "empty"),
        (FakeResponse(body=b"x" * 20), None, "response_too_large"),
        (FakeResponse(body=b"%%%"), None, "invalid_base64"),
        (None, TimeoutError(), "timeout"),
    ],
)
def test_source_failure_empty_and_size_limits(response, error, expected):
    report = run(
        collect(
            [Source("sample", "https://source.example/sub")],
            max_response_bytes=10,
            session=FakeSession(response, error),
        )
    )
    assert report.sources[0].status != "ok"
    assert report.sources[0].count == 0
    assert (
        report.sources[0].error == expected
        if expected != "empty"
        else report.sources[0].status == expected
    )


def test_valid_source_results_survive_another_source_failure():
    response = FakeResponse(body=b"vless://id@node.example:443")

    class SelectiveFakeSession:
        def get(self, url, **kwargs):
            assert kwargs["allow_redirects"] is False
            if "unavailable.example" in url:
                raise TimeoutError()
            return response

    report = run(
        collect(
            [
                Source("unavailable", "https://unavailable.example/sub"),
                Source("valid", "https://valid.example/sub"),
            ],
            session=SelectiveFakeSession(),
        )
    )

    assert report.sources[0].status == "error"
    assert report.sources[0].error == "timeout"
    assert report.sources[1].status == "ok"
    assert report.discovered_count == report.retained_count == 1
    assert report.configurations[0].status == "untested"
    assert report.configurations[0].healthy is None
    assert report.configurations[0].latency_ms is None


def test_reject_unsafe_source_urls():
    for url in (
        "http://source.example/sub",
        "https://127.0.0.1/sub",
        "https://user@source.example/sub",
        "https://metadata.google.internal/",
        "https://example.invalid/",
        "https://example.test/",
        "https://example.onion/",
    ):
        with pytest.raises(ValueError):
            validate_source_url(url)


def test_tester_unavailable_is_explicit_and_never_tests():
    result = run(UnavailableTester().test(None, "https://target.example/"))
    assert result.status == "untested"
    assert result.latency_ms is None
    assert result.error == "tester_unavailable"


@pytest.mark.parametrize(
    ("hour", "minute", "expected"),
    [(6, 59, False), (7, 0, True), (21, 59, True), (22, 0, False)],
)
def test_tehran_test_window_boundaries(hour, minute, expected):
    local_time = datetime(
        2026, 10, 23, hour, minute, tzinfo=ZoneInfo("Asia/Tehran")
    )
    assert is_tehran_test_window(local_time) is expected


def test_tehran_window_tester_skips_real_tester_outside_window(monkeypatch):
    class FakeTester:
        available = True

        def __init__(self):
            self.calls = 0

        async def test(self, configuration, target_url):
            self.calls += 1
            return ProtocolTestResult("tested", latency_ms=12)

    async def check():
        tester = FakeTester()
        monkeypatch.setattr("mkconfig.testing.is_tehran_test_window", lambda: False)
        result = await TehranWindowTester(tester).test(None, "https://target.example/")
        assert result.status == "untested"
        assert result.error == "outside_test_window"
        assert tester.calls == 0

        monkeypatch.setattr("mkconfig.testing.is_tehran_test_window", lambda: True)
        result = await TehranWindowTester(tester).test(None, "https://target.example/")
        assert result.status == "tested"
        assert result.latency_ms == 12
        assert tester.calls == 1

    run(check())


def test_allowlist_and_private_test_target_rejection(monkeypatch):
    async def private_dns(*args, **kwargs):
        return [(2, 1, 6, "", ("10.0.0.1", 443))]

    async def check():
        with pytest.raises(ValueError, match="not_allowlisted"):
            await validate_test_target("https://target.example/", {"other.example"})
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", private_dns)
        with pytest.raises(ValueError, match="unsafe_test_target"):
            await validate_test_target("https://target.example/", {"target.example"})

    run(check())


def test_unsafe_source_is_not_requested():
    report = run(
        collect([Source("local", "https://localhost/secret")], session=FakeSession())
    )
    assert report.sources[0].error == "unsafe_source_url"


def test_logs_and_report_do_not_expose_source_url_or_query(caplog):
    source_url = "https://source.example/private-path?key=synthetic-marker"
    caplog.set_level(logging.INFO, logger="mkconfig")
    report = run(
        collect(
            [Source("sensitive-label", source_url)],
            session=FakeSession(FakeResponse(body=b"vless://id@node.example:443")),
        )
    )

    assert source_url not in caplog.text
    assert "synthetic-marker" not in caplog.text
    assert source_url not in str(report.to_dict())
    assert "synthetic-marker" not in str(report.to_dict())
    assert report.sources[0].name == "source-1"


@pytest.mark.parametrize(
    "options",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"max_concurrency": 21},
        {"max_response_bytes": 10 * 1024 * 1024 + 1},
    ],
)
def test_collection_limits_cannot_disable_safeguards(options):
    with pytest.raises(ValueError, match="invalid_collection_limits"):
        run(collect([], **options))
