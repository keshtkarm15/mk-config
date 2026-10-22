import asyncio

import pytest

from mkconfig.collector import Source, collect, validate_source_url
from mkconfig.testing import UnavailableTester, validate_test_target


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


@pytest.mark.parametrize(
    ("response", "error", "expected"),
    [
        (FakeResponse(status=503), None, "http_error"),
        (FakeResponse(body=b""), None, "empty"),
        (FakeResponse(body=b"x" * 20), None, "response_too_large"),
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
    assert (
        report.sources[0].error == expected
        if expected != "empty"
        else report.sources[0].status == expected
    )


def test_reject_unsafe_source_urls():
    for url in (
        "http://source.example/sub",
        "https://127.0.0.1/sub",
        "https://user@source.example/sub",
        "https://metadata.google.internal/",
    ):
        with pytest.raises(ValueError):
            validate_source_url(url)


def test_tester_unavailable_is_explicit_and_never_tests():
    result = run(UnavailableTester().test(None, "https://target.example/"))
    assert result.status == "untested"
    assert result.latency_ms is None
    assert result.error == "tester_unavailable"


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
