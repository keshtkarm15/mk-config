import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest

from mkconfig.core import parse_configuration
from mkconfig.tester_client import (
    TesterClientError as ClientFailure,
    test_configurations as run_tester_checks,
)


TOKEN = "test-token-value-that-is-at-least-32-characters"
URI = "trojan://synthetic-password@edge.example:443?sni=edge.example"


class FakeContent:
    def __init__(self, body):
        self.body = body

    async def read(self, size):
        return self.body[:size]


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        return self.response


def run(coro):
    return asyncio.run(coro)


def _response(configuration, **updates):
    payload = {
        "success": True,
        "latency_ms": 23.4,
        "tested_at": datetime.now(UTC).isoformat(),
        "protocol": configuration.protocol,
        "configuration_id": configuration.id,
        "candidate_id": hmac.new(
            TOKEN.encode(), URI.encode(), hashlib.sha256
        ).hexdigest(),
        "error_code": None,
    }
    payload.update(updates)
    return FakeResponse(200, json.dumps(payload).encode())


def test_client_accepts_only_matching_real_success_result():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration))
    tested = run(
        run_tester_checks([configuration], "https://tester.example", TOKEN, session)
    )

    assert tested[0].status == "tested"
    assert tested[0].healthy is True
    assert tested[0].latency_ms == 23.4
    endpoint, request = session.calls[0]
    assert endpoint == "https://tester.example/test"
    assert request["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert request["allow_redirects"] is False


def test_client_rejects_response_for_another_configuration():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, configuration_id="wrong-id"))
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_result_for_same_endpoint_but_different_credentials():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, candidate_id="wrong-candidate"))
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_success_without_real_latency():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, latency_ms=None))
    with pytest.raises(ClientFailure, match="invalid_tester_response"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_failed_result_with_fabricated_latency():
    configuration = parse_configuration(URI)
    session = FakeSession(
        _response(
            configuration,
            success=False,
            latency_ms=10,
            error_code="probe_failed",
        )
    )
    with pytest.raises(ClientFailure, match="invalid_tester_response"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


@pytest.mark.parametrize(
    "url",
    [
        "http://tester.example",
        "https://127.0.0.1",
        "https://user:password@tester.example",
        "https://tester.example/path",
    ],
)
def test_client_rejects_unsafe_or_ambiguous_tester_urls(url):
    configuration = parse_configuration(URI)
    with pytest.raises(ClientFailure, match="invalid_tester_url"):
        run(run_tester_checks([configuration], url, TOKEN, FakeSession(None)))


def test_client_requires_strong_token():
    configuration = parse_configuration(URI)
    with pytest.raises(ClientFailure, match="tester_authentication_not_configured"):
        run(run_tester_checks([configuration], "https://tester.example", "short", FakeSession(None)))


@pytest.mark.parametrize(
    ("status", "error"),
    [(401, "tester_authentication_failed"), (429, "tester_rate_limited"), (503, "tester_unavailable")],
)
def test_client_fails_closed_on_http_error_responses(status, error):
    configuration = parse_configuration(URI)
    with pytest.raises(ClientFailure, match=error):
        run(
            run_tester_checks(
                [configuration],
                "https://tester.example",
                TOKEN,
                FakeSession(FakeResponse(status, b"{}")),
            )
        )