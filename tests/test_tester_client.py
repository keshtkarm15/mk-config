import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime
from uuid import UUID

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
        return self.response(kwargs) if callable(self.response) else self.response


def run(coro):
    return asyncio.run(coro)


def _response(configuration, signed_uri=URI, **updates):
    def respond(request):
        request_id = request["json"]["request_id"]
        UUID(request_id)
        payload = {
            "success": True,
            "latency_ms": 23.4,
            "tested_at": datetime.now(UTC).isoformat(),
            "protocol": configuration.protocol,
            "configuration_id": configuration.id,
            "request_id": request_id,
            "candidate_id": hmac.new(
                TOKEN.encode(),
                b"candidate\0" + request_id.encode() + b"\0" + signed_uri.encode(),
                "sha256",
            ).hexdigest(),
            "error_code": None,
        }
        payload.update(updates)
        message = json.dumps(
            {"uri": signed_uri, **payload}, sort_keys=True, separators=(",", ":")
        ).encode()
        payload["response_signature"] = hmac.new(
            TOKEN.encode(), message, "sha256"
        ).hexdigest()
        return FakeResponse(200, json.dumps(payload).encode())

    return respond


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
    assert request["json"]["uri"] == URI
    UUID(request["json"]["request_id"])


def test_client_rejects_response_for_another_configuration():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, configuration_id="wrong-id"))
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_uri_with_different_credentials():
    configuration = parse_configuration(URI)
    altered_uri = URI.replace("synthetic-password", "different-password")
    session = FakeSession(_response(configuration, signed_uri=altered_uri))
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_invalid_candidate_hmac():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, candidate_id="invalid-signature"))
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_invalid_response_signature():
    configuration = parse_configuration(URI)
    session = FakeSession(
        _response(configuration, response_signature="invalid-signature")
    )
    with pytest.raises(ClientFailure, match="tester_response_signature_invalid"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_incomplete_signed_response():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, response_signature=""))
    with pytest.raises(ClientFailure, match="tester_response_signature_invalid"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_replayed_response_from_previous_request():
    configuration = parse_configuration(URI)
    replay = _response(configuration)(
        {"json": {"uri": URI, "request_id": "00000000-0000-4000-8000-000000000001"}}
    )
    session = FakeSession(replay)
    with pytest.raises(ClientFailure, match="tester_result_mismatch"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_stale_response_timestamp():
    configuration = parse_configuration(URI)
    stale = datetime(2000, 1, 1, tzinfo=UTC).isoformat()
    session = FakeSession(_response(configuration, tested_at=stale))
    with pytest.raises(ClientFailure, match="stale_tester_response"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_success_without_real_latency():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, latency_ms=None))
    with pytest.raises(ClientFailure, match="invalid_tester_response"):
        run(run_tester_checks([configuration], "https://tester.example", TOKEN, session))


def test_client_rejects_success_with_boolean_latency():
    configuration = parse_configuration(URI)
    session = FakeSession(_response(configuration, latency_ms=True))
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