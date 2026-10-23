import base64
import json
import logging
from datetime import datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mkconfig import protocol_tester_service as service


def test_vless_builds_pinned_tls_websocket_outbound():
    identifier = str(uuid4())
    uri = (
        f"vless://{identifier}@edge.example:443?security=tls&sni=origin.example"
        "&type=ws&path=%2Fprobe&host=ws.example"
    )
    outbound = service.build_outbound(uri, "203.0.113.10")

    assert outbound["server"] == "203.0.113.10"
    assert outbound["server_port"] == 443
    assert outbound["uuid"] == identifier
    assert outbound["tls"] == {"enabled": True, "server_name": "origin.example"}
    assert outbound["transport"] == {
        "type": "ws",
        "path": "/probe",
        "headers": {"Host": "ws.example"},
    }
    assert "insecure" not in outbound["tls"]


def test_vmess_preserves_supported_connection_parameters():
    original = {
        "add": "edge.example",
        "port": "443",
        "id": str(uuid4()),
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "tls": "tls",
        "path": "/vmess",
        "host": "origin.example",
        "sni": "tls.example",
    }
    payload = base64.urlsafe_b64encode(json.dumps(original).encode()).decode()
    outbound = service.build_outbound(f"vmess://{payload}", "203.0.113.10")

    assert outbound["uuid"] == original["id"]
    assert outbound["alter_id"] == 0
    assert outbound["server"] == "203.0.113.10"
    assert outbound["tls"]["server_name"] == "tls.example"
    assert outbound["transport"] == {
        "type": "ws",
        "path": "/vmess",
        "headers": {"Host": "origin.example"},
    }


@pytest.mark.parametrize(
    ("uri", "expected_type"),
    [
        (
            "trojan://password@edge.example:443?sni=origin.example",
            "trojan",
        ),
        (
            "ss://YWVzLTI1Ni1nY206cGFzcw@edge.example:8388",
            "shadowsocks",
        ),
    ],
)
def test_trojan_and_shadowsocks_outbounds(uri, expected_type):
    outbound = service.build_outbound(uri, "203.0.113.10")
    assert outbound["type"] == expected_type
    assert outbound["server"] == "203.0.113.10"


def test_rejects_unsupported_protocol_transports_tls_and_cipher():
    with pytest.raises(service.TesterError, match="unsupported_protocol"):
        service.build_outbound("socks5://user:pass@edge.example:1080", "203.0.113.10")
    with pytest.raises(service.TesterError, match="unsupported_transport"):
        service.build_outbound(
            f"vless://{uuid4()}@edge.example:443?type=xhttp", "203.0.113.10"
        )
    with pytest.raises(service.TesterError, match="unsupported_tls_mode"):
        service.build_outbound(
            f"vless://{uuid4()}@edge.example:443?security=reality", "203.0.113.10"
        )
    with pytest.raises(service.TesterError, match="unsupported_shadowsocks_plugin"):
        service.build_outbound(
            "ss://YWVzLTI1Ni1nY206cGFzcw@edge.example:8388?plugin=obfs",
            "203.0.113.10",
        )


def test_rejects_private_test_and_proxy_addresses():
    for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"):
        with pytest.raises(service.TesterError, match="unsafe_destination"):
            service._resolve_public_ip(address, 443)


def test_probe_configuration_requires_allowlisted_https_destination(monkeypatch):
    monkeypatch.setenv("MKCONFIG_TEST_URL", "http://127.0.0.1/")
    with pytest.raises(RuntimeError, match="invalid_test_endpoint_configuration"):
        service._probe_settings()


def test_api_requires_bearer_auth_and_redacts_uri_and_token(monkeypatch, caplog):
    token = "test-token-value-that-is-at-least-32-characters"
    uri = "trojan://synthetic-password@edge.example:443?sni=edge.example"

    class FakeRunner:
        available = True

        async def test(self, candidate):
            assert candidate == uri
            return True, 23.4, None, "trojan"

    async def allow_request():
        return True

    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    monkeypatch.setattr(service, "_allow_request", allow_request)
    monkeypatch.setattr(service, "is_tehran_test_window", lambda: True)
    monkeypatch.setattr(service.app.state, "runner", FakeRunner())
    caplog.set_level(logging.INFO, logger="mkconfig.tester")

    with TestClient(service.app) as client:
        unauthorized = client.post("/test", json={"uri": uri})
        assert unauthorized.status_code == 401
        response = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json={"uri": uri},
        )

    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert result["latency_ms"] == 23.4
    assert result["protocol"] == "trojan"
    datetime.fromisoformat(result["tested_at"])
    assert token not in caplog.text
    assert "synthetic-password" not in caplog.text
    assert uri not in caplog.text


def test_api_rejects_extra_request_fields(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)

    async def allow_request():
        return True

    monkeypatch.setattr(service, "_allow_request", allow_request)
    with TestClient(service.app) as client:
        response = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "uri": "vless://uuid@edge.example:443",
                "target": "https://example.com",
            },
        )
    assert response.status_code == 400


def test_api_skips_tester_outside_tehran_window(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    uri = "trojan://synthetic-password@edge.example:443?sni=edge.example"

    class FakeRunner:
        available = True

        def __init__(self):
            self.calls = 0

        async def test(self, candidate):
            self.calls += 1
            return True, 23.4, None, "trojan"

    async def allow_request():
        return True

    runner = FakeRunner()
    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    monkeypatch.setattr(service, "_allow_request", allow_request)
    monkeypatch.setattr(service, "is_tehran_test_window", lambda: False)
    monkeypatch.setattr(service.app.state, "runner", runner)

    with TestClient(service.app) as client:
        response = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json={"uri": uri},
        )

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["latency_ms"] is None
    assert response.json()["error_code"] == "outside_test_window"
    assert runner.calls == 0


def test_api_rejects_oversized_body_and_rate_limits(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    async def allow_request():
        return True

    monkeypatch.setattr(service, "_allow_request", allow_request)
    with TestClient(service.app) as client:
        oversized = client.post(
            "/test",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            content=b"{" + b" " * service.MAX_REQUEST_BYTES + b"}",
        )
        assert oversized.status_code == 413

        async def deny_request():
            return False

        monkeypatch.setattr(service, "_allow_request", deny_request)
        rate_limited = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json={"uri": "vless://00000000-0000-0000-0000-000000000000@edge.example:443"},
        )
    assert rate_limited.status_code == 429