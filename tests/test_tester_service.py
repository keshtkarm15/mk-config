import asyncio
import base64
import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from mkconfig import protocol_tester_service as service


def _request(uri):
    return {"uri": uri, "request_id": str(uuid.uuid4())}


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
        unauthorized = client.post("/test", json=_request(uri))
        assert unauthorized.status_code == 401
        response = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json=_request(uri),
        )

    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert result["latency_ms"] == 23.4
    assert result["protocol"] == "trojan"
    datetime.fromisoformat(result["tested_at"])
    assert result["candidate_id"] == service._candidate_id(
        uri, result["request_id"], token
    )
    assert result["response_signature"] == service._response_signature(
        {key: value for key, value in result.items() if key != "response_signature"},
        uri,
        token,
    )
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
                "request_id": str(uuid.uuid4()),
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
            json=_request(uri),
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
            json=_request("vless://00000000-0000-0000-0000-000000000000@edge.example:443"),
        )
    assert rate_limited.status_code == 429


def test_api_rejects_incorrect_bearer_token(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    with TestClient(service.app) as client:
        response = client.post(
            "/test",
            headers={"Authorization": "Bearer wrong-token-value"},
            json=_request("trojan://secret@edge.example:443"),
        )
    assert response.status_code == 401


def test_api_rejects_replayed_request_id(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    uri = "trojan://synthetic-password@edge.example:443?sni=edge.example"

    class FakeRunner:
        available = True

        def __init__(self):
            self.calls = 0

        async def test(self, candidate):
            self.calls += 1
            return True, 8.0, None, "trojan"

    async def allow_request():
        return True

    runner = FakeRunner()
    payload = _request(uri)
    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    monkeypatch.setattr(service, "_allow_request", allow_request)
    monkeypatch.setattr(service, "is_tehran_test_window", lambda: True)
    monkeypatch.setattr(service.app.state, "runner", runner)
    with TestClient(service.app) as client:
        first = client.post(
            "/test", headers={"Authorization": f"Bearer {token}"}, json=payload
        )
        replay = client.post(
            "/test", headers={"Authorization": f"Bearer {token}"}, json=payload
        )
    assert first.status_code == 200
    assert replay.status_code == 409
    assert replay.json()["detail"] == "request_replayed"
    assert runner.calls == 1


def test_api_enforces_total_execution_timeout(monkeypatch):
    token = "test-token-value-that-is-at-least-32-characters"
    uri = "trojan://synthetic-password@edge.example:443?sni=edge.example"

    class HangingRunner:
        available = True

        async def test(self, candidate):
            await asyncio.Event().wait()

    async def allow_request():
        return True

    monkeypatch.setenv("MKCONFIG_TESTER_TOKEN", token)
    monkeypatch.setattr(service, "_allow_request", allow_request)
    monkeypatch.setattr(service, "is_tehran_test_window", lambda: True)
    monkeypatch.setattr(service, "MAX_TEST_EXECUTION_SECONDS", 0.01)
    monkeypatch.setattr(service.app.state, "runner", HangingRunner())
    with TestClient(service.app) as client:
        response = client.post(
            "/test",
            headers={"Authorization": f"Bearer {token}"},
            json=_request(uri),
        )
    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["latency_ms"] is None
    assert response.json()["error_code"] == "test_timeout"


def test_probe_rejects_reserved_hostname_even_when_allowlisted(monkeypatch):
    monkeypatch.setenv("MKCONFIG_TEST_URL", "https://metadata.google.internal/generate_204")
    monkeypatch.setenv("MKCONFIG_TEST_ALLOWED_HOSTS", "metadata.google.internal")
    with pytest.raises(RuntimeError, match="invalid_test_endpoint_configuration"):
        service._probe_settings()


def test_probe_dns_with_any_private_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(
        service.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(service.TesterError, match="unsafe_destination"):
        service._resolve_public_ip("probe.example", 443)


def test_bounded_dns_timeout_returns_failure_without_accepting_late_answer(
    monkeypatch,
):
    started = threading.Event()
    finish = threading.Event()

    def late_public_answer(host, port):
        started.set()
        finish.wait(timeout=2)
        return "8.8.8.8"

    monkeypatch.setattr(service, "_resolve_public_ip", late_public_answer)
    monkeypatch.setattr(service, "DNS_RESOLUTION_TIMEOUT_SECONDS", 0.01)

    async def resolve():
        with pytest.raises(service.TesterError, match="dns_timeout"):
            await service._resolve_public_ip_bounded("candidate.example", 443)

    try:
        asyncio.run(resolve())
        assert started.is_set()
    finally:
        finish.set()


def test_cancelled_dns_resolution_does_not_return_late_public_answer(monkeypatch):
    started = threading.Event()
    finish = threading.Event()

    def late_public_answer(host, port):
        started.set()
        finish.wait(timeout=2)
        return "8.8.8.8"

    monkeypatch.setattr(service, "_resolve_public_ip", late_public_answer)

    async def cancel_resolution():
        task = asyncio.create_task(
            service._resolve_public_ip_bounded("candidate.example", 443)
        )
        reached_resolver = await asyncio.get_running_loop().run_in_executor(
            None, started.wait, 1
        )
        assert reached_resolver
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(cancel_resolution())
    finally:
        finish.set()


def test_cancelling_curl_terminates_both_process_groups_and_removes_temp_config(
    monkeypatch,
):
    curl_started = asyncio.Event()
    terminated = []
    created_processes = {}
    config_paths = []

    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid
            self.returncode = None

        async def communicate(self):
            curl_started.set()
            await asyncio.Event().wait()

        async def wait(self):
            self.returncode = -15
            return self.returncode

    sing_box = FakeProcess(41001)
    curl = FakeProcess(41002)

    async def fake_create_subprocess_exec(*args, **kwargs):
        if "sing-box" in args:
            config_paths.append(Path(args[args.index("-c") + 1]))
            created_processes["sing-box"] = sing_box
            return sing_box
        created_processes["curl"] = curl
        return curl

    async def listener_ready(self, process, port):
        return True

    async def cancel_test():
        runner = service.SingBoxRunner()
        task = asyncio.create_task(
            runner.test("trojan://secret@edge.example:443?sni=edge.example")
        )
        await asyncio.wait_for(curl_started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    monkeypatch.setattr(
        service.SingBoxRunner, "available", property(lambda self: True)
    )
    monkeypatch.setattr(service, "_resolve_public_ip", lambda host, port: "8.8.8.8")
    monkeypatch.setattr(
        service,
        "_probe_settings",
        lambda: ("https://probe.example/", "probe.example", 443),
    )
    monkeypatch.setattr(
        service.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )
    monkeypatch.setattr(service.SingBoxRunner, "_wait_for_listener", listener_ready)
    monkeypatch.setattr(
        service.os, "killpg", lambda pid, sig: terminated.append((pid, sig))
    )

    asyncio.run(cancel_test())
    assert {pid for pid, _ in terminated} == {sing_box.pid, curl.pid}
    assert sing_box.returncode is not None
    assert curl.returncode is not None
    assert config_paths and not config_paths[0].exists()


def test_curl_timeout_terminates_process_groups_and_removes_temp_config(monkeypatch):
    terminated = []
    config_paths = []

    class FakeProcess:
        def __init__(self, pid, timeout=False):
            self.pid = pid
            self.returncode = None
            self.timeout = timeout

        async def communicate(self):
            if self.timeout:
                raise TimeoutError
            return b"", b""

        async def wait(self):
            self.returncode = -15
            return self.returncode

    sing_box = FakeProcess(42001)
    curl = FakeProcess(42002, timeout=True)

    async def fake_create_subprocess_exec(*args, **kwargs):
        if "sing-box" in args:
            config_paths.append(Path(args[args.index("-c") + 1]))
            return sing_box
        return curl

    async def listener_ready(self, process, port):
        return True

    monkeypatch.setattr(
        service.SingBoxRunner, "available", property(lambda self: True)
    )
    monkeypatch.setattr(service, "_resolve_public_ip", lambda host, port: "8.8.8.8")
    monkeypatch.setattr(
        service,
        "_probe_settings",
        lambda: ("https://probe.example/", "probe.example", 443),
    )
    monkeypatch.setattr(
        service.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )
    monkeypatch.setattr(service.SingBoxRunner, "_wait_for_listener", listener_ready)
    monkeypatch.setattr(
        service.os, "killpg", lambda pid, sig: terminated.append((pid, sig))
    )

    result = asyncio.run(
        service.SingBoxRunner().test(
            "trojan://secret@edge.example:443?sni=edge.example"
        )
    )
    assert result == (False, None, "probe_timeout", "trojan")
    assert {pid for pid, _ in terminated} == {sing_box.pid, curl.pid}
    assert sing_box.returncode is not None
    assert curl.returncode is not None
    assert config_paths and not config_paths[0].exists()


def test_process_group_termination_escalates_after_grace_timeout(monkeypatch):
    signals = []
    group_alive = True

    class SlowProcess:
        pid = 41003
        returncode = None
        waits = 0

        async def wait(self):
            self.waits += 1
            self.returncode = -9
            return self.returncode

    process = SlowProcess()

    def fake_killpg(pid, sig):
        nonlocal group_alive
        signals.append((pid, sig))
        if sig == 0 and not group_alive:
            raise ProcessLookupError
        if sig == 9:
            group_alive = False

    monkeypatch.setattr(service.os, "killpg", fake_killpg)
    monkeypatch.setattr(service, "PROCESS_TERMINATION_GRACE_SECONDS", 0.01)
    asyncio.run(service._terminate_process_group(process))
    assert signals[0] == (process.pid, 15)
    assert (process.pid, 0) in signals
    assert (process.pid, 9) in signals
    assert process.returncode == -9


def test_reaper_wait_timeout_does_not_hang_cleanup(monkeypatch):
    signals = []

    class UninterruptibleWait:
        pid = 41004
        returncode = None

        async def wait(self):
            await asyncio.Event().wait()

    process = UninterruptibleWait()

    def fake_killpg(pid, sig):
        signals.append((pid, sig))

    monkeypatch.setattr(service.os, "killpg", fake_killpg)
    monkeypatch.setattr(service, "PROCESS_TERMINATION_GRACE_SECONDS", 0.01)

    async def terminate():
        started = asyncio.get_running_loop().time()
        await service._terminate_process_group(process)
        return asyncio.get_running_loop().time() - started

    elapsed = asyncio.run(terminate())
    assert elapsed < 0.2
    assert (process.pid, 9) in signals