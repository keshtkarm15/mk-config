"""Authenticated, bounded sing-box protocol test API."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import ipaddress
import json
import logging
import math
import os
import shutil
import socket
import tempfile
import time
import uuid as uuid_module
import weakref
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from fastapi import FastAPI, Header, HTTPException, Request

from .core import is_reserved_hostname, parse_configuration
from .testing import is_tehran_test_window

logger = logging.getLogger("mkconfig.tester")
MAX_REQUEST_BYTES = 16_384
MAX_URI_BYTES = 8_192
MAX_TESTS_PER_MINUTE = 8
MAX_CONCURRENT_TESTS = 2
REQUEST_ID_TTL_SECONDS = 120
PROXY_START_TIMEOUT_SECONDS = 3
PROBE_TIMEOUT_SECONDS = 12
MAX_TEST_EXECUTION_SECONDS = 18
DNS_RESOLUTION_TIMEOUT_SECONDS = 4
PROCESS_TERMINATION_GRACE_SECONDS = 1
SUPPORTED_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "ss"})
SUPPORTED_TRANSPORTS = frozenset({"tcp", "ws", "grpc"})
SUPPORTED_SS_METHODS = frozenset(
    {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
)

_test_slots = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
_rate_lock = asyncio.Lock()
_request_times: deque[float] = deque()
_request_id_lock = asyncio.Lock()
_used_request_ids: dict[str, float] = {}
_dns_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mkconfig-dns")
_dns_slots_by_loop: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, asyncio.Semaphore
] = weakref.WeakKeyDictionary()
_pending_reap_tasks: set[asyncio.Task[int]] = set()


class TesterError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _one(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key, [])
    if len(values) > 1:
        raise TesterError("invalid_configuration")
    value = values[0] if values else default
    if len(value) > 4_096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TesterError("invalid_configuration")
    return value


def _decode_base64(value: str) -> bytes:
    compact = "".join(value.split())
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise TesterError("invalid_configuration") from error


def _candidate_id(uri: str, request_id: str, token: str) -> str:
    message = b"candidate\0" + request_id.encode("ascii") + b"\0" + uri.encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, "sha256").hexdigest()


def _response_signature(
    payload: dict[str, object], uri: str, token: str
) -> str:
    message = json.dumps(
        {"uri": uri, **payload}, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, "sha256").hexdigest()


def _signed_result(
    payload: dict[str, object], uri: str, request_id: str, token: str
) -> dict[str, object]:
    response = {
        **payload,
        "request_id": request_id,
        "candidate_id": _candidate_id(uri, request_id, token),
    }
    response["response_signature"] = _response_signature(response, uri, token)
    return response


def _tls_options(host: str, enabled: bool, server_name: str = "") -> dict[str, object]:
    if not enabled:
        return {"enabled": False}
    name = unquote(server_name) if server_name else host
    if len(name) > 253 or any(ord(char) < 33 or ord(char) == 127 for char in name):
        raise TesterError("invalid_configuration")
    return {
        "enabled": True,
        "server_name": name,
    }


def _transport_options(
    transport: str, query: dict[str, list[str]], vmess: dict[str, object] | None = None
) -> dict[str, object] | None:
    if transport not in SUPPORTED_TRANSPORTS:
        raise TesterError("unsupported_transport")
    if transport == "tcp":
        return None
    if transport == "ws":
        path = _one(query, "path")
        host = _one(query, "host")
        if vmess is not None:
            path = str(vmess.get("path", path))
            host = str(vmess.get("host", host))
        if any(
            len(value) > 4_096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in (path, host)
        ):
            raise TesterError("invalid_configuration")
        result: dict[str, object] = {"type": "ws", "path": path or "/"}
        if host:
            result["headers"] = {"Host": host}
        return result
    service_name = _one(query, "serviceName")
    if vmess is not None:
        service_name = str(vmess.get("serviceName", service_name))
    if len(service_name) > 4_096 or any(
        ord(char) < 32 or ord(char) == 127 for char in service_name
    ):
        raise TesterError("invalid_configuration")
    return {"type": "grpc", "service_name": service_name}


def _parse_vmess(uri: str) -> dict[str, object]:
    data = json.loads(_decode_base64(uri.removeprefix("vmess://")))
    if not isinstance(data, dict):
        raise TesterError("invalid_configuration")
    required = ("add", "port", "id")
    if any(not data.get(key) for key in required):
        raise TesterError("invalid_configuration")
    if str(data.get("tls", "")).lower() not in {
        "",
        "tls",
        "true",
        "false",
        "none",
    }:
        raise TesterError("unsupported_tls_mode")
    security = str(data.get("scy", "auto"))
    if security not in {"auto", "aes-128-gcm", "chacha20-poly1305", "zero"}:
        raise TesterError("unsupported_cipher")
    try:
        alter_id = int(data.get("aid", 0))
    except (TypeError, ValueError) as error:
        raise TesterError("invalid_configuration") from error
    if not 0 <= alter_id <= 65535:
        raise TesterError("invalid_configuration")
    return data


def _decode_ss_credentials(uri: str) -> tuple[str, str, str, int]:
    parsed = urlsplit(uri)
    if parsed.query:
        raise TesterError("unsupported_shadowsocks_plugin")
    host = parsed.hostname or ""
    try:
        port = parsed.port or 0
    except ValueError as error:
        raise TesterError("invalid_configuration") from error
    if parsed.username is not None and parsed.password is not None and host:
        method = unquote(parsed.username)
        password = unquote(parsed.password)
    elif parsed.username is not None and host:
        decoded = _decode_base64(parsed.username).decode("utf-8", errors="strict")
        if ":" not in decoded:
            raise TesterError("invalid_configuration")
        method, password = decoded.split(":", 1)
    else:
        payload = uri.removeprefix("ss://").split("#", 1)[0]
        decoded = _decode_base64(payload).decode("utf-8", errors="strict")
        credentials, separator, endpoint = decoded.rpartition("@")
        if not separator or ":" not in credentials:
            raise TesterError("invalid_configuration")
        method, password = credentials.split(":", 1)
        endpoint_uri = urlsplit(f"ss://{endpoint}")
        host = endpoint_uri.hostname or ""
        try:
            port = endpoint_uri.port or 0
        except ValueError as error:
            raise TesterError("invalid_configuration") from error
    if method not in SUPPORTED_SS_METHODS or not password:
        raise TesterError("unsupported_cipher")
    return method, password, host, port


def build_outbound(uri: str, server_ip: str) -> dict[str, object]:
    """Build the narrow sing-box outbound subset accepted by this service."""
    try:
        configuration = parse_configuration(uri)
        if configuration.protocol not in SUPPORTED_PROTOCOLS:
            raise TesterError("unsupported_protocol")
        parsed = urlsplit(uri)
        query = parse_qs(parsed.query, keep_blank_values=True)
        host = configuration.host
        common: dict[str, object] = {
            "tag": "proxy",
            "server": server_ip,
            "server_port": configuration.port,
        }

        if configuration.protocol == "vless":
            uuid = unquote(parsed.username or "")
            if not uuid:
                raise TesterError("invalid_configuration")
            try:
                uuid_module.UUID(uuid)
            except ValueError as error:
                raise TesterError("invalid_configuration") from error
            security = _one(query, "security", "none")
            if security not in {"none", "tls"}:
                raise TesterError("unsupported_tls_mode")
            transport = _one(query, "type", "tcp")
            outbound = {
                **common,
                "type": "vless",
                "uuid": uuid,
                "tls": _tls_options(host, security == "tls", _one(query, "sni")),
            }
            flow = _one(query, "flow")
            if flow:
                if flow != "xtls-rprx-vision" or security != "tls":
                    raise TesterError("unsupported_flow")
                outbound["flow"] = flow
            transport_options = _transport_options(transport, query)
        elif configuration.protocol == "vmess":
            data = _parse_vmess(uri)
            try:
                if int(data["port"]) != configuration.port or str(data["add"]).lower() != host:
                    raise TesterError("invalid_configuration")
                uuid = str(data["id"])
                alter_id = int(data.get("aid", 0))
                uuid_module.UUID(uuid)
            except (KeyError, TypeError, ValueError) as error:
                raise TesterError("invalid_configuration") from error
            security = str(data.get("tls", "")).lower() in {"tls", "true"}
            transport = str(data.get("net", "tcp"))
            outbound = {
                **common,
                "type": "vmess",
                "uuid": uuid,
                "alter_id": alter_id,
                "security": str(data.get("scy", "auto")),
                "tls": _tls_options(host, security, str(data.get("sni", ""))),
            }
            transport_options = _transport_options(transport, query, data)
        elif configuration.protocol == "trojan":
            password = unquote(parsed.username or "")
            security = _one(query, "security", "tls")
            if not password:
                raise TesterError("invalid_configuration")
            if security != "tls":
                raise TesterError("unsupported_tls_mode")
            transport = _one(query, "type", "tcp")
            outbound = {
                **common,
                "type": "trojan",
                "password": password,
                "tls": _tls_options(host, True, _one(query, "sni")),
            }
            transport_options = _transport_options(transport, query)
        else:
            method, password, ss_host, ss_port = _decode_ss_credentials(uri)
            if ss_host.lower() != host or ss_port != configuration.port:
                raise TesterError("invalid_configuration")
            outbound = {
                **common,
                "type": "shadowsocks",
                "method": method,
                "password": password,
            }
            transport_options = None

        if transport_options is not None:
            outbound["transport"] = transport_options
        return outbound
    except TesterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError) as error:
        raise TesterError("invalid_configuration") from error


def _resolve_public_ip(host: str, port: int) -> str:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise TesterError("dns_failure") from error
        addresses = [ipaddress.ip_address(result[4][0]) for result in results]
    if not addresses or any(not address.is_global for address in addresses):
        raise TesterError("unsafe_destination")
    return addresses[0].compressed


async def _resolve_public_ip_bounded(host: str, port: int) -> str:
    loop = asyncio.get_running_loop()
    slots = _dns_slots_by_loop.get(loop)
    if slots is None:
        slots = asyncio.Semaphore(2)
        _dns_slots_by_loop[loop] = slots
    await slots.acquire()
    future = loop.run_in_executor(_dns_executor, _resolve_public_ip, host, port)
    defer_slot_release = False
    try:
        return await asyncio.wait_for(
            asyncio.shield(future), timeout=DNS_RESOLUTION_TIMEOUT_SECONDS
        )
    except TimeoutError as error:
        defer_slot_release = True
        raise TesterError("dns_timeout") from error
    except asyncio.CancelledError:
        defer_slot_release = True
        raise
    finally:
        if defer_slot_release:
            future.add_done_callback(
                lambda _: loop.call_soon_threadsafe(slots.release)
            )
        else:
            slots.release()


def _probe_settings() -> tuple[str, str, int]:
    url = os.getenv("MKCONFIG_TEST_URL", "https://www.gstatic.com/generate_204")
    allowed = {
        value.strip().lower()
        for value in os.getenv("MKCONFIG_TEST_ALLOWED_HOSTS", "www.gstatic.com").split(",")
        if value.strip()
    }
    parsed = urlsplit(url)
    host = (parsed.hostname or "").rstrip(".").lower()
    port = parsed.port or 443
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or port != 443
        or host not in allowed
        or is_reserved_hostname(host)
    ):
        raise RuntimeError("invalid_test_endpoint_configuration")
    return url, host, port


async def _allow_request() -> bool:
    now = time.monotonic()
    async with _rate_lock:
        while _request_times and now - _request_times[0] >= 60:
            _request_times.popleft()
        if len(_request_times) >= MAX_TESTS_PER_MINUTE:
            return False
        _request_times.append(now)
        return True


async def _claim_request_id(request_id: str) -> bool:
    now = time.monotonic()
    async with _request_id_lock:
        expired = [
            key
            for key, claimed_at in _used_request_ids.items()
            if now - claimed_at >= REQUEST_ID_TTL_SECONDS
        ]
        for key in expired:
            del _used_request_ids[key]
        if request_id in _used_request_ids:
            return False
        _used_request_ids[request_id] = now
        return True


async def _read_request_body(request: Request) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="request_too_large")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="invalid_request") from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="request_too_large")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=400, detail="invalid_request") from error
    if (
        not isinstance(data, dict)
        or set(data) != {"uri", "request_id"}
        or not isinstance(data["uri"], str)
        or not isinstance(data["request_id"], str)
    ):
        raise HTTPException(status_code=400, detail="invalid_request")
    try:
        request_id = str(uuid_module.UUID(data["request_id"]))
    except ValueError as error:
        raise HTTPException(status_code=400, detail="invalid_request") from error
    if request_id != data["request_id"]:
        raise HTTPException(status_code=400, detail="invalid_request")
    try:
        uri_size = len(data["uri"].encode("utf-8"))
    except UnicodeEncodeError as error:
        raise HTTPException(status_code=400, detail="invalid_request") from error
    if not data["uri"] or uri_size > MAX_URI_BYTES:
        raise HTTPException(status_code=413, detail="request_too_large")
    data["request_id"] = request_id
    return data


async def _terminate_process_group(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(process.pid, 15)
    except ProcessLookupError:
        await _reap_process_bounded(process)
        return

    deadline = time.monotonic() + PROCESS_TERMINATION_GRACE_SECONDS
    group_exited = False
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            group_exited = True
            break
        await asyncio.sleep(0.02)
    if not group_exited:
        try:
            os.killpg(process.pid, 9)
        except ProcessLookupError:
            pass
    await _reap_process_bounded(process)


async def _reap_process_bounded(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    wait_task = asyncio.create_task(process.wait())
    try:
        await asyncio.wait_for(
            asyncio.shield(wait_task), timeout=PROCESS_TERMINATION_GRACE_SECONDS
        )
    except TimeoutError:
        _pending_reap_tasks.add(wait_task)
        wait_task.add_done_callback(_pending_reap_tasks.discard)


class SingBoxRunner:
    def __init__(
        self, binary: str = "sing-box", curl: str = "curl", prlimit: str = "prlimit"
    ):
        self.binary = binary
        self.curl = curl
        self.prlimit = prlimit

    @property
    def available(self) -> bool:
        return bool(
            shutil.which(self.binary)
            and shutil.which(self.curl)
            and shutil.which(self.prlimit)
        )

    async def test(self, uri: str) -> tuple[bool, float | None, str | None, str]:
        configuration = parse_configuration(uri)
        if configuration.protocol not in SUPPORTED_PROTOCOLS:
            return False, None, "unsupported_protocol", configuration.protocol
        proxy_ip = await _resolve_public_ip_bounded(
            configuration.host, configuration.port
        )
        outbound = build_outbound(uri, proxy_ip)
        probe_url, probe_host, probe_port = _probe_settings()
        probe_ip = await _resolve_public_ip_bounded(probe_host, probe_port)
        if not self.available:
            return False, None, "engine_unavailable", configuration.protocol

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            local_port = listener.getsockname()[1]
        sing_box_config = {
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "local",
                    "listen": "127.0.0.1",
                    "listen_port": local_port,
                }
            ],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": "proxy"},
        }
        with tempfile.TemporaryDirectory(prefix="mkconfig-test-") as directory:
            os.chmod(directory, 0o700)
            child_env = {
                "PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": directory,
                "TMPDIR": directory,
                "LANG": "C.UTF-8",
                "GOMEMLIMIT": "192MiB",
                "GOMAXPROCS": "1",
            }
            config_path = Path(directory) / "config.json"
            descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
                json.dump(sing_box_config, config_file)
            process = await asyncio.create_subprocess_exec(
                self.prlimit,
                "--cpu=15",
                "--nproc=16",
                "--nofile=64",
                "--fsize=4096",
                "--",
                self.binary,
                "run",
                "-c",
                str(config_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=child_env,
                start_new_session=True,
            )
            try:
                ready = await self._wait_for_listener(process, local_port)
                if not ready:
                    return False, None, "engine_start_failed", configuration.protocol
                ip = ipaddress.ip_address(probe_ip)
                curl_ip = f"[{probe_ip}]" if ip.version == 6 else probe_ip
                started = time.monotonic()
                try:
                    result = await asyncio.wait_for(
                        asyncio.create_subprocess_exec(
                            self.prlimit,
                            "--cpu=15",
                            "--nproc=8",
                            "--nofile=64",
                            "--fsize=4096",
                            "--",
                            self.curl,
                            "--proxy",
                            f"socks5://127.0.0.1:{local_port}",
                            "--connect-timeout",
                            "4",
                            "--max-time",
                            str(PROBE_TIMEOUT_SECONDS),
                            "--max-filesize",
                            "1024",
                            "--max-redirs",
                            "0",
                            "--proto",
                            "=https",
                            "--silent",
                            "--output",
                            "/dev/null",
                            "--write-out",
                            "%{http_code}",
                            "--resolve",
                            f"{probe_host}:{probe_port}:{curl_ip}",
                            probe_url,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                            env=child_env,
                            start_new_session=True,
                        ),
                        timeout=PROBE_TIMEOUT_SECONDS + 1,
                    )
                    stdout, _ = await asyncio.wait_for(
                        result.communicate(), timeout=PROBE_TIMEOUT_SECONDS + 1
                    )
                except TimeoutError:
                    return False, None, "probe_timeout", configuration.protocol
                finally:
                    if "result" in locals() and result.returncode is None:
                        await _terminate_process_group(result)
                if result.returncode != 0:
                    return False, None, "probe_failed", configuration.protocol
                try:
                    status = int(stdout.decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    return False, None, "probe_failed", configuration.protocol
                if not 200 <= status < 300:
                    return False, None, "probe_http_error", configuration.protocol
                latency_ms = (time.monotonic() - started) * 1000
                return True, latency_ms, None, configuration.protocol
            finally:
                if process.returncode is None:
                    await _terminate_process_group(process)

    async def _wait_for_listener(self, process: asyncio.subprocess.Process, port: int) -> bool:
        deadline = time.monotonic() + PROXY_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.returncode is not None:
                return False
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=0.1
                )
            except (OSError, TimeoutError):
                await asyncio.sleep(0.05)
            else:
                writer.close()
                await writer.wait_closed()
                return True
        return False


@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(os.getenv("MKCONFIG_TESTER_TOKEN", "")) < 32:
        raise RuntimeError("MKCONFIG_TESTER_TOKEN must contain at least 32 characters")
    _probe_settings()
    yield


app = FastAPI(
    title="MK.CONFIG protocol tester",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.state.runner = SingBoxRunner()


@app.get("/health")
async def health() -> dict[str, object]:
    available = app.state.runner.available
    return {"status": "ok" if available else "degraded", "engine_available": available}


@app.post("/test")
async def test_configuration(
    request: Request, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    expected = os.getenv("MKCONFIG_TESTER_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if len(expected) < 32 or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="unauthorized")
    if not await _allow_request():
        raise HTTPException(status_code=429, detail="rate_limited")
    data = await _read_request_body(request)
    tested_at = datetime.now(UTC).isoformat()
    uri = data["uri"]
    request_id = data["request_id"]
    if not await _claim_request_id(request_id):
        raise HTTPException(status_code=409, detail="request_replayed")
    try:
        configuration = parse_configuration(uri)
    except ValueError:
        return _signed_result(
            {
                "success": False,
                "latency_ms": None,
                "tested_at": tested_at,
                "protocol": "unknown",
                "error_code": "invalid_configuration",
            },
            uri,
            request_id,
            expected,
        )
    if configuration.protocol not in SUPPORTED_PROTOCOLS:
        return _signed_result(
            {
                "success": False,
                "latency_ms": None,
                "tested_at": tested_at,
                "protocol": configuration.protocol,
                "configuration_id": configuration.id,
                "error_code": "unsupported_protocol",
            },
            uri,
            request_id,
            expected,
        )
    if not is_tehran_test_window():
        return _signed_result(
            {
                "success": False,
                "latency_ms": None,
                "tested_at": tested_at,
                "protocol": configuration.protocol,
                "configuration_id": configuration.id,
                "error_code": "outside_test_window",
            },
            uri,
            request_id,
            expected,
        )
    if _test_slots.locked():
        raise HTTPException(status_code=429, detail="tester_busy")
    try:
        await asyncio.wait_for(_test_slots.acquire(), timeout=0.1)
    except TimeoutError as error:
        raise HTTPException(status_code=429, detail="tester_busy") from error
    try:
        success, latency_ms, error_code, protocol = await asyncio.wait_for(
            app.state.runner.test(uri), timeout=MAX_TEST_EXECUTION_SECONDS
        )
    except TimeoutError:
        success, latency_ms, error_code, protocol = (
            False,
            None,
            "test_timeout",
            configuration.protocol,
        )
    except TesterError as error:
        success, latency_ms, error_code, protocol = (
            False,
            None,
            error.code,
            configuration.protocol,
        )
    except Exception:
        logger.warning(
            "protocol test failed: protocol=%s error=internal_error",
            configuration.protocol,
        )
        success, latency_ms, error_code, protocol = (
            False,
            None,
            "internal_error",
            configuration.protocol,
        )
    finally:
        _test_slots.release()
    if (
        not isinstance(success, bool)
        or protocol != configuration.protocol
        or (
            success
            and (
                isinstance(latency_ms, bool)
                or not isinstance(latency_ms, (int, float))
                or not math.isfinite(latency_ms)
                or latency_ms < 0
                or error_code is not None
            )
        )
        or (
            not success
            and (
                latency_ms is not None
                or not isinstance(error_code, str)
                or not error_code
            )
        )
    ):
        success, latency_ms, error_code, protocol = (
            False,
            None,
            "invalid_test_result",
            configuration.protocol,
        )
    tested_at = datetime.now(UTC).isoformat()
    logger.info(
        "protocol test complete: protocol=%s success=%s",
        protocol,
        success,
    )
    return _signed_result(
        {
            "success": success,
            "latency_ms": latency_ms,
            "tested_at": tested_at,
            "protocol": protocol,
            "configuration_id": configuration.id,
            "error_code": error_code,
        },
        uri,
        request_id,
        expected,
    )
