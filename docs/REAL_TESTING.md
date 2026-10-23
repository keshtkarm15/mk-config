# Real Protocol Testing

The standalone service is `mkconfig.protocol_tester_service`, served by `mkconfig.tester_serve`. It tests a candidate only by starting the pinned sing-box process, opening a loopback-only SOCKS listener, and completing a real HTTPS request through that listener. The probe URL defaults to `https://www.gstatic.com/generate_204`; direct requests, successful parsing, DNS resolution, TCP reachability, or process startup alone never count as success.

The API accepts only `POST /test` with `Authorization: Bearer ...` and a JSON body containing exactly one field, `uri`. `/health` is unauthenticated and reports only whether sing-box and curl are installed. Responses include `success`, `latency_ms`, `tested_at`, `protocol`, `configuration_id`, and a token-keyed HMAC `candidate_id`; `error_code` is present on failure. The client checks protocol, endpoint identity, exact-candidate HMAC, timestamp, and latency before marking a result healthy. The HMAC binds the exact URI without logging or returning it.

Tests run from 07:00 up to (but not including) 22:00 in `Asia/Tehran`. The GitHub cron executes at 07:00, 09:00, ..., 21:00 local time. Manual workflow dispatch is permitted at other hours, but the service returns `outside_test_window`, no latency, and does not invoke sing-box.

## Supported Subset

Only the following are accepted by the service; the collector may parse more schemes than the tester can test:

- VLESS with valid UUID, TCP, WebSocket, or gRPC transport, TLS or no TLS, and optional `xtls-rprx-vision` flow only with TLS.
- VMess with valid UUID, alter ID 0-65535, TCP, WebSocket, or gRPC, TLS or no TLS, and the accepted `auto`, `aes-128-gcm`, `chacha20-poly1305`, or `zero` security values.
- Trojan with TLS and TCP, WebSocket, or gRPC.
- Shadowsocks with `aes-128-gcm`, `aes-256-gcm`, or `chacha20-ietf-poly1305`, without plugins.

Reality, other TLS modes, unsupported ciphers/flows/transports, Shadowsocks plugins, SOCKS, HTTP, and HTTPS proxy URIs are not tested and cannot be published as healthy by this service. Passing schema tests is not proof that a remote configuration works.

## Security Controls

- The token must contain at least 32 characters and is compared with constant-time comparison. `/test` rejects missing or invalid authentication.
- The request body is capped at 16 KiB; one URI is capped at 8 KiB. There are at most two concurrent tests and eight accepted tests per minute per process.
- The CLI tests at most five times the requested retention count, capped at 200 candidates, and starts at most one tester request every eight seconds. A free Render service may sleep between refresh windows, so cold-start and queue time can make a full candidate batch take longer.
- Only the configured HTTPS probe URL on an explicitly allowlisted hostname and port 443 is accepted. Redirects are disabled. The hostname is resolved and the public IP is pinned for curl with `--resolve`; TLS certificate verification remains enabled.
- The proxy endpoint is parsed by the existing safety parser, DNS-resolved immediately before testing, and pinned to a public address. Any non-global DNS result is rejected.
- sing-box and curl run as separate argument-vector subprocesses, never through a shell. They receive a minimal environment with no service token, use a private temporary directory and mode-0600 config, and are terminated on completion, timeout, or cancellation.
- Process CPU, number of processes, file descriptors, and file size are bounded with `prlimit`. sing-box receives `GOMEMLIMIT=192MiB` and `GOMAXPROCS=1`; Go needs address-space reservation, so `RLIMIT_AS` is deliberately not applied. The container/hosting plan provides the hard memory ceiling.
- Logs contain protocol and success/failure only. They exclude URIs, credentials, tokens, source URLs, and raw subprocess output.

The probe hostname and URL can be changed only by the service operator using `MKCONFIG_TEST_URL` and `MKCONFIG_TEST_ALLOWED_HOSTS`; the service rejects non-HTTPS URLs, non-443 ports, credentials, paths with query/fragment data, and hosts outside that list. Do not expose `/test` without authentication or accept a client-supplied destination.

## Local Development

The service dependencies are isolated from the collector's base install:

```sh
python -m pip install -r requirements-tester.txt
docker build -f Dockerfile.tester -t mkconfig-tester:local .
docker run --rm -p 10000:10000 \
	-e MKCONFIG_TESTER_TOKEN='<locally generated secret, 32+ characters>' \
	mkconfig-tester:local
```

Create a local token with `openssl rand -hex 32`. Do not put it in source control or paste it into logs/issues. Check `GET /health`; the actual `/test` route additionally needs an authorized, functioning proxy URI. `python -m pytest` runs unit and mocked API/client tests; those tests are not real connectivity evidence. The Docker build pins sing-box `v1.14.3` and verifies the official release asset SHA-256 before extraction.

## Render Deployment

`render.yaml` defines the separate service `mk-config-protocol-tester`, Dockerfile `Dockerfile.tester`, `/health` check, and free plan. To deploy, connect the repository to the authorized Render workspace, create the Blueprint from `render.yaml`, and enter `MKCONFIG_TESTER_TOKEN` in Render's secret prompt. Generate the secret in a trusted terminal with `openssl rand -hex 32`. Do not put its value in GitHub, the Blueprint, or this document. The service listens on Render's `PORT` and runs as non-root.

Render's free web services currently have 0.1 CPU and 512 MB RAM and spin down after 15 minutes without inbound traffic. Expect cold starts and limited test throughput; verify current plan terms before relying on it. No paid upgrade is configured or authorized by this change. A health check only confirms process/engine availability, not proxy connectivity.

After deployment, verify the returned Render HTTPS URL, `GET /health`, unauthenticated `POST /test` returning 401, and a permitted end-to-end candidate. Never claim real testing works based only on a healthy service or mocked tests.

## GitHub and Hatchable Configuration

Before a scheduled refresh can publish tested candidates, set repository variable `MKCONFIG_TESTER_URL` to the deployed HTTPS base URL and repository secret `MKCONFIG_TESTER_TOKEN` to the same secret entered in Render. The GitHub workflow passes them to the CLI without printing values. If either is missing, tester calls fail safely and the existing `docs/subscription.txt` remains unchanged.

The Hatchable application source named in the deployment request (`api/publish-subscription.js`, `api/test-configs`, `api/jobs/refresh-public-sources.js`, and `hatchable.toml`) is not present in this GitHub repository. The unauthenticated site redirects to Hatchable login. Consequently this change does not assert that Hatchable calls this service or that its own scheduler is configured. Its owner must update the application project to call `POST {protocol_tester_url}/test`, send the bearer token server-side, verify `success`, `configuration_id`, `candidate_id`, protocol, and finite latency, and preserve last-known-good output on any failure. Set the tester base URL and token only through the Hatchable server-side secrets/settings UI. Do not expose either in browser code.

The GitHub cron is UTC-based: `30 3-17/2 * * *` means 03:30 through 17:30 UTC every two hours, or 07:00 through 21:00 `Asia/Tehran` (UTC+03:30). The API independently enforces the test window. Do not enable a second independent publisher in Hatchable until its schedule and atomic publication behavior have been inspected; the Hatchable schedule cannot be verified from this repository.

## Rollback and Evidence

To roll back the tester, remove/rotate its secret in Render and disable the GitHub repository variable/secret; scheduled publication will fail closed and retain the previous subscription. Revert the reviewed Git commit to roll back code. Do not delete the last known-good subscription.

Verified locally on 2026-10-23: Python unit/mocked tests, Docker image build, sing-box schema checks for all four protocols, container health, unauthenticated 401, and invalid-URI failure response. No real proxy endpoint was supplied for an end-to-end test, no real latency was measured, no Render service was deployed, and no Hatchable secret/scheduler was configured. Update this evidence only after repeating those checks against the deployed service.