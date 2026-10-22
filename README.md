# MK.CONFIG

MK.CONFIG collects proxy configuration endpoints from explicitly configured HTTPS subscription sources, removes duplicates, and ranks records without claiming unmeasured health. It supports VLESS, VMess, Trojan, Shadowsocks, SOCKS, and HTTP proxy links.

The collector report contains only metadata: protocol, public endpoint host and port, an opaque stable identifier, and test status. Validated source URIs are held only in memory for subscription generation; credentials are excluded from reports and logs, but necessarily present in the public v2rayNG subscription. Treat published configurations as public operational data.

## Install and run

Requires Python 3.11 or newer.

```sh
python -m pip install .
cp sources.example.json sources.json
mkconfig refresh --sources sources.json
```

Edit `sources.json` to add sources you are authorized to use. Keep it out of version control. `--limit` overrides the `retention_limit` setting; both default to 40.

```sh
mkconfig refresh --sources sources.json --limit 20
```

The JSON report includes source status, last update time, parsed count, successful source count, safe error codes, and connection-test status. When `--output` is used, it also reports the published count and whether the previous output was preserved. Source failures do not expose their URLs or response bodies. Collection success only means the source was downloaded and parsed; all records remain `untested`, with `healthy: null` and `latency_ms: null`, until a real protocol tester reports a successful test.

The stable v2rayNG subscription is [subscription.txt](https://raw.githubusercontent.com/keshtkarm15/mk-config/main/docs/subscription.txt). It contains only standard Base64 encoding of validated VLESS, VMess, Trojan, and Shadowsocks URIs; other collector formats are omitted from this v2rayNG-specific file. It does not contain JSON reports or log text. Add that URL as a remote subscription in v2rayNG. Since usable proxy URIs inherently contain credentials, anyone with this public URL can use the published configurations. Do not add private feeds or publish configurations unless you are authorized to share them.

## Sources and safety

Only HTTPS sources without embedded credentials are accepted. Requests have bounded timeouts and response sizes, do not follow redirects, and use DNS resolution checks that reject non-public addresses. Configuration endpoints with literal private, loopback, link-local, reserved, or otherwise non-global IP addresses are rejected. Hostnames are not contacted during parsing.

The example source list enables the `ShadowsocksAggregator/Eternity.txt` and `Pawdroid/Free-servers/sub` public feeds. On 2026-10-22, both returned successful HTTPS responses through the actual collector and parsed 196 and 20 unique configurations respectively, with zero invalid lines. There were 214 unique configurations after cross-source deduplication; retention was 40 by default and 7 with a custom limit. The proposed `GO_V2rayCollector/mixed_iran.txt` feed was left disabled because the collector rejected its response with `response_too_large` under the default 1 MiB limit. These are point-in-time source and format checks, not proxy health tests.

Public subscriptions may disappear or contain unsafe and untrusted configurations. Only add sources you are authorized to access. Do not connect to configurations just because they were collected. Keep private source URLs out of version control. The scheduled workflow uses only the reviewed public source list and does not require a repository secret. If no valid configurations are collected, refresh fails without replacing the last published subscription; successful results from available feeds can still be published when another feed fails.

See [docs/REAL_TESTING.md](docs/REAL_TESTING.md) before integrating a protocol engine. There is no bundled engine; the default tester explicitly reports unavailable and does not attempt any proxy connection.

## Automation

GitHub Actions runs tests on pushes and pull requests. The refresh workflow runs every three hours and can also be started manually. It uses the public source list in `sources.example.json` and commits changes to `docs/subscription.txt`, making the raw GitHub URL a persistent subscription location rather than an ephemeral artifact. Its write permission is limited to repository contents. The manual run accepts a retention limit, defaulting to 40.