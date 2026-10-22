# MK.CONFIG

MK.CONFIG collects proxy configuration endpoints from explicitly configured HTTPS subscription sources, removes duplicates, and ranks records without claiming unmeasured health. It supports VLESS, VMess, Trojan, Shadowsocks, SOCKS, and HTTP proxy links.

The collector stores metadata only: protocol, public endpoint host and port, an opaque stable identifier, and test status. It never stores proxy credentials or source URLs in the generated report. The report can still reveal endpoint metadata, so treat generated files as operational data and do not publish them without review.

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

The JSON report is written to standard output; refresh does not persist or replace a cache. It includes source status, refresh time, configuration counts, safe error codes, and the explicit tester availability status. Source failures do not expose their URLs or response bodies. Collection success only means the source was downloaded and parsed; all records remain `untested` with no latency until a real protocol tester reports a successful test.

## Sources and safety

Only HTTPS sources without embedded credentials are accepted. Requests have bounded timeouts and response sizes, do not follow redirects, and use DNS resolution checks that reject non-public addresses. Configuration endpoints with literal private, loopback, link-local, reserved, or otherwise non-global IP addresses are rejected. Hostnames are not contacted during parsing.

The example source list enables the `ShadowsocksAggregator/Eternity.txt` and `Pawdroid/Free-servers/sub` public feeds. On 2026-10-22, both returned successful HTTPS responses through the actual collector and parsed 196 and 20 unique configurations respectively, with zero invalid lines. There were 214 unique configurations after cross-source deduplication; retention was 40 by default and 7 with a custom limit. The proposed `GO_V2rayCollector/mixed_iran.txt` feed was left disabled because the collector rejected its response with `response_too_large` under the default 1 MiB limit. These are point-in-time source and format checks, not proxy health tests.

Public subscriptions may disappear or contain unsafe and untrusted configurations. Only add sources you are authorized to access. Do not connect to configurations just because they were collected. Keep private URLs and credentials in ignored local `sources.json`; never commit them. The scheduled workflow uses only the reviewed public source list and does not require a repository secret.

See [docs/REAL_TESTING.md](docs/REAL_TESTING.md) before integrating a protocol engine. There is no bundled engine; the default tester explicitly reports unavailable and does not attempt any proxy connection.

## Automation

GitHub Actions runs tests on pushes and pull requests. The refresh workflow runs every three hours and can also be started manually. It uses the public source list in `sources.example.json`, with read-only permissions; refresh output is not committed or uploaded. The manual run accepts a retention limit, defaulting to 40.