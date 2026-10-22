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

The JSON report is written to standard output. It includes source status, refresh time, configuration counts, safe error codes, and the explicit tester availability status. Source failures do not expose their URLs or response bodies. Collection success only means the source was downloaded and parsed; all records remain `untested` with no latency until a real protocol tester reports a successful test.

## Sources and safety

Only HTTPS sources without embedded credentials are accepted. Requests have bounded timeouts and response sizes, do not follow redirects, and use DNS resolution checks that reject non-public addresses. Configuration endpoints with literal private, loopback, link-local, reserved, or otherwise non-global IP addresses are rejected. Hostnames are not contacted during parsing.

Public subscriptions may disappear or contain unsafe and untrusted configurations. Only add sources you are authorized to access. Do not connect to configurations just because they were collected. No private subscription URLs, tokens, or credentials belong in the repository. `sources.example.json` is intentionally empty.

See [docs/REAL_TESTING.md](docs/REAL_TESTING.md) before integrating a protocol engine. There is no bundled engine; the default tester explicitly reports unavailable and does not attempt any proxy connection.

## Automation

GitHub Actions runs tests on pushes and pull requests. The refresh workflow runs every three hours and can also be started manually. To provide private source configuration, add the JSON contents as the repository Actions secret `MKCONFIG_SOURCES_JSON`; the workflow uses it only in an ignored, temporary `sources.json`. Refresh output is not committed or uploaded. The manual run accepts a retention limit, defaulting to 40.