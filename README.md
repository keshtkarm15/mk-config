# MK.CONFIG

MK.CONFIG collects proxy configuration endpoints from explicitly configured HTTPS subscription sources, removes duplicates, and publishes only endpoints that pass a real HTTPS request through the authenticated sing-box tester. Collection, parsing, protocol testing, and publication are reported as separate stages.

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

The JSON report includes source, invalid, duplicate, tested, failed, and published counts. Publishing with `--output` requires `MKCONFIG_TESTER_URL` and `MKCONFIG_TESTER_TOKEN`. Missing credentials, source failures, tester failures, and malformed results preserve the prior output. The CLI tests up to five times the configured retention (hard maximum 200 candidates), at eight-second intervals, then publishes only verified successes up to the retention limit. Credentials, tester tokens, full URIs, and source URLs are not included in reports or logs.

The stable v2rayNG subscription is [subscription.txt](https://raw.githubusercontent.com/keshtkarm15/mk-config/main/docs/subscription.txt). It contains only standard Base64 encoding of validated VLESS, VMess, Trojan, and Shadowsocks URIs; other collector formats are omitted from this v2rayNG-specific file. Each displayed node name is prefixed with `MK.CONFIG | ` while its connection settings remain unchanged. The suggested subscription title when importing it is `MK.CONFIG | Config Subscription`; v2rayNG controls that title in the import UI, not in the Base64 file. It does not contain JSON reports or log text. Add that URL as a remote subscription in v2rayNG. Since usable proxy URIs inherently contain credentials, anyone with this public URL can use the published configurations. Do not add private feeds or publish configurations unless you are authorized to share them.

## Sources and safety

Only HTTPS sources without embedded credentials are accepted. Requests have bounded timeouts and response sizes, do not follow redirects, and use DNS resolution checks that reject non-public addresses. Configuration endpoints with literal private, loopback, link-local, reserved, or otherwise non-global IP addresses are rejected. Hostnames are not contacted during parsing.

The example source list enables the `ShadowsocksAggregator/Eternity.txt` and `Pawdroid/Free-servers/sub` public feeds. Public feed contents are untrusted and can change at any time. Only configure feeds you are authorized to use.

Public subscriptions may disappear or contain unsafe and untrusted configurations. Only add sources you are authorized to access. Do not connect to configurations just because they were collected. Keep private source URLs out of version control. The scheduled workflow uses only the reviewed public source list and does not require a repository secret. If a source fails or no valid configurations are collected, refresh fails without replacing the last published subscription.

See [docs/REAL_TESTING.md](docs/REAL_TESTING.md) for the tester architecture, supported protocol subset, security controls, local tests, and deployment handover.

## Automation

GitHub Actions runs tests on pushes and pull requests. Refresh runs at 07:00, 09:00, ..., 21:00 Asia/Tehran, equivalent to 03:30-17:30 UTC every two hours; manual dispatch remains available at any time, but the tester itself returns `untested` outside its Tehran window. The schedule uses `sources.example.json`, serializes runs, and commits only changed output. Configure repository variable `MKCONFIG_TESTER_URL` and secret `MKCONFIG_TESTER_TOKEN` before enabling tested publication. The manual retention limit defaults to 40.