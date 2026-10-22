# Real protocol testing

MK.CONFIG does not ship a proxy engine and does not connect to collected endpoints. Every collected record is `untested`, with `healthy: null` and `latency_ms: null`. Downloading and parsing a subscription says nothing about proxy uptime or latency.

The `ProtocolTester` interface in `mkconfig.testing` is the integration boundary for a compatible engine such as sing-box. An adapter must report success only after the engine establishes the selected protocol connection and successfully completes an HTTPS request to a configured test target. It must measure elapsed time around that actual request, apply a strict connection and request timeout, cap concurrency, terminate the engine process, and return no latency on failure.

Before invoking any engine, the integration must:

- use only configurations explicitly selected by the operator;
- require the HTTPS test target to match an operator-maintained hostname allowlist;
- resolve and reject the test target if any address is private, loopback, link-local, reserved, or otherwise non-global immediately before connection;
- ensure the engine connects only to the validated configuration endpoint and the pinned/validated test target, with no redirects or ambient proxy settings;
- enforce process, memory, connection, and response limits, and never log credentials, full configuration URIs, or source URLs.

The included `validate_test_target` checks allowlisting and public DNS answers, but by itself is not a proxy engine and does not remove the need for an adapter to prevent DNS rebinding between validation and connection. No arbitrary target or untrusted configuration is contacted by the collector.