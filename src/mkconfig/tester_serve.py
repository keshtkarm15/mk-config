"""Run the protocol tester on the port provided by the hosting platform."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    port = int(os.getenv("PORT", "10000"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    uvicorn.run("mkconfig.protocol_tester_service:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()