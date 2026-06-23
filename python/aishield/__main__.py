"""AI Firewall entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sys

import uvicorn

from .service import AiShieldService
from .dashboard.server import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Firewall — AI access control for your PC")
    parser.add_argument("--host", default=None, help="Dashboard host")
    parser.add_argument("--port", type=int, default=None, help="Dashboard port")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    service = AiShieldService()
    host = args.host or service.config.get("dashboard_host", "127.0.0.1")
    port = args.port or service.config.get("dashboard_port", 9470)

    if host not in ("127.0.0.1", "localhost", "::1"):
        logging.warning(
            "Dashboard bound to %s — API has no authentication; use localhost for production",
            host,
        )

    service.start()
    app = create_app(service)

    def shutdown(sig, frame):
        logging.info("Shutting down AI Firewall...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"\n  AI Firewall is running")
    print(f"  Dashboard: http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
