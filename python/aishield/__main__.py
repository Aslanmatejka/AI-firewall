"""AI Firewall entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import sys
import webbrowser

import uvicorn

from .dashboard.security import LOOPBACK_HOSTS, ApiSecurity, api_token_path
from .dashboard.server import create_app
from .service import AiShieldService


def _port_in_use(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except OSError:
        return False


def _exit_cleanly(_signum: int, _frame: object) -> None:
    raise SystemExit(0)


def main() -> int:
    parser = argparse.ArgumentParser(description="AI Firewall: AI access control for your PC")
    parser.add_argument("--host", default=None, help="Dashboard host (this PC only)")
    parser.add_argument("--port", type=int, default=None, help="Dashboard port")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING"])
    parser.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    service = AiShieldService()
    host = args.host or service.config.get("dashboard_host", "127.0.0.1")
    port = args.port or service.config.get("dashboard_port", 9470)

    if host not in LOOPBACK_HOSTS:
        logging.error("Refusing to listen on %s: the dashboard is only for this PC", host)
        return 2
    if _port_in_use(host, port):
        logging.error("Port %d is already in use. Is AI Firewall already running?", port)
        return 3

    security = ApiSecurity(port)
    token_path = api_token_path()
    security.write_token_file(token_path)
    app = create_app(service, security)
    sign_in_url = security.new_login_url()

    # After shutting down, uvicorn re-raises the signal it caught. The default
    # handler would then end the process here, before the cleanup below can run.
    signal.signal(signal.SIGTERM, _exit_cleanly)
    signal.signal(signal.SIGBREAK, _exit_cleanly)

    service.start()
    try:
        print("\n  AI Firewall is running")
        print(f"  Sign in (link works once, for 2 minutes): {sign_in_url}")
        print("  New link: .\\scripts\\open-dashboard.ps1")
        print("  Press Ctrl+C to stop\n")
        if args.open:
            webbrowser.open(sign_in_url)
        uvicorn.run(app, host=host, port=port, log_level="warning")
    finally:
        logging.info("Shutting down AI Firewall...")
        service.stop()
        token_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
