#!/usr/bin/env python3
"""Standalone enterprise policy server for AI Firewall."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def load_policy(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "version": 1,
        "global_policy": "ask",
        "network_policy": "ask",
        "clipboard_policy": "ask",
        "microphone_policy": "ask",
        "camera_policy": "ask",
        "fail_closed": False,
        "app_policies": {},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Firewall enterprise policy server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9480)
    parser.add_argument("--policy", default="config/enterprise-policy.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = root / policy_path

    policy = load_policy(policy_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path not in ("/", "/policy", "/policy.json"):
                self.send_error(404)
                return
            body = json.dumps(policy, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            print(f"[policy-server] {self.address_string()} {fmt % args}")

    print(f"Enterprise policy server: http://{args.host}:{args.port}/policy.json")
    HTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
