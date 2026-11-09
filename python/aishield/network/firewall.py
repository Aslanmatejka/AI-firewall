"""Network firewall — monitor and control traffic to AI services."""

from __future__ import annotations

import logging
import socket
import threading
import time
from functools import lru_cache
from typing import Any, Callable

import psutil

from ..core.models import EventSeverity, NetworkConnection, PolicyAction, ResourceType
from ..core.events import EventBus
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)

_MAX_SEEN_CONNECTIONS = 10_000
NETWORK_BLOCK_UNAVAILABLE = (
    "Network blocking is off until it can target one app. Blocking a domain's IP "
    "address also cuts off unrelated sites that share it."
)


@lru_cache(maxsize=2048)
def _reverse_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip


class NetworkFirewall:
    def __init__(
        self,
        config: dict[str, Any],
        event_bus: EventBus,
        policy_resolver: PolicyResolver,
        get_ai_type: Callable[[int], str],
    ) -> None:
        self._config = config
        self._bus = event_bus
        self._resolver = policy_resolver
        self._get_ai_type = get_ai_type
        self._domains = config.get("ai_domains", [])
        self._policy = PolicyAction(config.get("network_policy", "ask"))
        self._interval = config.get("monitor_interval_seconds", 2)
        self._running = False
        self._thread: threading.Thread | None = None
        self._connections: list[NetworkConnection] = []
        self._seen: set[str] = set()
        self._domain_cache: dict[str, bool] = {}

    @property
    def connections(self) -> list[NetworkConnection]:
        return list(self._connections)

    def update_policy(self, value: str) -> None:
        try:
            self._policy = PolicyAction(value)
        except ValueError:
            pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="NetworkFirewall")
        self._thread.start()
        logger.info("Network firewall started (policy=%s)", self._policy.value)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _is_ai_domain(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in self._domain_cache:
            return self._domain_cache[host]
        for domain in self._domains:
            if host == domain or host.endswith("." + domain):
                self._domain_cache[host] = True
                return True
        self._domain_cache[host] = False
        return False

    def _resolve_host(self, addr: str) -> str:
        if not addr or addr in ("*", "0.0.0.0", "::"):  # noqa: S104
            return ""
        ip = addr.split(":")[0] if ":" in addr and "." in addr else addr
        return _reverse_lookup(ip)

    def _loop(self) -> None:
        while self._running:
            try:
                self._scan_connections()
            except Exception as e:
                logger.error("Network scan error: %s", e)
            time.sleep(self._interval)

    def _scan_connections(self) -> None:
        ai_conns: list[NetworkConnection] = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                pname = proc.name() if proc else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"

            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            remote_addr = f"{remote_ip}:{remote_port}"
            remote_host = self._resolve_host(remote_ip)
            is_ai = self._is_ai_domain(remote_host) or self._is_ai_domain(remote_ip)

            nc = NetworkConnection(
                pid=conn.pid or 0,
                process_name=pname,
                local_addr=f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                remote_addr=remote_addr,
                remote_host=remote_host,
                status=conn.status,
                is_ai_traffic=is_ai,
            )
            if is_ai:
                ai_conns.append(nc)
                key = f"{conn.pid}:{remote_addr}"
                if key not in self._seen:
                    if len(self._seen) >= _MAX_SEEN_CONNECTIONS:
                        self._seen.clear()
                    self._seen.add(key)
                    self._handle_ai_connection(nc)

        self._connections = ai_conns

    def _handle_ai_connection(self, conn: NetworkConnection) -> None:
        app_name = self._get_ai_type(conn.pid) if conn.pid else conn.process_name
        policy = self._resolver.for_access(app_name, ResourceType.NETWORK, conn.remote_host)
        decision = self._bus.request_approval(
            app_name, conn.pid, ResourceType.NETWORK,
            f"{conn.remote_host} ({conn.remote_addr})", policy,
        )
        if decision == PolicyAction.BLOCK:
            self._block_connection(conn)

    def _block_connection(self, conn: NetworkConnection) -> None:
        self._bus.emit(
            ResourceType.NETWORK, PolicyAction.BLOCK, conn.process_name,
            conn.remote_host,
            f"Denied connection to {conn.remote_host}. The connection wasn't cut: "
            "per-app network blocking isn't available yet",
            EventSeverity.WARNING,
        )

    def get_stats(self) -> dict[str, int]:
        return {
            "ai_connections": len(self._connections),
            "total_seen": len(self._seen),
        }
