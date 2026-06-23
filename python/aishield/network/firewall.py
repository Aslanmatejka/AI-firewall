"""Network firewall — monitor and control traffic to AI services."""

from __future__ import annotations

import logging
import socket
import subprocess
import threading
import time
from typing import Any, Callable

import psutil

from ..core.models import EventSeverity, NetworkConnection, PolicyAction, ResourceType
from ..core.events import EventBus
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)

try:
    from ..native.wfp_bridge import get_engine as get_wfp_engine
except ImportError:
    get_wfp_engine = None  # type: ignore[assignment]


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
        self._blocked_rules: set[str] = {}
        self._domain_to_ips: dict[str, set[str]] = {}
        self._wfp_blocked_ips: set[str] = set()
        self._use_wfp = bool(config.get("wfp_enabled", True))

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
        if get_wfp_engine is not None:
            try:
                get_wfp_engine().close()
            except Exception as e:
                logger.debug("WFP engine close: %s", e)

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
        if not addr or addr in ("*", "0.0.0.0", "::"):
            return ""
        ip = addr.split(":")[0] if ":" in addr and "." in addr else addr
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ip

    def _resolve_domain_ips(self, domain: str) -> set[str]:
        if domain in self._domain_to_ips:
            return self._domain_to_ips[domain]
        ips: set[str] = set()
        try:
            for info in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
                ips.add(info[4][0])
        except (socket.gaierror, OSError) as e:
            logger.debug("DNS lookup failed for %s: %s", domain, e)
        self._domain_to_ips[domain] = ips
        return ips

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
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                logger.info("Terminated process %d for blocked AI connection", conn.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._bus.emit(
            ResourceType.NETWORK, PolicyAction.BLOCK, conn.process_name,
            conn.remote_host,
            f"Blocked connection to {conn.remote_host}",
            EventSeverity.WARNING,
        )

    def _block_ip(self, ip: str, domain: str = "") -> bool:
        """Try WFP user-mode filter first, then netsh advfirewall."""
        if self._use_wfp and get_wfp_engine is not None:
            engine = get_wfp_engine()
            if engine.available:
                label = f"AiShield-WFP-{domain}-{ip}" if domain else None
                if engine.block_outbound_ip(ip, label=label):
                    self._wfp_blocked_ips.add(ip)
                    return True

        rule_name = f"AiShield-Block-{domain.replace('.', '-')}-{ip.replace('.', '-')}" if domain else f"AiShield-Block-{ip.replace('.', '-')}"
        if rule_name in self._blocked_rules:
            return True
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._blocked_rules.add(rule_name)
                logger.info("netsh firewall rule added for %s", ip)
                return True
            logger.warning("Failed to add firewall rule: %s", result.stderr.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("Cannot add firewall rule: %s", e)
        return False

    def _unblock_ip(self, ip: str, domain: str = "") -> bool:
        removed = False
        if ip in self._wfp_blocked_ips and get_wfp_engine is not None:
            if get_wfp_engine().unblock_outbound_ip(ip):
                self._wfp_blocked_ips.discard(ip)
                removed = True

        prefix = f"AiShield-Block-{domain.replace('.', '-')}-" if domain else f"AiShield-Block-{ip.replace('.', '-')}"
        for rule_name in list(self._blocked_rules):
            if domain and not rule_name.startswith(f"AiShield-Block-{domain.replace('.', '-')}-"):
                continue
            if not domain and ip not in rule_name:
                continue
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10,
                )
                self._blocked_rules.discard(rule_name)
                removed = True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        return removed

    def block_domain(self, domain: str) -> bool:
        """Block outbound traffic to a domain (WFP preferred, netsh fallback)."""
        ips = self._resolve_domain_ips(domain)
        if not ips:
            logger.warning("No IPs resolved for domain %s", domain)
            return False
        ok = False
        for ip in ips:
            if self._block_ip(ip, domain):
                ok = True
        return ok

    def unblock_domain(self, domain: str) -> bool:
        ips = self._domain_to_ips.get(domain, set())
        removed = 0
        if get_wfp_engine is not None and ips:
            removed += get_wfp_engine().unblock_domain_ips(domain, ips)
            self._wfp_blocked_ips -= ips

        prefix = f"AiShield-Block-{domain.replace('.', '-')}-"
        for rule_name in list(self._blocked_rules):
            if not rule_name.startswith(prefix):
                continue
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10,
                )
                self._blocked_rules.discard(rule_name)
                removed += 1
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        self._domain_to_ips.pop(domain, None)
        return removed > 0

    def get_stats(self) -> dict[str, int]:
        return {
            "ai_connections": len(self._connections),
            "blocked_rules": len(self._blocked_rules),
            "wfp_blocked_ips": len(self._wfp_blocked_ips),
            "total_seen": len(self._seen),
        }
