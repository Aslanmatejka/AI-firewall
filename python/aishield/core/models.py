"""Shared data models and event types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


class ResourceType(str, Enum):
    FILE = "file"
    NETWORK = "network"
    CLIPBOARD = "clipboard"
    SCREENSHOT = "screenshot"
    MICROPHONE = "microphone"
    CAMERA = "camera"
    PROCESS = "process"


class EventSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AiProcess:
    pid: int
    name: str
    exe: str
    ai_type: str
    confidence: int
    gpu_mb: float = 0.0
    detected_at: datetime = field(default_factory=datetime.now)


@dataclass
class ShieldEvent:
    id: str
    timestamp: datetime
    severity: EventSeverity
    resource_type: ResourceType
    action: PolicyAction
    source_app: str
    resource: str
    message: str
    user_decision: str | None = None


@dataclass
class AccessRequest:
    id: str
    timestamp: datetime
    app_name: str
    app_pid: int
    resource_type: ResourceType
    resource_path: str
    policy: PolicyAction
    resolved: bool = False
    decision: PolicyAction | None = None


@dataclass
class NetworkConnection:
    pid: int
    process_name: str
    local_addr: str
    remote_addr: str
    remote_host: str
    status: str
    is_ai_traffic: bool = False


@dataclass
class ProtectedFolder:
    name: str
    path: str
    policy: PolicyAction


@dataclass
class ShieldStatus:
    running: bool
    ai_processes: list[AiProcess]
    active_connections: list[NetworkConnection]
    pending_requests: list[AccessRequest]
    recent_events: list[ShieldEvent]
    protected_folders: list[ProtectedFolder]
    stats: dict[str, Any] = field(default_factory=dict)
