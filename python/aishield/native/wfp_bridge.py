"""Windows Filtering Platform user-mode bridge (fwpuclnt.dll).

Adds outbound block filters at FWPM_LAYER_ALE_AUTH_CONNECT_V4.
Falls back gracefully when not admin or WFP unavailable.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import socket
import struct
import threading
import uuid
from ctypes import wintypes
from typing import Any

logger = logging.getLogger(__name__)

ERROR_SUCCESS = 0
RPC_C_AUTHN_WINNT = 10
FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
FWP_ACTION_BLOCK = 0x00001001
FWP_UINT32 = 3
FWP_V4_ADDR_MASK = 19

# {c86fd1bf-21cd-437e-a4e3-2446f109aeec}
LAYER_ALE_AUTH_CONNECT_V4 = uuid.UUID("{c86fd1bf-21cd-437e-a4e3-2446f109aeec}")
# {890bb49e-f540-4452-b1ff-503a59647e99}
CONDITION_IP_REMOTE_ADDRESS = uuid.UUID("{890bb49e-f540-4452-b1ff-503a59647e99}")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

    @classmethod
    def from_uuid(cls, value: uuid.UUID) -> GUID:
        b = value.bytes_le
        data4 = (wintypes.BYTE * 8)(*b[8:])
        return cls(
            struct.unpack("<I", b[0:4])[0],
            struct.unpack("<H", b[4:6])[0],
            struct.unpack("<H", b[6:8])[0],
            data4,
        )


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]


class FWP_CONDITION_VALUE0(ctypes.Structure):
    class _Union(ctypes.Union):
        _fields_ = [("v4AddrMask", ctypes.POINTER(FWP_V4_ADDR_AND_MASK))]

    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.c_uint32), ("u", _Union)]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [
        ("fieldKey", GUID),
        ("matchType", ctypes.c_uint32),
        ("conditionValue", FWP_CONDITION_VALUE0),
    ]


class FWP_VALUE0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32)]


class FWPM_ACTION0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("filterType", GUID)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", wintypes.LPCWSTR), ("description", wintypes.LPCWSTR)]


class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [
        ("sessionKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32),
        ("txnWaitTimeoutInMSec", ctypes.c_uint32),
        ("processId", wintypes.DWORD),
        ("sid", ctypes.c_void_p),
        ("username", wintypes.LPCWSTR),
        ("kernelMode", wintypes.BOOL),
    ]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.POINTER(GUID)),
        ("providerData", ctypes.c_void_p),
        ("layerKey", GUID),
        ("subLayerKey", GUID),
        ("weight", FWP_VALUE0),
        ("numFilterConditions", ctypes.c_uint32),
        ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
        ("action", FWPM_ACTION0),
        ("providerContextKey", ctypes.POINTER(GUID)),
        ("reserved", ctypes.c_void_p),
        ("filterId", ctypes.c_uint64),
        ("effectiveWeight", FWP_VALUE0),
    ]


class WfpEngine:
    """Dynamic WFP session — filters auto-removed when process exits."""

    FWP_MATCH_EQUAL = 0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handle: wintypes.HANDLE | None = None
        self._filter_ids: dict[str, int] = {}
        self._dll: Any = None
        self._available = os.name == "nt"
        if self._available:
            try:
                self._dll = ctypes.windll.fwpuclnt
            except OSError:
                self._available = False

    @property
    def available(self) -> bool:
        return self._available and self._dll is not None

    def _open(self) -> bool:
        if not self.available:
            return False
        if self._handle:
            return True
        engine = wintypes.HANDLE()
        session = FWPM_SESSION0()
        session.flags = FWPM_SESSION_FLAG_DYNAMIC
        rc = self._dll.FwpmEngineOpen0(
            None, RPC_C_AUTHN_WINNT, None, ctypes.byref(session), ctypes.byref(engine),
        )
        if rc != ERROR_SUCCESS:
            logger.debug("FwpmEngineOpen0 failed: %d", rc)
            return False
        self._handle = engine
        return True

    def close(self) -> None:
        if self._handle and self._dll:
            self._dll.FwpmEngineClose0(self._handle)
            self._handle = None
        self._filter_ids.clear()

    @staticmethod
    def _ip_to_uint32(ip: str) -> int | None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                return None
            return struct.unpack("!I", socket.inet_aton(str(addr)))[0]
        except ValueError:
            return None

    def block_outbound_ip(self, ip: str, label: str | None = None) -> bool:
        """Block outbound connections to a remote IPv4 address."""
        if ip in self._filter_ids:
            return True
        ip_int = self._ip_to_uint32(ip)
        if ip_int is None:
            return False

        with self._lock:
            if not self._open():
                return False

            name = label or f"AiShield-WFP-{ip.replace('.', '-')}"
            desc = f"AI Firewall outbound block for {ip}"

            addr_mask = FWP_V4_ADDR_AND_MASK(ip_int, 0xFFFFFFFF)
            cond_value = FWP_CONDITION_VALUE0()
            cond_value.type = FWP_V4_ADDR_MASK
            cond_value.v4AddrMask = ctypes.pointer(addr_mask)
            condition = FWPM_FILTER_CONDITION0(
                GUID.from_uuid(CONDITION_IP_REMOTE_ADDRESS),
                self.FWP_MATCH_EQUAL,
                cond_value,
            )

            action = FWPM_ACTION0(FWP_ACTION_BLOCK, GUID())
            display = FWPM_DISPLAY_DATA0(name, desc)
            weight = FWP_VALUE0(0)  # FWP_EMPTY
            filt = FWPM_FILTER0()
            filt.displayData = display
            filt.layerKey = GUID.from_uuid(LAYER_ALE_AUTH_CONNECT_V4)
            filt.weight = weight
            filt.action = action
            filt.numFilterConditions = 1
            filt.filterCondition = ctypes.pointer(condition)

            filter_id = ctypes.c_uint64(0)
            rc = self._dll.FwpmFilterAdd0(
                self._handle, ctypes.byref(filt), None, ctypes.byref(filter_id),
            )
            if rc != ERROR_SUCCESS:
                logger.debug("FwpmFilterAdd0 failed for %s: %d", ip, rc)
                return False

            self._filter_ids[ip] = int(filter_id.value)
            logger.info("WFP block filter added for %s (id=%s)", ip, filter_id.value)
            return True

    def unblock_outbound_ip(self, ip: str) -> bool:
        with self._lock:
            filter_id = self._filter_ids.pop(ip, None)
            if filter_id is None or not self._handle or not self._dll:
                return False
            rc = self._dll.FwpmFilterDeleteById0(self._handle, ctypes.c_uint64(filter_id))
            if rc != ERROR_SUCCESS:
                logger.debug("FwpmFilterDeleteById0 failed for %s: %d", ip, rc)
                return False
            logger.info("WFP block filter removed for %s", ip)
            return True

    def block_domain_ips(self, domain: str, ips: set[str]) -> bool:
        ok = False
        for ip in ips:
            if self.block_outbound_ip(ip, label=f"AiShield-WFP-{domain}-{ip}"):
                ok = True
        return ok

    def unblock_domain_ips(self, domain: str, ips: set[str]) -> int:
        removed = 0
        for ip in ips:
            if self.unblock_outbound_ip(ip):
                removed += 1
        return removed


_engine: WfpEngine | None = None


def get_engine() -> WfpEngine:
    global _engine
    if _engine is None:
        _engine = WfpEngine()
    return _engine


def block_outbound_ip(ip: str) -> bool:
    return get_engine().block_outbound_ip(ip)


def unblock_outbound_ip(ip: str) -> bool:
    return get_engine().unblock_outbound_ip(ip)


def try_native_rust_block(ip: str) -> bool:
    """Optional: load aishield_native.dll if built."""
    try:
        from pathlib import Path
        dll_paths = [
            Path(__file__).resolve().parents[3] / "native" / "aishield-native" / "target" / "release" / "aishield_native.dll",
            Path(__file__).resolve().parents[3] / "native" / "aishield-native" / "target" / "debug" / "aishield_native.dll",
        ]
        for path in dll_paths:
            if not path.exists():
                continue
            lib = ctypes.CDLL(str(path))
            lib.aishield_wfp_block_ip.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            lib.aishield_wfp_block_ip.restype = ctypes.c_bool
            return bool(lib.aishield_wfp_block_ip(ip.encode(), len(ip)))
    except Exception as e:
        logger.debug("Rust WFP DLL unavailable: %s", e)
    return False
