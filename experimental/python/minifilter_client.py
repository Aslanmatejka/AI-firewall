"""User-mode client for AI Firewall minifilter communication port."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import struct
import threading
from ctypes import wintypes
from typing import Any, Callable

logger = logging.getLogger(__name__)

PORT_NAME = r"\\AiShieldMinifilterPort"
MAGIC = 0x48534641
VERSION = 1

CMD_SYNC_POLICY = 1
CMD_PING = 2
CMD_FILE_QUERY = 3
CMD_FILE_RESPONSE = 4
CMD_POLICY_ACK = 5

POLICY_MAP = {"allow": 0, "block": 1, "ask": 2}
DECISION_MAP = {"allow": 0, "block": 1, "ask": 2}

MAX_PATH = 520
MAX_FOLDERS = 32
MAX_AI_PROCS = 64
MAX_APP_NAME = 64

HEADER_FMT = "<IIII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

S_OK = 0
HRESULT = wintypes.LONG


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", wintypes.ULONG),
        ("MessageId", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
    ]


FileQueryHandler = Callable[[dict[str, Any]], str]


class MinifilterClient:
    """Connects to the minifilter driver and syncs policy + handles file queries."""

    def __init__(self, on_file_query: FileQueryHandler | None = None) -> None:
        self._on_file_query = on_file_query
        self._handle: wintypes.HANDLE | None = None
        self._running = False
        self._listener: threading.Thread | None = None
        self._dll: Any = None
        if os.name == "nt":
            try:
                self._dll = ctypes.windll.fltlib
            except OSError:
                pass

    @property
    def connected(self) -> bool:
        return self._handle is not None

    def connect(self) -> bool:
        if not self._dll or self._handle:
            return self._handle is not None

        port = wintypes.HANDLE()
        hr = self._dll.FilterConnectCommunicationPort(
            PORT_NAME, 0, None, 0, None, ctypes.byref(port),
        )
        if hr != S_OK:
            logger.debug("Minifilter not loaded (FilterConnectCommunicationPort: 0x%08X)", hr & 0xFFFFFFFF)
            return False

        self._handle = port
        self._running = True
        self._listener = threading.Thread(
            target=self._listen_loop, daemon=True, name="MinifilterListener",
        )
        self._listener.start()
        logger.info("Connected to minifilter communication port")
        return True

    def close(self) -> None:
        self._running = False
        if self._handle and self._dll:
            self._dll.FilterClose(self._handle)
            self._handle = None
        if self._listener:
            self._listener.join(timeout=2)
            self._listener = None

    @staticmethod
    def _pack_message(command: int, payload: dict[str, Any] | None = None) -> bytes:
        body = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
        header = struct.pack(HEADER_FMT, MAGIC, VERSION, command, len(body))
        return header + body

    @staticmethod
    def _unpack_message(data: bytes) -> tuple[int, dict[str, Any]] | None:
        if len(data) < HEADER_SIZE:
            return None
        magic, ver, cmd, plen = struct.unpack_from(HEADER_FMT, data, 0)
        if magic != MAGIC or ver != VERSION:
            return None
        if len(data) < HEADER_SIZE + plen:
            return None
        payload = json.loads(data[HEADER_SIZE:HEADER_SIZE + plen].decode("utf-8"))
        return cmd, payload

    def send_message(self, command: int, payload: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if not self._handle or not self._dll:
            return None
        msg = self._pack_message(command, payload)
        out_buf = ctypes.create_string_buffer(65536)
        bytes_returned = wintypes.DWORD(0)
        hr = self._dll.FilterSendMessage(
            self._handle,
            msg, len(msg),
            out_buf, len(out_buf),
            ctypes.byref(bytes_returned),
        )
        if hr != S_OK:
            logger.debug("FilterSendMessage failed: 0x%08X", hr & 0xFFFFFFFF)
            return None
        if bytes_returned.value == 0:
            return {"ok": True}
        parsed = self._unpack_message(out_buf.raw[: bytes_returned.value])
        if parsed:
            cmd, payload = parsed
            if cmd == CMD_POLICY_ACK:
                return {"ok": True, **payload}
            return payload
        return {"ok": True}

    def ping(self) -> bool:
        resp = self.send_message(CMD_PING, {"ping": True})
        return resp is not None and resp.get("ok", False)

    @staticmethod
    def _pack_sync_binary(
        folders: list[dict[str, str]],
        ai_processes: list[dict[str, Any]],
        global_policy: str,
    ) -> bytes:
        global_pol = POLICY_MAP.get(global_policy, 2)
        folder_count = min(len(folders), MAX_FOLDERS)
        ai_count = min(len(ai_processes), MAX_AI_PROCS)

        body = struct.pack("<III", global_pol, folder_count, ai_count)
        for i in range(MAX_FOLDERS):
            if i < folder_count:
                path = folders[i].get("path", "")[: MAX_PATH - 1]
                pol = POLICY_MAP.get(folders[i].get("policy", "ask"), 2)
            else:
                path, pol = "", 0
            path_utf16 = path.encode("utf-16-le").ljust(MAX_PATH * 2, b"\x00")[: MAX_PATH * 2]
            body += path_utf16 + struct.pack("<I", pol)

        for i in range(MAX_AI_PROCS):
            if i < ai_count:
                pid = int(ai_processes[i].get("pid", 0))
                name = ai_processes[i].get("ai_type") or ai_processes[i].get("name", "")[: MAX_APP_NAME - 1]
            else:
                pid, name = 0, ""
            name_utf16 = name.encode("utf-16-le").ljust(MAX_APP_NAME * 2, b"\x00")[: MAX_APP_NAME * 2]
            body += struct.pack("<I", pid) + name_utf16

        header = struct.pack(HEADER_FMT, MAGIC, VERSION, CMD_SYNC_POLICY, len(body))
        return header + body

    def send_binary(self, data: bytes) -> bool:
        if not self._handle or not self._dll:
            return False
        out_buf = ctypes.create_string_buffer(256)
        bytes_returned = wintypes.DWORD(0)
        hr = self._dll.FilterSendMessage(
            self._handle, data, len(data),
            out_buf, len(out_buf), ctypes.byref(bytes_returned),
        )
        return hr == S_OK

    def sync_policy(
        self,
        folders: list[dict[str, str]],
        ai_processes: list[dict[str, Any]],
        global_policy: str = "ask",
    ) -> bool:
        payload = self._pack_sync_binary(folders, ai_processes, global_policy)
        return self.send_binary(payload)

    @staticmethod
    def _parse_file_query(raw: bytes) -> dict[str, Any] | None:
        if len(raw) < HEADER_SIZE:
            return None
        magic, ver, cmd, plen = struct.unpack_from(HEADER_FMT, raw, 0)
        if magic != MAGIC or cmd != CMD_FILE_QUERY:
            return None
        offset = HEADER_SIZE
        if len(raw) < offset + 8:
            return None
        query_id, pid = struct.unpack_from("<II", raw, offset)
        offset += 8
        app_bytes = raw[offset:offset + MAX_APP_NAME * 2]
        offset += MAX_APP_NAME * 2
        path_bytes = raw[offset:offset + MAX_PATH * 2]
        app_name = app_bytes.decode("utf-16-le").split("\x00", 1)[0]
        path = path_bytes.decode("utf-16-le").split("\x00", 1)[0]
        return {"query_id": query_id, "pid": pid, "app_name": app_name, "path": path}

    def _listen_loop(self) -> None:
        if not self._handle or not self._dll:
            return

        buf_size = 65536
        while self._running and self._handle:
            msg_buf = (ctypes.c_byte * buf_size)()
            header = FILTER_MESSAGE_HEADER.from_buffer(msg_buf)
            hr = self._dll.FilterGetMessage(
                self._handle,
                ctypes.byref(header),
                buf_size,
                None,
            )
            if hr != S_OK:
                if self._running:
                    logger.debug("FilterGetMessage: 0x%08X", hr & 0xFFFFFFFF)
                break

            raw = bytes(msg_buf)[ctypes.sizeof(FILTER_MESSAGE_HEADER):]
            payload = self._parse_file_query(raw)
            if payload is None:
                parsed = self._unpack_message(raw)
                if parsed and parsed[0] == CMD_FILE_QUERY:
                    payload = parsed[1]
            if not payload or not self._on_file_query:
                continue

            decision = self._on_file_query(payload)
            dec_val = DECISION_MAP.get(decision, 1)
            query_id = int(payload.get("query_id", 0))
            reply_body = struct.pack("<II", query_id, dec_val)
            reply_payload = struct.pack(HEADER_FMT, MAGIC, VERSION, CMD_FILE_RESPONSE, len(reply_body)) + reply_body

            reply = FILTER_MESSAGE_HEADER()
            reply.ReplyLength = len(reply_payload)
            reply_buf = (ctypes.c_byte * (ctypes.sizeof(FILTER_MESSAGE_HEADER) + len(reply_payload)))()
            ctypes.memmove(reply_buf, ctypes.byref(reply), ctypes.sizeof(FILTER_MESSAGE_HEADER))
            ctypes.memmove(
                ctypes.byref(reply_buf, ctypes.sizeof(FILTER_MESSAGE_HEADER)),
                reply_payload, len(reply_payload),
            )
            self._dll.FilterReplyMessage(
                self._handle,
                ctypes.byref(reply_buf),
                ctypes.sizeof(FILTER_MESSAGE_HEADER) + len(reply_payload),
            )


_client: MinifilterClient | None = None


def get_client(on_file_query: FileQueryHandler | None = None) -> MinifilterClient:
    global _client
    if _client is None:
        _client = MinifilterClient(on_file_query=on_file_query)
    elif on_file_query and _client._on_file_query is None:
        _client._on_file_query = on_file_query
    return _client
