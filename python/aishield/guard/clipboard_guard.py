"""Clipboard protection — warn/block when AI processes may read clipboard."""

from __future__ import annotations

import ctypes
import logging
import re
import threading
import time
from typing import Any, Callable

from ..core.models import EventSeverity, PolicyAction, ResourceType
from ..core.events import EventBus
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)

user32 = ctypes.windll.user32
WM_CLIPBOARDUPDATE = 0x031D

SENSITIVE_PATTERNS = [
    re.compile(r"password", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"token", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
]


class ClipboardGuard:
    def __init__(
        self,
        config: dict[str, Any],
        event_bus: EventBus,
        is_ai_active: Callable[[], bool],
        get_ai_app: Callable[[], tuple[str, int]],
        policy_resolver: PolicyResolver,
        get_ai_pids: Callable[[], set[int]],
        is_ai_foreground: Callable[[], bool],
    ) -> None:
        self._config = config
        self._bus = event_bus
        self._is_ai_active = is_ai_active
        self._get_ai_app = get_ai_app
        self._resolver = policy_resolver
        self._get_ai_pids = get_ai_pids
        self._is_ai_foreground = is_ai_foreground
        self._policy = PolicyAction(config.get("clipboard_policy", "ask"))
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_content = ""
        self._hwnd: int | None = None

    def update_policy(self, value: str) -> None:
        try:
            self._policy = PolicyAction(value)
        except ValueError:
            pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_listener, daemon=True, name="ClipboardGuard")
        self._thread.start()
        logger.info("Clipboard guard started (policy=%s)", self._policy.value)

    def stop(self) -> None:
        self._running = False
        if self._hwnd:
            try:
                import win32gui
                if hasattr(win32gui, "RemoveClipboardFormatListener"):
                    win32gui.RemoveClipboardFormatListener(self._hwnd)
                win32gui.DestroyWindow(self._hwnd)
            except Exception:
                pass
            self._hwnd = None

    def _get_clipboard_text(self) -> str:
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT) or ""
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            pass
        return ""

    def _is_sensitive(self, text: str) -> bool:
        if len(text) > 500:
            return True
        return any(p.search(text) for p in SENSITIVE_PATTERNS)

    def _clear_clipboard(self) -> None:
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            pass

    def _should_guard(self) -> bool:
        return self._is_ai_active() and self._is_ai_foreground()

    def _handle_clipboard_change(self) -> None:
        if not self._running or not self._should_guard():
            return
        text = self._get_clipboard_text()
        if not text or text == self._last_content:
            return
        self._last_content = text
        if not self._is_sensitive(text):
            return

        app_name, app_pid = self._get_ai_app()
        preview = text[:40] + "..." if len(text) > 40 else text
        policy = self._resolver.for_access(app_name or "AI Process", ResourceType.CLIPBOARD, preview)
        decision = self._bus.request_approval(
            app_name or "AI Process", app_pid, ResourceType.CLIPBOARD, preview, policy,
        )
        if decision == PolicyAction.BLOCK:
            self._clear_clipboard()
            self._bus.emit(
                ResourceType.CLIPBOARD, PolicyAction.BLOCK,
                app_name or "AI", preview,
                "Blocked sensitive clipboard access",
                EventSeverity.CRITICAL,
            )

    def _run_listener(self) -> None:
        try:
            if not hasattr(user32, "AddClipboardFormatListener"):
                raise AttributeError("AddClipboardFormatListener not available")

            guard = self
            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)

            def wnd_proc(hwnd, msg, wp, lp):
                if msg == WM_CLIPBOARDUPDATE:
                    guard._handle_clipboard_change()
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wp, lp)

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", ctypes.c_uint),
                    ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                ]

            wc = WNDCLASSW()
            wc.hInstance = ctypes.c_void_p(user32.GetModuleHandleW(None))
            wc.lpszClassName = "AiShieldClipboardGuard"
            wc.lpfnWndProc = WNDPROC(wnd_proc)
            atom = user32.RegisterClassW(ctypes.byref(wc))
            if not atom:
                raise OSError("RegisterClassW failed")

            HWND_MESSAGE = -3
            self._hwnd = user32.CreateWindowExW(
                0, wc.lpszClassName, "AiShieldClip", 0, 0, 0, 0, 0,
                HWND_MESSAGE, None, wc.hInstance, None,
            )
            if not self._hwnd:
                raise OSError("CreateWindowExW failed")

            if not user32.AddClipboardFormatListener(self._hwnd):
                raise OSError("AddClipboardFormatListener failed")

            logger.info("Clipboard listener active (ctypes message-only window)")

            msg = ctypes.wintypes.MSG()
            while self._running:
                if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                else:
                    time.sleep(0.05)

        except ImportError:
            logger.warning("pywin32 not available — clipboard guard running in poll mode")
            self._poll_mode()
        except Exception as e:
            logger.warning("Clipboard listener unavailable (%s) — using poll mode", e)
            self._poll_mode()

    def _poll_mode(self) -> None:
        while self._running:
            if self._should_guard():
                self._handle_clipboard_change()
            time.sleep(1)
