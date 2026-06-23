"""Windows screenshot exclusion via SetWindowDisplayAffinity."""

from __future__ import annotations

import ctypes
import logging

logger = logging.getLogger(__name__)

user32 = ctypes.windll.user32

WDA_NONE = 0x0
WDA_EXCLUDEFROMCAPTURE = 0x11

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def exclude_hwnd(hwnd: int) -> bool:
    try:
        return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE))
    except Exception as e:
        logger.debug("SetWindowDisplayAffinity failed for %s: %s", hwnd, e)
        return False


def allow_hwnd(hwnd: int) -> bool:
    try:
        return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_NONE))
    except Exception:
        return False


def exclude_windows_for_pids(pids: set[int]) -> int:
    """Apply capture exclusion to visible top-level windows not owned by given PIDs."""
    if not pids:
        return 0
    protected = 0

    def callback(hwnd, _lparam):
        nonlocal protected
        if not user32.IsWindowVisible(hwnd):
            return True
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value not in pids:
            if exclude_hwnd(hwnd):
                protected += 1
        return True

    user32.EnumWindows(EnumWindowsProc(callback), 0)
    return protected
