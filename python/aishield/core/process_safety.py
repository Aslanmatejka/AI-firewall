"""The one place that decides whether AI Firewall may stop a process."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import psutil

logger = logging.getLogger(__name__)

# Stopping any of these takes down far more than an AI feature: Windows itself,
# every open browser tab, or whatever the user was running in a terminal.
PROTECTED_PROCESS_NAMES = frozenset({
    # Windows
    "csrss.exe", "ctfmon.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe",
    "lsass.exe", "registry", "runtimebroker.exe", "searchhost.exe", "services.exe",
    "sihost.exe", "smss.exe", "spoolsv.exe", "startmenuexperiencehost.exe", "svchost.exe",
    "system", "system idle process", "taskhostw.exe", "textinputhost.exe", "wininit.exe",
    "winlogon.exe",
    # Browsers
    "arc.exe", "brave.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
    "msedgewebview2.exe", "opera.exe", "vivaldi.exe",
    # Shells and terminals
    "bash.exe", "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
    "windowsterminal.exe", "wsl.exe", "wslhost.exe", "wt.exe",
})


@dataclass(frozen=True)
class StopResult:
    stopped: bool
    name: str = ""
    reason: str = ""


def stop_process(pid: int) -> StopResult:
    """Terminate a process unless it's protected, and report what really happened."""
    if pid == os.getpid():
        return StopResult(False, "AI Firewall", "AI Firewall won't stop itself")
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        if name.lower() in PROTECTED_PROCESS_NAMES:
            return StopResult(False, name, f"{name} is protected and won't be stopped")
        proc.terminate()
        proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        return StopResult(False, "", "Process not found")
    except psutil.AccessDenied:
        return StopResult(False, "", "Access denied: run as administrator")
    except psutil.TimeoutExpired:
        return StopResult(False, name, f"{name} didn't exit in time")
    logger.warning("Stopped process %s (PID %d)", name, pid)
    return StopResult(True, name)
