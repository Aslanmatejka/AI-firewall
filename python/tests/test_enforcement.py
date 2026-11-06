"""A denied prompt must never kill an app, and whatever gets recorded must be true."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psutil

from aishield.actions.shield_actions import ShieldActions
from aishield.core.events import EventBus
from aishield.core.models import AiProcess, NetworkConnection, PolicyAction, ProtectedFolder, ResourceType
from aishield.core.process_safety import PROTECTED_PROCESS_NAMES, stop_process
from aishield.detector.ai_detector import AiDetector
from aishield.guard import file_enforcer
from aishield.guard.device_enforcer import DeviceEnforcer
from aishield.guard.device_guard import DeviceGuard
from aishield.guard.file_enforcer import FileAccessEnforcer
from aishield.monitor.process_monitor import ProcessMonitor
from aishield.network.firewall import NETWORK_BLOCK_UNAVAILABLE, NetworkFirewall


def recording_bus() -> tuple[EventBus, list]:
    bus = EventBus(approval_timeout=0.01)
    events: list = []
    bus.subscribe(events.append)
    return bus, events


def child_process() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


class StopProcessTests(unittest.TestCase):
    def test_stops_an_ordinary_process(self) -> None:
        child = child_process()
        self.addCleanup(child.kill)
        result = stop_process(child.pid)
        self.assertTrue(result.stopped, result.reason)
        self.assertFalse(psutil.pid_exists(child.pid) and child.poll() is None)

    def test_refuses_browsers_shells_and_windows(self) -> None:
        for name in ("chrome.exe", "MSEDGE.EXE", "firefox.exe", "powershell.exe", "cmd.exe",
                     "explorer.exe", "lsass.exe", "svchost.exe"):
            fake = mock.Mock()
            fake.name.return_value = name
            with mock.patch.object(psutil, "Process", return_value=fake):
                result = stop_process(4242)
            self.assertFalse(result.stopped, name)
            fake.terminate.assert_not_called()

    def test_protected_names_are_lower_case(self) -> None:
        self.assertEqual(PROTECTED_PROCESS_NAMES, {n.lower() for n in PROTECTED_PROCESS_NAMES})

    def test_wont_stop_itself(self) -> None:
        self.assertFalse(stop_process(os.getpid()).stopped)

    def test_reports_failures_instead_of_success(self) -> None:
        fake = mock.Mock()
        fake.name.return_value = "app.exe"
        fake.terminate.side_effect = psutil.AccessDenied()
        with mock.patch.object(psutil, "Process", return_value=fake):
            result = stop_process(4242)
        self.assertFalse(result.stopped)
        self.assertIn("Access denied", result.reason)


class TerminateActionTests(unittest.TestCase):
    def test_only_a_detected_ai_process_can_be_stopped(self) -> None:
        child = child_process()
        self.addCleanup(child.kill)
        bus, _ = recording_bus()
        service = SimpleNamespace(
            _process_monitor=SimpleNamespace(get_ai_pids=lambda: {1234}), event_bus=bus,
        )
        result = ShieldActions(service).terminate_process(child.pid)
        self.assertFalse(result["ok"])
        self.assertIsNone(child.poll(), "the process must still be running")


class FileEnforcerTests(unittest.TestCase):
    def enforcer(self, policy: PolicyAction, decision: PolicyAction, tmp_file: str):
        bus = mock.Mock()
        bus.request_approval.return_value = decision
        folder = ProtectedFolder("Secret", str(Path(tmp_file).parent), policy)
        resolver = mock.Mock()
        resolver.for_access.return_value = policy
        enforcer = FileAccessEnforcer([folder], bus, lambda: {99}, lambda _pid: "AI", resolver)
        proc = mock.Mock()
        proc.open_files.return_value = [SimpleNamespace(path=tmp_file)]
        return enforcer, bus, proc

    def test_denied_prompt_doesnt_stop_the_app(self) -> None:
        enforcer, bus, proc = self.enforcer(PolicyAction.ASK, PolicyAction.BLOCK, "C:\\Secret\\a.txt")
        with mock.patch.object(file_enforcer.psutil, "Process", return_value=proc), \
                mock.patch.object(file_enforcer, "stop_process") as stop:
            enforcer._scan_open_files()
        stop.assert_not_called()
        self.assertIn("kept running", bus.emit.call_args.args[4])

    def test_explicit_block_stops_the_app_and_says_so(self) -> None:
        enforcer, bus, proc = self.enforcer(PolicyAction.BLOCK, PolicyAction.BLOCK, "C:\\Secret\\a.txt")
        result = SimpleNamespace(stopped=True, name="ai.exe", reason="")
        with mock.patch.object(file_enforcer.psutil, "Process", return_value=proc), \
                mock.patch.object(file_enforcer, "stop_process", return_value=result) as stop:
            enforcer._scan_open_files()
        stop.assert_called_once_with(99)
        self.assertIn("Stopped ai.exe", bus.emit.call_args.args[4])

    def test_failed_stop_isnt_reported_as_blocked(self) -> None:
        enforcer, bus, proc = self.enforcer(PolicyAction.BLOCK, PolicyAction.BLOCK, "C:\\Secret\\a.txt")
        result = SimpleNamespace(stopped=False, name="ai.exe", reason="Access denied")
        with mock.patch.object(file_enforcer.psutil, "Process", return_value=proc), \
                mock.patch.object(file_enforcer, "stop_process", return_value=result):
            enforcer._scan_open_files()
        self.assertIn("Could not stop", bus.emit.call_args.args[4])


class NetworkTests(unittest.TestCase):
    def firewall(self):
        bus, events = recording_bus()
        return NetworkFirewall({"ai_domains": ["openai.com"]}, bus, mock.Mock(), lambda _p: "AI"), events

    def test_denied_connection_kills_nothing_and_says_it_wasnt_cut(self) -> None:
        firewall, events = self.firewall()
        conn = NetworkConnection(7, "chrome.exe", "", "1.2.3.4:443", "api.openai.com", "ESTABLISHED", True)
        with mock.patch.object(psutil, "Process") as process:
            firewall._block_connection(conn)
        process.assert_not_called()
        self.assertIn("wasn't cut", events[-1].message)

    def test_seen_connections_stay_bounded(self) -> None:
        import aishield.network.firewall as module

        firewall, _ = self.firewall()
        firewall._handle_ai_connection = mock.Mock()
        firewall._seen = {str(i) for i in range(module._MAX_SEEN_CONNECTIONS)}
        conn = SimpleNamespace(
            status="ESTABLISHED", pid=0,
            raddr=SimpleNamespace(ip="1.2.3.4", port=443),
            laddr=SimpleNamespace(ip="10.0.0.1", port=5),
        )
        with mock.patch.object(module.psutil, "net_connections", return_value=[conn]), \
                mock.patch.object(module, "_reverse_lookup", return_value="api.openai.com"):
            firewall._scan_connections()
        self.assertEqual(len(firewall._seen), 1)

    def test_domain_blocking_says_why_it_is_off(self) -> None:
        actions = ShieldActions(SimpleNamespace())
        for result in (actions.block_domain("openai.com"), actions.block_all_ai_domains(),
                       actions.unblock_domain("openai.com")):
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], NETWORK_BLOCK_UNAVAILABLE)


class DeviceTests(unittest.TestCase):
    def test_block_policy_on_app_start_kills_nothing(self) -> None:
        bus, events = recording_bus()
        resolver = mock.Mock()
        resolver.for_access.return_value = PolicyAction.BLOCK
        guard = DeviceGuard({}, bus, resolver)
        with mock.patch.object(psutil, "Process") as process:
            guard.on_ai_processes_changed([AiProcess(5, "ai.exe", "", "AI", 90)])
        process.assert_not_called()
        self.assertTrue(events)
        self.assertTrue(all("Not enforced" in e.message for e in events))

    def test_denied_device_kills_nothing(self) -> None:
        bus, events = recording_bus()
        resolver = mock.Mock()
        resolver.for_access.return_value = PolicyAction.ASK
        enforcer = DeviceEnforcer({}, bus, lambda: {5}, lambda _p: "AI", resolver)
        with mock.patch.object(psutil, "Process") as process:
            enforcer._enforce(5, ResourceType.MICROPHONE, "Microphone")
        process.assert_not_called()
        self.assertIn("Not enforced", events[-1].message)

    def test_in_use_means_started_after_last_stop(self) -> None:
        self.assertTrue(DeviceEnforcer._in_use(200, 100))
        self.assertTrue(DeviceEnforcer._in_use(200, 0))
        self.assertFalse(DeviceEnforcer._in_use(100, 200))
        self.assertFalse(DeviceEnforcer._in_use(0, 0))


class UnknownProcessTests(unittest.TestCase):
    def test_fail_closed_reports_but_doesnt_kill(self) -> None:
        bus, events = recording_bus()
        detector = mock.Mock()
        detector.match_process.return_value = ("", 0)
        detector.enrich_with_gpu.side_effect = lambda procs: procs
        detector.detect_unknown_ai.return_value = [AiProcess(5, "unknown", "", "Unknown AI Model", 60)]
        monitor = ProcessMonitor({"fail_closed": True}, bus, detector)
        with mock.patch.object(psutil, "process_iter", return_value=[]),                 mock.patch.object(psutil, "Process") as process:
            monitor._scan()
        process.assert_not_called()
        self.assertIn("Unknown AI model", events[-1].message)


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = AiDetector({
            "ml_heuristics_enabled": False,
            "ai_process_signatures": [
                {"name": "Claude", "patterns": ["claude"]},
                {"name": "Continue", "patterns": ["continue"]},
                {"name": "Cursor", "patterns": ["cursor.exe"]},
            ],
        })

    def test_folder_names_dont_make_a_program_an_ai(self) -> None:
        for name, exe in (
            ("notepad.exe", r"C:\Users\me\.claude\notepad.exe"),
            ("backup.exe", r"C:\Tools\continue\backup.exe"),
        ):
            self.assertEqual(self.detector.match_process(name, exe), ("", 0), exe)

    def test_real_programs_are_still_detected(self) -> None:
        self.assertEqual(self.detector.match_process("claude.exe", r"C:\Apps\claude.exe")[0], "Claude")
        self.assertEqual(self.detector.match_process("Cursor.exe", r"C:\Apps\Cursor.exe")[0], "Cursor")

    def test_ram_is_never_reported_as_gpu_memory(self) -> None:
        with mock.patch.object(self.detector, "_gpu_from_nvidia_smi", return_value={}):
            self.assertEqual(self.detector.get_gpu_usage(), {})
        self.assertFalse(hasattr(self.detector, "_gpu_from_wmi"))


if __name__ == "__main__":
    unittest.main()
