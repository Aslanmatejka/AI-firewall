"""Detect AI software via process signatures, GPU usage, and model files."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from ..core.models import AiProcess
from .ml_heuristics import MlHeuristics


class AiDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._signatures = config.get("ai_process_signatures", [])
        self._model_exts = config.get("model_file_extensions", [])
        self._gpu_threshold = config.get("gpu_threshold_mb", 512)
        self._known_paths: set[str] = set()
        self._ml = MlHeuristics(config) if config.get("ml_heuristics_enabled", True) else None

    def match_process(self, name: str, exe: str) -> tuple[str, int]:
        combined = f"{name} {exe}".lower()
        if self._is_helper_process(name, exe):
            return "", 0
        best_type = ""
        best_score = 0
        for sig in self._signatures:
            for pattern in sig["patterns"]:
                if pattern.lower() in combined:
                    score = 70 + len(pattern) * 2
                    if score > best_score:
                        best_score = min(score, 99)
                        best_type = sig["name"]
        return best_type, best_score

    @staticmethod
    def _is_helper_process(name: str, exe: str) -> bool:
        """Skip extension tooling and helper binaries that share an AI install path."""
        n = name.lower()
        x = exe.lower().replace("/", "\\")
        if n in ("node.exe", "pet.exe", "python.exe", "conhost.exe"):
            return True
        if "\\.cursor\\extensions\\" in x or "\\helpers\\" in x:
            return True
        return False

    def scan_model_files(self, search_paths: list[str] | None = None) -> list[dict[str, Any]]:
        if search_paths is None:
            search_paths = [
                os.path.expanduser("~"),
                os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "Ollama"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "LM Studio"),
            ]
        found = []
        for base in search_paths:
            if not base or not os.path.isdir(base):
                continue
            try:
                for root, _dirs, files in os.walk(base):
                    depth = root[len(base):].count(os.sep)
                    if depth > 4:
                        continue
                    for fname in files:
                        ext = Path(fname).suffix.lower()
                        if ext in self._model_exts:
                            fpath = os.path.join(root, fname)
                            try:
                                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                                if size_mb > 50:
                                    found.append({
                                        "path": fpath,
                                        "size_mb": round(size_mb, 1),
                                        "type": "local_model",
                                    })
                            except OSError:
                                pass
            except (PermissionError, OSError):
                continue
        return found[:20]

    def get_gpu_usage(self) -> dict[int, float]:
        """Return PID -> GPU memory MB for processes using GPU."""
        usage: dict[int, float] = {}
        usage.update(self._gpu_from_nvidia_smi())
        if not usage:
            usage.update(self._gpu_from_wmi())
        return usage

    def _gpu_from_nvidia_smi(self) -> dict[int, float]:
        usage: dict[int, float] = {}
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[0])
                            mb = float(parts[1])
                            if mb >= self._gpu_threshold:
                                usage[pid] = mb
                        except ValueError:
                            pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return usage

    def _gpu_from_wmi(self) -> dict[int, float]:
        """Fallback GPU usage via WMI (Windows)."""
        usage: dict[int, float] = {}
        if os.name != "nt":
            return usage
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process | "
                    "Where-Object { $_.Name -match 'python|ollama|lmstudio|cursor' } | "
                    "Select-Object ProcessId, WorkingSetSize | ConvertTo-Json",
                ],
                capture_output=True, text=True, timeout=8,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return usage
            import json
            data = json.loads(result.stdout)
            rows = data if isinstance(data, list) else [data]
            for row in rows:
                pid = int(row.get("ProcessId", 0))
                ws = int(row.get("WorkingSetSize", 0))
                mb = ws / (1024 * 1024)
                if pid and mb >= self._gpu_threshold:
                    usage[pid] = mb
        except Exception:
            pass
        return usage

    def enrich_with_gpu(self, processes: list[AiProcess]) -> list[AiProcess]:
        gpu = self.get_gpu_usage()
        enriched = []
        for proc in processes:
            if proc.pid in gpu:
                proc.gpu_mb = gpu[proc.pid]
                proc.confidence = min(99, proc.confidence + 15)
            enriched.append(proc)
        return enriched

    def detect_unknown_ai(
        self,
        all_pids: set[int],
        known_ai_pids: set[int],
        ai_network_pids: set[int] | None = None,
    ) -> list[AiProcess]:
        """Flag unknown processes via GPU threshold and behavioral heuristics."""
        unknown: list[AiProcess] = []
        seen: set[int] = set()
        gpu = self.get_gpu_usage()
        net_pids = ai_network_pids or set()

        for pid, mb in gpu.items():
            if pid in known_ai_pids or pid in seen:
                continue
            if self._ml:
                proc = self._ml.classify_unknown(
                    pid, mb, ai_domains_connected=pid in net_pids,
                )
                if proc:
                    unknown.append(proc)
                    seen.add(pid)
                    continue
            if mb >= self._gpu_threshold:
                unknown.append(AiProcess(
                    pid=pid, name="unknown", exe="", ai_type="Unknown AI Model",
                    confidence=60, gpu_mb=mb,
                ))
                seen.add(pid)

        if self._ml:
            for pid in all_pids - known_ai_pids - seen:
                proc = self._ml.classify_unknown(
                    pid, gpu.get(pid, 0.0), ai_domains_connected=pid in net_pids,
                )
                if proc:
                    unknown.append(proc)
        return unknown
