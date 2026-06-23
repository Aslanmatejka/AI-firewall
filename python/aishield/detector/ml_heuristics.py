"""Behavioral heuristics for unknown AI detection (no ML model required)."""

from __future__ import annotations

import os
import re
from typing import Any

import psutil

from ..core.models import AiProcess

_AI_PATH_HINTS = re.compile(
    r"(ollama|lmstudio|openai|anthropic|huggingface|\.cache\\huggingface|"
    r"models|gguf|transformers|torch|cuda|onnx|llama|gpt|claude|copilot|cursor)",
    re.I,
)

_AI_DLL_HINTS = re.compile(
    r"(cublas|cudnn|onnxruntime|torch|llama|ggml|openblas|mkl|directml)",
    re.I,
)

_SUSPICIOUS_CMDLINE = re.compile(
    r"(--model|--gguf|inference|generate|chat\.|api\.openai|localhost:11434)",
    re.I,
)


class MlHeuristics:
    """Scores processes 0–100 for AI-like behavior using observable signals."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._gpu_threshold = float(config.get("gpu_threshold_mb", 512))
        self._min_score = int(config.get("ml_heuristic_threshold", 65))

    @property
    def threshold(self) -> int:
        return self._min_score

    def score_process(
        self,
        pid: int,
        gpu_mb: float = 0.0,
        ai_domains_connected: bool = False,
    ) -> tuple[int, list[str]]:
        reasons: list[str] = []
        score = 0

        if gpu_mb >= self._gpu_threshold:
            score += 35
            reasons.append(f"GPU memory {gpu_mb:.0f} MB")
        elif gpu_mb >= self._gpu_threshold * 0.5:
            score += 15
            reasons.append(f"Elevated GPU {gpu_mb:.0f} MB")

        if ai_domains_connected:
            score += 20
            reasons.append("Connected to known AI domain")

        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            exe = (proc.exe() or "").lower()
            cmdline = " ".join(proc.cmdline()).lower()
            mem_mb = proc.memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return min(score, 100), reasons

        if mem_mb >= 2048:
            score += 15
            reasons.append(f"High RAM {mem_mb:.0f} MB")
        elif mem_mb >= 1024:
            score += 8

        if _AI_PATH_HINTS.search(exe) or _AI_PATH_HINTS.search(cmdline):
            score += 25
            reasons.append("AI-related path or command line")

        if _SUSPICIOUS_CMDLINE.search(cmdline):
            score += 20
            reasons.append("Inference-style command line")

        if ai_domains_connected:
            score += 20
            reasons.append("Connected to known AI domain")

        if self._has_ai_modules(proc):
            score += 15
            reasons.append("Loaded AI runtime libraries")

        if name in ("python.exe", "pythonw.exe") and score < 40:
            score += 5
            reasons.append("Python interpreter (weak signal)")

        return min(score, 100), reasons

    @staticmethod
    def _has_ai_modules(proc: psutil.Process) -> bool:
        if os.name != "nt":
            return False
        try:
            for dll in proc.memory_maps():
                path = (dll.path or "").lower()
                if _AI_DLL_HINTS.search(path):
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
        return False

    def classify_unknown(
        self,
        pid: int,
        gpu_mb: float,
        ai_domains_connected: bool = False,
    ) -> AiProcess | None:
        score, reasons = self.score_process(pid, gpu_mb, ai_domains_connected)
        if score < self._min_score:
            return None
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = proc.exe() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        label = "Unknown AI (heuristic)"
        if reasons:
            label = f"Unknown AI — {reasons[0]}"
        return AiProcess(
            pid=pid, name=name, exe=exe, ai_type=label,
            confidence=score, gpu_mb=gpu_mb,
        )
