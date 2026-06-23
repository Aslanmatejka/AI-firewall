"""Tests for ML behavioral heuristics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aishield.detector.ml_heuristics import MlHeuristics


class MlHeuristicsTests(unittest.TestCase):
    def test_high_gpu_scores_above_threshold(self) -> None:
        ml = MlHeuristics({"gpu_threshold_mb": 512, "ml_heuristic_threshold": 65})
        score, reasons = ml.score_process(99999, gpu_mb=600.0, ai_domains_connected=True)
        self.assertGreaterEqual(score, 55)
        self.assertTrue(reasons)

    def test_low_signal_below_threshold(self) -> None:
        ml = MlHeuristics({"gpu_threshold_mb": 512, "ml_heuristic_threshold": 65})
        score, _ = ml.score_process(99999, gpu_mb=0.0, ai_domains_connected=False)
        self.assertLess(score, 65)


if __name__ == "__main__":
    unittest.main()
