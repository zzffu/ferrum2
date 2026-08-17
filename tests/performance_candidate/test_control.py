#!/usr/bin/env python3
"""Behavior tests for the manual performance candidate control plane."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "performance_candidate.py"
SPEC = importlib.util.spec_from_file_location("performance_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class MeasurementInputTests(unittest.TestCase):
    def test_every_workflow_choice_is_valid(self) -> None:
        for warmup in ("1", "3", "5", "10"):
            for active in ("15", "30", "60"):
                for pairs in ("3", "5"):
                    self.assertEqual(
                        CONTROL.validate_measurement_inputs(warmup, active, pairs),
                        (int(warmup), int(active), int(pairs)),
                    )

    def test_each_measurement_input_rejects_invalid_values_independently(self) -> None:
        cases = (
            ("2", "15", "3", "warmup_seconds"),
            ("1", "45", "3", "active_seconds"),
            ("1", "15", "4", "pairs"),
            ("01", "15", "3", "warmup_seconds"),
            ("one", "15", "3", "warmup_seconds"),
        )
        for warmup, active, pairs, field in cases:
            with self.subTest(field=field, value=(warmup, active, pairs)):
                with self.assertRaisesRegex(CONTROL.CandidateControlError, field):
                    CONTROL.validate_measurement_inputs(warmup, active, pairs)


if __name__ == "__main__":
    unittest.main()
