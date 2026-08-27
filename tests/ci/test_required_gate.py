from __future__ import annotations

import unittest

from tools.ci import required_gate


class RequiredGateTests(unittest.TestCase):
    def test_ordinary_gate_accepts_executed_and_skipped_closures(self) -> None:
        for decision, result in [(True, "success"), (False, "skipped")]:
            with self.subTest(decision=decision):
                required_gate.validate_gate(
                    required_gate.GateMode.ORDINARY,
                    decision,
                    required_gate.parse_results(
                        [
                            "changes=success",
                            f"quality={result}",
                            f"platform={result}",
                            f"interop={result}",
                        ]
                    ),
                )

    def test_fuzz_gate_accepts_executed_and_skipped_closures(self) -> None:
        for decision, result in [(True, "success"), (False, "skipped")]:
            with self.subTest(decision=decision):
                required_gate.validate_gate(
                    required_gate.GateMode.FUZZ,
                    decision,
                    required_gate.parse_results(
                        [
                            "impact=success",
                            f"deterministic-build={result}",
                            f"libfuzzer-build={result}",
                            f"fuzz-campaign={result}",
                        ]
                    ),
                )

    def test_unknown_decision_and_result_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            required_gate.parse_decision("yes")
        with self.assertRaises(ValueError):
            required_gate.parse_results(["changes=neutral"])

    def test_missing_extra_and_duplicate_dependencies_fail_closed(self) -> None:
        for values in [
            ["changes=success", "quality=success", "platform=success"],
            [
                "changes=success",
                "quality=success",
                "platform=success",
                "interop=success",
                "shadow=success",
            ],
        ]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                required_gate.validate_gate(
                    required_gate.GateMode.ORDINARY,
                    True,
                    required_gate.parse_results(values),
                )
        with self.assertRaises(ValueError):
            required_gate.parse_results(["changes=success", "changes=success"])

    def test_failure_cancel_and_wrong_skip_state_fail_closed(self) -> None:
        for decision, quality in [
            (True, "failure"),
            (True, "cancelled"),
            (True, "skipped"),
            (False, "success"),
        ]:
            with self.subTest(decision=decision, quality=quality), self.assertRaises(
                ValueError
            ):
                required_gate.validate_gate(
                    required_gate.GateMode.ORDINARY,
                    decision,
                    required_gate.parse_results(
                        [
                            "changes=success",
                            f"quality={quality}",
                            f"platform={'success' if decision else 'skipped'}",
                            f"interop={'success' if decision else 'skipped'}",
                        ]
                    ),
                )

    def test_classifier_must_succeed(self) -> None:
        with self.assertRaises(ValueError):
            required_gate.validate_gate(
                required_gate.GateMode.FUZZ,
                False,
                required_gate.parse_results(
                    [
                        "impact=failure",
                        "deterministic-build=skipped",
                        "libfuzzer-build=skipped",
                        "fuzz-campaign=skipped",
                    ]
                ),
            )

    def test_cli_returns_failure_instead_of_accepting_malformed_input(self) -> None:
        result = required_gate.main(
            [
                "--mode",
                "ordinary",
                "--decision",
                "true",
                "--dependency",
                "changes=success",
            ]
        )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
