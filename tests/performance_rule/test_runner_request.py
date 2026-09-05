"""Small request-contract tests; no runner process is executed."""

import unittest

from tests.performance_rule._fixture import RUNNER_ARGUMENTS, RUNNER_SHA256, report
from tools.performance_rule.runner_request import parse_runner_request
from tools.performance_rule.schema import ControlError


class RunnerRequestTests(unittest.TestCase):
    def test_current_defaults_and_explicit_qualification_matrix(self):
        smoke = parse_runner_request([])
        self.assertEqual(smoke.profile, "smoke")
        self.assertEqual(smoke.configuration, {
            "match_sizes": [100], "route_sizes": [1, 32, 64], "dns_rule_sizes": [1],
            "samples": 101, "base_iterations_per_sample": 8192, "includes_100k": False,
        })
        full = parse_runner_request(["--profile=qualification", "--samples", "1001", "--iterations-per-sample=10", "--include-100k", "--workspace-root", ".", "--output=result.json"])
        self.assertEqual(full.configuration, {
            "match_sizes": [100, 1000, 10000, 100000], "route_sizes": [1, 32, 64, 1000, 10000],
            "dns_rule_sizes": [1, 64, 65, 100, 1000, 10000], "samples": 1001,
            "base_iterations_per_sample": 10, "includes_100k": True,
        })

    def test_unknown_abbreviated_duplicate_and_nonmeasurement_options_fail(self):
        cases = (["--sam", "5"], ["--help"], ["--version"], ["--samples"],
                 ["--samples", "5", "--samples=5"], ["--include-100k=true"],
                 ["--samples", "4"], ["--samples", "1002"], ["--samples", "5.0"],
                 ["--samples", "-5"], ["--profile", "SMOKE"], ["--iterations-per-sample", "0"])
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ControlError):
                parse_runner_request(arguments)

    def test_report_configuration_must_equal_the_actual_request(self):
        request = parse_runner_request(RUNNER_ARGUMENTS)
        request.validate_report(report(RUNNER_SHA256))
        for field, value in (("samples", 501), ("base_iterations_per_sample", 8192), ("route_sizes", [1]), ("includes_100k", True)):
            with self.subTest(field=field):
                raw = report(RUNNER_SHA256)
                raw["configuration"][field] = value
                with self.assertRaisesRegex(ControlError, "requested arguments"):
                    request.validate_report(raw)
        raw = report(RUNNER_SHA256)
        raw["profile"] = "qualification"
        with self.assertRaises(ControlError):
            request.validate_report(raw)
