import pathlib
import unittest

import yaml


class PerformanceConditionalWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = (
            pathlib.Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "performance-conditional.yml"
        )
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        cls.steps = next(iter(document["jobs"].values()))["steps"]

    def test_udp14_uses_normalized_topology_and_independent_perf_evidence(self):
        collect = next(
            step
            for step in self.steps
            if step.get("name") == "Collect typed profiler prerequisites"
        )["run"]
        udp = collect.split("UDP-14)", 1)[1].split(";;", 1)[0]
        self.assertIn("--topology m4-udp-small-high-full-round-trip-v1", udp)
        self.assertIn("--trigger-threshold 1.5", udp)
        self.assertIn("perf stat -x, -e cycles -e cycles:k", udp)
        self.assertIn("--trigger-threshold-percent 10", udp)
        self.assertIn("bind_available udp-syscall", udp)
        self.assertIn("bind_available udp-kernel-cpu", udp)
        self.assertEqual(udp.count('"${profile_command[@]}"'), 2)
        self.assertIn("capture_profile_output udp-strace", udp)
        self.assertIn("capture_profile_output udp-perf", udp)

    def test_hosted_terminal_scope_remains_non_adopting(self):
        terminal = next(
            step
            for step in self.steps
            if step.get("name") == "Enforce non-adoption terminal scope"
        )["run"]
        self.assertIn("NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE", terminal)
        self.assertIn('row["performance_authoritative"] is False', terminal)
        self.assertIn('row["bare_metal_gate_satisfied"] is False', terminal)
        self.assertIn('row["durable_evidence_gate_satisfied"] is False', terminal)


if __name__ == "__main__":
    unittest.main()
