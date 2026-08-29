import pathlib
import tempfile
import unittest

from tools.ci import performance_build_collect
from tools.performance_candidate.json_contract import CandidateControlError


class PerformanceBuildCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def raw(self, name: str, text: str) -> pathlib.Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_strace_subtracts_preregistered_topology_legs_before_triggering(self):
        raw = self.raw(
            "strace.txt",
            "recvfrom(3, ...) = 128\n" * 14 + "sendto(4, ...) = 128\n" * 14,
        )
        measurement = performance_build_collect.strace_udp_measurement(
            raw,
            datagrams=2,
            topology_id="m4-udp-small-high-full-round-trip-v1",
            trigger_threshold=1.5,
        )
        self.assertEqual(measurement["recv_syscalls"], 14)
        self.assertEqual(measurement["send_syscalls"], 14)
        self.assertEqual(measurement["expected_recv_syscalls"], 12)
        self.assertEqual(measurement["expected_send_syscalls"], 12)
        self.assertEqual(measurement["normalized_excess_syscalls_per_datagram"], 2.0)
        self.assertTrue(measurement["trigger_present"])

    def test_expected_full_topology_syscalls_do_not_false_trigger(self):
        raw = self.raw(
            "strace-baseline.txt",
            "recvmsg(3, ...) = 128\n" * 12 + "sendmsg(4, ...) = 128\n" * 12,
        )
        measurement = performance_build_collect.strace_udp_measurement(
            raw,
            datagrams=2,
            topology_id="m4-udp-small-high-full-round-trip-v1",
            trigger_threshold=1.5,
        )
        self.assertEqual(measurement["normalized_excess_syscalls_per_datagram"], 0.0)
        self.assertFalse(measurement["trigger_present"])

    def test_perf_kernel_cpu_share_is_independent_and_reconstructed(self):
        raw = self.raw(
            "udp-perf.csv",
            "1000,,cycles,100.00,\n200,,cycles:k,100.00,\n",
        )
        measurement = performance_build_collect.udp_kernel_cpu_measurement(
            raw, trigger_threshold_percent=10.0
        )
        self.assertEqual(measurement["kernel_cpu_share_percent"], 20.0)
        self.assertTrue(measurement["trigger_present"])

    def test_perf_stat_context_switch_rate_is_reconstructed(self):
        raw = self.raw("perf.csv", "1200,,context-switches,100.00,\n")
        measurement = performance_build_collect.context_switch_measurement(
            raw, duration_seconds=12.0, trigger_threshold=90.0
        )
        self.assertEqual(measurement["context_switches_per_second"], 100.0)
        self.assertTrue(measurement["trigger_present"])

    def test_perf_c2c_and_allocator_reports_are_typed(self):
        c2c = self.raw("c2c.txt", "120 Local HITM\n30 Remote HITM\n")
        c2c_measurement = performance_build_collect.perf_c2c_measurement(
            c2c, trigger_minimum=100
        )
        self.assertEqual(c2c_measurement["cache_line_bounces"], 150)

        allocator = self.raw(
            "allocator.txt",
            "# Samples: 500 of event 'cycles'\n"
            "  6.50% ferrum2 malloc\n  2.00% ferrum2 free\n",
        )
        allocation = performance_build_collect.allocator_hotspot_measurement(
            allocator, trigger_threshold=5.0
        )
        self.assertEqual(allocation["sample_count"], 500)
        self.assertEqual(allocation["hotspot_percent"], 8.5)
        self.assertTrue(allocation["trigger_present"])

    def test_empty_or_unrecognized_raw_output_fails_closed(self):
        with self.assertRaisesRegex(CandidateControlError, "empty"):
            performance_build_collect.strace_udp_measurement(
                self.raw("empty", ""),
                datagrams=1,
                topology_id="m4-udp-small-high-full-round-trip-v1",
                trigger_threshold=1.0,
            )
        with self.assertRaisesRegex(CandidateControlError, "no UDP"):
            performance_build_collect.strace_udp_measurement(
                self.raw("other", "openat(3, ...) = 4\n"),
                datagrams=1,
                topology_id="m4-udp-small-high-full-round-trip-v1",
                trigger_threshold=1.0,
            )
        with self.assertRaisesRegex(CandidateControlError, "inputs"):
            performance_build_collect.strace_udp_measurement(
                self.raw("unknown-topology", "recvmsg(3, ...) = 1\n"),
                datagrams=1,
                topology_id="unregistered",
                trigger_threshold=1.0,
            )


if __name__ == "__main__":
    unittest.main()
