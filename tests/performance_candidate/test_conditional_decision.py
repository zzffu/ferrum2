import json
import pathlib
import tempfile
import unittest

from tools.performance_candidate import conditional_decision
from tools.performance_candidate.json_contract import CandidateControlError

SOURCE_SHA = "a" * 40
SOURCE_TREE = "b" * 40


class ConditionalDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def record(
        self,
        kind: str,
        measurement: dict[str, object] | None,
        *,
        available: bool = True,
    ) -> pathlib.Path:
        raw = self.root / f"{kind}.raw"
        raw.write_text(f"raw {kind}\n", encoding="utf-8")
        row = conditional_decision.create_prerequisite_record(
            kind=kind,
            source_sha=SOURCE_SHA,
            source_tree=SOURCE_TREE,
            profiler_status="AVAILABLE" if available else "UNAVAILABLE",
            raw_artifact_path=raw if available else None,
            measurement=measurement if available else None,
        )
        path = self.root / f"{kind}.json"
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def assertion(reason: str = "fixture") -> dict[str, object]:
        return {"reason": reason, "satisfied": True}

    @staticmethod
    def udp_syscall(*, normalized_excess: float = 2.0) -> dict[str, object]:
        datagrams = 100
        expected = 600
        excess = round(normalized_excess * datagrams / 2)
        return {
            "datagrams": datagrams,
            "excess_recv_syscalls": excess,
            "excess_send_syscalls": excess,
            "expected_recv_syscalls": expected,
            "expected_send_syscalls": expected,
            "normalized_excess_syscalls_per_datagram": normalized_excess,
            "recv_syscalls": expected + excess,
            "send_syscalls": expected + excess,
            "topology": {
                "id": "m4-udp-small-high-full-round-trip-v1",
                "recv_legs_per_datagram": 6,
                "send_legs_per_datagram": 6,
            },
            "trigger_present": normalized_excess >= 1.5,
            "trigger_threshold_excess_per_datagram": 1.5,
        }

    @staticmethod
    def udp_kernel_cpu(*, share: float = 20.0) -> dict[str, object]:
        return {
            "kernel_cpu_share_percent": share,
            "kernel_cycles": share * 10,
            "total_cycles": 1_000.0,
            "trigger_present": share >= 10.0,
            "trigger_threshold_percent": 10.0,
        }

    def test_udp_syscall_trigger_is_typed_and_never_adopts_on_hosted_scope(self):
        paths = [
            self.record("exact-size-addressed", self.assertion()),
            self.record("udp-global-locks-addressed", self.assertion()),
            self.record(
                "udp-syscall",
                self.udp_syscall(),
            ),
            self.record("udp-kernel-cpu", self.udp_kernel_cpu()),
        ]

        decision = conditional_decision.create_conditional_decision(
            candidate="UDP-14",
            source_sha=SOURCE_SHA,
            source_tree=SOURCE_TREE,
            evidence_paths=paths,
        )

        self.assertEqual(decision["status"], "TRIGGER_PRESENT")
        self.assertTrue(decision["trigger_present"])
        self.assertEqual(
            decision["adoption_decision"],
            "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        )
        self.assertFalse(decision["performance_authoritative"])
        self.assertFalse(decision["bare_metal_gate_satisfied"])
        self.assertFalse(decision["durable_evidence_gate_satisfied"])
        self.assertEqual(decision["trigger_kinds"], ["udp-kernel-cpu", "udp-syscall"])

    def test_missing_prerequisite_is_deferred_and_unavailable_profiler_is_inconclusive(
        self,
    ):
        deferred = conditional_decision.create_conditional_decision(
            candidate="UDP-14",
            source_sha=SOURCE_SHA,
            source_tree=SOURCE_TREE,
            evidence_paths=[self.record("exact-size-addressed", self.assertion())],
        )
        self.assertEqual(deferred["status"], "DEFERRED")
        self.assertIn("udp-syscall", deferred["missing_prerequisites"])

        self.assertIn("udp-kernel-cpu", deferred["missing_prerequisites"])

        inconclusive = conditional_decision.create_conditional_decision(
            candidate="UDP-14",
            source_sha=SOURCE_SHA,
            source_tree=SOURCE_TREE,
            evidence_paths=[
                self.record("exact-size-addressed", self.assertion()),
                self.record("udp-global-locks-addressed", self.assertion()),
                self.record("udp-syscall", self.udp_syscall()),
                self.record("udp-kernel-cpu", None, available=False),
            ],
        )
        self.assertEqual(inconclusive["status"], "INCONCLUSIVE")
        self.assertEqual(inconclusive["profiler_unavailable"], ["udp-kernel-cpu"])

    def test_udp_requires_both_excess_and_kernel_cpu_share(self):
        decision = conditional_decision.create_conditional_decision(
            candidate="UDP-14",
            source_sha=SOURCE_SHA,
            source_tree=SOURCE_TREE,
            evidence_paths=[
                self.record("exact-size-addressed", self.assertion()),
                self.record("udp-global-locks-addressed", self.assertion()),
                self.record("udp-syscall", self.udp_syscall()),
                self.record("udp-kernel-cpu", self.udp_kernel_cpu(share=5.0)),
            ],
        )
        self.assertEqual(decision["status"], "NO_TRIGGER")
        self.assertFalse(decision["trigger_present"])
        self.assertEqual(
            decision["adoption_decision"],
            "NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE",
        )

    def test_udp_ratio_and_artifact_digest_tampering_fail_closed(self):
        with self.assertRaisesRegex(CandidateControlError, "reconstruct"):
            self.record(
                "udp-syscall",
                {**self.udp_syscall(), "normalized_excess_syscalls_per_datagram": 1.0},
            )

        with self.assertRaisesRegex(CandidateControlError, "preregistered"):
            self.record(
                "udp-syscall",
                {
                    **self.udp_syscall(),
                    "topology": {
                        "id": "m4-udp-small-high-full-round-trip-v1",
                        "recv_legs_per_datagram": 1,
                        "send_legs_per_datagram": 1,
                    },
                },
            )

        with self.assertRaisesRegex(CandidateControlError, "reconstruct"):
            self.record(
                "udp-kernel-cpu",
                {**self.udp_kernel_cpu(), "kernel_cpu_share_percent": 19.0},
            )

        evidence = self.record("exact-size-addressed", self.assertion())
        row = json.loads(evidence.read_text(encoding="utf-8"))
        pathlib.Path(row["raw_artifact"]["path"]).write_text(
            "changed\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(CandidateControlError, "identity changed"):
            conditional_decision.load_prerequisite_document(evidence)


if __name__ == "__main__":
    unittest.main()
