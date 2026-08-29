from __future__ import annotations

import hashlib
import pathlib
import tempfile
import unittest
from unittest import mock

from tools.ci.performance_udp_worker_workflow import (
    build_manifest,
    capture_host,
    validate_manifest,
)
from tools.performance_udp_workers.contract import (
    UdpWorkerControlError,
    canonical_bytes,
)
from tools.performance_udp_workers.pairing import build_plan, build_trials

CPUINFO = """vendor_id\t: AuthenticAMD
model name\t: AMD Fixture
vendor_id\t: AuthenticAMD
model name\t: AMD Fixture
"""
MEMINFO = "MemTotal:       16000000 kB\n"


class PerformanceUdpWorkerWorkflowTests(unittest.TestCase):
    def test_host_capture_requires_one_exact_amd_identity(self) -> None:
        def read_text(path: pathlib.Path, **_: object) -> str:
            return CPUINFO if str(path).endswith("cpuinfo") else MEMINFO

        with mock.patch.object(pathlib.Path, "read_text", read_text), mock.patch(
            "tools.ci.performance_udp_worker_workflow._first_line",
            side_effect=["Linux fixture", "rustc 1.97.1 (fixture)"],
        ), mock.patch(
            "tools.ci.performance_udp_worker_workflow.os.cpu_count", return_value=8
        ):
            host = capture_host()
        self.assertEqual(host["cpu_vendor"], "AuthenticAMD")
        self.assertEqual(host["cpu_model"], "AMD Fixture")

    def test_non_amd_host_is_rejected_before_workload(self) -> None:
        def read_text(path: pathlib.Path, **_: object) -> str:
            return (
                CPUINFO.replace("AuthenticAMD", "GenuineIntel")
                if str(path).endswith("cpuinfo")
                else MEMINFO
            )

        with mock.patch.object(pathlib.Path, "read_text", read_text), mock.patch(
            "tools.ci.performance_udp_worker_workflow.os.cpu_count", return_value=8
        ):
            with self.assertRaisesRegex(UdpWorkerControlError, "AuthenticAMD"):
                capture_host()

    def test_manifest_is_closed_and_cannot_claim_adoption(self) -> None:
        sha = "a" * 40
        contract = {
            "schema_version": 1,
            "trial_schema_version": 1,
            "structural_schema_version": 7,
            "runner_image": "ubuntu-24.04",
            "producer_source_sha256": "1" * 64,
            "controller_source_sha256": "2" * 64,
            "semantic_recipe_sha256": "3" * 64,
        }
        contract["evidence_bundle_sha256"] = hashlib.sha256(
            canonical_bytes(contract)
        ).hexdigest()
        trials = build_trials()
        plan = build_plan(sha, contract)
        summary = {
            "schema_version": 1,
            "kind": "ferrum2_udp_worker_summary",
            "candidate_sha": sha,
            "decision": "DEFERRED",
        }
        host = {
            "schema_version": 1,
            "kind": "ferrum2_udp_worker_host",
            "runner_image": "ubuntu-24.04",
            "runner_os": "Linux",
            "runner_arch": "X64",
            "cpu_vendor": "AuthenticAMD",
            "cpu_model": "AMD Fixture",
            "cpu_count": 8,
            "memory_kib": 16_000_000,
            "kernel": "Linux fixture",
            "rustc": "rustc 1.97.1 (fixture)",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            binary_dir = root / "target/profiling"
            binary_dir.mkdir(parents=True)
            for name in ("m4-qualification", "ferrum2-client", "ferrum2-server"):
                (binary_dir / name).write_bytes(name.encode("ascii"))
            files = {
                "profiles/udp-workers/host.json": host,
                "profiles/udp-workers/plan.json": plan,
                "profiles/udp-workers/summary.json": summary,
                **{trial.output: {"sequence": trial.sequence} for trial in trials},
            }
            for relative, value in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(canonical_bytes(value) + b"\n")
            with mock.patch(
                "tools.ci.performance_udp_worker_workflow.validate_checkout",
                return_value="b" * 40,
            ), mock.patch(
                "tools.ci.performance_udp_worker_workflow.evidence_contract",
                return_value=contract,
            ), mock.patch(
                "tools.ci.performance_udp_worker_workflow.load_and_validate_trials",
                return_value=[],
            ), mock.patch(
                "tools.ci.performance_udp_worker_workflow.load_json",
                side_effect=[host, plan, summary],
            ), mock.patch(
                "tools.ci.performance_udp_worker_workflow.summarize",
                return_value=summary,
            ):
                manifest = build_manifest(
                    root=root,
                    binary_dir=binary_dir,
                    candidate_sha=sha,
                    repository="owner/repository",
                    run_id="123",
                    run_attempt="2",
                )
        self.assertEqual(manifest["decision"], "DEFERRED")
        self.assertEqual(manifest["default_receive_workers"], 1)
        self.assertFalse(manifest["authority"]["performance_authoritative"])
        self.assertFalse(manifest["retention"]["durable_provenance"])
        self.assertEqual(len(manifest["files"]), len(trials) + 3)
        validate_manifest(manifest)
        manifest["authority"]["adoption_claim"] = True
        with self.assertRaisesRegex(UdpWorkerControlError, "authority"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
