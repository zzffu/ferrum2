from __future__ import annotations

import copy
import hashlib
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout

from tools.performance_candidate.cli import main as performance_candidate_main
from tools.performance_candidate.json_contract import CandidateControlError, U64_MAX
from tools.performance_candidate.linux.evidence_contract import (
    _TIMED_V6_EXCLUDED_CONTROLLER_FILES,
    _source_bundle,
    _timed_v6_source_bytes,
    controller_source_sha256,
)
from tools.performance_candidate.structural_diagnostic import (
    COUNTER_UNITS,
    STRUCTURAL_AGGREGATION,
    STRUCTURAL_KIND,
    STRUCTURAL_SCENARIO,
    STRUCTURAL_SCHEMA_VERSION,
    validate_structural_diagnostic,
)


class StructuralDiagnosticContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "structural@example.invalid")
        self._git("config", "user.name", "Structural Fixture")
        (self.repository / ".gitignore").write_text("/target/\n", encoding="utf-8")
        (self.repository / "README.md").write_text("fixture\n", encoding="utf-8")
        self._git("add", ".gitignore", "README.md")
        self._git("commit", "-q", "-m", "fixture")
        self.candidate_sha = self._git("rev-parse", "HEAD")
        self.tree_sha = self._git("rev-parse", "HEAD^{tree}")

        self.binary_dir = (
            self.repository / "target" / "structural-diagnostic" / "profiling"
        )
        self.binary_dir.mkdir(parents=True)
        self.runner = self._binary("m4-qualification", b"runner-v7")
        self.client = self._binary("ferrum2-client", b"client-feature-on")
        self.server = self._binary("ferrum2-server", b"server-feature-on")
        self.evidence = self.root / "structural.json"
        self.row = self._valid_row()
        self._write(self.row)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout.strip()

    def _binary(self, name: str, content: bytes) -> pathlib.Path:
        path = self.binary_dir / name
        path.write_bytes(content)
        return path

    @staticmethod
    def _digest(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _valid_row(self) -> dict[str, object]:
        before = {name: 0 for name in COUNTER_UNITS}
        client_after = dict(before)
        server_after = dict(before)
        for name, value in {
            "tcp_fused_fast_path_connections": 8,
            "tcp_fused_owned_upload_frames": 400,
            "tcp_fused_borrowed_download_frames": 400,
            "tcp_fused_frames": 800,
            "tcp_fused_encrypt_buffer_capacity_bytes": 524_288,
            "tcp_fused_decrypt_buffer_capacity_bytes": 524_288,
            "tcp_fused_relay_buffer_capacity_removed_bytes": 524_288,
        }.items():
            client_after[name] = value
        client_delta = dict(client_after)
        server_delta = dict(server_after)
        merged = {
            name: client_delta[name] + server_delta[name] for name in COUNTER_UNITS
        }
        return {
            "schema_version": STRUCTURAL_SCHEMA_VERSION,
            "kind": STRUCTURAL_KIND,
            "candidate_sha": self.candidate_sha,
            "tree_sha": self.tree_sha,
            "runner_sha256": self._digest(self.runner),
            "client_sha256": self._digest(self.client),
            "server_sha256": self._digest(self.server),
            "scenario": STRUCTURAL_SCENARIO,
            "warmup_seconds": 1,
            "active_seconds": 15,
            "build_profile": "profiling-structural-metrics",
            "performance_authoritative": False,
            "performance_adoption_allowed": False,
            "counter_schema": {
                name: {
                    "unit": unit,
                    "aggregation": STRUCTURAL_AGGREGATION,
                    "range": {"minimum": 0, "maximum": U64_MAX},
                }
                for name, unit in COUNTER_UNITS.items()
            },
            "snapshots": {
                "client": {"before": dict(before), "after": client_after},
                "server": {"before": dict(before), "after": server_after},
            },
            "overflow": {
                "client_before": False,
                "client_after": False,
                "server_before": False,
                "server_after": False,
                "any": False,
            },
            "deltas": {
                "client": client_delta,
                "server": server_delta,
                "merged": merged,
            },
            "workload": {"checked_bytes": 1_048_576, "workers": 8},
            "cleanup": {
                "active_processes": 0,
                "active_workers": 0,
                "rebind_status": "PASS",
                "status": "PASS",
            },
            "correctness": "PASS",
            "status": "PASS",
        }

    def _write(self, row: object) -> None:
        self.evidence.write_text(
            json.dumps(row, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )

    def _validate(self) -> dict[str, object]:
        return validate_structural_diagnostic(
            self.evidence,
            repository=self.repository,
            runner=self.runner,
            client=self.client,
            server=self.server,
            candidate_sha=self.candidate_sha,
        )

    def test_valid_v7_recomputes_identity_deltas_and_closed_49_family_schema(self) -> None:
        validated = self._validate()
        self.assertEqual(len(validated["counter_schema"]), 49)
        self.assertFalse(validated["performance_authoritative"])
        self.assertFalse(validated["performance_adoption_allowed"])
        self.assertGreater(
            validated["deltas"]["merged"]["tcp_fused_fast_path_connections"], 0
        )

    def test_supported_controller_entry_validates_v7(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = performance_candidate_main(
                [
                    "validate-structural-diagnostic",
                    "--evidence",
                    str(self.evidence),
                    "--repository",
                    str(self.repository),
                    "--runner",
                    str(self.runner),
                    "--client",
                    str(self.client),
                    "--server",
                    str(self.server),
                    "--candidate-sha",
                    self.candidate_sha,
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("m18_structural_trial\tPASS", output.getvalue())
        self.assertIn("performance_adoption_allowed=false", output.getvalue())

    def test_closed_schema_and_fail_closed_arithmetic_reject_mutations(self) -> None:
        def missing_family(row: dict[str, object]) -> None:
            row["snapshots"]["client"]["before"].pop(
                "tcp_decrypt_prepare_copy_bytes"
            )

        def extra_family(row: dict[str, object]) -> None:
            row["counter_schema"]["dynamic_peer_counter"] = copy.deepcopy(
                row["counter_schema"]["tcp_fused_frames"]
            )

        def wrong_unit(row: dict[str, object]) -> None:
            row["counter_schema"]["tcp_fused_frames"]["unit"] = "bytes"

        def wrong_aggregation(row: dict[str, object]) -> None:
            row["counter_schema"]["tcp_fused_frames"]["aggregation"] = "maximum"

        def wrong_range(row: dict[str, object]) -> None:
            row["counter_schema"]["tcp_fused_frames"]["range"]["maximum"] = 1

        def decreasing(row: dict[str, object]) -> None:
            row["snapshots"]["client"]["before"]["tcp_fused_frames"] = 801

        def forged_delta(row: dict[str, object]) -> None:
            row["deltas"]["merged"]["tcp_fused_frames"] += 1

        def endpoint_overflow(row: dict[str, object]) -> None:
            row["overflow"]["client_after"] = True
            row["overflow"]["any"] = True

        def forged_overflow_aggregate(row: dict[str, object]) -> None:
            row["overflow"]["any"] = True

        def authoritative(row: dict[str, object]) -> None:
            row["performance_authoritative"] = True

        def adoptable(row: dict[str, object]) -> None:
            row["performance_adoption_allowed"] = True

        def payload_copy(row: dict[str, object]) -> None:
            name = "tcp_plain_to_encrypt_copy_bytes"
            row["snapshots"]["client"]["after"][name] = 1
            row["deltas"]["client"][name] = 1
            row["deltas"]["merged"][name] = 1

        def fallback(row: dict[str, object]) -> None:
            name = "tcp_fused_fallback_multi_hop_connections"
            row["snapshots"]["client"]["after"][name] = 1
            row["deltas"]["client"][name] = 1
            row["deltas"]["merged"][name] = 1

        def no_fast_path(row: dict[str, object]) -> None:
            name = "tcp_fused_fast_path_connections"
            row["snapshots"]["client"]["after"][name] = 0
            row["deltas"]["client"][name] = 0
            row["deltas"]["merged"][name] = 0

        mutations = {
            "missing family": missing_family,
            "dynamic family": extra_family,
            "wrong unit": wrong_unit,
            "wrong aggregation": wrong_aggregation,
            "wrong range": wrong_range,
            "decreasing counter": decreasing,
            "forged delta": forged_delta,
            "endpoint overflow": endpoint_overflow,
            "forged overflow aggregate": forged_overflow_aggregate,
            "performance authoritative": authoritative,
            "performance adoptable": adoptable,
            "payload copy": payload_copy,
            "fallback": fallback,
            "absent fast path": no_fast_path,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                row = copy.deepcopy(self.row)
                mutate(row)
                self._write(row)
                with self.assertRaises(CandidateControlError):
                    self._validate()

    def test_duplicate_json_keys_and_binary_identity_tampering_are_rejected(self) -> None:
        self.evidence.write_text(
            '{"schema_version":7,"schema_version":7}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(CandidateControlError, "duplicate JSON key"):
            self._validate()

        self._write(self.row)
        self.client.write_bytes(b"tampered-client")
        with self.assertRaisesRegex(CandidateControlError, "client_sha256"):
            self._validate()

    def test_binaries_outside_independent_target_are_rejected(self) -> None:
        shared = self.repository / "target" / "profiling"
        shared.mkdir(parents=True)
        shared_runner = shared / "m4-qualification"
        shared_runner.write_bytes(self.runner.read_bytes())
        with self.assertRaisesRegex(CandidateControlError, "independent diagnostic target"):
            validate_structural_diagnostic(
                self.evidence,
                repository=self.repository,
                runner=shared_runner,
                client=self.client,
                server=self.server,
                candidate_sha=self.candidate_sha,
            )


class StructuralDiagnosticWorkflowTests(unittest.TestCase):
    def test_timed_v6_controller_closure_excludes_independent_build_owners(self) -> None:
        expected = frozenset(
            {
                "build_experiment.py",
                "build_qualification.py",
                "conditional_decision.py",
                "evidence_matrix.py",
                "structural_diagnostic.py",
            }
        )
        self.assertEqual(_TIMED_V6_EXCLUDED_CONTROLLER_FILES, expected)
        root = pathlib.Path.cwd()
        package = root / "tools" / "performance_candidate"
        paths = tuple(
            path
            for path in sorted(package.rglob("*.py"))
            if path.name not in expected
        )
        self.assertEqual(controller_source_sha256(), _source_bundle(root, paths))

    def test_diagnostic_sources_do_not_invalidate_timed_v6_calibration_identity(self) -> None:
        repository = pathlib.Path.cwd()
        bounded_files = {
            "tools/ferrum2-m4-qualification/Cargo.toml": (
                677,
                "f2b393469841d931a02d77e4f1805c5a902327e980a5428a505cfc5cf7545676",
            ),
            "tools/ferrum2-m4-qualification/src/m4_support/mod.rs": (
                3_505,
                "0817dd3cd3082f045ecf4f60013513d447c0755ae254e48cc4e2cf7b8642a151",
            ),
            "tools/ferrum2-m4-qualification/src/m4_support/self_check.rs": (
                33_863,
                "7a2edf0a272859d974d4b127932fddbf30ac05fb3bc9ad9d816810c0f215e79d",
            ),
            "tools/performance_candidate/cli.py": (
                19_632,
                "c2f7dbb466410bfa1f3bc2ac5259604f9eb0b0d0e3801871ff96e30abc829800",
            ),
            "tools/performance_candidate/linux/evidence_contract.py": (
                5_993,
                "f9290cf644a1dca56ccef75dea518c1094f44d53e82339e37d239895f9a0342e",
            ),
        }
        for relative, (expected_bytes, expected_sha256) in bounded_files.items():
            with self.subTest(relative=relative):
                current = (repository / relative).read_bytes()
                projected = _timed_v6_source_bytes(relative, current)
                self.assertEqual(len(projected), expected_bytes)
                self.assertEqual(hashlib.sha256(projected).hexdigest(), expected_sha256)

    def test_diagnostic_is_isolated_after_default_feature_off_abba(self) -> None:
        workflow = pathlib.Path(".github/workflows/performance-candidate.yml").read_text(
            encoding="utf-8"
        )
        paired_marker = "  paired-profile:\n"
        structural_marker = "  structural-diagnostic:\n"
        self.assertIn(paired_marker, workflow)
        self.assertIn(structural_marker, workflow)
        paired_start = workflow.index(paired_marker)
        structural_start = workflow.index(structural_marker)
        self.assertLess(paired_start, structural_start)
        paired = workflow[paired_start:structural_start]
        structural = workflow[structural_start:]
        self.assertIn("Run pre-registered six-pair ABBA schedule", paired)
        self.assertIn("Require preferred AMD performance host", paired)
        self.assertNotIn("structural-metrics", paired)
        self.assertNotIn("target/structural-diagnostic", paired)
        self.assertIn("needs: paired-profile", structural)
        self.assertIn("Require preferred AMD structural host", structural)
        self.assertIn("target/structural-diagnostic", structural)
        self.assertIn("ferrum2-client/structural-metrics", structural)
        self.assertIn("ferrum2-server/structural-metrics", structural)
        self.assertIn("ferrum2-m4-qualification/structural-diagnostic", structural)
        self.assertIn("structural-diagnostic \\", structural)
        validate = "- name: Recompute schema-v7 structural evidence"
        upload = "- name: Upload validated structural evidence"
        self.assertLess(structural.index(validate), structural.index(upload))


if __name__ == "__main__":
    unittest.main()
