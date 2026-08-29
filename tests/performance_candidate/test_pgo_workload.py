import pathlib
import tempfile
import unittest
from unittest import mock

from tools.performance_candidate.workloads import pgo_workload


class PgoWorkloadContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.source = self.root / "variant" / "profiling"
        self.source.mkdir(parents=True)
        for name in (
            "ferrum2-client",
            "ferrum2-rule-qualification",
            "ferrum2-server",
            "m4-qualification",
        ):
            (self.source / name).write_bytes(name.encode("ascii"))

    def test_m4_workload_uses_repo_relative_profiles_and_materialized_binaries(self):
        contract = {
            "unit": "datagrams_per_second",
            "runner_image": "ubuntu-24.04",
            "producer_source_sha256": "1" * 64,
            "controller_source_sha256": "2" * 64,
            "semantic_recipe_sha256": "3" * 64,
            "evidence_bundle_sha256": "4" * 64,
        }

        def executor(argv, **_kwargs):
            binary_dir = pathlib.Path(argv[argv.index("--binary-dir") + 1])
            ready = pathlib.Path(argv[argv.index("--ready-file") + 1])
            output = pathlib.Path(argv[argv.index("--output") + 1])
            self.assertEqual(binary_dir, self.repository / "target" / "profiling")
            self.assertEqual(pathlib.Path(argv[0]), binary_dir / "m4-qualification")
            self.assertFalse(ready.is_absolute())
            self.assertFalse(output.is_absolute())
            self.assertEqual(ready.parts[0], "profiles")
            self.assertEqual(output.parts[0], "profiles")
            destination = self.repository / output
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("{}\n", encoding="utf-8")
            return mock.Mock(returncode=0)

        with (
            mock.patch.object(pgo_workload, "_git", return_value="a" * 40),
            mock.patch.object(
                pgo_workload, "catalog_evidence_contract", return_value=contract
            ),
            mock.patch.object(pgo_workload.subprocess, "run", side_effect=executor),
        ):
            pgo_workload._run_m4(
                category="udp-small",
                runner=self.source / "m4-qualification",
                client=self.source / "ferrum2-client",
                server=self.source / "ferrum2-server",
                repository=self.repository,
            )

        with self.assertRaisesRegex(RuntimeError, "roles are invalid"):
            pgo_workload._run_m4(
                category="udp-small",
                runner=self.source / "ferrum2-client",
                client=self.source / "ferrum2-client",
                server=self.source / "ferrum2-server",
                repository=self.repository,
            )


if __name__ == "__main__":
    unittest.main()
