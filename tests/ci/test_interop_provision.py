from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tools.ci import interop_provision as subject


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY_ROOT / "tests/interop/versions.toml"
SPECS = {spec.provider_id: spec for spec in subject.PROVIDER_SPECS}


def tar_with_members(path: Path, members: tuple[tuple[str, bytes | None], ...]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, contents in members:
            info = tarfile.TarInfo(name)
            if contents is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.size = len(contents)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(contents))


class ManifestTests(unittest.TestCase):
    def test_repository_manifest_is_complete_and_typed(self) -> None:
        pins = subject.parse_manifest(MANIFEST.read_bytes())

        self.assertEqual(
            tuple(pin.provider_id for pin in pins),
            ("sing_box", "shadowsocks_rust", "coredns", "bind"),
        )
        self.assertEqual(pins[0].linux.asset, "sing-box-1.13.14-linux-amd64-glibc.tar.gz")
        self.assertEqual(pins[2].license.asset, "coredns-1.14.6-LICENSE")
        self.assertEqual(pins[3].expected_version, "DiG 9.20.26")

    def test_manifest_rejects_an_unreviewed_license_boundary(self) -> None:
        contents = MANIFEST.read_text(encoding="utf-8").replace(
            "MIT; execute only as an independent test process; do not redistribute",
            "MIT",
        )

        with self.assertRaisesRegex(ValueError, "reviewed boundary"):
            subject.parse_manifest(contents.encode())

    def test_manifest_rejects_a_url_that_does_not_match_its_asset(self) -> None:
        contents = MANIFEST.read_text(encoding="utf-8").replace(
            "/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz\"",
            "/different.tar.xz\"",
            1,
        )

        with self.assertRaisesRegex(ValueError, "end with the asset name"):
            subject.parse_manifest(contents.encode())

    def test_ordered_provider_registry_owns_all_provider_policy(self) -> None:
        self.assertEqual(
            tuple(
                (
                    spec.provider_id,
                    spec.timeout_seconds,
                    spec.github_status_name,
                    spec.license_marker,
                    spec.root_template,
                )
                for spec in subject.PROVIDER_SPECS
            ),
            (
                (
                    "sing_box",
                    300,
                    "M2_SING_BOX_SETUP_STATUS",
                    "NOASSERTION",
                    "sing-box-{version}",
                ),
                (
                    "shadowsocks_rust",
                    300,
                    "M2_SHADOWSOCKS_RUST_SETUP_STATUS",
                    "MIT",
                    "shadowsocks-rust-{version}",
                ),
                (
                    "coredns",
                    300,
                    "M12_COREDNS_SETUP_STATUS",
                    "Apache-2.0",
                    "coredns-{version}",
                ),
                (
                    "bind",
                    900,
                    "M12_BIND_SETUP_STATUS",
                    "MPL-2.0",
                    "bind-{version}",
                ),
            ),
        )
        self.assertTrue(all(callable(spec.verifier) for spec in subject.PROVIDER_SPECS))


class ArtifactTests(unittest.TestCase):
    def test_exact_size_and_digest_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.tar"
            path.write_bytes(b"reviewed")
            artifact = subject.Artifact(
                path.name,
                "https://example.invalid/provider.tar",
                path.stat().st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            subject.verify_artifact(path, artifact)

            path.write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "size mismatch|SHA-256 mismatch"):
                subject.verify_artifact(path, artifact)

    def test_provider_archive_contracts_are_derived_from_version(self) -> None:
        pins = subject.parse_manifest(MANIFEST.read_bytes())

        self.assertEqual(
            subject.expected_archive_names(SPECS["sing_box"], pins[0]),
            (
                "sing-box-1.13.14-linux-amd64-glibc",
                "sing-box-1.13.14-linux-amd64-glibc/LICENSE",
                "sing-box-1.13.14-linux-amd64-glibc/sing-box",
            ),
        )
        self.assertEqual(
            subject.expected_archive_names(SPECS["shadowsocks_rust"], pins[1]),
            ("sslocal", "ssserver", "ssurl", "ssmanager", "ssservice"),
        )


class ProviderVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pins = subject.parse_manifest(MANIFEST.read_bytes())

    def test_coredns_accepts_exact_version_and_reviewed_platform_metadata(self) -> None:
        subject.verify_coredns_version(
            self.pins[2],
            "CoreDNS-1.14.6\nlinux/amd64, go1.26.5, 424d125\n",
        )

    def test_coredns_rejects_unreviewed_version_output_shapes(self) -> None:
        invalid = {
            "missing platform metadata": "CoreDNS-1.14.6\n",
            "wrong version": "CoreDNS-1.14.5\nlinux/amd64, go1.26.5, 424d125\n",
            "wrong platform": "CoreDNS-1.14.6\nlinux/arm64, go1.26.5, 424d125\n",
            "unbounded Go version": "CoreDNS-1.14.6\nlinux/amd64, devel, 424d125\n",
            "wrong revision": "CoreDNS-1.14.6\nlinux/amd64, go1.26.5, deadbee\n",
            "extra line": (
                "CoreDNS-1.14.6\nlinux/amd64, go1.26.5, 424d125\nunreviewed\n"
            ),
        }

        for case, output in invalid.items():
            with self.subTest(case=case):
                with self.assertRaisesRegex(RuntimeError, "CoreDNS version mismatch"):
                    subject.verify_coredns_version(self.pins[2], output)

    def test_shadowsocks_version_remains_an_exact_single_line_contract(self) -> None:
        with mock.patch.object(subject, "require_executable"):
            with mock.patch.object(
                subject,
                "run",
                return_value="shadowsocks 1.24.0\nlinux/amd64\n",
            ):
                with self.assertRaisesRegex(RuntimeError, "sslocal version mismatch"):
                    subject.verify_shadowsocks_rust(
                        self.pins[1],
                        Path("unused"),
                        Path("unused"),
                        subject.Deadline.after(60),
                    )


class ExtractionTests(unittest.TestCase):
    def test_extraction_is_atomic_and_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "provider.tar.gz"
            destination = root / "provider"
            tar_with_members(archive, (("bin", None), ("bin/reference", b"binary")))

            subject.extract_atomic(archive, destination)

            binary = destination / "bin/reference"
            self.assertEqual(binary.read_bytes(), b"binary")
            if os.name != "nt":
                self.assertTrue(binary.stat().st_mode & os.X_OK)
            self.assertFalse(destination.with_name("provider.partial").exists())

    def test_extraction_rejects_traversal_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.tar.gz"
            destination = root / "provider"
            tar_with_members(archive, (("../escape", b"payload"),))

            with self.assertRaisesRegex(RuntimeError, "unsafe archive member"):
                subject.extract_atomic(archive, destination)

            self.assertFalse((root / "escape").exists())
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name("provider.partial").exists())

    def test_bind_prefix_is_stripped_into_the_canonical_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bind.tar.gz"
            destination = root / "bind-9.20.26"
            tar_with_members(
                archive,
                (("bind-9.20.26", None), ("bind-9.20.26/LICENSE", b"MPL-2.0")),
            )

            subject.extract_atomic(archive, destination, "bind-9.20.26")

            self.assertEqual((destination / "LICENSE").read_bytes(), b"MPL-2.0")
            self.assertFalse((destination / "bind-9.20.26").exists())


class GithubEnvironmentTests(unittest.TestCase):
    def test_mixed_statuses_are_exported_for_row_level_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / "github-env"

            subject.write_github_environment(
                environment,
                {
                    "sing_box": 0,
                    "shadowsocks_rust": 1,
                    "coredns": 1,
                    "bind": 0,
                },
            )

            self.assertEqual(
                environment.read_text(encoding="utf-8").splitlines(),
                [
                    "M2_SING_BOX_SETUP_STATUS=0",
                    "M2_SHADOWSOCKS_RUST_SETUP_STATUS=1",
                    "M12_COREDNS_SETUP_STATUS=1",
                    "M12_BIND_SETUP_STATUS=0",
                ],
            )

    def test_incomplete_statuses_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / "github-env"

            with self.assertRaisesRegex(ValueError, "cover every provider"):
                subject.write_github_environment(environment, {})


class ProvisioningTests(unittest.TestCase):
    def test_provision_dispatches_an_unrecognized_id_through_its_spec(self) -> None:
        verifier = mock.Mock()
        pin = replace(
            subject.parse_manifest(MANIFEST.read_bytes())[0],
            provider_id="future_provider",
        )
        spec = replace(
            SPECS["sing_box"],
            provider_id="future_provider",
            root_template="future-provider-{version}",
            verifier=verifier,
        )

        with mock.patch.object(subject, "download_atomic"):
            with mock.patch.object(subject, "verify_archive_members"):
                with mock.patch.object(subject, "extract_atomic"):
                    subject.provision(spec, pin, Path("work"))

        verifier.assert_called_once()
        _, root, work_root, deadline = verifier.call_args.args
        self.assertEqual(root, Path("work") / "future-provider-1.13.14")
        self.assertEqual(work_root, Path("work"))
        self.assertIsInstance(deadline, subject.Deadline)

    def test_provision_rejects_a_pin_from_a_different_strategy(self) -> None:
        pin = subject.parse_manifest(MANIFEST.read_bytes())[0]

        with self.assertRaisesRegex(ValueError, "pin and strategy do not match"):
            subject.provision(SPECS["bind"], pin, Path("unused"))

    def test_one_provider_failure_does_not_skip_later_providers(self) -> None:
        document = subject.parse_document(MANIFEST.read_bytes())
        attempted: list[str] = []

        def provision(
            _spec: subject.ProviderSpec,
            pin: subject.ProviderPin,
            _work_root: Path,
        ) -> None:
            attempted.append(pin.provider_id)
            if pin.provider_id in {"shadowsocks_rust", "coredns"}:
                raise RuntimeError("offline failure")

        with mock.patch.object(subject, "provision", side_effect=provision):
            with redirect_stderr(io.StringIO()):
                statuses = subject.provision_document(document, Path("unused"))

        self.assertEqual(
            attempted, ["sing_box", "shadowsocks_rust", "coredns", "bind"]
        )
        self.assertEqual(
            statuses,
            {
                "sing_box": 0,
                "shadowsocks_rust": 1,
                "coredns": 1,
                "bind": 0,
            },
        )

    def test_mixed_provider_result_exports_rows_without_failing_controller(self) -> None:
        statuses = {
            "sing_box": 0,
            "shadowsocks_rust": 1,
            "coredns": 1,
            "bind": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "github-env"
            arguments = [
                "interop_provision.py",
                "--manifest",
                str(MANIFEST),
                "--work-root",
                str(root / "providers"),
                "--github-env",
                str(environment),
            ]

            def provision(
                _spec: subject.ProviderSpec,
                pin: subject.ProviderPin,
                _work_root: Path,
            ) -> None:
                if statuses[pin.provider_id] != 0:
                    raise RuntimeError("offline failure")

            with mock.patch.object(sys, "argv", arguments):
                with mock.patch.object(subject, "provision", side_effect=provision):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        result = subject.main()

            self.assertEqual(result, 0)
            self.assertEqual(
                environment.read_text(encoding="utf-8").splitlines(),
                [
                    "M2_SING_BOX_SETUP_STATUS=0",
                    "M2_SHADOWSOCKS_RUST_SETUP_STATUS=1",
                    "M12_COREDNS_SETUP_STATUS=1",
                    "M12_BIND_SETUP_STATUS=0",
                ],
            )

    def test_malformed_bind_metadata_is_isolated_to_the_bind_row(self) -> None:
        original = MANIFEST.read_text(encoding="utf-8")
        mutations = {
            "source commit": original.replace(
                'source_commit = "7e228e3ba7c2ca945b1c2a22ed2ef0aa9d7cab10"',
                'source_commit = "not-a-git-commit"',
            ),
            "missing table": original.split("\n[bind]\n", maxsplit=1)[0],
            "local field": original.replace("linux_size = 5918032", "linux_size = -1"),
        }

        for case, contents in mutations.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "versions.toml"
                environment = root / "github-env"
                manifest.write_text(contents, encoding="utf-8")
                attempted: list[str] = []

                def provision(
                    _spec: subject.ProviderSpec,
                    pin: subject.ProviderPin,
                    _work_root: Path,
                ) -> None:
                    attempted.append(pin.provider_id)

                arguments = [
                    "interop_provision.py",
                    "--manifest",
                    str(manifest),
                    "--work-root",
                    str(root / "providers"),
                    "--github-env",
                    str(environment),
                ]
                with mock.patch.object(sys, "argv", arguments):
                    with mock.patch.object(subject, "provision", side_effect=provision):
                        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                            result = subject.main()

                self.assertEqual(result, 0)
                self.assertEqual(
                    attempted,
                    ["sing_box", "shadowsocks_rust", "coredns"],
                )
                self.assertEqual(
                    environment.read_text(encoding="utf-8").splitlines(),
                    [
                        "M2_SING_BOX_SETUP_STATUS=0",
                        "M2_SHADOWSOCKS_RUST_SETUP_STATUS=0",
                        "M12_COREDNS_SETUP_STATUS=0",
                        "M12_BIND_SETUP_STATUS=1",
                    ],
                )

    def test_global_manifest_failures_do_not_fabricate_provider_statuses(self) -> None:
        invalid_documents = {
            "toml syntax": b"schema_version = [",
            "schema version": MANIFEST.read_bytes().replace(
                b"schema_version = 1", b"schema_version = 2"
            ),
        }

        for case, contents in invalid_documents.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "versions.toml"
                environment = root / "github-env"
                work_root = root / "providers"
                manifest.write_bytes(contents)
                arguments = [
                    "interop_provision.py",
                    "--manifest",
                    str(manifest),
                    "--work-root",
                    str(work_root),
                    "--github-env",
                    str(environment),
                ]

                with mock.patch.object(sys, "argv", arguments):
                    with mock.patch.object(subject, "provision") as provision:
                        with self.assertRaises(
                            (ValueError, tomllib.TOMLDecodeError)
                        ):
                            subject.main()

                provision.assert_not_called()
                self.assertFalse(environment.exists())
                self.assertFalse(work_root.exists())


class CommandTests(unittest.TestCase):
    def test_nonzero_command_prints_captured_diagnostics_before_failure(self) -> None:
        result = subprocess.CompletedProcess(["provider"], 17, stdout="provider diagnostic\n")
        output = io.StringIO()

        with mock.patch.object(subject.subprocess, "run", return_value=result):
            with redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "failed with status 17: provider"):
                    subject.run(["provider", "--version"], subject.Deadline.after(60))

        self.assertEqual(output.getvalue(), "provider diagnostic\n")

    def test_timed_out_command_prints_captured_diagnostics_before_failure(self) -> None:
        timeout = subprocess.TimeoutExpired(
            ["provider"],
            60,
            output="partial provider diagnostic\n",
        )
        output = io.StringIO()

        with mock.patch.object(subject.subprocess, "run", side_effect=timeout):
            with redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "command timed out: provider"):
                    subject.run(["provider"], subject.Deadline.after(60))

        self.assertEqual(output.getvalue(), "partial provider diagnostic\n")


if __name__ == "__main__":
    unittest.main()
