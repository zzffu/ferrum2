from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap
import unittest

from support import TemporaryRepository
from tools.ci import fuzz_contract


POLICY = """
[fuzz_impact]
owner_paths = [
    "crates/ferrum2-tun/**",
    "tools/ci/fuzz_contract.py",
]
documentation_exclusions = [
    { pattern = "crates/ferrum2-tun/fuzz/*.md", kind = "markdown" },
]

[fuzz_campaign]
targets = [
    "packet_reassembly",
    "udp_reset_races",
    "config_legacy_fields",
    "strict_route_rules",
]
seconds_per_target = 900
total_seconds = 3600
"""

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_POLICY = (
    REPOSITORY_ROOT
    / "tests"
    / "m0-harness"
    / "tests"
    / "workspace_policy"
    / "architecture.toml"
)


class FuzzContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.policy_path = Path(self.temporary.name) / "architecture.toml"
        self.policy_path.write_text(textwrap.dedent(POLICY), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_load_contract_returns_reviewed_matrix_and_budget(self) -> None:
        contract = fuzz_contract.load_contract(self.policy_path)

        self.assertEqual(
            contract.targets,
            (
                "packet_reassembly",
                "udp_reset_races",
                "config_legacy_fields",
                "strict_route_rules",
            ),
        )
        self.assertEqual(contract.seconds_per_target, 900)
        self.assertEqual(
            contract.targets_json,
            '["packet_reassembly","udp_reset_races","config_legacy_fields","strict_route_rules"]',
        )

    def test_load_contract_rejects_inconsistent_total_budget(self) -> None:
        self.policy_path.write_text(
            textwrap.dedent(POLICY).replace("total_seconds = 3600", "total_seconds = 3599"),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "do not add up"):
            fuzz_contract.load_contract(self.policy_path)

    def test_load_contract_rejects_unsafe_or_duplicate_targets(self) -> None:
        for replacement, message in [
            ('"packet-reassembly"', "unsafe target"),
            ('"packet_reassembly"', "must not contain duplicates"),
        ]:
            with self.subTest(replacement=replacement):
                source = textwrap.dedent(POLICY).replace(
                    '"strict_route_rules"', replacement
                )
                self.policy_path.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    fuzz_contract.load_contract(self.policy_path)

    def test_documentation_exclusions_are_explicit_and_typed(self) -> None:
        contract = fuzz_contract.load_contract(self.policy_path)
        self.assertEqual(
            contract.documentation_exclusions,
            (
                fuzz_contract.ImpactExclusion(
                    "crates/ferrum2-tun/fuzz/*.md", "markdown"
                ),
            ),
        )

        source = textwrap.dedent(POLICY)
        for mutation in [
            source.replace('kind = "markdown"', 'kind = "source"'),
            source.replace("fuzz/*.md", "fuzz/*"),
            source.replace(
                '{ pattern = "crates/ferrum2-tun/fuzz/*.md", kind = "markdown" }',
                '{ pattern = "crates/ferrum2-tun/fuzz/*.md", kind = "markdown", '
                'reason = "broad" }',
            ),
        ]:
            with self.subTest(mutation=mutation):
                self.policy_path.write_text(mutation, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Markdown|exactly"):
                    fuzz_contract.load_contract(self.policy_path)

    def test_changed_owner_path_is_affected_and_unrelated_path_is_not(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        base = repository.commit_file("README.md", "baseline\n")
        owner_head = repository.commit_file(
            "crates/ferrum2-tun/src/lib.rs", "pub fn changed() {}\n"
        )
        contract = fuzz_contract.load_contract(self.policy_path)

        affected = fuzz_contract.classify_impact(
            contract,
            event_name="push",
            base_sha=base,
            head_sha=owner_head,
            repository=repository.root,
        )
        self.assertTrue(affected.affected)
        self.assertEqual(affected.changed_path_count, 1)

        unrelated_head = repository.commit_file("docs/notes.md", "unrelated\n")
        unaffected = fuzz_contract.classify_impact(
            contract,
            event_name="pull_request",
            base_sha=owner_head,
            head_sha=unrelated_head,
            repository=repository.root,
        )
        self.assertFalse(unaffected.affected)
        self.assertEqual(unaffected.changed_path_count, 1)

    def test_repository_policy_marks_transitive_owner_boundaries_affected(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        base = repository.commit_file("README.md", "baseline\n")
        contract = fuzz_contract.load_contract(REPOSITORY_POLICY)

        for relative in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/ferrum2-config/Cargo.toml",
            "crates/ferrum2-config/src/lib.rs",
            "crates/ferrum2-core/Cargo.toml",
            "crates/ferrum2-core/src/lib.rs",
            "crates/ferrum2-crypto/Cargo.toml",
            "crates/ferrum2-crypto/src/lib.rs",
            "crates/ferrum2-net/Cargo.toml",
            "crates/ferrum2-net/src/lib.rs",
            "crates/ferrum2-rule/Cargo.toml",
            "crates/ferrum2-rule/src/lib.rs",
            "crates/ferrum2-runtime/Cargo.toml",
            "crates/ferrum2-runtime/src/lib.rs",
            "crates/ferrum2-platform-windows/Cargo.toml",
            "crates/ferrum2-platform-windows/src/lib.rs",
            "crates/ferrum2-tun/Cargo.toml",
            "crates/ferrum2-tun/src/lib.rs",
            "crates/ferrum2-tun/fuzz/Cargo.toml",
            "crates/ferrum2-tun/fuzz/build.rs",
            "crates/ferrum2-tun/fuzz/generated_tables.rs",
            "crates/ferrum2-tun/fuzz/fuzz_targets/packet_reassembly.rs",
            "crates/ferrum2-tun/fuzz/corpus/packet_reassembly/malformed.hex",
            "crates/ferrum2-tun/tests/fixtures/packets/reassembly-v1.hex",
            "vendor/shadowsocks-crypto/Cargo.toml",
            "vendor/shadowsocks-crypto/src/lib.rs",
            "tools/ci/__init__.py",
            "tools/ci/fuzz_contract.py",
            ".github/workflows/tun-fuzz-deterministic.yml",
        ]:
            with self.subTest(relative=relative):
                head = repository.commit_file(relative, f"changed {relative}\n")
                decision = fuzz_contract.classify_impact(
                    contract,
                    event_name="push",
                    base_sha=base,
                    head_sha=head,
                    repository=repository.root,
                )
                self.assertTrue(decision.affected)
                self.assertEqual(decision.changed_path_count, 1)
                base = head

    def test_repository_policy_ignores_documentation_inside_owner_directories(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        base = repository.commit_file("README.md", "baseline\n")
        contract = fuzz_contract.load_contract(REPOSITORY_POLICY)

        for relative in [
            "crates/ferrum2-config/AGENTS.md",
            "crates/ferrum2-core/README.md",
            "crates/ferrum2-tun/AGENTS.md",
            "crates/ferrum2-tun/fuzz/README.md",
            "vendor/shadowsocks-crypto/README.md",
        ]:
            with self.subTest(relative=relative):
                head = repository.commit_file(relative, f"changed {relative}\n")
                decision = fuzz_contract.classify_impact(
                    contract,
                    event_name="push",
                    base_sha=base,
                    head_sha=head,
                    repository=repository.root,
                )
                self.assertFalse(decision.affected)
                self.assertEqual(decision.changed_path_count, 1)
                base = head

    def test_repository_policy_does_not_charge_platform_qualification_to_fuzz(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        base = repository.commit_file("README.md", "baseline\n")
        contract = fuzz_contract.load_contract(REPOSITORY_POLICY)

        for relative in [
            "tests/platform/Main.CampaignController.ps1",
            "tools/powershell/Ferrum2.Performance/HostContract.ps1",
            "tools/windows-tun/performance/run_windows_tun_performance_hyperv.ps1",
            "tools/windows_tun_hyperv_support_topology_plan.json",
            "tools/windows_tun_performance_policy.json",
        ]:
            with self.subTest(relative=relative):
                head = repository.commit_file(relative, f"changed {relative}\n")
                decision = fuzz_contract.classify_impact(
                    contract,
                    event_name="push",
                    base_sha=base,
                    head_sha=head,
                    repository=repository.root,
                )
                self.assertFalse(decision.affected)
                self.assertEqual(decision.changed_path_count, 1)
                base = head

    def test_owner_source_renamed_to_markdown_remains_affected(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        source = "crates/ferrum2-tun/src/retired.rs"
        destination = "docs/retired-tun-code.md"
        base = repository.commit_file(source, "pub fn retired() {}\n")
        (repository.root / destination).parent.mkdir(parents=True, exist_ok=True)
        repository.git("mv", "--", source, destination)
        repository.git("commit", "--quiet", "-m", "retire TUN source as documentation")
        head = repository.git("rev-parse", "HEAD")
        contract = fuzz_contract.load_contract(self.policy_path)

        decision = fuzz_contract.classify_impact(
            contract,
            event_name="push",
            base_sha=base,
            head_sha=head,
            repository=repository.root,
        )

        self.assertTrue(decision.affected)
        self.assertEqual(decision.changed_path_count, 2)

    def test_markdown_renamed_to_owner_source_is_affected(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        source = "docs/future-tun-code.md"
        destination = "crates/ferrum2-tun/src/promoted.rs"
        base = repository.commit_file(source, "design notes\n")
        (repository.root / destination).parent.mkdir(parents=True, exist_ok=True)
        repository.git("mv", "--", source, destination)
        repository.git("commit", "--quiet", "-m", "promote documentation to TUN source")
        head = repository.git("rev-parse", "HEAD")
        contract = fuzz_contract.load_contract(self.policy_path)

        decision = fuzz_contract.classify_impact(
            contract,
            event_name="push",
            base_sha=base,
            head_sha=head,
            repository=repository.root,
        )

        self.assertTrue(decision.affected)
        self.assertEqual(decision.changed_path_count, 2)

    def test_unknown_event_and_unavailable_base_fail_closed(self) -> None:
        contract = fuzz_contract.load_contract(self.policy_path)
        repository = Path(self.temporary.name)

        unknown = fuzz_contract.classify_impact(
            contract,
            event_name="schedule",
            base_sha="base",
            head_sha="head",
            repository=repository,
        )
        unavailable = fuzz_contract.classify_impact(
            contract,
            event_name="push",
            base_sha="0" * 40,
            head_sha="head",
            repository=repository,
        )

        self.assertTrue(unknown.affected)
        self.assertTrue(unavailable.affected)

    def test_cli_writes_all_downstream_outputs_from_one_contract(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        head = repository.commit_file("README.md", "baseline\n")
        output = Path(self.temporary.name) / "github-output"
        summary = Path(self.temporary.name) / "github-summary"

        result = fuzz_contract.main(
            [
                "--policy",
                str(self.policy_path),
                "--repository",
                str(repository.root),
                "--event-name",
                "workflow_dispatch",
                "--head-sha",
                head,
                "--github-output",
                str(output),
                "--github-summary",
                str(summary),
            ]
        )

        self.assertEqual(result, 0)
        self.assertEqual(
            output.read_text(encoding="utf-8").splitlines(),
            [
                "affected=true",
                'targets_json=["packet_reassembly","udp_reset_races","config_legacy_fields","strict_route_rules"]',
                "seconds_per_target=900",
            ],
        )
        self.assertIn(
            "manual dispatch has no trusted comparison range",
            summary.read_text(encoding="utf-8"),
        )

    def test_cli_derives_per_target_budget_from_the_policy(self) -> None:
        source = textwrap.dedent(POLICY)
        source = source.replace(
            '    "config_legacy_fields",\n    "strict_route_rules",\n', ""
        )
        source = source.replace("seconds_per_target = 900", "seconds_per_target = 1800")
        self.policy_path.write_text(source, encoding="utf-8")
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        head = repository.commit_file("README.md", "baseline\n")
        output = Path(self.temporary.name) / "derived-budget-output"
        summary = Path(self.temporary.name) / "derived-budget-summary"

        result = fuzz_contract.main(
            [
                "--policy",
                str(self.policy_path),
                "--repository",
                str(repository.root),
                "--event-name",
                "workflow_dispatch",
                "--head-sha",
                head,
                "--github-output",
                str(output),
                "--github-summary",
                str(summary),
            ]
        )

        self.assertEqual(result, 0)
        self.assertIn("seconds_per_target=1800", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
