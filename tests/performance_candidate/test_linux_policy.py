import copy
import pathlib
import tempfile
import unittest

from tests.performance_candidate._shared_fixture import POLICY_PATH, synthetic_policy
from tools.performance_candidate import json_contract
from tools.performance_candidate.linux import catalog as linux_catalog
from tools.performance_candidate.linux import plan as linux_plan
from tools.performance_candidate.linux import policy as linux_policy


class DecisionPolicyTests(unittest.TestCase):
    def test_repository_policy_records_exact_reviewed_calibration(self) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        self.assertEqual(policy["schema_version"], 4)
        self.assertRegex(policy["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            policy["policy_id"],
            "github-hosted-amd-provisional-profiling-v4-reviewed-3aa0c25",
        )
        self.assertEqual(
            policy["authority"], linux_policy.HOSTED_AMD_PROVISIONAL_AUTHORITY
        )
        self.assertEqual(linux_plan.PLAN_SCHEMA_VERSION, 11)
        self.assertEqual(linux_catalog.SUMMARY_SCHEMA_VERSION, 10)
        self.assertEqual(set(policy["scenarios"]), set(linux_catalog.SCENARIO_CATALOG))

        expected_thresholds = {
            "dns-cache-size-4096": (208.9, -261.2, 261.2),
            "dns-cache-size-64": (4.8, -6.0, 6.0),
            "dns-cache-size-65536": (67.8, -84.8, 84.8),
            "dns-udp-concurrency": (0.6, -1.1, 1.1),
            "socks-direct-request-16k": (2.4, -3.0, 3.0),
            "socks-direct-request-1k": (1.9, -2.4, 2.4),
            "socks-direct-request-4k": (1.3, -1.8, 1.8),
            "tcp-bulk": (29.2, -36.5, 36.5),
            "tcp-request-16k": (2.5, -3.2, 3.2),
            "tcp-request-1k": (1.5, -2.0, 2.0),
            "tcp-request-4k": (1.8, -2.3, 2.3),
            "tcp-stream-64k": (97.4, -121.8, 121.8),
            "udp-direct-max-65497": (6.0, -7.5, 7.5),
            "udp-direct-small-128": (2.7, -3.4, 3.4),
            "udp-max-wire-65507": (0.6, -1.1, 1.1),
            "udp-mtu-1200": (0.7, -1.2, 1.2),
            "udp-payload-1472": (0.9, -1.4, 1.4),
            "udp-payload-1500": (0.8, -1.3, 1.3),
            "udp-payload-8192": (1.1, -1.6, 1.6),
            "udp-replay-sequential": (0.4, -0.9, 0.9),
            "udp-response-concurrency-1": (1.9, -2.4, 2.4),
            "udp-response-concurrency-32": (3.1, -3.9, 3.9),
            "udp-response-concurrency-8": (1.9, -2.4, 2.4),
            "udp-small-high": (0.9, -1.4, 1.4),
        }

        calibration_groups = {
            "artifact:github-actions/runs/33167994941/tcp-frame-capacity@sha256:63497ef75710d1401fed94f431d44816ede41c8a9e27beb00c573f15610bf038": {
                "cpu_model": "AMD EPYC 7763 64-Core Processor",
                "scenarios": {
                    "tcp-bulk",
                    "tcp-request-16k",
                    "tcp-request-1k",
                    "tcp-request-4k",
                    "tcp-stream-64k",
                },
            },
            "artifact:github-actions/runs/33167996757/udp-payload-matrix@sha256:fa6486c0c62102b8ab90a853c722c4b5f23de851db4a85c611ec0e1f6ffa5964": {
                "cpu_model": "INTEL(R) XEON(R) PLATINUM 8573C",
                "scenarios": {
                    "udp-max-wire-65507",
                    "udp-mtu-1200",
                    "udp-payload-1472",
                    "udp-payload-1500",
                    "udp-payload-8192",
                    "udp-small-high",
                },
            },
            "artifact:github-actions/runs/33167998891/udp-direct-payload-bounds@sha256:01168520f1b055d9e85aed23fe477b2fb03392c3718f2d89e6127878f8dcb017": {
                "cpu_model": "AMD EPYC 7763 64-Core Processor",
                "scenarios": {
                    "udp-direct-max-65497",
                    "udp-direct-small-128",
                },
            },
            "artifact:github-actions/runs/33168000820/udp-response-concurrency-32@sha256:f7bf74f5badea8b783fabf4142fd17304efa40f247f47aa0e92807ca04f6aae0": {
                "cpu_model": "INTEL(R) XEON(R) PLATINUM 8573C",
                "scenarios": {
                    "udp-response-concurrency-1",
                    "udp-response-concurrency-32",
                    "udp-response-concurrency-8",
                },
            },
            "artifact:github-actions/runs/33168002486/udp-replay-sequential@sha256:8e5c5a020f92f37b962597dfa79021916c77e635a276ace01178d67282a85e6e": {
                "cpu_model": "AMD EPYC 9V74 80-Core Processor",
                "scenarios": {
                    "udp-replay-sequential",
                },
            },
            "artifact:github-actions/runs/33168004087/dns-udp-concurrency@sha256:34833964a783190490e4492a71d74da346ce2ded7f2f38e03b242311ad399c33": {
                "cpu_model": "AMD EPYC 9V74 80-Core Processor",
                "scenarios": {
                    "dns-udp-concurrency",
                },
            },
            "artifact:github-actions/runs/33168006440/socks-direct-request-1k@sha256:e621c62e33fc78de60e5d0c2ee5ba138903a1e57b657bd231ed8fd0b90c66289": {
                "cpu_model": "AMD EPYC 9V74 80-Core Processor",
                "scenarios": {
                    "socks-direct-request-16k",
                    "socks-direct-request-1k",
                    "socks-direct-request-4k",
                },
            },
            "artifact:github-actions/runs/33168008479/dns-cache-size-64@sha256:1d43d87b6390635b2c3ffcc67d781d8c94f8c45ea8a2e3b128a27cdf0646b495": {
                "cpu_model": "AMD EPYC 9V74 80-Core Processor",
                "scenarios": {
                    "dns-cache-size-4096",
                    "dns-cache-size-64",
                    "dns-cache-size-65536",
                },
            },
        }

        expected_contracts = {
            "dns-cache-size-4096": (
                "da93f99e386812c1977f638c28908df0e4f234e8a1d9c38e38665581fa80f485",
                "b6e77f1455c86994b20a75a005e3052ab1aa919c08fea947ae96dcfaf935970f",
            ),
            "dns-cache-size-64": (
                "d364bfeb215e194307bed84339376233f45d4d8f343cac999bce46eb99b649a1",
                "753c57a60ce6d2537b4c06382d1878770acfdfb145cb543ac37f84a8b5757056",
            ),
            "dns-cache-size-65536": (
                "09b581f277b58b161ba7236e37a653d03ddae61629acf03881934fd3804fde07",
                "ee64845ba5982db0e772479823e1050dc8ae92167905adef82156f62883cde4a",
            ),
            "dns-udp-concurrency": (
                "e21e2e7cf730484beafba57892937947206cfed056035b1fe8d8c7986b3f1375",
                "c93353bbe5c17103410cbda256e7a75173dd589df16bc60939735272471c770f",
            ),
            "socks-direct-request-16k": (
                "5f6a1e36de16cb8d1d65d90c4c4148b021470b1ffefd7625379e83c28d212c38",
                "3772d4ace54bf15275e6581f7e0e2a5a7390d1fe325effd711b4241cb3db8d40",
            ),
            "socks-direct-request-1k": (
                "d5b1bd66fe9ce57426d2ad5954a891f87d0f9fb6a4dd419dae2e0584a98b0b7a",
                "fc3e10d943a26f0b4b3fecf9cb788ed3b5c11388b4b4829517df2c945ff55fdf",
            ),
            "socks-direct-request-4k": (
                "016da3ea673d944912367b961f1d887ab41354a5a99cead953501405e3c20122",
                "c13b7b6ef3500673c3cd7e0435ec6e747b72b697147b8076d8c59f7288522e87",
            ),
            "tcp-bulk": (
                "9b5480168c65a37566bf3d6fb9f3d9b7ed118023e122f50fc5192920351a5912",
                "8835d0d970820b101f38c9e5ad5efde2283c63f4e459b9859309e8ac14c283a0",
            ),
            "tcp-request-16k": (
                "e8139375c49910a711bed39edfd87e7938444cc049a1cb4d0c9608a60260fb67",
                "5116baec13f88f92ed2f3910270c74d0c8fa91c97e35e0b4a9643cb40aa9ed73",
            ),
            "tcp-request-1k": (
                "62ac4e0c8c49806a71b532899f042065917e983257ec75b191e200ac9968b5a7",
                "85aed86e20573fe2070ab7deeaa8e2706200802052cc8b5255cb1908dfbdf8dc",
            ),
            "tcp-request-4k": (
                "4965a788c71b969020c20d1f994b0316a2017773e5648fb780e210ca986ebb5c",
                "6c99669d720c8a0deaa6ba5c83861e3d2c574ec7bcd580535ec349778a374bb6",
            ),
            "tcp-stream-64k": (
                "6a611615a261a84ec48913b6df68020de6433641dad6640cb45ba27d8193a368",
                "bf98b85fcb81e717ff5486b129d318527a7557fb8106cf97f5434eef739e5690",
            ),
            "udp-direct-max-65497": (
                "b1b91755a3c8fe1e9b7d4f5988c6956b891532b05971d5b792056ada86c3ebb2",
                "ee008b99592a78bab283f0cafa8e938d18483eb9631e3efe306a9a8726b50d21",
            ),
            "udp-direct-small-128": (
                "94782d0a88a6e8b46abd734d1e22819c17af1f4ba0591b1cdbff63b05e0fa5a1",
                "391872c0e23664c0fdd824ffe6ff80c5afca53a62ace345949eeb0f740e4aff9",
            ),
            "udp-max-wire-65507": (
                "2294390097de98b4c8095aae08459789c18f74a8addfbe9e7b26d24aa184cf01",
                "94c38f9eef59be7f6effbc0d06e89b065b99e1ba2f3297ac6681d5a393338b89",
            ),
            "udp-mtu-1200": (
                "2e9848e3e5abf9996b2d48948ba68876475fe5ffaaf075d8abf3a4872553b09d",
                "634ee4ad568e672f53a253f1ef7d43d7a13c34dd0dca18c662571ed5181c8b88",
            ),
            "udp-payload-1472": (
                "a73fb9c5e4ccb564330666988380757416c1c9e1eddb629381e7d9f5879e4c48",
                "26b42c2df6350d373ef51a1de2e7e9839b4605b398e60e336129fe956f58ceb1",
            ),
            "udp-payload-1500": (
                "e93fe1fb7b365f248c29543aeebe442c403c49d358036d2e2e0f875949915a55",
                "8a353cb7d6adbd2f78d9f8072942dd16c7be7865565e47f4ca36437e82c61a0e",
            ),
            "udp-payload-8192": (
                "aa0d02920d7d8ef5fd2ef24bb3683c5af15f0015ae91bda7201159b18de2bd79",
                "1ee14dcccaa22f70fdeb32c594cd2d41a4d8d9f5ba1168b13661ebdf76d25da8",
            ),
            "udp-replay-sequential": (
                "378e047a23dc0b4b17da8829770f8112cd3079856d26618b9b7abb3068716029",
                "67ae76943d155ed78ca2a160c0d8c4250d4bb09a20bd4b9a78b3503b421e813b",
            ),
            "udp-response-concurrency-1": (
                "71ffb7468433d3b88e7b9370aa365f5187ab0bfcd6f5b05311ee70acdc1c63e1",
                "1a4e3331017f1aa4b8b4dfd19ecb295ec9ac56918bd6c54309f9328ae1187137",
            ),
            "udp-response-concurrency-32": (
                "c04e92b13540e73896dbc5723375191cfce490c0d7a8b8455117dcd132fefcb0",
                "6a6690fed78e267f60483707396125c88c479d13526ce85f5d4de651599fdfdc",
            ),
            "udp-response-concurrency-8": (
                "d8616f7e32c20dbfa132e7b9dbbb4fe4d65652c64436e76cc10dd99568d8c3e3",
                "955218a32ab450e01956562c2ad9ca4c0749e507cf039dd94c1a4e32e6383992",
            ),
            "udp-small-high": (
                "9fa0b010c963194e4427d59cfa87ff773a744c2f61bf8402b91209ff3f62d009",
                "2cc2074ca92ef03e17304115c00f69cd02dbb73e778d810f34f3bc7c50adfbb7",
            ),
        }

        expected_fixed_environment = {
            "active_seconds": 30,
            "build_profile": "current",
            "cargo_profile": "profiling",
            "controller_source_sha256": "59d1933d6f86449080c945cd193167773770bc8d036473b771a65da4696149ef",
            "cpu_count": 4,
            "evidence_build_profile": "current",
            "kernel": "Linux 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 GNU/Linux",
            "memory_kib": 16384000,
            "pair_schedule": "abba-six-pairs",
            "producer_source_sha256": "91000577aee297545298a2c2f49550895b83d04618c29bd99bebc1f28c4f2fe2",
            "runner_arch": "X64",
            "runner_image": "ubuntu-24.04",
            "runner_os": "Linux",
            "rust_toolchain": "1.97.1",
            "rustc": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
            "warmup_seconds": 3,
        }
        expected_sources = {}
        expected_cpu_models = {}
        for source, group in calibration_groups.items():
            for scenario in group["scenarios"]:
                expected_sources[scenario] = source
                expected_cpu_models[scenario] = group["cpu_model"]

        calibrated_scenarios = {
            scenario
            for scenario, entry in policy["scenarios"].items()
            if entry["calibration_environment"] is not None
        }
        self.assertEqual(calibrated_scenarios, set(expected_thresholds))
        self.assertEqual(calibrated_scenarios, set(linux_catalog.SCENARIO_CATALOG))
        self.assertEqual(len(calibrated_scenarios), 24)
        self.assertEqual(set(policy["scenarios"]) - calibrated_scenarios, set())
        self.assertEqual(set(expected_sources), set(expected_thresholds))

        for scenario, entry in policy["scenarios"].items():
            with self.subTest(scenario=scenario):
                calibrated = [
                    entry[field]
                    for field in (
                        "noise_band_percent",
                        "regression_threshold_percent",
                        "adoption_threshold_percent",
                        "minimum_pairs",
                        "minimum_wins",
                        "minimum_losses",
                        "calibration_source",
                        "calibration_environment",
                    )
                ]
                self.assertTrue(all(value is not None for value in calibrated))
                self.assertEqual(
                    (
                        entry["noise_band_percent"],
                        entry["regression_threshold_percent"],
                        entry["adoption_threshold_percent"],
                    ),
                    expected_thresholds[scenario],
                )
                self.assertEqual(
                    (
                        entry["minimum_pairs"],
                        entry["minimum_wins"],
                        entry["minimum_losses"],
                    ),
                    (6, 5, 4),
                )
                self.assertEqual(
                    entry["calibration_source"], expected_sources[scenario]
                )
                environment = entry["calibration_environment"]
                self.assertEqual(
                    set(environment), linux_policy.CALIBRATION_ENVIRONMENT_FIELDS
                )
                self.assertEqual(
                    {field: environment[field] for field in expected_fixed_environment},
                    expected_fixed_environment,
                )
                self.assertEqual(
                    environment["cpu_model"], expected_cpu_models[scenario]
                )
                self.assertEqual(
                    (
                        environment["semantic_recipe_sha256"],
                        environment["evidence_bundle_sha256"],
                    ),
                    expected_contracts[scenario],
                )

    def test_repository_policy_is_stale_after_timed_controller_closure_correction(
        self,
    ) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        selections = (
            *sorted(linux_catalog.QUALIFICATION_GROUPS),
            *sorted(linux_catalog.SCENARIO_CATALOG),
        )
        for selection in selections:
            with self.subTest(selection=selection):
                plan = linux_plan.create_plan(
                    mode="qualification",
                    selection=selection,
                    warmup_seconds="3",
                    active_seconds="30",
                    pairs="6",
                    decision_policy=policy,
                )
                self.assertFalse(plan["adoption_eligible"])
                self.assertEqual(
                    plan["authority"],
                    linux_policy.HOSTED_AMD_PROVISIONAL_AUTHORITY,
                )
                for scenario in plan["scenarios"]:
                    contract = scenario["evidence_contract"]
                    for field in (
                        "producer_source_sha256",
                        "controller_source_sha256",
                        "semantic_recipe_sha256",
                        "evidence_bundle_sha256",
                    ):
                        self.assertRegex(contract[field], r"^[0-9a-f]{64}$")

        # Static eligibility proves complete recipe identity. Approved-host A/B
        # comparisons remain split because the structural union spans two CPU classes.
        structural_cpu_models = {
            policy["scenarios"][scenario]["calibration_environment"]["cpu_model"]
            for scenario in linux_catalog.STRUCTURAL_MATRIX_SCENARIOS
        }
        self.assertEqual(
            structural_cpu_models,
            {
                "AMD EPYC 9V74 80-Core Processor",
                "INTEL(R) XEON(R) PLATINUM 8573C",
            },
        )

    def test_policy_schema_rejects_shape_identity_and_partial_calibration_errors(
        self,
    ) -> None:
        mutations = {
            "obsolete schema": lambda policy: policy.update(schema_version=3),
            "missing authority": lambda policy: policy.pop("authority"),
            "authoritative hosted": lambda policy: policy["authority"].update(
                performance_authoritative=True
            ),
            "integer false authority": lambda policy: policy["authority"].update(
                performance_authoritative=0
            ),
            "bare metal claim": lambda policy: policy["authority"].update(
                bare_metal_gate_satisfied=True
            ),
            "durable claim": lambda policy: policy["authority"].update(
                durable_evidence_gate_satisfied=True
            ),
            "authority extra field": lambda policy: policy["authority"].update(
                unexpected=False
            ),
            "missing scenario": lambda policy: policy["scenarios"].pop("tcp-bulk"),
            "wrong metric": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                metric="p99_nanoseconds"
            ),
            "partial calibration": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(calibration_source=None),
            "threshold inside noise": lambda policy: policy["scenarios"][
                "tcp-bulk"
            ].update(regression_threshold_percent=-1.0),
            "boolean count": lambda policy: policy["scenarios"]["tcp-bulk"].update(
                minimum_wins=True
            ),
            "boolean recipe": lambda policy: policy["scenarios"]["tcp-bulk"][
                "calibration_environment"
            ].update(warmup_seconds=True),
            "unaligned memory capacity": lambda policy: policy["scenarios"]["tcp-bulk"][
                "calibration_environment"
            ].update(memory_kib=16_777_215),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                policy = synthetic_policy()
                mutation(policy)
                with self.assertRaises(json_contract.CandidateControlError):
                    linux_policy.validate_decision_policy(policy)

    def test_policy_loader_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-json-") as directory:
            root = pathlib.Path(directory)
            for name, text in (
                ("duplicate", '{"schema_version":4,"schema_version":4}'),
                (
                    "non-finite",
                    '{"schema_version":4,"policy_id":"x","authority":{},"scenarios":NaN}',
                ),
            ):
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(json_contract.CandidateControlError):
                        linux_policy.load_decision_policy(path)

    def test_canonical_plan_rejects_policy_digest_or_threshold_tampering(self) -> None:
        policy = linux_policy.load_decision_policy(POLICY_PATH)
        plan = linux_plan.create_plan(
            mode="qualification",
            selection="tcp-stream-64k",
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            decision_policy=policy,
        )
        with tempfile.TemporaryDirectory(prefix="ferrum2-policy-plan-") as directory:
            path = pathlib.Path(directory) / "plan.json"
            for name, mutate in (
                (
                    "schema version",
                    lambda value: value.update(schema_version=9),
                ),
                (
                    "digest",
                    lambda value: value["decision_policy"].update(
                        policy_sha256="0" * 64
                    ),
                ),
                (
                    "threshold",
                    lambda value: value["decision_policy"]["scenarios"][
                        "tcp-bulk"
                    ].update(noise_band_percent=2.0),
                ),
            ):
                with self.subTest(name=name):
                    tampered = copy.deepcopy(plan)
                    mutate(tampered)
                    linux_plan.write_plan(path, tampered)
                    with self.assertRaises(json_contract.CandidateControlError):
                        linux_plan.load_plan(path, decision_policy=policy)

    def test_calibrated_policy_matches_one_nearest_memory_capacity_class(self) -> None:
        policy = synthetic_policy(calibrated_scenarios={"tcp-bulk"})
        plan = linux_plan.create_plan(
            mode="qualification",
            selection="tcp-stream-64k",
            warmup_seconds="3",
            active_seconds="30",
            pairs="6",
            decision_policy=policy,
        )
        scenario = next(
            entry for entry in plan["scenarios"] if entry["scenario"] == "tcp-bulk"
        )
        entry = policy["scenarios"]["tcp-bulk"]
        calibrated = entry["calibration_environment"]
        observed = {
            field: calibrated[field]
            for field in (
                "runner_image",
                "rustc",
                "kernel",
                "cpu_model",
                "cpu_count",
                "memory_kib",
                "build_profile",
            )
        }

        def applicable(environment: dict[str, object]) -> bool:
            return linux_policy._scenario_policy_is_applicable(
                entry=entry,
                scenario_plan=scenario,
                warmup_seconds=3,
                active_seconds=30,
                pairs=6,
                observed_environment=environment,
            )

        anchor = observed["memory_kib"]
        for memory_kib in (anchor - 32_768, anchor + 32_767):
            with self.subTest(memory_kib=memory_kib):
                boundary = dict(observed)
                boundary["memory_kib"] = memory_kib
                self.assertTrue(applicable(boundary))

        for memory_kib in (anchor - 32_769, anchor + 32_768):
            with self.subTest(memory_kib=memory_kib):
                outside = dict(observed)
                outside["memory_kib"] = memory_kib
                self.assertFalse(applicable(outside))

        for field, value in (
            ("cpu_model", "different-cpu"),
            ("kernel", "different-kernel"),
        ):
            with self.subTest(field=field):
                changed = dict(observed)
                changed[field] = value
                self.assertFalse(applicable(changed))

        with_extra = {**observed, "unexpected": "field"}
        self.assertFalse(applicable(with_extra))
        missing = dict(observed)
        missing.pop("kernel")
        self.assertFalse(applicable(missing))
