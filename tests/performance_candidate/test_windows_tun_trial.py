import copy
import json
import pathlib
import tempfile
from decimal import Decimal

from tests.performance_candidate._shared_fixture import WINDOWS_TUN_POLICY_PATH
from tests.performance_candidate._windows_tun_trial_support import WindowsTunTrialSupport
from tools.performance_candidate import cli as controller_cli
from tools.performance_candidate import json_contract
from tools.performance_candidate import pairing as paired_stats
from tools.performance_candidate.windows_tun import plan as windows_plan
from tools.performance_candidate.windows_tun import trial as windows_trial

class WindowsTunTrialTests(WindowsTunTrialSupport):
    def test_trial_rejects_unit_correctness_and_order_tampering(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = []
        wrong_unit = copy.deepcopy(row)
        wrong_unit["measurements"]["throughput"]["unit"] = "bits_per_second"
        cases.append((wrong_unit, "unit mismatch"))
        wrong_check = copy.deepcopy(row)
        wrong_check["correctness"]["checks"]["payload_exact"] = False
        cases.append((wrong_check, "correctness check failed"))
        wrong_order = copy.deepcopy(row)
        wrong_order["order"] = 2
        cases.append((wrong_order, "alternating"))
        wrong_sequence = copy.deepcopy(row)
        wrong_sequence["sequence"] = 2
        cases.append((wrong_sequence, "planned sequence"))
        wrong_controller = copy.deepcopy(row)
        wrong_controller["controller_bundle_sha256"] = "d" * 64
        cases.append((wrong_controller, "controller_bundle_sha256"))
        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(json_contract.CandidateControlError, message):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_trial_rejects_invalid_dynamic_topology_identity(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = {
            "checkpoint_id": "00000000-0000-0000-0000-000000000000",
            "support_switch_id": "not-a-guid",
            "topology_manifest_sha256": "A" * 64,
            "topology_plan_sha256": True,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                candidate = copy.deepcopy(row)
                candidate["environment"][field] = value
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError, rf"{field} is invalid"
                ):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_trial_sequence_is_strictly_typed_and_uniquely_plan_bound(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        for value in (True, 1.0, "1", 0, 91):
            with self.subTest(sequence=value):
                candidate = copy.deepcopy(row)
                candidate["sequence"] = value
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError, "sequence"
                ):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for name, mutate in (
            (
                "scenario",
                lambda value: value.update(scenario="tcp-256-flow-fairness"),
            ),
            (
                "pair-member-order",
                lambda value: value.update(pair=2, member="candidate", order=1),
            ),
        ):
            with self.subTest(identity=name):
                candidate = copy.deepcopy(row)
                mutate(candidate)
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError, "planned sequence"
                ):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for name, index, replacement in (
            ("duplicate", 1, 1),
            ("missing", 0, 108),
        ):
            with self.subTest(plan_sequence=name):
                tampered_plan = copy.deepcopy(plan)
                tampered_plan["trials"][index]["sequence"] = replacement
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError,
                    "sequence does not uniquely match the plan",
                ):
                    windows_trial.validate_windows_tun_trial(
                        row,
                        plan=tampered_plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

        for field, value in (("pair", True), ("order", 1.0)):
            with self.subTest(plan_identity=field):
                tampered_plan = copy.deepcopy(plan)
                tampered_plan["trials"][0][field] = value
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError,
                    "planned trial identity is invalid",
                ):
                    windows_trial.validate_windows_tun_trial(
                        row,
                        plan=tampered_plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_udp_association_source_preflight_is_required_and_scenario_scoped(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        association = self.row(
            plan=plan,
            scenario="udp-8192-association-lookup-expiry",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        windows_trial.validate_windows_tun_trial(
            association,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        missing = copy.deepcopy(association)
        missing["diagnostics"] = None
        with self.assertRaisesRegex(
            json_contract.CandidateControlError,
            "UDP association.*diagnostics must be an object",
        ):
            windows_trial.validate_windows_tun_trial(
                missing,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

        tcp = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        tcp["diagnostics"] = copy.deepcopy(association["diagnostics"])
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "non-fragment.*must be null"
        ):
            windows_trial.validate_windows_tun_trial(
                tcp,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_udp_association_source_preflight_rejects_contract_tampering(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="udp-8192-association-lookup-expiry",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        def dynamic_intersection(diagnostics: dict[str, object]) -> None:
            preflight = diagnostics["udp_association_source_preflight"]
            dynamic_range = preflight["dynamic_port_range"]
            dynamic_range.update(
                first_port=20_000,
                last_port=28_191,
                port_count=8_192,
            )
            lines = preflight["dynamic_port_udp"]["lines"]
            lines[-2:] = [
                "Start Port      : 20000",
                "Number of Ports : 8192",
            ]

        def excluded_intersection(diagnostics: dict[str, object]) -> None:
            preflight = diagnostics["udp_association_source_preflight"]
            preflight["excluded_port_ranges"].append(
                {"first_port": 20_000, "last_port": 20_010}
            )
            snapshot = preflight["excluded_port_ranges_udp"]
            snapshot["lines"].append("     20000       20010")
            snapshot["total_lines"] += 1

        mutations = (
            ("diagnostics field", lambda d: d.update(unexpected=None)),
            (
                "preflight field",
                lambda d: d["udp_association_source_preflight"].update(
                    unexpected=None
                ),
            ),
            (
                "schema",
                lambda d: d["udp_association_source_preflight"].update(
                    schema="ferrum2.windows-tun.udp-fixed-source-preflight.v2"
                ),
            ),
            (
                "captured timestamp",
                lambda d: d["udp_association_source_preflight"].update(
                    captured_utc="2026-08-22T00:00:00Z"
                ),
            ),
            (
                "source IP",
                lambda d: d["udp_association_source_preflight"][
                    "source_contract"
                ].update(source_ip="198.18.0.3"),
            ),
            (
                "source port",
                lambda d: d["udp_association_source_preflight"][
                    "source_contract"
                ].update(source_port_first=20_001),
            ),
            (
                "source count",
                lambda d: d["udp_association_source_preflight"][
                    "source_contract"
                ].update(source_port_count=8_191),
            ),
            (
                "adapter count type",
                lambda d: d["udp_association_source_preflight"]["adapter"].update(
                    match_count=True
                ),
            ),
            (
                "adapter state",
                lambda d: d["udp_association_source_preflight"]["adapter"][
                    "matches"
                ][0].update(status="Down"),
            ),
            (
                "IP owner index",
                lambda d: d["udp_association_source_preflight"]["ip_owner"][
                    "matches"
                ][0].update(interface_index=18),
            ),
            (
                "endpoint conflict",
                lambda d: d["udp_association_source_preflight"][
                    "udp_endpoint_conflicts"
                ].update(count=1),
            ),
            (
                "dynamic snapshot command",
                lambda d: d["udp_association_source_preflight"][
                    "dynamic_port_udp"
                ].update(command="netsh.exe interface ipv6 show dynamicport udp"),
            ),
            ("dynamic intersection", dynamic_intersection),
            ("excluded intersection", excluded_intersection),
            (
                "unexpected excluded intersection report",
                lambda d: d["udp_association_source_preflight"].update(
                    excluded_port_intersections=[
                        {"first_port": 20_000, "last_port": 20_010}
                    ]
                ),
            ),
            (
                "invalid result",
                lambda d: d["udp_association_source_preflight"].update(valid=False),
            ),
            (
                "violation",
                lambda d: d["udp_association_source_preflight"].update(
                    violations=["source_port_conflict"]
                ),
            ),
            (
                "error",
                lambda d: d["udp_association_source_preflight"].update(
                    errors=["query failed"]
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                candidate = copy.deepcopy(row)
                mutate(candidate["diagnostics"])
                with self.assertRaises(json_contract.CandidateControlError):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_ring_pressure_diagnostics_accept_zero_and_positive_drop_accounting(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        for member, regression, expected_drop_rate in (
            ("parent", False, 0),
            ("candidate", True, 1_100),
        ):
            with self.subTest(member=member, regression=regression):
                row = self.row(
                    plan=plan,
                    scenario="wintun-ring-full-drop-rate",
                    pair=1,
                    member=member,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                    regression=regression,
                )
                windows_trial.validate_windows_tun_trial(
                    row,
                    plan=plan,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )
                self.assertEqual(
                    row["measurements"]["drop_rate"]["value"],
                    expected_drop_rate,
                )
                self.assertEqual(
                    row["correctness"]["checked_units"],
                    row["diagnostics"]["tun_response_attempts"],
                )

    def test_ring_pressure_diagnostics_enforce_minimum_response_sample(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="wintun-ring-full-drop-rate",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        minimum = plan["scenarios"]["wintun-ring-full-drop-rate"][
            "minimum_checked_units"
        ]
        self.assertEqual(minimum, 32_768)
        windows_trial.validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        below_minimum = copy.deepcopy(row)
        below_minimum["correctness"]["checked_units"] = minimum - 1
        below_minimum["diagnostics"]["tun_packets_egress"] = minimum - 1
        below_minimum["diagnostics"]["tun_response_attempts"] = minimum - 1
        with self.assertRaises(json_contract.CandidateControlError):
            windows_trial.validate_windows_tun_trial(
                below_minimum,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_ring_pressure_diagnostics_reject_closed_accounting_tampering(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="wintun-ring-full-drop-rate",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        mutations = (
            ("missing diagnostics", lambda r: r.update(diagnostics=None)),
            (
                "extra diagnostics field",
                lambda r: r["diagnostics"].update(unexpected=0),
            ),
            (
                "schema",
                lambda r: r["diagnostics"].update(schema_version=2),
            ),
            (
                "kind",
                lambda r: r["diagnostics"].update(kind="ring_full_events"),
            ),
            (
                "workload attempts",
                lambda r: r["diagnostics"].update(
                    workload_attempted_datagrams=999_999
                ),
            ),
            (
                "egress accounting",
                lambda r: r["diagnostics"].update(tun_packets_egress=32_767),
            ),
            (
                "ring drop accounting",
                lambda r: r["diagnostics"].update(wintun_ring_full_dropped=1),
            ),
            (
                "response accounting",
                lambda r: r["diagnostics"].update(tun_response_attempts=32_769),
            ),
            (
                "correctness denominator",
                lambda r: r["correctness"].update(checked_units=32_769),
            ),
            (
                "drop rate",
                lambda r: r["measurements"]["drop_rate"].update(value=1),
            ),
            (
                "pending measurement",
                lambda r: r["measurements"]["pending_response_peak"].update(
                    value=1
                ),
            ),
            (
                "pending baseline",
                lambda r: r["diagnostics"].update(pending_response_before=1),
            ),
            (
                "pending bound",
                lambda r: (
                    r["diagnostics"].update(pending_response_peak=2),
                    r["measurements"]["pending_response_peak"].update(value=2),
                ),
            ),
            (
                "pending drain",
                lambda r: r["diagnostics"].update(pending_response_after=1),
            ),
            (
                "boolean raw count",
                lambda r: r["diagnostics"].update(tun_packets_egress=True),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                candidate = copy.deepcopy(row)
                mutate(candidate)
                with self.assertRaises(json_contract.CandidateControlError):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_zero_baseline_comparison_is_explicit_and_directional(self) -> None:
        self.assertEqual(
            paired_stats._improvement(
                0, 0, "lower_is_better", allow_zero=True
            ),
            Decimal(0),
        )
        self.assertEqual(
            paired_stats._improvement(
                0, 1, "lower_is_better", allow_zero=True
            ),
            Decimal(-100),
        )
        self.assertEqual(
            paired_stats._improvement(
                0, 1, "higher_is_better", allow_zero=True
            ),
            Decimal(100),
        )
        self.assertEqual(
            paired_stats._improvement(
                1, 0, "lower_is_better", allow_zero=True
            ),
            Decimal(100),
        )
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "baseline must be positive"
        ):
            paired_stats._improvement(0, 0, "lower_is_better")

    def test_fragment_diagnostics_are_required_and_scenario_scoped(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        fragment = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        windows_trial.validate_windows_tun_trial(
            fragment,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        missing = copy.deepcopy(fragment)
        missing["diagnostics"] = None
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "diagnostics must be an object"
        ):
            windows_trial.validate_windows_tun_trial(
                missing,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

        non_fragment = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        non_fragment["diagnostics"] = copy.deepcopy(fragment["diagnostics"])
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "non-fragment.*must be null"
        ):
            windows_trial.validate_windows_tun_trial(
                non_fragment,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_fragment_diagnostics_reject_closed_schema_and_accounting_tampering(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        cases = []

        extra_field = copy.deepcopy(row)
        extra_field["diagnostics"]["unexpected"] = 0
        cases.append((extra_field, "fragment diagnostics schema mismatch"))

        packet_container_missing = copy.deepcopy(row)
        packet_container_missing["diagnostics"].pop("packet_counter_deltas")
        cases.append(
            (packet_container_missing, "fragment diagnostics schema mismatch")
        )

        wrong_schema = copy.deepcopy(row)
        wrong_schema["diagnostics"]["schema_version"] = 1
        cases.append((wrong_schema, "schema_version is unsupported"))

        wrong_kind = copy.deepcopy(row)
        wrong_kind["diagnostics"]["kind"] = "fragment_ack_summary"
        cases.append((wrong_kind, "diagnostics kind is invalid"))

        accounting_extra = copy.deepcopy(row)
        accounting_extra["diagnostics"]["accounting"]["unexpected"] = 0
        cases.append((accounting_extra, "diagnostics accounting schema mismatch"))

        packet_missing = copy.deepcopy(row)
        packet_missing["diagnostics"]["packet_counter_deltas"].pop(
            "background_invalid_destination"
        )
        cases.append((packet_missing, "packet counter deltas schema mismatch"))

        packet_extra = copy.deepcopy(row)
        packet_extra["diagnostics"]["packet_counter_deltas"]["unexpected"] = 0
        cases.append((packet_extra, "packet counter deltas schema mismatch"))

        packet_not_object = copy.deepcopy(row)
        packet_not_object["diagnostics"]["packet_counter_deltas"] = []
        cases.append((packet_not_object, "packet counter deltas must be an object"))

        packet_boolean = copy.deepcopy(row)
        packet_boolean["diagnostics"]["packet_counter_deltas"][
            "background_packets"
        ] = False
        cases.append((packet_boolean, "non-negative u64"))

        adapter_missing = copy.deepcopy(row)
        adapter_missing["diagnostics"]["adapter_counter_deltas"].pop(
            "OutboundPacketErrors"
        )
        cases.append((adapter_missing, "adapter counter deltas schema mismatch"))

        wrong_recipe = copy.deepcopy(row)
        wrong_recipe["diagnostics"]["ack_window_milliseconds"] = 501
        cases.append((wrong_recipe, "does not match the recipe"))

        wrong_batch = copy.deepcopy(row)
        wrong_batch["diagnostics"]["batch_datagrams"] = 7
        cases.append((wrong_batch, "does not match the recipe"))

        negative = copy.deepcopy(row)
        negative["diagnostics"]["accounting"]["retransmissions"] = -1
        cases.append((negative, "non-negative u64"))

        boolean = copy.deepcopy(row)
        boolean["diagnostics"]["accounting"]["duplicate_or_stale_acks"] = False
        cases.append((boolean, "non-negative u64"))

        zero_warmup = copy.deepcopy(row)
        zero_accounting = zero_warmup["diagnostics"]["accounting"]
        zero_accounting["warmup_unique_datagrams"] = 0
        zero_accounting["warmup_request_attempts"] = 0
        zero_accounting["total_unique_datagrams"] = zero_accounting[
            "active_unique_datagrams"
        ]
        zero_accounting["total_request_attempts"] = zero_accounting[
            "active_request_attempts"
        ]
        cases.append((zero_warmup, "warmup_unique_datagrams must be positive"))

        misaligned = copy.deepcopy(row)
        misaligned_accounting = misaligned["diagnostics"]["accounting"]
        misaligned_accounting["warmup_unique_datagrams"] += 1
        misaligned_accounting["warmup_request_attempts"] += 1
        misaligned_accounting["total_unique_datagrams"] += 1
        misaligned_accounting["total_request_attempts"] += 1
        cases.append((misaligned, "warmup_unique_datagrams is not batch-aligned"))

        active_mismatch = copy.deepcopy(row)
        active_mismatch["diagnostics"]["accounting"][
            "active_unique_datagrams"
        ] += 8
        cases.append((active_mismatch, "active unique count"))

        phase_attempts = copy.deepcopy(row)
        phase_attempts["diagnostics"]["accounting"][
            "active_request_attempts"
        ] = 0
        cases.append((phase_attempts, "active attempts are below"))

        total_unique = copy.deepcopy(row)
        total_unique["diagnostics"]["accounting"]["total_unique_datagrams"] += 8
        cases.append((total_unique, "total unique count"))

        total_attempts = copy.deepcopy(row)
        total_attempts["diagnostics"]["accounting"][
            "total_request_attempts"
        ] += 1
        cases.append((total_attempts, "total attempt count"))

        retransmissions = copy.deepcopy(row)
        retransmissions["diagnostics"]["accounting"]["retransmissions"] = 0
        cases.append((retransmissions, "retransmission count"))

        expirations = copy.deepcopy(row)
        expirations["diagnostics"]["accounting"]["ack_window_expirations"] = 0
        cases.append((expirations, "ACK-window expiration count"))

        duplicate_acks = copy.deepcopy(row)
        duplicate_acks["diagnostics"]["accounting"][
            "duplicate_or_stale_acks"
        ] = 2
        cases.append((duplicate_acks, "duplicate/stale ACK count"))

        wrong_budget = copy.deepcopy(row)
        wrong_budget["diagnostics"]["accounting"]["retry_budget"] = 2
        cases.append((wrong_budget, "retry budget is inconsistent"))

        exceeded_budget = copy.deepcopy(row)
        exceeded_accounting = exceeded_budget["diagnostics"]["accounting"]
        exceeded_accounting["active_request_attempts"] += 1
        exceeded_accounting["total_request_attempts"] += 1
        exceeded_accounting["retransmissions"] += 1
        exceeded_accounting["ack_window_expirations"] += 1
        cases.append((exceeded_budget, "exceeded the retry budget"))

        background_sum = copy.deepcopy(row)
        background_sum["diagnostics"]["packet_counter_deltas"][
            "background_packets"
        ] += 1
        cases.append((background_sum, "background packet accounting"))

        accepted_packets = copy.deepcopy(row)
        accepted_packets["diagnostics"]["packet_counter_deltas"][
            "accepted_packets"
        ] -= 1
        cases.append((accepted_packets, "accepted-packet accounting"))

        ingress_packets = copy.deepcopy(row)
        ingress_packets["diagnostics"]["packet_counter_deltas"][
            "ingress_packets"
        ] -= 1
        cases.append((ingress_packets, "ingress/background accounting"))

        adapter_loss = copy.deepcopy(row)
        adapter_loss["diagnostics"]["adapter_counter_deltas"][
            "ReceivedDiscardedPackets"
        ] = 1
        cases.append((adapter_loss, "recorded packet loss"))

        adapter_sent = copy.deepcopy(row)
        adapter_sent["diagnostics"]["adapter_counter_deltas"][
            "SentUnicastPackets"
        ] -= 1
        cases.append((adapter_sent, "adapter sent-packet accounting"))

        adapter_received = copy.deepcopy(row)
        adapter_received["diagnostics"]["adapter_counter_deltas"][
            "ReceivedUnicastPackets"
        ] = 0
        cases.append((adapter_received, "adapter received-packet accounting"))

        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(json_contract.CandidateControlError, message):
                    windows_trial.validate_windows_tun_trial(
                        candidate,
                        plan=plan,
                        parent_sha=self.PARENT_SHA,
                        candidate_sha=self.CANDIDATE_SHA,
                    )

    def test_fragment_diagnostics_retry_budget_uses_unique_datagram_ceiling(
        self,
    ) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="fragment-reassembly-throughput",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        accounting = row["diagnostics"]["accounting"]
        accounting["warmup_unique_datagrams"] = 1_000_000
        accounting["warmup_request_attempts"] = 1_000_000
        accounting["total_unique_datagrams"] = (
            accounting["warmup_unique_datagrams"]
            + accounting["active_unique_datagrams"]
        )
        accounting["total_request_attempts"] = (
            accounting["warmup_request_attempts"]
            + accounting["active_request_attempts"]
        )
        accounting["retry_budget"] = 2
        packet_counters = row["diagnostics"]["packet_counter_deltas"]
        expected_fragment_packets = accounting["total_request_attempts"] * 2
        packet_counters["accepted_packets"] = expected_fragment_packets
        packet_counters["ingress_packets"] = (
            expected_fragment_packets + packet_counters["background_packets"]
        )
        adapter = row["diagnostics"]["adapter_counter_deltas"]
        adapter["ReceivedUnicastPackets"] = accounting["total_request_attempts"]
        adapter["SentUnicastPackets"] = packet_counters["ingress_packets"]
        windows_trial.validate_windows_tun_trial(
            row,
            plan=plan,
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )

        accounting["retry_budget"] = 1
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "retry budget is inconsistent"
        ):
            windows_trial.validate_windows_tun_trial(
                row,
                plan=plan,
                parent_sha=self.PARENT_SHA,
                candidate_sha=self.CANDIDATE_SHA,
            )

    def test_single_trial_cli_validates_collector_output(self) -> None:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="comparison", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        row = self.row(
            plan=plan,
            scenario="tcp-single-flow",
            pair=1,
            member="parent",
            parent_sha=self.PARENT_SHA,
            candidate_sha=self.CANDIDATE_SHA,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan_path = root / "plan.json"
            trial_path = root / "trial.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            trial_path.write_text(json.dumps(row), encoding="utf-8")
            status = controller_cli.main(
                [
                    "windows-tun-validate-trial",
                    "--plan",
                    str(plan_path),
                    "--trial",
                    str(trial_path),
                    "--parent-sha",
                    self.PARENT_SHA,
                    "--candidate-sha",
                    self.CANDIDATE_SHA,
                    "--policy",
                    str(WINDOWS_TUN_POLICY_PATH),
                    "--controller-bundle-sha256",
                    self.CONTROLLER_BUNDLE_SHA256,
                ]
            )
        self.assertEqual(status, 0)
