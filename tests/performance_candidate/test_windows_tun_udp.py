import copy
import hashlib
import json
import pathlib
import tempfile

from tests.performance_candidate._shared_fixture import WINDOWS_TUN_POLICY_PATH
from tests.performance_candidate._windows_tun_trial_support import WindowsTunTrialSupport
from tools.performance_candidate import cli as controller_cli
from tools.performance_candidate import json_contract
from tools.performance_candidate.windows_tun import plan as windows_plan
from tools.performance_candidate.windows_tun import summary as windows_summary
from tools.performance_candidate.windows_tun import trial as windows_trial
from tools.performance_candidate.windows_tun import udp_diagnostic, udp_ledger, udp_schema

class WindowsTunUdpTests(WindowsTunTrialSupport):
    def test_udp_diagnostic_accepts_complete_failed_nonqualification_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            validated = self.validate_udp_diagnostic(root, plan, plan_sha256)
            self.assertIs(validated["qualification"], False)
            self.assertEqual(validated["trial_status"], "FAIL")
            self.assertEqual(validated["evidence_status"], "COMPLETE")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
            row["identity"]["plan_sha256"] = hashlib.sha256(
                plan_path.read_bytes()
            ).hexdigest()
            self.write_udp_diagnostic_document(root, row)
            status = controller_cli.main(
                [
                    "windows-tun-validate-udp-diagnostic",
                    "--plan", str(plan_path),
                    "--evidence-root", str(root),
                    "--parent-sha", self.AA_SHA,
                    "--candidate-sha", self.AA_SHA,
                    "--policy", str(WINDOWS_TUN_POLICY_PATH),
                    "--controller-bundle-sha256", self.CONTROLLER_BUNDLE_SHA256,
                ]
            )
            self.assertEqual(status, 0)

    def test_udp_diagnostic_is_explicitly_rejected_by_formal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, _plan_sha256 = self.udp_diagnostic_evidence(root)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "cannot be validated as a formal"
            ):
                windows_trial.validate_windows_tun_trial(
                    row,
                    plan=plan,
                    parent_sha=self.AA_SHA,
                    candidate_sha=self.AA_SHA,
                )
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "cannot enter the formal.*reducer"
            ):
                windows_summary.summarize_windows_tun_evidence(
                    plan=plan,
                    evidence_root=root,
                    parent_sha=self.AA_SHA,
                    candidate_sha=self.AA_SHA,
                )

    def test_udp_diagnostic_closed_schemas_and_enums_reject_mutations(self) -> None:
        mutations = (
            (
                "top-level extra",
                lambda row, failure: row.update(unexpected=True),
                "schema mismatch",
            ),
            (
                "qualification",
                lambda row, failure: row.update(qualification=True),
                "schema or status",
            ),
            (
                "failure observation missing",
                lambda row, failure: failure["observations"].pop("support_rx"),
                "observations schema mismatch",
            ),
            (
                "source state",
                lambda row, failure: failure["observation_sources"]["host_capture"].update(
                    state="BEST_EFFORT"
                ),
                "source state",
            ),
            (
                "artifact role",
                lambda row, failure: row["artifacts"][0].update(role="packet_dump"),
                "artifact role",
            ),
            (
                "failure reference extra",
                lambda row, failure: row["failure_summary"].update(unexpected=True),
                "reference schema mismatch",
            ),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                failure = json.loads((root / "failure-summary.json").read_text(encoding="utf-8"))
                mutate(row, failure)
                if name in {"failure observation missing", "source state"}:
                    (root / "failure-summary.json").write_text(
                        json.dumps(failure, sort_keys=True),
                        encoding="utf-8",
                    )
                    self.refresh_udp_artifact(root, row, "failure_summary")
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaisesRegex(json_contract.CandidateControlError, message):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_rejects_boolean_numeric_identity_aliases(self) -> None:
        for name in (
            "trial pair",
            "trial order",
            "failure qualification",
            "failure association",
            "failure round",
            "failure cleanup",
            "failure tuple port",
            "support endpoint port",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                failure = json.loads(
                    (root / "failure-summary.json").read_text(encoding="utf-8")
                )
                if name == "trial pair":
                    row["trial"]["pair"] = True
                    failure["pair"] = True
                elif name == "trial order":
                    row["trial"]["order"] = True
                    failure["order"] = True
                elif name == "failure qualification":
                    failure["qualification"] = 0
                elif name == "failure association":
                    failure["association_index"] = False
                elif name == "failure round":
                    failure["round"] = False
                elif name == "failure cleanup":
                    failure["cleanup"].update(
                        checkpoint_restored=1,
                        guest_owned_processes=False,
                    )
                elif name == "failure tuple port":
                    artifact = self.udp_artifact(row, "workload_ledger")
                    records = [
                        json.loads(line)
                        for line in (root / artifact["file"])
                        .read_text(encoding="utf-8")
                        .splitlines()
                    ]
                    records[1]["workload_local_port"] = 1
                    self.write_udp_ledger(root, row, "workload_ledger", records)
                    failure["workload_tuple"]["source_port"] = True
                else:
                    artifact = self.udp_artifact(row, "support_ledger")
                    records = [
                        json.loads(line)
                        for line in (root / artifact["file"])
                        .read_text(encoding="utf-8")
                        .splitlines()
                    ]
                    records[0]["tcp_port"] = 1
                    self.write_udp_ledger(root, row, "support_ledger", records)
                    row["support"]["listen_endpoints"][0]["port"] = True
                self.write_udp_json_artifact(root, row, "failure_summary", failure)
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_rejects_zero_byte_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            artifact = self.udp_artifact(row, "endpoint_snapshot_before")
            (root / artifact["file"]).write_bytes(b"")
            self.refresh_udp_artifact(root, row, "endpoint_snapshot_before")
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "positive u64"
            ):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_binds_ledgers_nonce_hash_bounds_and_footer(self) -> None:
        for name in ("nonce", "hash", "bounds"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                if name == "nonce":
                    row["run_nonce"] = "1"
                elif name == "hash":
                    next(
                        item for item in row["artifacts"] if item["role"] == "host_capture"
                    )["sha256"] = "0" * 64
                else:
                    row["bounds"]["max_ledger_events"] = 65_537
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

        for role in ("workload_ledger", "support_ledger"):
            for field in ("scope", "closure"):
                with self.subTest(role=role, field=field):
                    with tempfile.TemporaryDirectory() as directory:
                        root = pathlib.Path(directory)
                        plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                        artifact = self.udp_artifact(row, role)
                        records = [
                            json.loads(line)
                            for line in (root / artifact["file"])
                            .read_text(encoding="utf-8")
                            .splitlines()
                        ]
                        records[0][field] = "invalid"
                        self.write_udp_ledger(root, row, role, records)
                        self.write_udp_diagnostic_document(root, row)
                        with self.assertRaisesRegex(
                            json_contract.CandidateControlError, "ledger header identity"
                        ):
                            self.validate_udp_diagnostic(root, plan, plan_sha256)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(
                root, support_footer=False, support_truncation=True
            )
            self.validate_udp_diagnostic(root, plan, plan_sha256)
            failure = json.loads(
                (root / "failure-summary.json").read_text(encoding="utf-8")
            )
            failure["observations"]["support_rx"] = "NOT_SEEN"
            failure["first_missing_stage"] = "support_rx"
            (root / "failure-summary.json").write_text(
                json.dumps(failure, sort_keys=True), encoding="utf-8"
            )
            self.refresh_udp_artifact(root, row, "failure_summary")
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "not ledger-derived"
            ):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_fixed_source_header_and_events_are_closed(self) -> None:
        mutations = (
            ("missing header field", lambda header, event: header.pop("source_ip")),
            ("extra header field", lambda header, event: header.update(source_ports=8_192)),
            ("header IP", lambda header, event: header.update(source_ip="198.18.0.3")),
            ("header first port", lambda header, event: header.update(source_port_first=20_001)),
            ("header last port", lambda header, event: header.update(source_port_last=28_192)),
            (
                "event IP",
                lambda header, event: event.update(workload_local_ip="198.18.0.3"),
            ),
            (
                "event port",
                lambda header, event: event.update(workload_local_port=20_001),
            ),
            (
                "association prefix",
                lambda header, event: event.update(
                    association_index=1, workload_local_port=20_001
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                artifact = self.udp_artifact(row, "workload_ledger")
                records = [
                    json.loads(line)
                    for line in (root / artifact["file"])
                    .read_text(encoding="utf-8")
                    .splitlines()
                ]
                mutate(records[0], records[1])
                self.write_udp_ledger(root, row, "workload_ledger", records)
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_source_header_is_cross_bound_to_plan(self) -> None:
        for field, value in (
            ("canonical_source_ipv4", "198.18.0.3"),
            ("canonical_source_port_first", 20_001),
            ("canonical_source_port_last", 28_192),
            ("diagnostic_source_ipv4", "198.18.0.3"),
            ("diagnostic_source_port_first", 20_001),
            ("diagnostic_source_port_last", 28_192),
            ("canonical_source_port_strategy", "wildcard_ephemeral"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                plan["scenarios"]["udp-8192-association-lookup-expiry"][
                    "recipe"
                ][field] = value
                with self.assertRaisesRegex(
                    json_contract.CandidateControlError, "source header is not plan-bound"
                ):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_source_coverage_is_exact_or_a_prefix(self) -> None:
        complete = [{"association_index": index} for index in range(8_192)]
        udp_ledger._validate_windows_tun_udp_workload_source_coverage(
            complete, expected_associations=8_192, passing=True
        )
        udp_ledger._validate_windows_tun_udp_workload_source_coverage(
            complete[:8_177], expected_associations=8_192, passing=False
        )
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "lacks complete source coverage"
        ):
            udp_ledger._validate_windows_tun_udp_workload_source_coverage(
                complete[:8_191], expected_associations=8_192, passing=True
            )
        non_prefix = copy.deepcopy(complete[:8_177])
        non_prefix[-1]["association_index"] -= 1
        with self.assertRaisesRegex(
            json_contract.CandidateControlError, "not a consecutive prefix"
        ):
            udp_ledger._validate_windows_tun_udp_workload_source_coverage(
                non_prefix, expected_associations=8_192, passing=False
            )

    def test_udp_diagnostic_rejects_contradictory_ledger_snapshots(self) -> None:
        for name in ("footer regression", "event extra field", "truncation snapshot"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                kwargs = (
                    {"support_footer": False, "support_truncation": True}
                    if name == "truncation snapshot"
                    else {}
                )
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root, **kwargs)
                role = "support_ledger" if kwargs else "workload_ledger"
                artifact = self.udp_artifact(row, role)
                records = [
                    json.loads(line)
                    for line in (root / artifact["file"]).read_text(encoding="utf-8").splitlines()
                ]
                if name == "footer regression":
                    records[1]["event_index"] = 1
                    records[1]["ledger_counters"].update(
                        attempted_events=2, dropped_events=1
                    )
                elif name == "event extra field":
                    records[1]["unexpected"] = True
                else:
                    records[-1]["attempted_events"] = 3
                self.write_udp_ledger(root, row, role, records)
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_failure_claims_are_derived_from_ledgers(self) -> None:
        mutations = (
            ("packet nonce", lambda failure: failure.update(packet_nonce="999")),
            ("association", lambda failure: failure.update(association_index=8_191)),
            ("round", lambda failure: failure.update(round=63)),
            ("tuple", lambda failure: failure.update(workload_tuple=[])),
            ("classification", lambda failure: failure.update(failure_kind="other")),
            (
                "coverage",
                lambda failure: failure["observation_sources"]["support_ledger"].update(
                    covers_packet_nonce=False
                ),
            ),
            (
                "invented receive",
                lambda failure: failure["observations"].update(support_rx="SEEN"),
            ),
            (
                "invented physical tuple",
                lambda failure: failure.update(
                    physical_tuple={
                        "source_ip": "198.18.0.2",
                        "source_port": 1,
                        "target_ip": "192.0.2.10",
                        "target_port": 65_535,
                    }
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                failure = json.loads(
                    (root / "failure-summary.json").read_text(encoding="utf-8")
                )
                mutate(failure)
                self.write_udp_json_artifact(root, row, "failure_summary", failure)
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_support_packet_boundary_is_ledger_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            artifact = self.udp_artifact(row, "support_ledger")
            records = [
                json.loads(line)
                for line in (root / artifact["file"]).read_text(encoding="utf-8").splitlines()
            ]
            support_rx = {
                "schema": udp_schema.WINDOWS_TUN_UDP_SUPPORT_LEDGER_SCHEMA,
                "record_type": "event",
                "event_index": 0,
                "timestamp_qpc": 2_000,
                "timestamp_qpc_frequency": 1_000_000_000,
                "ledger_counters": {
                    "attempted_events": 1,
                    "events_written": 1,
                    "dropped_events": 0,
                    "write_failures": 0,
                },
                "stage": "rx",
                "listen_ip": "192.0.2.10",
                "listen_port": 44_160,
                "remote_ip": "198.18.0.2",
                "remote_port": 55_000,
                "payload_run_nonce": row["run_nonce"],
                "payload_run_nonce_match": True,
                "trial_sequence": row["trial"]["sequence"],
                "phase": "bootstrap",
                "association_index": 0,
                "round": 0,
                "packet_nonce": "0",
                "recv_bytes": 32,
                "send_attempted": None,
                "send_result": "pending",
                "send_bytes": None,
                "error_kind": None,
            }
            records.insert(1, support_rx)
            records[-1].update(attempted_events=1, events_written=1)
            self.write_udp_ledger(root, row, "support_ledger", records)
            artifact["records"] = 1
            failure = json.loads(
                (root / "failure-summary.json").read_text(encoding="utf-8")
            )
            failure["observation_sources"]["support_ledger"]["records"] = 1
            failure["observations"].update(support_rx="SEEN", support_tx="NOT_SEEN")
            failure["physical_tuple"] = {
                "source_ip": "198.18.0.2",
                "source_port": 55_000,
                "target_ip": "192.0.2.10",
                "target_port": 44_160,
            }
            failure["last_confirmed_stage"] = "support_rx"
            failure["first_missing_stage"] = "support_tx"
            failure["failure_fingerprint"] = "udp/bootstrap/reply-missing-at-support-tx"
            self.write_udp_json_artifact(root, row, "failure_summary", failure)
            self.write_udp_diagnostic_document(root, row)
            self.validate_udp_diagnostic(root, plan, plan_sha256)

            bool_port_rx = copy.deepcopy(support_rx)
            bool_port_rx["remote_port"] = 1
            records[1] = bool_port_rx
            failure["physical_tuple"]["source_port"] = True
            self.write_udp_ledger(root, row, "support_ledger", records)
            self.write_udp_json_artifact(root, row, "failure_summary", failure)
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "must be a valid port"
            ):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

            records[1] = support_rx
            failure["physical_tuple"]["source_port"] = 55_000
            self.write_udp_ledger(root, row, "support_ledger", records)
            self.write_udp_json_artifact(root, row, "failure_summary", failure)

            forged_tx = copy.deepcopy(support_rx)
            forged_tx.update(
                stage="tx",
                send_attempted=True,
                send_result="success",
                send_bytes=32,
            )
            records[1] = forged_tx
            self.write_udp_ledger(root, row, "support_ledger", records)
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "TX is not ordered after"
            ):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_capture_manifest_and_cleanup_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            (root / "PktMon.txt").write_text("tampered capture\n", encoding="utf-8")
            with self.assertRaisesRegex(
                json_contract.CandidateControlError, "capture file binding"
            ):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

        for name in ("filter", "cleanup", "non-ledger counters", "host nonce coverage"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                if name == "filter":
                    manifest = json.loads(
                        (root / "host-capture-manifest.json").read_text(encoding="utf-8")
                    )
                    manifest["filters"][0]["port"] = 70_000
                    self.write_udp_json_artifact(root, row, "host_capture", manifest)
                elif name == "cleanup":
                    row["cleanup"].update(status="FAIL", capture_stop_status="FAIL")
                    failure = json.loads(
                        (root / "failure-summary.json").read_text(encoding="utf-8")
                    )
                    failure["cleanup"] = copy.deepcopy(row["cleanup"])
                    self.write_udp_json_artifact(root, row, "failure_summary", failure)
                elif name == "non-ledger counters":
                    self.udp_artifact(row, "host_capture")["dropped_events"] = 99
                else:
                    failure = json.loads(
                        (root / "failure-summary.json").read_text(encoding="utf-8")
                    )
                    failure["observation_sources"]["host_capture"][
                        "covers_packet_nonce"
                    ] = True
                    self.write_udp_json_artifact(root, row, "failure_summary", failure)
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_endpoints_paths_and_line_bounds_are_closed(self) -> None:
        for name in (
            "support port",
            "topology IP",
            "ADS path",
            "case alias",
            "nested alias",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                if name == "support port":
                    artifact = self.udp_artifact(row, "support_ledger")
                    records = [
                        json.loads(line)
                        for line in (root / artifact["file"])
                        .read_text(encoding="utf-8")
                        .splitlines()
                    ]
                    records[0]["udp_ports"][0] = 70_000
                    self.write_udp_ledger(root, row, "support_ledger", records)
                elif name == "topology IP":
                    row["topology"]["support_ipv4"] = []
                elif name == "ADS path":
                    self.udp_artifact(row, "endpoint_snapshot_before")[
                        "file"
                    ] = "endpoints-before.txt:stream"
                elif name == "case alias":
                    before = self.udp_artifact(row, "endpoint_snapshot_before")
                    after = self.udp_artifact(row, "endpoint_snapshot_after")
                    after.update(
                        file=str(before["file"]).upper(),
                        bytes=before["bytes"],
                        sha256=before["sha256"],
                    )
                else:
                    raw = (root / "PktMon.txt").read_bytes()
                    row["artifacts"].append(
                        {
                            "role": "runner_log",
                            "state": "COMPLETE",
                            "file": "PktMon.txt",
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "bytes": len(raw),
                            "records": None,
                            "max_events": None,
                            "dropped_events": 0,
                            "write_failures": 0,
                        }
                    )
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

        for name in ("duplicate role", "duplicate file", "size", "count", "total"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                before = self.udp_artifact(row, "endpoint_snapshot_before")
                after = self.udp_artifact(row, "endpoint_snapshot_after")
                if name == "duplicate role":
                    row["artifacts"].append(copy.deepcopy(before))
                elif name == "duplicate file":
                    after["file"] = before["file"]
                elif name == "size":
                    before["bytes"] += 1
                elif name == "count":
                    row["bounds"]["max_artifacts"] = len(row["artifacts"]) - 1
                else:
                    largest = max(item["bytes"] for item in row["artifacts"])
                    row["bounds"].update(
                        max_artifact_bytes=largest,
                        max_total_bytes=largest,
                    )
                self.write_udp_diagnostic_document(root, row)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)

        for json_bytes, accepted in ((4_096, True), (4_097, False)):
            with self.subTest(json_bytes=json_bytes), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
                artifact = self.udp_artifact(row, "workload_ledger")
                path = root / artifact["file"]
                raw = path.read_bytes()
                newline = raw.index(b"\n")
                padded = raw[:newline] + b" " * (json_bytes - newline) + raw[newline:]
                path.write_bytes(padded)
                self.refresh_udp_artifact(root, row, "workload_ledger")
                self.write_udp_diagnostic_document(root, row)
                if accepted:
                    self.validate_udp_diagnostic(root, plan, plan_sha256)
                else:
                    with self.assertRaisesRegex(
                        json_contract.CandidateControlError, "line exceeds"
                    ):
                        self.validate_udp_diagnostic(root, plan, plan_sha256)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            artifact = self.udp_artifact(row, "support_ledger")
            path = root / artifact["file"]
            path.write_bytes(path.read_bytes()[:-1])
            self.refresh_udp_artifact(root, row, "support_ledger")
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaisesRegex(json_contract.CandidateControlError, "unterminated"):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_missing_either_footer_is_partial_but_valid(self) -> None:
        for kwargs in ({"workload_footer": False}, {"support_footer": False}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, row, plan_sha256 = self.udp_diagnostic_evidence(root, **kwargs)
                validated = self.validate_udp_diagnostic(root, plan, plan_sha256)
                self.assertEqual(validated["evidence_status"], "PARTIAL")

    def test_udp_diagnostic_requires_reviewed_aa_sequence_and_plan_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            plan, row, plan_sha256 = self.udp_diagnostic_evidence(root)
            comparison = windows_plan.create_windows_tun_plan(
                run_kind="comparison", decision_policy=self.policy(),
                controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
            )
            with self.assertRaisesRegex(json_contract.CandidateControlError, "calibration-aa A/A"):
                udp_diagnostic.validate_windows_tun_udp_diagnostic(
                    plan=comparison,
                    plan_sha256=plan_sha256,
                    evidence_root=root,
                    parent_sha=self.AA_SHA,
                    candidate_sha=self.AA_SHA,
                )
            with self.assertRaisesRegex(json_contract.CandidateControlError, "calibration-aa A/A"):
                udp_diagnostic.validate_windows_tun_udp_diagnostic(
                    plan=plan,
                    plan_sha256=plan_sha256,
                    evidence_root=root,
                    parent_sha=self.PARENT_SHA,
                    candidate_sha=self.CANDIDATE_SHA,
                )
            row["trial"]["sequence"] = (
                udp_diagnostic.WINDOWS_TUN_UDP_DIAGNOSTIC_TRIAL_SEQUENCE + 1
            )
            self.write_udp_diagnostic_document(root, row)
            with self.assertRaises(json_contract.CandidateControlError):
                self.validate_udp_diagnostic(root, plan, plan_sha256)

    def test_udp_diagnostic_rejects_duplicate_nonfinite_and_oversize_json(self) -> None:
        cases = (
            b'{"schema":"x","schema":"y"}',
            b'{"schema":NaN}',
            b"{" + b" " * udp_schema.WINDOWS_TUN_UDP_DIAGNOSTIC_MAX_BYTES + b"}",
        )
        for raw in cases:
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan, _row, plan_sha256 = self.udp_diagnostic_evidence(root)
                (root / "udp-diagnostic.json").write_bytes(raw)
                with self.assertRaises(json_contract.CandidateControlError):
                    self.validate_udp_diagnostic(root, plan, plan_sha256)
