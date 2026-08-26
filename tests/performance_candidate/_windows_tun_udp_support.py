import hashlib
import json
import pathlib

from tests.performance_candidate._windows_tun_base import WindowsTunBase
from tools.performance_candidate.windows_tun import plan as windows_plan
from tools.performance_candidate.windows_tun import recipe as windows_recipe
from tools.performance_candidate.windows_tun import udp_diagnostic, udp_schema

class WindowsTunUdpSupport(WindowsTunBase):
    @staticmethod
    def write_udp_diagnostic_document(
        root: pathlib.Path, row: dict[str, object]
    ) -> None:
        (root / "udp-diagnostic.json").write_text(
            json.dumps(row, sort_keys=True, allow_nan=False), encoding="utf-8"
        )
    def refresh_udp_artifact(
        root: pathlib.Path,
        row: dict[str, object],
        role: str,
        *,
        state: str | None = None,
    ) -> None:
        artifact = next(item for item in row["artifacts"] if item["role"] == role)
        raw = (root / artifact["file"]).read_bytes()
        artifact["bytes"] = len(raw)
        artifact["sha256"] = hashlib.sha256(raw).hexdigest()
        if state is not None:
            artifact["state"] = state
        if role == "failure_summary" and type(row["failure_summary"]) is dict:
            row["failure_summary"] = {
                "file": artifact["file"],
                "sha256": artifact["sha256"],
            }

    @staticmethod
    def udp_artifact(row: dict[str, object], role: str) -> dict[str, object]:
        return next(item for item in row["artifacts"] if item["role"] == role)

    def write_udp_ledger(
        self,
        root: pathlib.Path,
        row: dict[str, object],
        role: str,
        records: list[dict[str, object]],
    ) -> None:
        artifact = self.udp_artifact(row, role)
        (root / artifact["file"]).write_bytes(
            "".join(
                json.dumps(record, separators=(",", ":")) + "\n"
                for record in records
            ).encode("utf-8")
        )
        self.refresh_udp_artifact(root, row, role)

    def write_udp_json_artifact(
        self,
        root: pathlib.Path,
        row: dict[str, object],
        role: str,
        value: dict[str, object],
    ) -> None:
        artifact = self.udp_artifact(row, role)
        (root / artifact["file"]).write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )
        self.refresh_udp_artifact(root, row, role)

    def udp_diagnostic_evidence(
        self,
        root: pathlib.Path,
        *,
        workload_footer: bool = True,
        support_footer: bool = True,
        support_truncation: bool = False,
    ) -> tuple[dict[str, object], dict[str, object], str]:
        plan = windows_plan.create_windows_tun_plan(
            run_kind="calibration-aa", decision_policy=self.policy(),
            controller_bundle_sha256=self.CONTROLLER_BUNDLE_SHA256,
        )
        planned = next(trial for trial in plan["trials"] if trial["sequence"] == 31)
        plan_sha256 = "a" * 64
        run_nonce = "18446744073709551615"
        support_ip = "192.0.2.10"
        environment = self.environment()
        endpoints = [
            {"protocol": "tcp", "ip": support_ip, "port": 44150},
            *[
                {"protocol": "udp", "ip": support_ip, "port": port}
                for port in range(44160, 44164)
            ],
        ]
        identity = {
            "parent_sha": self.AA_SHA,
            "candidate_sha": self.AA_SHA,
            "sha": self.AA_SHA,
            "tree": "4" * 40,
            "client_sha256": "5" * 64,
            "server_sha256": "6" * 64,
            "harness_sha256": "7" * 64,
            "runner_sha256": windows_recipe.source_identities()["runner_source_sha256"],
            "recipe_sha256": plan["recipe_sha256"],
            "plan_sha256": plan_sha256,
        }
        trial = {
            "selection": plan["selection"],
            "run_kind": plan["run_kind"],
            **{
                field: planned[field]
                for field in ("sequence", "scenario", "member", "pair", "order")
            },
        }
        support = {
            "pid": 1234,
            "owner": "BUILTIN\\Administrators",
            "binary_sha256": "7" * 64,
            "listen_endpoints": endpoints,
        }
        def ledger_header(
            schema: str, *, max_events: int = 256, **metadata: object
        ) -> dict[str, object]:
            return {
                "schema": schema,
                "record_type": "header",
                "scope": "bootstrap",
                "closure": (
                    "workload_process_exit"
                    if schema == udp_schema.WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
                    else "host_four_port_barrier_after_vm_off"
                ),
                "run_nonce": run_nonce,
                "max_events": max_events,
                "timestamp_clock": "std_instant_normalized_nanoseconds",
                **metadata,
            }

        def ledger_footer(
            schema: str, *, attempted: int, written: int, dropped: int = 0
        ) -> dict[str, object]:
            return {
                "schema": schema,
                "record_type": "footer",
                "run_nonce": run_nonce,
                "attempted_events": attempted,
                "events_written": written,
                "dropped_events": dropped,
                "write_failures": 0,
                "closed": True,
            }

        workload_schema = udp_schema.WINDOWS_TUN_UDP_WORKLOAD_LEDGER_SCHEMA
        support_schema = udp_schema.WINDOWS_TUN_UDP_SUPPORT_LEDGER_SCHEMA
        workload_event = {
            "schema": workload_schema,
            "record_type": "event",
            "event_index": 0,
            "timestamp_qpc": 1_000,
            "timestamp_qpc_frequency": 1_000_000_000,
            "ledger_counters": {
                "attempted_events": 1,
                "events_written": 1,
                "dropped_events": 0,
                "write_failures": 0,
            },
            "run_nonce": run_nonce,
            "trial_sequence": 31,
            "phase": "bootstrap",
            "association_index": 0,
            "round": 0,
            "packet_nonce": "0",
            "workload_local_ip": windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
            "workload_local_port": (
                windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
            ),
            "target_ip": support_ip,
            "target_port": 44_160,
            "send_result": "success",
            "send_bytes": 32,
            "reply_result": "timeout",
            "reply_source_ip": None,
            "reply_source_port": None,
            "payload_match": False,
            "error_kind": "timeout",
        }
        workload_records = [
            ledger_header(
                workload_schema,
                trial_sequence=31,
                source_ip=windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
                source_port_first=(
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
                ),
                source_port_last=(
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_LAST
                ),
            ),
            workload_event,
            *(
                [ledger_footer(workload_schema, attempted=1, written=1)]
                if workload_footer
                else []
            ),
        ]
        support_event = {
            "schema": support_schema,
            "record_type": "event",
            "event_index": 0,
            "timestamp_qpc": 500,
            "timestamp_qpc_frequency": 1_000_000_000,
            "ledger_counters": {
                "attempted_events": 1,
                "events_written": 1,
                "dropped_events": 0,
                "write_failures": 0,
            },
            "stage": "rx",
            "listen_ip": support_ip,
            "listen_port": 44_160,
            "remote_ip": "198.18.0.2",
            "remote_port": 55_001,
            "payload_run_nonce": None,
            "payload_run_nonce_match": None,
            "trial_sequence": None,
            "phase": None,
            "association_index": None,
            "round": None,
            "packet_nonce": None,
            "recv_bytes": 4,
            "send_attempted": None,
            "send_result": "pending",
            "send_bytes": None,
            "error_kind": None,
        }
        support_records = [
            ledger_header(
                support_schema,
                max_events=1 if support_truncation else 256,
                pid=1234,
                listen_ip=support_ip,
                tcp_port=44150,
                udp_ports=list(range(44160, 44164)),
            ),
            *([support_event] if support_truncation else []),
            *(
                [{
                    "schema": support_schema,
                    "record_type": "truncation",
                    "run_nonce": run_nonce,
                    "attempted_events": 2,
                    "events_written": 1,
                    "dropped_events_at_least": 1,
                    "write_failures": 0,
                }]
                if support_truncation else []
            ),
            *(
                [
                    ledger_footer(
                        support_schema,
                        attempted=2 if support_truncation else 0,
                        written=1 if support_truncation else 0,
                        dropped=int(support_truncation),
                    )
                ]
                if support_footer
                else []
            ),
        ]
        for name, records in (
            ("udp-workload-flow-ledger.ndjson", workload_records),
            ("udp-support-ledger.ndjson", support_records),
        ):
            (root / name).write_bytes(
                "".join(
                    json.dumps(record, separators=(",", ":")) + "\n"
                    for record in records
                ).encode("utf-8")
            )
        plain_artifacts = {
            "endpoints-before.txt": "before\n",
            "endpoints-after.txt": "after\n",
            "dynamic-ports-before.txt": "before\n",
            "dynamic-ports-after.txt": "after\n",
            "host-network-path.json": '{"host_tun_bypassed":true}\n',
        }
        for name, content in plain_artifacts.items():
            (root / name).write_text(content, encoding="utf-8")
        for name in udp_schema.WINDOWS_TUN_UDP_CAPTURE_FILES:
            (root / name).write_bytes(f"bounded {name}\n".encode())
        capture_manifest = {
            "schema": "ferrum2.windows-tun.host-capture-manifest.v1",
            "state": "COMPLETE",
            "filters": [
                {
                    "name": f"Ferrum2UdpDiagnostic-{port}",
                    "support_ipv4": support_ip,
                    "protocol": "UDP",
                    "port": port,
                    "command_exit_code": 0,
                }
                for port in range(44_160, 44_164)
            ],
            "started_utc": "2026-08-24T01:00:00.0000000Z",
            "stop_status": "PASS",
            "expected_files": list(udp_schema.WINDOWS_TUN_UDP_CAPTURE_FILES),
            "files": [
                {
                    "file": name,
                    "bytes": (root / name).stat().st_size,
                    "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                }
                for name in udp_schema.WINDOWS_TUN_UDP_CAPTURE_FILES
            ],
            "failures": [],
        }
        (root / "host-capture-manifest.json").write_text(
            json.dumps(capture_manifest, sort_keys=True), encoding="utf-8"
        )
        cleanup = {
            "status": "PASS",
            "checkpoint_restored": True,
            "final_vm_state": "Off",
            "capture_stop_status": "PASS",
            "guest_owned_processes": 0,
        }
        support_complete = support_footer and not support_truncation
        observations = {
            stage: "UNKNOWN" for stage in udp_schema.WINDOWS_TUN_UDP_OBSERVATION_STAGES
        }
        observations["workload_send"] = "SEEN"
        observations["workload_reply"] = (
            "NOT_SEEN" if workload_footer else "UNKNOWN"
        )
        observations["support_rx"] = "NOT_SEEN" if support_complete else "UNKNOWN"
        observations["support_tx"] = "NOT_SEEN" if support_complete else "UNKNOWN"
        source = lambda state, records, covers, dropped=0: {
            "state": state,
            "records": records,
            "dropped_events": dropped,
            "write_failures": 0,
            "covers_packet_nonce": covers,
        }
        failure_summary = {
            "schema": udp_schema.WINDOWS_TUN_UDP_FAILURE_SUMMARY_SCHEMA,
            "qualification": False,
            "run_nonce": run_nonce,
            **{field: identity[field] for field in identity if field != "plan_sha256"},
            "vm_id": environment["vm_id"],
            "checkpoint_id": environment["checkpoint_id"],
            "support_pid": support["pid"],
            "support_owner": support["owner"],
            "support_sha256": support["binary_sha256"],
            "trial_sequence": trial["sequence"],
            **{field: trial[field] for field in ("scenario", "member", "pair", "order")},
            "failure_kind": "timeout",
            "phase": "bootstrap",
            "association_index": 0,
            "round": 0,
            "packet_nonce": "0",
            "workload_tuple": {
                "source_ip": windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_IPV4,
                "source_port": (
                    windows_recipe.WINDOWS_TUN_UDP_ASSOCIATION_SOURCE_PORT_FIRST
                ),
                "target_ip": support_ip,
                "target_port": 44_160,
            },
            "physical_tuple": None,
            "observation_sources": {
                "workload_ledger": source(
                    "COMPLETE" if workload_footer else "TRUNCATED",
                    1,
                    workload_footer,
                ),
                "support_ledger": source(
                    "COMPLETE" if support_complete else "TRUNCATED",
                    int(support_truncation),
                    support_complete,
                    int(support_truncation),
                ),
                "host_capture": source("COMPLETE", 0, False),
                "guest_capture": source("NOT_ENABLED", 0, False),
                "ferrum_boundary": source("NOT_ENABLED", 0, False),
            },
            "observations": observations,
            "last_confirmed_stage": "workload_send",
            "first_missing_stage": None,
            "response_sink_outcome": None,
            "failure_fingerprint": (
                "udp/bootstrap/request-missing-before-support-rx"
                if support_complete
                else "udp/bootstrap/support-boundary-unknown"
            ),
            "cleanup": cleanup,
        }
        (root / "failure-summary.json").write_text(
            json.dumps(failure_summary, sort_keys=True), encoding="utf-8"
        )
        roles = {
            "udp-workload-flow-ledger.ndjson": "workload_ledger",
            "udp-support-ledger.ndjson": "support_ledger",
            "host-capture-manifest.json": "host_capture",
            "PktMon.etl": "host_capture_native",
            "endpoints-before.txt": "endpoint_snapshot_before",
            "endpoints-after.txt": "endpoint_snapshot_after",
            "dynamic-ports-before.txt": "dynamic_port_snapshot_before",
            "dynamic-ports-after.txt": "dynamic_port_snapshot_after",
            "host-network-path.json": "host_network_path",
            "failure-summary.json": "failure_summary",
        }
        artifacts = []
        for filename, role in roles.items():
            raw = (root / filename).read_bytes()
            ledger = role in {"workload_ledger", "support_ledger"}
            partial = (
                role == "workload_ledger" and not workload_footer
            ) or (
                role == "support_ledger" and (not support_footer or support_truncation)
            )
            artifacts.append(
                {
                    "role": role,
                    "state": "PARTIAL" if partial else "COMPLETE",
                    "file": filename,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                    "records": (
                        1
                        if role == "workload_ledger"
                        else int(support_truncation)
                        if ledger
                        else None
                    ),
                    "max_events": (
                        1
                        if role == "support_ledger" and support_truncation
                        else 256
                        if ledger
                        else None
                    ),
                    "dropped_events": int(role == "support_ledger" and support_truncation),
                    "write_failures": 0,
                }
            )
        host_network = next(item for item in artifacts if item["role"] == "host_network_path")
        failure_artifact = next(
            item for item in artifacts if item["role"] == "failure_summary"
        )
        row = {
            "schema": udp_schema.WINDOWS_TUN_UDP_DIAGNOSTIC_SCHEMA,
            "qualification": False,
            "profile": "UdpFlowBoundary",
            "evidence_status": (
                "COMPLETE"
                if workload_footer and support_footer and not support_truncation
                else "PARTIAL"
            ),
            "trial_status": "FAIL",
            "run_nonce": run_nonce,
            "started_utc": "2026-08-24T01:00:00.0000000Z",
            "finished_utc": "2026-08-24T01:01:00.0000000Z",
            "identity": identity,
            "trial": trial,
            "environment": environment,
            "support": support,
            "topology": {
                "support_ipv4": support_ip,
                "guest_ipv4": "198.18.0.2",
                "host_network_path_file": host_network["file"],
                "host_network_path_sha256": host_network["sha256"],
                "host_tun_bypassed": True,
                "host_network_mutations": [],
            },
            "bounds": {
                "max_artifacts": 16,
                "max_total_bytes": 1_000_000,
                "max_artifact_bytes": 500_000,
                "max_ndjson_line_bytes": 4_096,
                "max_ledger_events": 256,
            },
            "artifacts": artifacts,
            "failure_summary": {
                "file": failure_artifact["file"],
                "sha256": failure_artifact["sha256"],
            },
            "cleanup": cleanup,
        }
        self.write_udp_diagnostic_document(root, row)
        return plan, row, plan_sha256

    def validate_udp_diagnostic(
        self, root: pathlib.Path, plan: dict[str, object], plan_sha256: str
    ) -> dict[str, object]:
        return udp_diagnostic.validate_windows_tun_udp_diagnostic(
            plan=plan,
            plan_sha256=plan_sha256,
            evidence_root=root,
            parent_sha=self.AA_SHA,
            candidate_sha=self.AA_SHA,
        )
