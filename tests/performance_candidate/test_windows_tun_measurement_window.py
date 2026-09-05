"""Pure numeric checks for the current workload window and count contract."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_windows_tun_host_evidence import (
    DIGEST, ROOT, RUN_ID, plan_for, trial_for, validate_windows_tun_trial,
)
from tools.performance_candidate.json_contract import CandidateControlError


def examples():
    plan = plan_for("Confirm", "ClientDirect")
    for scenario, value in (
        ("tcp-single-flow", 10_000_000),
        ("tcp-request-1k-p99", 100_000),
        ("tcp-256-flow-fairness", 900_000_000),
        ("udp-packets-per-second", 100_000),
        ("fragment-reassembly-throughput", 10_000_000),
    ):
        planned = next(row for row in plan["trials"] if row["scenario"] == scenario)
        yield planned, trial_for(planned, value)


def validate(planned, trial):
    return validate_windows_tun_trial(
        trial, planned_trial=planned, run_id=RUN_ID,
        performance_source_bundle_sha256=DIGEST,
    )


def window_cases():
    for planned, original in examples():
        yield planned, original, True
        scenario = original["scenario"]
        tail = copy.deepcopy(original)
        measurements = tail["workload_measurements"]
        measurements["active_elapsed_nanoseconds"] = (planned["active_seconds"] + 1) * 1_000_000_000
        tail["cpu_sample_seconds"] = planned["active_seconds"] + 1.01
        measurements["tail_checked_units"] = {
            "tcp-single-flow": 65536,
            "tcp-request-1k-p99": 1, "tcp-256-flow-fairness": 16384,
            "udp-packets-per-second": 1, "fragment-reassembly-throughput": 4,
        }[scenario]
        for field, payload in (("throughput", 1), ("aggregate_throughput", 1), ("packet_rate", 1), ("reassembly_rate", 1440)):
            if field in measurements:
                measurements[field] = tail["checked_units"] * payload * 1_000_000_000 // measurements["active_elapsed_nanoseconds"]
        tail["value"] = float(measurements[tail["metric"]])
        yield planned, tail, True
        uncovered = copy.deepcopy(tail)
        uncovered["cpu_sample_seconds"] = planned["active_seconds"]
        yield planned, uncovered, False
        excess_tail = {
            "tcp-single-flow": 131072,
            "tcp-request-1k-p99": 2, "tcp-256-flow-fairness": 257 * 16384,
            "udp-packets-per-second": 2, "fragment-reassembly-throughput": 8,
        }[scenario]
        for field, value in (
            ("active_elapsed_nanoseconds", planned["active_seconds"] * 1_000_000_000 - 1),
            ("active_elapsed_nanoseconds", float(measurements["active_elapsed_nanoseconds"])),
            ("active_elapsed_nanoseconds", 2**64),
            ("tail_checked_units", 0),
            ("tail_checked_units", True),
            ("tail_checked_units", tail["checked_units"] + 1),
            ("tail_checked_units", excess_tail),
        ):
            invalid = copy.deepcopy(tail)
            invalid["workload_measurements"][field] = value
            yield planned, invalid, False
        incomplete = copy.deepcopy(tail)
        del incomplete["workload_measurements"]["active_elapsed_nanoseconds"]
        yield planned, incomplete, False
        inconsistent = copy.deepcopy(tail)
        inconsistent["workload_measurements"]["io_completions"] -= 2
        inconsistent["io_completions"] -= 2
        yield planned, inconsistent, False
        for field in ("throughput", "aggregate_throughput", "packet_rate", "reassembly_rate"):
            if field in measurements:
                contradictory = copy.deepcopy(tail)
                contradictory["workload_measurements"][field] += 1
                contradictory["value"] = float(contradictory["workload_measurements"][tail["metric"]])
                yield planned, contradictory, False
        shortage = copy.deepcopy(tail)
        minimum, alignment = {
            "tcp-single-flow": (67108864, 65536),
            "tcp-request-1k-p99": (1024, 1), "tcp-256-flow-fairness": (4194304, 16384),
            "udp-packets-per-second": (4096, 1), "fragment-reassembly-throughput": (4096, 4),
        }[scenario]
        shortage["checked_units"] = minimum - alignment
        yield planned, shortage, False


class WindowsTunMeasurementWindowTests(unittest.TestCase):
    def test_current_trials_bind_actual_window_work_and_rates(self):
        for planned, trial, accepted in window_cases():
            with self.subTest(scenario=planned["scenario"], accepted=accepted, measurements=trial["workload_measurements"]):
                if accepted:
                    self.assertEqual(validate(planned, trial), trial)
                else:
                    with self.assertRaises(CandidateControlError):
                        validate(planned, trial)

    def test_retired_and_noninteger_schema_versions_are_rejected(self):
        for planned, trial in examples():
            for retired in (3, 4.0, True):
                invalid = copy.deepcopy(trial)
                invalid["schema_version"] = retired
                with self.subTest(scenario=planned["scenario"], version=retired):
                    with self.assertRaises(CandidateControlError):
                        validate(planned, invalid)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required for the host validator")
    def test_host_validator_uses_the_same_numeric_contract(self):
        rows = [trial | {"accepted": accepted} for _, trial, accepted in window_cases()]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cases.json"
            source.write_text(json.dumps(rows), encoding="utf-8")
            script = root / "validate.ps1"
            script.write_text(
                "param($Owner, $Cases)\n$ErrorActionPreference = 'Stop'\n. $Owner\n"
                "$results = @(foreach ($row in (Get-Content -Raw -LiteralPath $Cases | ConvertFrom-Json)) {\n"
                "  try { Assert-Ferrum2TrialMeasurements -Measurements $row.workload_measurements "
                "-Scenario $row.scenario -CheckedUnits $row.checked_units -ActiveSeconds $row.active_seconds "
                "-CpuSampleSeconds $row.cpu_sample_seconds; $true }\n"
                "  catch { $false }\n})\nConvertTo-Json -InputObject $results -Compress\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script),
                 str(ROOT / "tools/powershell/Ferrum2.Performance/HostTrial.ps1"), str(source)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [row["accepted"] for row in rows])
