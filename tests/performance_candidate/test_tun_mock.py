"""Offline evidence forgery and calibrated paired-decision regressions."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.performance_candidate.json_contract import CandidateControlError
from tools.performance_candidate.tun_mock import write_json
from tools.performance_candidate.tun_mock_contract import (
    BUILD_COMMAND, RECIPE_PATHS, QUICK_COUNTS, SCENARIOS, decision, digest, file_hash, schedule, trial, validate,
)

A = "1" * 40
B = "2" * 40
CONTROLLER = "3" * 64


def fixture(root, *, candidate=A, calibration=None, candidate_elapsed=1000):
    root.mkdir()
    recipes = {path: "4" * 64 for path in RECIPE_PATHS}
    manifest = {"schema_version": 1, "kind": "ferrum2.tun-mock.aa" if candidate == A else "ferrum2.tun-mock.ab",
        "baseline_sha": A, "candidate_sha": candidate, "mode": "Quick", "controller_sha256": CONTROLLER,
        "recipe_sha256": digest(recipes), "environment": {"os": "fixture", "release": "fixture", "version": "fixture",
        "architecture": "fixture", "cpu": "fixture", "cpu_count": 1, "rustc": "fixture", "cargo": "fixture", "environment_sha256": "5" * 64},
        "builds": {}, "trials": [], "calibration_sha256": None if calibration is None else file_hash(calibration / "manifest.json"),
        "result": None, "artifacts": {}}
    for side, source in (("baseline", A), ("candidate", candidate)):
        directory = root / "builds" / side
        directory.mkdir(parents=True)
        (directory / "tun-benchmark").write_bytes(b"offline fixture, never executed")
        (directory / "stdout.log").write_text("")
        (directory / "stderr.log").write_text("")
        manifest["builds"][side] = {"source_sha": source, "recipe_files": recipes, "binary": f"builds/{side}/tun-benchmark",
            "binary_sha256": file_hash(directory / "tun-benchmark"), "command": BUILD_COMMAND,
            "stdout": f"builds/{side}/stdout.log", "stderr": f"builds/{side}/stderr.log"}
    (root / "trials").mkdir()
    for index, (scenario, pair, side) in enumerate(schedule("Quick")):
        value = sample(scenario)
        value["elapsed_nanoseconds"] = 1000 if side == "baseline" else candidate_elapsed
        path = f"trials/{index:03d}.json"
        (root / path).write_text(json.dumps(value) + "\n")
        stderr = f"trials/{index:03d}.stderr"
        (root / stderr).write_text("")
        manifest["trials"].append({"scenario": scenario, "pair": pair, "side": side,
            "binary_sha256": manifest["builds"][side]["binary_sha256"], "stdout": path, "stderr": stderr, "trial": value})
    bounds = None if calibration is None else json.loads((calibration / "manifest.json").read_text())["result"]["noise_bounds_percent"]
    manifest["result"] = decision(manifest["trials"], bounds)
    save(root, manifest)
    return manifest


def sample(scenario="tcp-rewrite"):
    checked, inputs, outputs, rejected = (value * 128 for value in QUICK_COUNTS[scenario])
    return {"schema_version": 1, "kind": "ferrum2.tun-mock.trial", "scenario": scenario, "mode": "Quick",
        "checked_units": checked, "elapsed_nanoseconds": 1000, "unit": SCENARIOS[scenario],
        "workload_sha256": hashlib.sha256(f"ferrum2.tun-mock.v2\n{scenario}\nQuick\n128\n".encode()).hexdigest(),
        "observation": {"input_units": inputs, "output_units": outputs, "rejected_units": rejected, "peak_packet_storage_bytes": 100}}


def save(root, manifest):
    manifest["artifacts"] = {p.relative_to(root).as_posix(): file_hash(p) for p in root.rglob("*") if p.is_file() and p.name != "manifest.json"}
    write_json(root / "manifest.json", manifest)


def check(root, candidate=A, calibration=None):
    return validate(root, baseline_sha=A, candidate_sha=candidate, mode="Quick", controller_sha256=CONTROLLER,
        calibration_root=calibration, calibration_sha256=None if calibration is None else file_hash(calibration / "manifest.json"))


class TunMockEvidenceTests(unittest.TestCase):
    def test_calibration_is_not_speedup_and_all_pairs_bound_noise(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "aa"
            manifest = fixture(root, candidate_elapsed=900)
            result = check(root)
            self.assertEqual(result["status"], "calibrated")
            self.assertEqual(result["noise_bounds_percent"]["tcp-rewrite"], "10")
            manifest["result"]["noise_bounds_percent"]["tcp-rewrite"] = "0"
            save(root, manifest)
            with self.assertRaises(CandidateControlError):
                check(root)

    def test_calibration_allows_different_product_source_but_binds_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            aa, ab = Path(temporary) / "aa", Path(temporary) / "ab"
            fixture(aa, candidate_elapsed=990)
            manifest = fixture(ab, candidate=B, calibration=aa, candidate_elapsed=900)
            self.assertEqual(check(ab, B, aa)["status"], "improved")
            manifest["environment"]["cpu"] = "different"
            save(ab, manifest)
            with self.assertRaises(CandidateControlError):
                check(ab, B, aa)

    def test_raw_tampering_missing_pairs_and_forged_verdict_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "aa"
            original = fixture(root)
            for mutation in (lambda m: m["trials"].pop(),
                             lambda m: m["trials"].reverse(),
                             lambda m: m["trials"][0].update(binary_sha256="0" * 64),
                             lambda m: m.update(result={"status": "improved"}),
                             lambda m: m.update(controller_sha256="0" * 64)):
                manifest = copy.deepcopy(original)
                mutation(manifest)
                save(root, manifest)
                with self.assertRaises(CandidateControlError):
                    check(root)
            save(root, original)
            (root / "trials/000.json").write_text("{}\n")
            with self.assertRaises(CandidateControlError):
                check(root)

    def test_reviewed_calibration_hash_is_not_self_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            aa, ab = Path(temporary) / "aa", Path(temporary) / "ab"
            fixture(aa)
            fixture(ab, candidate=B, calibration=aa)
            with self.assertRaises(CandidateControlError):
                validate(ab, baseline_sha=A, candidate_sha=B, mode="Quick", controller_sha256=CONTROLLER,
                    calibration_root=aa, calibration_sha256="0" * 64)

    def test_recomputed_hash_cannot_hide_raw_count_or_type_forgery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "aa"
            manifest = fixture(root)
            value = manifest["trials"][0]["trial"]
            value["checked_units"] = True
            (root / "trials/000.json").write_text(json.dumps(value) + "\n")
            save(root, manifest)
            with self.assertRaises(CandidateControlError):
                check(root)

    def test_one_bad_pair_prevents_median_speedup_claim(self):
        rows = []
        for scenario, pair, side in schedule("Quick"):
            elapsed = 1000 if side == "baseline" else (1200 if pair == 2 else 500)
            rows.append({"scenario": scenario, "pair": pair, "side": side, "trial": {"elapsed_nanoseconds": elapsed}})
        self.assertEqual(decision(rows, {s: "1" for s in SCENARIOS})["status"], "regressed")

    def test_closed_trial_contract_rejects_boolean_count_and_unknown_recipe(self):
        for field, value in (("checked_units", True), ("elapsed_nanoseconds", 0), ("workload_sha256", "0" * 64), ("unit", "bytes"), ("extra", 0)):
            row = sample()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(CandidateControlError):
                trial(row, "tcp-rewrite", "Quick")


if __name__ == "__main__":
    unittest.main()
