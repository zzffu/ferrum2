"""Closed, offline-verifiable TUN mock evidence and paired decisions."""
from __future__ import annotations

import hashlib
import pathlib
import re
from decimal import Decimal

from tools.performance_candidate.json_contract import (
    CandidateControlError, _canonical_json_bytes, _exact_fields, _required_u64,
    read_bounded_closed_json,
)
from tools.performance_candidate.pairing import _median

MODES = {"Quick": 3, "Confirm": 5}
BATCHES = {"Quick": 128, "Confirm": 64}
SCENARIOS = {
    "tcp-rewrite": "packets", "tcp-churn": "flows", "udp-roundtrip": "datagrams",
    "fragment-reassembly": "datagrams", "mixed-backpressure": "packets", "state-reset": "resets",
}
BUILD_COMMAND = ["cargo", "build", "-p", "ferrum2-tun", "--example", "tun-benchmark",
                 "--no-default-features", "--features", "benchmark", "--profile", "profiling", "--locked"]
RECIPE_PATHS = (
    "crates/ferrum2-tun/src/benchmark.rs",
    "crates/ferrum2-tun/src/benchmark/recipe.rs",
    "crates/ferrum2-tun/src/benchmark/owner.rs",
    "crates/ferrum2-tun/examples/tun-benchmark.rs",
)
QUICK_COUNTS = {
    "tcp-rewrite": (2048, 2048, 2048, 0),
    "tcp-churn": (512, 1024, 1024, 0),
    "udp-roundtrip": (2048, 2048, 2048, 0),
    "fragment-reassembly": (1024, 2048, 1024, 0),
    "mixed-backpressure": (2048, 2048, 2048, 0),
    "state-reset": (32, 32, 0, 32),
}


def fail(message: str) -> None:
    raise CandidateControlError(message)


def digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def closed(value: object, fields: str, name: str) -> dict:
    if type(value) is not dict:
        fail(f"{name} must be an object")
    _exact_fields(value, frozenset(fields.split()), name)
    return value


def sha(value: object, length: int = 64) -> str:
    if type(value) is not str or re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None:
        fail("invalid SHA identity")
    return value


def load(path: pathlib.Path, limit: int = 2_000_000) -> object:
    return read_bounded_closed_json(path, maximum_bytes=limit, source=str(path)).value


def artifact(root: pathlib.Path, relative: str) -> pathlib.Path:
    if type(relative) is not str or pathlib.PurePosixPath(relative).is_absolute() or "\\" in relative:
        fail("invalid artifact path")
    result = root / relative
    if ".." in pathlib.PurePosixPath(relative).parts or result.is_symlink() or not result.resolve().is_relative_to(root.resolve()):
        fail("artifact escapes evidence root")
    return result


def file_hash(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                h.update(block)
    except OSError as error:
        raise CandidateControlError(f"cannot read retained artifact {path}") from error
    return h.hexdigest()


def schedule(mode: str) -> list[tuple[str, int, str]]:
    if mode not in MODES:
        fail("unsupported mode")
    return [(scenario, pair, side) for scenario in SCENARIOS for pair in range(MODES[mode])
            for side in (("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline"))]


def trial(value: object, scenario: str, mode: str) -> dict:
    row = closed(value, "schema_version kind scenario mode checked_units elapsed_nanoseconds unit workload_sha256 observation", "trial")
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["kind"] != "ferrum2.tun-mock.trial":
        fail("unsupported trial schema")
    if row["scenario"] != scenario or row["mode"] != mode or row["unit"] != SCENARIOS[scenario]:
        fail("trial scenario/mode/unit mismatch")
    _required_u64(row, "checked_units", positive=True)
    _required_u64(row, "elapsed_nanoseconds", positive=True)
    sha(row["workload_sha256"])
    expected_workload = hashlib.sha256(f"ferrum2.tun-mock.v2\n{scenario}\n{mode}\n{BATCHES[mode]}\n".encode("ascii")).hexdigest()
    if row["workload_sha256"] != expected_workload:
        fail("unknown workload recipe identity")
    observation = closed(row["observation"], "input_units output_units rejected_units peak_packet_storage_bytes", "observation")
    for key in observation:
        _required_u64(observation, key)
    factor = BATCHES[mode] * (1 if mode == "Quick" else 4)
    expected_counts = tuple(n * factor for n in QUICK_COUNTS[scenario])
    if (row["checked_units"], observation["input_units"], observation["output_units"], observation["rejected_units"]) != expected_counts:
        fail("trial recipe count mismatch")
    return row


def improvements(rows: list[dict], scenario: str) -> list[Decimal]:
    selected = {(r["pair"], r["side"]): r["trial"] for r in rows if r["scenario"] == scenario}
    values = []
    for pair in sorted({key[0] for key in selected}):
        a = selected[pair, "baseline"]["elapsed_nanoseconds"]
        b = selected[pair, "candidate"]["elapsed_nanoseconds"]
        values.append(Decimal(a - b) * 100 / Decimal(a))
    return values


def decision(rows: list[dict], bounds: dict | None) -> dict:
    result = {}
    for scenario in SCENARIOS:
        values = improvements(rows, scenario)
        if bounds is None:
            # Conservatively include every A/A pair, not just the median; zero noise
            # is legitimate and is never replaced by an inherited host threshold.
            result[scenario] = str(max(abs(value) for value in values))
        else:
            bound = Decimal(bounds[scenario])
            status = ("improved" if all(v > bound for v in values) else
                      "regressed" if any(v < -bound for v in values) else
                      "equivalent" if all(abs(v) <= bound for v in values) else "inconclusive")
            result[scenario] = {"direction": "lower_is_better", "median_improvement_percent": str(_median(values)), "status": status}
    if bounds is None:
        return {"status": "calibrated", "noise_bounds_percent": result}
    statuses = {row["status"] for row in result.values()}
    status = ("regressed" if "regressed" in statuses else "inconclusive" if "inconclusive" in statuses
              else "improved" if "improved" in statuses else "equivalent")
    return {"status": status, "scenarios": result}


def validate(root: pathlib.Path, *, baseline_sha: str, candidate_sha: str, mode: str,
             controller_sha256: str, calibration_root: pathlib.Path | None = None,
             calibration_sha256: str | None = None) -> dict:
    manifest = closed(load(root / "manifest.json"), "schema_version kind baseline_sha candidate_sha mode controller_sha256 recipe_sha256 environment builds trials calibration_sha256 result artifacts", "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or type(manifest["kind"]) is not str or manifest["kind"] not in {"ferrum2.tun-mock.aa", "ferrum2.tun-mock.ab"}:
        fail("unsupported manifest schema")
    for key, expected in (("baseline_sha", sha(baseline_sha, 40)), ("candidate_sha", sha(candidate_sha, 40)), ("mode", mode), ("controller_sha256", sha(controller_sha256))):
        if manifest[key] != expected:
            fail(f"manifest {key} mismatch")
    sha(manifest["recipe_sha256"])
    environment = closed(manifest["environment"], "os release version architecture cpu cpu_count rustc cargo environment_sha256", "environment")
    for key, value in environment.items():
        if key == "cpu_count":
            _required_u64(environment, key, positive=True)
        elif type(value) is not str or not value:
            fail(f"invalid environment {key}")
    sha(environment["environment_sha256"])
    files = manifest["artifacts"]
    if type(files) is not dict or len(files) != 6 + 2 * len(schedule(mode)):
        fail("incomplete artifact inventory")
    for relative, expected in files.items():
        path = artifact(root, relative)
        maximum = 512 * 1024 * 1024 if pathlib.PurePosixPath(relative).name in {"tun-benchmark", "tun-benchmark.exe"} else 32 * 1024 * 1024
        try:
            if path.stat().st_size > maximum:
                fail("retained artifact exceeds byte bound")
        except OSError as error:
            raise CandidateControlError("missing retained artifact") from error
        if file_hash(artifact(root, relative)) != sha(expected):
            fail(f"artifact hash mismatch: {relative}")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual != set(files) | {"manifest.json"}:
        fail("missing or unlisted evidence artifacts")
    builds = closed(manifest["builds"], "baseline candidate", "builds")
    required_files = set()
    for side in builds:
        build = closed(builds[side], "source_sha recipe_files binary binary_sha256 command stdout stderr", "build")
        if build["source_sha"] != manifest[f"{side}_sha"] or build["command"] != BUILD_COMMAND:
            fail("build source or command mismatch")
        recipes = closed(build["recipe_files"], " ".join(RECIPE_PATHS), "recipe files")
        for value in recipes.values():
            sha(value)
        if digest(recipes) != manifest["recipe_sha256"]:
            fail("build recipe mismatch")
        if build["binary"] != f"builds/{side}/tun-benchmark" + (".exe" if environment["os"] == "Windows" else ""):
            fail("build binary path mismatch")
        if build["stdout"] != f"builds/{side}/stdout.log" or build["stderr"] != f"builds/{side}/stderr.log":
            fail("build log path mismatch")
        required_files.update([build["binary"], build["stdout"], build["stderr"]])
        if files.get(build["binary"]) != sha(build["binary_sha256"]):
            fail("build binary digest mismatch")
    rows = manifest["trials"]
    expected_schedule = schedule(mode)
    if type(rows) is not list or len(rows) != len(expected_schedule):
        fail("incomplete trial schedule")
    identities = {}
    for index, (row, expected) in enumerate(zip(rows, expected_schedule)):
        closed(row, "scenario pair side binary_sha256 stdout stderr trial", "trial record")
        if type(row["pair"]) is not int or (row["scenario"], row["pair"], row["side"]) != expected:
            fail("trial pairing or interleaving mismatch")
        scenario, _, side = expected
        if row["binary_sha256"] != builds[side]["binary_sha256"]:
            fail("trial binary identity mismatch")
        if row["stdout"] != f"trials/{index:03d}.json" or row["stderr"] != f"trials/{index:03d}.stderr":
            fail("raw trial path mismatch")
        required_files.update([row["stdout"], row["stderr"]])
        raw = read_bounded_closed_json(artifact(root, row["stdout"]), maximum_bytes=65536, source="raw trial", layout="single_row").value
        parsed = trial(raw, scenario, mode)
        if digest(parsed) != digest(row["trial"]):
            fail("raw trial differs from recorded observation")
        identity = {k: v for k, v in parsed.items() if k not in {"elapsed_nanoseconds", "observation"}}
        identity["observation"] = {k: v for k, v in parsed["observation"].items() if k != "peak_packet_storage_bytes"}
        if scenario in identities and identities[scenario] != identity:
            fail("workload recipe or count mismatch")
        identities[scenario] = identity
    if required_files != set(files):
        fail("unexpected artifact set")
    aa = manifest["kind"] == "ferrum2.tun-mock.aa"
    if aa != (baseline_sha == candidate_sha):
        fail("A/A versus A/B source mismatch")
    bounds = None
    if aa:
        if manifest["calibration_sha256"] is not None or calibration_root is not None or calibration_sha256 is not None:
            fail("A/A cannot consume calibration")
    else:
        if calibration_root is None or calibration_sha256 is None:
            fail("A/B requires reviewed calibration root and digest")
        expected_hash = sha(calibration_sha256)
        if manifest["calibration_sha256"] != expected_hash or file_hash(calibration_root / "manifest.json") != expected_hash:
            fail("reviewed calibration digest mismatch")
        calibration = load(calibration_root / "manifest.json")
        if not isinstance(calibration, dict):
            fail("invalid calibration")
        calibration_report = validate(calibration_root, baseline_sha=calibration.get("baseline_sha"), candidate_sha=calibration.get("baseline_sha"), mode=mode, controller_sha256=controller_sha256)
        for field in ("recipe_sha256", "environment"):
            if manifest[field] != calibration[field]:
                fail(f"calibration {field} mismatch")
        calibration_identities = {}
        for row in calibration["trials"]:
            value = row["trial"]
            calibration_identities[row["scenario"]] = {k: v for k, v in value.items() if k not in {"elapsed_nanoseconds", "observation"}}
            calibration_identities[row["scenario"]]["observation"] = {k: v for k, v in value["observation"].items() if k != "peak_packet_storage_bytes"}
        if identities != calibration_identities:
            fail("calibration workload identity mismatch")
        bounds = calibration_report["noise_bounds_percent"]
    result = decision(rows, bounds)
    if manifest["result"] != result:
        fail("forged paired decision or calibration bounds")
    return result
