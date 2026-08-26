"""scale trial owner."""

from __future__ import annotations

from tools.performance_candidate.json_contract import CandidateControlError, U64_MAX, _exact_fields, _required_i64

from collections.abc import Sequence
from fractions import Fraction

from tools.performance_candidate.linux.scale import SCALE_CORRECTNESS_FIELDS, SCALE_FAIRNESS_FIELDS, SCALE_FIELDS, SCALE_RECIPE, SCALE_RESOURCE_FIELDS, SCALE_SAMPLE_FIELDS, SCALE_TRAFFIC_FIELDS

def _scale_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise CandidateControlError(f"{field} must be an unsigned 64-bit integer")
    return value


def _scale_u64_vector(value: object, field: str, length: int) -> list[int]:
    if type(value) is not list or len(value) != length:
        raise CandidateControlError(f"{field} must contain exactly {length} values")
    return [_scale_u64(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _scale_u64_sum(values: Sequence[int], field: str) -> int:
    total = sum(values)
    if total > U64_MAX:
        raise CandidateControlError(f"{field} overflows u64")
    return total


def _scale_even_median(values: Sequence[int], field: str) -> int:
    if not values or len(values) % 2:
        raise CandidateControlError(f"{field} requires a nonempty even vector")
    ordered = sorted(values)
    upper = len(ordered) // 2
    total = ordered[upper - 1] + ordered[upper]
    if total > U64_MAX:
        raise CandidateControlError(f"{field} median sum overflows u64")
    return total // 2


def _scale_stage_median(samples: Sequence[dict[str, object]], field: str) -> int:
    if not samples:
        raise CandidateControlError("scale resource stage is empty")
    values = sorted(_scale_u64(sample[field], field) for sample in samples)
    return values[len(values) // 2]


def _truncating_division(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise AssertionError("positive denominator required")
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _scale_nearest_rank(ordered: Sequence[int], percentile: int) -> int:
    rank = (len(ordered) * percentile + 99) // 100
    return ordered[rank - 1]


def _recompute_scale_fairness(flow_bytes: Sequence[int]) -> dict[str, object]:
    if len(flow_bytes) != SCALE_RECIPE["sessions"]:
        raise CandidateControlError("scale fairness vector length is invalid")
    ordered = sorted(flow_bytes)
    total = sum(flow_bytes)
    square_sum = sum(value * value for value in flow_bytes)
    u128_max = (1 << 128) - 1
    if total > u128_max or square_sum > u128_max:
        raise CandidateControlError("scale fairness arithmetic exceeds u128")
    denominator = len(flow_bytes) * square_sum
    numerator = total * total
    if denominator > u128_max or numerator > u128_max:
        raise CandidateControlError("scale fairness aggregate exceeds u128")
    scaled_numerator = numerator * 1_000_000_000
    if scaled_numerator > u128_max:
        raise CandidateControlError("scale fairness scaled numerator exceeds u128")
    jain_ppb = 0 if denominator == 0 else scaled_numerator // denominator
    median_bytes = _scale_even_median(ordered, "scale fairness")
    p01 = _scale_nearest_rank(ordered, 1)
    ratio_numerator = p01 * 1_000_000
    if ratio_numerator > u128_max:
        raise CandidateControlError("scale fairness ratio exceeds u128")
    ratio_ppm = 0 if median_bytes == 0 else ratio_numerator // median_bytes
    return {
        "jain_ppb": jain_ppb,
        "minimum_bytes": ordered[0],
        "p01_bytes": p01,
        "p05_bytes": _scale_nearest_rank(ordered, 5),
        "median_bytes": median_bytes,
        "p95_bytes": _scale_nearest_rank(ordered, 95),
        "p99_bytes": _scale_nearest_rank(ordered, 99),
        "maximum_bytes": ordered[-1],
        "p01_to_median_ppm": ratio_ppm,
        "jain_fraction": Fraction(numerator, denominator) if denominator else Fraction(0),
        "p01_median_fraction": (
            Fraction(p01, median_bytes) if median_bytes else Fraction(0)
        ),
    }


def _validate_scale_sample(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise CandidateControlError(f"{field} must be an object")
    _exact_fields(value, SCALE_SAMPLE_FIELDS, field)
    for key in SCALE_SAMPLE_FIELDS:
        _scale_u64(value[key], f"{field}.{key}")
    return value


def _validate_scale_evidence(row: dict[str, object]) -> dict[str, object]:
    scale = row["scale"]
    if type(scale) is not dict:
        raise CandidateControlError("tcp-scale-10k evidence requires a scale object")
    _exact_fields(scale, SCALE_FIELDS, "scale evidence")
    if _scale_u64(scale["schema_version"], "scale.schema_version") != 1:
        raise CandidateControlError("scale evidence schema_version is unsupported")

    recipe = scale["recipe"]
    if type(recipe) is not dict:
        raise CandidateControlError("scale recipe must be an object")
    _exact_fields(recipe, frozenset(SCALE_RECIPE), "scale recipe")
    for field, expected in SCALE_RECIPE.items():
        if _scale_u64(recipe[field], f"scale.recipe.{field}") != expected:
            raise CandidateControlError(f"scale recipe {field} does not match")

    correctness = scale["correctness"]
    if type(correctness) is not dict:
        raise CandidateControlError("scale correctness must be an object")
    _exact_fields(correctness, SCALE_CORRECTNESS_FIELDS, "scale correctness")
    numeric_correctness = SCALE_CORRECTNESS_FIELDS - {"drain", "rebind", "cleanup"}
    for field in numeric_correctness:
        _scale_u64(correctness[field], f"scale.correctness.{field}")
    for field in ("drain", "rebind", "cleanup"):
        if correctness[field] not in {"PASS", "FAIL"}:
            raise CandidateControlError(f"scale correctness {field} is invalid")

    traffic = scale["traffic"]
    if type(traffic) is not dict:
        raise CandidateControlError("scale traffic must be an object")
    _exact_fields(traffic, SCALE_TRAFFIC_FIELDS, "scale traffic")
    partial_bytes = _scale_u64_vector(
        traffic["partial_flow_bytes"],
        "scale.traffic.partial_flow_bytes",
        SCALE_RECIPE["partial_active_flows"],
    )
    full_bytes = _scale_u64_vector(
        traffic["full_flow_bytes"],
        "scale.traffic.full_flow_bytes",
        SCALE_RECIPE["sessions"],
    )
    full_completions = _scale_u64_vector(
        traffic["full_flow_completions"],
        "scale.traffic.full_flow_completions",
        SCALE_RECIPE["sessions"],
    )
    payload_bytes = SCALE_RECIPE["payload_bytes"]
    if any(value % payload_bytes for value in partial_bytes):
        raise CandidateControlError("scale partial bytes are not whole round trips")
    partial_completions = _scale_u64_sum(
        [value // payload_bytes for value in partial_bytes],
        "scale partial completions",
    )
    partial_checked = _scale_u64_sum(partial_bytes, "scale partial bytes")
    for field, expected in (
        ("partial_checked_bytes", partial_checked),
        ("partial_io_completions", partial_completions),
    ):
        if _scale_u64(traffic[field], f"scale.traffic.{field}") != expected:
            raise CandidateControlError(f"scale traffic {field} is inconsistent")
    partial_tails = _scale_u64(
        traffic["partial_discarded_tail_completions"],
        "scale.traffic.partial_discarded_tail_completions",
    )
    if partial_tails > SCALE_RECIPE["partial_active_flows"]:
        raise CandidateControlError("scale partial tail count exceeds one per flow")

    for index, (byte_count, completions) in enumerate(
        zip(full_bytes, full_completions, strict=True)
    ):
        product = completions * payload_bytes
        if product > U64_MAX or byte_count != product:
            raise CandidateControlError(
                f"scale full flow {index} byte/completion accounting is inconsistent"
            )
    full_checked = _scale_u64_sum(full_bytes, "scale full bytes")
    full_completion_sum = _scale_u64_sum(
        full_completions, "scale full completions"
    )
    for field, expected in (
        ("full_checked_bytes", full_checked),
        ("full_io_completions", full_completion_sum),
    ):
        if _scale_u64(traffic[field], f"scale.traffic.{field}") != expected:
            raise CandidateControlError(f"scale traffic {field} is inconsistent")
    full_tails = _scale_u64(
        traffic["full_discarded_tail_completions"],
        "scale.traffic.full_discarded_tail_completions",
    )
    if full_tails > SCALE_RECIPE["sessions"]:
        raise CandidateControlError("scale full tail count exceeds one per flow")
    elapsed = _scale_u64(
        traffic["full_elapsed_nanoseconds"],
        "scale.traffic.full_elapsed_nanoseconds",
    )
    expected_elapsed = SCALE_RECIPE["full_seconds"] * 1_000_000_000
    if elapsed != expected_elapsed:
        raise CandidateControlError("scale full elapsed window is not exact")
    rate = full_checked * 1_000_000_000 // elapsed
    if rate > U64_MAX or _scale_u64(
        traffic["aggregate_bytes_per_second"],
        "scale.traffic.aggregate_bytes_per_second",
    ) != rate:
        raise CandidateControlError("scale aggregate rate is inconsistent")

    fairness = scale["fairness"]
    if type(fairness) is not dict:
        raise CandidateControlError("scale fairness must be an object")
    _exact_fields(fairness, SCALE_FAIRNESS_FIELDS, "scale fairness")
    recomputed_fairness = _recompute_scale_fairness(full_bytes)
    for field in SCALE_FAIRNESS_FIELDS:
        if _scale_u64(fairness[field], f"scale.fairness.{field}") != recomputed_fairness[field]:
            raise CandidateControlError(f"scale fairness {field} is inconsistent")

    resource = scale["resource"]
    if type(resource) is not dict:
        raise CandidateControlError("scale resource must be an object")
    _exact_fields(resource, SCALE_RESOURCE_FIELDS, "scale resource")
    stage_lengths = {
        "pre_load": 1,
        "established": 5,
        "touched": 5,
        "partial_active": 5,
        "full_active": 5,
        "post_full": 5,
        "drained": 1,
    }
    samples: dict[str, list[dict[str, object]]] = {}
    for stage, expected_length in stage_lengths.items():
        value = resource[stage]
        if type(value) is not list or len(value) != expected_length:
            raise CandidateControlError(
                f"scale resource {stage} must contain {expected_length} samples"
            )
        samples[stage] = [
            _validate_scale_sample(sample, f"scale.resource.{stage}[{index}]")
            for index, sample in enumerate(value)
        ]
    all_samples = [sample for stage in samples.values() for sample in stage]
    peak = max(_scale_u64(sample["harness_rss_kib"], "harness_rss_kib") for sample in all_samples)
    if _scale_u64(resource["harness_peak_rss_kib"], "scale.resource.harness_peak_rss_kib") != peak:
        raise CandidateControlError("scale harness RSS peak is inconsistent")
    sessions = SCALE_RECIPE["sessions"]
    client_increment = _truncating_division(
        (
            _scale_stage_median(samples["touched"], "client_smaps_rss_kib")
            - _scale_stage_median(samples["established"], "client_smaps_rss_kib")
        )
        * 1024,
        sessions,
    )
    server_increment = _truncating_division(
        (
            _scale_stage_median(samples["touched"], "server_smaps_rss_kib")
            - _scale_stage_median(samples["established"], "server_smaps_rss_kib")
        )
        * 1024,
        sessions,
    )
    combined_increment = client_increment + server_increment
    for field, expected in (
        ("client_touched_increment_bytes_per_connection", client_increment),
        ("server_touched_increment_bytes_per_connection", server_increment),
        ("combined_touched_increment_bytes_per_connection", combined_increment),
    ):
        if _required_i64(resource[field], f"scale.resource.{field}") != expected:
            raise CandidateControlError(f"scale resource {field} is inconsistent")
    _scale_u64(resource["memory_available_kib"], "scale.resource.memory_available_kib")
    _scale_u64(resource["nofile_soft"], "scale.resource.nofile_soft")

    partial_nonzero = sum(value != 0 for value in partial_bytes)
    full_nonzero = sum(value != 0 for value in full_bytes)
    if correctness["partial_nonzero_flows"] != partial_nonzero:
        raise CandidateControlError("scale partial nonzero count is inconsistent")
    if correctness["full_nonzero_flows"] != full_nonzero:
        raise CandidateControlError("scale full nonzero count is inconsistent")
    touch_completions = _scale_u64(
        correctness["touch_completed_round_trips"],
        "scale.correctness.touch_completed_round_trips",
    )
    if correctness["touch_checked_bytes"] != touch_completions * payload_bytes:
        raise CandidateControlError("scale touch byte accounting is inconsistent")
    payload_checks = (
        touch_completions
        + partial_completions
        + partial_tails
        + full_completion_sum
        + full_tails
    )
    if payload_checks > U64_MAX or correctness["payload_checks"] != payload_checks:
        raise CandidateControlError("scale payload check accounting is inconsistent")

    if row["value"] != rate or row["checked_units"] != full_checked:
        raise CandidateControlError("scale top-level traffic values are inconsistent")
    if row["io_completions"] != full_completion_sum * 2:
        raise CandidateControlError("scale top-level I/O completions are inconsistent")
    return {
        "fairness": recomputed_fairness,
        "samples": samples,
        "partial_nonzero": partial_nonzero,
        "full_nonzero": full_nonzero,
    }
