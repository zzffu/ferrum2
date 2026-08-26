"""scale decision owner."""

from __future__ import annotations

from tools.performance_candidate.json_contract import CandidateControlError, _scale_decimal
from tools.performance_candidate.linux.catalog import SUMMARY_SCHEMA_VERSION, WARNING_POLICY
from tools.performance_candidate.pairing import _display_decimal, _improvement, _median
from tools.performance_candidate.status import CALIBRATION_REQUIRED, REGRESSION, WITHIN_CALIBRATED_BAND
from tools.performance_candidate.linux.scale import scale_policy_is_applicable

from collections.abc import Sequence
from decimal import Decimal
from fractions import Fraction

from tools.performance_candidate.linux.scale import SCALE_RECIPE, SCALE_SCENARIO, validate_scale_safety_policy
from tools.performance_candidate.linux.scale_trial import _scale_stage_median, _truncating_division, _validate_scale_evidence

def _fraction_from_policy(value: object, field: str) -> Fraction:
    decimal = _scale_decimal(value, field)
    return Fraction(decimal)


def _median_fraction(values: Sequence[Fraction]) -> Fraction:
    ordered = sorted(values)
    if not ordered:
        raise CandidateControlError("scale median requires values")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _fraction_display(value: Fraction) -> float:
    return _display_decimal(Decimal(value.numerator) / Decimal(value.denominator))


def _scale_trial_observation(
    row: dict[str, object], policy: dict[str, object]
) -> tuple[dict[str, object], list[str]]:
    derived = _validate_scale_evidence(row)
    scale = row["scale"]
    correctness = scale["correctness"]
    resource = scale["resource"]
    samples = derived["samples"]
    fairness = derived["fairness"]
    failures: list[str] = []
    if row["cpu_count"] < 4:
        failures.append("HOST_CPU_COUNT")
    if row["memory_kib"] < 15_000_000:
        failures.append("HOST_MEMORY_TOTAL")
    expected_correctness = {
        "target_accepted": 10_000,
        "client_active": 10_000,
        "server_active": 10_000,
        "touch_completed_flows": 10_000,
        "touch_completed_round_trips": 20_000,
        "touch_checked_bytes": 20_000 * 32_768,
        "partial_nonzero_flows": 1_000,
        "full_nonzero_flows": 10_000,
        "application_tasks_joined": 10_000,
        "target_tasks_joined": 10_000,
    }
    for field, expected in expected_correctness.items():
        if correctness[field] != expected:
            failures.append(f"CORRECTNESS_{field.upper()}")
    for field in ("drain", "rebind", "cleanup"):
        if correctness[field] != "PASS":
            failures.append(f"CORRECTNESS_{field.upper()}")
    if resource["memory_available_kib"] < 8_000_000:
        failures.append("HOST_MEMORY_AVAILABLE")
    if resource["nofile_soft"] < 65_536:
        failures.append("HOST_NOFILE")
    for stage in ("pre_load", "drained"):
        for sample in samples[stage]:
            if sample["client_active"] != 0 or sample["server_active"] != 0:
                failures.append(f"RESOURCE_{stage.upper()}_ACTIVE")
                break
    pre = samples["pre_load"][0]
    drained = samples["drained"][0]
    for field in ("client_fds", "server_fds", "client_tasks", "server_tasks"):
        if drained[field] != pre[field]:
            failures.append(f"RESOURCE_DRAINED_{field.upper()}")
    owner_fields = (
        "client_active",
        "client_fds",
        "client_tasks",
        "server_active",
        "server_fds",
        "server_tasks",
    )
    owner_tuple = tuple(samples["established"][0][field] for field in owner_fields)
    for stage in (
        "established",
        "touched",
        "partial_active",
        "full_active",
        "post_full",
    ):
        for sample in samples[stage]:
            if tuple(sample[field] for field in owner_fields) != owner_tuple:
                failures.append(f"RESOURCE_{stage.upper()}_OWNER_TUPLE")
                break
    if owner_tuple[0] != 10_000 or owner_tuple[3] != 10_000:
        failures.append("RESOURCE_ESTABLISHED_ACTIVE")
    jain = fairness["jain_fraction"]
    ratio = fairness["p01_median_fraction"]
    if jain < _fraction_from_policy(
        policy["minimum_trial_jain_index"], "minimum_trial_jain_index"
    ):
        failures.append("TRIAL_JAIN")
    if ratio < _fraction_from_policy(
        policy["minimum_trial_p01_median_ratio"],
        "minimum_trial_p01_median_ratio",
    ):
        failures.append("TRIAL_P01_MEDIAN_RATIO")
    if derived["partial_nonzero"] != 1_000:
        failures.append("PARTIAL_ALL_FLOWS_NONZERO")
    if derived["full_nonzero"] != 10_000:
        failures.append("FULL_ALL_FLOWS_NONZERO")
    post_limit = _scale_decimal(
        policy["maximum_post_full_percent_of_page_touched"],
        "maximum_post_full_percent_of_page_touched",
    )
    resource_medians: dict[str, int] = {}
    for side in ("client", "server"):
        field = f"{side}_smaps_rss_kib"
        established = _scale_stage_median(samples["established"], field)
        touched = _scale_stage_median(samples["touched"], field)
        post = _scale_stage_median(samples["post_full"], field)
        resource_medians[f"{side}_established_smaps_rss_kib"] = established
        resource_medians[f"{side}_touched_smaps_rss_kib"] = touched
        resource_medians[f"{side}_post_full_smaps_rss_kib"] = post
        if touched == 0:
            failures.append(f"{side.upper()}_TOUCHED_RSS_ZERO")
        elif Decimal(post) * 100 > Decimal(touched) * post_limit:
            failures.append(f"{side.upper()}_POST_FULL_RSS")
    observation = {
        "pair": row["pair"],
        "member": row["member"],
        "order": row["order"],
        "throughput_bytes_per_second": row["value"],
        "jain_index": _fraction_display(jain),
        "jain_numerator": jain.numerator,
        "jain_denominator": jain.denominator,
        "p01_median_ratio": _fraction_display(ratio),
        "p01_median_numerator": ratio.numerator,
        "p01_median_denominator": ratio.denominator,
        "partial_nonzero_flows": derived["partial_nonzero"],
        "full_nonzero_flows": derived["full_nonzero"],
        "client_touched_increment_bytes_per_connection": resource[
            "client_touched_increment_bytes_per_connection"
        ],
        "server_touched_increment_bytes_per_connection": resource[
            "server_touched_increment_bytes_per_connection"
        ],
        "combined_touched_increment_bytes_per_connection": resource[
            "combined_touched_increment_bytes_per_connection"
        ],
        **resource_medians,
        "failures": sorted(set(failures)),
    }
    return observation, failures


def _summarize_scale_evidence(
    *,
    plan: dict[str, object],
    rows: dict[tuple[str, int, str], dict[str, object]],
    parent_sha: str,
    candidate_sha: str,
    member_identity: dict[str, tuple[object, ...]],
    identity_fields: tuple[str, ...],
    evidence_files: list[dict[str, str]],
) -> dict[str, object]:
    policy = plan["scale_safety_policy"]
    validate_scale_safety_policy(policy)
    failures: list[str] = []
    trial_observations: list[dict[str, object]] = []
    pair_observations: list[dict[str, object]] = []
    jain_deltas: list[Fraction] = []
    ratio_deltas: list[Fraction] = []
    throughput_improvements: list[Decimal] = []
    throughput_wins = 0
    maximum_process_gog = _scale_decimal(
        policy[
            "maximum_page_touch_growth_of_growth_kib_per_connection_per_process"
        ],
        "maximum_page_touch_growth_of_growth_kib_per_connection_per_process",
    )
    maximum_combined_gog = _scale_decimal(
        policy["maximum_page_touch_growth_of_growth_kib_per_connection_combined"],
        "maximum_page_touch_growth_of_growth_kib_per_connection_combined",
    )
    sessions = SCALE_RECIPE["sessions"]
    for pair in range(1, plan["pairs"] + 1):
        parent = rows[(SCALE_SCENARIO, pair, "parent")]
        candidate = rows[(SCALE_SCENARIO, pair, "candidate")]
        if {parent["order"], candidate["order"]} != {1, 2}:
            raise CandidateControlError(f"scale pair={pair} must contain orders 1 and 2")
        expected_parent_order = 1 if pair % 2 else 2
        if parent["order"] != expected_parent_order:
            raise CandidateControlError(f"scale pair={pair} does not alternate order")
        parent_observation, parent_failures = _scale_trial_observation(parent, policy)
        candidate_observation, candidate_failures = _scale_trial_observation(
            candidate, policy
        )
        trial_observations.extend((parent_observation, candidate_observation))
        failures.extend(f"PAIR_{pair}_PARENT_{failure}" for failure in parent_failures)
        failures.extend(
            f"PAIR_{pair}_CANDIDATE_{failure}" for failure in candidate_failures
        )
        parent_derived = _validate_scale_evidence(parent)
        candidate_derived = _validate_scale_evidence(candidate)
        jain_delta = (
            candidate_derived["fairness"]["jain_fraction"]
            - parent_derived["fairness"]["jain_fraction"]
        )
        ratio_delta = (
            candidate_derived["fairness"]["p01_median_fraction"]
            - parent_derived["fairness"]["p01_median_fraction"]
        )
        jain_deltas.append(jain_delta)
        ratio_deltas.append(ratio_delta)
        improvement: Decimal | None = None
        if parent["value"] == 0:
            failures.append(f"PAIR_{pair}_ZERO_PARENT_THROUGHPUT")
        else:
            improvement = _improvement(
                parent["value"], candidate["value"], "higher_is_better"
            )
            throughput_improvements.append(improvement)
            if improvement > 0:
                throughput_wins += 1
            if improvement < _scale_decimal(
                policy["minimum_pair_throughput_improvement_percent"],
                "minimum_pair_throughput_improvement_percent",
            ):
                failures.append(f"PAIR_{pair}_THROUGHPUT_FLOOR")
        growth_of_growth_kib: dict[str, int] = {}
        for side in ("client", "server"):
            field = f"{side}_smaps_rss_kib"
            parent_growth = _scale_stage_median(
                parent_derived["samples"]["touched"], field
            ) - _scale_stage_median(parent_derived["samples"]["established"], field)
            candidate_growth = _scale_stage_median(
                candidate_derived["samples"]["touched"], field
            ) - _scale_stage_median(
                candidate_derived["samples"]["established"], field
            )
            growth_of_growth_kib[side] = candidate_growth - parent_growth
        client_gog_kib = growth_of_growth_kib["client"]
        server_gog_kib = growth_of_growth_kib["server"]
        combined_gog_kib = client_gog_kib + server_gog_kib
        if Decimal(client_gog_kib) > maximum_process_gog * sessions:
            failures.append(f"PAIR_{pair}_CLIENT_PAGE_TOUCH_GOG")
        if Decimal(server_gog_kib) > maximum_process_gog * sessions:
            failures.append(f"PAIR_{pair}_SERVER_PAGE_TOUCH_GOG")
        if Decimal(combined_gog_kib) > maximum_combined_gog * sessions:
            failures.append(f"PAIR_{pair}_COMBINED_PAGE_TOUCH_GOG")
        client_gog_bytes = _truncating_division(client_gog_kib * 1024, sessions)
        server_gog_bytes = _truncating_division(server_gog_kib * 1024, sessions)
        combined_gog_bytes = _truncating_division(combined_gog_kib * 1024, sessions)
        pair_observations.append(
            {
                "pair": pair,
                "parent_order": parent["order"],
                "candidate_order": candidate["order"],
                "parent_throughput_bytes_per_second": parent["value"],
                "candidate_throughput_bytes_per_second": candidate["value"],
                "throughput_improvement_percent": (
                    None if improvement is None else _display_decimal(improvement)
                ),
                "jain_delta": _fraction_display(jain_delta),
                "p01_median_ratio_delta": _fraction_display(ratio_delta),
                "client_page_touch_growth_of_growth_bytes_per_connection": client_gog_bytes,
                "server_page_touch_growth_of_growth_bytes_per_connection": server_gog_bytes,
                "combined_page_touch_growth_of_growth_bytes_per_connection": combined_gog_bytes,
            }
        )
    median_jain_delta = _median_fraction(jain_deltas)
    median_ratio_delta = _median_fraction(ratio_deltas)
    if median_jain_delta < _fraction_from_policy(
        policy["minimum_median_jain_delta"], "minimum_median_jain_delta"
    ):
        failures.append("MEDIAN_JAIN_DELTA")
    if median_ratio_delta < _fraction_from_policy(
        policy["minimum_median_p01_median_ratio_delta"],
        "minimum_median_p01_median_ratio_delta",
    ):
        failures.append("MEDIAN_P01_MEDIAN_RATIO_DELTA")
    median_throughput: Decimal | None = None
    minimum_throughput: Decimal | None = None
    if len(throughput_improvements) != plan["pairs"]:
        failures.append("THROUGHPUT_PAIR_SET")
    else:
        median_throughput = _median(throughput_improvements)
        minimum_throughput = min(throughput_improvements)
        if median_throughput < _scale_decimal(
            policy["minimum_median_throughput_improvement_percent"],
            "minimum_median_throughput_improvement_percent",
        ):
            failures.append("MEDIAN_THROUGHPUT")
    if throughput_wins < policy["minimum_throughput_wins"]:
        failures.append("THROUGHPUT_WINS")
    failures = sorted(set(failures))
    passed = not failures
    build_identities = {
        member: dict(zip(identity_fields, member_identity[member], strict=True))
        for member in ("parent", "candidate")
    }
    first_row = next(iter(rows.values()))
    policy_applicable = scale_policy_is_applicable(
        policy, plan["scenarios"][0], first_row["environment_identity"]
    )
    status = (
        REGRESSION
        if not passed
        else WITHIN_CALIBRATED_BAND
        if policy_applicable
        else CALIBRATION_REQUIRED
    )
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "kind": "performance_candidate_summary",
        "mode": plan["mode"],
        "selection": plan["selection"],
        "selected_scenario": SCALE_SCENARIO,
        "scenario_group": SCALE_SCENARIO,
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "build_identities": build_identities,
        "environment_identity": dict(first_row["environment_identity"]),
        "pairs": plan["pairs"],
        "decision_policy": plan["decision_policy"],
        "scale_safety_policy": policy,
        "scale_lineage": plan["scale_lineage"],
        "warning_policy": dict(WARNING_POLICY),
        "decision_enabled": policy_applicable,
        "candidate_win_enabled": False,
        "decision_reason": (
            "reviewed six-pair scale calibration is required"
            if passed and not policy_applicable
            else "all dedicated tcp-scale safety gates passed"
            if passed
            else "one or more dedicated tcp-scale safety gates failed"
        ),
        "threshold_availability": "scale_safety" if policy_applicable else "none",
        "adoption_claim": False,
        "status": status,
        "workflow_failure_reason": (
            None
            if status == WITHIN_CALIBRATED_BAND
            else "reviewed six-pair scale calibration is required"
            if status == CALIBRATION_REQUIRED
            else "; ".join(failures)
        ),
        "mandatory_scenarios": [SCALE_SCENARIO],
        "missing_scenarios": [],
        "primary_results": [],
        "guard_results": [],
        "scenarios": [{"scenario": SCALE_SCENARIO, "status": status}],
        "scale_safety": {
            "schema_version": 1,
            "status": "PASS" if passed else "FAIL",
            "failures": failures,
            "throughput_wins": throughput_wins,
            "median_throughput_improvement_percent": (
                None
                if median_throughput is None
                else _display_decimal(median_throughput)
            ),
            "minimum_throughput_improvement_percent": (
                None
                if minimum_throughput is None
                else _display_decimal(minimum_throughput)
            ),
            "median_jain_delta": _fraction_display(median_jain_delta),
            "median_p01_median_ratio_delta": _fraction_display(median_ratio_delta),
            "trials": sorted(
                trial_observations, key=lambda item: (item["pair"], item["order"])
            ),
            "pairs": pair_observations,
        },
        "evidence_files": sorted(
            evidence_files, key=lambda item: (item["member"], item["file"])
        ),
    }
