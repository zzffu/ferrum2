"""network model route owner."""

from __future__ import annotations


from tools.performance_candidate.windows_tun.network_model_identity import MAX_LIFECYCLE_METRIC, SCHEMA_VERSION, _exact_fields, _fail, _integer, _observation_identity

MAX_ROUTE_ELAPSED_NANOSECONDS = 240 * 1_000_000_000


ROUTE_ONCE_WORKLOAD = "udp-route-once"


ROUTE_GENERATIONS = 2


ROUTE_SOURCE_SLOTS = 64


ROUTE_TARGET_SLOTS = 4


ROUTE_DATAGRAMS_PER_TARGET = 32


def summarize_route_once_observation(observation: object) -> dict[str, object]:
    """Validate and summarize the fixed multi-target UDP workload."""

    row = _exact_fields(
        observation,
        {
            "schema_version",
            "workload",
            "identity",
            "elapsed_nanoseconds",
            "association_creation_elapsed_nanoseconds",
            "association_creations_observed",
            "router_invocations_observed",
            "generations",
        },
        "route-once observation",
    )
    if row["schema_version"] != SCHEMA_VERSION or row["workload"] != ROUTE_ONCE_WORKLOAD:
        _fail("route-once observation schema is unsupported")
    elapsed = _integer(
        row["elapsed_nanoseconds"],
        label="route-once elapsed_nanoseconds",
        minimum=1,
        maximum=MAX_ROUTE_ELAPSED_NANOSECONDS,
    )
    association_elapsed = _integer(
        row["association_creation_elapsed_nanoseconds"],
        label="route-once association_creation_elapsed_nanoseconds",
        minimum=1,
        maximum=elapsed,
    )
    identity = _observation_identity(row["identity"])
    expected_count = ROUTE_GENERATIONS * ROUTE_SOURCE_SLOTS
    association_creations = _integer(
        row["association_creations_observed"],
        label="route-once association_creations_observed",
        maximum=expected_count,
    )
    router_invocations = _integer(
        row["router_invocations_observed"],
        label="route-once router_invocations_observed",
        maximum=expected_count * ROUTE_TARGET_SLOTS,
    )
    if association_creations != expected_count:
        _fail("route-once workload did not create exactly one association per source and generation")
    if router_invocations != expected_count:
        _fail("route-once workload did not invoke the router exactly once per association")
    generations = row["generations"]
    if type(generations) is not list or len(generations) != ROUTE_GENERATIONS:
        _fail(f"route-once workload requires exactly {ROUTE_GENERATIONS} generations")

    datagrams_sent = 0
    direct_datagrams = 0
    proxy_datagrams = 0
    expected_targets = list(range(ROUTE_TARGET_SLOTS))
    expected_datagrams = ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET
    expected_path_datagrams = ROUTE_SOURCE_SLOTS // 2 * expected_datagrams
    prior_network_generation: int | None = None
    for generation_index, generation_value in enumerate(generations, start=1):
        generation_label = f"route-once generation[{generation_index - 1}]"
        generation = _exact_fields(
            generation_value,
            {
                "ordinal",
                "network_generation",
                "session_generation",
                "direct_datagrams_observed",
                "direct_replies_observed",
                "proxy_datagrams_observed",
                "proxy_replies_observed",
                "associations",
            },
            generation_label,
        )
        if generation["ordinal"] != generation_index:
            _fail(f"{generation_label}.ordinal is not contiguous")
        network_generation = _integer(
            generation["network_generation"],
            label=f"{generation_label}.network_generation",
            minimum=1,
            maximum=MAX_LIFECYCLE_METRIC,
        )
        session_generation = _integer(
            generation["session_generation"],
            label=f"{generation_label}.session_generation",
            minimum=1,
            maximum=MAX_LIFECYCLE_METRIC,
        )
        if network_generation != session_generation:
            _fail(f"{generation_label} network and session generations must match")
        if prior_network_generation is not None and network_generation != prior_network_generation + 1:
            _fail("route-once reset must advance the generation exactly once")
        prior_network_generation = network_generation
        for path in ("direct", "proxy"):
            observed_datagrams = _integer(
                generation[f"{path}_datagrams_observed"],
                label=f"{generation_label}.{path}_datagrams_observed",
                maximum=expected_path_datagrams,
            )
            observed_replies = _integer(
                generation[f"{path}_replies_observed"],
                label=f"{generation_label}.{path}_replies_observed",
                maximum=expected_path_datagrams,
            )
            if observed_datagrams != expected_path_datagrams or observed_replies != expected_path_datagrams:
                _fail(f"{generation_label} did not observe the exact {path} traffic split")
            if path == "direct":
                direct_datagrams += observed_datagrams
            else:
                proxy_datagrams += observed_datagrams
        associations = generation["associations"]
        if type(associations) is not list or len(associations) != ROUTE_SOURCE_SLOTS:
            _fail(f"{generation_label} requires exactly {ROUTE_SOURCE_SLOTS} associations")
        observed_sources: set[int] = set()
        for association_index, association_value in enumerate(associations):
            label = f"{generation_label}.association[{association_index}]"
            association = _exact_fields(
                association_value,
                {
                    "source_slot",
                    "target_slots",
                    "first_target_slot",
                    "datagrams_sent",
                    "replies_received",
                },
                label,
            )
            source_slot = _integer(
                association["source_slot"],
                label=f"{label}.source_slot",
                maximum=ROUTE_SOURCE_SLOTS - 1,
            )
            if source_slot in observed_sources:
                _fail(f"{generation_label} source slot {source_slot} is duplicated")
            observed_sources.add(source_slot)
            if association["target_slots"] != expected_targets:
                _fail(f"{label}.target_slots does not cover the deterministic target set")
            expected_first_target = 0 if source_slot % 2 == 0 else 1
            if association["first_target_slot"] != expected_first_target:
                _fail(f"{label}.first_target_slot does not select the closed outbound split")
            if association["datagrams_sent"] != expected_datagrams:
                _fail(f"{label}.datagrams_sent does not match the workload recipe")
            if association["replies_received"] != expected_datagrams:
                _fail(f"{label}.replies_received does not account for every datagram")
            datagrams_sent += expected_datagrams
        if observed_sources != set(range(ROUTE_SOURCE_SLOTS)):
            _fail(f"{generation_label} does not cover every source slot")

    per_target_baseline = expected_count * ROUTE_TARGET_SLOTS
    return {
        "schema_version": SCHEMA_VERSION,
        "workload": ROUTE_ONCE_WORKLOAD,
        "identity": dict(identity),
        "associations_created": association_creations,
        "datagrams_sent": datagrams_sent,
        "direct_datagrams_observed": direct_datagrams,
        "proxy_datagrams_observed": proxy_datagrams,
        "packets_per_second": datagrams_sent * 1_000_000_000 // elapsed,
        "associations_per_second": association_creations * 1_000_000_000
        // association_elapsed,
        "router_invocations": router_invocations,
        "per_target_routing_baseline": per_target_baseline,
        "router_invocations_avoided": per_target_baseline - router_invocations,
        "direct_and_proxy_verified": True,
        "route_once_verified": True,
        "post_reset_reroute_verified": True,
    }
