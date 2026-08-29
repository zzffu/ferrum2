# UDP owned-headroom qualification

This package owns the independently activatable Phase 7 qualification route.
Use only `python -B -m tools.performance_udp_headroom`; it does not alter the
shared performance-candidate dispatcher or its CLI.

The timed comparison builds `default` and `candidate-udp-owned-headroom` from
the same clean SHA. Neither timed artifact includes structural instrumentation.
Each of the five registered UDP scenarios receives two six-pair candidate A/A
rounds and one six-pair default-versus-candidate ABBA round.

After all timed trials, separate default and candidate builds enable structural
metrics and reuse the identical M4 GATE-05 UDP diagnostic workload on the same
host. The default record must show positive
`udp_payload_to_wire_copy_bytes` at both endpoints. The candidate record must
show zero copy bytes and positive `udp_owned_fast_path_hits` independently for
the client and server. Both records use the closed 49-counter schema.

GitHub-hosted `AuthenticAMD` evidence is provisional only. It cannot enable the
feature, satisfy GATE-03 or GATE-07, or make an adoption claim. Do not run the
workload on an ordinary development host; local verification is limited to
offline controller tests, formatting, imports, and workflow linting.
