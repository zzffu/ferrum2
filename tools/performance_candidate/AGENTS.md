# Performance Candidate Controller Guidelines

The only command entry point is `python -B -m tools.performance_candidate`. Keep `cli.py` a
composition root. Shared JSON, identity, atomic output and pairing contracts have named owners;
the `linux/` package retains Linux workload/calibration/scale behavior.

`tun_mock.py` and `tun_mock_contract.py` own TUN-only run and evidence. Shared
`tools/owned_process.py` owns bounded child lifetimes and is part of controller identity.
The controller builds the crate-owned `tun-benchmark` with
`--no-default-features --features benchmark`; it never creates host network state or
invokes the privileged correctness runner.

Quick uses three interleaved pairs across six scenarios, Confirm five. Independent product builds
must share the exact benchmark recipe closure. Bind source SHAs, binaries, controller, workload,
mode, units, counts and environment. Preserve all raw trials and cleanup failures. Strict JSON
validation must reject boolean-as-integer, missing/extra fields and forged decisions. A/A observes
noise, never speedup; A/B requires an independently reviewed calibration manifest digest. Do not
reuse retired host thresholds or server CPU guards, or hide a bad pair in an aggregate score.

Keep the Windows child suspended until its kill-on-close job owns it; Unix children use an owned
process group. Timeouts, output caps, failures and leader exit must not leave descendants running.
Test real process behavior separately from synthetic evidence contracts. Network-independent
benchmarking does not prove real reactor, Wintun, WFP or complete product performance.

```text
python -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v
python -B -m tools.performance_candidate --help
```

Do not preserve retired host topology schemas, guest readers, performance script shims or aliases.
