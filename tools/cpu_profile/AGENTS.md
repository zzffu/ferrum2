# CPU Diagnostic Owner Guidelines

The only public entry point is `tools/profile-cpu.sh`. This private package owns the Linux
attach-only helper lifecycle, private artifacts, and bounded container parsing. Do not start a
workload, signal a Ferrum/M4 target, change perf permissions, install tools, or provide a fallback.

Every subprocess goes through the owned helper group and bounded dual-pipe/deadline contract.
Preserve errors and partial artifacts. `COLLECTED` is diagnostic command completion only;
unbound build/workload/window identity or unverified sample/loss/symbol schemas cannot produce
analysis or adoption qualification. A container-valid JSON object is not validated CPU samples.

Offline tests live under the existing `tests/ci/test_cpu_profile*.py` gate. Use small artifacts,
injected collectors, and finite fake helper processes; never run real perf/Samply or workloads.
Linux helper tests are Linux-only; do not claim their execution from Windows-skipped results.
