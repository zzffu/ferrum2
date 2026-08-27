# Windows TUN Performance Tooling Guide

The repository, `tools/`, and parent Windows TUN guides remain in force. This directory is the only canonical home for the Windows TUN performance runner, trial collector, and UDP diagnostic collector. Performance code may measure throughput, latency, packet rate, lifecycle cost, and resource use; it must not define or emit a Windows TUN correctness-qualification verdict.

The runner may depend on `tools/powershell/Ferrum2.Performance` for performance behavior and `tools/powershell/Ferrum2.WindowsTun.Lab` for neutral controller-bundle, host-input, and Hyper-V transaction mechanics. It must not import `Ferrum2.Qualification.Evidence` or `Ferrum2.Qualification.HostHyperV`. Repository source paths retain the `tools/windows-tun/performance/` prefix even when the guest controller stages collectors by basename.

Plan-only and static verification may run on an ordinary host. Do not start Hyper-V, run trials or diagnostics, collect performance evidence, or open a real TUN session outside the approved guest procedure. The performance source manifest is a closed 38-source set: these three scripts, 25 `Ferrum2.Performance` owners, the six-file Lab module, and the guest-path probe, host-path helper, topology read-only owner, and topology runtime executed directly from `tools/windows-tun/lab`. All four helpers are source-manifest members. Any source change requires an atomic refresh of byte lengths and SHA-256 values.

The runner performs only the minimal same-bytes bootstrap check, then delegates flat-manifest
capture, dependency capture, and private locked staging to the canonical Lab bootstrap API. It must
execute or stage only that snapshot. Keep the private stage read-locked through the complete run;
module imports, direct owner loads, topology helpers, and guest-controller file maps must never
return to mutable repository source paths after validation.
