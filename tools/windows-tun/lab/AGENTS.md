# Windows TUN Lab Guide

The repository, `tools/`, and parent Windows TUN guides remain in force. This directory owns neutral Hyper-V lab mechanics: topology inspection and provisioning, manifest-bound runtime validation, and read-only host/guest network-path proofs. It must not define qualification profiles, performance scenarios, thresholds, verdicts, or adoption policy.

Keep topology mutation in the explicitly authorized provisioning driver and keep inspection and runtime libraries read-only. Preserve fail-closed external manifest validation, resource ownership checks, checkpoint restoration, and the rule that no compatibility script remains at `tools/windows-tun/` after a move. Reusable host input, VM transaction, controller bundle, and JSON mechanics belong in `tools/powershell/Ferrum2.WindowsTun.Lab` rather than being copied here.

`provisioning-source-bundle.json` is the single closed source identity for the bootstrap, provisioning
driver, read-only topology owner, primary, host, guest, rollback, transaction, and the five loaded Lab
module owners. It binds exact role/path order,
bytes, per-file SHA-256 values, and the complete bundle hash. The driver validates that closure
before loading any owner and again across the transaction. Do not restore parent/child SHA literals
or add an owner outside this manifest.

`provision_windows_tun_hyperv_support_topology.ps1` is the sole public mutation driver. The primary
library owns host-side orchestration and remoting shape validation; its guest owner separately owns
support-interface configuration and readback. The host owner contains only support switch/interface
mechanics, while generic input, credential, VM lifecycle, and PowerShell Direct primitives remain in
`Ferrum2.WindowsTun.Lab`. The rollback owner keeps ownership audit, source restoration,
owned-resource removal, and terminal verification in separate helpers.

Topology plans and generated manifests use the neutral `lab_checkpoint` field exclusively. Do not
accept or emit a qualification-named compatibility field.

On an ordinary host, use only PowerShell parsing, `Invoke-ScriptAnalyzer`, module validation, and static contract tests. Do not provision or start Hyper-V, modify host networking, open a real TUN session, or run a performance workload.
