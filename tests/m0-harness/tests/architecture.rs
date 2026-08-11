use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const CURRENT_COMPATIBILITY_MEMBERS: [&str; 13] = [
    "bins/ferrum2-client",
    "bins/ferrum2-server",
    "crates/ferrum2-config",
    "crates/ferrum2-core",
    "crates/ferrum2-crypto",
    "crates/ferrum2-observability",
    "crates/ferrum2-runtime",
    "crates/ferrum2-shadowsocks",
    "crates/ferrum2-sniff",
    "crates/ferrum2-socks5",
    "crates/ferrum2-tun",
    "crates/ferrum2-wintun",
    "tests/m0-harness",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("harness must be two levels below the workspace root")
        .to_path_buf()
}

#[test]
fn m16_managed_tun_route_and_binding_have_one_owner_and_fail_closed_order() {
    let root = workspace_root();
    let wintun = fs::read_to_string(root.join("crates/ferrum2-wintun/src/windows.rs"))
        .expect("Wintun Windows owner");
    let tun = fs::read_to_string(root.join("crates/ferrum2-tun/src/lib.rs")).expect("TUN owner");
    let client = fs::read_to_string(root.join("bins/ferrum2-client/src/run.rs"))
        .expect("client composition");
    let egress = fs::read_to_string(root.join("bins/ferrum2-client/src/run/egress/mod.rs"))
        .expect("client egress");
    let udp = fs::read_to_string(root.join("bins/ferrum2-client/src/run/egress/udp.rs"))
        .expect("client UDP egress");

    assert!(
        wintun.contains("GetBestInterfaceEx")
            && wintun.contains("GetBestRoute2")
            && wintun.contains("InitializeIpForwardEntry")
            && wintun.contains("CreateIpForwardEntry2")
            && wintun.contains("GetIpForwardEntry2")
            && wintun.contains("DeleteIpForwardEntry2")
            && wintun.contains("install_managed_dns(")
            && wintun.contains("restore_managed_dns(")
            && wintun.contains("self.0.pending_route = Some(row)")
            && wintun
                .contains("take_last_owned_route(&mut state.pending_route, &mut state.routes)",)
            && wintun.contains("pending.take().or_else(|| journal.pop())")
            && wintun.contains("IP_UNICAST_IF")
            && wintun.contains("to_be()"),
        "the sole unsafe Wintun owner must retain route discovery, exact route journal and network-order socket binding"
    );
    assert!(
        tun.contains("let underlay = adapter.underlay_policy();")
            && tun.contains("underlay.publish(policy)")
            && tun.find("underlay.publish(policy)").unwrap()
                < tun.find("return Ok(Some(TunRoot").unwrap(),
        "the Wintun owner must publish its immutable underlay policy before Ready"
    );
    assert!(
        client.rfind("roots.push(tun::process_root(")
            > client.rfind("roots.push(ProcessRoot::new("),
        "the managed TUN root must be composed last"
    );
    let tcp_binding_precedes_connect = |source: &str| {
        let source = source.split_whitespace().collect::<String>();
        let connect = source.find("operations.connect(socket,address).await")?;
        let fixed = source.find("operations.bind_fixed(&socket,endpoint)?")?;
        let default = source.find("operations.bind_default(&socket)?")?;
        (fixed < connect
            && default < connect
            && source.contains(
                "TCP_BINDING.try_with(|binding|*binding).map_err(|_|std::io::Error::other(\"managedTCPbindingcontextmissing\"))?",
            )
            && !source.contains("unwrap_or(TcpBinding::None)")
            && source.matches("operations.connect(socket,address).await").count() == 1)
            .then_some(())
    };
    let udp_binding_precedes_io = |source: &str| {
        let source = source.split_whitespace().collect::<String>();
        let connect = source.find("operations.connect(&socket,endpoint).await.map_err(|_|())?")?;
        let fixed = source.find("operations.bind_fixed(&socket,endpoint)?")?;
        let default = source.find("operations.bind_default(&socket)?")?;
        let managed = source.find("ClientDirectUdpSocket::Managed{ipv4,ipv6}")?;
        (fixed < connect
            && default < connect
            && connect < managed
            && source.contains("iftarget.is_ipv4()=>ipv4.send_to(payload,target).await")
            && source.contains("ipv6:Some(ipv6),..}=>ipv6.send_to(payload,target).await")
            && source.contains("Self::Managed{ipv6:None,..}=>")
            && source.contains("managed_direct_udp_ipv6_allowed(origin)"))
        .then_some(())
    };
    assert!(
        tcp_binding_precedes_connect(&egress).is_some() && udp_binding_precedes_io(&udp).is_some(),
        "the existing client egress engine must bind before connect/send and never retry unpinned"
    );
    for mutation in [
        egress.replace(
            "operations.bind_fixed(&socket, endpoint)",
            ".bind_fixed_after_connect(endpoint)",
        ),
        egress.replace(
            "operations.bind_default(&socket)",
            ".bind_default_after_connect(&socket)",
        ),
        egress.replace(
            "operations.connect(socket, address).await",
            "unbound_connect(address).await",
        ),
    ] {
        assert!(
            tcp_binding_precedes_connect(&mutation).is_none(),
            "TCP bind/connect mutation survived"
        );
    }
    for mutation in [
        udp.replace(
            "operations.bind_fixed(&socket, endpoint)",
            ".bind_fixed_after_send(endpoint)",
        ),
        udp.replace(
            "operations.bind_default(&socket)",
            "bind_after_send(&socket)",
        ),
        udp.replace(
            "ipv4.send_to(payload, target)",
            "ipv6.send_to(payload, target)",
        ),
    ] {
        assert!(
            udp_binding_precedes_io(&mutation).is_none(),
            "UDP bind/send mutation survived"
        );
    }

    let wintun = wintun.split_whitespace().collect::<String>();
    let preflight = wintun
        .find("forrowinrows{operations.require_absent(row)?;}forrowinrows{operations.create_pending(*row)?;")
        .is_some();
    let post_capture = wintun
        .split("fnunderlay_matches_with")
        .nth(1)
        .and_then(|body| body.split("structPlatformUnderlay").next())
        .is_some_and(|body| {
            body.contains("eligible_interfaces(Some(owned))")
                && body.contains("constrained_route(*endpoint.ip(),expected.interface_index,true)")
                && !body.contains("best_interface(")
        });
    assert!(
        preflight
            && post_capture
            && wintun.contains("prepare_managed_intent(self.config.managed_ipv4()")
            && wintun.contains("let(handles,context)=subscribe_notification_sequence(")
            && wintun.contains("failed.push(handle)")
            && wintun.contains("handles.append(&mutfailed)")
            && wintun.contains("ifself.cancel_all(){leak_notification_owners")
            && egress.contains("(ClientRequestOrigin::Dns, true) => TcpBinding::Fixed")
            && udp.contains("ManagedUdpBinding::Fixed(endpoint)"),
        "notification lifetime, all-key route preflight, frozen underlay and fixed DNS binding must stay closed"
    );
    let finish = wintun
        .split("fnfinish_managed")
        .nth(1)
        .and_then(|body| body.split("fncleanup_inner").next())
        .expect("managed finish transaction");
    let cleanup = wintun
        .split("fncleanup_transaction")
        .nth(1)
        .and_then(|body| body.split("structPlatformCleanup").next())
        .expect("managed cleanup transaction");
    assert!(
        finish.find("install_managed_dns(").unwrap()
            < finish.find("install_managed_routes(").unwrap()
            && cleanup.find("cleanup.delete_last_route()").unwrap()
                < cleanup.find("cleanup.restore_dns()").unwrap(),
        "IPv4 DNS must apply before capture and restore after capture removal"
    );
}

#[test]
fn m16_managed_tun_pre_snapshot_generation_is_authoritative() {
    let source = fs::read_to_string(workspace_root().join("crates/ferrum2-wintun/src/windows.rs"))
        .expect("Wintun Windows owner");
    let compact = source.split_whitespace().collect::<String>();
    let (product, _) = compact
        .split_once("#[cfg(test)]modtests{")
        .expect("exact Wintun test module boundary");
    let finish = source
        .split("fn finish_managed")
        .nth(1)
        .and_then(|source| source.split("fn cleanup_inner").next())
        .expect("managed finish caller path")
        .split_whitespace()
        .collect::<String>();
    assert_eq!(
        finish
            .matches("owned,state.snapshot_generation,||state.notifications.generation()")
            .count(),
        2,
        "both pre/post-capture checks must use the generation stored before snapshot"
    );
    assert!(
        !finish.contains("settled_generation")
            && !finish.contains("state.snapshot_generation=")
            && finish.find("underlay_snapshot_matches(").unwrap()
                < finish.find("install_managed_routes(").unwrap()
            && finish.rfind("underlay_snapshot_matches(").unwrap()
                > finish.find("install_managed_routes(").unwrap(),
        "the authoritative generation cannot be rebased or omit either validation"
    );
    let publisher = compact
        .split("fnpublish_owned_luid")
        .nth(1)
        .and_then(|body| body.split("structNotificationCallbackGuard").next())
        .expect("notification owner publisher");
    let classifier = compact
        .split("fnclassify_notification_luid")
        .nth(1)
        .and_then(|body| body.split("structManagedState").next())
        .expect("notification LUID classifier");
    assert!(
        compact.contains("provisional_luid:AtomicU64")
            && compact.contains("callbacks_in_flight:AtomicU64")
            && product.matches("classify_notification_luid(").count() == 4
            && publisher
                .contains("owned_luid.compare_exchange(0,luid,Ordering::SeqCst,Ordering::SeqCst)",)
            && publisher.find("owned_luid.compare_exchange").unwrap()
                < publisher
                    .find("whileself.callbacks_in_flight.load")
                    .unwrap()
            && publisher
                .find("whileself.callbacks_in_flight.load")
                .unwrap()
                < publisher.find("provisional_luid.swap").unwrap()
            && publisher.contains("cancelled.load(Ordering::Acquire)||Instant::now()>=deadline")
            && publisher.contains("provisional_luid.swap(0,Ordering::SeqCst)")
            && publisher.contains("provisional!=0&&provisional!=luid")
            && classifier
                .find("NotificationCallbackGuard::enter(context)")
                .unwrap()
                < classifier
                    .find("owned_luid.load(Ordering::SeqCst)")
                    .unwrap()
            && classifier
                .matches("owned_luid.load(Ordering::SeqCst)")
                .count()
                == 1
            && classifier.contains("ifowned!=0{ifowned!=luid")
            && classifier.contains(
                "provisional_luid.compare_exchange(0,luid,Ordering::SeqCst,Ordering::SeqCst)",
            )
            && classifier.contains("ifprovisional_mismatch")
            && compact.contains("set_owned_luid(self.luid,deadline,cancelled)?")
            && compact.contains("set_owned_luid(self.owner.luid,self.deadline,self.cancelled)?",),
        "callback entry, owner publication, drain and provisional reconciliation must remain ordered and fallible"
    );
}

#[test]
fn m16_observability_and_network_change_lifecycle_stay_redacted_and_owner_driven() {
    let root = workspace_root();
    let source = fs::read_to_string(root.join("crates/ferrum2-wintun/src/windows.rs"))
        .expect("Wintun Windows owner");
    let compact = source.split_whitespace().collect::<String>();
    let callbacks = compact
        .split("unsafeextern\"system\"fnroute_changed")
        .nth(1)
        .and_then(|body| body.split("structManagedState").next())
        .expect("bounded notification callback region");
    assert!(
        callbacks.matches("classify_notification_luid(").count() == 4
            && callbacks.contains(
                "ifcontext.monitor_runtime.load(Ordering::Acquire){context.signal_owner();return;"
            )
            && compact.contains("ifletSome(wake)=&self.wake{let_=wake.signal();}")
            && !callbacks.contains("tracing::")
            && !callbacks.contains("format!(")
            && !callbacks.contains("println!(")
            && !callbacks.contains("Vec::")
            && !callbacks.contains("Box::"),
        "callbacks may only classify and signal their owner"
    );
    assert!(
        compact.contains("ResetEvent(self.network_change.0.0)")
            && compact.contains("self.revalidate_managed_network().unwrap_or(false)")
            && compact.contains("state.policy.invalidate()")
            && compact.contains("self.valid.load(Ordering::Acquire)")
            && compact.contains("managed_routes_match(&state.routes")
            && compact.contains("cleanup.cancel_notifications()")
            && compact.find("cleanup.delete_last_route()").unwrap()
                < compact.find("cleanup.restore_dns()").unwrap(),
        "the owner must revoke binding, revalidate exact state and clean capture before DNS"
    );

    let qualifier = fs::read_to_string(root.join("tests/platform/qualify_windows_tun.ps1"))
        .expect("Windows TUN qualifier");
    let identity = qualifier
        .split("function Get-NetworkFeasibilityIdentity")
        .nth(1)
        .and_then(|body| body.split("function Get-Tcp01Boundary").next())
        .expect("bounded canonical identity loader");
    let artifact_checks = identity
        .find("Get-FileHash -LiteralPath $binary")
        .zip(identity.find("Get-FileHash -LiteralPath $serverBinary"))
        .zip(identity.find("Get-CimInstance Win32_OperatingSystem"));
    assert!(
        identity.contains("[bool]$RequireServer")
            && identity.contains("\"client_sha256\", \"server_sha256\"")
            && identity.contains("$ledger.client_sha256 -cmatch '^[0-9a-f]{64}$'")
            && identity.contains("$ledger.server_sha256 -cmatch '^[0-9a-f]{64}$'")
            && identity.contains("Test-Path -LiteralPath $binary")
            && identity.contains("if (Test-Path -LiteralPath $serverBinary)")
            && identity.contains("Assert-True (-not $RequireServer)")
            && artifact_checks.is_some_and(|((client, server), os)| client < server && server < os)
            && !identity.contains("git -C $workspace"),
        "one canonical ledger must bind required staged artifacts before guest identity or product work"
    );
    let build_dispatch = qualifier
        .split(
            "if ($Mode -notin @(\"network-feasibility\", \"managed-product\", \"full\", \"hard-kill\"))",
        )
        .nth(1)
        .and_then(|body| body.split("if ($Mode -eq \"managed-product\")").next())
        .expect("bounded staged/legacy build dispatch");
    assert!(
        qualifier.contains(
            "Get-NetworkFeasibilityIdentity $IdentityLedger ($Mode -eq \"full\")",
        ) && qualifier.contains(
            "if ($Mode -notin @(\"network-feasibility\", \"managed-product\", \"full\", \"hard-kill\"))",
        ) && build_dispatch.contains("if ($Mode -in @(\"tcp\", \"udp\", \"performance\"))")
            && !build_dispatch.contains("\"full\""),
        "identity-bound modes must consume staged artifacts while legacy M15 modes retain local builds"
    );
    let integrated = qualifier
        .split("if ($Mode -in @(\"full\", \"hard-kill\")) {")
        .nth(1)
        .and_then(|body| {
            body.split("if ($Mode -eq \"network-feasibility\") {")
                .next()
        })
        .expect("bounded integrated lifecycle profile");
    let system_dns_witness = qualifier
        .split("function Invoke-SystemDnsWitness")
        .nth(1)
        .and_then(|body| body.split("function Open-TunTcp").next())
        .expect("bounded system DNS witness");
    let adapter_readiness = qualifier
        .split("function Wait-AdapterReady")
        .nth(1)
        .and_then(|body| body.split("function Wait-AdapterAbsent").next())
        .expect("bounded adapter readiness");
    let adapter_cycles = qualifier
        .split("function Invoke-AdapterCycles")
        .nth(1)
        .and_then(|body| body.split("try {").next())
        .expect("bounded adapter cycles");
    let managed_cycle_metrics = adapter_cycles
        .split("if ($Managed) {")
        .nth(1)
        .and_then(|body| body.split('}').next())
        .expect("bounded managed cycle metrics");
    assert!(
        integrated.contains("Invoke-TunProductTcp $supportAddress $supportTcpPort")
            && integrated.contains("Invoke-TunProductUdp $supportAddress $supportUdpPort")
            && integrated.matches("Invoke-SystemDnsWitness").count() == 3
            && integrated.contains("[[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"127.0.0.1:$managedDnsPort\"")
            && integrated.matches("[[dns.inbounds]]").count() == 1
            && integrated.contains("foreach ($managedConfig in @($managedLifecycleConfig, $managedRouteOnlyConfig))")
            && integrated.contains("& $binary --config $managedConfig --check-config")
            && integrated.contains("foreach ($change in @(\"route\", \"interface\", \"address\"))")
            && integrated.contains("Set-NetRoute -InputObject $physicalRoute")
            && integrated.contains("Disable-NetAdapter -InputObject $physicalAdapter")
            && integrated.contains("Set-NetIPAddress -InputObject $sourceRow")
            && integrated.contains("$captureRemaining -eq 0 -and $dnsRemaining -eq 0")
            && integrated.contains("$admissionRejected")
            && integrated.contains("[Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id) -ne 0")
            && integrated.contains("Invoke-AdapterCycles $binary $managedLifecycleConfig $managedAutoAdapterName $managedMetricsPort $true")
            && integrated.contains("[Ferrum2ProcessGroup]::Terminate([uint32]$activeProcess.Id)"),
        "integrated rows must execute direct TUN, system DNS, invalidation, cycles and hard-kill evidence"
    );
    assert!(
        system_dns_witness.contains("([string]$Name, [bool]$TcpOnly)")
            && system_dns_witness.contains("Clear-DnsClientCache -ErrorAction Stop")
            && system_dns_witness.contains(
                "$parameters = @{ Name = $Name; Type = \"A\"; DnsOnly = $true; NoHostsFile = $true; ErrorAction = \"Stop\" }"
            )
            && system_dns_witness.contains("if ($TcpOnly) { $parameters.TcpOnly = $true }")
            && system_dns_witness.contains(
                "Where-Object { $_.Type -eq \"A\" -and $_.IPAddress -eq \"192.0.2.55\" }"
            )
            && system_dns_witness.contains("$answer.Count -eq 1")
            && !system_dns_witness.contains("Write-Output")
            && !system_dns_witness.contains("Requests")
            && !system_dns_witness.contains("$deadline")
            && !system_dns_witness.contains("$quiet")
            && !system_dns_witness.contains("[pscustomobject]")
            && integrated.contains(
                "Invoke-SystemDnsWitness \"m16-$runIdentity-udp.tun.test\" $false"
            )
            && integrated.contains(
                "Invoke-SystemDnsWitness \"m16-$runIdentity-tcp.tun.test\" $true"
            )
            && integrated.matches("$managedSystemDnsRows++").count() == 2
            && !integrated.contains("$managedUdpDnsWitness")
            && !integrated.contains("$managedTcpDnsWitness")
            && !integrated.contains("system_dns_udp_immediate_requests")
            && !integrated.contains("system_dns_tcp_settled_requests"),
        "system DNS rows must prove two unique A answers without a responder-global request oracle"
    );
    assert!(
        adapter_readiness.contains("[bool]$Managed = $false")
            && adapter_readiness
                .contains("$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)")
            && adapter_readiness.contains("Start-Sleep -Milliseconds 100")
            && adapter_readiness.contains("while ([DateTime]::UtcNow -lt $deadline)")
            && adapter_readiness
                .contains("($capturePrefixes -join \"|\") -ceq \"0.0.0.0/1|128.0.0.0/1\"",)
            && adapter_readiness.contains("($dnsAddresses -join \"|\") -ceq \"198.18.0.1\"")
            && adapter_readiness.contains("$finalCapturePrefixes")
            && adapter_readiness.contains("-ErrorAction Stop")
            && adapter_readiness
                .contains("Assert-SnapshotEqual @(\"0.0.0.0/1\", \"128.0.0.0/1\")",)
            && adapter_readiness
                .contains("Assert-SnapshotEqual @(\"198.18.0.1\") $finalDnsAddresses")
            && adapter_readiness
                .matches("$script:activeProcess.Refresh()")
                .count()
                >= 2
            && adapter_readiness.contains("throw \"managed state readiness readback failed\"")
            && adapter_readiness.contains("throw \"managed state readiness timeout\"")
            && !adapter_readiness.contains("throw \"managed state readiness readback failed:")
            && !adapter_readiness.contains("throw \"managed state readiness timeout:")
            && adapter_cycles.contains("Wait-AdapterReady $ExpectedAdapter 20 $Managed")
            && !adapter_cycles.contains("managed cycle capture route mismatch"),
        "managed cycles must await exact capture and DNS state through one bounded process-aware readiness seam"
    );
    assert!(
        adapter_cycles.contains("[Nullable[int]]$MetricsPort = $null")
            && managed_cycle_metrics.contains(
                "Assert-True ($null -ne $MetricsPort) \"managed cycles require metrics port\"",
            )
            && managed_cycle_metrics.contains("$owners = Get-Metrics ([int]$MetricsPort)")
            && managed_cycle_metrics
                .find("managed cycles require metrics port")
                .unwrap()
                < managed_cycle_metrics.find("Get-Metrics").unwrap()
            && !adapter_cycles.contains("$MetricsPort.Value"),
        "managed cycles must reject a null metrics port and pass the concrete PowerShell integer directly"
    );
    assert!(
        qualifier.contains("\"hard-kill\"")
            && qualifier.contains("network_change=3/3")
            && qualifier.contains("route_change=1/1")
            && qualifier.contains("interface_change=1/1")
            && qualifier.contains("address_change=1/1")
            && qualifier.contains("m15_transport=16/16")
            && qualifier.contains("direct_tcp=1/1")
            && qualifier.contains("direct_udp=1/1")
            && qualifier.contains("dns=2/2")
            && qualifier.contains("hard_kill=3/3")
            && qualifier.contains("m16_windows_hard_kill status=PASS cases=3/3")
            && qualifier.contains("m16_windows_tun_full status=PASS")
            && qualifier
                .matches("m16_windows_hard_kill status=PASS")
                .count()
                == 1
            && qualifier
                .matches("m16_windows_tun_full status=PASS")
                .count()
                == 1,
        "one identity-bound qualifier must retain the exact T06 marker schemas"
    );
}

#[test]
fn m16_managed_product_qualification_is_candidate_bound_and_additive() {
    let source =
        fs::read_to_string(workspace_root().join("tests/platform/qualify_windows_tun.ps1"))
            .expect("Windows TUN qualifier");
    let compact = source.split_whitespace().collect::<String>();

    assert!(
        source.contains("\"managed-product\"")
            && source.contains("if ($Mode -eq \"managed-product\")")
            && compact.contains("Get-NetworkFeasibilityIdentity$IdentityLedger")
            && source.contains("auto_route = true")
            && source.contains("auto_route = false")
            && compact.contains("Start-Candidate$binary$managedAutoConfig")
            && compact.contains("Start-Candidate$binary$managedManualConfig")
            && compact.contains("Wait-AdapterReady$managedManualAdapterName")
            && compact.contains("Add-TunRoute$manualInterfaceIndex\"0.0.0.0/1\"1")
            && compact.contains("Add-TunRoute$manualInterfaceIndex\"128.0.0.0/1\"1")
            && source.contains(
                "m16_windows_managed_product status=PASS fixed_tcp=2/2 fixed_udp=2/2 dynamic_tcp=1/1 dynamic_udp=1/1 manual_tcp=1/1 manual_udp=1/1 unpinned=2/2 routes=2/2 interface_metric=unchanged cleanup=PASS",
            ),
        "the additive managed-product qualifier must execute both candidate-bound route modes"
    );
    assert_eq!(
        source
            .matches("m16_windows_network_feasibility status=PASS")
            .count(),
        1,
        "the historical network-feasibility marker must remain unique"
    );
    assert_eq!(
        source
            .matches("m16_windows_managed_product status=PASS")
            .count(),
        1,
        "the managed-product marker must remain unique"
    );
}

fn metadata() -> Value {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must start");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON")
}

fn package_names_by_id(metadata: &Value) -> BTreeMap<String, String> {
    metadata["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("package id").to_owned(),
                package["name"].as_str().expect("package name").to_owned(),
            )
        })
        .collect()
}

fn contains_explicit_target_declaration(manifest: &str, declaration: &str) -> bool {
    manifest.replace("\r\n", "\n").contains(declaration)
}

fn rust_sources(directory: &Path) -> Vec<PathBuf> {
    let mut pending = vec![directory.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

fn rust_tokens(source: &str) -> Vec<String> {
    fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }
        cursor += 1;
        let hashes = bytes[cursor..]
            .iter()
            .take_while(|byte| **byte == b'#')
            .count();
        cursor += hashes;
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && bytes
                    .get(cursor + 1..cursor + 1 + hashes)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                return Some(cursor + 1 + hashes);
            }
            cursor += 1;
        }
        Some(bytes.len())
    }

    fn quoted_end(bytes: &[u8], quote: usize) -> usize {
        let mut cursor = quote + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => cursor = (cursor + 2).min(bytes.len()),
                b'"' => return cursor + 1,
                _ => cursor += 1,
            }
        }
        bytes.len()
    }

    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor + 2) == Some(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            cursor += 2;
            let mut depth = 1;
            while cursor < bytes.len() && depth > 0 {
                if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if matches!(bytes[cursor], b'r' | b'b')
            && let Some(end) = raw_string_end(bytes, cursor)
        {
            cursor = end;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor = quoted_end(bytes, cursor);
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"b\"") {
            cursor = quoted_end(bytes, cursor + 1);
            continue;
        }
        if bytes[cursor] == b'\''
            && (bytes.get(cursor + 2) == Some(&b'\'') || bytes.get(cursor + 1) == Some(&b'\\'))
        {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'\'' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"b'") {
            cursor += 2;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'\'' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }
        if bytes[cursor].is_ascii_digit() {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_alphanumeric() {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }
        if !bytes[cursor].is_ascii_whitespace() {
            tokens.push((bytes[cursor] as char).to_string());
        }
        cursor += 1;
    }
    tokens
}

fn has_tokens(tokens: &[String], expected: &[&str]) -> bool {
    tokens.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

fn balanced_end(tokens: &[String], start: usize, open: &str, close: &str) -> Option<usize> {
    (tokens.get(start)? == open).then_some(())?;
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if token == open {
            depth += 1;
        } else if token == close {
            depth -= 1;
            if depth == 0 {
                return Some(index + 1);
            }
        }
    }
    None
}

fn is_identifier(token: &str) -> bool {
    token
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
}

fn test_module_end(tokens: &[String], start: usize) -> Option<usize> {
    if !has_tokens(
        tokens.get(start..start + 7)?,
        &["#", "[", "cfg", "(", "test", ")", "]"],
    ) {
        return None;
    }
    let mut cursor = start + 7;
    if tokens.get(cursor).is_some_and(|token| token == "pub") {
        cursor = balanced_end(tokens, cursor + 1, "(", ")")?;
    }
    if tokens.get(cursor).map(String::as_str) != Some("mod")
        || tokens
            .get(cursor + 1)
            .is_none_or(|name| !is_identifier(name))
    {
        return None;
    }
    match tokens.get(cursor + 2)?.as_str() {
        ";" => Some(cursor + 3),
        "{" => balanced_end(tokens, cursor + 2, "{", "}"),
        _ => None,
    }
}

struct TokenSource {
    path: String,
    tokens: Vec<String>,
}

impl TokenSource {
    fn new(path: impl Into<String>, source: &str) -> Self {
        Self {
            path: path.into(),
            tokens: rust_tokens(source),
        }
    }

    fn production_tokens(&self) -> Result<&[String], String> {
        let mut delimiters = Vec::new();
        let mut cursor = 0;
        while cursor < self.tokens.len() {
            if delimiters.is_empty()
                && let Some(end) = test_module_end(&self.tokens, cursor)
            {
                let production_end = cursor;
                cursor = end;
                while cursor < self.tokens.len() {
                    cursor = test_module_end(&self.tokens, cursor).ok_or_else(|| {
                        format!("{} has production after a test module", self.path)
                    })?;
                }
                return Ok(&self.tokens[..production_end]);
            }
            match self.tokens[cursor].as_str() {
                "(" => delimiters.push(")"),
                "[" => delimiters.push("]"),
                "{" => delimiters.push("}"),
                token if delimiters.last().is_some_and(|close| *close == token) => {
                    delimiters.pop();
                }
                _ => {}
            }
            cursor += 1;
        }
        Ok(&self.tokens)
    }
}

fn token_sources(root: &Path, paths: &[&str]) -> Vec<TokenSource> {
    paths
        .iter()
        .map(|path| {
            TokenSource::new(
                *path,
                &fs::read_to_string(root.join(path)).expect("token source"),
            )
        })
        .collect()
}

fn token_sources_under(root: &Path, directories: &[&str]) -> Vec<TokenSource> {
    let mut sources = Vec::new();
    for directory in directories {
        for path in rust_sources(&root.join(directory)) {
            let relative = path
                .strip_prefix(root)
                .expect("product source under workspace")
                .to_string_lossy()
                .replace('\\', "/");
            sources.push(TokenSource::new(
                relative,
                &fs::read_to_string(path).expect("product source"),
            ));
        }
    }
    sources
}

type DefinitionRule = (&'static str, &'static str, &'static str);

fn ownership_scope(owner: &str) -> &str {
    owner.find("src/").map_or_else(
        || owner.rsplit_once('/').map_or("", |(scope, _)| scope),
        |end| &owner[..end + 4],
    )
}

fn check_definition_ownership(
    sources: &[TokenSource],
    rules: &[DefinitionRule],
    roots: &[&str],
) -> Result<(), String> {
    for &(keyword, name, owner) in rules {
        let scope = ownership_scope(owner);
        let locations: Vec<_> = sources
            .iter()
            .filter(|source| {
                source.path.starts_with(scope) && has_tokens(&source.tokens, &[keyword, name])
            })
            .map(|source| source.path.as_str())
            .collect();
        if locations != [owner] {
            return Err(format!(
                "{keyword} {name} must have one owner {owner}, found {locations:?}"
            ));
        }
        if locations.iter().any(|location| roots.contains(location)) {
            return Err(format!("composition root restores {keyword} {name}"));
        }
    }
    Ok(())
}

fn check_no_identifiers<'a>(
    sources: impl IntoIterator<Item = &'a TokenSource>,
    forbidden: &[&str],
) -> Result<(), String> {
    for source in sources {
        if let Some(identifier) = source
            .production_tokens()?
            .iter()
            .find(|token| forbidden.contains(&token.as_str()))
        {
            return Err(format!("{} contains forbidden {identifier}", source.path));
        }
    }
    Ok(())
}

fn check_no_sequences<'a>(
    sources: impl IntoIterator<Item = &'a TokenSource>,
    forbidden: &[&[&str]],
) -> Result<(), String> {
    for source in sources {
        let tokens = source.production_tokens()?;
        if let Some(sequence) = forbidden
            .iter()
            .find(|sequence| has_tokens(tokens, sequence))
        {
            return Err(format!("{} contains forbidden {sequence:?}", source.path));
        }
    }
    Ok(())
}

fn check_composition_roots(
    sources: &[TokenSource],
    expected: &[(&str, &[&str])],
) -> Result<(), String> {
    for (path, names) in expected {
        let source = sources
            .iter()
            .find(|source| source.path == *path)
            .ok_or_else(|| format!("missing composition root {path}"))?;
        let tokens = source.production_tokens()?;
        let actual = name_counts(tokens.windows(2).filter_map(|window| {
            (window[0] == "fn" && is_identifier(&window[1])).then_some(window[1].as_str())
        }));
        let expected = name_counts(names.iter().copied());
        if actual != expected {
            return Err(format!(
                "composition root function mismatch for {path}: expected {expected:?}, found {actual:?}"
            ));
        }
        check_no_identifiers([source], &["accept_response", "commit_request"])?;
    }
    Ok(())
}

fn has_glob_use(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        token == "use"
            && tokens[index + 1..]
                .iter()
                .take_while(|token| token.as_str() != ";")
                .any(|token| token == "*")
    })
}

fn check_no_glob_facades(
    sources: &[TokenSource],
    owners: &[&str],
    roots: &[&str],
) -> Result<(), String> {
    for owner in owners {
        let source = sources
            .iter()
            .find(|source| source.path == *owner)
            .ok_or_else(|| format!("missing owner {owner}"))?;
        if has_glob_use(source.production_tokens()?) {
            return Err(format!("production owner remains a glob facade: {owner}"));
        }
    }
    for root in roots {
        let source = sources
            .iter()
            .find(|source| source.path == *root)
            .ok_or_else(|| format!("missing composition root {root}"))?;
        if has_glob_use(source.production_tokens()?) {
            return Err(format!("composition root has a glob import: {root}"));
        }
    }
    Ok(())
}

fn name_counts<'a>(names: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for name in names {
        *counts.entry(name.to_owned()).or_default() += 1;
    }
    counts
}

fn restricted_items(tokens: &[String]) -> BTreeMap<String, usize> {
    let mut items = BTreeMap::new();
    for index in 0..tokens.len() {
        if tokens.get(index).map(String::as_str) != Some("pub")
            || tokens.get(index + 1).map(String::as_str) != Some("(")
        {
            continue;
        }
        let Some(declaration_start) = balanced_end(tokens, index + 1, "(", ")") else {
            continue;
        };
        let declaration = tokens[declaration_start..]
            .iter()
            .take_while(|token| !matches!(token.as_str(), "," | ";" | "{" | "}"));
        let declaration: Vec<_> = declaration.map(String::as_str).collect();
        for keyword in ["struct", "enum", "fn", "trait", "type", "const"] {
            if let Some(keyword) = declaration.iter().position(|token| *token == keyword) {
                if let Some(name) = declaration.get(keyword + 1) {
                    *items.entry((*name).to_owned()).or_default() += 1;
                }
                break;
            }
        }
    }
    items
}

fn check_restricted_interfaces(
    sources: &[TokenSource],
    expected: &[(&str, &[&str])],
) -> Result<(), String> {
    for (path, names) in expected {
        let source = sources
            .iter()
            .find(|source| source.path == *path)
            .ok_or_else(|| format!("missing interface owner {path}"))?;
        let actual = restricted_items(source.production_tokens()?);
        let expected = name_counts(names.iter().copied());
        if actual != expected {
            return Err(format!(
                "restricted interface mismatch for {path}: expected {expected:?}, found {actual:?}"
            ));
        }
    }
    Ok(())
}

fn check_test_placement(
    sources: &[TokenSource],
    rules: &[DefinitionRule],
    composition_tests: &[&str],
    support_modules: &[&str],
) -> Result<(), String> {
    check_definition_ownership(sources, rules, composition_tests)?;
    for source in sources {
        let references_tests = source
            .tokens
            .windows(3)
            .any(|window| window[0] == "tests" && window[1] == ":" && window[2] == ":");
        if references_tests {
            let role = if composition_tests.contains(&source.path.as_str()) {
                "composition"
            } else if support_modules.contains(&source.path.as_str()) {
                "support"
            } else {
                "owner"
            };
            return Err(format!(
                "{role} source references a test module: {}",
                source.path
            ));
        }
    }
    Ok(())
}

#[test]
fn workspace_contains_current_compatibility_members_without_exhausting_future_topology() {
    let metadata = metadata();
    let root = PathBuf::from(metadata["workspace_root"].as_str().expect("workspace root"));
    let actual: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| {
            let id = id.as_str().expect("workspace member id");
            let package = metadata["packages"]
                .as_array()
                .expect("packages")
                .iter()
                .find(|package| package["id"].as_str() == Some(id))
                .expect("workspace member package");
            let manifest = PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
            manifest
                .parent()
                .expect("manifest parent")
                .strip_prefix(&root)
                .expect("member under workspace")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();

    for required in CURRENT_COMPATIBILITY_MEMBERS {
        assert!(
            actual.contains(required),
            "current compatibility member is missing: {required}"
        );
    }
}

#[test]
fn current_deep_modules_keep_one_way_internal_dependencies() {
    let exposes_standalone_plan_snapshot = |source: &str| {
        source.split(';').any(|statement| {
            let mut tokens = statement
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .filter(|token| !token.is_empty());
            let mut saw_public = false;
            tokens.any(|token| {
                saw_public |= token == "pub";
                saw_public && token == "PlanSnapshot"
            })
        })
    };
    for mutation in [
        "pub use runtime_provider::{SystemDnsEgress, PlanSnapshot, DnsTcpIo};",
        "#[derive(Clone)]\npub struct PlanSnapshot(std::sync::Arc<[usize]>);",
    ] {
        assert!(exposes_standalone_plan_snapshot(mutation));
    }
    assert!(!exposes_standalone_plan_snapshot(
        "pub use ferrum2_core::route::EgressPlanSnapshot;"
    ));

    let metadata = metadata();
    let names = package_names_by_id(&metadata);
    let workspace_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| id.as_str().expect("member id").to_owned())
        .collect();
    let allowed: BTreeMap<&str, BTreeSet<&str>> = [
        (
            "ferrum2-config",
            BTreeSet::from(["ferrum2-core", "ferrum2-crypto"]),
        ),
        ("ferrum2-core", BTreeSet::new()),
        ("ferrum2-crypto", BTreeSet::new()),
        ("ferrum2-dns", BTreeSet::from(["ferrum2-core"])),
        ("ferrum2-observability", BTreeSet::new()),
        ("ferrum2-runtime", BTreeSet::from(["ferrum2-core"])),
        (
            "ferrum2-shadowsocks",
            BTreeSet::from(["ferrum2-core", "ferrum2-crypto"]),
        ),
        ("ferrum2-sniff", BTreeSet::new()),
        ("ferrum2-socks5", BTreeSet::from(["ferrum2-core"])),
    ]
    .into_iter()
    .collect();
    let workspace_names: BTreeSet<_> = workspace_ids
        .iter()
        .map(|id| names.get(id).expect("workspace package name").as_str())
        .collect();

    for package in metadata["packages"].as_array().expect("packages") {
        let package_id = package["id"].as_str().expect("package id");
        if !workspace_ids.contains(package_id) {
            continue;
        }
        let package_name = names.get(package_id).expect("package name");
        let actual: BTreeSet<_> = package["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .filter_map(|dependency| {
                let dependency_name = dependency["name"].as_str().expect("dependency name");
                workspace_names
                    .contains(dependency_name)
                    .then_some(dependency_name)
            })
            .collect();
        assert!(
            actual.is_disjoint(&BTreeSet::from(["ferrum2-client", "ferrum2-server"])),
            "internal package must not depend on a composition root: {package_name}"
        );
        if let Some(permitted) = allowed.get(package_name.as_str()) {
            assert!(
                actual.is_subset(permitted),
                "deep module has an upward or cross-layer dependency: {package_name}"
            );
        }
    }

    let root = workspace_root();
    for path in rust_sources(&root.join("crates/ferrum2-dns/src")) {
        let source = fs::read_to_string(&path).expect("DNS source");
        for forbidden in ["ferrum2_config", "DnsServerConfig", "DnsTransport"] {
            assert!(
                !source.contains(forbidden),
                "DNS runtime source imports config ownership: {} contains {forbidden}",
                path.display()
            );
        }
        assert!(
            !exposes_standalone_plan_snapshot(&source),
            "DNS source exposes a standalone PlanSnapshot: {}",
            path.display()
        );
    }
    let public =
        fs::read_to_string(root.join("crates/ferrum2-dns/src/lib.rs")).expect("DNS public module");
    assert!(public.contains("DnsUpstreamSpec"));

    let core_manifest =
        fs::read_to_string(root.join("crates/ferrum2-core/Cargo.toml")).expect("core manifest");
    let sniff_manifest =
        fs::read_to_string(root.join("crates/ferrum2-sniff/Cargo.toml")).expect("sniff manifest");
    let check_parser_direction = |core: &str, sniff: &str| -> Result<(), &'static str> {
        if core.contains("ferrum2-sniff")
            || [
                "ferrum2-config",
                "ferrum2-runtime",
                "ferrum2-client",
                "ferrum2-server",
            ]
            .iter()
            .any(|dependency| sniff.contains(dependency))
        {
            return Err("parser dependency direction inverted");
        }
        Ok(())
    };
    check_parser_direction(&core_manifest, &sniff_manifest)
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        check_parser_direction(
            &(core_manifest.clone() + "\nferrum2-sniff.workspace = true\n"),
            &sniff_manifest,
        )
        .is_err(),
        "core-to-parser dependency mutation survived"
    );
    assert!(
        check_parser_direction(
            &core_manifest,
            &(sniff_manifest.clone() + "\nferrum2-config.workspace = true\n"),
        )
        .is_err(),
        "parser-to-composition dependency mutation survived"
    );

    let sniff = token_sources_under(&root, &["crates/ferrum2-sniff/src"]);
    check_no_identifiers(
        &sniff,
        &[
            "unsafe",
            "async",
            "spawn",
            "TcpListener",
            "TcpStream",
            "UdpSocket",
            "ToSocketAddrs",
            "ServerConfig",
            "ClientConnection",
            "HashMap",
            "dyn",
            "trait",
            "ferrum2_config",
            "ferrum2_runtime",
            "tracing",
            "metrics",
        ],
    )
    .unwrap_or_else(|error| panic!("pure sniff module gained runtime/registry ownership: {error}"));
    for required in [
        &["Header", ":", ":", "read"][..],
        &["Message", ":", ":", "read"][..],
        &["Acceptor", ":", ":", "default"],
        &["httparse", ":", ":", "Request", ":", ":", "new"],
    ] {
        assert_eq!(
            sniff
                .iter()
                .map(|source| {
                    source
                        .production_tokens()
                        .expect("sniff production tokens")
                        .windows(required.len())
                        .filter(|window| {
                            window
                                .iter()
                                .map(String::as_str)
                                .eq(required.iter().copied())
                        })
                        .count()
                })
                .sum::<usize>(),
            1,
            "sniff module must have exactly one owner/use of reviewed parser {required:?}"
        );
    }

    let mut decode_dns_bodies = Vec::new();
    for source in &sniff {
        let tokens = source.production_tokens().expect("sniff production tokens");
        for definition in tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| (window == ["fn", "decode_dns"]).then_some(index))
        {
            let body_start = (definition + 2..tokens.len())
                .find(|index| tokens[*index] == "{")
                .expect("decode_dns body start");
            let body_end =
                balanced_end(tokens, body_start, "{", "}").expect("balanced decode_dns definition");
            decode_dns_bodies.push(&tokens[body_start..body_end]);
        }
    }
    assert_eq!(
        decode_dns_bodies.len(),
        1,
        "DNS decoding must have one semantic production owner"
    );
    let decode_dns = decode_dns_bodies[0];
    let parser_position = |parser: &[&str]| {
        decode_dns
            .windows(parser.len())
            .position(|window| window.iter().map(String::as_str).eq(parser.iter().copied()))
            .unwrap_or_else(|| panic!("decode_dns must call {parser:?}"))
    };
    let header_read = parser_position(&["Header", ":", ":", "read"]);
    let checked_multiply = parser_position(&[".", "checked_mul"]);
    let checked_add = parser_position(&[".", "checked_add"]);
    let message_read = parser_position(&["Message", ":", ":", "read"]);
    assert!(
        header_read < checked_multiply
            && checked_multiply < checked_add
            && checked_add < message_read,
        "bounded Hickory Header preflight must precede allocating Message decode"
    );
    for required in [
        &["header", ".", "metadata", ".", "message_type"][..],
        &["header", ".", "metadata", ".", "op_code"],
        &["header", ".", "counts", ".", "queries"],
        &["header", ".", "counts", ".", "answers"],
        &["header", ".", "counts", ".", "authorities"],
        &["header", ".", "counts", ".", "additionals"],
    ] {
        assert!(
            has_tokens(decode_dns, required),
            "DNS Header preflight must constrain {required:?}"
        );
    }

    assert_eq!(
        name_counts(sniff.iter().flat_map(|source| {
            source
                .production_tokens()
                .expect("sniff production tokens")
                .windows(3)
                .filter_map(|window| {
                    (window[0] == "pub" && window[1] == "fn").then_some(window[2].as_str())
                })
        })),
        BTreeMap::from([("sniff".to_owned(), 1)]),
        "sniff module exposes exactly one byte-slice function"
    );
}

#[test]
fn core_is_runtime_and_protocol_neutral() {
    let metadata = metadata();
    let core = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-core")
        .expect("core package");
    let dependencies: BTreeSet<_> = core["dependencies"]
        .as_array()
        .expect("dependencies")
        .iter()
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();

    assert_eq!(dependencies, BTreeSet::from(["bytes", "ipnet"]));
}

#[test]
fn core_source_preserves_endpoint_ownership_without_freezing_address_family() {
    let source = fs::read_to_string(workspace_root().join("crates/ferrum2-core/src/lib.rs"))
        .expect("core source");

    for required in [
        "type Stream: LocalEndpoint;",
        "fn local_socket_addr(&self) -> SocketAddr",
        "fn succeeded_socket(",
        "bound: SocketAddr",
    ] {
        assert!(
            source.contains(required),
            "core contract must contain `{required}`"
        );
    }
}

#[test]
fn crypto_profiles_keep_cipher_dispatch_inside_one_deep_module() {
    let root = workspace_root();
    let metadata = metadata();
    let crypto =
        fs::read_to_string(root.join("crates/ferrum2-crypto/src/lib.rs")).expect("crypto source");
    for required in [
        "pub enum MethodProfile",
        "pub type TcpMethodProfile = MethodProfile",
        "pub struct MethodPsk",
        "pub trait MethodKeyProvider",
        "ShadowsocksTcpCipher::try_new",
        "ShadowsocksTcpCipher::try_from_subkey",
        "pub struct TcpSealer",
        "pub struct TcpOpener",
        "enum UdpCryptoInner",
        "ShadowsocksUdpCipher::try_new",
        "ShadowsocksAesHeaderCipher::try_new",
        "pub struct UdpCrypto",
        "pub struct UdpSessionId",
        "pub struct UdpOutboundSession",
        "outbound: &mut UdpOutboundSession",
    ] {
        assert!(
            crypto.contains(required),
            "crypto deep module must contain `{required}`"
        );
    }
    for separable_udp_state in [
        "pub struct UdpPacketCounter",
        "pub fn generate_udp_session_id",
        "pub fn generate_distinct_udp_session_id",
    ] {
        assert!(
            !crypto.contains(separable_udp_state),
            "outbound UDP identity and packet lineage must remain inseparable: {separable_udp_state}"
        );
    }
    for duplicated_owner in [
        "Aes256TcpSealer",
        "Aes256TcpOpener",
        "ChaChaTcpSealer",
        "ChaChaTcpOpener",
        "Aes128UdpCrypto",
        "Aes256UdpCrypto",
        "ChaChaUdpCrypto",
    ] {
        assert!(
            !crypto.contains(duplicated_owner),
            "method-specific public flow owner is forbidden: {duplicated_owner}"
        );
    }
    for replaced_implementation in [
        "enum TcpCipher",
        "enum AesUdpBodyCipher",
        "fn cipher_from_subkey",
        "fn derive_subkey_16",
        "fn derive_subkey_32",
        "fn derive_udp_subkey_16",
        "fn derive_udp_subkey_32",
        "SIP022_KDF_CONTEXT",
        "Aes128Gcm::new_from_slice",
        "Aes256Gcm::new_from_slice",
        "XChaCha20Poly1305::new_from_slice",
    ] {
        assert!(
            !crypto.contains(replaced_implementation),
            "replaced local crypto implementation is forbidden: {replaced_implementation}"
        );
    }

    let workspace_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| id.as_str().expect("workspace member id"))
        .collect();
    for package in metadata["packages"].as_array().expect("packages") {
        let package_id = package["id"].as_str().expect("package id");
        if !workspace_ids.contains(package_id) || package["name"] == "ferrum2-crypto" {
            continue;
        }
        let manifest_path = package["manifest_path"].as_str().expect("manifest path");
        let manifest = fs::read_to_string(manifest_path).expect("member manifest");
        assert!(
            !manifest.contains("chacha20poly1305"),
            "ChaCha primitive dependency must stay inside ferrum2-crypto: {}",
            package["name"]
        );
    }
}

#[test]
fn current_product_targets_are_explicit_without_exhausting_future_targets() {
    let root = workspace_root();
    for (manifest, declaration) in [
        (
            "bins/ferrum2-client/Cargo.toml",
            "[[bin]]\nname = \"ferrum2-client\"\npath = \"src/main.rs\"",
        ),
        (
            "bins/ferrum2-server/Cargo.toml",
            "[[bin]]\nname = \"ferrum2-server\"\npath = \"src/main.rs\"",
        ),
        (
            "crates/ferrum2-crypto/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-shadowsocks/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-socks5/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-runtime/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-config/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-observability/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
    ] {
        let contents = fs::read_to_string(root.join(manifest)).expect("member manifest");
        assert!(
            contains_explicit_target_declaration(&contents, declaration),
            "{manifest} must explicitly declare `{declaration}`"
        );
    }
}

#[test]
fn current_target_declaration_matching_accepts_crlf() {
    let manifest = "[[bin]]\r\nname = \"ferrum2-client\"\r\npath = \"src/main.rs\"\r\n";
    let declaration = "[[bin]]\nname = \"ferrum2-client\"\npath = \"src/main.rs\"";

    assert!(contains_explicit_target_declaration(manifest, declaration));
}

#[test]
fn tagged_composition_stays_out_of_core_and_protocol_modules() {
    let root = workspace_root();
    let core = fs::read_to_string(root.join("crates/ferrum2-core/src/lib.rs")).expect("core");
    assert_eq!(core.matches("pub mod route").count(), 1);
    let native = fs::read_to_string(root.join("tests/platform/qualify_native.py")).expect("native");
    for required in "def bounded_accept(|listener.settimeout(timeout)|peer.settimeout(timeout)|except (TimeoutError, OSError)|bounded_accept(tcp, 9)".split('|') {
        assert!(native.contains(required), "native lacks {required}");
    }
    for (members, forbidden) in [
        (
            "crates/ferrum2-shadowsocks,crates/ferrum2-socks5,crates/ferrum2-runtime",
            "RouteRule,RouteTable,route::,pub trait Route",
        ),
        (
            "crates/ferrum2-core,crates/ferrum2-shadowsocks,crates/ferrum2-socks5",
            "pub trait Endpoint,RouteFactory,RouteRegistry,AdapterRegistry,ServiceRegistry,adapter_registry,endpoint_registry",
        ),
    ] {
        for member in members.split(',') {
            let sources = rust_sources(&root.join(member));
            assert!(!sources.is_empty(), "{member} has no sources");
            for path in sources {
                let source = fs::read_to_string(&path).expect("source");
                assert!(
                    forbidden.split(',').all(|item| !source.contains(item)),
                    "{} violates architecture",
                    path.display()
                );
            }
        }
    }
    for member in "bins/ferrum2-client,bins/ferrum2-server,crates/ferrum2-observability".split(',')
    {
        for path in rust_sources(&root.join(member)) {
            let source = fs::read_to_string(path).expect("observable source");
            assert!(
                "tag,target,destination,route"
                    .split(',')
                    .all(|field| !source.contains(&format!("{field} = %"))
                        && !source.contains(&format!("{field} = ?"))),
                "{member} exposes route identity"
            );
        }
    }
    for member in "crates/ferrum2-core,crates/ferrum2-shadowsocks,crates/ferrum2-socks5".split(',')
    {
        let manifest =
            fs::read_to_string(root.join(member).join("Cargo.toml")).expect("deep-module manifest");
        for forbidden in ["ferrum2-config", "ferrum2-runtime"] {
            assert!(
                !manifest.contains(forbidden),
                "{member} must not depend on {forbidden}"
            );
        }
    }
}

#[test]
fn ordered_route_program_is_protocol_neutral_and_the_only_ordinary_engine() {
    let root = workspace_root();
    let sources = [TokenSource::new(
        "crates/ferrum2-core/src/route.rs",
        &fs::read_to_string(root.join("crates/ferrum2-core/src/route.rs"))
            .expect("core route module"),
    )];
    check_definition_ownership(
        &sources,
        &[
            (
                "struct",
                "OrderedRouteProgram",
                "crates/ferrum2-core/src/route.rs",
            ),
            (
                "struct",
                "RouteProgramEvaluation",
                "crates/ferrum2-core/src/route.rs",
            ),
        ],
        &[],
    )
    .unwrap_or_else(|error| panic!("ordered-route ownership changed: {error}"));
    let route = &sources[0];
    let tokens = route.production_tokens().expect("route production tokens");
    assert!(has_tokens(tokens, &["cursor", ":", "usize"]));
    assert!(has_tokens(
        tokens,
        &[
            "program",
            ":",
            "OrderedRouteProgram",
            "<",
            "(",
            ")",
            ",",
            "OutboundAction"
        ]
    ));
    assert!(has_tokens(
        tokens,
        &[
            "assert_eq",
            "!",
            "(",
            "plan",
            ".",
            "hops",
            ".",
            "len",
            "(",
            ")",
            ",",
            "1"
        ]
    ));
    let concrete: Vec<_> =
        "Dns,DNS,Tls,TLS,Http,HTTP,Sniff,sniff,Hijack,hijack,tokio,ferrum2_config,ferrum2_runtime"
            .split(',')
            .collect();
    let core_sources = token_sources_under(&root, &["crates/ferrum2-core/src"]);
    check_no_identifiers(&core_sources, &concrete)
        .unwrap_or_else(|error| panic!("core route owns concrete vocabulary: {error}"));
    let mut concrete_mutation = token_sources_under(&root, &["crates/ferrum2-core/src"]);
    concrete_mutation.push(TokenSource::new(
        "crates/ferrum2-core/src/concrete_protocol.rs",
        "struct Http;",
    ));
    assert!(
        check_no_identifiers(&concrete_mutation, &concrete).is_err(),
        "concrete protocol in another core module mutation survived"
    );
    let duplicate_route = [
        TokenSource::new(
            "crates/ferrum2-core/src/route.rs",
            &fs::read_to_string(root.join("crates/ferrum2-core/src/route.rs"))
                .expect("core route owner"),
        ),
        TokenSource::new(
            "crates/ferrum2-core/src/route_duplicate.rs",
            "struct OrderedRouteProgram; struct RouteProgramEvaluation;",
        ),
    ];
    assert!(
        check_definition_ownership(
            &duplicate_route,
            &[
                (
                    "struct",
                    "OrderedRouteProgram",
                    "crates/ferrum2-core/src/route.rs",
                ),
                (
                    "struct",
                    "RouteProgramEvaluation",
                    "crates/ferrum2-core/src/route.rs",
                ),
            ],
            &[],
        )
        .is_err(),
        "second ordinary route owner mutation survived"
    );
    check_no_sequences(
        [route],
        &[
            &["actions", ":", "ActionTable", "<", "OutboundAction", ">"],
            &["pub", "cursor"],
            &["pub", "(", "crate", ")", "cursor"],
        ],
    )
    .unwrap_or_else(|error| panic!("ordered-route ownership changed: {error}"));

    let validation = TokenSource::new(
        "crates/ferrum2-config/src/validation.rs",
        &fs::read_to_string(root.join("crates/ferrum2-config/src/validation.rs"))
            .expect("config validation"),
    );
    let validation = validation
        .production_tokens()
        .expect("config production tokens");
    let empty_server_plans = [
        "selectors",
        ".",
        "as_deref",
        "(",
        ")",
        ",",
        "&",
        "[",
        "]",
        ",",
        "detour_tags",
        ",",
        "source",
    ];
    let check_server_scalar = |tokens: &[String]| {
        has_tokens(tokens, &empty_server_plans)
            .then_some(())
            .ok_or("server scalar route compilation accepted a multi-hop plan input")
    };
    check_server_scalar(validation).unwrap_or_else(|error| panic!("{error}"));
    let mut multi_hop_server = validation.to_vec();
    let empty = multi_hop_server
        .windows(empty_server_plans.len())
        .position(|window| {
            window
                .iter()
                .map(String::as_str)
                .eq(empty_server_plans.iter().copied())
        })
        .expect("server empty plan input");
    multi_hop_server[empty + 7] = "plans".to_owned();
    assert!(
        check_server_scalar(&multi_hop_server).is_err(),
        "server multi-hop scalar selection mutation survived"
    );
}

#[test]
fn server_consumes_typed_routes_through_one_runtime_prefix_collector() {
    let root = workspace_root();
    let runtime = token_sources_under(&root, &["crates/ferrum2-runtime/src"]);
    check_definition_ownership(
        &runtime,
        &[(
            "fn",
            "collect_sniff_prefix",
            "crates/ferrum2-runtime/src/sniff.rs",
        )],
        &[],
    )
    .unwrap_or_else(|error| panic!("prefix collector ownership changed: {error}"));

    let server = token_sources(
        &root,
        &[
            "bins/ferrum2-server/src/run.rs",
            "bins/ferrum2-server/src/run/tcp.rs",
            "bins/ferrum2-server/src/run/udp.rs",
        ],
    );
    let run = server[0]
        .production_tokens()
        .expect("server root production tokens");
    assert!(has_tokens(
        run,
        &["program", ":", "config", ".", "route_program"]
    ));
    assert!(
        !run.iter().any(|token| token == "schema_version"),
        "server root restored a schema-v2 startup latch"
    );
    let tcp = server[1]
        .production_tokens()
        .expect("server TCP production tokens");
    assert!(has_tokens(
        tcp,
        &["program", ":", "Option", "<", "CompiledRoute", ">"]
    ));
    assert!(has_tokens(tcp, &["collect_sniff_prefix", "("]));
    assert!(has_tokens(tcp, &["poll_read_plain", "("]));
    let udp = server[2]
        .production_tokens()
        .expect("server UDP production tokens");
    for required in [
        &["prepare_request", "("][..],
        &["select_udp_route", "("][..],
        &["reserve_udp_direct", "("][..],
        &["commit_request", "("][..],
    ] {
        assert!(
            has_tokens(udp, required),
            "missing UDP composition {required:?}"
        );
    }
    check_no_sequences(server.iter(), &[&["fn", "collect_sniff_prefix"]])
        .unwrap_or_else(|error| panic!("server restored a second prefix collector: {error}"));

    let runtime_manifest = fs::read_to_string(root.join("crates/ferrum2-runtime/Cargo.toml"))
        .expect("runtime manifest");
    assert!(!runtime_manifest.contains("ferrum2-sniff"));
    let server_manifest =
        fs::read_to_string(root.join("bins/ferrum2-server/Cargo.toml")).expect("server manifest");
    assert!(server_manifest.contains("ferrum2-sniff.workspace = true"));

    let position = |tokens: &[String], sequence: &[&str], start: usize| {
        tokens[start..]
            .windows(sequence.len())
            .position(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(sequence.iter().copied())
            })
            .map(|offset| start + offset)
    };
    let check_udp_order = |tokens: &[String]| -> Result<(), String> {
        let prepare = position(tokens, &["prepare_request", "("], 0)
            .ok_or("missing authenticated UDP prepare")?;
        let select = position(tokens, &["select_udp_route", "("], prepare + 1)
            .ok_or("UDP policy precedes prepare")?;
        let reject = position(
            tokens,
            &[
                "if",
                "terminal",
                "=",
                "=",
                "ServerTerminalRoute",
                ":",
                ":",
                "Reject",
            ],
            select + 1,
        )
        .ok_or("missing immediate UDP terminal split")?;
        let legacy = position(
            tokens,
            &["routing", ".", "program", "(", ")", ".", "is_none"],
            reject + 1,
        )
        .ok_or("legacy reject no-mutation gate moved")?;
        let commits: Vec<_> = tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (index > select && window[0] == "commit_request" && window[1] == "(")
                    .then_some(index)
            })
            .collect();
        let reserves: Vec<_> = tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (index > select && window[0] == "reserve_udp_direct" && window[1] == "(")
                    .then_some(index)
            })
            .collect();
        if has_tokens(tokens, &["orphan_count", "("]) {
            return Err("UDP restored a split orphan-only admission ceiling".to_owned());
        }
        let reconcile = position(tokens, &["reconcile_udp_generations", "("], legacy + 1)
            .ok_or("missing retained-orphan reconciliation before admission")?;
        let prune = position(
            tokens,
            &["mappings", ".", "prune_protocol", "("],
            reconcile + 1,
        )
        .ok_or("missing retained-orphan prune before admission")?;
        let session_cap = position(tokens, &["protocol", ".", "session_count", "("], prune + 1)
            .ok_or("missing shared protocol session ceiling")?;
        if commits.len() != 3
            || reserves.len() != 2
            || !(select < reject
                && reject < legacy
                && legacy < reconcile
                && reconcile < prune
                && prune < session_cap
                && session_cap < commits[0]
                && session_cap < reserves[0]
                && commits[0] < reserves[0]
                && reserves[0] < commits[1]
                && commits[1] < reserves[1]
                && reserves[1] < commits[2])
        {
            return Err(format!(
                "UDP prepare/select/shared-cap/reject/direct reservation order changed: select={select} reject={reject} legacy={legacy} reconcile={reconcile} prune={prune} session_cap={session_cap} commits={commits:?} reserves={reserves:?}"
            ));
        }
        Ok(())
    };
    check_udp_order(udp).unwrap_or_else(|error| panic!("{error}"));

    let check_tcp_boundary = |tokens: &[String]| -> Result<(), String> {
        if tokens
            .iter()
            .filter(|token| token.as_str() == "poll_read_plain")
            .count()
            != 1
            || tokens
                .windows(2)
                .filter(|window| window[0] == "collect_sniff_prefix" && window[1] == "(")
                .count()
                != 1
        {
            return Err("TCP restored an alias read loop or second collector".to_owned());
        }
        let function = position(tokens, &["async", "fn", "server_connection"], 0)
            .ok_or("missing server connection")?;
        let body_start = tokens[function..]
            .iter()
            .position(|token| token == "{")
            .map(|offset| function + offset)
            .ok_or("missing server connection body")?;
        let body_end = balanced_end(tokens, body_start, "{", "}")
            .ok_or("unbalanced server connection body")?;
        let body = &tokens[body_start..body_end];
        let authenticate = position(body, &["inbound", ".", "accept", "("], 0)
            .ok_or("missing SIP022 authentication")?;
        let select = position(body, &["select_tcp_route", "("], 0)
            .ok_or("missing post-auth route selection")?;
        if authenticate >= select
            || has_tokens(body, &["ferrum2_sniff", "::", "sniff", "("])
            || has_tokens(body, &["collect_sniff_prefix", "("])
        {
            return Err("TCP sniff moved before authentication or escaped its selector".to_owned());
        }
        Ok(())
    };
    check_tcp_boundary(tcp).unwrap_or_else(|error| panic!("{error}"));
    let observation = TokenSource::new(
        "bins/ferrum2-server/src/run/observation.rs",
        &fs::read_to_string(root.join("bins/ferrum2-server/src/run/observation.rs"))
            .expect("server observation"),
    );
    let observation = observation
        .production_tokens()
        .expect("server observation production tokens");
    assert_eq!(
        observation
            .windows(2)
            .filter(|window| window[0] == "fn" && window[1] == "record_sniff")
            .count(),
        1,
        "sniff telemetry must keep one server mapping seam"
    );
    assert_eq!(
        observation
            .windows(4)
            .filter(|window| {
                window[0] == "metrics"
                    && window[1] == "."
                    && window[2] == "sniff"
                    && window[3] == "("
            })
            .count(),
        1,
        "server observation must emit one closed sniff tuple"
    );
    assert_eq!(
        tcp.windows(2)
            .filter(|window| window[0] == "record_sniff" && window[1] == "(")
            .count(),
        2,
        "TCP must cover fatal and continuing sniff terminals"
    );
    assert_eq!(
        udp.windows(2)
            .filter(|window| window[0] == "record_sniff" && window[1] == "(")
            .count(),
        1,
        "UDP must emit once after authenticated borrow-sniff"
    );

    let mut reordered_udp = udp.to_vec();
    let prepare = position(&reordered_udp, &["prepare_request", "("], 0).expect("prepare token");
    let select = position(&reordered_udp, &["select_udp_route", "("], 0).expect("select token");
    reordered_udp.swap(prepare, select);
    assert!(
        check_udp_order(&reordered_udp).is_err(),
        "UDP prepare/select reorder mutation survived"
    );
    let mut split_udp_cap = udp.to_vec();
    let session_cap = position(&split_udp_cap, &["protocol", ".", "session_count", "("], 0)
        .expect("shared session ceiling token");
    split_udp_cap[session_cap] = "mappings".to_owned();
    split_udp_cap[session_cap + 2] = "orphan_count".to_owned();
    assert!(
        check_udp_order(&split_udp_cap).is_err(),
        "orphan-only admission mutation survived"
    );
    let mut aliased_tcp = tcp.to_vec();
    aliased_tcp.extend(["poll_read_plain".to_owned(), "(".to_owned()]);
    assert!(
        check_tcp_boundary(&aliased_tcp).is_err(),
        "second plaintext read-loop mutation survived"
    );
    let mut preauth_tcp = tcp.to_vec();
    let function = position(&preauth_tcp, &["async", "fn", "server_connection"], 0)
        .expect("server connection token");
    let authenticate = position(&preauth_tcp, &["accept", "("], function).expect("accept token");
    let select = position(&preauth_tcp, &["select_tcp_route", "("], function)
        .expect("route selection token");
    preauth_tcp.swap(authenticate, select);
    assert!(
        check_tcp_boundary(&preauth_tcp).is_err(),
        "pre-auth TCP sniff mutation survived"
    );
    let check_run_latch = |tokens: &[String]| {
        (!tokens.iter().any(|token| token == "schema_version"))
            .then_some(())
            .ok_or("server schema latch restored")
    };
    check_run_latch(run).unwrap_or_else(|error| panic!("{error}"));
    let mut latched_run = run.to_vec();
    latched_run.push("schema_version".to_owned());
    assert!(
        check_run_latch(&latched_run).is_err(),
        "schema latch mutation survived"
    );
}

#[test]
fn client_socks_owns_one_terminal_route_and_one_plan_udp_association() {
    fn item_body<'a>(tokens: &'a [String], header: &[&str]) -> &'a [String] {
        let start = tokens
            .windows(header.len())
            .position(|window| window.iter().map(String::as_str).eq(header.iter().copied()))
            .unwrap_or_else(|| panic!("missing item {header:?}"));
        let body = tokens[start..]
            .iter()
            .position(|token| token == "{")
            .map(|offset| start + offset)
            .expect("item body");
        let end = balanced_end(tokens, body, "{", "}").expect("balanced item body");
        &tokens[body..end]
    }

    let root = workspace_root();
    let sources = token_sources(
        &root,
        &[
            "bins/ferrum2-client/src/run/socks.rs",
            "bins/ferrum2-client/src/run/egress/udp.rs",
        ],
    );
    let socks = sources[0]
        .production_tokens()
        .expect("client SOCKS production tokens");
    let udp = sources[1]
        .production_tokens()
        .expect("client UDP production tokens");
    let endpoint = item_body(socks, &["struct", "SocksUdpEndpoint"]);
    for field in ["socket", "peer_ip", "port", "wire", "last_valid"] {
        assert!(
            has_tokens(endpoint, &[field, ":"]),
            "SOCKS endpoint lost private {field} ownership"
        );
    }
    assert!(
        !endpoint.iter().any(|token| token == "pub"),
        "SOCKS endpoint exposed an owned field"
    );

    let association = item_body(udp, &["struct", "ClientUdpAssociation"]);
    let check_one_plan = |association: &[String], udp: &[String]| -> Result<(), &'static str> {
        for field in [
            "plan",
            "first_server",
            "protocol",
            "pending_session",
            "manager",
            "handle",
            "live_ids",
            "upstream",
            "inner_wire",
            "upstream_wire",
            "scratch",
            "_fixed_capacity",
        ] {
            if !has_tokens(association, &[field, ":"]) {
                return Err("association lost setup-time ownership");
            }
        }
        if !has_tokens(
            association,
            &["protocol", ":", "Option", "<", "ClientUdpPlan", ">"],
        ) {
            return Err("association protocol is not one lazy slot");
        }
        if association.iter().any(|token| token == "pub") {
            return Err("client UDP exposed an owned field");
        }
        if has_tokens(udp, &["struct", "ClientUdpProtocol"]) {
            return Err("client UDP restored a duplicate protocol wrapper");
        }
        if [
            "plans",
            "plan_map",
            "plans_by_key",
            "application",
            "application_wire",
        ]
        .iter()
        .any(|forbidden| association.iter().any(|token| token == forbidden))
            || ["HashMap", "BTreeMap"]
                .iter()
                .any(|forbidden| udp.iter().any(|token| token == forbidden))
            || has_tokens(association, &["Vec", "<", "EgressPlanSnapshot", ">"])
            || has_tokens(association, &["Vec", "<", "ClientUdpPlan", ">"])
        {
            return Err("client UDP restored a plan-keyed collection");
        }
        Ok(())
    };
    check_one_plan(association, udp).unwrap_or_else(|error| panic!("{error}"));

    let mut btree_map = udp.to_vec();
    btree_map.push("BTreeMap".to_owned());
    assert!(
        check_one_plan(association, &btree_map).is_err(),
        "BTreeMap plan-map mutation survived"
    );
    let mut vector_map = association.to_vec();
    vector_map.extend(["plans", ":", "Vec", "<", "EgressPlanSnapshot", ">"].map(str::to_owned));
    assert!(
        check_one_plan(&vector_map, udp).is_err(),
        "Vec plan-map mutation survived"
    );

    let prepare = item_body(udp, &["async", "fn", "prepare"]);
    let activate = item_body(udp, &["fn", "activate"]);
    let check_split_phase = |prepare: &[String], activate: &[String]| -> Result<(), &'static str> {
        for required in ["reserve_session", "buffer_budget", "bind", "connect"] {
            if !prepare.iter().any(|token| token == required) {
                return Err("prepare lost setup-time resource ownership");
            }
        }
        if prepare.iter().any(|token| token == "register_udp_plan") {
            return Err("prepare eagerly registered protocol state");
        }
        if !activate.iter().any(|token| token == "register_udp_plan") {
            return Err("activate lost protocol registration");
        }
        for forbidden in ["reserve_session", "buffer_budget", "bind", "connect"] {
            if activate.iter().any(|token| token == forbidden) {
                return Err("activate recreated setup-time resources");
            }
        }
        Ok(())
    };
    check_split_phase(prepare, activate).unwrap_or_else(|error| panic!("{error}"));
    for (phase, mutation) in [("prepare", "register_udp_plan"), ("activate", "bind")] {
        let mut mutated_prepare = prepare.to_vec();
        let mut mutated_activate = activate.to_vec();
        if phase == "prepare" {
            mutated_prepare.push(mutation.to_owned());
        } else {
            mutated_activate.push(mutation.to_owned());
        }
        assert!(
            check_split_phase(&mutated_prepare, &mutated_activate).is_err(),
            "split-phase mutation survived: {phase}"
        );
    }

    let check_endpoint_surface = |tokens: &[String]| -> Result<(), &'static str> {
        for declaration in tokens.windows(2).filter(|window| {
            matches!(window[0].as_str(), "fn" | "struct" | "trait" | "type")
                && window[1].to_ascii_lowercase().contains("endpoint")
        }) {
            if declaration != ["struct", "SocksUdpEndpoint"] {
                return Err("SOCKS endpoint gained a helper/factory seam");
            }
        }
        if tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "Factory" | "factory" | "SocksUdpEndpointFactory"
            )
        }) {
            return Err("SOCKS endpoint gained a factory");
        }
        Ok(())
    };
    check_endpoint_surface(socks).unwrap_or_else(|error| panic!("{error}"));
    for mutation in [
        ["trait", "SocksUdpEndpointFactory"],
        ["fn", "make_socks_udp_endpoint"],
    ] {
        let mut mutated = socks.to_vec();
        mutated.extend(mutation.map(str::to_owned));
        assert!(
            check_endpoint_surface(&mutated).is_err(),
            "endpoint helper/factory mutation survived"
        );
    }

    let classify = item_body(socks, &["async", "fn", "classify_udp_association"]);
    assert_eq!(
        classify
            .windows(2)
            .filter(|window| window[0] == "select_terminal" && window[1] == "(")
            .count(),
        1,
        "schema-v2 UDP must classify exactly once"
    );
    assert_eq!(
        classify
            .windows(2)
            .filter(|window| window[0] == "prepare_udp" && window[1] == "(")
            .count(),
        1,
        "terminal route must create one selected plan owner"
    );
    let check_post_classification = |body: &[String]| -> Result<(), &'static str> {
        for forbidden in [
            "select_terminal",
            "select_plan_snapshot",
            "selector_control",
            "evaluate",
            "program",
            "legacy",
            "final",
        ] {
            if body.iter().any(|token| token == forbidden) {
                return Err("established UDP association re-entered route state");
            }
        }
        for field in [
            "plan",
            "protocol",
            "pending_session",
            "upstream",
            "inner_wire",
            "upstream_wire",
        ] {
            if has_tokens(body, &["prepared", ".", field]) {
                return Err("SOCKS owner reached through a client UDP field");
            }
        }
        Ok(())
    };
    for (helper, mutation) in [
        ("relay_udp_association", "select_terminal"),
        ("forward_udp_request", "program"),
        ("relay_hijacked_udp", "final"),
        ("answer_hijacked_udp", "select_plan_snapshot"),
    ] {
        let body = item_body(socks, &["async", "fn", helper]);
        check_post_classification(body).unwrap_or_else(|error| panic!("{helper}: {error}"));
        let mut mutated = body.to_vec();
        mutated.push(mutation.to_owned());
        assert!(
            check_post_classification(&mutated).is_err(),
            "post-classification route mutation survived: {helper}"
        );
    }
    let mut reach_through = item_body(socks, &["async", "fn", "forward_udp_request"]).to_vec();
    reach_through.extend(["prepared", ".", "plan"].map(str::to_owned));
    assert!(
        check_post_classification(&reach_through).is_err(),
        "client UDP field reach-through mutation survived"
    );

    let manifest =
        fs::read_to_string(root.join("bins/ferrum2-client/Cargo.toml")).expect("client manifest");
    assert!(manifest.contains("ferrum2-sniff.workspace = true"));
}

#[test]
fn recursive_rust_source_discovery_excludes_non_rust_files() {
    let directory = tempfile::tempdir().expect("source discovery tempdir");
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).expect("nested source directory");
    fs::write(directory.path().join("root.rs"), "root").expect("root source");
    fs::write(nested.join("nested.rs"), "nested").expect("nested source");
    fs::write(nested.join("ignored.txt"), "ignored").expect("non-source");

    let sources = rust_sources(directory.path());
    assert_eq!(sources.len(), 2);
    assert!(sources.iter().any(|path| path.ends_with("nested.rs")));
    assert!(sources.iter().any(|path| path.ends_with("root.rs")));
}

#[test]
fn lexical_ownership_scanner_rejects_decoys_and_owner_mutations() {
    let definition = ("struct", "Owned", "sample/owner.rs");
    let reformatted = [TokenSource::new(
        "sample/owner.rs",
        "pub\nstruct\nOwned; // pub struct CommentDecoy\n\
         const TEXT: &str = \"pub struct StringDecoy\";",
    )];
    assert!(
        check_definition_ownership(&reformatted, &[definition], &["sample/root.rs"]).is_ok(),
        "whitespace and comment/string decoys must preserve the real owner"
    );
    for (mutation, sources) in [
        (
            "duplicate",
            vec![
                TokenSource::new("sample/owner.rs", "struct Owned;"),
                TokenSource::new("sample/duplicate.rs", "struct Owned;"),
            ],
        ),
        (
            "wrong owner/move",
            vec![TokenSource::new("sample/wrong.rs", "struct Owned;")],
        ),
        (
            "root restoration",
            vec![TokenSource::new("sample/root.rs", "struct Owned;")],
        ),
    ] {
        assert!(
            check_definition_ownership(&sources, &[definition], &["sample/root.rs"]).is_err(),
            "ownership checker accepted {mutation}"
        );
    }

    let globbed = [TokenSource::new("sample/owner.rs", "use super :: *;")];
    assert!(
        check_no_glob_facades(&globbed, &["sample/owner.rs"], &[]).is_err(),
        "ownership checker accepted a glob facade"
    );

    let test_rule = ("fn", "owned_case", "sample/owner.rs");
    let wrong_test_owner = [TokenSource::new(
        "sample/tests.rs",
        "#[test] fn owned_case() {}",
    )];
    assert!(
        check_test_placement(&wrong_test_owner, &[test_rule], &["sample/tests.rs"], &[]).is_err(),
        "test placement checker accepted the wrong owner"
    );
    let cycle = [
        TokenSource::new(
            "sample/owner.rs",
            "use crate::run::tests::fixture; #[test] fn owned_case() {}",
        ),
        TokenSource::new("sample/tests.rs", ""),
    ];
    assert!(
        check_test_placement(&cycle, &[test_rule], &["sample/tests.rs"], &[]).is_err(),
        "test placement checker accepted an owner/composition cycle"
    );

    let mut accepted = Vec::new();
    for (mutation, source) in [
        (
            "cfg(test) use followed by mod and production",
            "#[cfg(test)] use crate::fixture; mod tests; fn production() {}",
        ),
        (
            "non-terminal cfg(test) module",
            "#[cfg(test)] mod tests; fn production() {}",
        ),
    ] {
        let source = TokenSource::new("sample/owner.rs", source);
        if check_no_identifiers([&source], &["production"]).is_ok() {
            accepted.push(mutation);
        }
    }
    for (mutation, source, expected) in [
        (
            "pub(in path) restricted item",
            "pub(in crate::run) fn extra() {}",
            &[][..],
        ),
        (
            "duplicate restricted item name",
            "struct A; impl A { pub(super) fn new() {} } \
             struct B; impl B { pub(super) fn new() {} }",
            &["new"][..],
        ),
    ] {
        let sources = [TokenSource::new("sample/owner.rs", source)];
        if check_restricted_interfaces(&sources, &[("sample/owner.rs", expected)]).is_ok() {
            accepted.push(mutation);
        }
    }
    for (mutation, source, owners, roots) in [
        (
            "crate root glob import",
            "use crate::run::*;",
            &["sample/owner.rs"][..],
            &[][..],
        ),
        (
            "self child root glob import",
            "use self::child::*;",
            &[][..],
            &["sample/root.rs"][..],
        ),
    ] {
        let sources = [TokenSource::new(
            if owners.is_empty() {
                "sample/root.rs"
            } else {
                "sample/owner.rs"
            },
            source,
        )];
        if check_no_glob_facades(&sources, owners, roots).is_ok() {
            accepted.push(mutation);
        }
    }
    let relative_cycle = [
        TokenSource::new(
            "sample/owner.rs",
            "use super::super::tests::fixture; #[test] fn owned_case() {}",
        ),
        TokenSource::new("sample/tests.rs", ""),
    ];
    if check_test_placement(&relative_cycle, &[test_rule], &["sample/tests.rs"], &[]).is_ok() {
        accepted.push("relative owner/test cycle");
    }

    for (mutation, source) in [
        (
            "renamed root executor",
            "fn run() {} fn renamed_executor() {}",
        ),
        (
            "allowed root function with protocol operation",
            "fn run() { association.accept_response(); }",
        ),
    ] {
        let sources = [TokenSource::new("sample/root.rs", source)];
        if check_composition_roots(&sources, &[("sample/root.rs", &["run"])]).is_ok() {
            accepted.push(mutation);
        }
    }
    assert!(
        accepted.is_empty(),
        "ownership scanner accepted mutations: {accepted:?}"
    );
}

#[test]
fn production_owner_dependencies_are_explicit_and_narrow() {
    let root = workspace_root();
    let owners = [
        "bins/ferrum2-client/src/run/context.rs",
        "bins/ferrum2-client/src/run/dns.rs",
        "bins/ferrum2-client/src/run/io.rs",
        "bins/ferrum2-client/src/run/observation.rs",
        "bins/ferrum2-client/src/run/socks.rs",
        "bins/ferrum2-server/src/run/dns.rs",
        "bins/ferrum2-server/src/run/io.rs",
        "bins/ferrum2-server/src/run/observation.rs",
        "bins/ferrum2-server/src/run/tcp.rs",
        "bins/ferrum2-server/src/run/udp.rs",
        "crates/ferrum2-config/src/error.rs",
        "crates/ferrum2-config/src/load.rs",
        "crates/ferrum2-config/src/model.rs",
        "crates/ferrum2-config/src/raw.rs",
        "crates/ferrum2-config/src/validation.rs",
    ];
    let roots = [
        "bins/ferrum2-client/src/run.rs",
        "bins/ferrum2-server/src/run.rs",
    ];
    let mut paths = owners.to_vec();
    paths.extend(roots);
    let sources = token_sources(&root, &paths);
    check_no_glob_facades(&sources, &owners, &roots).unwrap_or_else(|error| panic!("{error}"));

    check_restricted_interfaces(
        &sources,
        &[
            (owners[0], &["ClientContext", "ClientRouting"]),
            (owners[1], &["ClientDnsRoot"]),
            (
                owners[2],
                &[
                    "TokioConnector",
                    "TokioFramed",
                    "TokioTransport",
                    "bind_listener",
                    "new",
                    "new",
                    "new",
                    "shutdown_signal",
                    "terminal",
                ],
            ),
            (
                owners[3],
                &[
                    "ClientMetricsRoot",
                    "UdpPacketPhase",
                    "finish_relay",
                    "log_level",
                    "observation_for_error",
                    "record_failure",
                    "record_forced_udp_sessions",
                    "record_sniff",
                    "record_udp_drop",
                    "record_udp_packet_error",
                    "record_udp_runtime_error",
                    "record_udp_terminal",
                    "run_error_for_supervisor",
                ],
            ),
            (owners[4], &["ClientTcpListeners", "ClientTcpRoot"]),
            (owners[5], &["ServerDnsRoot"]),
            (
                owners[6],
                &[
                    "TokioFramed",
                    "TokioTransport",
                    "bind_listener",
                    "new",
                    "new",
                    "shutdown_signal",
                    "terminal",
                ],
            ),
            (
                owners[7],
                &[
                    "ServerMetricsRoot",
                    "finish_relay",
                    "log_level",
                    "observation_for_direct_connect",
                    "observation_for_error",
                    "record_failure",
                    "record_sniff",
                    "record_udp_failure",
                    "record_udp_protocol_failure",
                    "record_udp_request_accepted",
                    "record_udp_runtime_failure",
                    "run_error_for_supervisor",
                    "update_replay_metric",
                    "update_udp_resource_metrics",
                ],
            ),
            (
                owners[8],
                &[
                    "ServerContext",
                    "ServerRouting",
                    "ServerTerminalRoute",
                    "ServerTcpListeners",
                    "ServerTcpRoot",
                    "legacy",
                    "program",
                    "route_metadata",
                    "sniff_order",
                    "terminal",
                ],
            ),
            (
                owners[9],
                &[
                    "PreparedUdpServer",
                    "ServerUdpListener",
                    "ServerUdpShared",
                    "UdpMappings",
                    "new",
                    "prepare_udp_server",
                    "udp_runtime_limits",
                ],
            ),
            (owners[10], &["new", "semantic"]),
            (owners[11], &[]),
            (owners[12], &[]),
            (
                owners[13],
                &[
                    "RawChain",
                    "RawClient",
                    "RawClientInbound",
                    "RawClientOutbound",
                    "RawClientRoot",
                    "RawDns",
                    "RawDnsInbound",
                    "RawDnsRoute",
                    "RawDnsRouteRule",
                    "RawDnsServer",
                    "RawLogging",
                    "RawMetrics",
                    "RawReplay",
                    "RawRoute",
                    "RawRouteRule",
                    "RawRouteTarget",
                    "RawRuntime",
                    "RawSelector",
                    "RawServer",
                    "RawServerInbound",
                    "RawServerOutbound",
                    "RawServerRoot",
                    "RawShadowsocks",
                    "RawTun",
                    "RawUdp",
                    "SecretString",
                    "as_str",
                ],
            ),
            (owners[14], &["validate_client", "validate_server"]),
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn tun_foundation_is_deep_safe_and_composed_as_one_required_root() {
    let root = workspace_root();
    let tun_manifest =
        fs::read_to_string(root.join("crates/ferrum2-tun/Cargo.toml")).expect("TUN manifest");
    for forbidden in [
        "ferrum2-config",
        "ferrum2-dns",
        "ferrum2-shadowsocks",
        "bins/",
    ] {
        assert!(
            !tun_manifest.contains(forbidden),
            "TUN owns forbidden edge {forbidden}"
        );
    }
    let tun = fs::read_to_string(root.join("crates/ferrum2-tun/src/lib.rs")).expect("TUN source");
    let tun_production = tun.split("#[cfg(test)]").next().expect("TUN production");
    let tun_tcp = fs::read_to_string(root.join("crates/ferrum2-tun/src/tcp.rs"))
        .expect("TUN TCP flow source");
    let tun_udp = fs::read_to_string(root.join("crates/ferrum2-tun/src/udp.rs"))
        .expect("TUN UDP mapping source");
    let client_tun = fs::read_to_string(root.join("bins/ferrum2-client/src/run/tun.rs"))
        .expect("client TUN adapter");
    let client_routing = fs::read_to_string(root.join("bins/ferrum2-client/src/run/routing.rs"))
        .expect("shared client terminal routing");
    let client_socks = fs::read_to_string(root.join("bins/ferrum2-client/src/run/socks.rs"))
        .expect("client SOCKS adapter");
    let client_udp = fs::read_to_string(root.join("bins/ferrum2-client/src/run/egress/udp.rs"))
        .expect("shared client UDP association");
    let client_egress = fs::read_to_string(root.join("bins/ferrum2-client/src/run/egress/mod.rs"))
        .expect("shared client egress engine");
    let config_contract =
        fs::read_to_string(root.join("crates/ferrum2-config/tests/config_contract.rs"))
            .expect("config contract tests");
    for required in [
        "#![forbid(unsafe_code)]",
        "poll_ingress_single",
        "const PACKET_QUANTUM: usize = 8",
        "set_any_ip(true)",
        "add_default_ipv4_route",
        "add_default_ipv6_route",
        "ferrum2-tun-owner",
        "impl<E, T> PreparedProcessRoot<E>",
    ] {
        assert!(
            tun.contains(required),
            "missing TUN owner contract {required}"
        );
    }
    let has_reap_contract = |source: &str| {
        source
            .matches("prepare_failure(guard, errors.startup, errors.cleanup).await")
            .count()
            >= 3
            && source.contains("guard.reap().await == OwnerExit::CleanupFailed")
            && source.contains("tokio::task::spawn_blocking(move || thread.join()).await")
            && source.contains("tokio::task::block_in_place(move ||")
    };
    assert!(
        has_reap_contract(&tun),
        "prepare/drop reaping contract missing"
    );
    let detached_mutation = tun.replace("guard.reap().await == OwnerExit::CleanupFailed", "false");
    assert!(
        !has_reap_contract(&detached_mutation),
        "cancellation mutation must remove the guarded reap proof"
    );
    let has_single_deadline_contract = |source: &str| {
        let compact = source.split_whitespace().collect::<String>();
        source.matches(".checked_add(timeout)").count() == 1
            && source
                .matches("std::time::Instant::now() >= deadline")
                .count()
                >= 3
            && compact.contains("owner_main(config,owner_control,ready_sender,deadline,metrics)")
    };
    assert!(
        has_single_deadline_contract(&tun),
        "prepare and owner must share one absolute readiness deadline"
    );
    let late_ready_mutation = tun.replace("std::time::Instant::now() >= deadline", "false");
    assert!(
        !has_single_deadline_contract(&late_ready_mutation),
        "late-ready mutation must remove the deadline proof"
    );
    for forbidden in ["VecDeque", "pub trait", "pub enum", "Interface::poll("] {
        assert!(
            !tun.contains(forbidden),
            "TUN exposes or uses forbidden seam {forbidden}"
        );
    }

    let wintun_root =
        fs::read_to_string(root.join("crates/ferrum2-wintun/src/lib.rs")).expect("Wintun root");
    let wintun_windows = fs::read_to_string(root.join("crates/ferrum2-wintun/src/windows.rs"))
        .expect("Wintun FFI module");
    let (wintun_production, _) = wintun_windows
        .split_once("#[cfg(test)]\nmod tests {")
        .expect("exact Wintun test module boundary");
    assert!(wintun_root.contains("#[allow(unsafe_code)]\nmod windows;"));
    assert_eq!(
        token_sources_under(&root, &["crates/ferrum2-wintun/src"])
            .iter()
            .filter(|source| source.tokens.iter().any(|token| token == "unsafe"))
            .map(|source| source.path.as_str())
            .collect::<Vec<_>>(),
        vec!["crates/ferrum2-wintun/src/windows.rs"]
    );
    let received_packet_is_borrowed_and_released = |source: &str| {
        source.matches("pub struct ReceivedPacket<'a>").count() == 1
            && source
                .contains("pub fn receive(&mut self) -> Result<Option<ReceivedPacket<'_>>, Error>")
            && source.contains("_borrow: PhantomData<&'a mut Adapter>")
            && source.contains("_not_send: PhantomData<Rc<()>>")
            && source.contains("release: self.library.exports.release_receive_packet")
            && source.contains("impl Drop for ReceivedPacket<'_>")
            && source.contains("unsafe { (self.release)(self.session, self.packet) };")
            && !source.contains("unsafe impl Send for ReceivedPacket")
    };
    assert!(
        received_packet_is_borrowed_and_released(wintun_production),
        "ReceivedPacket must borrow Adapter, remain !Send and release exactly on Drop"
    );
    for mutation in [
        wintun_production.replace(
            "_borrow: PhantomData<&'a mut Adapter>",
            "_borrow: PhantomData<&'a ()>",
        ),
        wintun_production.replace(
            "_not_send: PhantomData<Rc<()>>",
            "_not_send: PhantomData<()>",
        ),
        wintun_production.replace(
            "unsafe { (self.release)(self.session, self.packet) };",
            "let _ = self.packet;",
        ),
    ] {
        assert!(
            !received_packet_is_borrowed_and_released(&mutation),
            "ReceivedPacket lifetime/affinity/release mutation survived"
        );
    }
    let sole_stack_owner = |source: &str| {
        let owner = source
            .split_once("fn owner_main<T: Send + 'static>(")
            .and_then(|(_, tail)| tail.split_once("\n#[derive(Clone, Copy)]"))
            .map(|(body, _)| body);
        source.matches("ferrum2_wintun::Adapter::create(").count() == 1
            && source.matches("Stack::new_with_udp(").count() == 1
            && source
                .matches("owner_main(config, owner_control, ready_sender, deadline, metrics)")
                .count()
                == 1
            && owner.is_some_and(|owner| {
                owner.contains("ferrum2_wintun::Adapter::create(")
                    && owner.contains("Stack::new_with_udp(")
                    && owner.contains("adapter.receive()")
                    && owner.contains("stack.enqueue_at(")
                    && owner.contains("stack.poll_udp_events(")
                    && owner.contains("stack.poll_quantum(")
                    && owner.contains("stack.take_output(|packet| adapter.send(packet).is_ok())")
                    && owner.contains("match adapter.cleanup()")
            })
    };
    assert!(
        sole_stack_owner(tun_production),
        "the named TUN owner must exclusively own the adapter and stack pump"
    );
    for mutation in [
        tun_production.replace("adapter.receive()", "receive_packet()"),
        tun_production.replace("stack.poll_udp_events(", "poll_udp_events("),
        tun_production.replace(
            "stack.take_output(|packet| adapter.send(packet).is_ok())",
            "stack.take_output(|_| true)",
        ),
    ] {
        assert!(
            !sole_stack_owner(&mutation),
            "sole adapter/stack owner mutation survived"
        );
    }
    let mut product_sources = token_sources_under(&root, &["bins", "crates"]);
    let forbidden_platform_prefixes = [
        "CreateIpForward",
        "SetIpForward",
        "DeleteIpForward",
        "SetInterfaceDns",
        "DnsInterfaceSettings",
        "Fwpm",
    ];
    let has_no_platform_mutation = |sources: &[TokenSource]| {
        sources.iter().all(|source| {
            source.production_tokens().is_ok_and(|tokens| {
                tokens.iter().all(|token| {
                    let forbidden = forbidden_platform_prefixes
                        .iter()
                        .any(|prefix| token.starts_with(prefix));
                    !forbidden
                        || source.path == "crates/ferrum2-wintun/src/windows.rs"
                            && matches!(
                                token.as_str(),
                                "CreateIpForwardEntry2"
                                    | "DeleteIpForwardEntry2"
                                    | "SetInterfaceDnsSettings"
                            )
                })
            })
        })
    };
    assert!(
        has_no_platform_mutation(&product_sources),
        "product code must not mutate host routes, DNS or WFP"
    );
    for forbidden in [
        "CreateIpForwardEntry2",
        "SetIpForwardEntry2",
        "DeleteIpForwardEntry2",
        "SetInterfaceDnsSettings",
        "DnsInterfaceSettings",
        "FwpmFilterAdd0",
    ] {
        product_sources.push(TokenSource::new(
            "crates/ferrum2-tun/src/platform_mutation.rs",
            &format!("fn mutation() {{ {forbidden}(); }}"),
        ));
        assert!(
            !has_no_platform_mutation(&product_sources),
            "product-wide platform mutation oracle missed {forbidden}"
        );
        product_sources.pop();
    }
    let preserves_setup_cleanup_failure = |wintun: &str, tun: &str| {
        wintun.contains("finish_setup_transaction(setup, || owner.cleanup_inner())")
            && wintun.contains("if cleanup()")
            && wintun.contains("Err(CreateError::cleanup())")
            && tun.contains("if error.is_cleanup_failure()")
            && tun.contains("guard.reap().await == OwnerExit::CleanupFailed")
    };
    assert!(
        preserves_setup_cleanup_failure(&wintun_windows, &tun),
        "setup rollback failure must reach the cleanup process error"
    );
    let swallowed_cleanup_mutation = wintun_windows.replace(
        "Err(CreateError::cleanup())",
        "Err(CreateError::operation())",
    );
    assert!(
        !preserves_setup_cleanup_failure(&swallowed_cleanup_mutation, &tun),
        "setup cleanup mutation must remove the failure-kind proof"
    );
    let setup_order = [
        "setup.check_cancelled()?",
        "setup.check_deadline()?",
        "setup.create_adapter()?",
        "setup.check_driver()?",
        "setup.set_ipv4_mtu()?",
        "setup.set_ipv6_mtu()?",
        "setup.add_ipv4_address()?",
        "setup.add_ipv6_address()?",
        "setup.start_session()?",
        "setup.wait_for_dad()",
    ];
    let cleanup_order = [
        "cleanup.end_session()",
        "cleanup.delete_last_address()",
        "cleanup.restore_ipv6_mtu()",
        "cleanup.restore_ipv4_mtu()",
        "cleanup.close_adapter()",
    ];
    for order in [setup_order.as_slice(), cleanup_order.as_slice()] {
        let positions = order
            .iter()
            .map(|needle| wintun_windows.find(needle).expect("transaction step"))
            .collect::<Vec<_>>();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "Wintun transaction order drifted: {order:?}"
        );
    }
    let wait_cleanup_is_serial = |source: &str| {
        source.contains("let _wait = self.session_journal.begin_wait()?")
            && source.contains("if !cleanup.session_is_idle()")
            && source.find("if !cleanup.session_is_idle()") < source.find("cleanup.end_session()")
    };
    assert!(
        wait_cleanup_is_serial(&wintun_windows),
        "active receive wait must fail closed before EndSession"
    );
    let overlapping_wait_mutation =
        wintun_windows.replace("if !cleanup.session_is_idle()", "if false");
    assert!(
        !wait_cleanup_is_serial(&overlapping_wait_mutation),
        "wait/EndSession overlap mutation must remove the serialization proof"
    );
    assert!(
        !wintun_windows.contains("DadState = IpDadStatePreferred"),
        "optimistic DAD assignment is forbidden"
    );
    let reordered_dad = wintun_windows.replace(
        "setup.start_session()?;\n    setup.wait_for_dad()",
        "setup.wait_for_dad()?;\n    setup.start_session()",
    );
    assert_ne!(
        reordered_dad, wintun_windows,
        "StartSession-before-DAD mutation anchor missing"
    );
    let wintun_setup_is_production_connected = |source: &str| {
        let compact = source.split_whitespace().collect::<String>();
        compact.contains("setup.create_adapter()?;setup.check_driver()?;")
            && compact
                .contains("classify_adapter_create_failure(unsafe{GetLastError()}).into_error()")
            && compact
                .contains("dad_snapshot(self.session.is_some(),states,Instant::now()>=deadline)")
    };
    assert!(
        wintun_setup_is_production_connected(wintun_production),
        "private create classification and post-session dual-family DAD must drive production"
    );
    for mutation in [
        wintun_production.replace("setup.create_adapter()?;", ""),
        wintun_production.replace(
            "classify_adapter_create_failure(unsafe { GetLastError() })",
            "AdapterCreateFailure::Other",
        ),
        wintun_production.replace("self.session.is_some()", "false"),
    ] {
        assert!(
            !wintun_setup_is_production_connected(&mutation),
            "Wintun setup mutation must sever the production proof"
        );
    }
    for forbidden in [
        "WintunOpenAdapter",
        "WintunDeleteDriver",
        "WintunSetLogger",
        "SetIpForwardEntry",
        "Fwpm",
    ] {
        assert!(
            !wintun_windows.contains(forbidden),
            "forbidden platform surface {forbidden}"
        );
    }
    assert!(
        !wintun_windows
            .replace("CreateIpForwardEntry2", "")
            .contains("CreateIpForwardEntry")
            && !wintun_windows
                .replace("DeleteIpForwardEntry2", "")
                .contains("DeleteIpForwardEntry"),
        "Wintun route mutation must use only the exact M16 Create/DeleteIpForwardEntry2 surface"
    );
    assert!(
        wintun_windows.contains("GetInterfaceDnsSettings")
            && wintun_windows.contains("SetInterfaceDnsSettings")
            && wintun_windows.contains("FreeInterfaceDnsSettings")
            && wintun_windows.contains("DNS_SETTING_NAMESERVER")
            && !wintun_windows.contains("DNS_SETTING_IPV6"),
        "Wintun DNS mutation must remain the exact IPv4-only snapshot/set/free surface"
    );

    let controller = fs::read_to_string(root.join("tests/platform/qualify_windows_tun.ps1"))
        .expect("Windows TUN qualification controller");
    let has_cleanup_snapshots = |source: &str| {
        source.contains("Get-InterfaceAddressSnapshot")
            && source.contains("Get-InterfaceRouteSnapshot")
            && source.contains("Assert-SnapshotEqual $systemRoutes $afterOwnedRoutes")
            && source.contains("Assert-InterfaceGone $adapterName $ownedInterfaceIndex")
            && source.contains("Stop-Process -InputObject $activeProcess -Force")
            && source.contains("$binary --config $config --check-config")
            && source
                .split_once("$activeProcess = Start-Candidate $binary $failureConfig")
                .and_then(|(_, tail)| tail.split_once("$heldMetrics.Stop()"))
                .map(|(failure, _)| {
                    !failure.contains("Wait-AdapterAppeared")
                        && !failure.contains("$failedAdapter")
                        && [
                            "Assert-True (Wait-ProcessExit $activeProcess 20)",
                            "$failureExit = [Ferrum2ProcessGroup]::ExitCode([uint32]$activeProcess.Id)",
                            "Assert-True ($failureExit -ne 0)",
                            "[Ferrum2ProcessGroup]::Close([uint32]$activeProcess.Id)",
                            "$activeProcess = $null",
                            "Assert-InterfaceGone $adapterName $null",
                        ]
                        .iter()
                        .map(|needle| failure.find(needle))
                        .collect::<Option<Vec<_>>>()
                        .is_some_and(|positions| {
                            positions.windows(2).all(|pair| pair[0] < pair[1])
                        })
                })
                .unwrap_or(false)
            && source.contains("$failureExit -ne 0")
            && source.contains(
                "Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes",
            )
            && source.contains("Assert-SnapshotEqual $expectedAutomaticRoutes $automaticRoutes")
            && source.contains("ferrum2_tun_packets_accepted")
            && source.contains("$acceptedDelta -gt 0")
            && source
                .split_once("$udp4.Connect(\"192.0.2.200\", 53)")
                .and_then(|(_, tail)| tail.split_once("$udp6 ="))
                .map(|(witness, _)| witness)
                .is_some_and(|witness| {
                    !witness.contains("$settleDeadline")
                        && !witness.contains("$stableSamples")
                        && !witness.contains("quiet baseline")
                        && !witness.contains("ferrum2_tun_packets_foundation_dropped")
                        && [
                            "$beforeMetrics = Get-Metrics $metricsPort",
                            "$acceptedBefore = Get-CounterValue $beforeMetrics",
                            "[void]$udp4.Send([byte[]](1,2,3,4), 4)",
                            "$packetDeadline = [DateTime]::UtcNow.AddSeconds(5)",
                            "$afterMetrics = Get-Metrics $metricsPort",
                            "$acceptedAfter = Get-CounterValue $afterMetrics",
                            "$acceptedDelta = $acceptedAfter - $acceptedBefore",
                            "} while ([DateTime]::UtcNow -lt $packetDeadline)",
                            "Assert-True ($acceptedDelta -gt 0)",
                        ]
                        .iter()
                        .map(|needle| witness.find(needle))
                        .collect::<Option<Vec<_>>>()
                        .is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1]))
                })
            && source.contains("$createdSiblingDll")
            && source.contains("FERRUM2_WINTUN_ZIP")
            && source.contains("Resolve-Path -LiteralPath $zipInput")
            && !source.contains("Downloads")
            && source.matches("$foundation++").count() == 4
            && source.contains("m15_windows_tun_e2e status=PASS profile=foundation")
            && source.find("finally {").is_some_and(|finally| {
                source
                    .find("Write-Output \"m15_windows_tun_e2e")
                    .is_some_and(|marker| marker > finally)
            })
    };
    assert!(
        has_cleanup_snapshots(&controller),
        "privileged controller snapshot/fallback contract missing"
    );
    let cleanup_mutation = controller.replace(
        "Assert-SnapshotEqual $systemRoutes $afterOwnedRoutes",
        "Write-Output $afterOwnedRoutes",
    );
    assert!(
        !has_cleanup_snapshots(&cleanup_mutation),
        "route-cleanup mutation must remove the snapshot proof"
    );
    let route_subset_mutation = controller.replace(
        "Assert-SnapshotEqual $expectedAddressDerivedRoutes $addressDerivedRoutes",
        "foreach ($route in $expectedAddressDerivedRoutes) { Assert-True ($addressDerivedRoutes -contains $route) 'subset' }",
    );
    assert!(
        !has_cleanup_snapshots(&route_subset_mutation),
        "ready route subset mutation must remove exact-equality proof"
    );
    let witness_order_mutation = controller.replace(
        "    $beforeMetrics = Get-Metrics $metricsPort\n    $acceptedBefore = Get-CounterValue $beforeMetrics",
        "    $acceptedBefore = Get-CounterValue $beforeMetrics\n    $beforeMetrics = Get-Metrics $metricsPort",
    );
    assert!(
        !has_cleanup_snapshots(&witness_order_mutation),
        "packet witness mutation must snapshot counters before the controlled send"
    );
    let quiet_prerequisite_mutation = controller.replace(
        "    $beforeMetrics = Get-Metrics $metricsPort",
        "    $stableSamples = 0\n    $beforeMetrics = Get-Metrics $metricsPort",
    );
    assert!(
        !has_cleanup_snapshots(&quiet_prerequisite_mutation),
        "packet witness mutation must reject a quiet/stability prerequisite"
    );
    let stale_drop_mutation = controller.replace(
        "    $acceptedBefore = Get-CounterValue $beforeMetrics \"ferrum2_tun_packets_accepted\"",
        "    $acceptedBefore = Get-CounterValue $beforeMetrics \"ferrum2_tun_packets_accepted\"\n    $droppedBefore = Get-CounterValue $beforeMetrics \"ferrum2_tun_packets_foundation_dropped\"",
    );
    assert!(
        !has_cleanup_snapshots(&stale_drop_mutation),
        "controller witness mutation must reject the stale foundation-drop prerequisite"
    );
    let supports_headless_process_groups = |source: &str| {
        source.contains("GetConsoleProcessList")
            && source.contains("CREATE_NEW_CONSOLE")
            && source.contains("AttachConsole")
            && source.contains("FreeConsole")
            && !source.contains("GetConsoleWindow")
            && !source.contains("AllocConsole")
    };
    assert!(
        supports_headless_process_groups(&controller),
        "privileged controller must support a headless runner console"
    );
    assert!(
        !supports_headless_process_groups(&controller.replace("CREATE_NEW_CONSOLE", "0")),
        "headless-console creation mutation must remove the process-group proof"
    );
    let has_tcp_controller = |source: &str| {
        let open_tcp = source
            .split_once("function Open-TunTcp(")
            .and_then(|(_, tail)| tail.split_once("function Read-StreamToEnd("))
            .map(|(body, _)| body);
        let add_tun_route = source
            .split_once("function Add-TunRoute(")
            .and_then(|(_, tail)| tail.split_once("function Add-TargetAddress("))
            .map(|(body, _)| body);
        let classifier = source
            .split_once("function Get-Tcp01Boundary(")
            .and_then(|(_, tail)| tail.split_once("function Get-PeExportNames"))
            .map(|(body, _)| body);
        let pktmon_attribution = source
            .split_once("function Invoke-PktMon(")
            .and_then(|(_, tail)| tail.split_once("function Invoke-UnpinnedTcpCapture("))
            .map(|(body, _)| body);
        let capture_route_cleanup = source
            .split_once(
                "$routesBeforeCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)",
            )
            .and_then(|(_, tail)| tail.split_once("Restore-CapabilityDns $ownedInterfaceIndex"))
            .map(|(body, _)| body);
        let gate = source
            .split_once("public sealed class Ferrum2TcpGateObservation")
            .and_then(|(_, tail)| tail.split_once("public sealed class Ferrum2TcpProbe"))
            .map(|(body, _)| body);
        let probe = source
            .split_once("public sealed class Ferrum2TcpProbe")
            .and_then(|(_, tail)| tail.split_once("public sealed class Ferrum2DnsResponder"))
            .map(|(body, _)| body);
        let invoke_echo = source
            .split_once("function Invoke-EchoRow(")
            .and_then(|(_, tail)| tail.split_once("function Assert-ResetWithoutEgress("))
            .map(|(body, _)| body);
        let tcp_mode = source
            .split_once(
                "if ($Mode -in @(\"tcp\", \"udp\", \"full\", \"performance\")) {\n        $serverBinary =",
            )
            .and_then(|(_, tail)| tail.split_once("\n    if ($Mode -eq \"full\")"))
            .map(|(body, _)| body);
        let tcp01_diag = tcp_mode.and_then(|tcp| {
            let start = tcp.find("        $tcp01Target = $targets[0]")?;
            let row = "        $tcpRows++";
            let end = start + tcp[start..].find(row)? + row.len();
            Some(&tcp[start..end])
        });
        let cleanup = source.rsplit_once("\nfinally {").map(|(_, body)| body);
        source.contains(
            "[ValidateSet(\"lifecycle\", \"tcp\", \"udp\", \"cycles\", \"full\", \"performance\", \"cleanup\")]",
        )
            && source.contains("[Reflection.PortableExecutable.PEReader]::new($stream)")
            && source.contains("$exports = @(Get-PeExportNames $pe)")
            && !source.to_ascii_lowercase().contains("dumpbin.exe")
            && !source.to_ascii_lowercase().contains("vswhere")
            && pktmon_attribution.is_some_and(|pktmon| {
                pktmon.contains("C:\\Windows\\System32\\PktMon.exe")
                    && pktmon.contains("10.0.19041.906")
                    && pktmon.contains("[Diagnostics.ProcessStartInfo]::new()")
                    && pktmon.contains("$start.ArgumentList.Add($argument)")
                    && pktmon.contains("function Assert-PktMonAbsent")
                    && pktmon.contains("function Get-PktMonComponentId")
                    && pktmon.contains("$Record.PSObject.Properties[\"Properties\"]")
                    && pktmon.contains("$group.Components")
                    && pktmon.contains("$properties[\"ifIndex\"]")
                    && pktmon.contains("$properties[\"ifGuid\"]")
                    && pktmon.contains("if ($recordIndexMatches -and $recordGuidMatches) { $hasIdentityRecord = $true }")
                    && pktmon.contains("if ($hasIdentityRecord -and $hasDriver)")
                    && pktmon.contains("$Adapter.InterfaceGuid")
                    && pktmon.contains("$record.DriverName")
                    && pktmon.contains("$Adapter.DriverFileName")
                    && pktmon.contains("function Get-PktMonFlowPackets")
                    && pktmon.contains("@(\"counters\", \"--type\", \"flow\", \"--json\", \"--zero\")")
                    && pktmon.contains("$component.Counters")
                    && pktmon.contains("$counter.Type -ceq \"Flows\"")
                    && pktmon.contains("foreach ($direction in @(\"Inbound\", \"Outbound\"))")
                    && pktmon.contains("$edge.Value.Packets")
                    && pktmon.contains("$edge.Value.Bytes")
                    && pktmon.contains("function Wait-PktMonFlowPacketsAfter")
                    && pktmon.contains("$deadline = [DateTime]::UtcNow.AddSeconds(5)")
                    && pktmon.contains("$quiet.ElapsedMilliseconds -ge 500")
                    && pktmon.contains("Assert-True ($after -ge $last)")
                    && pktmon.contains("function Stop-CapabilityPktMon")
                    && pktmon.contains("$cleanupFailures.Add(\"stop\")")
                    && pktmon.contains("$cleanupFailures.Add(\"filters\")")
                    && pktmon.contains("$cleanupFailures.Add(\"reset\")")
                    && pktmon.contains("$cleanupFailures.Add(\"absence\")")
            })
            && !source.contains("Wait-TunAcceptedQuiescent")
            && source
                .matches("[void](Wait-TunAcceptedAfter $MetricsPort $before)")
                .count()
                == 2
            && source
                .matches("$filteredPackets = Wait-PktMonFlowPacketsAfter -Before $filteredBefore")
                .count()
                == 2
            && source
                .matches("$filteredPackets = Get-PktMonFlowPacketDelta -Before $filteredBefore")
                .count()
                == 2
            && source
                .matches("Assert-True ($filteredPackets -eq 0)")
                .count()
                == 2
            && source.contains("pktmon_filtered_flow_packets = $capabilityFilteredPackets")
            && source.matches("Stop-CapabilityPktMon").count() >= 3
            && source.matches("Assert-PktMonAbsent").count() >= 4
            && source.contains("@(\"start\", \"--capture\", \"--counters-only\", \"--comp\", [string]$pktmonComponentId, \"--type\", \"flow\")")
            && source.matches("Start-Sleep -Milliseconds 500").count() >= 2
            && source.contains("Assert-SnapshotEqual $routeBaseline @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex) \"partial route rollback\"")
            && capture_route_cleanup.is_some_and(|cleanup| {
                cleanup.contains("\"IPv4|0.0.0.0/1|0.0.0.0\"")
                    && cleanup.contains("\"IPv4|128.0.0.0/1|0.0.0.0\"")
                    && cleanup.contains("$limitedBroadcastRoute = \"IPv4|255.255.255.255/32|0.0.0.0\"")
                    && cleanup.contains("@($routeBaseline | Where-Object { $_ -ceq $limitedBroadcastRoute }).Count -eq 1")
                    && cleanup.contains("$routeCleanupBaseline = @($routeBaseline | Where-Object { $_ -cne $limitedBroadcastRoute })")
                    && cleanup.contains("$routeCleanupBaseline.Count -eq $routeBaseline.Count - 1")
                    && cleanup.contains("@($routesBeforeCaptureCleanup | Where-Object { $_ -ceq $captureRouteRow }).Count -eq 1")
                    && cleanup.contains("$routeCleanupDeadline = [DateTime]::UtcNow.AddSeconds(5)")
                    && cleanup.contains("Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup)")
                    && cleanup.contains("Start-Sleep -Milliseconds 50")
                    && cleanup.contains("} while ([DateTime]::UtcNow -lt $routeCleanupDeadline)")
                    && cleanup.contains("$routeCleanupDifference = @(Compare-Object -ReferenceObject @($routeCleanupBaseline) -DifferenceObject @($routesAfterCaptureCleanup))")
                    && cleanup.contains("if ($routeCleanupDifference.Count -gt 0)")
                    && cleanup.contains("Select-Object InputObject,SideIndicator")
                    && cleanup.contains("ConvertTo-Json -InputObject $routeCleanupDiagnostic -Compress")
                    && !cleanup.contains("$expectedRoutesAfterCaptureCleanup")
                    && !cleanup.contains("-cnotcontains")
                    && !cleanup.contains("-like")
                    && !cleanup.contains("-match")
                    && [
                        "$limitedBroadcastRoute = \"IPv4|255.255.255.255/32|0.0.0.0\"",
                        "$routeCleanupBaseline = @(",
                        "$captureRouteRows = @(",
                        "foreach ($captureRouteRow in $captureRouteRows)",
                        "Remove-CapabilityRoutes",
                        "$routeCleanupDeadline = [DateTime]::UtcNow.AddSeconds(5)",
                        "$routesAfterCaptureCleanup = @(Get-InterfaceRouteSnapshot $ownedInterfaceIndex)",
                        "if (@(Compare-Object -ReferenceObject @($routeCleanupBaseline)",
                        "Start-Sleep -Milliseconds 50",
                        "$routeCleanupDifference = @(Compare-Object",
                        "$routeCleanupLabel = \"capture route exact rollback\"",
                        "if ($routeCleanupDifference.Count -gt 0)",
                        "$routeCleanupDiagnostic = @(",
                        "$routeCleanupLabel += \" difference=",
                        "Assert-SnapshotEqual $routeCleanupBaseline $routesAfterCaptureCleanup $routeCleanupLabel",
                    ]
                    .iter()
                    .map(|needle| cleanup.find(needle))
                    .collect::<Option<Vec<_>>>()
                    .is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1]))
            })
            && source.contains("[void](Invoke-UnpinnedUdpCapture $supportAddress $supportUdpPort $metricsPort")
            && source.matches("$tcpRows++").count() == 8
            && source.matches("Add-TunRoute $").count() == 7
            && source.matches("Add-TargetAddress $").count() == 3
            && !source.contains("Remove-OwnedRoute")
            && source.contains("[void](Add-TunRoute $adapter.ifIndex \"192.0.2.200/32\")")
            && source.contains("[void](Add-TunRoute $adapter.ifIndex \"2001:db8::200/128\")")
            && source.contains("Invoke-EchoRow $tcp01Target $tcp01Port")
            && source.contains("Invoke-EchoRow $targets[1]")
            && source.contains("$ssl.AuthenticateAsClientAsync(\"tls.tun.test\")")
            && source.contains("HTTP prefix was not replayed exactly once")
            && source.contains("$dnsResponder.Requests -eq 2")
            && source.contains("[byte]($Id -band 0xff)")
            && source.contains("[byte]($id -band 0xff)")
            && source
                .matches("Assert-ResetWithoutEgress $targets[")
                .count()
                == 2
            && invoke_echo.is_some_and(|echo| {
                    echo.contains("[hashtable]$Observation = $null")
                        && echo.contains(
                        "$session = Open-TunTcp $Address $Port $InterfaceIndex\n    try {",
                    ) && echo
                        .find("$Gate.WaitAccepted($expectedGate, 5000)")
                        .zip(echo.find("$stream.Write($Payload, 0, $Payload.Length)"))
                        .zip(echo.find(
                            "$session.Client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)",
                        ))
                        .zip(echo.find("$probe = [Ferrum2TcpProbe]::new($Address, $Port, \"echo\")"))
                        .is_some_and(|(((accepted, write), shutdown), probe)| {
                            accepted < write && write < shutdown && shutdown < probe
                        })
                        && echo
                            .find("$Observation.Probe = $probe")
                            .zip(echo.find("$echo = Read-StreamToEnd $stream"))
                            .is_some_and(|(observation, read)| observation < read)
                        && echo
                            .find("$probe.WaitCompleted(5000)")
                            .zip(echo.find("$probe.SessionComplete -eq \"yes\" -and $probe.Fault -eq \"none\""))
                            .is_some_and(|(completed, status)| completed < status)
                        && echo.contains("$errorCursor.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset")
                        && echo.contains("$Observation.AppResult = $appResult")
                        && !echo.contains("Add-TargetAddress")
                        && echo.contains("finally { $session.Client.Dispose() }")
                })
            && source
                .split_once("$pressure = Open-TunTcp $targets[7]")
                .and_then(|(_, tail)| tail.split_once("$activeProcess = Start-Candidate $binary $config"))
                .is_some_and(|(pressure, _)| {
                    pressure
                        .find("$gateA.WaitAccepted($pressureGate, 5000)")
                        .zip(pressure.find("$pressureChunk = [byte[]]::new(1024 * 1024)"))
                        .zip(pressure.find("for ($attempt = 0; $attempt -lt 128; $attempt++)"))
                        .zip(pressure.find("$pressureWrite = $pressure.Client.GetStream().WriteAsync("))
                        .zip(pressure.find("if (-not $pressureWrite.Wait(100)) { break }"))
                        .zip(pressure.find("$pressureWrite -and -not $pressureWrite.IsCompleted"))
                        .zip(pressure.find("$stall = [Ferrum2TcpProbe]::new($targets[7]"))
                        .is_some_and(|((((((accepted, chunk), loop_start), write), pending), asserted), probe)| {
                            accepted < chunk
                                && chunk < loop_start
                                && loop_start < write
                                && write < pending
                                && pending < asserted
                                && asserted < probe
                        })
                        && !pressure.contains("Add-TargetAddress")
                })
            && open_tcp.is_some_and(|open| {
                open.contains("[Net.IPAddress]::Parse(\"198.18.0.2\")")
                    && open.contains("[Net.IPAddress]::Parse(\"fd00::2\")")
                    && open
                        .find("$client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))")
                        .zip(open.find("$connected = $client.ConnectAsync($Address, $Port)"))
                        .is_some_and(|(bound, connected)| bound < connected)
                    && open.contains("$localEndpoint.Address.Equals($sourceAddress)")
                    && !open.contains("Add-TunRoute")
            })
            && add_tun_route.is_some_and(|route| {
                route.contains("[int]$RouteMetric = 1")
                    && route
                    .find("Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue")
                    .zip(route.find("New-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex"))
                    .is_some_and(|(baseline, create)| baseline < create)
                    && route.contains("-RouteMetric $RouteMetric -PolicyStore ActiveStore")
                    && route.contains("controller route baseline not absent")
            })
            && tcp_mode.is_some_and(|tcp| {
                tcp.contains("        $ports[4] = 53")
                    && tcp.find("$strongHostInterfaces = @(Get-NetIPInterface -InterfaceIndex @($ownedInterfaceIndex, 1) -PolicyStore ActiveStore -ErrorAction Stop)")
                    .zip(tcp.find("$strongHostInterfaces.Count -eq 4"))
                    .zip(tcp.find("$_.WeakHostSend -ne \"Disabled\" -or $_.WeakHostReceive -ne \"Disabled\""))
                    .zip(tcp.find("foreach ($target in $targets) {"))
                    .zip(tcp.find("$prefixLength = if ($target.Contains(\":\")) { 128 } else { 32 }"))
                    .zip(tcp.find("[void](Add-TunRoute $ownedInterfaceIndex \"$target/$prefixLength\" 500)"))
                    .zip(tcp.find("foreach ($targetIndex in @(0, 1, 2, 3, 7)) {"))
                    .zip(tcp.find("[void](Add-TargetAddress $targets[$targetIndex])"))
                    .zip(tcp.find("Invoke-EchoRow $tcp01Target $tcp01Port"))
                    .is_some_and(|((((((((interfaces, count), strong), targets), prefix), route), local_targets), provision), first_flow)| {
                        interfaces < count
                            && count < strong
                            && strong < targets
                            && targets < prefix
                            && prefix < route
                            && route < local_targets
                            && local_targets < provision
                            && provision < first_flow
                    })
                    && tcp.contains(
                        "foreach ($target in $targets) {\n            $prefixLength = if ($target.Contains(\":\")) { 128 } else { 32 }\n            [void](Add-TunRoute $ownedInterfaceIndex \"$target/$prefixLength\" 500)\n        }",
                    )
                    && tcp.contains(
                        "foreach ($targetIndex in @(0, 1, 2, 3, 7)) {\n            [void](Add-TargetAddress $targets[$targetIndex])\n        }",
                    )
                    && !tcp.contains("Remove-NetRoute")
            })
            && gate.is_some_and(|gate| {
                let pump = gate
                    .split_once("private static async Task Pump(")
                    .and_then(|(_, tail)| tail.split_once("\n    public void Dispose()"))
                    .map(|(body, _)| body);
                gate.contains("ClientToServerBytes")
                    && gate.contains("ServerToClientBytes")
                    && gate.contains("ClientToServerStage")
                    && gate.contains("ServerToClientStage")
                    && gate.contains("ClientToServerEof")
                    && gate.contains("ServerToClientEof")
                    && gate.contains("ClientToServerFault")
                    && gate.contains("ServerToClientFault")
                    && gate.contains("SessionComplete")
                    && gate
                        .find("var clientStream = client.GetStream()")
                        .zip(gate.find("var upstreamStream = upstream.GetStream()"))
                        .zip(gate.find(
                            "Pump(clientStream, upstreamStream, upstream.Client, observation, true)",
                        ))
                        .zip(gate.find(
                            "Pump(upstreamStream, clientStream, client.Client, observation, false)",
                        ))
                        .is_some_and(
                            |(((client_stream, upstream_stream), forward), reverse)| {
                                client_stream < upstream_stream
                                    && upstream_stream < forward
                                    && upstream_stream < reverse
                            },
                        )
                    && gate.contains("observation.AddBytes(forward, count)")
                    && gate.contains("observation.MarkEof(forward)")
                    && gate.contains("observation.SetStage(true, \"source_stream\")")
                    && gate.contains("observation.SetStage(false, \"destination_stream\")")
                    && gate.contains("observation.SetStage(true, \"destination_stream\")")
                    && gate.contains("observation.SetStage(false, \"source_stream\")")
                    && gate
                        .find("observation.SetStage(true, \"source_stream\")")
                        .zip(gate.find(
                            "observation.SetStage(false, \"destination_stream\")",
                        ))
                        .zip(gate.find("var clientStream = client.GetStream()"))
                        .zip(gate.find(
                            "observation.SetStage(true, \"destination_stream\")",
                        ))
                        .zip(gate.find("observation.SetStage(false, \"source_stream\")"))
                        .zip(gate.find("var upstreamStream = upstream.GetStream()"))
                        .is_some_and(
                            |(((((forward_source, reverse_destination), client_stream), forward_destination), reverse_source), upstream_stream)| {
                                forward_source < reverse_destination
                                    && reverse_destination < client_stream
                                    && client_stream < forward_destination
                                    && forward_destination < reverse_source
                                    && reverse_source < upstream_stream
                            },
                        )
                    && gate.contains("observation.SetStage(forward, \"read\")")
                    && gate.contains("observation.SetStage(forward, \"write\")")
                    && gate.contains("observation.SetStage(forward, \"shutdown\")")
                    && gate.contains("observation.Fail(forward, \"io\")")
                    && gate.contains("observation.Fail(forward, \"disposed\")")
                    && gate.contains("observation.Fail(forward, \"socket\")")
                    && gate.contains("observation.Fail(forward, \"cancelled\")")
                    && gate.contains("observation.Fail(forward, \"invalid_operation\")")
                    && gate.contains("observation.Fail(forward, \"not_supported\")")
                    && gate.contains("observation.FailBoth(\"aggregate\")")
                    && gate.contains("observation.Fail(forward, \"other\")")
                    && gate.contains("finally { observation.Complete(); }")
                    && gate.contains("public bool WaitCompleted(int index, int milliseconds)")
                    && gate.contains("public Ferrum2TcpGateObservation Observation(int index)")
                    && !gate.contains("catch (IOException) { }")
                    && pump.is_some_and(|pump| {
                        gate.contains(
                            "private static async Task Pump(NetworkStream input, NetworkStream output, Socket destination",
                        ) && !pump.contains("GetStream()")
                            && pump
                                .find("observation.SetStage(forward, \"read\")")
                                .zip(pump.find("await input.ReadAsync"))
                                .is_some_and(|(stage, operation)| stage < operation)
                            && pump
                                .find("observation.SetStage(forward, \"write\")")
                                .zip(pump.find("await output.WriteAsync"))
                                .zip(pump.find("observation.AddBytes(forward, count)"))
                                .is_some_and(|((stage, operation), accounted)| {
                                    stage < operation && operation < accounted
                                })
                            && pump
                                .find("observation.SetStage(forward, \"shutdown\")")
                                .zip(pump.find("destination.Shutdown"))
                                .is_some_and(|(stage, operation)| stage < operation)
                    })
            })
            && probe.is_some_and(|probe| {
                probe.contains("public byte[] Received")
                    && probe.contains("public long EchoByteCount")
                    && probe.contains("public string ReadEof")
                    && probe.contains("public string SendShutdown")
                    && probe.contains("public string Fault")
                    && probe.contains("public string SessionComplete")
                    && probe.contains("Volatile.Write(ref readEof, 1)")
                    && probe.contains("Interlocked.Add(ref echoBytes, received.Length)")
                    && probe.contains("Interlocked.CompareExchange(ref fault, \"io\", null)")
                    && probe.contains("Interlocked.CompareExchange(ref fault, \"disposed\", null)")
                    && probe.contains("Interlocked.CompareExchange(ref fault, \"socket\", null)")
                    && probe.contains("Interlocked.CompareExchange(ref fault, \"cancelled\", null)")
                    && probe.contains("Interlocked.CompareExchange(ref fault, \"other\", null)")
                    && probe.contains("Volatile.Write(ref sessionComplete, 1)")
                    && !probe.contains("catch (IOException) { }")
            })
            && classifier.is_some_and(|classifier| {
                for boundary in [
                    "BEFORE_TARGET",
                    "TARGET_ECHO_INCOMPLETE",
                    "GATE_REVERSE_INCOMPLETE",
                    "CLIENT_AFTER_GATE_REVERSE",
                    "COMPLETE",
                    "UNRESOLVED",
                ] {
                    if !classifier.contains(boundary) {
                        return false;
                    }
                }
                classifier.contains("$gateFaults = @(\"none\", \"io\", \"disposed\", \"socket\", \"cancelled\", \"invalid_operation\", \"not_supported\", \"aggregate\", \"other\")")
                    && classifier.contains("$probeFaults = @(\"none\", \"io\", \"disposed\", \"socket\", \"cancelled\", \"other\")")
                    && classifier.contains("Get-Tcp01Boundary $state")
                    && classifier.contains("GateForwardFault = \"invalid\"")
                    && classifier.contains("GateReverseStage = \"invalid\"")
                    && classifier.contains("ProbeEcho = \"other\"")
                    && classifier.contains("GateReverseBytes = \"zero\"")
                    && classifier.contains("GateComplete = \"no\"")
                    && classifier.contains("ProbeComplete = \"no\"")
                    && classifier.contains("AppResult = \"reset\"")
                    && classifier.contains("TCP-01 boundary table mismatch")
                    && !classifier.contains("Get-Net")
                    && !classifier.contains("[Console]::")
            })
            && tcp01_diag.is_some_and(|diag| {
                let diagnostic = diag
                    .lines()
                    .find(|line| line.contains("$tcp01Diagnostic = \"status=OBSERVED"));
                diag.contains("$tcp01Target = $targets[0]")
                    && diag.contains("$tcp01Port = $ports[0]")
                    && !diag.contains("192.0.2.200")
                    && diag.contains("Invoke-EchoRow $tcp01Target $tcp01Port $ownedInterfaceIndex $gateA $tcp01Payload $tcp01Observation")
                    && diag.contains("$gateSettled = $false")
                    && diag.contains("$gateSettled = $tcp01Observation.Gate.WaitCompleted")
                    && diag.contains("$probeSettled = $false")
                    && diag.contains("$probeSettled = $tcp01Observation.Probe.WaitCompleted")
                    && diag.contains("$tcp01Observation.Gate.Observation")
                    && diag.contains("$probe.Received")
                    && diag.contains("$probe.EchoByteCount")
                    && diag.contains("GateForwardStage = if ($gateObservation) { $gateObservation.ClientToServerStage } else { \"pending\" }")
                    && diag.contains("GateReverseStage = if ($gateObservation) { $gateObservation.ServerToClientStage } else { \"pending\" }")
                    && diag.contains("GateComplete = if ($gateSettled -and $gateObservation -and $gateObservation.SessionComplete -eq \"yes\")")
                    && diag.contains("ProbeComplete = if ($probeSettled -and $probe -and $probe.SessionComplete -eq \"yes\")")
                    && diag.contains("$tcp01Boundary = Get-Tcp01Boundary $tcp01State")
                    && diag.contains("if ($tcp01Error -or $tcp01Boundary -ne \"COMPLETE\") {")
                    && diag.contains("$tcp01Diagnostic = \"status=OBSERVED boundary=$tcp01Boundary app=$($tcp01State.AppResult)")
                    && diag.contains("gate_c2s_stage=$($tcp01State.GateForwardStage)")
                    && diag.contains("gate_s2c_stage=$($tcp01State.GateReverseStage)")
                    && diag.contains("Assert-True ($tcp01Boundary -eq \"COMPLETE\") \"TCP-01 observation incomplete\"")
                    && !diag.contains("TCP-01 diagnostic sentinel")
                    && diagnostic.is_some_and(|line| {
                        !line.contains("tcp01Target")
                            && !line.contains("tcp01Port")
                            && !line.contains("Exception")
                            && !line.contains("Error")
                            && !line.contains("Received")
                    })
                    && diag
                        .find("Invoke-EchoRow $tcp01Target")
                        .zip(diag.find("$gateSettled = $tcp01Observation.Gate.WaitCompleted"))
                        .zip(diag.find("$probeSettled = $tcp01Observation.Probe.WaitCompleted"))
                        .zip(diag.find("$gateObservation = if ($tcp01Observation.Gate)"))
                        .zip(diag.find("$tcp01State = @{"))
                        .is_some_and(|((((invoke, gate_settle), probe_settle), snapshot), state)| {
                            invoke < gate_settle
                                && gate_settle < probe_settle
                                && probe_settle < snapshot
                                && snapshot < state
                        })
                    && diag
                        .find("$tcp01State = @{")
                        .zip(diag.find("if ($tcp01Error -or $tcp01Boundary -ne \"COMPLETE\")"))
                        .zip(diag.find("$tcp01Diagnostic = \"status=OBSERVED"))
                        .zip(diag.find("if ($tcp01Error) { throw $tcp01Error }"))
                        .zip(diag.find("Assert-True ($tcp01Boundary -eq \"COMPLETE\")"))
                        .zip(diag.find("$tcpRows++"))
                        .is_some_and(|(((((state, condition), diagnostic), primary), complete), row)| {
                            state < condition
                                && condition < diagnostic
                                && diagnostic < primary
                                && primary < complete
                                && complete < row
                        })
            })
            && cleanup.is_some_and(|cleanup| {
                cleanup
                    .contains(
                    "foreach ($route in $ownedRoutes) {\n        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue\n    }",
                ) && cleanup.contains(
                    "Get-NetRoute -DestinationPrefix $route.DestinationPrefix -PolicyStore ActiveStore",
                ) && cleanup.contains("$_.InterfaceIndex -eq $route.InterfaceIndex")
                    && cleanup.contains(
                        "controller-owned route leaked: $($route.DestinationPrefix)",
                    )
                    && cleanup.contains(
                        "$tcp01Cleanup = if ($outerCleanupError) { \"FAIL\" } else { \"PASS\" }",
                    )
                    && cleanup
                        .find("Assert-True (-not (Test-Path -LiteralPath $work))")
                        .zip(cleanup.find("if ($tcp01Diagnostic)"))
                        .zip(cleanup.find("[Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup"))
                        .zip(cleanup.find("if ($outerCleanupError -and -not $primaryError)"))
                        .zip(cleanup.find("if ($primaryError) { throw $primaryError }"))
                        .is_some_and(|((((cleaned, diagnostic), marker), cleanup_error), primary)| {
                            cleaned < diagnostic
                                && diagnostic < marker
                                && marker < cleanup_error
                                && cleanup_error < primary
                        })
            })
            && source.contains("-not [Ferrum2ProcessGroup]::Wait([uint32]$activeProcess.Id, 300)")
            && !source.contains("Wait-ProcessExit $activeProcess 300")
            && source.contains("[bool]$SkipAsSource = $true")
            && source.contains("New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore ActiveStore")
            && !source.contains("New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore PersistentStore")
            && source
                .find("$localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue")
                .zip(source.find("$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru"))
                .is_some_and(|(selected, updated)| selected < updated)
            && !source.contains("Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PolicyStore")
            && source.contains("-not $pressureWrite.IsCompleted")
            && source.contains("$forcedShutdown.ElapsedMilliseconds -ge 900")
            && source.contains("TCP-08 forced cancellation did not exit")
            && source.contains("$forcedExit -eq 0")
            && source.contains("Wait-AdapterAbsent $adapterName")
            && source.contains("profile=tcp tcp=8/8 cleanup=PASS")
            && source
                .find("m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup")
                .zip(source.find("m15_windows_tun_e2e status=PASS profile=tcp"))
                .is_some_and(|(diagnostic, pass)| diagnostic < pass)
            && source.contains("$ownedTargetRoutes")
            && source.find("finally {").is_some_and(|finally| {
                source
                    .find("Write-Output \"m15_windows_tun_e2e")
                    .is_some_and(|marker| marker > finally)
            })
    };
    assert!(
        has_tcp_controller(&controller),
        "privileged TCP controller must retain all eight real-process rows and cleanup"
    );
    for (index, mutation) in [
        controller.replacen("$tcpRows++", "", 1),
        controller.replace("$dnsResponder.Requests -eq 2", "$true"),
        controller.replace("[byte]($Id -band 0xff)", "[byte]$Id"),
        controller.replace("[byte]($id -band 0xff)", "[byte]$id"),
        controller.replace("$ports[4] = 53", "$ports[4] = 54"),
        controller.replace("$attempt -lt 128", "$attempt -lt 1"),
        controller.replace("if (-not $pressureWrite.Wait(100)) { break }", "if ($false) { break }"),
        controller.replace(
            "$client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))",
            "",
        ),
        controller.replace(
            "    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))\n    $connected = $client.ConnectAsync($Address, $Port)",
            "    $connected = $client.ConnectAsync($Address, $Port)\n    $client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))",
        ),
        controller.replace(
            "    $client = [Net.Sockets.TcpClient]::new($family)",
            "    $route = Add-TunRoute $InterfaceIndex $Address\n    $client = [Net.Sockets.TcpClient]::new($family)",
        ),
        controller.replace(
            "    Assert-True (@(Get-NetRoute -InterfaceIndex $InterfaceIndex -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0) \"controller route baseline not absent\"\n",
            "",
        ),
        controller.replace(
            "        Invoke-EchoRow $tcp01Target $tcp01Port",
            "        Remove-NetRoute -InputObject $ownedRoutes[0] -Confirm:$false\n        Invoke-EchoRow $tcp01Target $tcp01Port",
        ),
        controller.replace(
            "        foreach ($targetIndex in @(0, 1, 2, 3, 7)) {\n            [void](Add-TargetAddress $targets[$targetIndex])\n        }",
            "",
        ),
        controller.replace(
            "        Assert-True ($Gate.WaitAccepted($expectedGate, 5000))",
            "        [void](Add-TargetAddress $Address)\n        Assert-True ($Gate.WaitAccepted($expectedGate, 5000))",
        ),
        controller.replace(
            "@(0, 1, 2, 3, 7)",
            "@(0, 1, 2, 3, 6)",
        ),
        controller.replace("foreach ($target in $targets) {", "foreach ($target in $targets[0..6]) {"),
        controller.replace(
            "$prefixLength = if ($target.Contains(\":\")) { 128 } else { 32 }",
            "$prefixLength = 32",
        ),
        controller.replace(
            "[void](Add-TunRoute $ownedInterfaceIndex \"$target/$prefixLength\" 500)",
            "[void](Add-TunRoute $ownedInterfaceIndex \"$target/24\" 500)",
        ),
        controller.replace(
            "[void](Add-TunRoute $ownedInterfaceIndex \"$target/$prefixLength\" 500)",
            "[void](Add-TunRoute $ownedInterfaceIndex \"$target/$prefixLength\" 1)",
        ),
        controller.replace(
            "-RouteMetric $RouteMetric -PolicyStore ActiveStore",
            "-RouteMetric 1 -PolicyStore ActiveStore",
        ),
        controller.replace(
            "[void](Add-TunRoute $adapter.ifIndex \"192.0.2.200/32\")",
            "",
        ),
        controller.replace(
            "$_.WeakHostSend -ne \"Disabled\" -or $_.WeakHostReceive -ne \"Disabled\"",
            "$false",
        ),
        controller.replace(
            "foreach ($route in $ownedRoutes) {\n        Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue\n    }",
            "",
        ),
        controller.replace(
            "controller-owned route leaked: $($route.DestinationPrefix)",
            "controller route cleanup skipped",
        ),
        controller.replace(
            "-not [Ferrum2ProcessGroup]::Wait([uint32]$activeProcess.Id, 300)",
            "$true",
        ),
        controller.replace(
            "Assert-True (-not $pressureWrite.IsCompleted)",
            "Wait-ProcessExit $activeProcess 300\nAssert-True (-not $pressureWrite.IsCompleted)",
        ),
        controller.replace(
            "New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore ActiveStore",
            "New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource",
        ),
        controller.replace(
            "Assert-True (-not $pressureWrite.IsCompleted)",
            "New-NetIPAddress -InterfaceIndex 1 -IPAddress $Address -PrefixLength $prefix -SkipAsSource $SkipAsSource -PolicyStore PersistentStore\nAssert-True (-not $pressureWrite.IsCompleted)",
        ),
        controller.replace(
            "$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru",
            "$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PolicyStore ActiveStore -PassThru",
        ),
        controller.replace(
            "$localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
            "$localRoute = Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefixText -ErrorAction SilentlyContinue",
        ),
        controller.replace(
            "$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru",
            "$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PolicyStore PersistentStore -PassThru\n$localRoute = Set-NetRoute -InputObject $localRoute -RouteMetric 1 -PassThru",
        ),
        controller.replace("-not $pressureWrite.IsCompleted", "$true"),
        controller.replace("$forcedShutdown.ElapsedMilliseconds -ge 900", "$true"),
        controller.replace("TCP-08 forced cancellation did not exit", "TCP-08 exited"),
        controller.replace("profile=tcp tcp=8/8 cleanup=PASS", "profile=tcp"),
        controller.replace(
            "$tcp01Target = $targets[0]",
            "$tcp01Target = \"192.0.2.200\"",
        ),
        controller.replace(
            "                var upstreamStream = upstream.GetStream();\n                var first = Pump(clientStream, upstreamStream, upstream.Client, observation, true);",
            "                var first = Pump(clientStream, upstreamStream, upstream.Client, observation, true);\n                var upstreamStream = upstream.GetStream();",
        ),
        controller.replace(
            "                observation.AddBytes(forward, count);",
            "",
        ),
        controller.replace(
            "if (count == 0) { observation.MarkEof(forward); break; }",
            "if (count == 0) { break; }",
        ),
        controller.replace(
            "catch (IOException) { observation.Fail(forward, \"io\"); }",
            "catch (IOException) { }",
        ),
        controller.replace(
            "finally { observation.Complete(); }",
            "finally { }",
        ),
        controller.replace(
            "observation.SetStage(true, \"destination_stream\");",
            "",
        ),
        controller.replace(
            "                observation.SetStage(forward, \"write\");\n                await output.WriteAsync(buffer, 0, count).ConfigureAwait(false);",
            "                await output.WriteAsync(buffer, 0, count).ConfigureAwait(false);\n                observation.SetStage(forward, \"write\");",
        ),
        controller.replace(
            "                observation.SetStage(true, \"source_stream\");\n                observation.SetStage(false, \"destination_stream\");\n                var clientStream = client.GetStream();",
            "                observation.SetStage(false, \"destination_stream\");\n                observation.SetStage(true, \"source_stream\");\n                var clientStream = client.GetStream();",
        ),
        controller.replace(
            "            observation.SetStage(forward, \"shutdown\");\n            try { destination.Shutdown(SocketShutdown.Send); }",
            "            try { destination.Shutdown(SocketShutdown.Send); }\n            observation.SetStage(forward, \"shutdown\");",
        ),
        controller.replace(
            "catch (InvalidOperationException) { observation.Fail(forward, \"invalid_operation\"); }",
            "catch (InvalidOperationException) { observation.Fail(forward, \"other\"); }",
        ),
        controller.replace(
            "catch (NotSupportedException) { observation.Fail(forward, \"not_supported\"); }",
            "catch (NotSupportedException) { observation.Fail(forward, \"other\"); }",
        ),
        controller.replace(
            "catch (AggregateException) { observation.FailBoth(\"aggregate\"); }",
            "catch (AggregateException) { observation.FailBoth(\"other\"); }",
        ),
        controller.replace(
            "if (count == 0) { Volatile.Write(ref readEof, 1); break; }",
            "if (count == 0) { break; }",
        ),
        controller.replace(
            "Interlocked.Add(ref echoBytes, received.Length);",
            "",
        ),
        controller.replace(
            "catch (IOException) { Interlocked.CompareExchange(ref fault, \"io\", null); }",
            "catch (IOException) { }",
        ),
        controller.replace(
            "Volatile.Write(ref sessionComplete, 1);",
            "",
        ),
        controller.replace(
            "if ($null -ne $Observation) { $Observation.Probe = $probe }",
            "",
        ),
        controller.replace(
            "        if ($null -ne $Observation) { $Observation.Probe = $probe }\n        $Gate.Release($expectedGate)",
            "        $Gate.Release($expectedGate)",
        ).replace(
            "        $echo = Read-StreamToEnd $stream",
            "        $echo = Read-StreamToEnd $stream\n        if ($null -ne $Observation) { $Observation.Probe = $probe }",
        ),
        controller.replace(
            "Assert-True ($probe.SessionComplete -eq \"yes\" -and $probe.Fault -eq \"none\" -and",
            "Assert-True ($true -and",
        ),
        controller.replace(
            "$Observation.AppResult = $appResult",
            "$Observation.AppResult = \"success\"",
        ),
        controller.replace(
            "Assert-True ((Get-Tcp01Boundary $state) -eq $row.Expected)",
            "Assert-True (\"COMPLETE\" -eq $row.Expected)",
        ),
        controller.replace(
            "$tcp01Boundary = Get-Tcp01Boundary $tcp01State",
            "$tcp01Boundary = \"COMPLETE\"",
        ),
        controller.replace(
            "@{ Change = @{ GateReverseStage = \"invalid\" }; Expected = \"UNRESOLVED\" }",
            "@{ Change = @{ GateReverseStage = \"read\" }; Expected = \"UNRESOLVED\" }",
        ),
        controller.replace(
            "$probeFaults = @(\"none\", \"io\", \"disposed\", \"socket\", \"cancelled\", \"other\")",
            "$probeFaults = @(\"none\", \"io\", \"disposed\", \"socket\", \"cancelled\", \"aggregate\", \"other\")",
        ),
        controller.replace(
            "@{ Change = @{ ProbeEcho = \"other\" }; Expected = \"TARGET_ECHO_INCOMPLETE\" }",
            "@{ Change = @{ ProbeEcho = \"exact\" }; Expected = \"TARGET_ECHO_INCOMPLETE\" }",
        ),
        controller.replace(
            "$tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)",
            "$true",
        ),
        controller.replace(
            "$gateSettled = $tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)",
            "[void]$tcp01Observation.Gate.WaitCompleted([int]$tcp01Observation.GateIndex, 1500)",
        ),
        controller.replace(
            "$tcp01Observation.Probe.WaitCompleted(1500)",
            "$true",
        ),
        controller.replace(
            "$probeSettled = $tcp01Observation.Probe.WaitCompleted(1500)",
            "[void]$tcp01Observation.Probe.WaitCompleted(1500)",
        ),
        controller.replace(
            "GateComplete = if ($gateSettled -and $gateObservation -and $gateObservation.SessionComplete -eq \"yes\")",
            "GateComplete = if ($gateObservation -and $gateObservation.SessionComplete -eq \"yes\")",
        ),
        controller.replace(
            "ProbeComplete = if ($probeSettled -and $probe -and $probe.SessionComplete -eq \"yes\")",
            "ProbeComplete = if ($probe -and $probe.SessionComplete -eq \"yes\")",
        ),
        controller.replace(
            "@{ Change = @{ GateComplete = \"no\" }; Expected = \"GATE_REVERSE_INCOMPLETE\" }",
            "@{ Change = @{ GateComplete = \"yes\" }; Expected = \"GATE_REVERSE_INCOMPLETE\" }",
        ),
        controller.replace(
            "@{ Change = @{ ProbeComplete = \"no\" }; Expected = \"TARGET_ECHO_INCOMPLETE\" }",
            "@{ Change = @{ ProbeComplete = \"yes\" }; Expected = \"TARGET_ECHO_INCOMPLETE\" }",
        ),
        controller.replace(
            "GateReverseStage = if ($gateObservation) { $gateObservation.ServerToClientStage } else { \"pending\" }",
            "GateReverseStage = \"pending\"",
        ),
        controller.replace(
            "$tcp01Diagnostic = \"status=OBSERVED boundary=$tcp01Boundary",
            "$tcp01Diagnostic = \"status=OBSERVED target=$tcp01Target boundary=$tcp01Boundary",
        ),
        controller.replace(
            "gate_s2c_stage=$($tcp01State.GateReverseStage)",
            "gate_s2c_stage=$($tcp01Error.Exception.Message)",
        ),
        controller.replace(
            "if ($tcp01Error -or $tcp01Boundary -ne \"COMPLETE\") {",
            "if ($true) {",
        ),
        controller.replace(
            "Assert-True ($tcp01Boundary -eq \"COMPLETE\") \"TCP-01 observation incomplete\"",
            "",
        ),
        controller.replace(
            "        Assert-True ($tcp01Boundary -eq \"COMPLETE\") \"TCP-01 observation incomplete\"\n        $tcpRows++",
            "        $tcpRows++\n        Assert-True ($tcp01Boundary -eq \"COMPLETE\") \"TCP-01 observation incomplete\"",
        ),
        controller.replace(
            "[Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup",
            "Write-Output (\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup",
        ),
        controller.replace(
            "$tcp01Cleanup = if ($outerCleanupError) { \"FAIL\" } else { \"PASS\" }",
            "$tcp01Cleanup = \"PASS\"",
        ),
        controller
            .replace(
                "    [Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt\")\n",
                "",
            )
            .replace(
                "    Assert-True (-not (Test-Path -LiteralPath $work)) \"controller work directory leaked\"",
                "    [Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt\")\n    Assert-True (-not (Test-Path -LiteralPath $work)) \"controller work directory leaked\"",
            ),
        controller.replace(
            "    [Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt\")\n}\nif ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }\nif ($primaryError) { throw $primaryError }",
            "}\nif ($outerCleanupError -and -not $primaryError) { $primaryError = $outerCleanupError }\nif ($primaryError) { throw $primaryError }\n[Console]::Error.WriteLine(\"m15_windows_tun_tcp01_diag $tcp01Diagnostic cleanup=$tcp01Cleanup sha=$tcp01Sha run_id=$tcp01RunId run_attempt=$tcp01RunAttempt\")",
        ),
        controller.replace(
            "$tcp01Diagnostic = \"status=OBSERVED boundary=$tcp01Boundary",
            "$tcp01Diagnostic = \"status=OBSERVED pktmon=present boundary=$tcp01Boundary",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            !has_tcp_controller(&mutation),
            "TCP controller mutation {index} must remove the eight-row production proof"
        );
    }

    let has_udp_controller = |source: &str| {
        let gate = source
            .split_once("public sealed class Ferrum2UdpGate")
            .and_then(|(_, tail)| tail.split_once("public sealed class Ferrum2UdpProbe"))
            .map(|(body, _)| body);
        let probe = source
            .split_once("public sealed class Ferrum2UdpProbe")
            .and_then(|(_, tail)| tail.split_once("public sealed class Ferrum2DnsResponder"))
            .map(|(body, _)| body);
        let rows = source
            .split_once("        # UDP-01")
            .and_then(|(_, tail)| tail.split_once("        Assert-True ($udpRows -eq 8)"))
            .map(|(body, _)| body);
        let target_address = source
            .split_once("function Add-TargetAddress(")
            .and_then(|(_, tail)| tail.split_once("Add-Type -TypeDefinition"))
            .map(|(body, _)| body);
        source.contains(
            "[ValidateSet(\"lifecycle\", \"tcp\", \"udp\", \"cycles\", \"full\", \"performance\", \"cleanup\")]",
        )
            && source.matches("$udpRows++").count() == 8
            && !source.contains("FERRUM2_T05_")
            && !source.contains("m15_udp_")
            && !source.contains("DiagnosticOnly")
            && !source.contains("Assert-UdpGateCrossProcess")
            && source.contains("function Open-TunUdp(")
            && source.contains("$client.Client.Bind([Net.IPEndPoint]::new($sourceAddress, 0))")
            && source.contains("function Invoke-UdpEchoRow(")
            && source.contains("max_udp_mappings = 4")
            && source.contains("max_udp_buffered_bytes = 4194304")
            && source.contains("[udp]\nenabled = false\nmax_sessions = 32\nmax_buffered_bytes = 4194304\nidle_timeout_ms = 60000")
            && source.contains("tag = \"udp-two-hop\"")
            && source.contains("tag = \"udp-manual\"")
            && source.contains("tag = \"udp-one\"")
            && source.contains("server = \"${udpGateAddress}:$gatePortA\"")
            && source.contains("server = \"${udpGateAddress}:$gatePortB\"")
            && source.contains("hops = [\"udp-one\", \"udp-inner\"]")
            && source.contains("outbounds = [\"udp-one\", \"udp-inner\"]")
            && source.contains("default = \"udp-one\"")
            && source.matches("outbound = \"udp-one\"").count() == 3
            && source.contains(
                "protocol = \"dns\"\naction = \"route\"\noutbound = \"udp-two-hop\"\n[[route.rules]]\ninbound = \"tun-in\"\nnetwork = \"udp\"\nip = \"$($targets[3])\"\nport = $($ports[3])\naction = \"route\"\noutbound = \"udp-one\"",
            )
            && source.contains("network = \"udp\"")
            && source.contains("action = \"hijack-dns\"")
            && source.contains("profile=transport functional=16/16 cleanup=PASS")
            && gate.is_some_and(|gate| {
                gate.contains(
                    "public Ferrum2UdpGate(string listenAddress, int listenPort, int upstreamPort)",
                ) && gate.contains(
                    "new UdpClient(new IPEndPoint(IPAddress.Parse(listenAddress), listenPort))",
                ) && !gate.contains("new UdpClient(new IPEndPoint(IPAddress.Loopback, listenPort))")
                    && gate.contains("new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))")
                    && gate.contains("await upstream.ReceiveAsync()")
                    && gate.contains("ReplayFirstToLatest")
            })
            && target_address.is_some_and(|target| {
                target.contains("[bool]$SkipAsSource = $true")
                    && target.contains("-SkipAsSource $SkipAsSource -PolicyStore ActiveStore")
            })
            && source
                .find("$udpGateAddress = \"192.0.2.250\"")
                .zip(source.find("[void](Add-TargetAddress $udpGateAddress $false)"))
                .zip(source.find(
                    "$udpGateA = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortA, $serverPortA)",
                ))
                .zip(source.find(
                    "$udpGateB = [Ferrum2UdpGate]::new($udpGateAddress, $gatePortB, $serverPortB)",
                ))
                .is_some_and(|(((declared, address), gate_a), gate_b)| {
                    declared < address && address < gate_a && gate_a < gate_b
                })
            && probe.is_some_and(|probe| {
                probe.contains("new UdpClient(new IPEndPoint(IPAddress.Parse(address), port))")
                    && probe.contains("await socket.ReceiveAsync()")
                    && probe.contains("await socket.SendAsync(request.Buffer")
            })
            && rows.is_some_and(|rows| {
                for id in 2..=8 {
                    if !rows.contains(&format!("# UDP-{id:02}")) {
                        return false;
                    }
                }
                rows.contains("$udpGateB.Requests -eq $beforeGateB + 1")
                && rows.contains("Start-Sleep -Milliseconds 60500")
                && rows.contains("$dnsResponder.Requests -eq $beforeDns + 1")
                && rows.contains(
                    "$udpGateA.Requests -eq $beforeGateA -and $udpGateB.Requests -eq $beforeGateB",
                )
                && rows.contains("[byte[]]::new(2000)")
                && rows.contains("$saturatedClients.Count -eq 4")
                && rows.contains("$udpGateA.ReplayFirstToLatest()")
                && rows.contains(
                    "Start-Sleep -Milliseconds 60500\n                [void]$overflowClient.Send($overflow, $overflow.Length)\n                Assert-True ($overflowResponse.Wait(5000)) \"UDP-08 expired response timeout\"\n                if ($overflowResponse.IsFaulted) { throw \"UDP-08 expired response failed\" }\n                Assert-True (($overflowResponse.Result.Buffer -join \",\") -eq ($overflow -join \",\")) \"UDP-08 expired slot was not reusable\"\n                Assert-True ($udpGateA.ReplayFirstToLatest()) \"UDP-08 stale response replay was unavailable\"\n                $staleResponse = $overflowClient.ReceiveAsync()",
                )
            })
    };
    assert!(
        has_udp_controller(&controller),
        "privileged UDP controller must retain all eight real-process rows and cleanup"
    );
    for mutation in [
        controller.replacen("$udpRows++", "", 1),
        controller.replace(
            "await upstream.ReceiveAsync()",
            "await socket.ReceiveAsync()",
        ),
        controller.replace(
            "$udpGateAddress = \"192.0.2.250\"",
            "$udpGateAddress = \"127.0.0.1\"",
        ),
        controller.replace(
            "[void](Add-TargetAddress $udpGateAddress $false)",
            "[void](Add-TargetAddress $udpGateAddress $true)",
        ),
        controller.replace(
            "IPAddress.Parse(listenAddress), listenPort",
            "IPAddress.Loopback, listenPort",
        ),
        controller.replace(
            "server = \"${udpGateAddress}:$gatePortA\"",
            "server = \"127.0.0.1:$gatePortA\"",
        ),
        controller.replace("outbound = \"udp-one\"", "outbound = \"one\""),
        controller.replace(
            "[[route.rules]]\ninbound = \"tun-in\"\nnetwork = \"udp\"\nip = \"$($targets[3])\"\nport = $($ports[3])\naction = \"route\"\noutbound = \"udp-one\"",
            "",
        ),
        controller.replace("$udpGateA.ReplayFirstToLatest()", ""),
        controller.replace(
            "$overflowResponse.Result.Buffer",
            "(Receive-TunUdp $overflowClient)",
        ),
        controller.replace(
            "Start-Sleep -Milliseconds 60500",
            "Start-Sleep -Milliseconds 1",
        ),
        controller.replace(
            "profile=transport functional=16/16 cleanup=PASS",
            "profile=transport functional=8/8 cleanup=PASS",
        ),
    ] {
        assert!(
            !has_udp_controller(&mutation),
            "UDP controller mutation must remove the sixteen-row transport proof"
        );
    }

    let has_integrated_controller_profiles = |source: &str| {
        let cycles = source
            .split_once("function Invoke-AdapterCycles(")
            .and_then(|(_, tail)| tail.split_once("\ntry {"))
            .map(|(body, _)| body);
        let completion = source
            .rsplit_once("\nif ($completed) {")
            .map(|(_, body)| body);
        source.contains(
            "[ValidateSet(\"lifecycle\", \"tcp\", \"udp\", \"cycles\", \"full\", \"performance\", \"network-feasibility\", \"managed-product\", \"hard-kill\", \"cleanup\")]",
        ) && source.matches("Get-FileHash -LiteralPath $zip -Algorithm SHA256").count() == 1
            && source.contains("if ($Mode -eq \"cleanup\")")
            && source.contains("ferrum2-m15-tun-$runIdentity")
            && source.contains("Ferrum2-M15-$runIdentity")
            && source.contains("Get-ExactRunProcesses $work")
            && source.contains("$executables -contains $_.ExecutablePath")
            && source.contains("$_.CommandLine.IndexOf($WorkPath, [StringComparison]::OrdinalIgnoreCase)")
            && source.contains("$addressJournal")
            && source.contains("$dllJournal")
            && source.contains("run work baseline not absent")
            && source.contains(
                "Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) \"run process baseline not absent\"",
            )
            && source.contains("run adapter baseline not absent")
            && !source.contains("Ferrum2-M15-*")
            && !source.contains("ferrum2-m15-tun-*")
            && !source.contains("Get-Process -Name ferrum2-client")
            && source.contains("if ($Mode -in @(\"lifecycle\", \"full\"))")
            && source.contains("if ($Mode -in @(\"tcp\", \"udp\", \"full\", \"performance\"))")
            && source.contains("if ($Mode -in @(\"udp\", \"full\", \"performance\"))")
            && source.contains(
                "Assert-True ($foundation -eq 4 -and $tcpRows -eq 8 -and $udpRows -eq 8) \"full profile prerequisite count mismatch\"",
            )
            && source.contains("Invoke-AdapterCycles $binary $config")
            && !source.contains("$PSCommandPath")
            && cycles.is_some_and(|cycles| {
                cycles.contains("for ($cycle = 0; $cycle -lt 100; $cycle++)")
                    && cycles
                        .find("$candidateBaseline = @(Get-ExactRunProcesses $script:work")
                        .zip(cycles.find("$script:activeProcess = Start-Candidate"))
                        .is_some_and(|(baseline, start)| baseline < start)
                    && cycles
                        .find("Assert-True $cycleProcess.HasExited")
                        .zip(cycles.find("$candidateAfterStop = @(Get-ExactRunProcesses $script:work"))
                        .zip(cycles.find("Wait-AdapterAbsent $ExpectedAdapter"))
                        .is_some_and(|((stopped, process_absent), adapter_absent)| {
                            stopped < process_absent && process_absent < adapter_absent
                        })
                    && cycles
                        .find("$cycleRoute = Add-TunRoute $script:ownedInterfaceIndex \"192.0.2.200/32\"")
                        .zip(cycles.find("$cycleRouteReadback = @(Get-NetRoute"))
                        .zip(cycles.find("Remove-NetRoute -InputObject $cycleRoute"))
                        .zip(cycles.find("\"cycle route leaked\""))
                        .zip(cycles.find("Stop-Candidate $cycleProcess"))
                        .zip(cycles.find("Assert-True $cycleProcess.HasExited"))
                        .zip(cycles.find("Wait-AdapterAbsent $ExpectedAdapter"))
                        .zip(cycles.find(
                            "Assert-InterfaceGone $ExpectedAdapter $script:ownedInterfaceIndex",
                        ))
                        .zip(cycles.find("$script:cycleRows++"))
                        .is_some_and(|((((((((created, readback), removed), route_absent), stop), process), absent), interface), counted)| {
                            created < readback
                                && readback < removed
                                && removed < route_absent
                                && route_absent < stop
                                && stop < process
                                && process < absent
                                && absent < interface
                                && interface < counted
                        })
                    && cycles.contains(
                        "Assert-True ($script:cycleRows -eq 100) \"adapter cycle count mismatch\"",
                    )
            })
            && source.contains("if ($Mode -in @(\"udp\", \"full\", \"performance\"))")
            && source.contains("Get-NetAdapterStatistics -Name $Name")
            && source.contains("TotalProcessorTime.TotalMilliseconds")
            && source.contains("WorkingSet64")
            && source.contains("HandleCount")
            && source.contains("Threads.Count")
            && source.contains("ferrum2_udp_sessions_active")
            && source.contains("ferrum2_udp_buffered_bytes")
            && source.contains("ReceivedBytes")
            && source.contains("SentBytes")
            && source.contains("ReceivedUnicastPackets")
            && source.contains("SentUnicastPackets")
            && source.contains("ReceivedPacketErrors")
            && source.contains("OutboundPacketErrors")
            && source.contains("ReceivedDiscardedPackets")
            && source.contains("OutboundDiscardedPackets")
            && source.contains("adapter_rx_bytes=$performanceAdapterRxBytes")
            && source.contains("adapter_tx_bytes=$performanceAdapterTxBytes")
            && source.contains("adapter_rx_packets=$performanceAdapterRxPackets")
            && source.contains("adapter_tx_packets=$performanceAdapterTxPackets")
            && source.contains("adapter_rx_errors=$performanceAdapterRxErrors")
            && source.contains("adapter_tx_errors=$performanceAdapterTxErrors")
            && source.contains("adapter_rx_discards=$performanceAdapterRxDiscards")
            && source.contains("adapter_tx_discards=$performanceAdapterTxDiscards")
            && source.contains("tun_accepted_delta=$performanceTunAcceptedDelta")
            && source.contains("cpu_ms_delta=$performanceCpuMilliseconds")
            && source.contains("rss_bytes=$performanceRssBytes")
            && source.contains("handles_peak=$performanceHandlesPeak")
            && source.contains("threads_peak=$performanceThreadsPeak")
            && source.contains("udp_sessions_peak=$performanceUdpSessionsPeak")
            && source.contains("udp_buffered_bytes_peak=$performanceUdpBufferedBytesPeak")
            && source.contains("controller_inflight_peak=$performanceControllerInflightPeak")
            && source.contains("queues=bounded bounds_ring_bytes=8388608 bounds_tcp_flows=8 bounds_tcp_buffer_bytes=4096 bounds_udp_mappings=4 bounds_udp_buffered_bytes=4194304")
            && source.contains("adapter_churn=$performanceAdapterChurn grace_drain=PASS force_drain=PASS")
            && source.contains("$performanceAdapterChurn -ge 2")
            && completion.is_some_and(|completion| {
                completion.contains(
                    "m15_windows_tun_performance status=PASS witnesses=2/2 cleanup=PASS",
                ) && completion.contains(
                    "m16_windows_tun_full status=PASS m15_transport=16/16 direct_tcp=1/1 direct_udp=1/1 dns=2/2 network_change=3/3 route_change=1/1 interface_change=1/1 address_change=1/1 cycles=100/100 hard_kill=3/3 cleanup=PASS",
                ) && completion
                    .find("m15_windows_tun_performance_resource adapter_rx_bytes=")
                    .zip(completion.find(
                        "m15_windows_tun_performance status=PASS witnesses=2/2 cleanup=PASS",
                    ))
                    .is_some_and(|(resource, marker)| resource < marker)
            })
            && !source.contains("m15_windows_tun_performance threshold=")
            && !source.contains("m15_windows_tun_performance ratio=")
            && !source.contains("$performanceCpuMilliseconds -gt 0")
    };
    assert!(
        has_integrated_controller_profiles(&controller),
        "integrated full/cycle/performance controller contract missing"
    );
    for mutation in [
        controller.replacen(
            "Assert-True (@(Get-ExactRunProcesses $work).Count -eq 0) \"run process baseline not absent\"",
            "Assert-True ($true) \"run process baseline not absent\"",
            1,
        ),
        controller.replace("Ferrum2-M15-$runIdentity", "Ferrum2-M15-*"),
        controller.replace("$executables -contains $_.ExecutablePath", "$true"),
        controller.replace("run work baseline not absent", "run work ignored"),
        controller.replace("$cycle -lt 100", "$cycle -lt 99"),
        controller.replace("$script:cycleRows++", ""),
        controller.replace(
            "Get-NetAdapterStatistics -Name $Name",
            "Get-NetAdapter -Name $Name",
        ),
        controller.replace(
            "TotalProcessorTime.TotalMilliseconds",
            "UserProcessorTime.TotalMilliseconds",
        ),
        controller.replace("ferrum2_udp_buffered_bytes", "ferrum2_udp_packets"),
        controller.replace(
            "udp_sessions_peak=$performanceUdpSessionsPeak",
            "udp_sessions=unknown",
        ),
        controller.replace(
            "controller_inflight_peak=$performanceControllerInflightPeak",
            "controller_inflight=unknown",
        ),
        controller.replace(
            "adapter_churn=$performanceAdapterChurn grace_drain=PASS force_drain=PASS",
            "adapter_churn=unknown",
        ),
        controller.replace(
            "m15_transport=16/16 direct_tcp=1/1 direct_udp=1/1 dns=2/2 network_change=3/3",
            "m15_transport=16/16",
        ),
        controller.replace("witnesses=2/2 cleanup=PASS", "witnesses=1/2 cleanup=PASS"),
    ] {
        assert!(
            !has_integrated_controller_profiles(&mutation),
            "integrated controller mutation must remove full/performance proof"
        );
    }
    let client = fs::read_to_string(root.join("bins/ferrum2-client/src/run.rs"))
        .expect("client composition");
    let composes_tun_tcp = |composition: &str, adapter: &str, routing: &str| {
        composition.contains("roots.push(tun::process_root(")
            && composition.contains("Arc::clone(&context)")
            && composition.contains("tun_inbound")
            && adapter.contains("move |flow, cancellation|")
            && adapter.contains("Box::pin(run_tcp(")
            && adapter.contains("flow.target(),")
            && adapter.contains(".select_tcp(")
            && adapter.contains("ClientTerminalRoute::Reject")
            && adapter.contains("ClientTerminalRoute::HijackDns")
            && adapter.contains("ClientTerminalRoute::Route(plan)")
            && adapter.contains("context.egress.open_tcp(")
            && adapter.contains("relay_lifecycle(")
            && routing.contains("collect_sniff_prefix(")
            && routing.contains("pub(super) struct ReplayIo")
            && routing.contains("pub(super) async fn relay_hijacked_tcp")
    };
    assert!(
        composes_tun_tcp(&client, &client_tun, &client_routing),
        "TUN TCP must compose the one shared policy, prefix, DNS, egress and relay path"
    );
    for (composition, adapter, routing) in [
        (
            client.replace(
                "roots.push(tun::process_root(",
                "roots.push(ProcessRoot::new(",
            ),
            client_tun.clone(),
            client_routing.clone(),
        ),
        (
            client.clone(),
            client_tun.replace("context.egress.open_tcp(", "return; // open bypassed\n("),
            client_routing.clone(),
        ),
        (
            client.clone(),
            client_tun.clone(),
            client_routing.replace("collect_sniff_prefix(", "collect_other_prefix("),
        ),
    ] {
        assert!(
            !composes_tun_tcp(&composition, &adapter, &routing),
            "TUN TCP composition mutation must sever the shared production path"
        );
    }
    assert!(
        client_socks.contains("routing::{ClientTerminalRoute, relay_hijacked_tcp}")
            && !client_socks.contains("async fn relay_hijacked_tcp"),
        "SOCKS and TUN must call one moved terminal/DNS framing implementation"
    );
    assert!(
        tun_tcp.contains("pub struct TcpFlow")
            && !tun_tcp.contains("impl Clone for TcpFlow")
            && !tun_tcp.contains("derive(Clone"),
        "the public TUN TCP flow must remain one non-cloneable bounded stream"
    );

    let tun_udp_is_opaque_and_client_owned = |owner: &str, adapter: &str, association: &str| {
        owner.contains("pub struct UdpCandidate<T>")
            && owner.contains("pub async fn commit(")
            && owner.contains("terminal: T")
            && owner.contains("selected_payload_bound")
            && owner.contains("enum OwnerEvent<T>")
            && !owner.contains("pub enum OwnerEvent")
            && !owner.contains("ClientTerminalRoute")
            && !owner.contains("DnsProxy")
            && owner
                .find("self.slots[id.slot] = Some(Slot::Mapping")
                .zip(owner.find("sender.try_send(first)"))
                .is_some_and(|(mapping, first)| mapping < first)
            && owner.contains("self.generations.current(id.slot) != Some(id)")
            && owner.contains("let valid = admitting")
            && owner.contains("source != tuple.target")
            && adapter.contains("enum TunUdpTerminal")
            && adapter.contains("move |candidate, cancellation|")
            && adapter.contains("select_udp_terminal(")
            && adapter.contains("candidate.commit(terminal, selected_bound).await")
            && adapter.contains("run_udp_route(")
            && adapter.contains("run_udp_dns(")
            && adapter.contains("run_udp_reject(")
            && association.contains("fn prepare_application_request(")
            && association.contains("fn prepare_application_response(")
            && adapter.contains("association.prepare_application_request(")
            && adapter.contains("association.prepare_application_response(")
            && client_socks.contains("prepared.prepare_application_request(")
            && client_socks.contains("prepared.prepare_application_response(")
    };
    assert!(
        tun_udp_is_opaque_and_client_owned(&tun_udp, &client_tun, &client_udp),
        "TUN UDP must expose only an opaque commit/mapping flow and reuse client-owned policy/DNS/association paths"
    );
    for (owner, adapter, association) in [
        (
            tun_udp.replace("terminal: T", "terminal: ClientTerminalRoute"),
            client_tun.clone(),
            client_udp.clone(),
        ),
        (
            tun_udp.replace(
                "self.slots[id.slot] = Some(Slot::Mapping",
                "// mapping commit bypassed",
            ),
            client_tun.clone(),
            client_udp.clone(),
        ),
        (
            tun_udp.replace("self.generations.current(id.slot) != Some(id)", "false"),
            client_tun.clone(),
            client_udp.clone(),
        ),
        (
            tun_udp.replace("let valid = admitting", "let valid = true"),
            client_tun.clone(),
            client_udp.clone(),
        ),
        (
            tun_udp.clone(),
            client_tun.replace(
                "candidate.commit(terminal, selected_bound).await",
                "Err(ferrum2_tun::UdpCommitError::Rejected)",
            ),
            client_udp.clone(),
        ),
        (
            tun_udp.clone(),
            client_tun.replace("run_udp_dns(", "run_udp_route("),
            client_udp.clone(),
        ),
        (
            tun_udp.clone(),
            client_tun.clone(),
            client_udp.replace(
                "fn prepare_application_response(",
                "fn prepare_other_response(",
            ),
        ),
    ] {
        assert!(
            !tun_udp_is_opaque_and_client_owned(&owner, &adapter, &association),
            "TUN UDP mutation must sever opaque owner/client composition evidence"
        );
    }

    let has_t03_memory_carrier_composition =
        |foundation: &str, adapter: &str, egress: &str, config_tests: &str| {
            [
                "fn tcp_five_tuple_admission_is_bounded_before_socket_or_buffer_creation()",
                "async fn tcp_handshake_publishes_once_and_preserves_both_byte_directions()",
                "async fn udp_ipv4_ipv6_candidates_commit_and_inject_through_the_real_stack()",
                "let ipv6_flow = ipv6_stack.flows[0].as_ref().expect(\"IPv6 flow\");",
                "assert_eq!(ipv6_flow.tuple.source, \"[fd00::2]:10000\".parse().unwrap());",
                "assert_eq!(ipv6_flow.tuple.target, \"[2001:db8::1]:443\".parse().unwrap());",
                "Arc::new(handle_tcp)",
                "Arc::new(handle_udp)",
                "tasks.spawn((self.handle_tcp)(flow, cancellation.clone()))",
                "tasks.spawn((self.handle_udp)(candidate, cancellation.clone()))",
            ]
            .iter()
            .all(|required| foundation.contains(required))
                && [
                    "ferrum2_tun::process_root(",
                    "async fn tun_udp_over_limit_is_mapping_free_then_selector_snapshot_is_fixed()",
                    "async fn tun_auto_dns_tcp_answer_failure_closes_flow_before_ordinary_route()",
                    "ClientRequestOrigin::Tun",
                    "context.egress.open_tcp(",
                    "context.egress.prepare_udp(",
                    "candidate.commit(terminal, selected_bound).await",
                ]
                .iter()
                .all(|required| adapter.contains(required))
                && [
                    "async fn m16_direct_pre_socket_and_m16_redaction_classify_without_side_effects()",
                    "matches!(origin, ClientRequestOrigin::Tun)",
                    "ClientRequestOrigin::Socks",
                    "ClientPlanFailure::DirectIpv6Unsupported",
                ]
                .iter()
                .all(|required| egress.contains(required))
                && [
                    "fn m16_direct_only_client_omits_global_credentials_and_compiles_static_plan()",
                    "fn m16_client_outbound_shape_and_direct_plan_roots_are_closed()",
                    "config.route.select_plan(1, Network::Tcp, &target).hops()",
                    "config.route.final_plan().hops()",
                    "config.selector_control().switch(\"manual\", \"proxy\").unwrap()",
                ]
                .iter()
                .all(|required| config_tests.contains(required))
        };
    assert!(
        has_t03_memory_carrier_composition(&tun, &client_tun, &client_egress, &config_contract),
        "MemoryDevice family carriers must hand off through the one binary TUN composition into the shared Direct/proxy route forms"
    );
    for (foundation, adapter, egress, config_tests) in [
        (
            tun.replace(
                "tasks.spawn((self.handle_tcp)(flow, cancellation.clone()))",
                "drop(flow)",
            ),
            client_tun.clone(),
            client_egress.clone(),
            config_contract.clone(),
        ),
        (
            tun.replace(
                "assert_eq!(ipv6_flow.tuple.target, \"[2001:db8::1]:443\".parse().unwrap());",
                "assert!(true);",
            ),
            client_tun.clone(),
            client_egress.clone(),
            config_contract.clone(),
        ),
        (
            tun.clone(),
            client_tun.replace("context.egress.prepare_udp(", "prepare_other_udp("),
            client_egress.clone(),
            config_contract.clone(),
        ),
        (
            tun.clone(),
            client_tun.clone(),
            client_egress.replace(
                "matches!(origin, ClientRequestOrigin::Tun)",
                "origin.is_tun()",
            ),
            config_contract.clone(),
        ),
        (
            tun.clone(),
            client_tun.clone(),
            client_egress.clone(),
            config_contract.replace(
                "config.selector_control().switch(\"manual\", \"proxy\").unwrap()",
                "Ok(())",
            ),
        ),
    ] {
        assert!(
            !has_t03_memory_carrier_composition(&foundation, &adapter, &egress, &config_tests),
            "T03 MemoryDevice/composition/route-form mutation survived"
        );
    }

    let composes_private_tun_udp_owner = |composition: &str| {
        composition.contains("let tun_udp_defaults = tun_config.as_ref().map(|_| {")
            && composition.contains("let defaults = UdpRuntimeLimits::default();")
            && composition.contains("defaults.max_sessions()")
            && composition.contains("defaults.max_buffered_bytes()")
            && composition.contains("defaults.idle_timeout()")
            && composition
                .contains("dns.as_ref().is_some_and(|dns| dns.6) || tun_udp_defaults.is_some()")
            && composition.contains("if public_udp_enabled || internal_udp_needed")
            && composition.contains("if let Some(defaults) = tun_udp_defaults")
            && composition.contains("let tun_udp_idle_timeout = tun_config")
            && composition
                .contains(".map(|_| udp_limits.expect(\"TUN UDP requires internal limits\").2)")
            && composition.contains("tun_udp_idle_timeout.expect(\"TUN UDP idle retained\")")
            && composition.contains("udp_associate_enabled: public_udp_enabled")
    };
    assert!(
        composes_private_tun_udp_owner(&client),
        "TUN UDP must construct its private owner without enabling public SOCKS UDP"
    );
    for mutation in [
        client.replace(
            "dns.as_ref().is_some_and(|dns| dns.6) || tun_udp_defaults.is_some()",
            "dns.as_ref().is_some_and(|dns| dns.6)",
        ),
        client.replace(
            "let defaults = UdpRuntimeLimits::default();",
            "let defaults = UdpRuntimeLimits::new(1, 1, config.runtime.idle_timeout).expect(\"limits\");",
        ),
        client.replace(
            "tun_udp_idle_timeout.expect(\"TUN UDP idle retained\")",
            "config.runtime.idle_timeout",
        ),
        client.replace(
            "udp_associate_enabled: public_udp_enabled",
            "udp_associate_enabled: internal_udp_needed",
        ),
    ] {
        assert!(
            !composes_private_tun_udp_owner(&mutation),
            "TUN UDP composition mutation must remove private-owner/public-inbound separation"
        );
    }

    let tun_udp_idle_is_exact = |owner: &str, adapter: &str| {
        owner.contains("pub udp_timeout: Duration")
            && owner.contains("config.udp_timeout,")
            && adapter.contains("udp_timeout: udp_idle_timeout")
    };
    assert!(
        tun_udp_idle_is_exact(&tun, &client_tun),
        "TUN mapping and the shared UDP manager must use one validated idle lifetime"
    );
    for (owner, adapter) in [
        (
            tun.replace("config.udp_timeout,", "config.tcp_timeout,"),
            client_tun.clone(),
        ),
        (
            tun.clone(),
            client_tun.replace(
                "udp_timeout: udp_idle_timeout",
                "udp_timeout: context.runtime.idle_timeout",
            ),
        ),
    ] {
        assert!(
            !tun_udp_idle_is_exact(&owner, &adapter),
            "TUN UDP idle mutation must sever the shared lifetime proof"
        );
    }

    let runtime = fs::read_to_string(root.join("crates/ferrum2-runtime/src/process.rs"))
        .expect("process lifecycle");
    let cancellation_reap = |source: &str| {
        source.contains("pub fn new_cancellable")
            && source.contains("if reap_on_cancellation")
            && source.contains("match preparation.await")
            && source.contains("ProcessCleanupFailure::RootFailed")
    };
    assert!(
        cancellation_reap(&runtime),
        "in-flight cancellation-aware preparation is not explicitly reaped"
    );
    assert!(
        !cancellation_reap(&runtime.replace(
            "match preparation.await",
            "drop(preparation); match Err(())"
        )),
        "dropped preparation mutation must remove explicit reap proof"
    );
    assert!(tun_udp.contains("generation.checked_add(1)"));
    assert!(!tun_udp.contains("generation.wrapping_add(1)"));
    assert!(tun.contains("if self.validator.accepts(&self.output[..len])"));
    let tcp_owner_path_is_bounded = |source: &str| {
        source.contains("entry.owner.stack_buffered() != 0")
            && source.contains("entry.owner.stack_buffered() == 0")
            && source.contains("let repr = TcpRepr::parse(")
            && source.contains("repr.control != TcpControl::Syn || repr.ack_number.is_some()")
            && source.contains("Err(()) => return false")
            && source
                .find("while let Some(result) = tasks.try_join_next()")
                .zip(source.find("tasks.spawn("))
                .is_some_and(|(drain, spawn)| drain < spawn)
            && source.contains("break 'required OwnerExit::RuntimeFailed;")
            && source.contains("result.is_some_and(|result| result.is_err())")
    };
    assert!(
        tcp_owner_path_is_bounded(&tun),
        "TUN TCP queue, SYN parsing and handler owners must stay production-coupled"
    );
    for mutation in [
        tun.replace(
            "entry.owner.stack_buffered() != 0",
            "entry.owner.stack_buffered() == 0",
        ),
        tun.replace("let repr = TcpRepr::parse(", "let repr = parse_unchecked("),
        tun.replace(
            "while let Some(result) = tasks.try_join_next()",
            "while let Some(result) = None",
        ),
        tun.replace(
            "break 'required OwnerExit::RuntimeFailed;",
            "break 'required OwnerExit::Stopped;",
        ),
    ] {
        assert!(
            !tcp_owner_path_is_bounded(&mutation),
            "TUN TCP ownership mutation must sever the production proof"
        );
    }
    let owner_failures_are_production_connected = |source: &str| {
        source.contains("let thread = map_owner_spawn(")
            && source.contains("match finish_stack_setup(stack, adapter")
            && source.contains("Stack::new_with_udp(")
            && source.contains("|adapter| adapter.cleanup())")
    };
    assert!(
        owner_failures_are_production_connected(tun_production),
        "spawn and smoltcp setup failures must use the private owner cleanup helpers"
    );
    for mutation in [
        tun_production.replace("let thread = map_owner_spawn(", "let thread = Ok("),
        tun_production.replace(
            "match finish_stack_setup(stack, adapter",
            "match Ok((stack, adapter)",
        ),
        tun_production.replace("|adapter| adapter.cleanup())", "|_| Ok(()))"),
    ] {
        assert!(
            !owner_failures_are_production_connected(&mutation),
            "owner failure mutation must sever the production proof"
        );
    }
    let packet_witness_path = |source: &str| {
        source.contains("!self.validator.accepts(packet)")
            && source.contains("if stack.enqueue_at(")
            && source.contains("(metrics.accepted)();")
            && source.contains("stack.poll_quantum(Instant::from_millis(elapsed))")
            && source.contains("(metrics.foundation_dropped)();")
            && source.contains("match stack.take_output(|packet| adapter.send(packet).is_ok())")
    };
    assert!(
        packet_witness_path(&tun),
        "packet witness must traverse validation, enqueue, poll and foundation drop"
    );
    for mutation in [
        tun.replace("!self.validator.accepts(packet)", "false"),
        tun.replace("if stack.enqueue_at(", "if true || stack.enqueue_at("),
        tun.replace("stack.poll_quantum(Instant::from_millis(elapsed))", "0..0"),
        tun.replace(
            "match stack.take_output(|packet| adapter.send(packet).is_ok())",
            "match OutputResult::Empty",
        ),
    ] {
        assert!(
            !packet_witness_path(&mutation),
            "packet-path mutation must remove the real witness proof"
        );
    }
}

#[test]
fn owner_specific_tests_leave_composition_roots_and_form_no_cycles() {
    let root = workspace_root();
    let sources = token_sources_under(
        &root,
        &["bins/ferrum2-client/src", "bins/ferrum2-server/src"],
    );
    let rules = [
        (
            "fn",
            "phase_deadline_contract_table_preserves_defaults_overrides_and_first_write",
            "bins/ferrum2-client/src/run/egress/tcp.rs",
        ),
        (
            "fn",
            "routed_tcp_selects_after_target_and_never_falls_back",
            "bins/ferrum2-client/src/run/egress/tcp.rs",
        ),
        (
            "fn",
            "udp_send_lifecycle_covers_socket_io_session_idle_and_process_cancel",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "routed_udp_first_valid_packet_selects_association_once",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "client_route_reject_hijack",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "concrete_udp_socket_faults_release_every_owner_and_endpoint",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "composed_udp_boundaries_are_real_and_sequential_for_every_method_and_target",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_layers_mixed_credentials_bounds_and_response_binding",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_selector_snapshots_and_cross_plan_binding",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_invalid_inner_state_and_shutdown_are_atomic",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "dns_proxy_prepare_cancellation_awaits_owner_and_rebinds",
            "bins/ferrum2-client/src/run/dns.rs",
        ),
        (
            "fn",
            "dns_proxy_selector_snapshot_and_no_fallback",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_first_match_direct_and_detoured_transports",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_detoured_udp_with_public_associate_off",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_detour_saturation_shutdown_and_exact_rebind",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "tagged_dns_selection_uses_authenticated_original_context_and_final",
            "bins/ferrum2-server/src/dns_egress.rs",
        ),
        (
            "fn",
            "udp_composition_three_methods_echo_and_deferred_client_commit_table",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "fn",
            "udp_real_socket_session_saturation_never_reaches_second_target",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
    ];
    check_test_placement(
        &sources,
        &rules,
        &[
            "bins/ferrum2-client/src/run/tests.rs",
            "bins/ferrum2-server/src/run/tests.rs",
        ],
        &[
            "bins/ferrum2-client/src/run/test_support.rs",
            "bins/ferrum2-server/src/run/test_support.rs",
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn binary_composition_roots_delegate_protocol_execution_to_owned_modules() {
    let root = workspace_root();
    let sources = token_sources(
        &root,
        &[
            "bins/ferrum2-client/src/run.rs",
            "bins/ferrum2-server/src/run.rs",
        ],
    );
    check_composition_roots(
        &sources,
        &[
            (
                "bins/ferrum2-client/src/run.rs",
                &[
                    "fmt",
                    "run",
                    "run_async",
                    "run_with_registry",
                    "run_with_registry_and_metrics",
                    "run_with_registry_and_metrics_inner",
                    "report_result",
                ],
            ),
            (
                "bins/ferrum2-server/src/run.rs",
                &[
                    "fmt",
                    "run",
                    "run_async",
                    "run_with_registry",
                    "run_with_registry_prepared",
                    "report_result",
                ],
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("composition root owns protocol execution: {error}"));
    check_no_sequences(
        &sources,
        &[&["struct", "UdpMappings"], &["struct", "TokioTransport"]],
    )
    .unwrap_or_else(|error| panic!("composition root owns protocol execution: {error}"));
}

#[test]
fn runtime_and_library_owners_are_unique_and_composition_only() {
    let root = workspace_root();
    let sources = token_sources_under(&root, &["bins", "crates"]);
    let rules = [
        (
            "struct",
            "ClientRouting",
            "bins/ferrum2-client/src/run/context.rs",
        ),
        (
            "struct",
            "ClientContext",
            "bins/ferrum2-client/src/run/context.rs",
        ),
        (
            "struct",
            "ClientDnsRoot",
            "bins/ferrum2-client/src/run/dns.rs",
        ),
        (
            "struct",
            "ClientDnsEgress",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "struct",
            "ClientEgressEngine",
            "bins/ferrum2-client/src/run/egress/mod.rs",
        ),
        (
            "struct",
            "TokioTransport",
            "bins/ferrum2-client/src/run/io.rs",
        ),
        (
            "struct",
            "ClientMetricsRoot",
            "bins/ferrum2-client/src/run/observation.rs",
        ),
        (
            "fn",
            "observation_for_error",
            "bins/ferrum2-client/src/run/observation.rs",
        ),
        (
            "fn",
            "client_connection",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "run_udp_association",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "relay_udp_association",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "struct",
            "ServerDnsRoot",
            "bins/ferrum2-server/src/run/dns.rs",
        ),
        (
            "struct",
            "ServerDnsEgress",
            "bins/ferrum2-server/src/dns_egress.rs",
        ),
        (
            "struct",
            "TokioTransport",
            "bins/ferrum2-server/src/run/io.rs",
        ),
        (
            "struct",
            "ServerMetricsRoot",
            "bins/ferrum2-server/src/run/observation.rs",
        ),
        (
            "fn",
            "observation_for_error",
            "bins/ferrum2-server/src/run/observation.rs",
        ),
        (
            "fn",
            "server_connection",
            "bins/ferrum2-server/src/run/tcp.rs",
        ),
        (
            "struct",
            "UdpMappings",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "fn",
            "prepare_udp_server",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "struct",
            "EgressPlanSnapshot",
            "crates/ferrum2-core/src/route.rs",
        ),
        (
            "struct",
            "SelectorControl",
            "crates/ferrum2-core/src/selector.rs",
        ),
        (
            "struct",
            "ValidatedClientConfig",
            "crates/ferrum2-config/src/model.rs",
        ),
        (
            "struct",
            "ValidatedServerConfig",
            "crates/ferrum2-config/src/model.rs",
        ),
        (
            "struct",
            "ConfigError",
            "crates/ferrum2-config/src/error.rs",
        ),
        (
            "enum",
            "ConfigErrorKind",
            "crates/ferrum2-config/src/error.rs",
        ),
        ("fn", "load_client", "crates/ferrum2-config/src/load.rs"),
        ("fn", "load_server", "crates/ferrum2-config/src/load.rs"),
        (
            "struct",
            "RawClientRoot",
            "crates/ferrum2-config/src/raw.rs",
        ),
        (
            "struct",
            "RawServerRoot",
            "crates/ferrum2-config/src/raw.rs",
        ),
        (
            "fn",
            "validate_client",
            "crates/ferrum2-config/src/validation.rs",
        ),
        (
            "fn",
            "validate_server",
            "crates/ferrum2-config/src/validation.rs",
        ),
        ("struct", "DnsProxy", "crates/ferrum2-dns/src/proxy.rs"),
        ("enum", "ProxyIngress", "crates/ferrum2-dns/src/proxy.rs"),
        ("fn", "answer", "crates/ferrum2-dns/src/proxy.rs"),
        (
            "struct",
            "SystemDnsEgress",
            "crates/ferrum2-dns/src/runtime_provider.rs",
        ),
        (
            "struct",
            "TaggedResolver",
            "crates/ferrum2-dns/src/runtime_owner.rs",
        ),
        (
            "struct",
            "ClientTcpOutbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "struct",
            "ShadowsocksTcpInbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "struct",
            "UdpClientSession",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "struct",
            "UdpServer",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "fn",
            "encode_request_first_write",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
    ];
    let roots = [
        "bins/ferrum2-client/src/run.rs",
        "bins/ferrum2-server/src/run.rs",
        "crates/ferrum2-config/src/lib.rs",
        "crates/ferrum2-core/src/lib.rs",
    ];
    check_definition_ownership(&sources, &rules, &roots).unwrap_or_else(|error| panic!("{error}"));
    for (label, keyword, name, owner, duplicate) in [
        (
            "DNS",
            "struct",
            "DnsProxy",
            "crates/ferrum2-dns/src/proxy.rs",
            "crates/ferrum2-dns/src/duplicate_proxy.rs",
        ),
        (
            "SIP022",
            "struct",
            "ShadowsocksTcpInbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
            "crates/ferrum2-shadowsocks/src/duplicate_tcp.rs",
        ),
        (
            "SIP022 UDP",
            "struct",
            "UdpServer",
            "crates/ferrum2-shadowsocks/src/udp.rs",
            "crates/ferrum2-shadowsocks/src/duplicate_udp.rs",
        ),
    ] {
        let mutation = [
            TokenSource::new(
                owner,
                &fs::read_to_string(root.join(owner)).expect("protocol owner source"),
            ),
            TokenSource::new(duplicate, &format!("{keyword} {name};")),
        ];
        assert!(
            check_definition_ownership(&mutation, &[(keyword, name, owner)], &[]).is_err(),
            "second {label} implementation mutation survived"
        );
    }

    check_no_identifiers(
        sources
            .iter()
            .filter(|source| source.path != "crates/ferrum2-wintun/src/windows.rs"),
        &["unsafe", "PlanSnapshot"],
    )
    .unwrap_or_else(|error| panic!("product source changes unsafe/plan ownership: {error}"));
    let dns_adapters = [
        "bins/ferrum2-client/src/dns_egress.rs",
        "bins/ferrum2-client/src/run/dns.rs",
        "bins/ferrum2-server/src/dns_egress.rs",
        "bins/ferrum2-server/src/run/dns.rs",
    ];
    check_no_identifiers(
        sources
            .iter()
            .filter(|source| dns_adapters.contains(&source.path.as_str())),
        &["hickory_proto", "DnsParser"],
    )
    .unwrap_or_else(|error| panic!("DNS adapter duplicates protocol behavior: {error}"));
    for adapter in dns_adapters {
        let source = sources
            .iter()
            .find(|source| source.path == adapter)
            .unwrap();
        check_no_sequences([source], &[&["Message", ":", ":", "from_vec"]])
            .unwrap_or_else(|error| panic!("DNS adapter parses wire: {error}"));
    }
    let dns_sources: Vec<_> = sources
        .iter()
        .filter(|source| source.path.starts_with("crates/ferrum2-dns/src/"))
        .collect();
    check_no_identifiers(
        dns_sources.iter().copied(),
        &["DnsService", "DnsFramer", "DnsParser", "DnsQueryEngine"],
    )
    .unwrap_or_else(|error| panic!("DNS crate restored a delegating/duplicate module: {error}"));
    let parser_owners: Vec<_> = dns_sources
        .iter()
        .filter(|source| {
            has_tokens(
                source.production_tokens().expect("DNS production tokens"),
                &["Message", ":", ":", "from_vec"],
            )
        })
        .map(|source| source.path.as_str())
        .collect();
    assert_eq!(
        parser_owners,
        ["crates/ferrum2-dns/src/proxy.rs"],
        "DnsProxy::answer must remain the only DNS wire decoder"
    );
    let proxy = dns_sources
        .iter()
        .find(|source| source.path == "crates/ferrum2-dns/src/proxy.rs")
        .expect("DNS proxy owner")
        .production_tokens()
        .expect("DNS proxy production tokens");
    assert_eq!(
        proxy
            .windows(4)
            .filter(|window| *window == ["HickoryTcpStream", ":", ":", "from_stream"])
            .count(),
        1,
        "DnsProxy listeners must retain one Hickory TCP framer"
    );
    let server_dns = sources
        .iter()
        .find(|source| source.path == "bins/ferrum2-server/src/dns_egress.rs")
        .expect("server DNS policy adapter");
    check_no_identifiers([server_dns], &["DnsQueryType", "RecordType", "qtype"])
        .unwrap_or_else(|error| panic!("server application DNS policy gained qtype: {error}"));
    let server_dns_tokens = server_dns
        .production_tokens()
        .expect("server DNS policy tokens");
    for (sequence, message) in [
        (
            ["state", ".", "select"],
            "application DNS policy must select exactly once",
        ),
        (
            ["resolver", ".", "lookup_ips"],
            "server resolution must enter one A+AAAA lookup",
        ),
    ] {
        assert_eq!(
            server_dns_tokens
                .windows(sequence.len())
                .filter(|window| *window == sequence)
                .count(),
            1,
            "{message}"
        );
    }
    let server_run = sources
        .iter()
        .find(|source| source.path == "bins/ferrum2-server/src/run.rs")
        .expect("server composition root")
        .production_tokens()
        .expect("server composition tokens");
    for (sequence, message) in [
        (
            &["config", ".", "dns_route"][..],
            "server root must hand off the application DNS policy exactly once",
        ),
        (
            &[
                "ServerDnsState",
                ":",
                ":",
                "new",
                "(",
                "route",
                ",",
                "policy",
                ")",
            ],
            "server root must preserve the selected DNS route and policy",
        ),
    ] {
        assert_eq!(
            server_run
                .windows(sequence.len())
                .filter(|window| {
                    window
                        .iter()
                        .map(String::as_str)
                        .eq(sequence.iter().copied())
                })
                .count(),
            1,
            "{message}"
        );
    }
    let server_dns_tests = &server_dns.tokens[server_dns_tokens.len()..];
    for (sequence, count, message) in [
        (
            &["Message", ":", ":", "from_vec"][..],
            2,
            "server live DNS responders must decode with Hickory",
        ),
        (
            &["Message", ":", ":", "response"][..],
            2,
            "server live DNS responders must construct typed responses",
        ),
        (
            &["response", ".", "to_vec"][..],
            2,
            "server live DNS responders must encode with Hickory",
        ),
    ] {
        assert_eq!(
            server_dns_tests
                .windows(sequence.len())
                .filter(|window| {
                    window
                        .iter()
                        .map(String::as_str)
                        .eq(sequence.iter().copied())
                })
                .count(),
            count,
            "{message}"
        );
    }
    assert!(
        !server_dns_tests
            .iter()
            .any(|token| matches!(token.as_str(), "qtype_offset" | "from_be_bytes")),
        "server live DNS responders must not decode query fields manually"
    );
    assert!(
        !server_dns_tests
            .iter()
            .any(|token| matches!(token.as_str(), "24" | "25" | "26" | "28" | "29")),
        "server live DNS responders must not depend on fixed qtype offsets"
    );
    assert!(
        !server_dns_tests.windows(3).any(|window| {
            window[0] == "[" && matches!(window[1].as_str(), "2" | "3") && window[2] == "]"
        }),
        "server live DNS responders must not edit header flag offsets"
    );
}
#[test]
fn server_dns_composition_reuses_the_tagged_resolver_and_connector_seams() {
    let root = workspace_root();
    let run = fs::read_to_string(root.join("bins/ferrum2-server/src/run.rs"))
        .expect("server composition");
    let egress = fs::read_to_string(root.join("bins/ferrum2-server/src/dns_egress.rs"))
        .expect("server DNS egress adapter");
    let dns = fs::read_to_string(root.join("bins/ferrum2-server/src/run/dns.rs"))
        .expect("server DNS process owner");
    let support = fs::read_to_string(root.join("tests/m0-harness/src/local_support/mod.rs"))
        .expect("shared process support");

    for required in [
        "mod dns_egress;",
        "ServerDnsRoot",
        "TaggedResolver::new",
        "ServerDnsResolver::new",
    ] {
        assert!(
            run.contains(required),
            "missing server DNS composition: {required}"
        );
    }
    assert!(dns.contains("PreparedProcessRoot<RunError> for ServerDnsRoot"));
    for required in [
        "ActionTable<usize>",
        "SystemTcpResolver",
        "SystemUdpResolver",
        "impl TcpResolver for ServerDnsResolver",
        "impl UdpResolver for ServerDnsResolver",
        "MAX_RESOLVED_CANDIDATES",
    ] {
        assert!(
            egress.contains(required),
            "missing reused DNS seam: {required}"
        );
    }
    let production = [
        TokenSource::new("bins/ferrum2-server/src/run.rs", &run),
        TokenSource::new("bins/ferrum2-server/src/run/dns.rs", &dns),
        TokenSource::new("bins/ferrum2-server/src/dns_egress.rs", &egress),
    ];
    check_no_identifiers(production.iter(), &["hickory_proto", "DnsParser"]).unwrap_or_else(
        |error| panic!("server composition duplicated DNS protocol behavior: {error}"),
    );
    check_no_sequences(production.iter(), &[&["Message", ":", ":", "from_vec"]])
        .unwrap_or_else(|error| panic!("server composition parsed DNS wire: {error}"));
    for required in [
        "Message::from_vec",
        "Record::from_rdata",
        "RData::A",
        ".to_vec().expect(\"DNS answer encode\")",
    ] {
        assert!(
            support.contains(required),
            "shared DNS fixture must use Hickory: {required}"
        );
    }
    for forbidden in [
        "let mut end = 12",
        "u16::from_be_bytes([request[end]",
        "response.extend_from_slice(&[0x81, 0x80",
        "0xc0,\n                    0x0c",
    ] {
        assert!(
            !support.contains(forbidden),
            "shared DNS fixture copied DNS wire behavior: {forbidden}"
        );
    }
}
