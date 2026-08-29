#![forbid(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    eprintln!("windows non-TUN qualification is only available on Windows");
    std::process::exit(2);
}

#[cfg(windows)]
mod windows_gate {
    use std::env;
    use std::fs::OpenOptions;
    use std::future::Future as _;
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use ferrum2_net::{
        DialOptions, NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions,
    };
    use ferrum2_platform_windows::{WindowsNetworkInterfaceCatalog, WindowsResolvedSocketBinder};
    use ferrum2_runtime::{
        DirectUdpSocket, NetworkResetCoordinator, NetworkResetIntent, NetworkResetLimits,
        NetworkResetOutcome, NetworkResetReason, NetworkResetReport,
        NetworkRuntimeOwnerCancellation, NetworkSnapshotPublisher, NetworkSocketMode,
        NetworkSocketService, NetworkUdpSocket, OwnerRegistry, OwnerSnapshot,
        SystemNetworkSocketOperations,
    };
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    const REPORT_LIMIT_BYTES: usize = 64 * 1024;
    const REQUIRED_SCALE_SOCKETS: usize = 10_000;
    const PORT_HEADROOM: usize = 2_048;
    const LOOPBACK_SAMPLES: usize = 256;
    const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(2);
    const RESET_TIMEOUT: Duration = Duration::from_secs(30);
    const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
    const STATIC_STAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const DYNAMIC_STAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const SCALE_1K_STAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const SCALE_10K_STAGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    const ECHO_STAGE_TIMEOUT: Duration = Duration::from_secs(15);
    const CLEANUP_RETRIES: usize = 20;

    type GateOperations = SystemNetworkSocketOperations<WindowsResolvedSocketBinder>;
    type GateService = NetworkSocketService<WindowsNetworkInterfaceCatalog, GateOperations>;
    type GateSocket = NetworkUdpSocket<UdpSocket>;

    #[derive(Clone, Copy)]
    struct GateError(&'static str);

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum GateDisposition {
        EnvironmentReject,
        Failure,
    }

    impl GateError {
        fn disposition(self) -> GateDisposition {
            if self.0 == "reset_deadline_exceeded" {
                GateDisposition::Failure
            } else if self.0.starts_with("udp_port_")
                || self.0.ends_with("_deadline_exceeded")
                || matches!(
                    self.0,
                    "echo_bind_failed"
                        | "echo_address_failed"
                        | "network_snapshot_capture_failed"
                        | "powershell_query_failed"
                        | "process_sample_invalid"
                        | "environment_udp_capacity_changed"
                )
            {
                GateDisposition::EnvironmentReject
            } else {
                GateDisposition::Failure
            }
        }
    }

    #[derive(Clone, Copy)]
    struct ProcessSample {
        working_set_bytes: u64,
        private_memory_bytes: u64,
        threads: usize,
        handles: usize,
        physical_udp_endpoints: usize,
    }

    #[derive(Clone, Copy)]
    struct ResourceBaseline {
        tasks: usize,
        owners: OwnerSnapshot,
        process: ProcessSample,
    }

    #[derive(Clone, Copy)]
    struct PortHeadroom {
        start: u16,
        count: usize,
        ports_in_use: usize,
        ports_excluded: usize,
        ports_unavailable: usize,
    }

    struct AbortOnDropTask<T> {
        task: Option<JoinHandle<T>>,
    }

    impl<T> AbortOnDropTask<T> {
        const fn new(task: JoinHandle<T>) -> Self {
            Self { task: Some(task) }
        }

        async fn abort(mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
                let _ = task.await;
            }
        }

        async fn join(mut self) -> Result<T, GateError> {
            let mut task = self
                .task
                .take()
                .ok_or(GateError("pending_receive_join_failed"))?;
            match tokio::time::timeout(ROUND_TRIP_TIMEOUT, &mut task).await {
                Ok(Ok(result)) => Ok(result),
                Ok(Err(_)) => Err(GateError("pending_receive_join_failed")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(GateError("pending_receive_timeout"))
                }
            }
        }
    }

    impl<T> Drop for AbortOnDropTask<T> {
        fn drop(&mut self) {
            if let Some(task) = self.task.as_ref() {
                task.abort();
            }
        }
    }

    struct EchoServer {
        address: SocketAddr,
        task: Option<JoinHandle<std::io::Result<()>>>,
    }

    impl EchoServer {
        async fn start() -> Result<Self, GateError> {
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| GateError("echo_bind_failed"))?;
            let address = socket
                .local_addr()
                .map_err(|_| GateError("echo_address_failed"))?;
            let task = tokio::spawn(async move {
                let mut payload = [0_u8; 64];
                loop {
                    let (length, peer) = socket.recv_from(&mut payload).await?;
                    socket.send_to(&payload[..length], peer).await?;
                }
            });
            Ok(Self {
                address,
                task: Some(task),
            })
        }

        async fn close(mut self) -> Result<(), GateError> {
            let task = self.task.take().ok_or(GateError("echo_cleanup_failed"))?;
            task.abort();
            match task.await {
                Err(error) if error.is_cancelled() => Ok(()),
                _ => Err(GateError("echo_cleanup_failed")),
            }
        }
    }

    impl Drop for EchoServer {
        fn drop(&mut self) {
            if let Some(task) = self.task.as_ref() {
                task.abort();
            }
        }
    }

    pub async fn entry() -> i32 {
        let Some(output) = output_path() else {
            eprintln!("usage: windows_non_tun_gate06 --output <new-json-path>");
            return 2;
        };
        let cpu_vendor =
            env::var("FERRUM2_GATE06_CPU_VENDOR").unwrap_or_else(|_| "unknown".to_owned());
        let cpu_name = env::var("FERRUM2_GATE06_CPU_NAME").unwrap_or_else(|_| "unknown".to_owned());
        let binary_sha256 = current_executable_sha256().unwrap_or_else(|_| "unknown".to_owned());
        let mut evidence = base_evidence(&cpu_vendor, &cpu_name, &binary_sha256);

        if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || env::var("RUNNER_OS").as_deref() != Ok("Windows")
        {
            set_failed_stage(&mut evidence, "environment_preflight");
            set_outcome(
                &mut evidence,
                "ENVIRONMENT_REJECT",
                "hosted_windows_required",
            );
            return finish(&output, &evidence, 2);
        }
        if !identity_is_valid(&cpu_vendor, &cpu_name, &binary_sha256) {
            set_failed_stage(&mut evidence, "identity_preflight");
            set_outcome(
                &mut evidence,
                "ENVIRONMENT_REJECT",
                "identity_preflight_failed",
            );
            return finish(&output, &evidence, 2);
        }

        let headroom = match query_udp_port_headroom() {
            Ok(headroom) => headroom,
            Err(error) => {
                set_failed_stage(&mut evidence, "port_preflight");
                set_outcome(&mut evidence, "ENVIRONMENT_REJECT", error.0);
                return finish(&output, &evidence, 2);
            }
        };
        let available = headroom.count.saturating_sub(headroom.ports_unavailable);
        evidence["preflight"] = json!({
            "udp_dynamic_port_start": headroom.start,
            "udp_dynamic_port_count": headroom.count,
            "udp_dynamic_ports_in_use": headroom.ports_in_use,
            "udp_dynamic_ports_excluded": headroom.ports_excluded,
            "udp_dynamic_ports_unavailable": headroom.ports_unavailable,
            "udp_dynamic_ports_available": available,
            "required_scale_sockets": REQUIRED_SCALE_SOCKETS,
            "reserved_headroom": PORT_HEADROOM,
        });
        if available < REQUIRED_SCALE_SOCKETS + PORT_HEADROOM {
            set_failed_stage(&mut evidence, "port_preflight");
            set_outcome(
                &mut evidence,
                "ENVIRONMENT_REJECT",
                "insufficient_udp_port_headroom",
            );
            return finish(&output, &evidence, 2);
        }

        match bounded_stage(
            QUALIFICATION_TIMEOUT,
            "qualification_deadline_exceeded",
            run_qualification(&mut evidence),
        )
        .await
        {
            Ok(()) => {
                set_outcome(&mut evidence, "PASS", "none");
                finish(&output, &evidence, 0)
            }
            Err(error) => {
                if error.0 == "qualification_deadline_exceeded" {
                    set_failed_stage(&mut evidence, "qualification_total");
                }
                let (status, code) = match error.disposition() {
                    GateDisposition::EnvironmentReject => ("ENVIRONMENT_REJECT", 2),
                    GateDisposition::Failure => ("FAIL", 1),
                };
                set_outcome(&mut evidence, status, error.0);
                finish(&output, &evidence, code)
            }
        }
    }

    fn output_path() -> Option<PathBuf> {
        let mut arguments = env::args_os().skip(1);
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
            return None;
        }
        let output = arguments.next().map(PathBuf::from)?;
        arguments.next().is_none().then_some(output)
    }

    fn base_evidence(cpu_vendor: &str, cpu_name: &str, binary_sha256: &str) -> Value {
        json!({
            "schema": "ferrum2.windows-non-tun-gate06.v1",
            "status": "RUNNING",
            "reason": "none",
            "failed_stage": Value::Null,
            "scope": "hosted_correctness_and_diagnostic",
            "performance_authoritative": false,
            "performance_adoption_allowed": false,
            "amd_preferred": cpu_vendor.eq_ignore_ascii_case("AuthenticAMD"),
            "identity": {
                "sha": environment_value("GITHUB_SHA"),
                "repository": environment_value("GITHUB_REPOSITORY"),
                "workflow_ref": environment_value("GITHUB_WORKFLOW_REF"),
                "workflow_sha": environment_value("GITHUB_WORKFLOW_SHA"),
                "run_id": environment_value("GITHUB_RUN_ID"),
                "run_attempt": environment_value("GITHUB_RUN_ATTEMPT"),
                "runner_os": environment_value("RUNNER_OS"),
                "runner_arch": environment_value("RUNNER_ARCH"),
                "image_os": environment_value("ImageOS"),
                "image_version": environment_value("ImageVersion"),
                "cpu_vendor": cpu_vendor,
                "cpu_name": cpu_name,
                "profile": environment_value("FERRUM2_GATE06_PROFILE"),
                "target": environment_value("FERRUM2_GATE06_TARGET"),
                "rustc": environment_value("FERRUM2_GATE06_RUSTC_IDENTITY"),
                "release_example_sha256": binary_sha256,
            },
            "preflight": Value::Null,
            "closed_measurements": {
                "physical_pending_send": "not_applicable_nondeterministic_on_loopback",
                "real_interface_change": "not_applicable_hosted_non_privileged",
                "etw_lock_contention": "not_applicable_hosted_non_privileged",
                "runtime_state_lock_count": "not_exposed",
                "runtime_lock_wait": "not_exposed",
            },
            "cleanup_contract": {
                "network_runtime_owners": "exact_zero",
                "physical_udp_sockets": "exact_zero",
                "tokio_tasks": "exact_stage_baseline",
                "threads": "at_or_below_stage_baseline",
                "handle_count": "at_or_below_stage_baseline",
                "working_set_and_private_memory": "diagnostic_allocator_retention_allowed",
            },
            "contracts": {
                "runtime_concurrent_send_receive_reset": "covered_by_network_socket_service_test",
                "static": Value::Null,
                "dynamic": Value::Null,
                "scale": [],
            },
            "stages": [],
        })
    }

    fn environment_value(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| "unknown".to_owned())
    }

    fn identity_is_valid(cpu_vendor: &str, cpu_name: &str, binary_sha256: &str) -> bool {
        let sha = environment_value("GITHUB_SHA");
        let repository = environment_value("GITHUB_REPOSITORY");
        let workflow_ref = environment_value("GITHUB_WORKFLOW_REF");
        let workflow_sha = environment_value("GITHUB_WORKFLOW_SHA");
        let expected_binary = environment_value("FERRUM2_GATE06_EXPECTED_BINARY_SHA256");
        is_lower_hex(&sha, 40)
            && is_repository(&repository)
            && workflow_ref.starts_with(&format!("{repository}/.github/workflows/m0.yml@"))
            && is_lower_hex(&workflow_sha, 40)
            && environment_value("GITHUB_RUN_ID")
                .parse::<u64>()
                .is_ok_and(|value| value != 0)
            && environment_value("GITHUB_RUN_ATTEMPT")
                .parse::<u64>()
                .is_ok_and(|value| value != 0)
            && environment_value("RUNNER_ARCH") == "X64"
            && known_identity(&environment_value("ImageOS"))
            && known_identity(&environment_value("ImageVersion"))
            && known_identity(cpu_vendor)
            && known_identity(cpu_name)
            && environment_value("FERRUM2_GATE06_PROFILE") == "windows-msvc"
            && environment_value("FERRUM2_GATE06_TARGET") == "x86_64-pc-windows-msvc"
            && environment_value("FERRUM2_GATE06_RUSTC_IDENTITY").starts_with("rustc 1.97.1 ")
            && is_lower_hex(binary_sha256, 64)
            && expected_binary == binary_sha256
    }

    fn known_identity(value: &str) -> bool {
        !value.trim().is_empty() && !value.eq_ignore_ascii_case("unknown")
    }

    fn is_repository(value: &str) -> bool {
        let Some((owner, repository)) = value.split_once('/') else {
            return false;
        };
        !owner.is_empty()
            && !repository.is_empty()
            && !repository.contains('/')
            && owner.bytes().all(identity_byte)
            && repository.bytes().all(identity_byte)
    }

    fn identity_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
    }

    fn is_lower_hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn current_executable_sha256() -> Result<String, GateError> {
        let path = env::current_exe().map_err(|_| GateError("binary_identity_unavailable"))?;
        let mut file =
            std::fs::File::open(path).map_err(|_| GateError("binary_identity_unavailable"))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| GateError("binary_identity_unavailable"))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn set_outcome(evidence: &mut Value, status: &'static str, reason: &'static str) {
        evidence["status"] = json!(status);
        evidence["reason"] = json!(reason);
    }

    fn set_failed_stage(evidence: &mut Value, stage: &'static str) {
        evidence["failed_stage"] = json!(stage);
    }

    fn finish(output: &Path, evidence: &Value, desired_code: i32) -> i32 {
        match write_evidence(output, evidence) {
            Ok(()) => desired_code,
            Err(()) => {
                eprintln!("failed to write bounded GATE-06 evidence");
                1
            }
        }
    }

    fn write_evidence(output: &Path, evidence: &Value) -> Result<(), ()> {
        let encoded = serde_json::to_vec_pretty(evidence).map_err(|_| ())?;
        if encoded.len() > REPORT_LIMIT_BYTES {
            return Err(());
        }
        let parent = output.parent().ok_or(())?;
        std::fs::create_dir_all(parent).map_err(|_| ())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|_| ())?;
        file.write_all(&encoded).map_err(|_| ())?;
        file.write_all(b"\n").map_err(|_| ())?;
        file.sync_all().map_err(|_| ())
    }

    fn query_udp_port_headroom() -> Result<PortHeadroom, GateError> {
        let output = Command::new("netsh.exe")
            .args(["interface", "ipv4", "show", "dynamicport", "udp"])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| GateError("udp_port_range_query_failed"))?;
        if !output.status.success() || output.stdout.len() > 16 * 1024 {
            return Err(GateError("udp_port_range_query_failed"));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| GateError("udp_port_range_query_failed"))?;
        let values = text
            .lines()
            .filter_map(|line| line.split_once(':').map(|(_, value)| value.trim()))
            .filter_map(|value| value.parse::<usize>().ok())
            .collect::<Vec<_>>();
        let [start, count] = values.as_slice() else {
            return Err(GateError("udp_port_range_query_failed"));
        };
        let start = u16::try_from(*start)
            .ok()
            .filter(|start| *start != 0)
            .ok_or(GateError("udp_port_range_invalid"))?;
        let end = usize::from(start)
            .checked_add(*count)
            .and_then(|end| end.checked_sub(1))
            .filter(|end| *end <= usize::from(u16::MAX))
            .ok_or(GateError("udp_port_range_invalid"))?;
        let script = format!(
            "$first={start}; $last={end}; \
             $used=[System.Collections.Generic.HashSet[int]]::new(); \
             Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {{ $_.LocalPort -ge $first -and $_.LocalPort -le $last }} | ForEach-Object {{ [void]$used.Add([int]$_.LocalPort) }}; \
             $excluded=[System.Collections.Generic.HashSet[int]]::new(); \
             $ranges=& netsh.exe interface ipv4 show excludedportrange protocol=udp; \
             if ($LASTEXITCODE -ne 0) {{ exit 21 }}; \
             foreach ($line in $ranges) {{ if ($line -match '^\\s*(\\d+)\\s+(\\d+)(?:\\s+\\*)?\\s*$') {{ $lo=[Math]::Max([int]$Matches[1],$first); $hi=[Math]::Min([int]$Matches[2],$last); for ($port=$lo; $port -le $hi; $port++) {{ [void]$excluded.Add($port) }} }} }}; \
             $unavailable=[System.Collections.Generic.HashSet[int]]::new(); \
             $unavailable.UnionWith($used); \
             $unavailable.UnionWith($excluded); \
             Write-Output ('{{0}},{{1}},{{2}}' -f $used.Count,$excluded.Count,$unavailable.Count)"
        );
        let counts = powershell_output(&script, 1024)?;
        let fields = counts.trim().split(',').map(str::trim).collect::<Vec<_>>();
        let [ports_in_use, ports_excluded, ports_unavailable] = fields.as_slice() else {
            return Err(GateError("udp_port_usage_query_failed"));
        };
        let ports_in_use = ports_in_use
            .parse::<usize>()
            .map_err(|_| GateError("udp_port_usage_query_failed"))?;
        let ports_excluded = ports_excluded
            .parse::<usize>()
            .map_err(|_| GateError("udp_port_usage_query_failed"))?;
        let ports_unavailable = ports_unavailable
            .parse::<usize>()
            .map_err(|_| GateError("udp_port_usage_query_failed"))?;
        if ports_in_use > *count || ports_excluded > *count || ports_unavailable > *count {
            return Err(GateError("udp_port_range_invalid"));
        }
        Ok(PortHeadroom {
            start,
            count: *count,
            ports_in_use,
            ports_excluded,
            ports_unavailable,
        })
    }

    fn powershell_output(script: &str, limit: usize) -> Result<String, GateError> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| GateError("powershell_query_failed"))?;
        if !output.status.success() || output.stdout.len() > limit {
            return Err(GateError("powershell_query_failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| GateError("powershell_query_failed"))
    }

    fn process_sample() -> Result<ProcessSample, GateError> {
        let process_id = std::process::id();
        let script = format!(
            "$p=Get-Process -Id {process_id} -ErrorAction Stop; \
             $udp=@(Get-NetUDPEndpoint -OwningProcess {process_id} -ErrorAction Stop).Count; \
             Write-Output ('{{0}},{{1}},{{2}},{{3}},{{4}}' -f $p.WorkingSet64,$p.PrivateMemorySize64,@($p.Threads).Count,$p.HandleCount,$udp)"
        );
        let output = powershell_output(&script, 1024)?;
        let fields = output.trim().split(',').map(str::trim).collect::<Vec<_>>();
        let [
            working_set,
            private_memory,
            threads,
            handles,
            physical_udp_endpoints,
        ] = fields.as_slice()
        else {
            return Err(GateError("process_sample_invalid"));
        };
        Ok(ProcessSample {
            working_set_bytes: working_set
                .parse()
                .map_err(|_| GateError("process_sample_invalid"))?,
            private_memory_bytes: private_memory
                .parse()
                .map_err(|_| GateError("process_sample_invalid"))?,
            threads: threads
                .parse()
                .map_err(|_| GateError("process_sample_invalid"))?,
            handles: handles
                .parse()
                .map_err(|_| GateError("process_sample_invalid"))?,
            physical_udp_endpoints: physical_udp_endpoints
                .parse()
                .map_err(|_| GateError("process_sample_invalid"))?,
        })
    }

    impl ResourceBaseline {
        fn capture(owners: &OwnerRegistry) -> Result<Self, GateError> {
            Ok(Self {
                tasks: alive_tasks(),
                owners: owners.snapshot(),
                process: process_sample()?,
            })
        }
    }

    fn alive_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    fn new_service(
        mode: NetworkSocketMode,
        owners: &OwnerRegistry,
    ) -> Result<(NetworkResetCoordinator, GateService), GateError> {
        let catalog = WindowsNetworkInterfaceCatalog::system();
        let snapshot = Arc::new(
            NetworkSnapshot::capture(1, &catalog)
                .map_err(|_| GateError("network_snapshot_capture_failed"))?,
        );
        let coordinator = NetworkResetCoordinator::new(
            NetworkSnapshotPublisher::new(snapshot),
            NetworkResetLimits::default(),
            owners.clone(),
        );
        let service = NetworkSocketService::with_mode(
            mode,
            coordinator.clone(),
            NetworkInterfaceResolver::new(catalog),
            SystemNetworkSocketOperations::new(WindowsResolvedSocketBinder),
        );
        Ok((coordinator, service))
    }

    fn open_socket(service: &GateService, target: SocketAddr) -> Result<GateSocket, GateError> {
        service
            .open_udp(
                &DialOptions::default(),
                &RouteNetworkOptions::new(false, None::<&str>),
                target,
            )
            .map_err(|_| GateError("physical_udp_open_failed"))
    }

    fn next_snapshot(
        service: &GateService,
        generation: u64,
    ) -> Result<Arc<NetworkSnapshot>, GateError> {
        NetworkSnapshot::capture(generation, service.resolver().catalog())
            .map(Arc::new)
            .map_err(|_| GateError("network_snapshot_capture_failed"))
    }

    async fn reset(
        coordinator: &NetworkResetCoordinator,
        service: &GateService,
    ) -> Result<NetworkResetReport, GateError> {
        tokio::time::timeout(
            RESET_TIMEOUT,
            coordinator.reset_network(
                next_snapshot(service, 2)?,
                NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest),
            ),
        )
        .await
        .map_err(|_| GateError("reset_deadline_exceeded"))?
        .map_err(|_| GateError("synthetic_reset_failed"))
    }

    fn reset_report_is_exact(report: NetworkResetReport, cancelled: usize) -> bool {
        report.outcome() == NetworkResetOutcome::ResetCompleted
            && report.published_generation() == 2
            && report.completed_resets() == 1
            && report.cancelled_runtime_owners() == cancelled
    }

    fn reset_cancellation_is_exact(cancellation: NetworkRuntimeOwnerCancellation) -> bool {
        matches!(
            cancellation,
            NetworkRuntimeOwnerCancellation::Reset(signal)
                if signal.target_generation() == 2
                    && signal.intent()
                        == NetworkResetIntent::Ordinary(NetworkResetReason::ExplicitRequest)
        )
    }

    async fn round_trip<S: DirectUdpSocket>(
        socket: &S,
        target: SocketAddr,
        sequence: u64,
    ) -> Result<u64, GateError> {
        let payload = sequence.to_le_bytes();
        let started = Instant::now();
        tokio::time::timeout(ROUND_TRIP_TIMEOUT, async {
            let sent = socket
                .send_to(&payload, target)
                .await
                .map_err(|_| GateError("loopback_send_failed"))?;
            if sent != payload.len() {
                return Err(GateError("loopback_send_truncated"));
            }
            let mut response = BytesMut::with_capacity(64);
            let (received, source) = socket
                .recv_buf_from(&mut response)
                .await
                .map_err(|_| GateError("loopback_receive_failed"))?;
            if source != target || received != payload.len() || response.as_ref() != payload {
                return Err(GateError("loopback_response_invalid"));
            }
            Ok(())
        })
        .await
        .map_err(|_| GateError("loopback_timeout"))??;
        u64::try_from(started.elapsed().as_nanos())
            .map_err(|_| GateError("latency_sample_overflow"))
    }

    async fn collect_latencies<S: DirectUdpSocket>(
        socket: &S,
        target: SocketAddr,
        samples: usize,
    ) -> Result<Vec<u64>, GateError> {
        let mut latencies = Vec::with_capacity(samples);
        for sequence in 0..samples {
            latencies.push(round_trip(socket, target, sequence as u64).await?);
        }
        Ok(latencies)
    }

    async fn bounded_stage<T>(
        timeout: Duration,
        timeout_reason: &'static str,
        future: impl std::future::Future<Output = Result<T, GateError>>,
    ) -> Result<T, GateError> {
        tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| GateError(timeout_reason))?
    }

    async fn run_qualification(evidence: &mut Value) -> Result<(), GateError> {
        let echo = match bounded_stage(
            ECHO_STAGE_TIMEOUT,
            "echo_start_deadline_exceeded",
            EchoServer::start(),
        )
        .await
        {
            Ok(echo) => echo,
            Err(error) => {
                set_failed_stage(evidence, "echo_start");
                return Err(error);
            }
        };
        if let Err(error) = bounded_stage(
            STATIC_STAGE_TIMEOUT,
            "static_stage_deadline_exceeded",
            run_static(evidence, echo.address),
        )
        .await
        {
            set_failed_stage(evidence, "static");
            return Err(error);
        }
        if let Err(error) = bounded_stage(
            DYNAMIC_STAGE_TIMEOUT,
            "dynamic_stage_deadline_exceeded",
            run_dynamic(evidence, echo.address),
        )
        .await
        {
            set_failed_stage(evidence, "dynamic");
            return Err(error);
        }
        if let Err(error) = bounded_stage(
            SCALE_1K_STAGE_TIMEOUT,
            "scale_1k_stage_deadline_exceeded",
            run_scale(evidence, echo.address, 1_000),
        )
        .await
        {
            set_failed_stage(evidence, "scale_1k");
            return Err(error);
        }
        if let Err(error) = bounded_stage(
            SCALE_10K_STAGE_TIMEOUT,
            "scale_10k_stage_deadline_exceeded",
            run_scale(evidence, echo.address, REQUIRED_SCALE_SOCKETS),
        )
        .await
        {
            set_failed_stage(evidence, "scale_10k");
            return Err(error);
        }
        let result = bounded_stage(
            ECHO_STAGE_TIMEOUT,
            "echo_cleanup_deadline_exceeded",
            echo.close(),
        )
        .await;
        if result.is_err() {
            set_failed_stage(evidence, "echo_cleanup");
        }
        result
    }

    async fn run_static(evidence: &mut Value, target: SocketAddr) -> Result<(), GateError> {
        let owners = OwnerRegistry::new();
        let (coordinator, service) = new_service(NetworkSocketMode::Static, &owners)?;
        let baseline = ResourceBaseline::capture(&owners)?;
        let socket = open_socket(&service, target)?;
        if socket.is_generation_bound() || owners.snapshot().network_runtime_owners != 0 {
            return Err(GateError("static_owner_contract_failed"));
        }
        let latencies = collect_latencies(&socket, target, LOOPBACK_SAMPLES).await?;
        record_stage(
            evidence,
            "static_loopback",
            "Static",
            1,
            &owners,
            baseline,
            &latencies,
            None,
        )?;

        let reset_report = reset(&coordinator, &service).await?;
        if !reset_report_is_exact(reset_report, 0)
            || service.published_generation() != 1
            || !service.generation_is_admissible(1)
            || service.generation_is_admissible(2)
            || socket.is_closed().await
        {
            return Err(GateError("static_reset_contract_failed"));
        }
        let after_reset = [round_trip(&socket, target, u64::MAX).await?];
        record_stage(
            evidence,
            "static_after_synthetic_reset",
            "Static",
            1,
            &owners,
            baseline,
            &after_reset,
            None,
        )?;
        evidence["contracts"]["static"] = json!({
            "generation_bound": false,
            "owners_open": 0,
            "owners_cancelled_by_reset": 0,
            "frozen_generation_after_reset": 1,
            "socket_survived_reset": true,
        });
        drop(socket);
        drop(service);
        drop(coordinator);
        let cleanup = settle_cleanup(&owners, baseline).await?;
        record_cleanup_stage(
            evidence,
            "static_cleanup",
            "Static",
            &owners,
            baseline,
            cleanup,
        )
    }

    async fn run_dynamic(evidence: &mut Value, target: SocketAddr) -> Result<(), GateError> {
        let owners = OwnerRegistry::new();
        let (coordinator, service) = new_service(NetworkSocketMode::Dynamic, &owners)?;
        let baseline = ResourceBaseline::capture(&owners)?;
        let socket = Arc::new(open_socket(&service, target)?);
        if !socket.is_generation_bound() || owners.snapshot().network_runtime_owners != 1 {
            return Err(GateError("dynamic_owner_contract_failed"));
        }
        let latencies = collect_latencies(socket.as_ref(), target, LOOPBACK_SAMPLES).await?;
        record_stage(
            evidence,
            "dynamic_loopback",
            "Dynamic",
            1,
            &owners,
            baseline,
            &latencies,
            None,
        )?;

        let pending_socket = Arc::clone(&socket);
        let (pending_tx, pending_rx) = oneshot::channel();
        let pending_receive = AbortOnDropTask::new(tokio::spawn(async move {
            let mut payload = BytesMut::with_capacity(64);
            let mut receive = Box::pin(pending_socket.recv_buf_from(&mut payload));
            let mut pending_tx = Some(pending_tx);
            std::future::poll_fn(move |context| match receive.as_mut().poll(context) {
                Poll::Pending => {
                    if let Some(pending_tx) = pending_tx.take() {
                        let _ = pending_tx.send(());
                    }
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result),
            })
            .await
        }));
        if !matches!(
            tokio::time::timeout(ROUND_TRIP_TIMEOUT, pending_rx).await,
            Ok(Ok(()))
        ) {
            pending_receive.abort().await;
            return Err(GateError("pending_receive_not_pending"));
        }
        let reset_report = match reset(&coordinator, &service).await {
            Ok(report) => report,
            Err(error) => {
                pending_receive.abort().await;
                return Err(error);
            }
        };
        if !reset_report_is_exact(reset_report, 1) {
            pending_receive.abort().await;
            return Err(GateError("dynamic_reset_owner_count_failed"));
        }
        match pending_receive.join().await {
            Ok(Err(_)) => {}
            _ => return Err(GateError("pending_receive_reset_failed")),
        }
        let mut payload = BytesMut::with_capacity(64);
        if !socket.is_closed().await
            || !socket.closed().is_some_and(reset_cancellation_is_exact)
            || socket.send_to(b"closed", target).await.is_ok()
            || socket.try_recv_buf_from(&mut payload).is_ok()
            || owners.snapshot().network_runtime_owners != 0
            || service.published_generation() != 2
            || !service.generation_is_admissible(2)
            || service.generation_is_admissible(1)
        {
            return Err(GateError("dynamic_close_contract_failed"));
        }
        record_stage(
            evidence,
            "dynamic_pending_receive_reset",
            "Dynamic",
            0,
            &owners,
            baseline,
            &[],
            None,
        )?;
        evidence["contracts"]["dynamic"] = json!({
            "generation_bound": true,
            "owners_open": 1,
            "owners_cancelled_by_reset": 1,
            "reset_outcome": "ResetCompleted",
            "reset_published_generation": 2,
            "reset_completed_count": 1,
            "reset_reason": "ExplicitRequest",
            "pending_receive_cancelled_by_reset": true,
            "socket_closed_after_reset": true,
        });
        drop(socket);
        drop(service);
        drop(coordinator);
        let cleanup = settle_cleanup(&owners, baseline).await?;
        record_cleanup_stage(
            evidence,
            "dynamic_cleanup",
            "Dynamic",
            &owners,
            baseline,
            cleanup,
        )
    }

    async fn run_scale(
        evidence: &mut Value,
        target: SocketAddr,
        socket_count: usize,
    ) -> Result<(), GateError> {
        let owners = OwnerRegistry::new();
        let (coordinator, service) = new_service(NetworkSocketMode::Dynamic, &owners)?;
        let baseline = ResourceBaseline::capture(&owners)?;
        let mut sockets = Vec::with_capacity(socket_count);
        for _ in 0..socket_count {
            match open_socket(&service, target) {
                Ok(socket) => sockets.push(socket),
                Err(error) => {
                    if error.0 == "physical_udp_open_failed" {
                        let headroom = query_udp_port_headroom()?;
                        let available = headroom.count.saturating_sub(headroom.ports_unavailable);
                        let remaining = socket_count.saturating_sub(sockets.len());
                        if available < remaining.saturating_add(PORT_HEADROOM) {
                            return Err(GateError("environment_udp_capacity_changed"));
                        }
                    }
                    return Err(error);
                }
            }
        }
        tokio::task::yield_now().await;
        if owners.snapshot().network_runtime_owners != socket_count
            || alive_tasks() != baseline.tasks
            || sockets.iter().any(|socket| !socket.is_generation_bound())
        {
            return Err(GateError("dynamic_scale_open_contract_failed"));
        }
        record_stage(
            evidence,
            &format!("dynamic_scale_{socket_count}_open"),
            "Dynamic",
            socket_count,
            &owners,
            baseline,
            &[],
            None,
        )?;

        let mut latencies = Vec::with_capacity(socket_count);
        for (sequence, socket) in sockets.iter().enumerate() {
            latencies.push(round_trip(socket, target, sequence as u64).await?);
        }
        record_stage(
            evidence,
            &format!("dynamic_scale_{socket_count}_loopback"),
            "Dynamic",
            socket_count,
            &owners,
            baseline,
            &latencies,
            None,
        )?;

        let reset_report = reset(&coordinator, &service).await?;
        if !reset_report_is_exact(reset_report, socket_count)
            || owners.snapshot().network_runtime_owners != 0
            || sockets
                .iter()
                .any(|socket| !socket.closed().is_some_and(reset_cancellation_is_exact))
            || service.published_generation() != 2
            || !service.generation_is_admissible(2)
            || service.generation_is_admissible(1)
        {
            return Err(GateError("dynamic_scale_reset_contract_failed"));
        }
        record_stage(
            evidence,
            &format!("dynamic_scale_{socket_count}_reset"),
            "Dynamic",
            0,
            &owners,
            baseline,
            &[],
            None,
        )?;
        evidence["contracts"]["scale"]
            .as_array_mut()
            .ok_or(GateError("evidence_scale_state_invalid"))?
            .push(json!({
                "requested_sockets": socket_count,
                "opened_sockets": socket_count,
                "owners_open": socket_count,
                "tokio_tasks_per_socket": 0,
                "owners_cancelled_by_reset": socket_count,
                "reset_outcome": "ResetCompleted",
                "reset_published_generation": 2,
                "reset_completed_count": 1,
                "reset_reason": "ExplicitRequest",
                "closed_sockets": socket_count,
            }));
        drop(sockets);
        drop(service);
        drop(coordinator);
        let cleanup = settle_cleanup(&owners, baseline).await?;
        record_cleanup_stage(
            evidence,
            &format!("dynamic_scale_{socket_count}_cleanup"),
            "Dynamic",
            &owners,
            baseline,
            cleanup,
        )
    }

    async fn settle_cleanup(
        owners: &OwnerRegistry,
        baseline: ResourceBaseline,
    ) -> Result<ProcessSample, GateError> {
        for _ in 0..CLEANUP_RETRIES {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let latest = process_sample()?;
            if owners.snapshot() == baseline.owners
                && alive_tasks() == baseline.tasks
                && latest.physical_udp_endpoints == baseline.process.physical_udp_endpoints
                && latest.threads <= baseline.process.threads
                && latest.handles <= baseline.process.handles
            {
                return Ok(latest);
            }
        }
        Err(GateError("cleanup_did_not_return_to_baseline"))
    }

    fn record_cleanup_stage(
        evidence: &mut Value,
        stage: &str,
        mode: &str,
        owners: &OwnerRegistry,
        baseline: ResourceBaseline,
        process: ProcessSample,
    ) -> Result<(), GateError> {
        let cleanup = owners.snapshot() == baseline.owners
            && alive_tasks() == baseline.tasks
            && process.physical_udp_endpoints == baseline.process.physical_udp_endpoints
            && process.threads <= baseline.process.threads
            && process.handles <= baseline.process.handles;
        if !cleanup {
            return Err(GateError("cleanup_did_not_return_to_baseline"));
        }
        record_stage_with_sample(
            evidence,
            stage,
            mode,
            0,
            owners,
            baseline,
            &[],
            Some(cleanup),
            process,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_stage(
        evidence: &mut Value,
        stage: &str,
        mode: &str,
        expected_physical_udp_sockets: usize,
        owners: &OwnerRegistry,
        baseline: ResourceBaseline,
        latencies: &[u64],
        cleanup_at_baseline: Option<bool>,
    ) -> Result<(), GateError> {
        record_stage_with_sample(
            evidence,
            stage,
            mode,
            expected_physical_udp_sockets,
            owners,
            baseline,
            latencies,
            cleanup_at_baseline,
            process_sample()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_stage_with_sample(
        evidence: &mut Value,
        stage: &str,
        mode: &str,
        expected_physical_udp_sockets: usize,
        owners: &OwnerRegistry,
        baseline: ResourceBaseline,
        latencies: &[u64],
        cleanup_at_baseline: Option<bool>,
        process: ProcessSample,
    ) -> Result<(), GateError> {
        let physical_udp_sockets = process
            .physical_udp_endpoints
            .checked_sub(baseline.process.physical_udp_endpoints)
            .ok_or(GateError("physical_udp_endpoint_count_below_baseline"))?;
        if physical_udp_sockets != expected_physical_udp_sockets {
            return Err(GateError("physical_udp_endpoint_count_mismatch"));
        }
        let alive = alive_tasks();
        let task_delta = alive.saturating_sub(baseline.tasks);
        let tasks_per_socket_ppm = (physical_udp_sockets != 0).then(|| {
            task_delta
                .saturating_mul(1_000_000)
                .checked_div(physical_udp_sockets)
                .unwrap_or_default()
        });
        let (p50, p99) = latency_percentiles(latencies);
        let stage = json!({
            "stage": stage,
            "mode": mode,
            "physical_udp_sockets": physical_udp_sockets,
            "process_udp_endpoints": process.physical_udp_endpoints,
            "network_runtime_owners": owners.snapshot().network_runtime_owners,
            "network_reset_hooks": owners.snapshot().network_reset_hooks,
            "network_reset_drivers": owners.snapshot().network_reset_drivers,
            "tokio_alive_tasks": alive,
            "tokio_task_delta_from_baseline": task_delta,
            "tasks_per_socket_ppm": tasks_per_socket_ppm,
            "working_set_bytes": process.working_set_bytes,
            "private_memory_bytes": process.private_memory_bytes,
            "threads": process.threads,
            "handle_count": process.handles,
            "loopback_p50_ns": p50,
            "loopback_p99_ns": p99,
            "cleanup_at_baseline": cleanup_at_baseline,
        });
        evidence["stages"]
            .as_array_mut()
            .ok_or(GateError("evidence_stage_state_invalid"))?
            .push(stage);
        Ok(())
    }

    fn latency_percentiles(samples: &[u64]) -> (Option<u64>, Option<u64>) {
        if samples.is_empty() {
            return (None, None);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        (
            Some(sorted[nearest_rank_index(sorted.len(), 50)]),
            Some(sorted[nearest_rank_index(sorted.len(), 99)]),
        )
    }

    fn nearest_rank_index(samples: usize, percentile: usize) -> usize {
        samples
            .saturating_mul(percentile)
            .div_ceil(100)
            .saturating_sub(1)
            .min(samples.saturating_sub(1))
    }

    #[cfg(test)]
    mod tests {
        use super::nearest_rank_index;

        #[test]
        fn nearest_rank_percentiles_cover_small_and_gate_sample_counts() {
            assert_eq!(
                (nearest_rank_index(1, 50), nearest_rank_index(1, 99)),
                (0, 0)
            );
            assert_eq!(
                (nearest_rank_index(2, 50), nearest_rank_index(2, 99)),
                (0, 1)
            );
            assert_eq!(
                (nearest_rank_index(100, 50), nearest_rank_index(100, 99)),
                (49, 98)
            );
            assert_eq!(
                (nearest_rank_index(256, 50), nearest_rank_index(256, 99)),
                (127, 253)
            );
        }
    }
}

#[cfg(windows)]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    std::process::exit(windows_gate::entry().await);
}
