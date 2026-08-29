use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::dns_resource::{prove_tcp_rebind, prove_tcp_udp_rebind, prove_udp_rebind};
use super::evidence_support::{PortReservation, TcpUdpReservation, profile_binary, spawn_proxy};
use super::process_support::{
    IO_TIMEOUT, ProcessGuard, STARTUP_TIMEOUT, StartGate, clean_io, join_worker, spawn_worker, v4,
    wait_for_listener,
};
#[cfg(feature = "structural-diagnostic")]
use super::process_support::{remaining, wait_for_metrics};
use super::profile_contract::{
    PROFILE_UDP_MAX_BUFFERED_BYTES, ProfileArgs, ProfileOutcome, ProfileUdpTopology, ReadyFile,
    Topology,
};
use super::profile_output::{
    ensure_profile_workers_running, wait_for_profile_phase_optional_server,
};
use super::profile_structural::StructuralMetrics;
use super::proxy_config::{
    profile_direct_udp_client_axis_config, profile_shadowsocks_udp_client_axis_config,
    profile_udp_server_axis_config, profile_udp_server_config,
};
use super::resource::{M14UdpRoundTripBuffers, m14_udp_associate, m14_udp_round_trip_reused};
#[cfg(feature = "structural-diagnostic")]
use super::structural_contract::{StructuralMeasurement, StructuralSnapshot, capture, measure};
use super::throughput::{rate_per_second, transfer_is_measured};

const UDP_WORKER_LATENCY_SAMPLE_CAP: usize = 2_000_000;

pub(super) fn run_profile_udp(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    run_profile_udp_axis(arguments, ready_file, ProfileUdpAxis::standard()).map(|run| run.outcome)
}

#[derive(Clone, Copy)]
struct ProfileUdpAxis {
    server_receive_workers: usize,
    logical_sessions: usize,
    collect_diagnostics: bool,
}

impl ProfileUdpAxis {
    fn standard() -> Self {
        Self {
            server_receive_workers: 1,
            logical_sessions: 0,
            collect_diagnostics: false,
        }
    }
}

struct ProfileUdpRun {
    outcome: ProfileOutcome,
    #[cfg(feature = "structural-diagnostic")]
    diagnostics: Option<UdpWorkerDiagnostics>,
}

#[cfg(feature = "structural-diagnostic")]
pub(super) struct UdpWorkerDiagnostics {
    pub(super) structural: StructuralMeasurement,
    pub(super) client_process: ProcessDiagnosticDelta,
    pub(super) server_process: ProcessDiagnosticDelta,
    pub(super) latency_sample_count: u64,
}

#[cfg(feature = "structural-diagnostic")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessDiagnosticDelta {
    pub(super) cpu_nanoseconds: u64,
    pub(super) voluntary_context_switches: u64,
    pub(super) involuntary_context_switches: u64,
}

#[cfg(feature = "structural-diagnostic")]
pub(super) struct UdpWorkerProfileRun {
    pub(super) outcome: ProfileOutcome,
    pub(super) diagnostics: UdpWorkerDiagnostics,
}

#[cfg(feature = "structural-diagnostic")]
pub(super) fn run_udp_worker_profile(
    arguments: &ProfileArgs,
    ready_file: &Path,
    server_receive_workers: usize,
    logical_sessions: usize,
) -> Result<UdpWorkerProfileRun, String> {
    if !matches!(server_receive_workers, 1 | 2 | 4 | 8) {
        return Err("UDP worker axis is outside 1/2/4/8".to_owned());
    }
    if !matches!(logical_sessions, 1 | 32) {
        return Err("UDP session topology must contain 1 or 32 logical sessions".to_owned());
    }
    let run = run_profile_udp_axis(
        arguments,
        ready_file,
        ProfileUdpAxis {
            server_receive_workers,
            logical_sessions,
            collect_diagnostics: true,
        },
    )?;
    Ok(UdpWorkerProfileRun {
        outcome: run.outcome,
        diagnostics: run
            .diagnostics
            .ok_or_else(|| "UDP worker diagnostics are missing".to_owned())?,
    })
}

fn run_profile_udp_axis(
    arguments: &ProfileArgs,
    ready_file: &Path,
    axis: ProfileUdpAxis,
) -> Result<ProfileUdpRun, String> {
    let topology = arguments
        .scenario
        .udp_topology()
        .expect("UDP scenario has a topology");
    let payload_bytes = arguments
        .scenario
        .udp_payload_bytes()
        .expect("UDP scenario has a payload size");
    let scenario_workers = arguments
        .scenario
        .udp_workers()
        .expect("UDP scenario has a worker count");
    let udp_workers = if axis.logical_sessions == 0 {
        scenario_workers
    } else {
        axis.logical_sessions
    };
    let max_sessions = udp_workers.max(16);
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-udp-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let mut server_reservation = match topology {
        ProfileUdpTopology::Shadowsocks => Some(TcpUdpReservation::new()?),
        ProfileUdpTopology::Direct => None,
    };
    let mut proxy_reservation = Some(PortReservation::new()?);
    #[cfg(feature = "structural-diagnostic")]
    let mut client_metrics_reservation = axis
        .collect_diagnostics
        .then(PortReservation::new)
        .transpose()?;
    #[cfg(feature = "structural-diagnostic")]
    let mut server_metrics_reservation = axis
        .collect_diagnostics
        .then(PortReservation::new)
        .transpose()?;
    let server = server_reservation.as_ref().map(|slot| slot.address);
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    #[cfg(feature = "structural-diagnostic")]
    let client_metrics = client_metrics_reservation.as_ref().map(|slot| slot.address);
    #[cfg(not(feature = "structural-diagnostic"))]
    let client_metrics = None;
    #[cfg(feature = "structural-diagnostic")]
    let server_metrics = server_metrics_reservation.as_ref().map(|slot| slot.address);
    #[cfg(not(feature = "structural-diagnostic"))]
    let server_metrics = None;
    let client_config = directory
        .as_ref()
        .expect("profile config owner")
        .path()
        .join("client.toml");
    let server_config = directory
        .as_ref()
        .expect("profile config owner")
        .path()
        .join("server.toml");
    let mut server_process = None;
    let mut client_process = None;
    let mut prepared = Vec::with_capacity(udp_workers);
    let mut target_addresses = Vec::with_capacity(udp_workers);
    let mut application_addresses = Vec::with_capacity(udp_workers);
    let mut relay_addresses = Vec::with_capacity(udp_workers);
    let gate = Arc::new(StartGate::default());
    #[cfg(feature = "structural-diagnostic")]
    let active_gate = axis
        .collect_diagnostics
        .then(|| Arc::new(StartGate::default()));
    #[cfg(not(feature = "structural-diagnostic"))]
    let active_gate: Option<Arc<StartGate>> = None;
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let active_inflight = Arc::new(AtomicUsize::new(0));
    let active_peak = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(udp_workers);
    let mut errors = Vec::new();
    let mut ready = None;
    #[cfg(feature = "structural-diagnostic")]
    let mut structural_before: Option<(StructuralSnapshot, StructuralSnapshot)> = None;
    #[cfg(feature = "structural-diagnostic")]
    let mut structural_after: Option<(StructuralSnapshot, StructuralSnapshot)> = None;
    #[cfg(feature = "structural-diagnostic")]
    let mut process_before: Option<(ProcessDiagnosticSnapshot, ProcessDiagnosticSnapshot)> = None;
    #[cfg(feature = "structural-diagnostic")]
    let mut process_after: Option<(ProcessDiagnosticSnapshot, ProcessDiagnosticSnapshot)> = None;
    let execution = (|| -> Result<(), String> {
        let client_source = match topology {
            ProfileUdpTopology::Shadowsocks => {
                let server = server.expect("Shadowsocks UDP server address");
                profile_shadowsocks_udp_client_axis_config(
                    proxy,
                    server,
                    max_sessions,
                    client_metrics,
                )
            }
            ProfileUdpTopology::Direct => {
                profile_direct_udp_client_axis_config(proxy, max_sessions, client_metrics)
            }
        };
        fs::write(&client_config, client_source).map_err(clean_io)?;
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        if topology == ProfileUdpTopology::Shadowsocks {
            let server = server.expect("Shadowsocks UDP server address");
            let server_source = if axis.collect_diagnostics {
                profile_udp_server_axis_config(
                    server,
                    PROFILE_UDP_MAX_BUFFERED_BYTES,
                    max_sessions,
                    axis.server_receive_workers,
                    server_metrics,
                )
            } else {
                profile_udp_server_config(server, PROFILE_UDP_MAX_BUFFERED_BYTES, max_sessions)
            };
            fs::write(&server_config, server_source).map_err(clean_io)?;
            let server_binary = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
            server_reservation
                .take()
                .expect("server reservation")
                .release();
            #[cfg(feature = "structural-diagnostic")]
            if let Some(reservation) = server_metrics_reservation.take() {
                reservation.release();
            }
            server_process = Some(spawn_proxy(
                Topology::Ferrum,
                "profile UDP server",
                &server_binary,
                &server_config,
            )?);
            wait_for_listener(server_process.as_mut().expect("server process"), server)?;
            #[cfg(feature = "structural-diagnostic")]
            if let Some(metrics) = server_metrics {
                wait_for_metrics(server_process.as_mut().expect("server process"), metrics)?;
            }
        }
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        #[cfg(feature = "structural-diagnostic")]
        if let Some(reservation) = client_metrics_reservation.take() {
            reservation.release();
        }
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile UDP client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), proxy)?;
        #[cfg(feature = "structural-diagnostic")]
        if let Some(metrics) = client_metrics {
            wait_for_metrics(client_process.as_mut().expect("client process"), metrics)?;
        }
        for worker_index in 0..udp_workers {
            let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
            target
                .set_read_timeout(Some(IO_TIMEOUT))
                .map_err(clean_io)?;
            target
                .set_write_timeout(Some(IO_TIMEOUT))
                .map_err(clean_io)?;
            let target_address = v4(target.local_addr().map_err(clean_io)?)?;
            let (control, application, relay) = m14_udp_associate(proxy)?;
            let application_address = v4(application.local_addr().map_err(clean_io)?)?;
            target_addresses.push(target_address);
            application_addresses.push(application_address);
            relay_addresses.push(relay);
            prepared.push((
                worker_index,
                control,
                application,
                relay,
                target,
                target_address,
            ));
        }
        for (worker_index, control, application, relay, target, target_address) in
            std::mem::take(&mut prepared)
        {
            let worker_gate = Arc::clone(&gate);
            let worker_active_gate = active_gate.as_ref().map(Arc::clone);
            let worker_stop = Arc::clone(&stop);
            let failure_gate = Arc::clone(&gate);
            let failure_stop = Arc::clone(&stop);
            let worker_inflight = Arc::clone(&active_inflight);
            let worker_peak = Arc::clone(&active_peak);
            workers.push(spawn_worker(move || {
                let latency_sample_cap = (UDP_WORKER_LATENCY_SAMPLE_CAP / udp_workers).max(1);
                let result = if axis.collect_diagnostics {
                    profile_udp_load::<true>(
                        worker_index,
                        control,
                        application,
                        relay,
                        target,
                        target_address,
                        worker_gate,
                        worker_stop,
                        warmup,
                        active,
                        payload_bytes,
                        worker_inflight,
                        worker_peak,
                        worker_active_gate,
                        latency_sample_cap,
                    )
                } else {
                    profile_udp_load::<false>(
                        worker_index,
                        control,
                        application,
                        relay,
                        target,
                        target_address,
                        worker_gate,
                        worker_stop,
                        warmup,
                        active,
                        payload_bytes,
                        worker_inflight,
                        worker_peak,
                        worker_active_gate,
                        latency_sample_cap,
                    )
                };
                if result.is_err() {
                    failure_stop.store(true, Ordering::SeqCst);
                    failure_gate.cancel();
                }
                result
            })?);
        }
        let start = gate.start_when_ready(udp_workers, Instant::now() + STARTUP_TIMEOUT)?;
        let warm_end = start + warmup;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(udp_workers)?;
        client_process
            .as_mut()
            .expect("client process")
            .ensure_running()?;
        if let Some(process) = server_process.as_mut() {
            process.ensure_running()?;
        }
        ensure_profile_workers_running(&gate, &workers)?;
        #[cfg(feature = "structural-diagnostic")]
        if let Some(active_gate) = active_gate.as_ref() {
            wait_for_gate_ready(active_gate, udp_workers, Instant::now() + STARTUP_TIMEOUT)?;
            let client = client_process.as_ref().expect("client process");
            let server_process_ref = server_process
                .as_ref()
                .ok_or_else(|| "UDP worker diagnostics require a server process".to_owned())?;
            let client_metrics = client_metrics
                .ok_or_else(|| "UDP worker client metrics address is missing".to_owned())?;
            let server_metrics = server_metrics
                .ok_or_else(|| "UDP worker server metrics address is missing".to_owned())?;
            let deadline = Instant::now() + IO_TIMEOUT;
            let client_before = capture(client_metrics, deadline)?;
            let server_before = capture(server_metrics, deadline)?;
            if client_before.overflowed || server_before.overflowed {
                return Err(
                    "UDP worker structural baseline overflow invalidates the trial".to_owned(),
                );
            }
            structural_before = Some((client_before, server_before));
            process_before = Some((
                read_process_diagnostic(client.id())?,
                read_process_diagnostic(server_process_ref.id())?,
            ));
        }
        let active_start = match active_gate.as_ref() {
            Some(active_gate) => {
                active_gate.start_when_ready(udp_workers, Instant::now() + STARTUP_TIMEOUT)?
            }
            None => warm_end,
        };
        let active_end = active_start + active;
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            client_process.as_ref().expect("client process").id(),
            server_process.as_ref().map(ProcessGuard::id),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            active_end,
            false,
        )?;
        #[cfg(feature = "structural-diagnostic")]
        if axis.collect_diagnostics {
            wait_for_worker_completion(&workers, Instant::now() + STARTUP_TIMEOUT)?;
            let client = client_process.as_ref().expect("client process");
            let server_process_ref = server_process
                .as_ref()
                .ok_or_else(|| "UDP worker diagnostics require a server process".to_owned())?;
            let client_metrics = client_metrics
                .ok_or_else(|| "UDP worker client metrics address is missing".to_owned())?;
            let server_metrics = server_metrics
                .ok_or_else(|| "UDP worker server metrics address is missing".to_owned())?;
            let deadline = Instant::now() + IO_TIMEOUT;
            structural_after = Some((
                capture(client_metrics, deadline)?,
                capture(server_metrics, deadline)?,
            ));
            process_after = Some((
                read_process_diagnostic(client.id())?,
                read_process_diagnostic(server_process_ref.id())?,
            ));
        }
        Ok(())
    })();
    let execution_succeeded = execution.is_ok();
    if let Err(error) = execution {
        errors.push(error);
    }
    if let Some(owner) = ready.take()
        && let Err(error) = owner.remove()
    {
        errors.push(format!("ready cleanup failed: {error}"));
    }
    stop.store(true, Ordering::SeqCst);
    gate.cancel();
    if let Some(active_gate) = active_gate.as_ref() {
        active_gate.cancel();
    }
    drop(prepared);
    let mut datagrams = 0_usize;
    let mut latency_samples = Vec::new();
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(result) => {
                match datagrams.checked_add(result.datagrams) {
                    Some(total) => datagrams = total,
                    None => errors.push("profile UDP datagram count overflow".to_owned()),
                }
                if latency_samples
                    .len()
                    .checked_add(result.latency_nanoseconds.len())
                    .is_some_and(|length| length <= UDP_WORKER_LATENCY_SAMPLE_CAP)
                {
                    latency_samples.extend(result.latency_nanoseconds);
                } else {
                    errors.push("profile UDP latency sample bound was exceeded".to_owned());
                }
            }
            Err(error) => errors.push(error),
        }
    }
    if execution_succeeded && datagrams == 0 {
        errors.push("profile UDP completed no validated datagrams".to_owned());
    }
    for process in [&mut client_process, &mut server_process] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("process cleanup failed: {error}"));
        }
    }
    drop((client_process.take(), server_process.take()));
    drop((proxy_reservation.take(), server_reservation.take()));
    #[cfg(feature = "structural-diagnostic")]
    drop((
        client_metrics_reservation.take(),
        server_metrics_reservation.take(),
    ));
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("config cleanup failed: {error}"));
    }
    let mut rebind_results = vec![prove_tcp_rebind(proxy, "profile UDP client")];
    if let Some(server) = server {
        rebind_results.push(prove_tcp_udp_rebind(server, "profile UDP server"));
    }
    if let Some(metrics) = client_metrics {
        rebind_results.push(prove_tcp_rebind(metrics, "profile UDP client metrics"));
    }
    if let Some(metrics) = server_metrics {
        rebind_results.push(prove_tcp_rebind(metrics, "profile UDP server metrics"));
    }
    for result in rebind_results {
        if let Err(error) = result {
            errors.push(format!("rebind failed: {error}"));
        }
    }
    for (kind, addresses) in [
        ("target", target_addresses),
        ("application", application_addresses),
        ("relay", relay_addresses),
    ] {
        for address in addresses {
            if let Err(error) = prove_udp_rebind(address, &format!("profile UDP {kind}")) {
                errors.push(format!("rebind failed: {error}"));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let summary = format!(
        "m18_profile_workload_completion status=PASS scenario={} topology={} \
         datagrams={datagrams} workers={udp_workers} \
         application_payload_bytes={payload_bytes} socks_datagram_bytes={} \
         upstream_wire_bytes={} warmup_seconds={} active_seconds={} drain=PASS rebind=PASS",
        arguments.scenario.label(),
        topology.label(),
        arguments
            .scenario
            .socks_datagram_bytes()
            .expect("UDP SOCKS size"),
        arguments
            .scenario
            .upstream_wire_bytes()
            .expect("UDP wire size"),
        arguments.warmup_seconds,
        arguments.active_seconds,
    );
    let checked_units =
        u64::try_from(datagrams).map_err(|_| "profile UDP datagram count overflow".to_owned())?;
    let p99_nanoseconds = if axis.collect_diagnostics {
        Some(nearest_rank_p99(&mut latency_samples)?)
    } else {
        None
    };
    let outcome = ProfileOutcome {
        summary,
        metric: "datagrams_per_second",
        value: rate_per_second(checked_units, active)?,
        checked_units,
        p99_nanoseconds,
        io_completions: checked_units.saturating_mul(4),
        scale_json: None,
        structural_metrics: StructuralMetrics::network(
            u64::try_from(active_peak.load(Ordering::SeqCst))
                .map_err(|_| "profile UDP peak inflight overflow".to_owned())?,
            0,
        ),
    };
    #[cfg(feature = "structural-diagnostic")]
    let diagnostics = if axis.collect_diagnostics {
        let (client_before, server_before) = structural_before
            .ok_or_else(|| "UDP worker structural baseline is missing".to_owned())?;
        let (client_after, server_after) = structural_after
            .ok_or_else(|| "UDP worker structural final snapshot is missing".to_owned())?;
        let (client_process_before, server_process_before) =
            process_before.ok_or_else(|| "UDP worker process baseline is missing".to_owned())?;
        let (client_process_after, server_process_after) = process_after
            .ok_or_else(|| "UDP worker process final snapshot is missing".to_owned())?;
        Some(UdpWorkerDiagnostics {
            structural: measure(client_before, client_after, server_before, server_after)?,
            client_process: process_diagnostic_delta(
                client_process_before,
                client_process_after,
                "client",
            )?,
            server_process: process_diagnostic_delta(
                server_process_before,
                server_process_after,
                "server",
            )?,
            latency_sample_count: u64::try_from(latency_samples.len())
                .map_err(|_| "profile UDP latency sample count overflow".to_owned())?,
        })
    } else {
        None
    };
    Ok(ProfileUdpRun {
        outcome,
        #[cfg(feature = "structural-diagnostic")]
        diagnostics,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn profile_udp_load<const COLLECT_LATENCY: bool>(
    worker_index: usize,
    _control: TcpStream,
    application: UdpSocket,
    relay: SocketAddrV4,
    target: UdpSocket,
    target_address: SocketAddrV4,
    gate: Arc<StartGate>,
    stop: Arc<AtomicBool>,
    warmup: Duration,
    active: Duration,
    payload_bytes: usize,
    active_inflight: Arc<AtomicUsize>,
    active_peak: Arc<AtomicUsize>,
    active_gate: Option<Arc<StartGate>>,
    latency_sample_cap: usize,
) -> Result<ProfileUdpWorkerResult, String> {
    let mut payload = vec![0x5a; payload_bytes];
    payload[8] = u8::try_from(worker_index).expect("profile UDP worker index");
    let mut buffers = M14UdpRoundTripBuffers::new(target_address, payload_bytes)?;
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let mut sequence = 0_u64;
    let mut reported_valid = false;
    while Instant::now() < warm_end && !stop.load(Ordering::SeqCst) {
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        m14_udp_round_trip_reused(&application, relay, &target, &payload, &mut buffers)?;
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "profile UDP sequence overflow".to_owned())?;
    }
    let active_start = match active_gate {
        Some(active_gate) => active_gate.ready_and_wait()?,
        None => warm_end,
    };
    let active_end = active_start + active;
    let mut counted = 0_usize;
    let mut latency_nanoseconds = Vec::with_capacity(if COLLECT_LATENCY {
        latency_sample_cap.min(16_384)
    } else {
        0
    });
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let transfer_start = Instant::now();
        let inflight = active_inflight.fetch_add(1, Ordering::SeqCst) + 1;
        active_peak.fetch_max(inflight, Ordering::SeqCst);
        let round_trip =
            m14_udp_round_trip_reused(&application, relay, &target, &payload, &mut buffers);
        active_inflight.fetch_sub(1, Ordering::SeqCst);
        round_trip?;
        let completion = Instant::now();
        if transfer_is_measured(transfer_start, completion, active_start, active_end) {
            counted = counted
                .checked_add(1)
                .ok_or_else(|| "profile UDP datagram count overflow".to_owned())?;
            if COLLECT_LATENCY && latency_nanoseconds.len() < latency_sample_cap {
                latency_nanoseconds.push(
                    u64::try_from(completion.duration_since(transfer_start).as_nanos())
                        .map_err(|_| "profile UDP latency sample overflow".to_owned())?,
                );
            }
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "profile UDP sequence overflow".to_owned())?;
    }
    Ok(ProfileUdpWorkerResult {
        datagrams: counted,
        latency_nanoseconds,
    })
}

pub(super) struct ProfileUdpWorkerResult {
    datagrams: usize,
    latency_nanoseconds: Vec<u64>,
}

pub(super) fn nearest_rank_p99(samples: &mut [u64]) -> Result<u64, String> {
    if samples.is_empty() {
        return Err("profile UDP p99 sample set is empty".to_owned());
    }
    samples.sort_unstable();
    let rank = samples
        .len()
        .checked_mul(99)
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .ok_or_else(|| "profile UDP p99 rank overflow".to_owned())?;
    samples
        .get(rank.saturating_sub(1))
        .copied()
        .ok_or_else(|| "profile UDP p99 rank is outside the sample set".to_owned())
}

#[cfg(feature = "structural-diagnostic")]
#[derive(Clone, Copy)]
struct ProcessDiagnosticSnapshot {
    cpu_nanoseconds: u64,
    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
}

#[cfg(feature = "structural-diagnostic")]
fn wait_for_gate_ready(gate: &StartGate, expected: usize, deadline: Instant) -> Result<(), String> {
    let mut state = gate
        .state
        .lock()
        .map_err(|_| "UDP active gate is poisoned".to_owned())?;
    while state.ready != expected && !state.cancelled {
        let timeout = remaining(deadline)?;
        let (next, result) = gate
            .changed
            .wait_timeout(state, timeout)
            .map_err(|_| "UDP active gate is poisoned".to_owned())?;
        state = next;
        if result.timed_out() && state.ready != expected {
            return Err("UDP workers did not reach the diagnostic active gate".to_owned());
        }
    }
    if state.cancelled {
        return Err("UDP diagnostic active gate was cancelled".to_owned());
    }
    Ok(())
}

#[cfg(feature = "structural-diagnostic")]
fn wait_for_worker_completion<T>(
    workers: &[std::thread::JoinHandle<Result<T, String>>],
    deadline: Instant,
) -> Result<(), String> {
    while workers.iter().any(|worker| !worker.is_finished()) {
        std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
    }
    Ok(())
}

#[cfg(feature = "structural-diagnostic")]
fn read_process_diagnostic(pid: u32) -> Result<ProcessDiagnosticSnapshot, String> {
    let task_root = std::path::PathBuf::from(format!("/proc/{pid}/task"));
    let mut tasks = fs::read_dir(&task_root)
        .map_err(|_| "UDP worker process task state is unavailable".to_owned())?
        .map(|entry| {
            entry
                .map_err(clean_io)
                .map(|entry| entry.path())
                .and_then(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
                        .map(|_| path.clone())
                        .ok_or_else(|| "UDP worker process task entry is malformed".to_owned())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    tasks.sort();
    if tasks.is_empty() || tasks.len() > 256 {
        return Err("UDP worker process task count is outside its finite bound".to_owned());
    }
    let mut total = ProcessDiagnosticSnapshot {
        cpu_nanoseconds: 0,
        voluntary_context_switches: 0,
        involuntary_context_switches: 0,
    };
    for task in tasks {
        let schedstat = fs::read_to_string(task.join("schedstat"))
            .map_err(|_| "UDP worker task schedstat is unavailable".to_owned())?;
        let cpu_nanoseconds = schedstat
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "UDP worker task schedstat is malformed".to_owned())?
            .parse::<u64>()
            .map_err(|_| "UDP worker task schedstat is malformed".to_owned())?;
        let status = fs::read_to_string(task.join("status"))
            .map_err(|_| "UDP worker task status is unavailable".to_owned())?;
        let context_switches = |prefix: &str| {
            let mut values = status.lines().filter_map(|line| {
                line.strip_prefix(prefix)
                    .map(str::trim)
                    .and_then(|value| value.parse::<u64>().ok())
            });
            let value = values
                .next()
                .ok_or_else(|| "UDP worker context-switch evidence is malformed".to_owned())?;
            if values.next().is_some() {
                return Err("UDP worker context-switch evidence is duplicated".to_owned());
            }
            Ok(value)
        };
        total.cpu_nanoseconds = total
            .cpu_nanoseconds
            .checked_add(cpu_nanoseconds)
            .ok_or_else(|| "UDP worker process CPU evidence overflow".to_owned())?;
        total.voluntary_context_switches = total
            .voluntary_context_switches
            .checked_add(context_switches("voluntary_ctxt_switches:")?)
            .ok_or_else(|| "UDP worker voluntary context-switch evidence overflow".to_owned())?;
        total.involuntary_context_switches = total
            .involuntary_context_switches
            .checked_add(context_switches("nonvoluntary_ctxt_switches:")?)
            .ok_or_else(|| "UDP worker involuntary context-switch evidence overflow".to_owned())?;
    }
    Ok(total)
}

#[cfg(feature = "structural-diagnostic")]
fn process_diagnostic_delta(
    before: ProcessDiagnosticSnapshot,
    after: ProcessDiagnosticSnapshot,
    process: &str,
) -> Result<ProcessDiagnosticDelta, String> {
    let delta = |before: u64, after: u64, field: &str| {
        after
            .checked_sub(before)
            .ok_or_else(|| format!("UDP worker {process} {field} counter decreased"))
    };
    Ok(ProcessDiagnosticDelta {
        cpu_nanoseconds: delta(before.cpu_nanoseconds, after.cpu_nanoseconds, "CPU")?,
        voluntary_context_switches: delta(
            before.voluntary_context_switches,
            after.voluntary_context_switches,
            "voluntary context switch",
        )?,
        involuntary_context_switches: delta(
            before.involuntary_context_switches,
            after.involuntary_context_switches,
            "involuntary context switch",
        )?,
    })
}
