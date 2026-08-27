use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::dns_resource::{prove_tcp_rebind, prove_tcp_udp_rebind, prove_udp_rebind};
use super::evidence_support::{PortReservation, TcpUdpReservation, profile_binary, spawn_proxy};
use super::process_support::{
    IO_TIMEOUT, ProcessGuard, STARTUP_TIMEOUT, StartGate, clean_io, join_worker, spawn_worker, v4,
    wait_for_listener,
};
use super::profile_contract::{
    PROFILE_UDP_MAX_BUFFERED_BYTES, PROFILE_UDP_WORKERS, ProfileArgs, ProfileOutcome,
    ProfileUdpTopology, ReadyFile, Topology,
};
use super::profile_output::{
    ensure_profile_workers_running, wait_for_profile_phase_optional_server,
};
use super::proxy_config::{
    m14_udp_server_config, profile_direct_udp_client_config, profile_shadowsocks_udp_client_config,
};
use super::resource::{M14UdpRoundTripBuffers, m14_udp_associate, m14_udp_round_trip_reused};
use super::throughput::{rate_per_second, transfer_is_measured};

pub(super) fn run_profile_udp(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let topology = arguments
        .scenario
        .udp_topology()
        .expect("UDP scenario has a topology");
    let payload_bytes = arguments
        .scenario
        .udp_payload_bytes()
        .expect("UDP scenario has a payload size");
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
    let server = server_reservation.as_ref().map(|slot| slot.address);
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
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
    let mut prepared = Vec::with_capacity(PROFILE_UDP_WORKERS);
    let mut target_addresses = Vec::with_capacity(PROFILE_UDP_WORKERS);
    let mut application_addresses = Vec::with_capacity(PROFILE_UDP_WORKERS);
    let mut relay_addresses = Vec::with_capacity(PROFILE_UDP_WORKERS);
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let mut workers = Vec::with_capacity(PROFILE_UDP_WORKERS);
    let mut errors = Vec::new();
    let mut ready = None;
    let execution = (|| -> Result<(), String> {
        let client_source = match topology {
            ProfileUdpTopology::Shadowsocks => {
                let server = server.expect("Shadowsocks UDP server address");
                profile_shadowsocks_udp_client_config(proxy, server)
            }
            ProfileUdpTopology::Direct => profile_direct_udp_client_config(proxy),
        };
        fs::write(&client_config, client_source).map_err(clean_io)?;
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        if topology == ProfileUdpTopology::Shadowsocks {
            let server = server.expect("Shadowsocks UDP server address");
            fs::write(
                &server_config,
                m14_udp_server_config(server, PROFILE_UDP_MAX_BUFFERED_BYTES),
            )
            .map_err(clean_io)?;
            let server_binary = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
            server_reservation
                .take()
                .expect("server reservation")
                .release();
            server_process = Some(spawn_proxy(
                Topology::Ferrum,
                "profile UDP server",
                &server_binary,
                &server_config,
            )?);
            wait_for_listener(server_process.as_mut().expect("server process"), server)?;
        }
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile UDP client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), proxy)?;
        for worker_index in 0..PROFILE_UDP_WORKERS {
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
            let worker_stop = Arc::clone(&stop);
            let failure_gate = Arc::clone(&gate);
            let failure_stop = Arc::clone(&stop);
            workers.push(spawn_worker(move || {
                let result = profile_udp_load(
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
                );
                if result.is_err() {
                    failure_stop.store(true, Ordering::SeqCst);
                    failure_gate.cancel();
                }
                result
            })?);
        }
        let start = gate.start_when_ready(PROFILE_UDP_WORKERS, Instant::now() + STARTUP_TIMEOUT)?;
        let warm_end = start + warmup;
        let active_end = warm_end + active;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(PROFILE_UDP_WORKERS)?;
        client_process
            .as_mut()
            .expect("client process")
            .ensure_running()?;
        if let Some(process) = server_process.as_mut() {
            process.ensure_running()?;
        }
        ensure_profile_workers_running(&gate, &workers)?;
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
        )
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
    drop(prepared);
    let mut datagrams = 0_usize;
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(count) => match datagrams.checked_add(count) {
                Some(total) => datagrams = total,
                None => errors.push("profile UDP datagram count overflow".to_owned()),
            },
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
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("config cleanup failed: {error}"));
    }
    let mut rebind_results = vec![prove_tcp_rebind(proxy, "profile UDP client")];
    if let Some(server) = server {
        rebind_results.push(prove_tcp_udp_rebind(server, "profile UDP server"));
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
         datagrams={datagrams} workers={PROFILE_UDP_WORKERS} \
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
    Ok(ProfileOutcome {
        summary,
        metric: "datagrams_per_second",
        value: rate_per_second(checked_units, active)?,
        checked_units,
        p99_nanoseconds: None,
        io_completions: checked_units.saturating_mul(4),
        scale_json: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn profile_udp_load(
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
) -> Result<usize, String> {
    let mut payload = vec![0x5a; payload_bytes];
    payload[8] = u8::try_from(worker_index).expect("profile UDP worker index");
    let mut buffers = M14UdpRoundTripBuffers::new(target_address, payload_bytes)?;
    let started = gate.ready_and_wait()?;
    let warm_end = started + warmup;
    let active_end = warm_end + active;
    let mut sequence = 0_u64;
    let mut counted = 0_usize;
    let mut reported_valid = false;
    while Instant::now() < active_end && !stop.load(Ordering::SeqCst) {
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let transfer_start = Instant::now();
        m14_udp_round_trip_reused(&application, relay, &target, &payload, &mut buffers)?;
        let completion = Instant::now();
        if !reported_valid {
            gate.worker_validated()?;
            reported_valid = true;
        }
        if transfer_is_measured(transfer_start, completion, warm_end, active_end) {
            counted = counted
                .checked_add(1)
                .ok_or_else(|| "profile UDP datagram count overflow".to_owned())?;
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "profile UDP sequence overflow".to_owned())?;
    }
    Ok(counted)
}
