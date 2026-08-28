use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use super::dns_resource::{prove_tcp_rebind, prove_udp_rebind};
use super::evidence_support::{
    DnsLoad, DnsResponder, PortReservation, profile_binary, spawn_proxy,
};
use super::process_support::{STARTUP_TIMEOUT, clean_io, v4, wait_for_listener, wait_for_metrics};
use super::profile_contract::{
    PROFILE_DNS_QUERY_BYTES, PROFILE_DNS_UDP_WORKERS, ProfileArgs, ProfileOutcome, ReadyFile,
    Topology,
};
use super::profile_structural::StructuralMetrics;
use super::proxy_config::profile_dns_udp_client_config;
use super::throughput::rate_per_second;

const PROFILE_DNS_NAME: &str = "profile.matrix.invalid.";

pub(super) fn run_profile_dns(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-dns-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut metrics_reservation = Some(PortReservation::new()?);
    let proxy = proxy_reservation
        .as_ref()
        .expect("DNS profile proxy reservation")
        .address;
    let metrics = metrics_reservation
        .as_ref()
        .expect("DNS profile metrics reservation")
        .address;
    let dns_reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let dns = v4(dns_reservation.local_addr().map_err(clean_io)?)?;
    let mut dns_reservation = Some(dns_reservation);
    let mut responder = Some(DnsResponder::start(PROFILE_DNS_NAME)?);
    let upstream = responder.as_ref().expect("DNS responder").address;
    let config = directory
        .as_ref()
        .expect("DNS profile config owner")
        .path()
        .join("client.toml");
    let mut process = None;
    let mut load = None;
    let mut ready = None;
    let mut errors = Vec::new();
    let mut warm_completed = 0_usize;
    let mut measured_queries = 0_usize;
    let mut inflight_peak = 0_usize;
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let execution = (|| -> Result<(), String> {
        fs::write(
            &config,
            profile_dns_udp_client_config(proxy, dns, upstream, metrics),
        )
        .map_err(clean_io)?;
        let binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        proxy_reservation
            .take()
            .expect("DNS profile proxy reservation")
            .release();
        metrics_reservation
            .take()
            .expect("DNS profile metrics reservation")
            .release();
        drop(dns_reservation.take());
        process = Some(spawn_proxy(
            Topology::Ferrum,
            "profile DNS client",
            &binary,
            &config,
        )?);
        wait_for_listener(process.as_mut().expect("DNS client process"), proxy)?;
        wait_for_metrics(process.as_mut().expect("DNS client process"), metrics)?;
        load = Some(DnsLoad::start_with_workers(
            dns,
            PROFILE_DNS_NAME,
            PROFILE_DNS_UDP_WORKERS,
            Some(PROFILE_DNS_QUERY_BYTES),
        )?);
        load.as_ref()
            .expect("DNS profile load")
            .wait_started(Instant::now() + STARTUP_TIMEOUT)?;
        let warm_end = Instant::now() + warmup;
        wait_for_dns_phase(
            process.as_mut().expect("DNS client process"),
            load.as_ref().expect("DNS profile load"),
            warm_end,
        )?;
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            process.as_ref().expect("DNS client process").id(),
            None,
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        warm_completed = load.as_ref().expect("DNS profile load").completed();
        let active_end = Instant::now() + active;
        wait_for_dns_phase(
            process.as_mut().expect("DNS client process"),
            load.as_ref().expect("DNS profile load"),
            active_end,
        )?;
        let completed = load.as_ref().expect("DNS profile load").completed();
        measured_queries = completed
            .checked_sub(warm_completed)
            .ok_or_else(|| "profile DNS completion counter regressed".to_owned())?;
        Ok(())
    })();
    if let Err(error) = execution {
        errors.push(error);
    }
    if let Some(owner) = ready.take()
        && let Err(error) = owner.remove()
    {
        errors.push(format!("ready cleanup failed: {error}"));
    }
    let completed = if let Some(load) = load.as_mut() {
        match load.finish() {
            Ok(count) => {
                inflight_peak = load.peak();
                count
            }
            Err(error) => {
                errors.push(format!("DNS load cleanup failed: {error}"));
                0
            }
        }
    } else {
        0
    };
    if let Some(process) = process.as_mut()
        && let Err(error) = process.terminate()
    {
        errors.push(format!("process cleanup failed: {error}"));
    }
    drop(process.take());
    let observed = if let Some(responder) = responder.as_mut() {
        match responder.finish() {
            Ok(count) => count,
            Err(error) => {
                errors.push(format!("DNS responder cleanup failed: {error}"));
                0
            }
        }
    } else {
        0
    };
    if completed != observed {
        errors.push("DNS responder/load completion accounting mismatch".to_owned());
    }
    drop(responder.take());
    drop((
        proxy_reservation.take(),
        metrics_reservation.take(),
        dns_reservation.take(),
    ));
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("config cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_rebind(proxy, "profile DNS client"),
        prove_tcp_rebind(metrics, "profile DNS metrics"),
        prove_udp_rebind(dns, "profile DNS inbound"),
        prove_udp_rebind(upstream, "profile DNS upstream"),
    ] {
        if let Err(error) = result {
            errors.push(format!("rebind failed: {error}"));
        }
    }
    if measured_queries == 0 {
        errors.push("profile DNS completed no measured queries".to_owned());
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let checked_units = u64::try_from(measured_queries)
        .map_err(|_| "profile DNS query count overflow".to_owned())?;
    let request_count = checked_units;
    let inflight_peak = u64::try_from(inflight_peak)
        .map_err(|_| "profile DNS inflight peak overflow".to_owned())?;
    let worker_count = u64::try_from(PROFILE_DNS_UDP_WORKERS).expect("bounded DNS workers");
    if inflight_peak == 0 || inflight_peak > worker_count {
        return Err("profile DNS externally observed inflight peak is invalid".to_owned());
    }
    let drop_count = 0;
    let encode_failure_count = 0;
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario={} queries={checked_units} \
             workers={PROFILE_DNS_UDP_WORKERS} requests={request_count} \
             inflight_peak={inflight_peak} pool_drops={drop_count} encode_failures={encode_failure_count} \
             warmup_seconds={} active_seconds={} drain=PASS rebind=PASS",
            arguments.scenario.label(),
            arguments.warmup_seconds,
            arguments.active_seconds,
        ),
        metric: "queries_per_second",
        value: rate_per_second(checked_units, active)?,
        checked_units,
        p99_nanoseconds: None,
        io_completions: checked_units.saturating_mul(2),
        scale_json: None,
        structural_metrics: StructuralMetrics::dns_listener(
            request_count,
            inflight_peak,
            drop_count,
            encode_failure_count,
        ),
    })
}

fn wait_for_dns_phase(
    process: &mut super::process_support::ProcessGuard,
    load: &DnsLoad,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        process.ensure_running()?;
        load.ensure_running()?;
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(20)));
    }
}
