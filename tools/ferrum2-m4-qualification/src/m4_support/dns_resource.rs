use std::fs;
use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::evidence_support::{
    DnsLoad, DnsResponder, Evidence, PortReservation, TcpUdpReservation, ferrum_binary, spawn_proxy,
};
use super::host_identity::HostedIdentity;
use super::process_support::{
    ProcessGuard, STARTUP_TIMEOUT, clean_io, json, remaining, sha256, wait_for_listener,
    wait_for_metrics, wait_for_sample_slot,
};
use super::profile_contract::{HostedArgs, Topology};
use super::proxy_config::{ferrum_dns_resource_client_config, ferrum_dns_resource_server_config};
use super::resource_sampling::{
    PairSample, proc_sample, validate_dns_samples, validate_thp_profile,
};
use super::self_check::assert_no_owners;
use super::{DRAIN_TIMEOUT, THP_MAX_PTES_NONE_PATH};

pub(super) const DNS_LOAD_WORKERS: usize = 16;
pub(super) const DNS_MAX_INFLIGHT: u16 = 32;
pub(super) const DNS_RESOURCE_SAMPLES: usize = 24;
pub(super) const DNS_RSS_WINDOW: usize = 4;
pub(super) const DNS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const DNS_UPSTREAM_DELAY: Duration = Duration::from_millis(5);
pub(super) const DNS_OWNER_DELTA: u64 = DNS_MAX_INFLIGHT as u64 * 4 + 32;
// ponytail: UDP is the one hot-path resource witness; add transports only for a transport claim.
pub(super) const DNS_DIRECT_NAME: &str = "direct.performance.test.";
pub(super) const DNS_DETOURED_NAME: &str = "detoured.performance.test.";

pub(super) fn run_dns_resource(arguments: HostedArgs) -> Result<String, String> {
    let identity = HostedIdentity::load(&arguments.sha, &arguments.output)?;
    validate_thp_profile(Path::new(THP_MAX_PTES_NONE_PATH))?;
    let mut output = Evidence::create(&arguments.output)?;
    output.line(format!(
        "{{\"kind\":\"identity\",{}}}",
        identity.json_fields()
    ))?;
    let directory = tempfile::Builder::new()
        .prefix("dns-resource-")
        .tempdir_in(output.parent())
        .map_err(clean_io)?;
    let mut direct_upstream = DnsResponder::start(DNS_DIRECT_NAME)?;
    let mut detoured_upstream = DnsResponder::start(DNS_DETOURED_NAME)?;
    let direct_upstream_address = direct_upstream.address;
    let detoured_upstream_address = detoured_upstream.address;
    let server_reservation = TcpUdpReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let direct_dns_reservation = TcpUdpReservation::new()?;
    let detoured_dns_reservation = TcpUdpReservation::new()?;
    let client_metrics_reservation = PortReservation::new()?;
    let server_metrics_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let direct_dns = direct_dns_reservation.address;
    let detoured_dns = detoured_dns_reservation.address;
    let client_metrics = client_metrics_reservation.address;
    let server_metrics = server_metrics_reservation.address;
    let client_config = directory.path().join("client.toml");
    let server_config = directory.path().join("server.toml");
    fs::write(
        &client_config,
        ferrum_dns_resource_client_config(
            proxy,
            server,
            direct_dns,
            detoured_dns,
            direct_upstream_address,
            detoured_upstream_address,
            client_metrics,
        ),
    )
    .map_err(clean_io)?;
    fs::write(
        &server_config,
        ferrum_dns_resource_server_config(server, direct_upstream_address, server_metrics),
    )
    .map_err(clean_io)?;
    let client_hash = sha256("DNS resource client config SHA-256 probe", &client_config)?;
    let server_hash = sha256("DNS resource server config SHA-256 probe", &server_config)?;
    output.line(format!(
        "{{\"kind\":\"dns_resource_profile\",\"max_inflight\":{DNS_MAX_INFLIGHT},\
         \"load_workers\":{DNS_LOAD_WORKERS},\"samples_per_phase\":{DNS_RESOURCE_SAMPLES},\
         \"sample_interval_seconds\":{},\"upstream_delay_ms\":{},\
         \"owner_delta\":{DNS_OWNER_DELTA},\
         \"client_config_sha256\":{},\"server_config_sha256\":{}}}",
        DNS_SAMPLE_INTERVAL.as_secs(),
        DNS_UPSTREAM_DELAY.as_millis(),
        json(&client_hash),
        json(&server_hash),
    ))?;

    server_reservation.release();
    server_metrics_reservation.release();
    let mut server_process = spawn_proxy(
        Topology::Ferrum,
        "DNS resource server",
        &ferrum_binary("ferrum2-server")?,
        &server_config,
    )?;
    wait_for_metrics(&mut server_process, server_metrics)?;
    proxy_reservation.release();
    direct_dns_reservation.release();
    detoured_dns_reservation.release();
    client_metrics_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "DNS resource client",
        &ferrum_binary("ferrum2-client")?,
        &client_config,
    )?;
    wait_for_metrics(&mut client_process, client_metrics)?;
    wait_for_listener(&mut client_process, direct_dns)?;
    wait_for_listener(&mut client_process, detoured_dns)?;

    let idle = wait_for_dns_idle(&mut client_process, &mut server_process)?;
    output.line(dns_sample_json("idle", 0, idle))?;
    let direct_queries = run_dns_resource_phase(
        "direct",
        direct_dns,
        DNS_DIRECT_NAME,
        &mut client_process,
        &mut server_process,
        idle,
        &mut output,
    )?;
    if direct_upstream.observed() < direct_queries {
        return Err("direct DNS upstream observed fewer queries than the load client".to_owned());
    }
    let detoured_queries = run_dns_resource_phase(
        "detoured",
        detoured_dns,
        DNS_DETOURED_NAME,
        &mut client_process,
        &mut server_process,
        idle,
        &mut output,
    )?;
    if detoured_upstream.observed() < detoured_queries {
        return Err("detoured DNS upstream observed fewer queries than the load client".to_owned());
    }

    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    let direct_upstream_queries = direct_upstream.finish()?;
    let detoured_upstream_queries = detoured_upstream.finish()?;
    if direct_upstream_queries < direct_queries || detoured_upstream_queries < detoured_queries {
        return Err("DNS upstream completion count is incomplete".to_owned());
    }
    prove_tcp_udp_rebind(server, "DNS resource server")?;
    prove_tcp_rebind(proxy, "DNS resource SOCKS listener")?;
    prove_tcp_udp_rebind(direct_dns, "direct DNS listener")?;
    prove_tcp_udp_rebind(detoured_dns, "detoured DNS listener")?;
    prove_tcp_rebind(client_metrics, "DNS resource client metrics")?;
    prove_tcp_rebind(server_metrics, "DNS resource server metrics")?;
    prove_udp_rebind(direct_upstream_address, "direct DNS upstream")?;
    prove_udp_rebind(detoured_upstream_address, "detoured DNS upstream")?;
    directory.close().map_err(clean_io)?;
    output.line(format!(
        "{{\"kind\":\"dns_resource_summary\",\"roots\":\"client,server\",\
         \"phases\":\"idle,direct,detoured\",\"direct_queries\":{direct_queries},\
         \"detoured_queries\":{detoured_queries},\"samples\":{},\
         \"rss_windows\":12,\"bounds\":\"PASS\",\"drain\":\"PASS\",\
         \"rebind\":\"PASS\"}}",
        DNS_RESOURCE_SAMPLES * 2,
    ))?;
    output.finish()?;
    assert_no_owners()?;
    Ok(format!(
        "m12_dns_resource_completion status=PASS roots=client,server \
         phases=idle,direct,detoured direct_queries={direct_queries} \
         detoured_queries={detoured_queries} samples={} rss_windows=12/12 \
         bounds=PASS drain=PASS rebind=PASS sha={} run_id={} run_attempt={}",
        DNS_RESOURCE_SAMPLES * 2,
        identity.sha,
        identity.run_id,
        identity.run_attempt,
    ))
}

pub(super) fn run_dns_resource_phase(
    phase: &'static str,
    listen: SocketAddrV4,
    name: &'static str,
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    idle: PairSample,
    output: &mut Evidence,
) -> Result<usize, String> {
    let mut load = DnsLoad::start(listen, name)?;
    load.wait_started(Instant::now() + STARTUP_TIMEOUT)?;
    let mut samples = Vec::with_capacity(DNS_RESOURCE_SAMPLES);
    let started = Instant::now();
    for index in 0..DNS_RESOURCE_SAMPLES {
        let slot =
            started + DNS_SAMPLE_INTERVAL * u32::try_from(index + 1).expect("DNS sample index");
        let next_slot = slot + DNS_SAMPLE_INTERVAL;
        wait_for_sample_slot(slot, next_slot)?;
        let sample = dns_process_sample(client, server)?;
        validate_dns_owner_bound(&sample, &idle)
            .map_err(|error| format!("{phase} DNS sample {}: {error}", index + 1))?;
        output.line(dns_sample_json(phase, index + 1, sample))?;
        samples.push(sample);
    }
    let queries = load.finish()?;
    if queries < DNS_LOAD_WORKERS {
        return Err(format!("{phase} DNS load completed too few queries"));
    }
    let rss = validate_dns_samples(&samples, &idle)?;
    for verdict in &rss {
        output.line(verdict.dns_json(phase))?;
    }
    let drained = wait_for_dns_drain(client, server, &idle)?;
    output.line(dns_sample_json(&format!("{phase}-drained"), 0, drained))?;
    Ok(queries)
}

pub(super) fn dns_process_sample(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
) -> Result<PairSample, String> {
    client.ensure_running()?;
    server.ensure_running()?;
    Ok(PairSample {
        client: proc_sample(client.id())?,
        server: proc_sample(server.id())?,
    })
}

pub(super) fn wait_for_dns_idle(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
) -> Result<PairSample, String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut previous = None;
    let mut stable = 0;
    loop {
        let sample = dns_process_sample(client, server)?;
        let tuple = dns_owner_tuple(&sample);
        if previous == Some(tuple) {
            stable += 1;
            if stable == 3 {
                return Ok(sample);
            }
        } else {
            previous = Some(tuple);
            stable = 0;
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
    }
}

pub(super) fn wait_for_dns_drain(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    idle: &PairSample,
) -> Result<PairSample, String> {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    let mut previous = None;
    let mut stable = 0;
    loop {
        let sample = dns_process_sample(client, server)?;
        validate_dns_owner_bound(&sample, idle)?;
        let tuple = dns_owner_tuple(&sample);
        if previous == Some(tuple) {
            stable += 1;
            if stable == 3 {
                return Ok(sample);
            }
        } else {
            previous = Some(tuple);
            stable = 0;
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
    }
}

pub(super) fn dns_owner_tuple(sample: &PairSample) -> (u64, u64, u64, u64) {
    (
        sample.client.fds,
        sample.server.fds,
        sample.client.tasks,
        sample.server.tasks,
    )
}

pub(super) fn validate_dns_owner_bound(
    sample: &PairSample,
    idle: &PairSample,
) -> Result<(), String> {
    for (role, sample, idle) in [
        ("client", sample.client, idle.client),
        ("server", sample.server, idle.server),
    ] {
        if sample.active != 0
            || sample.fds > idle.fds.saturating_add(DNS_OWNER_DELTA)
            || sample.tasks > idle.tasks.saturating_add(DNS_OWNER_DELTA)
        {
            return Err(format!("{role} DNS owner ceiling exceeded"));
        }
    }
    Ok(())
}

pub(super) fn dns_sample_json(phase: &str, index: usize, sample: PairSample) -> String {
    format!(
        "{{\"kind\":\"dns_resource_sample\",\"phase\":{},\"sample\":{index},\
         \"client_fds\":{},\"server_fds\":{},\"client_tasks\":{},\
         \"server_tasks\":{},\"client_rss_kib\":{},\"server_rss_kib\":{},\
         \"client_smaps_rss_kib\":{},\"server_smaps_rss_kib\":{},\
         \"client_anonymous_kib\":{},\"server_anonymous_kib\":{},\
         \"client_anon_huge_pages_kib\":{},\"server_anon_huge_pages_kib\":{}}}",
        json(phase),
        sample.client.fds,
        sample.server.fds,
        sample.client.tasks,
        sample.server.tasks,
        sample.client.rss_kib,
        sample.server.rss_kib,
        sample.client.smaps_rss_kib,
        sample.server.smaps_rss_kib,
        sample.client.anonymous_kib,
        sample.server.anonymous_kib,
        sample.client.anon_huge_pages_kib,
        sample.server.anon_huge_pages_kib,
    )
}

pub(super) fn prove_tcp_rebind(address: SocketAddrV4, label: &str) -> Result<(), String> {
    drop(TcpListener::bind(address).map_err(|_| format!("{label} did not rebind"))?);
    Ok(())
}

pub(super) fn prove_udp_rebind(address: SocketAddrV4, label: &str) -> Result<(), String> {
    drop(UdpSocket::bind(address).map_err(|_| format!("{label} did not rebind"))?);
    Ok(())
}

pub(super) fn prove_tcp_udp_rebind(address: SocketAddrV4, label: &str) -> Result<(), String> {
    let tcp = TcpListener::bind(address).map_err(|_| format!("{label} TCP did not rebind"))?;
    let udp = UdpSocket::bind(address).map_err(|_| format!("{label} UDP did not rebind"))?;
    drop((tcp, udp));
    Ok(())
}
