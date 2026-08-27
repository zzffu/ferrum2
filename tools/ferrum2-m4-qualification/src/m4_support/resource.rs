use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RecordType};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName, version::TLS13,
};
use socket2::{Domain, Protocol, Socket, Type};

use super::dns_resource::{prove_tcp_rebind, prove_tcp_udp_rebind, prove_udp_rebind};
use super::evidence_support::{
    DnsResponder, Evidence, PortReservation, TcpUdpReservation, ferrum_binary, spawn_proxy,
};
use super::host_identity::HostedIdentity;
use super::process_support::{
    HoldingTarget, IO_TIMEOUT, STARTUP_TIMEOUT, TargetWorker, clean_io, json, remaining, sha256,
    socks_connect, v4, wait_for_listener, wait_for_metrics, wait_for_sample_slot,
};
use super::profile_contract::{HostedArgs, PROFILE_SOCKS_IPV4_HEADER_BYTES, Topology};
use super::proxy_config::{
    M14TcpProfile, ferrum_client_config, ferrum_server_config, m14_dns_hijack_client_config,
    m14_tcp_server_config, m14_udp_client_config, m14_udp_server_config,
};
use super::resource_sampling::{
    establish_sessions, sample_pair, validate_drain, validate_owner_tuple, validate_samples,
    validate_thp_profile, wait_for_sessions,
};
use super::self_check::{assert_no_owners, ensure_redacted};
use super::{
    DRAIN_TIMEOUT, PSK, RESOURCE_SAMPLES, RESOURCE_SESSIONS, RSS_WINDOW, SAMPLE_INTERVAL,
    STABILIZATION_SAMPLES, THP_MAX_PTES_NONE_PATH,
};

pub(super) fn run_resource(arguments: HostedArgs) -> Result<String, String> {
    let identity = HostedIdentity::load(&arguments.sha, &arguments.output)?;
    validate_thp_profile(Path::new(THP_MAX_PTES_NONE_PATH))?;
    let mut output = Evidence::create(&arguments.output)?;
    output.line(format!(
        "{{\"kind\":\"identity\",{}}}",
        identity.json_fields()
    ))?;
    let work = output.parent().to_path_buf();
    run_m14_measurements(&mut output, &work)?;
    let directory = tempfile::Builder::new()
        .prefix("resource-")
        .tempdir_in(output.parent())
        .map_err(clean_io)?;
    let target_socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(clean_io)?;
    target_socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())
        .map_err(clean_io)?;
    target_socket
        .listen(i32::try_from(RESOURCE_SESSIONS).expect("resource backlog fits i32"))
        .map_err(clean_io)?;
    let target_listener: TcpListener = target_socket.into();
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let server_reservation = PortReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let client_metrics_reservation = PortReservation::new()?;
    let server_metrics_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let client_metrics = client_metrics_reservation.address;
    let server_metrics = server_metrics_reservation.address;
    let client_config = directory.path().join("client.toml");
    let server_config = directory.path().join("server.toml");
    fs::write(
        &client_config,
        ferrum_client_config(proxy, server, Some(client_metrics)),
    )
    .map_err(clean_io)?;
    fs::write(
        &server_config,
        ferrum_server_config(server, Some(server_metrics)),
    )
    .map_err(clean_io)?;
    let client_hash = sha256("resource client config SHA-256 probe", &client_config)?;
    let server_hash = sha256("resource server config SHA-256 probe", &server_config)?;
    output.line(format!(
        "{{\"kind\":\"resource_profile\",\"max_ptes_none\":0,\"sessions\":10000,\"setup_concurrency\":256,\
         \"stabilization_samples\":30,\"samples\":180,\"interval_seconds\":10,\
         \"client_config_sha256\":{},\"server_config_sha256\":{}}}",
        json(&client_hash),
        json(&server_hash),
    ))?;
    let mut target_worker = HoldingTarget::start(target_listener, RESOURCE_SESSIONS)?;
    server_reservation.release();
    server_metrics_reservation.release();
    let mut server_process = spawn_proxy(
        Topology::Ferrum,
        "server",
        &ferrum_binary("ferrum2-server")?,
        &server_config,
    )?;
    wait_for_metrics(&mut server_process, server_metrics)?;
    proxy_reservation.release();
    client_metrics_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "client",
        &ferrum_binary("ferrum2-client")?,
        &client_config,
    )?;
    wait_for_metrics(&mut client_process, client_metrics)?;
    let pre_load = sample_pair(
        &mut client_process,
        &mut server_process,
        client_metrics,
        server_metrics,
        Instant::now() + SAMPLE_INTERVAL,
    )?;
    if pre_load.client.active != 0 || pre_load.server.active != 0 {
        return Err("pre-load active gauges are not zero".to_owned());
    }
    let applications = establish_sessions(proxy, target)?;
    target_worker.wait_accepted(Instant::now() + DRAIN_TIMEOUT)?;
    let first_stable = wait_for_sessions(
        &mut client_process,
        &mut server_process,
        client_metrics,
        server_metrics,
    )?;
    let stabilization_started = Instant::now();
    for index in 1..=STABILIZATION_SAMPLES {
        let slot =
            stabilization_started + SAMPLE_INTERVAL * u32::try_from(index).expect("sample index");
        let next_slot = slot + SAMPLE_INTERVAL;
        wait_for_sample_slot(slot, next_slot)?;
        let sample = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            next_slot,
        )?;
        validate_owner_tuple(&sample, &first_stable, RESOURCE_SESSIONS as u64)
            .map_err(|error| format!("stabilization sample {index}: {error}"))?;
    }
    let mut samples = Vec::with_capacity(RESOURCE_SAMPLES);
    let started = Instant::now();
    for index in 0..RESOURCE_SAMPLES {
        let slot = started + SAMPLE_INTERVAL * u32::try_from(index + 1).expect("sample index");
        let next_slot = slot + SAMPLE_INTERVAL;
        wait_for_sample_slot(slot, next_slot)?;
        let sample = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            next_slot,
        )?;
        validate_owner_tuple(&sample, &first_stable, RESOURCE_SESSIONS as u64)?;
        output.line(sample.json(index + 1))?;
        samples.push(sample);
    }
    let rss = validate_samples(
        &samples,
        RESOURCE_SAMPLES,
        RSS_WINDOW,
        RESOURCE_SESSIONS as u64,
    )?;
    for verdict in &rss {
        output.line(verdict.json())?;
    }
    drop(applications);
    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
    target_worker.wait_closed(drain_deadline)?;
    loop {
        let drained = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            drain_deadline,
        )?;
        if Instant::now() >= drain_deadline {
            return Err("resource drain did not return to exact baseline".to_owned());
        }
        if validate_drain(&drained, &pre_load).is_ok() {
            break;
        }
        thread::sleep(remaining(drain_deadline)?.min(Duration::from_millis(100)));
    }
    validate_thp_profile(Path::new(THP_MAX_PTES_NONE_PATH))?;
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    prove_tcp_rebind(proxy, "resource client")?;
    prove_tcp_rebind(server, "resource server")?;
    prove_tcp_rebind(client_metrics, "resource client metrics")?;
    prove_tcp_rebind(server_metrics, "resource server metrics")?;
    prove_tcp_rebind(target, "resource target")?;
    output.line(
        "{\"kind\":\"m14_measurement\",\"phase\":\"resource-owners\",\
         \"rss\":\"sampled\",\"tasks\":\"sampled\",\"connections\":10000,\
         \"sessions\":10000,\"owners\":\"baseline\",\"drain\":\"PASS\",\"rebind\":\"PASS\"}"
            .to_owned(),
    )?;
    output.line(
        "{\"kind\":\"resource_summary\",\"sessions\":10000,\"samples\":180,\
         \"rss_windows\":6,\"drain\":\"PASS\"}"
            .to_owned(),
    )?;
    output.finish()?;
    assert_no_owners()?;
    Ok(format!(
        "m4_resource_completion status=PASS sessions=10000 samples=180 rss_windows=6/6 \
         drain=PASS sha={} run_id={} run_attempt={}",
        identity.sha, identity.run_id, identity.run_attempt
    ))
}

pub(super) fn run_m14_measurements(output: &mut Evidence, work: &Path) -> Result<(), String> {
    let tls = m14_tls_client_hello()?;
    validate_m14_measurement_plan(&M14_MEASUREMENT_PHASES, &tls, true)?;
    run_m14_schema_v1_rejection(output, work)?;
    for (phase, profile) in [
        ("64-rule", M14TcpProfile::Rules64),
        ("server-tls-sniff", M14TcpProfile::TlsSniff),
        ("server-http-sniff", M14TcpProfile::HttpSniff),
    ] {
        run_m14_tcp_measurement(output, work, phase, profile, &tls)?;
    }
    run_m14_udp_measurement(output, work)?;
    run_m14_dns_hijack_measurements(output, work)?;
    assert_no_owners()
}

pub(super) const M14_MEASUREMENT_PHASES: [&str; 6] = [
    "schema-v1-routed-udp-rejection",
    "64-rule",
    "server-tls-sniff",
    "server-http-sniff",
    "association-route-once",
    "client-dns-hijack",
];

pub(super) fn validate_m14_measurement_plan(
    phases: &[&str],
    tls_client_hello: &[u8],
    terminal_outcomes_distinguishable: bool,
) -> Result<(), String> {
    if !phases.contains(&"schema-v1-routed-udp-rejection") {
        return Err("missing M14 schema-v1 rejection phase".to_owned());
    }
    let mut acceptor = rustls::server::Acceptor::default();
    let mut input = tls_client_hello;
    loop {
        let read = acceptor
            .read_tls(&mut input)
            .map_err(|_| "invalid M14 TLS ClientHello".to_owned())?;
        match acceptor.accept() {
            Ok(Some(_)) => break,
            Ok(None) if read != 0 => {}
            Ok(None) | Err(_) => return Err("invalid M14 TLS ClientHello".to_owned()),
        }
    }
    if !terminal_outcomes_distinguishable {
        return Err("non-distinguishing M14 terminal oracle".to_owned());
    }
    Ok(())
}

pub(super) fn m14_tls_client_hello() -> Result<Vec<u8>, String> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| "M14 TLS version is unavailable".to_owned())?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("tls.performance.test")
            .map_err(|_| "M14 TLS server name is invalid".to_owned())?
            .to_owned(),
    )
    .map_err(|_| "M14 TLS client could not start".to_owned())?;
    let mut wire = Vec::new();
    while client.wants_write() {
        client
            .write_tls(&mut wire)
            .map_err(|_| "M14 TLS ClientHello could not be encoded".to_owned())?;
    }
    Ok(wire)
}

pub(super) fn run_m14_schema_v1_rejection(
    output: &mut Evidence,
    work: &Path,
) -> Result<(), String> {
    let directory = tempfile::Builder::new()
        .prefix("m14-schema-v1-rejection-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let client = PortReservation::new()?;
    let server = TcpUdpReservation::new()?;
    let config = directory.path().join("client.toml");
    fs::write(
        &config,
        format!(
            "schema_version = 1\n[[inbounds]]\ntag = \"in\"\nlisten = \"{}\"\n\
             [[outbounds]]\ntag = \"out\"\nserver = \"{}\"\n\
             [route]\nfinal = \"out\"\n[[route.rules]]\nnetwork = \"udp\"\naction = \"reject\"\n\
             [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
             [udp]\nenabled = true\n[logging]\nlevel = \"error\"\n",
            client.address, server.address,
        ),
    )
    .map_err(clean_io)?;
    let started = Instant::now();
    let result = Command::new(ferrum_binary("ferrum2-client")?)
        .args([
            OsStr::new("--config"),
            config.as_os_str(),
            OsStr::new("--check-config"),
        ])
        .output()
        .map_err(|_| "M14 schema-v1 rejection check did not start".to_owned())?;
    if result.status.code() != Some(2)
        || !result.stdout.is_empty()
        || result.stderr
            != b"error[config.semantic] schema_version: configuration value is invalid\n"
    {
        return Err("M14 schema-v1 rejection check had the wrong observable".to_owned());
    }
    ensure_redacted(
        std::str::from_utf8(&result.stderr).map_err(|_| "schema-v1 rejection stderr".to_owned())?,
    )?;
    let elapsed = started.elapsed();
    let client_address = client.address;
    let server_address = server.address;
    drop((client, server));
    directory.close().map_err(clean_io)?;
    prove_tcp_rebind(client_address, "M14 schema-v1 rejection client")?;
    prove_tcp_udp_rebind(server_address, "M14 schema-v1 rejection server")?;
    output.line(format!(
        "{{\"kind\":\"m14_measurement\",\"phase\":\"schema-v1-routed-udp-rejection\",\
         \"exit_code\":2,\"elapsed_ns\":{},\"side_effects\":\"none\",\"rebind\":\"PASS\"}}",
        elapsed.as_nanos(),
    ))
}

pub(super) fn run_m14_tcp_measurement(
    output: &mut Evidence,
    work: &Path,
    phase: &str,
    profile: M14TcpProfile,
    tls_client_hello: &[u8],
) -> Result<(), String> {
    let directory = tempfile::Builder::new()
        .prefix("m14-tcp-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let server_reservation = PortReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let payloads = match profile {
        M14TcpProfile::HttpSniff => vec![
            (
                b"GET / HTTP/1.1\r\nHost: performance.test\r\n\r\n".to_vec(),
                false,
            ),
            (b"G@T invalid\r\n\r\n".to_vec(), true),
        ],
        M14TcpProfile::TlsSniff => vec![(tls_client_hello.to_vec(), false), (vec![0], true)],
        M14TcpProfile::Rules64 => vec![(b"m14-measurement".to_vec(), true)],
    };
    let client_config = directory.path().join("client.toml");
    let server_config = directory.path().join("server.toml");
    fs::write(&client_config, ferrum_client_config(proxy, server, None)).map_err(clean_io)?;
    fs::write(&server_config, m14_tcp_server_config(server, profile)).map_err(clean_io)?;
    let config_hash = sha256("M14 TCP config SHA-256 probe", &server_config)?;
    let target_worker = TargetWorker::echo(
        target_listener,
        payloads.iter().filter(|(_, echoes)| *echoes).count(),
    )?;
    server_reservation.release();
    let mut server_process = spawn_proxy(
        Topology::Ferrum,
        "M14 measurement server",
        &ferrum_binary("ferrum2-server")?,
        &server_config,
    )?;
    wait_for_listener(&mut server_process, server)?;
    proxy_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "M14 measurement client",
        &ferrum_binary("ferrum2-client")?,
        &client_config,
    )?;
    wait_for_listener(&mut client_process, proxy)?;
    let started = Instant::now();
    for (payload, echoes) in &payloads {
        let mut stream = socks_connect(proxy, target, Instant::now() + STARTUP_TIMEOUT)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(clean_io)?;
        stream.write_all(payload).map_err(clean_io)?;
        stream.shutdown(Shutdown::Write).map_err(clean_io)?;
        let mut echoed = Vec::with_capacity(payload.len());
        if let Err(error) = stream.read_to_end(&mut echoed)
            && (!matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) || *echoes)
        {
            return Err(clean_io(error));
        }
        if (*echoes && echoed != *payload) || (!*echoes && !echoed.is_empty()) {
            return Err(format!("{phase} terminal outcome mismatch"));
        }
    }
    let elapsed = started.elapsed();
    target_worker.finish()?;
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    prove_tcp_rebind(proxy, "M14 TCP client")?;
    prove_tcp_rebind(server, "M14 TCP server")?;
    prove_tcp_rebind(target, "M14 TCP target")?;
    output.line(format!(
        "{{\"kind\":\"m14_measurement\",\"phase\":{},\"transactions\":{},\
         \"elapsed_ns\":{},\"config_sha256\":{},\"drain\":\"PASS\",\"rebind\":\"PASS\"}}",
        json(phase),
        payloads.len(),
        elapsed.as_nanos(),
        json(&config_hash),
    ))
}

pub(super) fn run_m14_udp_measurement(output: &mut Evidence, work: &Path) -> Result<(), String> {
    let directory = tempfile::Builder::new()
        .prefix("m14-udp-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let first_target = v4(first.local_addr().map_err(clean_io)?)?;
    let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let second_target = v4(second.local_addr().map_err(clean_io)?)?;
    for socket in [&first, &second] {
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(clean_io)?;
        socket
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(clean_io)?;
    }
    let server_reservation = TcpUdpReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let unselected_reservation = TcpUdpReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let unselected = unselected_reservation.address;
    let client_config = directory.path().join("client.toml");
    let server_config = directory.path().join("server.toml");
    fs::write(&server_config, m14_udp_server_config(server, 1_048_576)).map_err(clean_io)?;
    fs::write(
        &client_config,
        m14_udp_client_config(
            proxy,
            server,
            unselected,
            first_target,
            second_target,
            1_048_576,
        ),
    )
    .map_err(clean_io)?;
    let config_hash = sha256("M14 UDP config SHA-256 probe", &client_config)?;
    server_reservation.release();
    let mut server_process = spawn_proxy(
        Topology::Ferrum,
        "M14 UDP measurement server",
        &ferrum_binary("ferrum2-server")?,
        &server_config,
    )?;
    wait_for_listener(&mut server_process, server)?;
    proxy_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "M14 UDP measurement client",
        &ferrum_binary("ferrum2-client")?,
        &client_config,
    )?;
    wait_for_listener(&mut client_process, proxy)?;
    let started = Instant::now();
    let (control, application, relay) = m14_udp_associate(proxy)?;
    m14_udp_round_trip(&application, relay, &first, first_target, b"first")?;
    m14_udp_round_trip(&application, relay, &second, second_target, b"later")?;
    let transactions = 2;
    let elapsed = started.elapsed();
    drop((application, control));
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    drop(unselected_reservation);
    drop((first, second));
    prove_tcp_rebind(proxy, "M14 UDP client")?;
    prove_tcp_udp_rebind(server, "M14 UDP server")?;
    prove_tcp_udp_rebind(unselected, "M14 UDP unselected server")?;
    prove_udp_rebind(first_target, "M14 UDP first target")?;
    prove_udp_rebind(second_target, "M14 UDP second target")?;
    prove_udp_rebind(relay, "M14 UDP relay")?;
    output.line(format!(
        "{{\"kind\":\"m14_measurement\",\"phase\":{},\"datagrams\":{transactions},\
         \"elapsed_ns\":{},\"config_sha256\":{},\"drain\":\"PASS\",\"rebind\":\"PASS\"}}",
        json("association-route-once"),
        elapsed.as_nanos(),
        json(&config_hash),
    ))
}

pub(super) fn m14_udp_associate(
    proxy: SocketAddrV4,
) -> Result<(TcpStream, UdpSocket, SocketAddrV4), String> {
    let mut control =
        TcpStream::connect_timeout(&SocketAddr::V4(proxy), IO_TIMEOUT).map_err(clean_io)?;
    control
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    control
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    control.write_all(&[5, 1, 0]).map_err(clean_io)?;
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).map_err(clean_io)?;
    if method != [5, 0] {
        return Err("M14 UDP SOCKS authentication negotiation failed".to_owned());
    }
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(clean_io)?;
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).map_err(clean_io)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("M14 UDP ASSOCIATE failed".to_owned());
    }
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    application
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    application
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(clean_io)?;
    Ok((control, application, relay))
}

pub(super) fn m14_socks_datagram(target: SocketAddrV4, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut wire = vec![0, 0, 0, 1];
    wire.extend_from_slice(&target.ip().octets());
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire.extend_from_slice(payload);
    if wire.len() > MAX_SOCKS_UDP_DATAGRAM_BYTES {
        return Err("M14 UDP SOCKS datagram exceeds the IPv4 UDP payload bound".to_owned());
    }
    Ok(wire)
}

pub(super) struct M14UdpRoundTripBuffers {
    pub(super) request: Vec<u8>,
    pub(super) received: Vec<u8>,
}

impl M14UdpRoundTripBuffers {
    pub(super) fn new(target: SocketAddrV4, payload_bytes: usize) -> Result<Self, String> {
        let socks_bytes = payload_bytes
            .checked_add(PROFILE_SOCKS_IPV4_HEADER_BYTES)
            .filter(|length| *length <= MAX_SOCKS_UDP_DATAGRAM_BYTES)
            .ok_or_else(|| "M14 UDP payload exceeds the SOCKS IPv4 bound".to_owned())?;
        let mut request = vec![0_u8; socks_bytes];
        request[3] = 1;
        request[4..8].copy_from_slice(&target.ip().octets());
        request[8..10].copy_from_slice(&target.port().to_be_bytes());
        // One sentinel byte makes kernel truncation observable for every size
        // below the IPv4/SOCKS maximum. At exactly 65,507 bytes there is no
        // larger valid IPv4 UDP payload; constructor and encoder bounds prove
        // that special case separately in self-check.
        let received_bytes = socks_bytes
            .saturating_add(1)
            .min(MAX_SOCKS_UDP_DATAGRAM_BYTES);
        Ok(Self {
            request,
            received: vec![0_u8; received_bytes],
        })
    }

    pub(super) fn validate_target_payload(
        &self,
        length: usize,
        payload: &[u8],
    ) -> Result<(), String> {
        if length != payload.len() || self.received.get(..length) != Some(payload) {
            return Err("M14 UDP target payload mismatch".to_owned());
        }
        Ok(())
    }

    pub(super) fn validate_application_response(
        &self,
        length: usize,
        source: SocketAddr,
        relay: SocketAddrV4,
    ) -> Result<(), String> {
        if source != SocketAddr::V4(relay)
            || length != self.request.len()
            || self.received.get(..length) != Some(self.request.as_slice())
        {
            return Err("M14 UDP response binding mismatch".to_owned());
        }
        Ok(())
    }
}

pub(super) fn m14_udp_round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    target: &UdpSocket,
    target_address: SocketAddrV4,
    payload: &[u8],
) -> Result<(), String> {
    let mut buffers = M14UdpRoundTripBuffers::new(target_address, payload.len())?;
    m14_udp_round_trip_reused(application, relay, target, payload, &mut buffers)
}

pub(super) fn m14_udp_round_trip_reused(
    application: &UdpSocket,
    relay: SocketAddrV4,
    target: &UdpSocket,
    payload: &[u8],
    buffers: &mut M14UdpRoundTripBuffers,
) -> Result<(), String> {
    if buffers.request.len() != payload.len() + PROFILE_SOCKS_IPV4_HEADER_BYTES {
        return Err("M14 UDP reusable buffer does not match its payload".to_owned());
    }
    buffers.request[PROFILE_SOCKS_IPV4_HEADER_BYTES..].copy_from_slice(payload);
    application
        .send_to(&buffers.request, relay)
        .map_err(clean_io)?;
    let (length, peer) = target.recv_from(&mut buffers.received).map_err(clean_io)?;
    buffers.validate_target_payload(length, payload)?;
    target
        .send_to(&buffers.received[..length], peer)
        .map_err(clean_io)?;
    let (length, source) = application
        .recv_from(&mut buffers.received)
        .map_err(clean_io)?;
    buffers.validate_application_response(length, source, relay)
}

pub(super) const M14_DNS_NAME: &str = "hijack.performance.test.";

pub(super) fn run_m14_dns_hijack_measurements(
    output: &mut Evidence,
    work: &Path,
) -> Result<(), String> {
    let directory = tempfile::Builder::new()
        .prefix("m14-hijack-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let mut upstream = DnsResponder::start(M14_DNS_NAME)?;
    let upstream_address = upstream.address;
    let proxy_reservation = PortReservation::new()?;
    let dns_reservation = TcpUdpReservation::new()?;
    let protected_reservation = TcpUdpReservation::new()?;
    let proxy = proxy_reservation.address;
    let dns_listen = dns_reservation.address;
    let protected = protected_reservation.address;
    let config = directory.path().join("client.toml");
    fs::write(
        &config,
        m14_dns_hijack_client_config(proxy, protected, dns_listen, upstream_address),
    )
    .map_err(clean_io)?;
    let config_hash = sha256("M14 DNS hijack config SHA-256 probe", &config)?;
    proxy_reservation.release();
    dns_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "M14 DNS hijack measurement client",
        &ferrum_binary("ferrum2-client")?,
        &config,
    )?;
    wait_for_listener(&mut client_process, proxy)?;
    wait_for_listener(&mut client_process, dns_listen)?;
    let query = m14_dns_query(0x1408)?;

    let tcp_started = Instant::now();
    let mut tcp = socks_connect(
        proxy,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        Instant::now() + STARTUP_TIMEOUT,
    )?;
    tcp.set_read_timeout(Some(IO_TIMEOUT)).map_err(clean_io)?;
    tcp.write_all(
        &u16::try_from(query.len())
            .map_err(|_| "M14 DNS query exceeded TCP frame".to_owned())?
            .to_be_bytes(),
    )
    .map_err(clean_io)?;
    tcp.write_all(&query).map_err(clean_io)?;
    let mut length = [0_u8; 2];
    tcp.read_exact(&mut length).map_err(clean_io)?;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tcp.read_exact(&mut response).map_err(clean_io)?;
    m14_validate_dns_response(&response, 0x1408)?;
    let tcp_elapsed = tcp_started.elapsed();
    drop(tcp);
    output.line(format!(
        "{{\"kind\":\"m14_measurement\",\"phase\":\"client-tcp-dns-hijack\",\
         \"queries\":1,\"elapsed_ns\":{},\"config_sha256\":{}}}",
        tcp_elapsed.as_nanos(),
        json(&config_hash),
    ))?;

    let udp_started = Instant::now();
    let (control, application, relay) = m14_udp_associate(proxy)?;
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
    let request = m14_socks_datagram(target, &query)?;
    application.send_to(&request, relay).map_err(clean_io)?;
    let mut response = [0_u8; 4096];
    let (length, source) = application.recv_from(&mut response).map_err(clean_io)?;
    let prefix = m14_socks_datagram(target, &[])?;
    if source != SocketAddr::V4(relay) || response[..prefix.len()] != prefix {
        return Err("M14 UDP DNS hijack response binding mismatch".to_owned());
    }
    m14_validate_dns_response(&response[prefix.len()..length], 0x1408)?;
    let udp_elapsed = udp_started.elapsed();
    drop((application, control));
    output.line(format!(
        "{{\"kind\":\"m14_measurement\",\"phase\":\"client-udp-dns-hijack\",\
         \"queries\":1,\"elapsed_ns\":{},\"config_sha256\":{}}}",
        udp_elapsed.as_nanos(),
        json(&config_hash),
    ))?;

    client_process.ensure_running()?;
    client_process.terminate()?;
    if upstream.finish()? == 0 {
        return Err("M14 DNS hijack did not issue an upstream query".to_owned());
    }
    directory.close().map_err(clean_io)?;
    drop(protected_reservation);
    prove_tcp_rebind(proxy, "M14 DNS hijack client")?;
    prove_tcp_udp_rebind(dns_listen, "M14 DNS dedicated inbound")?;
    prove_tcp_udp_rebind(protected, "M14 DNS protected outbound")?;
    prove_udp_rebind(upstream_address, "M14 DNS upstream")?;
    prove_udp_rebind(relay, "M14 DNS hijack relay")?;
    Ok(())
}

pub(super) fn m14_dns_query(id: u16) -> Result<Vec<u8>, String> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii(M14_DNS_NAME).map_err(|_| "M14 DNS name is invalid".to_owned())?,
        RecordType::A,
    ));
    query
        .to_vec()
        .map_err(|_| "M14 DNS query could not be encoded".to_owned())
}

pub(super) fn m14_validate_dns_response(wire: &[u8], id: u16) -> Result<(), String> {
    let response =
        Message::from_vec(wire).map_err(|_| "M14 DNS hijack returned malformed wire".to_owned())?;
    if response.metadata.id != id
        || response.metadata.message_type != MessageType::Response
        || response.answers.first().map(|record| &record.data)
            != Some(&RData::A(A(Ipv4Addr::LOCALHOST)))
    {
        return Err("M14 DNS hijack returned the wrong answer".to_owned());
    }
    Ok(())
}
