#[path = "socks_udp_support/mod.rs"]
mod support;

use base64::Engine as _;
use std::path::{Path, PathBuf};
use support::local_support as tcp_support;
use support::*;

const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

struct Credentials {
    directory: tempfile::TempDir,
}

impl Credentials {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("F2P credentials");
        let root = directory.path();
        write_pem(
            root,
            "ca.pem",
            "CERTIFICATE",
            include_bytes!("../../../tests/fixtures/dns-tls/m12-test-ca.der"),
        );
        write_pem(
            root,
            "cert.pem",
            "CERTIFICATE",
            include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.der"),
        );
        write_pem(
            root,
            "key.pem",
            "PRIVATE KEY",
            include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.pk8"),
        );
        std::fs::write(root.join("token"), TOKEN).expect("synthetic token");
        Self { directory }
    }

    fn path(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn server(&self, address: SocketAddrV4, rules: &str) -> PathBuf {
        let token = self.path("token");
        let certificate = self.path("cert.pem");
        let key = self.path("key.pem");
        let path = self.directory.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                "schema_version = 2\n\
             [[inbounds]]\ntag = \"f2p-in\"\ntype = \"f2p\"\nlisten = \"{address}\"\n\
             [inbounds.auth]\ntoken_file = \"{token}\"\n\
             [inbounds.tls]\ncertificate_file = \"{certificate}\"\nprivate_key_file = \"{key}\"\n\
             [[outbounds]]\ntag = \"direct\"\n\
             [route]\nfinal = \"direct\"\n{rules}\n\
             [udp]\nenabled = true\nmax_sessions = 256\nmax_buffered_bytes = 8388608\n"
            ),
        )
        .expect("F2P server config");
        path
    }

    fn client(
        &self,
        address: SocketAddrV4,
        server: SocketAddrV4,
        profile: &str,
        token_name: &str,
        server_name: &str,
    ) -> PathBuf {
        let token = self.path(token_name);
        let ca = self.path("ca.pem");
        let path = self
            .directory
            .path()
            .join(format!("client-{profile}-{token_name}-{server_name}.toml"));
        std::fs::write(&path, format!(
            "schema_version = 2\n\
             [[inbounds]]\ntag = \"socks\"\nlisten = \"{address}\"\noutbound = \"proxy\"\n\
             [[outbounds]]\ntag = \"proxy\"\ntype = \"f2p\"\nserver = \"{server}\"\nprofile = \"{profile}\"\n\
             [outbounds.auth]\ntoken_file = \"{token}\"\n\
             [outbounds.tls]\nserver_name = \"{server_name}\"\nca_file = \"{ca}\"\n\
             [udp]\nenabled = true\nmax_sessions = 256\nmax_buffered_bytes = 8388608\n"
        )).expect("F2P client config");
        path
    }
}

fn write_pem(root: &Path, name: &str, label: &str, bytes: &[u8]) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    std::fs::write(root.join(name), pem).expect("PEM fixture");
}

fn stop(mut child: ChildGuard) {
    child.request_graceful_shutdown();
    let exit = child.wait_for_exit(Duration::from_secs(8));
    assert!(
        exit.status.success(),
        "{exit}: {}",
        exit.shutdown_report_diagnostic()
    );
    exit.assert_stderr_excludes(&[TOKEN, "denied.f2p.test"]);
}

#[test]
fn f2p_profiles_preserve_tcp_half_close_and_udp_session_identity() {
    let credentials = Credentials::new();
    let server_address = unused_loopback();
    let server_config = credentials.server(server_address, "");
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &server_config, "F2P forwarding");
    wait_for_listener(&mut server, server_address);

    for profile in ["balanced", "realtime"] {
        let client_address = unused_tcp_udp_loopback();
        let config = credentials.client(
            client_address,
            server_address,
            profile,
            "token",
            "resolver.test",
        );
        let mut client = ChildGuard::spawn_signallable("ferrum2-client", &config, "F2P forwarding");
        wait_for_listener(&mut client, client_address);
        let (target, echo) = tcp_support::start_echo();
        let (mut tcp, reply) = tcp_support::socks_connect_wire(
            client_address,
            &domain_target_wire("127.0.0.1", target.port()),
        );
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let payload = vec![0x5a; 131_071];
        tcp.write_all(&payload).expect("F2P TCP payload");
        tcp.shutdown(Shutdown::Write).expect("F2P write-half close");
        let mut response = Vec::new();
        tcp.read_to_end(&mut response)
            .expect("response after half close");
        assert_eq!(response, payload);
        assert_eq!(echo.join().expect("TCP echo complete"), payload);
        drop(tcp);

        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let first_target = target_wire(first.local_addr().unwrap());
        let second_target = target_wire(second.local_addr().unwrap());
        let first_domain = domain_target_wire("127.0.0.1", first.local_addr().unwrap().port());
        let first_echo = echo_datagrams(first, 4);
        let second_echo = echo_datagrams(second, 1);
        let (control_a, application_a, relay_a) = udp_associate(client_address, false);
        let (control_b, application_b, relay_b) = udp_associate(client_address, false);
        // Open two source identities to the same destination before reading either response.
        let packet_a = socks_datagram_for_target(&first_target, b"source-a");
        let packet_b = socks_datagram_for_target(&first_target, b"source-b");
        application_a.send_to(&packet_a, relay_a).unwrap();
        application_b.send_to(&packet_b, relay_b).unwrap();
        let mut response = [0_u8; 128];
        let (length, _) = application_b
            .recv_from(&mut response)
            .expect("source B reply");
        assert_eq!(&response[..length], packet_b);
        let (length, _) = application_a
            .recv_from(&mut response)
            .expect("source A reply");
        assert_eq!(&response[..length], packet_a);
        // One SOCKS association may target several peers; zero bytes remains a datagram.
        round_trip(
            &application_a,
            relay_a,
            &second_target,
            &second_target,
            b"other-target",
        );
        round_trip(&application_a, relay_a, &first_target, &first_target, b"");
        round_trip(
            &application_a,
            relay_a,
            &first_domain,
            &first_target,
            b"domain-target",
        );
        drop((control_a, control_b, application_a, application_b));
        first_echo.join().unwrap();
        second_echo.join().unwrap();
        stop(client);
    }
    stop(server);
}

#[test]
fn f2p_server_payload_policy_rejects_before_target_connection_or_datagram() {
    let credentials = Credentials::new();
    let server_address = unused_loopback();
    let denied_tcp = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    denied_tcp.set_nonblocking(true).unwrap();
    let denied_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    denied_udp
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let denied_udp_port = denied_udp.local_addr().unwrap().port();
    let rules = format!(
        "[route.sniff]\ntimeout_ms = 500\nmax_bytes = 8192\n\
         [[route.rules]]\nnetwork = \"tcp\"\naction = \"sniff\"\nsniffers = \"http\"\n\
         [[route.rules]]\nnetwork = \"tcp\"\ndomain = \"denied.f2p.test\"\nprotocol = \"http\"\naction = \"reject\"\n\
         [[route.rules]]\nnetwork = \"udp\"\nport = {denied_udp_port}\naction = \"reject\"\n"
    );
    let server_config = credentials.server(server_address, &rules);
    let client_address = unused_tcp_udp_loopback();
    let client_config = credentials.client(
        client_address,
        server_address,
        "balanced",
        "token",
        "resolver.test",
    );
    let mut server = ChildGuard::spawn_signallable("ferrum2-server", &server_config, "F2P policy");
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn_signallable("ferrum2-client", &client_config, "F2P policy");
    wait_for_listener(&mut client, client_address);
    let (mut tcp, reply) = tcp_support::socks_connect_wire(
        client_address,
        &target_wire(denied_tcp.local_addr().unwrap()),
    );
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: denied.f2p.test\r\n\r\n")
        .unwrap();
    match tcp.read(&mut [0_u8; 1]) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        result => panic!("policy rejection did not terminate promptly: {result:?}"),
    }
    assert!(
        matches!(denied_tcp.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let (control, application, relay) = udp_associate(client_address, false);
    let allowed = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let allowed_target = target_wire(allowed.local_addr().unwrap());
    let allowed_echo = echo_datagrams(allowed, 2);
    round_trip(
        &application,
        relay,
        &allowed_target,
        &allowed_target,
        b"before-reject",
    );
    application
        .send_to(
            &socks_datagram_for_target(
                &target_wire(denied_udp.local_addr().unwrap()),
                b"must-not-forward",
            ),
            relay,
        )
        .unwrap();
    assert!(
        matches!(denied_udp.recv_from(&mut [0_u8; 64]), Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
    );
    // A rejected target must not tear down unrelated sessions in this association.
    application
        .send_to(
            &socks_datagram_for_target(
                &target_wire(denied_udp.local_addr().unwrap()),
                b"still-rejected",
            ),
            relay,
        )
        .unwrap();
    round_trip(
        &application,
        relay,
        &allowed_target,
        &allowed_target,
        b"after-reject",
    );
    allowed_echo.join().unwrap();
    drop((tcp, control, application));
    stop(client);
    stop(server);
}

#[test]
fn f2p_wrong_token_and_wrong_server_identity_never_reach_target() {
    let credentials = Credentials::new();
    std::fs::write(
        credentials.directory.path().join("wrong-token"),
        base64::engine::general_purpose::STANDARD.encode([0xff; 32]),
    )
    .unwrap();
    let server_address = unused_loopback();
    let server_config = credentials.server(server_address, "");
    let mut server = ChildGuard::spawn_signallable("ferrum2-server", &server_config, "F2P auth");
    wait_for_listener(&mut server, server_address);
    let target = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    for (token, server_name) in [("wrong-token", "resolver.test"), ("token", "wrong.test")] {
        let client_address = unused_tcp_udp_loopback();
        let config = credentials.client(
            client_address,
            server_address,
            "balanced",
            token,
            server_name,
        );
        let mut client = ChildGuard::spawn_signallable("ferrum2-client", &config, "F2P auth");
        wait_for_listener(&mut client, client_address);
        let (stream, reply) = tcp_support::socks_connect_wire(
            client_address,
            &target_wire(target.local_addr().unwrap()),
        );
        assert_ne!(reply[1], 0, "unauthenticated proxy must not be admitted");
        assert!(
            matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        drop(stream);
        stop(client);
    }
    stop(server);
}

#[test]
fn mixed_protocol_server_preserves_minimum_global_udp_limits() {
    let credentials = Credentials::new();
    let server_address = unused_loopback();
    let shadowsocks_address = unused_tcp_udp_loopback();
    let server_config = credentials.server(server_address, "");
    let source = std::fs::read_to_string(&server_config)
        .unwrap()
        .replace("max_sessions = 256", "max_sessions = 1")
        .replace(
            "max_buffered_bytes = 8388608",
            "max_buffered_bytes = 1048576",
        );
    std::fs::write(&server_config, format!(
        "{source}\n[[inbounds]]\ntag = \"ss-in\"\ntype = \"shadowsocks\"\nlisten = \"{shadowsocks_address}\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n"
    )).unwrap();
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &server_config, "mixed UDP minima");
    wait_for_listener(&mut server, server_address);
    wait_for_listener(&mut server, shadowsocks_address);
    let client_address = unused_tcp_udp_loopback();
    let config = credentials.client(
        client_address,
        server_address,
        "balanced",
        "token",
        "resolver.test",
    );
    let mut client = ChildGuard::spawn_signallable("ferrum2-client", &config, "mixed UDP minima");
    wait_for_listener(&mut client, client_address);
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target = target_wire(echo.local_addr().unwrap());
    let echo = echo_datagrams(echo, 1);
    let (control, application, relay) = udp_associate(client_address, false);
    round_trip(&application, relay, &target, &target, b"one-global-session");
    echo.join().unwrap();
    drop((control, application));
    stop(client);
    stop(server);
}

#[test]
fn sparse_f2p_associations_forward_within_one_mib_client_budget() {
    let credentials = Credentials::new();
    let server_address = unused_loopback();
    let server_config = credentials.server(server_address, "");
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &server_config, "F2P sparse budget");
    wait_for_listener(&mut server, server_address);
    for profile in ["balanced", "realtime"] {
        let client_address = unused_tcp_udp_loopback();
        let metrics = unused_loopback();
        let config = credentials.client(
            client_address,
            server_address,
            profile,
            "token",
            "resolver.test",
        );
        let source = std::fs::read_to_string(&config).unwrap().replace(
            "max_buffered_bytes = 8388608",
            "max_buffered_bytes = 1048576",
        );
        std::fs::write(
            &config,
            format!("{source}\n[metrics]\nlisten = \"{metrics}\"\n"),
        )
        .unwrap();
        let mut client =
            ChildGuard::spawn_signallable("ferrum2-client", &config, "F2P sparse budget");
        wait_for_listener(&mut client, client_address);
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let source = target_wire(socket.local_addr().unwrap());
        let domain = domain_target_wire("127.0.0.1", socket.local_addr().unwrap().port());
        let echo = echo_datagrams(socket, 12);
        let mut associations = Vec::new();
        for index in 0_u8..6 {
            let (control, application, relay) = udp_associate(client_address, false);
            round_trip(&application, relay, &domain, &source, &[index]);
            associations.push((control, application, relay));
        }
        // Admission must preserve all earlier associations, not evict them to
        // make room for the next target mapping.
        for (index, (_, application, relay)) in associations.iter().enumerate() {
            round_trip(application, *relay, &domain, &source, &[index as u8, 1]);
        }
        echo.join().unwrap();
        let buffered = metric_value(
            &wait_for_metrics(metrics),
            "ferrum2_udp_buffered_bytes{role=\"client\"}",
        )
        .unwrap();
        assert!(
            buffered <= 1_048_576,
            "{profile}: budget exceeded: {buffered}"
        );
        drop(associations);
        stop(client);
    }
    stop(server);
}

#[test]
fn rocom_records_application_bytes_across_f2p_without_changing_half_close() {
    let credentials = Credentials::new();
    let server_address = unused_loopback();
    let server_config = credentials.server(server_address, "");
    let client_address = unused_tcp_udp_loopback();
    let client_config = credentials.client(
        client_address,
        server_address,
        "balanced",
        "token",
        "resolver.test",
    );
    let captures = credentials.directory.path().join("captures");
    let source = std::fs::read_to_string(&client_config).unwrap();
    std::fs::write(
        &client_config,
        format!(
            "{source}\n[rocom]\nrecord_path = \"{}\"\n",
            credentials.path("captures")
        ),
    )
    .unwrap();
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &server_config, "F2P recording");
    wait_for_listener(&mut server, server_address);
    let mut client =
        ChildGuard::spawn_signallable("ferrum2-client", &client_config, "F2P recording");
    wait_for_listener(&mut client, client_address);
    let (target, echo) = tcp_support::start_echo();
    let (mut stream, reply) =
        tcp_support::socks_connect_wire(client_address, &target_wire(target.into()));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut wire = vec![0x33, 0x66, 0, 1, 0, 1, 0x10, 1, 0];
    wire.extend_from_slice(&1_u32.to_be_bytes());
    wire.extend_from_slice(&23_u32.to_be_bytes());
    wire.extend_from_slice(&0_u32.to_be_bytes());
    wire.extend_from_slice(&[2, 3]);
    wire.extend_from_slice(b"opaque tail must remain exact\0\xff");
    stream.write_all(&wire[..7]).unwrap();
    stream.write_all(&wire[7..]).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut returned = Vec::new();
    stream.read_to_end(&mut returned).unwrap();
    assert_eq!(returned, wire);
    assert_eq!(echo.join().unwrap(), wire);
    drop(stream);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let records = loop {
        let finalized = std::fs::read_dir(&captures).unwrap().find_map(|entry| {
            let text = std::fs::read_to_string(entry.ok()?.path()).ok()?;
            let records = text
                .lines()
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            records
                .iter()
                .any(|record| record["kind"] == "stopped" && record["complete"] == true)
                .then_some(records)
        });
        if let Some(records) = finalized {
            break records;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "recording did not finalize"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    for direction in ["upload", "download"] {
        let captured: Vec<u8> = records
            .iter()
            .filter(|record| record["kind"] == "data" && record["direction"] == direction)
            .flat_map(|record| {
                base64::engine::general_purpose::STANDARD
                    .decode(record["bytes"].as_str().unwrap())
                    .unwrap()
            })
            .collect();
        assert_eq!(captured, wire, "{direction}");
    }
    stop(client);
    stop(server);
}
