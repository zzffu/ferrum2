#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use local_support::{
    ChildGuard, active_child_count, bind_loopback_listener, run_binary, start_dns_answer,
    unused_loopback, unused_tcp_udp_loopback, wait_for_bound, wait_for_listener,
    wait_for_tcp_udp_bound, write_server_config, write_tagged_dns_server_config,
    write_udp_client_config,
};

const STARTUP_BIND_DIAGNOSTIC: &[u8] =
    b"error[startup.bind] process: unable to prepare required endpoint\n";
// ponytail: file-wide lock; use socket inheritance if these tests need parallel throughput.
static UDP_LOCAL_E2E_TEST_LOCK: Mutex<()> = Mutex::new(());
use socket2::{Domain, Protocol, Socket, Type};

fn udp_associate(client: SocketAddrV4) -> (TcpStream, UdpSocket, SocketAddrV4) {
    let mut control = TcpStream::connect(client).expect("connect SOCKS control");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("control timeout");
    control.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).expect("UDP command reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("application UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("application timeout");
    (control, socket, relay)
}

fn domain_target(name: &str, port: u16) -> Vec<u8> {
    let mut target = vec![3, u8::try_from(name.len()).expect("domain length")];
    target.extend_from_slice(name.as_bytes());
    target.extend_from_slice(&port.to_be_bytes());
    target
}

fn ip_target(target: SocketAddrV4) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend_from_slice(&target.ip().octets());
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire
}

fn dns_udp_round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    name: &str,
    target: SocketAddrV4,
    payload: &[u8],
) {
    let mut request = vec![0, 0, 0];
    request.extend_from_slice(&domain_target(name, target.port()));
    request.extend_from_slice(payload);
    assert_eq!(
        application.send_to(&request, relay).expect("UDP send"),
        request.len()
    );
    let mut response = [0_u8; 65_507];
    let (length, source) = application.recv_from(&mut response).expect("UDP response");
    assert_eq!(source, SocketAddr::V4(relay));
    let mut expected = vec![0, 0, 0];
    expected.extend_from_slice(&ip_target(target));
    expected.extend_from_slice(payload);
    assert_eq!(&response[..length], expected);
}

#[test]
fn tagged_dns_udp_resolution_uses_detour_and_reaps() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let selected_name = "selected-udp.test.";
    let final_name = "final-udp.test.";
    let selected_target = UdpSocket::bind("127.0.0.1:0").expect("selected target");
    let final_target = UdpSocket::bind("127.0.0.2:0").expect("final target");
    for target in [&selected_target, &final_target] {
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("target timeout");
    }
    let selected_address = match selected_target.local_addr().expect("selected address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 selected target"),
    };
    let final_address = match final_target.local_addr().expect("final address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 final target"),
    };
    let selected_echo = thread::spawn(move || {
        let mut packet = [0_u8; 64];
        let (length, peer) = selected_target
            .recv_from(&mut packet)
            .expect("selected receive");
        selected_target
            .send_to(&packet[..length], peer)
            .expect("selected echo");
    });
    let final_echo = thread::spawn(move || {
        let mut packet = [0_u8; 64];
        let (length, peer) = final_target.recv_from(&mut packet).expect("final receive");
        final_target
            .send_to(&packet[..length], peer)
            .expect("final echo");
    });
    let selected_dns = start_dns_answer(Ipv4Addr::new(127, 0, 0, 1), 2);
    let final_dns = start_dns_answer(Ipv4Addr::new(127, 0, 0, 2), 2);
    let dns_addresses = [selected_dns.address(), final_dns.address()];
    let server_address = unused_tcp_udp_loopback();
    let client_address = unused_loopback();
    let server_config = write_tagged_dns_server_config(
        directory.path(),
        server_address,
        selected_name,
        selected_address.port(),
        "udp",
        dns_addresses,
        true,
    )
    .expect("tagged DNS server config");
    let client_config =
        write_udp_client_config(directory.path(), client_address, server_address, None)
            .expect("UDP client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_tcp_udp_bound(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (control, application, relay) = udp_associate(client_address);

    dns_udp_round_trip(
        &application,
        relay,
        selected_name,
        selected_address,
        b"selected",
    );
    dns_udp_round_trip(&application, relay, final_name, final_address, b"final");
    selected_echo.join().expect("selected echo join");
    final_echo.join().expect("final echo join");
    assert_eq!(selected_dns.join(), [1, 28]);
    assert_eq!(final_dns.join(), [1, 28]);
    drop((application, control));
    let client_exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
    let server_exit = server.terminate_and_reap_with_exit(Duration::from_secs(5));
    for exit in [&client_exit, &server_exit] {
        exit.assert_stderr_excludes(&[
            selected_name,
            final_name,
            "selected",
            "final",
            "dns-direct",
            "app-direct",
        ]);
    }
    assert_eq!(active_child_count(), baseline_children);
    drop(bind_loopback_listener(client_address).expect("client exact rebind"));
    drop(bind_loopback_listener(server_address).expect("server TCP exact rebind"));
    drop(UdpSocket::bind(server_address).expect("server UDP exact rebind"));
    drop(UdpSocket::bind(relay).expect("client relay exact rebind"));
    drop(UdpSocket::bind(dns_addresses[0]).expect("selected DNS exact rebind"));
    drop(UdpSocket::bind(dns_addresses[1]).expect("final DNS exact rebind"));
}

fn disable_udp(path: &std::path::Path) {
    let mut source = fs::read_to_string(path).expect("server config");
    source.push_str("\n[udp]\nenabled = false\n");
    fs::write(path, source).expect("disable UDP");
}

fn bind_ipv6_only(address: SocketAddrV6) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.bind(&SocketAddr::V6(address).into())?;
    Ok(socket.into())
}

fn udp_protocol_example_path() -> std::path::PathBuf {
    let name = format!("udp_protocol_client{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .expect("test executable path")
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo target profile directory")
        .join("examples")
        .join(name)
}

#[test]
fn portable_ipv4_live_udp_signal_exits_cleanly_and_rebinds() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_tcp_udp_loopback();
    let config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let mut source = fs::read_to_string(&config).expect("read server config");
    source.push_str("\n[runtime]\nshutdown_grace_ms = 0\n");
    fs::write(&config, source).expect("write zero signal grace");
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &config, "portable live UDP signal");
    wait_for_tcp_udp_bound(&mut server, server_address);

    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 target bind");
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("target read timeout");
    let mut example = Command::new(udp_protocol_example_path())
        .args([
            "2022-blake3-aes-128-gcm",
            &server_address.to_string(),
            &target.local_addr().expect("target address").to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn UDP protocol example");
    let mut payload = [0_u8; 64];
    let (received, _) = target
        .recv_from(&mut payload)
        .expect("observe admitted UDP");
    assert_eq!(&payload[..received], b"m2-udp-aes128-datagram-0");
    assert!(example.try_wait().expect("example status").is_none());

    server.request_graceful_shutdown();
    let exit = server.wait_for_exit(Duration::from_secs(5));
    if example
        .try_wait()
        .expect("example status after signal")
        .is_none()
    {
        example.kill().expect("stop blocked UDP example");
    }
    example.wait().expect("reap UDP example");

    assert_eq!(exit.status.code(), Some(0), "{exit}");
    let tcp = bind_loopback_listener(server_address).expect("TCP signal rebind");
    let udp = UdpSocket::bind(server_address).expect("UDP signal rebind");
    drop((tcp, udp));
}

#[test]
#[ignore = "requires a Linux release host with IPv6-only loopback UDP enabled"]
fn ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_tcp_udp_loopback();
    let config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let mut server =
        ChildGuard::spawn_with_context("ferrum2-server", &config, "IPv4 ingress to IPv6 target");
    wait_for_tcp_udp_bound(&mut server, server_address);

    let echo = bind_ipv6_only(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .expect("IPv6-only echo bind");
    let echo_address = match echo.local_addr().expect("IPv6 echo address") {
        SocketAddr::V6(address) => address,
        SocketAddr::V4(_) => unreachable!("IPv6-only echo address"),
    };
    echo.set_nonblocking(true).expect("nonblocking IPv6 echo");
    let mut example = Command::new(udp_protocol_example_path())
        .args([
            "2022-blake3-aes-128-gcm",
            &server_address.to_string(),
            &echo_address.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn UDP protocol example");

    let (cancel, cancelled) = std::sync::mpsc::channel();
    let echo_worker = thread::spawn(move || {
        let mut observed = Vec::with_capacity(3);
        let mut buffer = [0_u8; 65_507];
        while cancelled.try_recv().is_err() {
            match echo.recv_from(&mut buffer) {
                Ok((received, peer)) => match echo.send_to(&buffer[..received], peer) {
                    Ok(sent) if sent == received => {
                        observed.push((buffer[..received].to_vec(), peer));
                        if observed.len() == 3 {
                            break;
                        }
                    }
                    _ => break,
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        observed
    });

    let deadline = Instant::now() + Duration::from_secs(40);
    let example_wait_error = loop {
        match example.try_wait() {
            Ok(Some(_)) => break None,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = example.kill();
                break Some("UDP protocol example timed out");
            }
            Err(_) => {
                let _ = example.kill();
                break Some("UDP protocol example status failed");
            }
        }
    };
    let example_output = example.wait_with_output();
    let _ = cancel.send(());
    let observed = echo_worker.join();
    server.terminate_and_reap(Duration::from_secs(5));
    let rebinds = (
        bind_loopback_listener(server_address),
        UdpSocket::bind(server_address),
        bind_ipv6_only(echo_address),
    );

    assert_eq!(example_wait_error, None);
    let output = example_output.expect("reap UDP protocol example");
    assert!(output.status.success(), "UDP protocol example failed");
    assert_eq!(
        output.stdout,
        b"udp_protocol_client status=PASS datagrams=3\n"
    );
    let observed = observed.expect("reap IPv6 echo owner");
    assert_eq!(observed.len(), 3);
    assert_eq!(observed[0].0, b"m2-udp-aes128-datagram-0");
    assert_eq!(observed[1].0, b"m2-udp-aes128-datagram-1");
    assert_eq!(observed[2].0, b"m2-udp-aes128-datagram-2");
    assert!(observed.iter().all(|(_, peer)| *peer == observed[0].1));
    assert!(matches!(observed[0].1, SocketAddr::V6(peer) if peer.ip().is_loopback()));
    assert!(
        rebinds.0.is_ok() && rebinds.1.is_ok() && rebinds.2.is_ok(),
        "socket rebind failed"
    );
    assert_eq!(active_child_count(), baseline_children);
    println!(
        "m2_ipv6_udp_real_process status=PASS datagrams=3 payload=PASS source=PASS cleanup=PASS"
    );
}

#[test]
fn default_startup_owns_same_tcp_udp_port_and_shutdown_rebinds_both() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = unused_tcp_udp_loopback();
    let config = write_server_config(directory.path(), address, None).expect("server config");
    let mut child = ChildGuard::spawn_with_context("ferrum2-server", &config, "UDP dual bind");
    wait_for_tcp_udp_bound(&mut child, address);

    let tcp_error = bind_loopback_listener(address).expect_err("TCP must be owned");
    assert_eq!(tcp_error.kind(), io::ErrorKind::AddrInUse);
    let udp_error = UdpSocket::bind(address).expect_err("UDP must be owned");
    assert_eq!(udp_error.kind(), io::ErrorKind::AddrInUse);

    child.terminate_and_reap(Duration::from_secs(5));
    let tcp = bind_loopback_listener(address).expect("TCP rebind");
    let udp = UdpSocket::bind(address).expect("UDP rebind");
    drop(udp);
    drop(tcp);
}

#[test]
fn either_bind_failure_rolls_back_the_other_before_any_loop_runs() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");

    let udp_address = unused_tcp_udp_loopback();
    let udp_incumbent = UdpSocket::bind(udp_address).expect("occupy UDP");
    let udp_config =
        write_server_config(directory.path(), udp_address, None).expect("UDP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", udp_config.to_str().expect("UTF-8 config")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, STARTUP_BIND_DIAGNOSTIC);
    let rolled_back_tcp = bind_loopback_listener(udp_address).expect("TCP bind rolled back");
    drop(rolled_back_tcp);
    drop(udp_incumbent);

    let tcp_address = unused_tcp_udp_loopback();
    let tcp_incumbent = bind_loopback_listener(tcp_address).expect("occupy TCP");
    let tcp_config =
        write_server_config(directory.path(), tcp_address, None).expect("TCP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", tcp_config.to_str().expect("UTF-8 config")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, STARTUP_BIND_DIAGNOSTIC);
    let never_owned_udp = UdpSocket::bind(tcp_address).expect("UDP was never retained");
    drop(never_owned_udp);
    drop(tcp_incumbent);
}

#[test]
fn disabled_udp_creates_no_udp_owner_and_preserves_tcp_only_restart() {
    let _test_guard = UDP_LOCAL_E2E_TEST_LOCK.lock().expect("UDP local E2E lock");
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = unused_tcp_udp_loopback();
    let config = write_server_config(directory.path(), address, None).expect("server config");
    disable_udp(&config);

    for cycle in 0..2 {
        let mut child = ChildGuard::spawn_with_context(
            "ferrum2-server",
            &config,
            format!("UDP disabled cycle {cycle}"),
        );
        wait_for_bound(&mut child, address);
        let udp = UdpSocket::bind(address).expect("disabled UDP leaves port free");
        child.assert_running();
        drop(udp);
        child.terminate_and_reap(Duration::from_secs(5));
    }
}
