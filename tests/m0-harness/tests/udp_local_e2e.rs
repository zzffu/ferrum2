#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::fs;
use std::io;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, UdpSocket,
};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use local_support::{
    ChildGuard, active_child_count, bind_loopback_listener, run_binary, wait_for_bound,
    write_server_config,
};
use socket2::{Domain, Protocol, Socket, Type};

fn reserve_dual_free_address() -> SocketAddrV4 {
    loop {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve TCP port");
        let address = match tcp.local_addr().expect("reserved address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 reservation"),
        };
        match UdpSocket::bind(address) {
            Ok(udp) => {
                drop(udp);
                drop(tcp);
                return address;
            }
            Err(_) => drop(tcp),
        }
    }
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
#[ignore = "requires a Linux release host with IPv6-only loopback UDP enabled"]
fn ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps() {
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = reserve_dual_free_address();
    let config =
        write_server_config(directory.path(), server_address, None).expect("server config");
    let mut server =
        ChildGuard::spawn_with_context("ferrum2-server", &config, "IPv4 ingress to IPv6 target");
    wait_for_bound(&mut server, server_address);

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
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = reserve_dual_free_address();
    let config = write_server_config(directory.path(), address, None).expect("server config");
    let mut child = ChildGuard::spawn_with_context("ferrum2-server", &config, "UDP dual bind");
    wait_for_bound(&mut child, address);

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
    let directory = tempfile::tempdir().expect("temporary directory");

    let udp_address = reserve_dual_free_address();
    let udp_incumbent = UdpSocket::bind(udp_address).expect("occupy UDP");
    let udp_config =
        write_server_config(directory.path(), udp_address, None).expect("UDP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", udp_config.to_str().expect("UTF-8 config")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let rolled_back_tcp = bind_loopback_listener(udp_address).expect("TCP bind rolled back");
    drop(rolled_back_tcp);
    drop(udp_incumbent);

    let tcp_address = reserve_dual_free_address();
    let tcp_incumbent = bind_loopback_listener(tcp_address).expect("occupy TCP");
    let tcp_config =
        write_server_config(directory.path(), tcp_address, None).expect("TCP collision config");
    let output = run_binary(
        "ferrum2-server",
        &["--config", tcp_config.to_str().expect("UTF-8 config")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let never_owned_udp = UdpSocket::bind(tcp_address).expect("UDP was never retained");
    drop(never_owned_udp);
    drop(tcp_incumbent);
}

#[test]
fn disabled_udp_creates_no_udp_owner_and_preserves_tcp_only_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let address = reserve_dual_free_address();
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
