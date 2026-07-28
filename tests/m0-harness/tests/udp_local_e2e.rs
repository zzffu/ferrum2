#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::time::Duration;

use local_support::{
    ChildGuard, bind_loopback_listener, run_binary, wait_for_bound, write_server_config,
};

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
