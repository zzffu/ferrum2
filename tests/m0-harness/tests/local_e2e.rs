#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use local_support::{
    ChildGuard, TCP_METHOD_CONFIGS, rewrite_config_method, unused_loopback, wait_for_listener,
    write_client_config, write_client_config_with_psk, write_tcp_only_server_config,
    write_tcp_only_server_config_with_psk,
};

fn start_echo() -> (SocketAddrV4, thread::JoinHandle<Vec<u8>>) {
    let (address, handle) =
        start_echo_at(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let address = match address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    (address, handle)
}

fn start_echo_at(bind: SocketAddr) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(bind).expect("echo listener");
    let address = listener.local_addr().expect("echo address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking echo listener");
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "echo accept timed out"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("echo accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking echo stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("echo timeout");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("echo read");
        stream.write_all(&received).expect("echo write");
        stream.shutdown(Shutdown::Write).expect("echo half close");
        received
    });
    (address, handle)
}

fn start_recording_bridge(
    upstream: SocketAddrV4,
) -> (
    SocketAddrV4,
    mpsc::Receiver<SocketAddrV4>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bridge listener");
    let address = match listener.local_addr().expect("bridge address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    listener
        .set_nonblocking(true)
        .expect("nonblocking bridge listener");
    let (peer_sender, peer_receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (client, peer) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "bridge accept timed out"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("bridge accept failed: {error}"),
            }
        };
        client
            .set_nonblocking(false)
            .expect("blocking bridge client");
        let peer = match peer {
            std::net::SocketAddr::V4(peer) => peer,
            std::net::SocketAddr::V6(_) => unreachable!("IPv4 bridge peer"),
        };
        peer_sender.send(peer).expect("record bridge peer");
        let server = TcpStream::connect(upstream).expect("bridge upstream");
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("bridge read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .expect("bridge write timeout");
        }
        let mut client_read = client.try_clone().expect("clone bridge client");
        let mut server_write = server.try_clone().expect("clone bridge server");
        let forward = thread::spawn(move || {
            std::io::copy(&mut client_read, &mut server_write).expect("bridge client to server");
            server_write
                .shutdown(Shutdown::Write)
                .expect("bridge upstream half close");
        });
        let mut server_read = server;
        let mut client_write = client;
        std::io::copy(&mut server_read, &mut client_write).expect("bridge server to client");
        client_write
            .shutdown(Shutdown::Write)
            .expect("bridge client half close");
        forward.join().expect("bridge forward thread");
    });
    (address, peer_receiver, handle)
}

fn socks_connect(client: SocketAddrV4, target: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    socks_connect_wire(client, &address_wire(SocketAddr::V4(target)))
}

fn address_wire(target: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::new();
    match target {
        SocketAddr::V4(target) => {
            wire.push(1);
            wire.extend_from_slice(&target.ip().octets());
        }
        SocketAddr::V6(target) => {
            wire.push(4);
            wire.extend_from_slice(&target.ip().octets());
        }
    }
    wire.extend_from_slice(&target.port().to_be_bytes());
    wire
}

fn socks_connect_wire(client: SocketAddrV4, target: &[u8]) -> (TcpStream, [u8; 10]) {
    let mut stream = TcpStream::connect(client).expect("connect SOCKS client");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("SOCKS read timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(target);
    stream.write_all(&request).expect("SOCKS request");
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).expect("SOCKS reply");
    (stream, reply)
}

#[test]
fn success_bounded_method_matrix_preserves_bytes_and_half_close() {
    let ipv6_loopback = TcpListener::bind("[::1]:0").is_ok_and(|listener| {
        TcpStream::connect(listener.local_addr().expect("IPv6 probe address")).is_ok()
    });
    if !ipv6_loopback {
        eprintln!("SKIP real-process IPv6 row: host IPv6 loopback connect unavailable");
    }
    for (address_class, method) in TCP_METHOD_CONFIGS.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let server_address = unused_loopback();
        let client_address = unused_loopback();
        let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
            .expect("server config");
        let client_config =
            write_client_config(directory.path(), client_address, server_address, None)
                .expect("client config");
        rewrite_config_method(&server_config, method).expect("server method");
        rewrite_config_method(&client_config, method).expect("client method");
        let (target, echo) = match address_class {
            0 => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
            1 => {
                let (target, echo) = start_echo();
                let mut wire = b"\x03\x09127.0.0.1".to_vec();
                wire.extend_from_slice(&target.port().to_be_bytes());
                (wire, echo)
            }
            _ if ipv6_loopback => {
                let (target, echo) =
                    start_echo_at("[::1]:0".parse().expect("IPv6 loopback address"));
                (address_wire(target), echo)
            }
            _ => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
        };

        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        wait_for_listener(&mut server, server_address);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_listener(&mut client, client_address);

        let (mut socks, reply) = socks_connect_wire(client_address, &target);
        assert_eq!(&reply[..4], &[5, 0, 0, 1], "{}", method.0);
        let first = method.0.as_bytes();
        let second = vec![0x5a; 16_385];
        socks.write_all(first).expect("first payload");
        socks.write_all(&second).expect("second payload");
        socks.shutdown(Shutdown::Write).expect("client half close");

        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("reverse drain");
        let mut expected = first.to_vec();
        expected.extend_from_slice(&second);
        assert_eq!(echoed, expected, "{}", method.0);
        assert_eq!(echo.join().expect("echo thread"), expected, "{}", method.0);
    }
}

#[test]
fn success_reply_uses_exact_opened_shadowsocks_socket_local_endpoint() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let (bridge_address, bridge_peer, bridge) = start_recording_bridge(server_address);
    let client_config = write_client_config(directory.path(), client_address, bridge_address, None)
        .expect("client config");
    let (echo_address, echo) = start_echo();

    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, echo_address);
    let opened_endpoint = bridge_peer
        .recv_timeout(Duration::from_secs(5))
        .expect("opened Shadowsocks endpoint");
    let mut expected = [0_u8; 6];
    expected[..4].copy_from_slice(&opened_endpoint.ip().octets());
    expected[4..].copy_from_slice(&opened_endpoint.port().to_be_bytes());
    assert_eq!(&reply[4..], &expected);

    socks.write_all(b"endpoint").expect("payload");
    socks.shutdown(Shutdown::Write).expect("client half close");
    let mut echoed = Vec::new();
    socks.read_to_end(&mut echoed).expect("reverse drain");
    assert_eq!(echoed, b"endpoint");
    assert_eq!(echo.join().expect("echo thread"), b"endpoint");
    bridge.join().expect("bridge thread");
}

#[test]
fn failures_unauthenticated_request_never_connects_target() {
    const DIFFERENT_SYNTHETIC_PSK: &str = "EBESExQVFhcYGRobHB0eHw==";

    let directory = tempfile::tempdir().expect("temporary directory");
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("recording target");
    target
        .set_nonblocking(true)
        .expect("nonblocking recording target");
    let target_address = match target.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config_with_psk(
        directory.path(),
        server_address,
        None,
        DIFFERENT_SYNTHETIC_PSK,
    )
    .expect("server config");
    let client_config = write_client_config_with_psk(
        directory.path(),
        client_address,
        server_address,
        None,
        local_support::SYNTHETIC_PSK,
    )
    .expect("client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, target_address);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected application byte count after authentication reject: {read}"),
    }
    match target.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("unauthenticated request connected to target"),
        Err(error) => panic!("recording target accept failed: {error}"),
    }
}

#[test]
fn failures_pre_success_connect_and_post_success_target_refusal() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let unavailable_server = unused_loopback();
    let client_address = unused_loopback();
    let client_config =
        write_client_config(directory.path(), client_address, unavailable_server, None)
            .expect("client config");
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (_socks, reply) = socks_connect(client_address, unused_loopback());
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(client);

    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let client_config = write_client_config(directory.path(), client_address, server_address, None)
        .expect("client config");
    let refused_target = unused_loopback();
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (mut socks, reply) = socks_connect(client_address, refused_target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected second SOCKS reply/application byte count: {read}"),
    }
}
