#![allow(dead_code, unused_imports)]

#[path = "../../src/local_support/mod.rs"]
pub(super) mod local_support;

pub(super) use std::io::{Read, Write};
pub(super) use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
pub(super) use std::sync::mpsc;
pub(super) use std::thread;
pub(super) use std::time::{Duration, Instant};

pub(super) use hickory_proto::op::{Message, MessageType, OpCode, Query};
pub(super) use hickory_proto::rr::{Name, RData, RecordType};
pub(super) use local_support::{
    ChainRoot, ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, TCP_METHOD_CONFIGS,
    active_child_count, bind_loopback_listener, rewrite_config_method, route_tagged_config,
    start_dns_answer, start_dns_script, unused_loopback, unused_tcp_udp_loopback, wait_for_bound,
    wait_for_listener, wait_for_metrics, wait_for_metrics_sample, wait_for_tcp_udp_bound,
    write_client_config, write_client_config_with_psk, write_tagged_client_config,
    write_tagged_dns_server_matrix_config, write_tagged_server_config,
    write_tcp_only_server_config, write_tcp_only_server_config_with_psk,
    write_two_hop_client_config,
};
pub(super) use local_support::{EchoWorker, socks_connect_wire, start_echo, start_echo_at};

pub(super) fn start_recording_bridge(
    upstream: SocketAddrV4,
) -> (
    SocketAddrV4,
    mpsc::Receiver<SocketAddrV4>,
    thread::JoinHandle<()>,
) {
    let listener =
        bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bridge listener");
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

pub(super) fn socks_connect(client: SocketAddrV4, target: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    socks_connect_wire(client, &address_wire(SocketAddr::V4(target)))
}

pub(super) fn address_wire(target: SocketAddr) -> Vec<u8> {
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

pub(super) fn domain_wire(name: &str, port: u16) -> Vec<u8> {
    let mut wire = Vec::with_capacity(name.len() + 4);
    wire.extend_from_slice(&[3, name.len() as u8]);
    wire.extend_from_slice(name.as_bytes());
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

pub(super) fn assert_socks_domain_failure(client: SocketAddrV4, name: &str, port: u16) {
    let (mut socks, reply) = socks_connect_wire(client, &domain_wire(name, port));
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    socks
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("failed domain timeout");
    let mut byte = [0_u8; 1];
    match socks.read(&mut byte) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("failed domain forwarded {read} application bytes"),
    }
}
