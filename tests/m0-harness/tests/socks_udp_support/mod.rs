#![allow(dead_code, unused_imports)]

#[path = "../../src/local_support/mod.rs"]
pub(super) mod local_support;

pub(super) use std::io::{Read, Write};
pub(super) use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket,
};
pub(super) use std::sync::atomic::{AtomicBool, Ordering};
pub(super) use std::sync::{Arc, Barrier};
pub(super) use std::thread;
pub(super) use std::time::Duration;

pub(super) use hickory_proto::op::{Message, MessageType, OpCode, Query};
pub(super) use hickory_proto::rr::{Name, RData, RecordType};
pub(super) use local_support::{
    ChainRoot, ChildGuard, DnsReply, DnsStep, SYNTHETIC_PSK, TCP_METHOD_CONFIGS,
    active_child_count, bind_loopback_listener, metric_value, rewrite_config_method,
    start_dns_script, unused_loopback, unused_tcp_udp_loopback, wait_for_bound, wait_for_listener,
    wait_for_metrics, wait_for_metrics_sample, wait_for_tcp_udp_bound, write_client_config,
    write_server_config, write_server_config_with_psk, write_tagged_client_config,
    write_tagged_server_config, write_two_hop_client_config, write_udp_client_config,
};
pub(super) use socket2::SockRef;

pub(super) fn udp_associate(
    client: SocketAddrV4,
    hinted: bool,
) -> (TcpStream, UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("application UDP socket");
    let hint = if hinted {
        socket.local_addr().expect("application address").port()
    } else {
        0
    };
    let (control, reply) = udp_command_with_port(client, hint);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("application timeout");
    (control, socket, relay)
}

pub(super) fn udp_command(client: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    udp_command_with_port(client, 0)
}

pub(super) fn udp_command_with_port(client: SocketAddrV4, port: u16) -> (TcpStream, [u8; 10]) {
    let mut control = TcpStream::connect(client).expect("connect SOCKS control");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("control timeout");
    control.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let [high, low] = port.to_be_bytes();
    let hint = if port == 0 {
        [0, 0, 0, 0]
    } else {
        [192, 0, 2, 99]
    };
    control
        .write_all(&[5, 3, 0, 1, hint[0], hint[1], hint[2], hint[3], high, low])
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).expect("UDP command reply");
    (control, reply)
}

pub(super) fn socks_datagram(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    socks_datagram_for_target(&target_wire(SocketAddr::V4(target)), payload)
}

pub(super) fn socks_datagram_for_target(target: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0];
    wire.extend_from_slice(target);
    wire.extend_from_slice(payload);
    wire
}

pub(super) fn target_wire(target: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::new();
    match target {
        SocketAddr::V4(target) => {
            wire.push(1);
            wire.extend_from_slice(&target.ip().octets());
            wire.extend_from_slice(&target.port().to_be_bytes());
        }
        SocketAddr::V6(target) => {
            wire.push(4);
            wire.extend_from_slice(&target.ip().octets());
            wire.extend_from_slice(&target.port().to_be_bytes());
        }
    }
    wire
}

pub(super) fn domain_target_wire(domain: &str, port: u16) -> Vec<u8> {
    let mut wire = vec![3, u8::try_from(domain.len()).expect("test domain length")];
    wire.extend_from_slice(domain.as_bytes());
    wire.extend_from_slice(&port.to_be_bytes());
    wire
}

pub(super) fn round_trip(
    application: &UdpSocket,
    relay: SocketAddrV4,
    request_target: &[u8],
    response_target: &[u8],
    payload: &[u8],
) {
    let request = socks_datagram_for_target(request_target, payload);
    assert_eq!(
        application
            .send_to(&request, relay)
            .expect("SOCKS UDP send"),
        request.len()
    );
    let mut response = [0_u8; 65_507];
    let (length, source) = application
        .recv_from(&mut response)
        .expect("SOCKS UDP response");
    assert_eq!(source, SocketAddr::V4(relay));
    assert_eq!(
        &response[..length],
        socks_datagram_for_target(response_target, payload)
    );
}

pub(super) struct DatagramEcho {
    pub(super) address: SocketAddr,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) task: Option<thread::JoinHandle<()>>,
}

impl DatagramEcho {
    pub(super) fn join(mut self) -> thread::Result<()> {
        self.task.take().expect("datagram echo worker").join()
    }
}

impl Drop for DatagramEcho {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.stop.store(true, Ordering::SeqCst);
            let wake = match self.address {
                SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)),
            };
            if let Ok(wake) = wake {
                let _ = wake.send_to(&[], self.address);
            }
            let _ = task.join();
        }
    }
}

pub(super) fn echo_datagrams(socket: UdpSocket, count: usize) -> DatagramEcho {
    let address = socket.local_addr().expect("echo address");
    let stop = Arc::new(AtomicBool::new(false));
    let task_stop = Arc::clone(&stop);
    let task = thread::spawn(move || {
        let mut buffer = [0_u8; 65_507];
        for _ in 0..count {
            let (length, peer) = socket.recv_from(&mut buffer).expect("echo receive");
            if task_stop.load(Ordering::SeqCst) {
                return;
            }
            assert_eq!(
                socket.send_to(&buffer[..length], peer).expect("echo send"),
                length
            );
        }
    });
    DatagramEcho {
        address,
        stop,
        task: Some(task),
    }
}

pub(super) fn assert_no_datagram(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("short UDP timeout");
    let mut buffer = [0_u8; 1];
    let error = socket
        .recv_from(&mut buffer)
        .expect_err("datagram must drop");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("restore UDP timeout");
}

pub(super) fn wait_udp_rebind(address: SocketAddrV4, label: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match UdpSocket::bind(address) {
            Ok(socket) => return drop(socket),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                assert!(std::time::Instant::now() < deadline, "{label}");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
}

pub(super) struct Stack {
    pub(super) _directory: tempfile::TempDir,
    pub(super) server: ChildGuard,
    pub(super) client: ChildGuard,
    pub(super) client_address: SocketAddrV4,
    pub(super) metrics_address: SocketAddrV4,
}

impl Stack {
    pub(super) fn start(method: (&str, &str)) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let server_address = unused_tcp_udp_loopback();
        let client_address = unused_loopback();
        let metrics_address = unused_loopback();
        let server_config =
            write_server_config(directory.path(), server_address, None).expect("server config");
        let client_config = write_udp_client_config(
            directory.path(),
            client_address,
            server_address,
            Some(metrics_address),
        )
        .expect("client config");
        rewrite_config_method(&server_config, method).expect("server method");
        rewrite_config_method(&client_config, method).expect("client method");
        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        wait_for_tcp_udp_bound(&mut server, server_address);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_listener(&mut client, client_address);
        Self {
            _directory: directory,
            server,
            client,
            client_address,
            metrics_address,
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.client.terminate_and_reap(Duration::from_secs(5));
        self.server.terminate_and_reap(Duration::from_secs(5));
    }
}
