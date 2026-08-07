pub(in crate::run) use std::collections::BTreeSet;
pub(in crate::run) use std::io;
pub(in crate::run) use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
pub(in crate::run) use std::path::PathBuf;
pub(in crate::run) use std::pin::Pin;
pub(in crate::run) use std::sync::atomic::{AtomicUsize, Ordering};
pub(in crate::run) use std::sync::{Arc, Mutex, OnceLock};
pub(in crate::run) use std::task::Context;
pub(in crate::run) use std::time::Duration;

pub(in crate::run) use ferrum2_config::ValidatedServerConfig;
pub(in crate::run) use ferrum2_core::route::compile_selector_route;
pub(in crate::run) use ferrum2_core::selector::{
    SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedRoute, TaggedStaticBinding,
};
pub(in crate::run) use ferrum2_core::{ConnectErrorKind, Datagram, TargetAddr};
pub(in crate::run) use ferrum2_crypto::{
    Clock, MethodProfile, MethodPsk, MethodSinglePskProvider, SystemClock, SystemRandom,
};
pub(in crate::run) use ferrum2_runtime::{
    MAX_UDP_WIRE_DATAGRAM_BYTES, OwnerRegistry, OwnerSnapshot, ProcessCause, ProcessRoot,
    ProcessRootExit, ProcessSupervisor, RuntimeTcpStream, TcpConnector,
};
pub(in crate::run) use ferrum2_shadowsocks::{
    DetectionReason, MethodKeyAdapter, ProtocolReason, UdpClientSession, UdpPacketScratch,
};
pub(in crate::run) use tokio::net::{TcpListener, UdpSocket};

pub(in crate::run) use super::RunError;
use super::run_with_registry;
pub(in crate::run) use super::tokio_io::TokioTransport;

pub(in crate::run) const PSK_BYTES: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

pub(in crate::run) fn reserve_address() -> SocketAddrV4 {
    static ISSUED_SERVER_PORTS: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();
    loop {
        let tcp =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve TCP address");
        let address = match tcp.local_addr().expect("reserved address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 reservation"),
        };
        let Ok(udp) = std::net::UdpSocket::bind(address) else {
            drop(tcp);
            continue;
        };
        let inserted = ISSUED_SERVER_PORTS
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .expect("issued server port registry")
            .insert(address.port());
        drop((tcp, udp));
        if inserted {
            return address;
        }
    }
}

pub(in crate::run) async fn udp_loopback() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("UDP bind")
}

pub(in crate::run) async fn recv_udp(socket: &UdpSocket, buffer: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), socket.recv_from(buffer))
        .await
        .expect("UDP receive deadline")
        .expect("UDP receive")
}

pub(in crate::run) async fn assert_pending<F: std::future::Future>(future: F, message: &str) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), future)
            .await
            .is_err(),
        "{message}"
    );
}

pub(in crate::run) fn aes_keys() -> MethodKeyAdapter<MethodSinglePskProvider> {
    MethodKeyAdapter::new(MethodSinglePskProvider::new(
        MethodPsk::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &PSK_BYTES)
            .expect("AES-128 key"),
    ))
}

pub(in crate::run) fn server_test_config(listen: SocketAddrV4) -> (PathBuf, ValidatedServerConfig) {
    server_test_config_for_method(
        listen,
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==",
    )
}

pub(in crate::run) fn server_test_config_for_method(
    listen: SocketAddrV4,
    method: &str,
    psk: &str,
) -> (PathBuf, ValidatedServerConfig) {
    static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "ferrum2-server-composition-{}-{}.toml",
        std::process::id(),
        CONFIG_ID.fetch_add(1, Ordering::SeqCst)
    ));
    let source = format!(
        "schema_version = 1\n\
             [server]\n\
             listen = \"{listen}\"\n\
             [shadowsocks]\n\
             method = \"{method}\"\n\
             psk = \"{psk}\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n"
    );
    std::fs::write(&path, source).expect("server test config");
    let config = ferrum2_config::load_server(&path).expect("validated server test config");
    (path, config)
}

pub(in crate::run) fn tagged_server_test_config<const N: usize>(
    listens: [SocketAddrV4; N],
    selector: bool,
) -> (PathBuf, ValidatedServerConfig) {
    let (path, mut config) = server_test_config(listens[0]);
    config.inbounds.extend(
        listens[1..]
            .iter()
            .map(|listen| ferrum2_config::ServerInboundConfig { listen: *listen }),
    );
    config.runtime.max_connections = 1.try_into().expect("one connection");
    config.udp.max_sessions = 1;
    if selector {
        config.outbounds.push(ferrum2_config::ServerOutboundConfig);
        let (route, _) = compile_selector_route(
            &[TaggedInbound::new("i0", 0), TaggedInbound::new("i1", 1)],
            &[TaggedOutbound::new("o0", 0), TaggedOutbound::new("o1", 1)],
            &[
                SelectorDefinition::new("manual", vec!["o0", "o1"], Some("o0")),
                SelectorDefinition::new("nested", vec!["manual"], Some("manual")),
            ],
            TaggedRoute::Static(vec![
                TaggedStaticBinding::new("i0", "manual"),
                TaggedStaticBinding::new("i1", "nested"),
            ]),
        )
        .expect("selector route");
        config.route = route;
    }
    (path, config)
}

pub(in crate::run) fn active(mut snapshot: OwnerSnapshot) -> OwnerSnapshot {
    snapshot.process_root_reaps = 0;
    snapshot.process_root_rollbacks = 0;
    snapshot.process_forced_roots = 0;
    snapshot.forced_shutdowns = 0;
    snapshot.udp_forced_shutdowns = 0;
    snapshot
}

pub(in crate::run) type TestServerTask = tokio::task::JoinHandle<Result<(), RunError>>;

pub(in crate::run) fn spawn_test_server(
    config: ValidatedServerConfig,
    registry: &OwnerRegistry,
) -> (tokio::sync::oneshot::Sender<()>, TestServerTask) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(run_with_registry(config, registry.clone(), async move {
        let _ = stopped.await;
    }));
    (stop, task)
}

pub(in crate::run) fn encoded_udp_request(
    client: &mut UdpClientSession,
    clock: &SystemClock,
    target: TargetAddr,
    payload: &[u8],
) -> Vec<u8> {
    let request = Datagram::new(target, payload.into(), payload.len()).expect("UDP request");
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    let length = client
        .encode_request(clock, &SystemRandom, &request, 0, &mut wire, &mut scratch)
        .expect("encode UDP request");
    wire.truncate(length);
    wire
}
pub(in crate::run) async fn wait_until_bound(
    server: &mut tokio::task::JoinHandle<Result<(), RunError>>,
    address: SocketAddrV4,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if server.is_finished() {
            let result = (&mut *server).await.expect("server task before readiness");
            panic!("server exited before readiness: {result:?}");
        }
        match std::net::TcpListener::bind(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
            Ok(listener) => drop(listener),
            Err(error) => panic!("bind readiness failed: {error}"),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "listener readiness timed out"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
