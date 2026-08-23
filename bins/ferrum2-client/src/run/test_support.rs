pub(in crate::run) use std::collections::HashSet;
pub(in crate::run) use std::io;
pub(in crate::run) use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
pub(in crate::run) use std::path::PathBuf;
pub(in crate::run) use std::pin::Pin;
pub(in crate::run) use std::sync::atomic::{AtomicUsize, Ordering};
pub(in crate::run) use std::sync::{Arc, Mutex};
pub(in crate::run) use std::task::{Context, Poll};
pub(in crate::run) use std::time::Duration;

pub(in crate::run) use ferrum2_config::{RuntimeConfig, ValidatedClientConfig};
pub(in crate::run) use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, Datagram, Inbound as _,
    LocalEndpoint, TargetAddr,
};
pub(in crate::run) use ferrum2_crypto::{
    Clock, MethodProfile, MethodSinglePskProvider, RandomError, SecureRandom, SystemClock,
    SystemRandom,
};
pub(in crate::run) use ferrum2_dns::{DnsProxy, DnsProxySockets};
pub(in crate::run) use ferrum2_observability::Metrics;
pub(in crate::run) use ferrum2_rule::{
    SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan, TaggedRoute, TaggedRouteRule,
    TaggedStaticBinding, compile_selector_plans, compile_selector_plans_with_roots,
    compile_selector_route,
};
pub(in crate::run) use ferrum2_runtime::{
    OwnerRegistry, OwnerSnapshot, ProcessRoot, ProcessSupervisor, SupervisorError, TcpConnector,
    UdpDirection, UdpRuntimeLimits, UdpSessionManager,
};
pub(in crate::run) use ferrum2_shadowsocks::{
    BufferObserver, BufferRole, DetectionReason, FlowObserver, FlowTerminal, MAX_UDP_WIRE_LEN,
    MethodKeyAdapter, ProtocolReason, ShadowsocksTcpInbound, TcpReplayStore, UdpServer,
    max_udp_payload_len,
};
pub(in crate::run) use ferrum2_socks5::{
    Socks5Inbound, SocksCommand, SocksUdpAssociate, encode_udp_datagram,
};
pub(in crate::run) use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
pub(in crate::run) use hickory_proto::rr::rdata::A;
pub(in crate::run) use hickory_proto::rr::{Name, RData, Record, RecordType};
pub(in crate::run) use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf,
};
pub(in crate::run) use tokio::net::{TcpListener, UdpSocket};
pub(in crate::run) use tokio::sync::Notify;
pub(in crate::run) use tokio::time::Instant;

pub(in crate::run) use super::RunError;
pub(in crate::run) use super::context::{ClientContext, ClientRouting};
pub(in crate::run) use super::egress::{
    ClientEgressEngine, ClientOpenFailure, ClientOutboundContext, ClientShadowsocksContext,
    ClientUdpContext, prepare_client_outbounds,
};
pub(in crate::run) use super::tokio_io::{TokioConnector, TokioFramed, TokioTransport};
use super::{
    ClientRunResources, dns_egress, run_with_registry, run_with_registry_and_metrics_inner,
};

enum ScriptedMode {
    Duplex(tokio::io::DuplexStream),
    Fail,
    Pending(Arc<AtomicUsize>),
    StallAfter {
        writes: usize,
        drops: Arc<AtomicUsize>,
    },
    WriteLimitAfter {
        writes: usize,
        limit: Option<usize>,
        accepted: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    },
}

pub(in crate::run) struct ScriptedIo {
    mode: ScriptedMode,
    endpoint: SocketAddrV4,
    aborts: Arc<AtomicUsize>,
}

impl ScriptedIo {
    pub(in crate::run) fn duplex(
        inner: tokio::io::DuplexStream,
        endpoint: SocketAddrV4,
        aborts: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            mode: ScriptedMode::Duplex(inner),
            endpoint,
            aborts,
        }
    }

    pub(in crate::run) fn failing() -> Self {
        Self {
            mode: ScriptedMode::Fail,
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
            aborts: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(in crate::run) fn pending(drops: Arc<AtomicUsize>, aborts: Arc<AtomicUsize>) -> Self {
        Self {
            mode: ScriptedMode::Pending(drops),
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
            aborts,
        }
    }

    pub(in crate::run) fn stall_after(
        writes: usize,
        drops: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            mode: ScriptedMode::StallAfter { writes, drops },
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
            aborts,
        }
    }

    pub(in crate::run) fn write_limit_after(
        writes: usize,
        limit: usize,
        accepted: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            mode: ScriptedMode::WriteLimitAfter {
                writes,
                limit: Some(limit),
                accepted,
                calls,
                drops,
            },
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
            aborts,
        }
    }
}

impl Drop for ScriptedIo {
    fn drop(&mut self) {
        match &self.mode {
            ScriptedMode::Pending(drops)
            | ScriptedMode::StallAfter { drops, .. }
            | ScriptedMode::WriteLimitAfter { drops, .. } => {
                drops.fetch_add(1, Ordering::SeqCst);
            }
            ScriptedMode::Duplex(_) | ScriptedMode::Fail => {}
        }
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.mode {
            ScriptedMode::Duplex(inner) => Pin::new(inner).poll_read(cx, buffer),
            ScriptedMode::Fail => Poll::Ready(Err(io::Error::other("transport source sentinel"))),
            ScriptedMode::Pending(_)
            | ScriptedMode::StallAfter { .. }
            | ScriptedMode::WriteLimitAfter { .. } => Poll::Pending,
        }
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.mode {
            ScriptedMode::Duplex(inner) => Pin::new(inner).poll_write(cx, source),
            ScriptedMode::Fail => Poll::Ready(Err(io::Error::other("transport source sentinel"))),
            ScriptedMode::Pending(_) => Poll::Pending,
            ScriptedMode::StallAfter { writes, .. } if *writes == 0 => Poll::Pending,
            ScriptedMode::StallAfter { writes, .. } => {
                *writes -= 1;
                Poll::Ready(Ok(source.len()))
            }
            ScriptedMode::WriteLimitAfter {
                writes,
                limit,
                accepted,
                calls,
                ..
            } => {
                let written = if *writes == 0 {
                    limit
                        .take()
                        .map_or(source.len(), |limit| limit.min(source.len()))
                } else {
                    *writes -= 1;
                    source.len()
                };
                accepted
                    .lock()
                    .expect("accepted raw wire")
                    .extend_from_slice(&source[..written]);
                calls.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.mode {
            ScriptedMode::Duplex(inner) => Pin::new(inner).poll_flush(cx),
            ScriptedMode::Fail => Poll::Ready(Err(io::Error::other("transport source sentinel"))),
            ScriptedMode::Pending(_)
            | ScriptedMode::StallAfter { .. }
            | ScriptedMode::WriteLimitAfter { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.mode {
            ScriptedMode::Duplex(inner) => Pin::new(inner).poll_shutdown(cx),
            ScriptedMode::Fail => Poll::Ready(Err(io::Error::other("transport source sentinel"))),
            ScriptedMode::Pending(_)
            | ScriptedMode::StallAfter { .. }
            | ScriptedMode::WriteLimitAfter { .. } => Poll::Ready(Ok(())),
        }
    }
}

impl LocalEndpoint for ScriptedIo {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }
}

impl AbortiveClose for ScriptedIo {
    type Error = io::Error;
    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

static ISSUED_TEST_PORTS: std::sync::LazyLock<Mutex<HashSet<u16>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

pub(in crate::run) struct GateConnector {
    pub(in crate::run) gate: Arc<Notify>,
    pub(in crate::run) calls: Arc<AtomicUsize>,
    pub(in crate::run) targets: Arc<Mutex<Vec<TargetAddr>>>,
    pub(in crate::run) stream: Mutex<Option<ScriptedIo>>,
}

impl Connector for GateConnector {
    type Stream = ScriptedIo;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets
            .lock()
            .expect("connector targets")
            .push(target.clone());
        self.gate.notified().await;
        Ok(self
            .stream
            .lock()
            .expect("connector stream")
            .take()
            .expect("one connect"))
    }
}

pub(in crate::run) struct DeadlineConnector {
    pub(in crate::run) delay: Duration,
    pub(in crate::run) targets: Mutex<Vec<TargetAddr>>,
    pub(in crate::run) stream: Mutex<Option<TokioTransport<ScriptedIo>>>,
}

impl Connector for DeadlineConnector {
    type Stream = TokioTransport<ScriptedIo>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.targets
            .lock()
            .expect("deadline targets")
            .push(target.clone());
        tokio::time::sleep(self.delay).await;
        Ok(self
            .stream
            .lock()
            .expect("deadline stream")
            .take()
            .expect("one deadline connect"))
    }
}

pub(in crate::run) struct FixedRandom;

impl SecureRandom for FixedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        destination.fill(0x42);
        Ok(())
    }
}

#[derive(Default)]
pub(in crate::run) struct ChainObserver {
    pub(in crate::run) buffers: Mutex<Vec<(BufferRole, usize, usize)>>,
    pub(in crate::run) terminals: Mutex<Vec<FlowTerminal>>,
    pub(in crate::run) owner_drops: AtomicUsize,
}

impl BufferObserver for ChainObserver {
    fn allocated(&self, role: BufferRole, limit: usize, identity: usize) {
        self.buffers
            .lock()
            .expect("chain buffers")
            .push((role, limit, identity));
    }
}

impl FlowObserver for ChainObserver {
    fn terminal_installed(&self, terminal: FlowTerminal) {
        self.terminals
            .lock()
            .expect("chain terminals")
            .push(terminal);
    }

    fn owner_dropped(&self) {
        self.owner_drops.fetch_add(1, Ordering::SeqCst);
    }
}

pub(in crate::run) fn chain_test_setup(
    methods: [MethodProfile; 4],
    first_port: u16,
) -> (
    Arc<[ClientOutboundContext]>,
    ferrum2_rule::RouteTable,
    ferrum2_core::selector::SelectorControl,
) {
    let servers: [SocketAddrV4; 4] =
        std::array::from_fn(|hop| SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port + hop as u16));
    let psks: [ferrum2_crypto::MethodPsk; 4] = std::array::from_fn(|hop| {
        let bytes = [0x41 + hop as u8; 32];
        ferrum2_crypto::MethodPsk::try_from_slice(methods[hop], &bytes[..methods[hop].key_bytes()])
            .expect("hop PSK")
    });
    let outbounds = prepare_client_outbounds(
        servers
            .into_iter()
            .zip(psks)
            .map(
                |(server, psk)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: server.into(),
                    psk: Arc::new(psk),
                    dial_options: Default::default(),
                },
            )
            .collect(),
    )
    .expect("checked runtime outbounds");
    let (route, selector) = compile_selector_plans(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("a", 0),
            TaggedOutbound::new("b", 1),
            TaggedOutbound::new("c", 2),
            TaggedOutbound::new("d", 3),
        ],
        &[
            TaggedPlan::new("a-b", vec![0, 1]),
            TaggedPlan::new("c-d", vec![2, 3]),
        ],
        &[SelectorDefinition::new(
            "manual",
            vec!["a-b", "c-d"],
            Some("a-b"),
        )],
        TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "manual")]),
    )
    .expect("chain selector");
    (outbounds, route, selector)
}

pub(in crate::run) async fn scripted_input(bytes: &[u8]) -> TokioTransport<ScriptedIo> {
    let (io, mut source) = tokio::io::duplex(65_536);
    source.write_all(bytes).await.expect("scripted wire");
    source.shutdown().await.expect("scripted EOF");
    TokioTransport::new(ScriptedIo::duplex(
        io,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_153),
        Arc::new(AtomicUsize::new(0)),
    ))
}

pub(in crate::run) fn assert_two_layer_buffers(
    observer: &ChainObserver,
    label: impl std::fmt::Display,
) {
    let buffers = observer.buffers.lock().expect("chain buffers");
    assert_eq!(buffers.len(), 4, "{label}");
    assert_eq!(
        buffers
            .iter()
            .map(|(_, _, identity)| identity)
            .collect::<HashSet<_>>()
            .len(),
        4,
        "{label}"
    );
}

pub(in crate::run) fn test_datagram(target: TargetAddr, payload: &[u8]) -> Datagram {
    Datagram::new(target, payload.into(), payload.len()).expect("test datagram")
}
pub(in crate::run) fn psk_for_method(method: MethodProfile) -> ferrum2_crypto::MethodPsk {
    match method {
        MethodProfile::Blake3Aes128Gcm2022 => ferrum2_crypto::MethodPsk::aes128([0x31; 16]),
        MethodProfile::Blake3Aes256Gcm2022 => ferrum2_crypto::MethodPsk::aes256([0x32; 32]),
        MethodProfile::Blake3ChaCha20Poly13052022 => {
            ferrum2_crypto::MethodPsk::chacha20_poly1305([0x33; 32])
        }
    }
}

pub(in crate::run) fn other_psk_for_method(method: MethodProfile) -> ferrum2_crypto::MethodPsk {
    match method {
        MethodProfile::Blake3Aes128Gcm2022 => ferrum2_crypto::MethodPsk::aes128([0xa1; 16]),
        MethodProfile::Blake3Aes256Gcm2022 => ferrum2_crypto::MethodPsk::aes256([0xa2; 32]),
        MethodProfile::Blake3ChaCha20Poly13052022 => {
            ferrum2_crypto::MethodPsk::chacha20_poly1305([0xa3; 32])
        }
    }
}
pub(in crate::run) fn reserve_address() -> SocketAddrV4 {
    let mut issued = ISSUED_TEST_PORTS.lock().expect("issued test ports");
    for port in 10_000..30_000 {
        if issued.contains(&port) {
            continue;
        }
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        if let (Ok(_tcp), Ok(_udp)) = (
            std::net::TcpListener::bind(address),
            std::net::UdpSocket::bind(address),
        ) {
            issued.insert(port);
            return address;
        }
    }
    panic!("no paired test address available")
}

pub(in crate::run) fn client_test_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
) -> (PathBuf, ValidatedClientConfig) {
    static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "ferrum2-client-composition-{}-{}.toml",
        std::process::id(),
        CONFIG_ID.fetch_add(1, Ordering::SeqCst)
    ));
    let source = format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{listen}\"\noutbound = \"proxy-out\"\n[[outbounds]]\ntag = \"proxy-out\"\nserver = \"{server}\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n[runtime]\nshutdown_grace_ms = 0\n"
    );
    std::fs::write(&path, source).expect("client test config");
    let config = ferrum2_config::load_client(&path).expect("validated client test config");
    (path, config)
}

pub(in crate::run) fn client_udp_test_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
) -> (PathBuf, ValidatedClientConfig) {
    let (path, _) = client_test_config(listen, server);
    let mut source = std::fs::read_to_string(&path).expect("client test config");
    source.push_str("[udp]\nmax_sessions = 1\nmax_buffered_bytes = 1048576\n");
    std::fs::write(&path, source).expect("client UDP test config");
    let config = ferrum2_config::load_client(&path).expect("validated client UDP config");
    (path, config)
}

pub(in crate::run) fn client_udp_chain_test_config(
    listen: SocketAddrV4,
    servers: [SocketAddrV4; 2],
    methods: [MethodProfile; 2],
) -> (PathBuf, ValidatedClientConfig) {
    let (path, mut config) = client_udp_test_config(listen, servers[0]);
    config.outbounds = servers
        .into_iter()
        .zip(methods)
        .map(
            |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: server.into(),
                psk: Arc::new(psk_for_method(method)),
                dial_options: Default::default(),
            },
        )
        .collect();
    config.route = compile_selector_plans(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("outer", 0),
            TaggedOutbound::new("inner", 1),
        ],
        &[TaggedPlan::new("chain", vec![0, 1])],
        &[],
        TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "chain")]),
    )
    .expect("static chain")
    .0;
    (path, config)
}

pub(in crate::run) fn tagged_client_test_config(
    mappings: &[(SocketAddrV4, SocketAddrV4)],
    udp: bool,
) -> (PathBuf, ValidatedClientConfig) {
    let (path, mut config) = if udp {
        client_udp_test_config(mappings[0].0, mappings[0].1)
    } else {
        client_test_config(mappings[0].0, mappings[0].1)
    };
    config.inbounds = mappings
        .iter()
        .map(|(listen, _)| ferrum2_config::ClientInboundConfig { listen: *listen })
        .collect();
    config.outbounds = mappings
        .iter()
        .map(
            |(_, server)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: (*server).into(),
                psk: Arc::new(psk_for_method(MethodProfile::Blake3Aes128Gcm2022)),
                dial_options: Default::default(),
            },
        )
        .collect();
    config.route = ferrum2_rule::RouteTable::static_bindings((0..mappings.len()).collect())
        .expect("bounded test mappings");
    (path, config)
}

pub(in crate::run) fn default_test_psk() -> ferrum2_crypto::MethodPsk {
    ferrum2_crypto::MethodPsk::aes128([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
}

pub(in crate::run) fn test_routing(
    server: SocketAddrV4,
    psk: ferrum2_crypto::MethodPsk,
) -> ClientRouting {
    ClientRouting {
        legacy: ferrum2_rule::RouteTable::static_bindings(vec![0]).expect("test route"),
        program: None,
        outbounds: vec![ClientOutboundContext::Shadowsocks(
            ClientShadowsocksContext {
                tcp_server: TargetAddr::ipv4(server).expect("server target"),
                udp_server: server.into(),
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk)),
                dial_options: ferrum2_runtime::DialOptions::default(),
            },
        )]
        .into(),
        selector: ferrum2_rule::SelectorControl::empty(),
    }
}

pub(in crate::run) fn active(mut snapshot: OwnerSnapshot) -> OwnerSnapshot {
    snapshot.process_root_reaps = 0;
    snapshot.process_root_rollbacks = 0;
    snapshot.process_forced_roots = 0;
    snapshot.forced_shutdowns = 0;
    snapshot.udp_forced_shutdowns = 0;
    snapshot
}

pub(in crate::run) type TestClientTask = tokio::task::JoinHandle<Result<(), RunError>>;

pub(in crate::run) fn spawn_test_client(
    config: ValidatedClientConfig,
    registry: &OwnerRegistry,
) -> (tokio::sync::oneshot::Sender<()>, TestClientTask) {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_with_registry(config, registry.clone(), async move {
        let _ = stopped.await;
    }));
    (stop, task)
}

pub(in crate::run) fn spawn_test_client_with_random(
    config: ValidatedClientConfig,
    registry: &OwnerRegistry,
    random: Arc<dyn SecureRandom>,
) -> (tokio::sync::oneshot::Sender<()>, TestClientTask) {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    let task = tokio::spawn(run_with_registry_and_metrics_inner(
        config,
        registry.clone(),
        async move {
            let _ = stopped.await;
        },
        Arc::new(Metrics::new()),
        Some(random),
        None,
        ClientRunResources::test_unmaterialized(dns_specs),
    ));
    (stop, task)
}

pub(in crate::run) async fn socks_command(
    listen: SocketAddrV4,
    command: u8,
) -> (tokio::net::TcpStream, [u8; 10]) {
    let mut stream = tokio::net::TcpStream::connect(listen)
        .await
        .expect("SOCKS connect");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    let request = if command == 3 {
        [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
    } else {
        [5, command, 0, 1, 127, 0, 0, 1, 0, 80]
    };
    stream.write_all(&request).await.expect("command");
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.expect("reply");
    (stream, reply)
}

pub(in crate::run) async fn socks_connect_port(
    listen: SocketAddrV4,
    port: u16,
) -> (tokio::net::TcpStream, [u8; 10]) {
    let mut stream = tokio::net::TcpStream::connect(listen)
        .await
        .expect("SOCKS connect");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.expect("method");
    let [high, low] = port.to_be_bytes();
    stream
        .write_all(&[5, 1, 0, 1, 192, 0, 2, 1, high, low])
        .await
        .expect("request");
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.expect("reply");
    (stream, reply)
}

pub(in crate::run) async fn udp_association(
    listen: SocketAddrV4,
) -> (tokio::net::TcpStream, UdpSocket, SocketAddrV4) {
    let (control, reply) = socks_command(listen, 3).await;
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application socket");
    (control, application, relay)
}

pub(in crate::run) struct FailingConnector {
    pub(in crate::run) calls: Arc<AtomicUsize>,
}

impl Connector for FailingConnector {
    type Stream = ScriptedIo;

    async fn connect(&self, _target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ConnectError::new(ConnectErrorKind::Other))
    }
}
pub(in crate::run) fn udp_test_context_for_server(
    registry: OwnerRegistry,
    server: SocketAddrV4,
) -> (PathBuf, Arc<ClientContext>) {
    udp_test_context_for_psk(registry, server, None)
}

pub(in crate::run) fn udp_test_context_for_psk(
    registry: OwnerRegistry,
    server: SocketAddrV4,
    psk: Option<ferrum2_crypto::MethodPsk>,
) -> (PathBuf, Arc<ClientContext>) {
    let (path, config) = client_udp_test_config(reserve_address(), server);
    let server_psk = psk.unwrap_or_else(default_test_psk);
    let udp = config.udp.expect("enabled UDP");
    let server = match config.outbounds[0].server().unwrap() {
        std::net::SocketAddr::V4(server) => server,
        std::net::SocketAddr::V6(_) => panic!("IPv4 test server"),
    };
    let runtime = config.runtime;
    let outbounds = prepare_client_outbounds(config.outbounds).expect("test outbounds");
    let udp = ClientUdpContext {
        manager: UdpSessionManager::new(
            UdpRuntimeLimits::new(udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout)
                .expect("UDP limits"),
            registry.clone(),
        ),
        live_ids: Arc::new(Mutex::new(HashSet::new())),
    };
    let context = ClientContext {
        inbound: Socks5Inbound::new(),
        egress: Arc::new(ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                super::egress::system_application_resolver(),
                runtime.connect_timeout,
            )),
            SystemClock::new(),
            SystemRandom,
            (runtime.connect_timeout, runtime.handshake_timeout),
            Some(udp),
            None,
        )),
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(server_psk)),
        runtime,
        udp_associate_enabled: true,
        registry,
        metrics: Arc::new(Metrics::new()),
        dns: None,
        test_udp_server: server,
    };
    (path, Arc::new(context))
}

pub(in crate::run) async fn parsed_udp_association() -> (
    SocksUdpAssociate<tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
) {
    let (mut peer, application) = tokio::io::duplex(128);
    let peer_task = tokio::spawn(async move {
        peer.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        peer.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [5, 0]);
        peer.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP request");
        peer
    });
    let command = Socks5Inbound::new()
        .accept_command(application)
        .await
        .expect("parsed command");
    let SocksCommand::UdpAssociate(association) = command else {
        panic!("UDP association")
    };
    (association, peer_task.await.expect("peer task"))
}
pub(in crate::run) async fn wait_until_bound(address: SocketAddrV4) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
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
