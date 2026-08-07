use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_core::route::compile_selector_route;
use ferrum2_core::selector::{
    SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedRoute, TaggedStaticBinding,
};
use ferrum2_core::{ConnectError, Connector, Datagram, TargetAddr};
use ferrum2_crypto::{
    Aes128Psk, MethodProfile, MethodPsk, MethodSinglePskProvider, MethodTcpSalt, SinglePskProvider,
};
use ferrum2_runtime::{OwnerSnapshot, UdpDirection, UdpSessionManager};
use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

#[test]
fn tagged_dns_selection_uses_authenticated_original_context_and_final() {
    let selected = TargetAddr::domain("selected.example.", 8443).expect("selected target");
    let other = TargetAddr::domain("other.example.", 8443).expect("final target");
    let route = ferrum2_core::route::ActionTable::new(
        vec![ferrum2_core::route::ActionRule::new(
            Some(1),
            Some(Network::Tcp),
            Some(selected.clone()),
            0,
        )],
        1,
    )
    .expect("DNS route");
    let state = dns_egress::ServerDnsState::new(route);

    assert_eq!(state.select(1, Network::Tcp, &selected), 0);
    assert_eq!(state.select(0, Network::Tcp, &selected), 1);
    assert_eq!(state.select(1, Network::Udp, &selected), 1);
    assert_eq!(state.select(1, Network::Tcp, &other), 1);
}

const PSK_BYTES: [u8; 16] = [
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

async fn assert_pending<F: std::future::Future>(future: F, message: &str) {
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

fn server_test_config_for_method(
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

fn tagged_server_test_config<const N: usize>(
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

type TestServerTask = tokio::task::JoinHandle<Result<(), RunError>>;

fn spawn_test_server(
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

#[tokio::test]
async fn udp_composition_three_methods_echo_and_deferred_client_commit_table() {
    let rows: [(MethodProfile, &str, &str, &[u8]); 3] = [
        (
            MethodProfile::Blake3Aes128Gcm2022,
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
            &PSK_BYTES,
        ),
        (
            MethodProfile::Blake3Aes256Gcm2022,
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            "2022-blake3-chacha20-poly1305",
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            &[
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ],
        ),
    ];
    for (profile, method, encoded_psk, psk) in rows {
        let listen = reserve_address();
        let echo = udp_loopback().await;
        let echo_target = echo.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            for _ in 0..3 {
                let (length, peer) = echo.recv_from(&mut buffer).await.expect("echo receive");
                echo.send_to(&buffer[..length], peer)
                    .await
                    .expect("echo reply");
            }
        });
        let (path, config) = server_test_config_for_method(listen, method, encoded_psk);
        let registry = OwnerRegistry::new();
        let (stop, mut server) = spawn_test_server(config, &registry);
        wait_until_bound(&mut server, listen).await;

        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, psk).expect("method key"),
        ));
        let clock = SystemClock::new();
        let mut client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
        let socket = udp_loopback().await;
        let mut response_scratch = UdpPacketScratch::new();
        let mut response_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        let client_registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), client_registry.clone());
        let mut handle = None;

        for (index, payload) in [b"one".as_slice(), b"two", b"three"]
            .into_iter()
            .enumerate()
        {
            let target = if profile == MethodProfile::Blake3Aes128Gcm2022 && index == 2 {
                TargetAddr::domain("127.0.0.1", echo_target.port()).expect("numeric domain target")
            } else {
                TargetAddr::ip(echo_target).expect("echo target")
            };
            let request_wire = encoded_udp_request(&mut client, &clock, target, payload);
            socket
                .send_to(&request_wire, listen)
                .await
                .expect("send request");
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response_wire))
                    .await
                    .expect("response deadline")
                    .expect("receive response");
            assert_eq!(source, SocketAddr::V4(listen));
            let pending = client
                .prepare_response(&clock, &response_wire[..length], &mut response_scratch)
                .expect("prepare response");
            let capacity = pending.datagram().allocated_capacity();
            let (datagram, commit) = pending.into_parts();
            let now = tokio::time::Instant::now();
            let accepted_handle = match handle {
                Some(handle) => {
                    manager
                        .reserve_datagram(handle, UdpDirection::ToClient, capacity)
                        .expect("response capacity")
                        .commit_with(datagram, now, || {
                            // The local client composition owns this call;
                            // it mirrors the same deferred T03 transition.
                            client.commit_response(commit, clock.monotonic_now())
                        })
                        .expect("deferred response commit");
                    handle
                }
                None => {
                    let session = manager.reserve_session(now).expect("client session");
                    let reserved = session
                        .reserve_datagram(UdpDirection::ToClient, capacity)
                        .expect("first response capacity");
                    session
                        .commit_with(reserved, datagram, now, || {
                            // The first client association is also deferred
                            // until session/bytes/queue capacity is reserved.
                            client.commit_response(commit, clock.monotonic_now())
                        })
                        .expect("deferred first response commit")
                }
            };
            handle = Some(accepted_handle);
            let accepted = manager
                .pop(accepted_handle, UdpDirection::ToClient)
                .expect("response queue")
                .expect("accepted response");
            assert_eq!(accepted.datagram().payload(), payload);
            assert_eq!(
                accepted.datagram().target(),
                &TargetAddr::ip(echo_target).expect("observed source target")
            );
        }

        echo_task.await.expect("echo task");
        stop.send(()).expect("stop server");
        assert_eq!(server.await.expect("server task"), Ok(()), "{method}");
        manager.cancel_all();
        assert_eq!(client_registry.snapshot().udp_sessions, 0);
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove UDP config");
    }
}

#[tokio::test]
async fn udp_real_socket_session_saturation_never_reaches_second_target() {
    let listen = reserve_address();
    let (path, _config) = server_test_config(listen);
    let mut source = std::fs::read_to_string(&path).expect("server config");
    source.push_str(
        "[udp]\nmax_sessions = 1\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n",
    );
    std::fs::write(&path, source).expect("bounded UDP config");
    let config = ferrum2_config::load_server(&path).expect("bounded server config");
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let stalled_target = udp_loopback().await;
    let stalled_address = stalled_target.local_addr().expect("stalled address");
    let forbidden_target = udp_loopback().await;
    let forbidden_address = forbidden_target.local_addr().expect("forbidden address");
    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut first = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
    let mut second = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let first_socket = udp_loopback().await;
    let second_socket = udp_loopback().await;
    let wire = encoded_udp_request(
        &mut first,
        &clock,
        TargetAddr::ip(stalled_address).expect("stalled target"),
        b"occupy",
    );
    first_socket
        .send_to(&wire, listen)
        .await
        .expect("first send");
    let mut target_buffer = [0_u8; 32];
    let (received, _) = recv_udp(&stalled_target, &mut target_buffer).await;
    assert_eq!(&target_buffer[..received], b"occupy");

    let wire = encoded_udp_request(
        &mut second,
        &clock,
        TargetAddr::ip(forbidden_address).expect("forbidden target"),
        b"must-not-send",
    );
    second_socket
        .send_to(&wire, listen)
        .await
        .expect("second send");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            forbidden_target.recv_from(&mut target_buffer)
        )
        .await
        .is_err(),
        "saturated session reached the second target"
    );

    stop.send(()).expect("stop server");
    assert_eq!(server.await.expect("server task"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove saturation config");
}

#[tokio::test]
async fn tagged_udp_is_process_bounded_and_bound_to_its_local_inbound() {
    let first_listen = reserve_address();
    let second_listen = reserve_address();
    let target = udp_loopback().await;
    let target_address = target.local_addr().expect("target address");
    let routed_target = udp_loopback().await;
    let routed_address = routed_target.local_addr().expect("routed target address");
    let routed_domain =
        TargetAddr::domain("127.0.0.1", routed_address.port()).expect("domain target");
    let poison_new = udp_loopback().await;
    let poison_new_address = TargetAddr::ip(poison_new.local_addr().expect("new poison address"))
        .expect("new poison target");
    let poison_existing = udp_loopback().await;
    let poison_existing_address = TargetAddr::domain(
        "127.0.0.1",
        poison_existing
            .local_addr()
            .expect("existing poison address")
            .port(),
    )
    .expect("existing poison target");
    let (path, mut config) = tagged_server_test_config([first_listen, second_listen], true);
    let selector = config.selector_control();
    config.outbounds.truncate(1);
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, first_listen).await;
    wait_until_bound(&mut server, second_listen).await;

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let first_peer = udp_loopback().await;
    let roaming_peer = udp_loopback().await;
    let cross_peer = udp_loopback().await;
    let mut second = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let poison_wire = encoded_udp_request(&mut second, &clock, poison_new_address, b"new-poison");
    let baseline = registry.snapshot();
    selector.switch("manual", "o1").expect("select missing B");
    cross_peer
        .send_to(&poison_wire, second_listen)
        .await
        .expect("new poison send");
    let mut payload = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    assert_pending(
        poison_new.recv_from(&mut payload),
        "new poison reached target",
    )
    .await;
    assert_eq!(registry.snapshot(), baseline);
    assert_eq!(selector.selected("manual"), Ok("o1"));
    selector.switch("manual", "o0").expect("select direct A");
    let first_wire = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target_address).expect("target"),
        b"first",
    );
    first_peer
        .send_to(&first_wire, second_listen)
        .await
        .expect("first send");
    let (received, direct_peer) = recv_udp(&target, &mut payload).await;
    assert_eq!(&payload[..received], b"first");
    selector.switch("manual", "o1").expect("switch in flight");
    target
        .send_to(b"first-response", direct_peer)
        .await
        .expect("first target response");
    let (_, response_source) = recv_udp(&first_peer, &mut payload).await;
    assert_eq!(response_source, SocketAddr::V4(second_listen));
    let poison_wire = encoded_udp_request(
        &mut client,
        &clock,
        poison_existing_address,
        b"existing-poison",
    );
    let before_poison = registry.snapshot();
    first_peer
        .send_to(&poison_wire, second_listen)
        .await
        .expect("existing poison send");
    assert_pending(
        poison_existing.recv_from(&mut payload),
        "existing poison reached target",
    )
    .await;
    assert_eq!(registry.snapshot(), before_poison);
    selector.switch("manual", "o0").expect("restore direct A");
    let cross_wire = encoded_udp_request(&mut client, &clock, routed_domain, b"cross-fresh");
    let before_cross = registry.snapshot();

    cross_peer
        .send_to(&cross_wire, first_listen)
        .await
        .expect("cross-inbound send");
    assert_pending(
        routed_target.recv_from(&mut payload),
        "cross-inbound session reached target",
    )
    .await;
    let after_cross = registry.snapshot();
    assert_eq!(after_cross, before_cross);
    roaming_peer
        .send_to(&cross_wire, second_listen)
        .await
        .expect("same-inbound roaming send");
    let (received, direct_peer) = recv_udp(&routed_target, &mut payload).await;
    assert_eq!(&payload[..received], b"cross-fresh");
    selector
        .switch("manual", "o1")
        .expect("switch routed response");
    routed_target
        .send_to(b"roaming-response", direct_peer)
        .await
        .expect("roaming target response");
    let (_, response_source) = recv_udp(&roaming_peer, &mut payload).await;
    assert_eq!(response_source, SocketAddr::V4(second_listen));
    selector.switch("manual", "o0").expect("restore direct A");
    let second_wire = encoded_udp_request(
        &mut second,
        &clock,
        TargetAddr::ip(target_address).expect("second target"),
        b"over-capacity",
    );
    roaming_peer
        .send_to(&second_wire, second_listen)
        .await
        .expect("second inbound capacity send");
    assert_pending(
        target.recv_from(&mut payload),
        "second inbound multiplied process session cap",
    )
    .await;
    stop.send(()).expect("stop tagged server");
    assert_eq!(server.await.expect("tagged server owner"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove tagged config");
}

#[tokio::test]
async fn tagged_tcp_shares_static_direct_mapping_and_one_replay_store() {
    let first_listen = reserve_address();
    let second_listen = reserve_address();
    let first_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("first target bind");
    let second_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("second target bind");
    let first_address = TargetAddr::ip(first_target.local_addr().expect("first target address"))
        .expect("first target");
    let second_address = TargetAddr::ip(second_target.local_addr().expect("second target address"))
        .expect("second target");
    let (path, mut config) = tagged_server_test_config([first_listen, second_listen], true);
    let selector = config.selector_control();
    config.outbounds.truncate(1);
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, first_listen).await;
    wait_until_bound(&mut server, second_listen).await;

    let keys = aes_keys();
    let timestamp = SystemClock::new().unix_seconds().expect("wall clock");
    let request = |salt_byte, target: &TargetAddr, payload: &[u8]| {
        let salt =
            MethodTcpSalt::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &[salt_byte; 16])
                .expect("request salt");
        encode_request_first_write(&keys, &salt, timestamp, target, &[0xa1], payload)
            .expect("request wire")
    };
    let mut invalid = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("invalid inbound connect");
    invalid
        .write_all(b"invalid")
        .await
        .expect("invalid request");
    invalid.shutdown().await.expect("invalid shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), invalid.read(&mut [0_u8; 1]))
        .await
        .expect("invalid close deadline");
    assert_pending(first_target.accept(), "invalid request reached target").await;

    let replayed = request(0x51, &first_address, b"first");
    let mut first = tokio::net::TcpStream::connect(first_listen)
        .await
        .expect("first inbound connect");
    first.write_all(&replayed).await.expect("first request");
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), first_target.accept())
        .await
        .expect("first direct deadline")
        .expect("first direct accept");
    let mut payload = [0_u8; 5];
    accepted
        .read_exact(&mut payload)
        .await
        .expect("first initial payload");
    assert_eq!(&payload, b"first");
    selector.switch("manual", "o1").expect("switch to B");
    accepted
        .write_all(b"captured A")
        .await
        .expect("target write");
    assert!(first.read(&mut [0; 64]).await.expect("captured A wire") > 0);

    let mut replay = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("replay inbound connect");
    replay.write_all(&replayed).await.expect("replayed request");
    let poison = request(0x52, &first_address, b"poison");
    let mut second = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("second inbound connect");
    second.write_all(&poison).await.expect("poison request");
    assert_pending(
        first_target.accept(),
        "second listener bypassed process permit",
    )
    .await;
    assert_eq!(registry.snapshot().connection_tasks, 1);

    drop((first, accepted));
    for rejected in [&mut replay, &mut second] {
        let _ = tokio::time::timeout(Duration::from_secs(5), rejected.read(&mut payload))
            .await
            .expect("rejected deadline");
    }
    assert_eq!(selector.selected("manual"), Ok("o1"));
    let final_poison = request(0x53, &second_address, b"final");
    let mut final_flow = tokio::net::TcpStream::connect(first_listen)
        .await
        .expect("final-route connect");
    final_flow
        .write_all(&final_poison)
        .await
        .expect("final request");
    let _ = tokio::time::timeout(Duration::from_secs(5), final_flow.read(&mut payload))
        .await
        .expect("final close deadline");
    assert_pending(second_target.accept(), "final poison reached target").await;
    assert_pending(
        first_target.accept(),
        "replay or inbound poison reached target",
    )
    .await;
    selector.switch("manual", "o0").expect("restore A");
    let selected = request(0x54, &second_address, b"selected");
    let mut later = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("later inbound connect");
    later.write_all(&selected).await.expect("later request");
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), second_target.accept())
        .await
        .expect("later direct deadline")
        .expect("later direct accept");
    let mut payload = [0; 8];
    accepted
        .read_exact(&mut payload)
        .await
        .expect("later initial payload");
    assert_eq!(&payload, b"selected");
    drop((later, accepted));

    stop.send(()).expect("stop tagged server");
    assert_eq!(server.await.expect("tagged server owner"), Ok(()));
    assert_eq!(registry.snapshot().connection_tasks, 0);
    std::fs::remove_file(path).expect("remove tagged config");
}

#[tokio::test]
async fn tagged_prepare_failure_positions_rollback_every_bound_address() {
    for block in 0..7 {
        let listens = [reserve_address(), reserve_address(), reserve_address()];
        let metrics = reserve_address();
        let (path, mut config) = tagged_server_test_config(listens, false);
        config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
        let incumbent: Box<dyn Send> = match block {
            0..=2 => {
                Box::new(std::net::TcpListener::bind(listens[block]).expect("occupy TCP position"))
            }
            3..=5 => Box::new(
                std::net::UdpSocket::bind(listens[block - 3]).expect("occupy UDP position"),
            ),
            _ => Box::new(std::net::TcpListener::bind(metrics).expect("occupy metrics position")),
        };
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        assert_eq!(
            run_with_registry(config, registry.clone(), std::future::pending()).await,
            Err(RunError::StartupBind)
        );
        drop(incumbent);
        for listen in listens {
            let tcp = std::net::TcpListener::bind(listen).expect("TCP rollback rebind");
            let udp = std::net::UdpSocket::bind(listen).expect("UDP rollback rebind");
            drop((tcp, udp));
        }
        drop(std::net::TcpListener::bind(metrics).expect("metrics rollback rebind"));
        assert_eq!(active(registry.snapshot()), baseline);
        std::fs::remove_file(path).expect("remove tagged failure config");
    }
}

async fn wait_until_bound(
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

struct ProtocolClientConnector {
    inner: TcpConnector,
}

impl Connector for ProtocolClientConnector {
    type Stream = TokioTransport<RuntimeTcpStream>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.inner.connect(target).await.map(TokioTransport::new)
    }
}

#[tokio::test]
async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
    let listen = reserve_address();
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_address = match target_listener.local_addr().expect("target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let (config_path, config) = server_test_config(listen);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, mut run_task) = spawn_test_server(config, &registry);
    wait_until_bound(&mut run_task, listen).await;

    let target_accept =
        tokio::spawn(async move { target_listener.accept().await.expect("target accept").0 });
    let keys = SinglePskProvider::new(Aes128Psk::from_bytes(PSK_BYTES));
    let connector = ProtocolClientConnector {
        inner: TcpConnector::new(Duration::from_secs(5)),
    };
    let server_target = TargetAddr::ipv4(listen).expect("server target");
    let application_target = TargetAddr::ipv4(target_address).expect("application target");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let outbound = ClientTcpOutbound::new(server_target, &keys, &connector, &clock, &random);
    let flow = outbound
        .connect_server()
        .await
        .expect("connect server")
        .write_request(&application_target)
        .await
        .expect("write request");
    let target_stream = target_accept.await.expect("target accept task");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let live = registry.snapshot();
        if live.active_supervisor_children == 1
            && live.connection_tasks == 1
            && live.owned_buffers == 2
            && live.owned_permits >= 1
            && live.listeners == 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "registry never exposed the live production path: {live:?}"
        );
        tokio::task::yield_now().await;
    }

    shutdown_sender.send(()).expect("request shutdown");
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    drop(flow);
    drop(target_stream);
    let final_snapshot = registry.snapshot();
    assert_eq!(
        final_snapshot.active_supervisor_children,
        baseline.active_supervisor_children
    );
    assert_eq!(final_snapshot.connection_tasks, baseline.connection_tasks);
    assert_eq!(final_snapshot.owned_buffers, baseline.owned_buffers);
    assert_eq!(final_snapshot.owned_permits, baseline.owned_permits);
    assert_eq!(final_snapshot.listeners, baseline.listeners);
    assert!(
        final_snapshot.process_forced_roots > baseline.process_forced_roots,
        "zero-grace process did not force any required root: {final_snapshot:?}"
    );
    assert_eq!(
        final_snapshot.forced_shutdowns,
        baseline.forced_shutdowns + 1,
        "phase-aware TCP root did not explicitly force and reap its child"
    );
    std::fs::remove_file(config_path).expect("remove server test config");
}
