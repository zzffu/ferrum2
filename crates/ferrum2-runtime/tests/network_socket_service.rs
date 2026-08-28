use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_net::{
    DialOptions, InterfaceBinding, InterfaceSelectionSource, NetworkInterfaceCatalog,
    NetworkInterfaceCatalogError, NetworkInterfaceObservation, NetworkInterfaceResolver,
    NetworkSnapshot, ResolvedInterface, RouteNetworkOptions, SystemBestRoute,
};
use ferrum2_runtime::{
    DirectUdpSocket, NetworkResetCoordinator, NetworkResetIntent, NetworkResetLimits,
    NetworkResetReason, NetworkRuntimeOwnerCancellation, NetworkRuntimeResourceAdmissionError,
    NetworkSnapshotPublisher, NetworkSocketMode, NetworkSocketOperations, NetworkSocketService,
    NetworkSocketServiceError, NetworkTcpStream, OwnerRegistry, RuntimeTcpStream,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[test]
fn physical_tcp_stream_satisfies_shared_protocol_io_contract() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NetworkTcpStream<RuntimeTcpStream>>();
}

#[derive(Default)]
struct Catalog;

impl NetworkInterfaceCatalog for Catalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Ok(Vec::new())
    }

    fn system_best_route(
        &self,
        _: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}

fn binding(generation: u64) -> InterfaceBinding {
    InterfaceBinding::new(
        format!("underlay-{generation}"),
        generation,
        u32::try_from(generation).unwrap(),
        [IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            u8::try_from(generation).unwrap(),
        ))],
    )
    .unwrap()
}

fn snapshot(generation: u64) -> Arc<NetworkSnapshot> {
    Arc::new(NetworkSnapshot::new(generation, Some(binding(generation)), None).unwrap())
}

fn coordinator(owners: &OwnerRegistry) -> NetworkResetCoordinator {
    NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(snapshot(1)),
        NetworkResetLimits::default(),
        owners.clone(),
    )
}

fn destination(port: u16) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, 9], port))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallKind {
    PrepareTcp,
    ConnectTcp,
    PrepareUdp,
    ConnectUdp,
    SendTo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Call {
    kind: CallKind,
    destination: SocketAddr,
    generation: u64,
    source: InterfaceSelectionSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeError {
    Connect,
}

#[derive(Default)]
struct FakeState {
    calls: Mutex<Vec<Call>>,
    race_publications: AtomicUsize,
    snapshots: Mutex<Option<NetworkSnapshotPublisher>>,
    tcp_connect_pending: AtomicUsize,
    tcp_connect_failure: AtomicUsize,
    udp_connect_pending: AtomicUsize,
    connect_started: tokio::sync::Notify,
    tcp_read_started: tokio::sync::Notify,
    udp_read_started: tokio::sync::Notify,
    udp_send_started: tokio::sync::Notify,
    udp_recv_started: tokio::sync::Notify,
    udp_send_pending: AtomicUsize,
    tcp_socket_drops: AtomicUsize,
    tcp_stream_drops: AtomicUsize,
    udp_socket_drops: AtomicUsize,
}

#[derive(Clone)]
struct FakeOperations {
    state: Arc<FakeState>,
}

impl FakeOperations {
    fn record(&self, kind: CallKind, destination: SocketAddr, resolved: &ResolvedInterface) {
        self.state.calls.lock().unwrap().push(Call {
            kind,
            destination,
            generation: resolved.snapshot_generation(),
            source: resolved.selection_source(),
        });
    }

    fn publish_race(&self, generation: u64) {
        let remaining = self.state.race_publications.load(Ordering::SeqCst);
        if remaining == 0 {
            return;
        }
        self.state.race_publications.fetch_sub(1, Ordering::SeqCst);
        self.state
            .snapshots
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .publish_if_current(generation, snapshot(generation + 1))
            .unwrap();
    }
}

struct FakeTcpSocket {
    state: Arc<FakeState>,
}

impl Drop for FakeTcpSocket {
    fn drop(&mut self) {
        self.state.tcp_socket_drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeTcpStream {
    state: Arc<FakeState>,
}

impl Drop for FakeTcpStream {
    fn drop(&mut self) {
        self.state.tcp_stream_drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for FakeTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.state.tcp_read_started.notify_one();
        Poll::Pending
    }
}

impl AsyncWrite for FakeTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(payload.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl LocalEndpoint for FakeTcpStream {
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 49_152))
    }
}

impl AbortiveClose for FakeTcpStream {
    type Error = Infallible;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct FakeUdpSocket {
    state: Arc<FakeState>,
    generation: u64,
    source: InterfaceSelectionSource,
}

impl Drop for FakeUdpSocket {
    fn drop(&mut self) {
        self.state.udp_socket_drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl DirectUdpSocket for FakeUdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.state.calls.lock().unwrap().push(Call {
            kind: CallKind::SendTo,
            destination: target,
            generation: self.generation,
            source: self.source,
        });
        self.state.udp_send_started.notify_one();
        if self.state.udp_send_pending.load(Ordering::SeqCst) != 0 {
            std::future::pending::<()>().await;
        }
        Ok(payload.len())
    }

    async fn readable(&self) -> io::Result<()> {
        self.state.udp_read_started.notify_one();
        std::future::pending().await
    }

    async fn recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        self.state.udp_recv_started.notify_one();
        std::future::pending().await
    }

    fn try_recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl NetworkSocketOperations for FakeOperations {
    type TcpSocket = FakeTcpSocket;
    type TcpStream = FakeTcpStream;
    type UdpSocket = FakeUdpSocket;
    type Error = FakeError;

    fn prepare_tcp(
        &self,
        destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::TcpSocket, Self::Error> {
        self.record(CallKind::PrepareTcp, destination, resolved);
        self.publish_race(resolved.snapshot_generation());
        Ok(FakeTcpSocket {
            state: Arc::clone(&self.state),
        })
    }

    async fn connect_tcp(
        &self,
        socket: Self::TcpSocket,
        destination: SocketAddr,
    ) -> Result<Self::TcpStream, Self::Error> {
        self.state.calls.lock().unwrap().push(Call {
            kind: CallKind::ConnectTcp,
            destination,
            generation: 0,
            source: InterfaceSelectionSource::SystemBestRoute,
        });
        self.state.connect_started.notify_one();
        if self.state.tcp_connect_pending.load(Ordering::SeqCst) != 0 {
            std::future::pending::<()>().await;
            return Err(FakeError::Connect);
        }
        drop(socket);
        if self.state.tcp_connect_failure.load(Ordering::SeqCst) != 0 {
            return Err(FakeError::Connect);
        }
        Ok(FakeTcpStream {
            state: Arc::clone(&self.state),
        })
    }

    fn prepare_udp(
        &self,
        destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::UdpSocket, Self::Error> {
        self.record(CallKind::PrepareUdp, destination, resolved);
        self.publish_race(resolved.snapshot_generation());
        Ok(FakeUdpSocket {
            state: Arc::clone(&self.state),
            generation: resolved.snapshot_generation(),
            source: resolved.selection_source(),
        })
    }

    async fn connect_udp(
        &self,
        socket: Self::UdpSocket,
        destination: SocketAddr,
    ) -> Result<Self::UdpSocket, Self::Error> {
        self.state.calls.lock().unwrap().push(Call {
            kind: CallKind::ConnectUdp,
            destination,
            generation: socket.generation,
            source: socket.source,
        });
        self.state.connect_started.notify_one();
        if self.state.udp_connect_pending.load(Ordering::SeqCst) != 0 {
            std::future::pending::<()>().await;
            return Err(FakeError::Connect);
        }
        Ok(socket)
    }
}

fn service(
    owners: &OwnerRegistry,
    state: Arc<FakeState>,
) -> (
    NetworkResetCoordinator,
    NetworkSocketService<Catalog, FakeOperations>,
) {
    service_with_mode(owners, state, NetworkSocketMode::Dynamic)
}

fn service_with_mode(
    owners: &OwnerRegistry,
    state: Arc<FakeState>,
    mode: NetworkSocketMode,
) -> (
    NetworkResetCoordinator,
    NetworkSocketService<Catalog, FakeOperations>,
) {
    let coordinator = coordinator(owners);
    *state.snapshots.lock().unwrap() = Some(coordinator.snapshots());
    let service = NetworkSocketService::with_mode(
        mode,
        coordinator.clone(),
        NetworkInterfaceResolver::new(Catalog),
        FakeOperations { state },
    );
    (coordinator, service)
}

fn route() -> RouteNetworkOptions {
    RouteNetworkOptions::new(true, None::<&str>)
}

#[tokio::test]
async fn unconnected_udp_uses_first_target_only_for_selection_and_allows_send_to() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (_coordinator, service) = service(&owners, Arc::clone(&state));
    let first = destination(53);
    let second = destination(5353);

    let socket = service
        .open_udp(&DialOptions::default(), &route(), first)
        .unwrap();
    assert_eq!(socket.resolved_interface().snapshot_generation(), 1);
    assert_eq!(
        socket.resolved_interface().selection_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(socket.send_to(b"query", second).await.unwrap(), 5);

    let calls = state.calls.lock().unwrap().clone();
    assert_eq!(calls[0].kind, CallKind::PrepareUdp);
    assert_eq!(calls[0].destination, first);
    assert!(!calls.iter().any(|call| call.kind == CallKind::ConnectUdp));
    assert_eq!(calls.last().unwrap().kind, CallKind::SendTo);
    assert_eq!(calls.last().unwrap().destination, second);
    assert_eq!(owners.snapshot().network_runtime_owners, 1);
    drop(socket);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn frozen_udp_generation_never_retries_into_the_new_generation() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.race_publications.store(1, Ordering::SeqCst);
    let (coordinator, service) = service(&owners, Arc::clone(&state));

    let error = service
        .open_udp_for_generation(1, &DialOptions::default(), &route(), destination(53))
        .unwrap_err();
    assert!(matches!(
        error,
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                attempted_source: InterfaceSelectionSource::AutoDetected,
            }
        )
    ));
    assert_eq!(
        state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.kind == CallKind::PrepareUdp)
            .count(),
        1,
        "an exact-generation association must not retry preparation on generation 2"
    );
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(coordinator.snapshots().generation(), 2);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);

    let calls_before = state.calls.lock().unwrap().len();
    let stale = service
        .open_udp_for_generation(1, &DialOptions::default(), &route(), destination(5353))
        .unwrap_err();
    assert!(matches!(
        stale,
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged { .. }
        )
    ));
    assert_eq!(
        state.calls.lock().unwrap().len(),
        calls_before,
        "an already-stale generation must fail before socket preparation"
    );
}

#[tokio::test]
async fn connected_udp_has_an_explicit_connect_path() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (_coordinator, service) = service(&owners, Arc::clone(&state));

    let socket = service
        .connect_udp(&DialOptions::default(), &route(), destination(443))
        .await
        .unwrap();
    assert_eq!(
        state
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.kind)
            .collect::<Vec<_>>(),
        [CallKind::PrepareUdp, CallKind::ConnectUdp]
    );
    drop(socket);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn a_second_generation_race_fails_after_exactly_two_complete_prepares() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.race_publications.store(2, Ordering::SeqCst);
    let (coordinator, service) = service(&owners, Arc::clone(&state));

    let error = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        NetworkSocketServiceError::Admission(
            NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                attempted_source: InterfaceSelectionSource::AutoDetected,
            }
        )
    ));
    assert_eq!(
        error.attempted_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(
        state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.kind == CallKind::PrepareTcp)
            .count(),
        2
    );
    assert_eq!(state.tcp_socket_drops.load(Ordering::SeqCst), 2);
    assert_eq!(coordinator.snapshots().generation(), 3);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn one_generation_race_retries_the_whole_prepare_and_admits_the_new_source() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.race_publications.store(1, Ordering::SeqCst);
    let (_coordinator, service) = service(&owners, Arc::clone(&state));

    let stream = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .unwrap();
    let generations = state
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.kind == CallKind::PrepareTcp)
        .map(|call| call.generation)
        .collect::<Vec<_>>();
    assert_eq!(generations, [1, 2]);
    assert_eq!(stream.resolved_interface().snapshot_generation(), 2);
    assert_eq!(
        stream.resolved_interface().selection_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(state.tcp_socket_drops.load(Ordering::SeqCst), 2);
    assert_eq!(owners.snapshot().network_runtime_owners, 1);
    drop(stream);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn stable_connection_failure_retains_the_closed_selection_source() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.tcp_connect_failure.store(1, Ordering::SeqCst);
    let (_coordinator, service) = service(&owners, Arc::clone(&state));

    let error = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        NetworkSocketServiceError::Connection {
            attempted_source: InterfaceSelectionSource::AutoDetected,
            error: FakeError::Connect,
        }
    ));
    assert_eq!(
        error.attempted_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn tcp_connect_reset_closes_the_prepared_socket_and_releases_owner() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.tcp_connect_pending.store(1, Ordering::SeqCst);
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let connect = tokio::spawn(async move {
        service
            .connect_tcp(&DialOptions::default(), &route(), destination(443))
            .await
    });
    state.connect_started.notified().await;
    let report = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .await
        .unwrap();
    let error = connect.await.unwrap().unwrap_err();

    assert!(matches!(error, NetworkSocketServiceError::Cancelled { .. }));
    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert_eq!(state.tcp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn tcp_reset_wakes_a_pending_operation_and_retains_the_terminal_reason() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let mut stream = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .expect("generation-bound TCP stream");
    let operation = tokio::spawn(async move {
        let result = stream.read_u8().await;
        (stream, result)
    });
    state.tcp_read_started.notified().await;

    let intent = NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged);
    let report = coordinator
        .reset_network(snapshot(2), intent)
        .await
        .unwrap();
    let (stream, result) = tokio::time::timeout(std::time::Duration::from_secs(1), operation)
        .await
        .expect("reset wakes the pending TCP poll")
        .expect("TCP operation task");

    assert!(result.is_err());
    let NetworkRuntimeOwnerCancellation::Reset(signal) = stream.closed().expect("reset reason")
    else {
        panic!("TCP stream retained the wrong terminal reason");
    };
    assert_eq!(signal.target_generation(), 2);
    assert_eq!(signal.intent(), intent);
    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    drop(stream);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_connect_reset_closes_the_prepared_socket_and_releases_owner() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.udp_connect_pending.store(1, Ordering::SeqCst);
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let connect = tokio::spawn(async move {
        service
            .connect_udp(&DialOptions::default(), &route(), destination(443))
            .await
    });
    state.connect_started.notified().await;
    let report = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::UnicastAddressChanged),
        )
        .await
        .unwrap();
    let error = connect.await.unwrap().unwrap_err();

    assert!(matches!(error, NetworkSocketServiceError::Cancelled { .. }));
    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test]
async fn idle_connected_resources_are_closed_before_reset_acknowledgement() {
    let owners = OwnerRegistry::new();
    let tcp_state = Arc::new(FakeState::default());
    let (tcp_coordinator, tcp_service) = service(&owners, Arc::clone(&tcp_state));
    let mut stream = tcp_service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .unwrap();
    let tcp_report = tcp_coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::InterfaceChanged),
        )
        .await
        .unwrap();
    assert_eq!(tcp_report.cancelled_runtime_owners(), 1);
    assert_eq!(tcp_state.tcp_stream_drops.load(Ordering::SeqCst), 1);
    assert!(stream.read_u8().await.is_err());
    let NetworkRuntimeOwnerCancellation::Reset(signal) = stream.closed().expect("reset reason")
    else {
        panic!("TCP stream retained the wrong terminal reason");
    };
    assert_eq!(signal.target_generation(), 2);
    assert_eq!(
        signal.intent(),
        NetworkResetIntent::Ordinary(NetworkResetReason::InterfaceChanged)
    );
    assert_eq!(
        stream.resolved_interface().selection_source(),
        InterfaceSelectionSource::AutoDetected
    );

    let udp_state = Arc::new(FakeState::default());
    let (udp_coordinator, udp_service) = service(&owners, Arc::clone(&udp_state));
    let socket = udp_service
        .open_udp(&DialOptions::default(), &route(), destination(53))
        .unwrap();
    let udp_report = udp_coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .await
        .unwrap();
    assert_eq!(udp_report.cancelled_runtime_owners(), 1);
    assert_eq!(udp_state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert!(socket.is_closed().await);
    assert!(socket.send_to(b"stale", destination(5353)).await.is_err());
    assert!(socket.closed().is_some());
    assert_eq!(
        socket.resolved_interface().selection_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_reset_closes_many_wrappers_once_and_retains_every_reason() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let mut streams = Vec::new();
    for offset in 0..64 {
        streams.push(
            service
                .connect_tcp(
                    &DialOptions::default(),
                    &route(),
                    destination(10_000 + offset),
                )
                .await
                .expect("generation-bound TCP stream"),
        );
    }
    assert_eq!(owners.snapshot().network_runtime_owners, 64);

    let intent = NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged);
    let report = coordinator
        .reset_network(snapshot(2), intent)
        .await
        .unwrap();
    assert_eq!(report.cancelled_runtime_owners(), 64);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 64);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);

    for stream in &streams {
        let NetworkRuntimeOwnerCancellation::Reset(signal) =
            stream.closed().expect("reset terminal reason")
        else {
            panic!("TCP stream retained the wrong terminal reason");
        };
        assert_eq!(signal.target_generation(), 2);
        assert_eq!(signal.intent(), intent);
        assert!(stream.with_stream(|_| ()).is_none());
    }
    drop(streams);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 64);
}

#[tokio::test]
async fn coordinator_drop_closes_tcp_wrapper_once_with_the_complete_reason() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let stream = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .expect("generation-bound TCP stream");
    drop(service);
    drop(coordinator);

    for _ in 0..200 {
        if stream.closed().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        stream.closed(),
        Some(NetworkRuntimeOwnerCancellation::CoordinatorDropped)
    );
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    drop(stream);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_reset_waits_for_an_inflight_operation_before_acknowledging_its_owner() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let socket = Arc::new(
        service
            .open_udp(&DialOptions::default(), &route(), destination(53))
            .unwrap(),
    );
    let operation_socket = Arc::clone(&socket);
    let operation = tokio::spawn(async move { operation_socket.readable().await });
    state.udp_read_started.notified().await;

    let report = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .await
        .unwrap();

    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert!(operation.await.unwrap().is_err());
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert!(socket.is_closed().await);
    assert!(socket.closed().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_reset_cancels_concurrent_send_and_receive_before_acknowledging() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    state.udp_send_pending.store(1, Ordering::SeqCst);
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let socket = Arc::new(
        service
            .open_udp(&DialOptions::default(), &route(), destination(53))
            .unwrap(),
    );

    let send_socket = Arc::clone(&socket);
    let send =
        tokio::spawn(async move { send_socket.send_to(b"pending", destination(5353)).await });
    let recv_socket = Arc::clone(&socket);
    let recv = tokio::spawn(async move {
        let mut payload = BytesMut::with_capacity(512);
        recv_socket.recv_buf_from(&mut payload).await
    });
    state.udp_send_started.notified().await;
    state.udp_recv_started.notified().await;

    let intent = NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged);
    let report = coordinator
        .reset_network(snapshot(2), intent)
        .await
        .unwrap();

    assert!(send.await.unwrap().is_err());
    assert!(recv.await.unwrap().is_err());
    assert_eq!(report.cancelled_runtime_owners(), 1);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert!(socket.is_closed().await);
    let NetworkRuntimeOwnerCancellation::Reset(signal) =
        socket.closed().expect("reset terminal reason")
    else {
        panic!("UDP socket retained the wrong terminal reason");
    };
    assert_eq!(signal.target_generation(), 2);
    assert_eq!(signal.intent(), intent);
}

#[tokio::test]
async fn udp_close_is_idempotent_and_retains_the_first_terminal_reason() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let socket = service
        .open_udp(&DialOptions::default(), &route(), destination(53))
        .unwrap();
    let first_intent = NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged);

    let first_report = coordinator
        .reset_network(snapshot(2), first_intent)
        .await
        .unwrap();
    assert_eq!(first_report.cancelled_runtime_owners(), 1);
    assert!(socket.send_to(b"stale", destination(5353)).await.is_err());
    assert!(socket.readable().await.is_err());
    let mut payload = BytesMut::with_capacity(512);
    assert!(socket.recv_buf_from(&mut payload).await.is_err());
    assert!(socket.try_recv_buf_from(&mut payload).is_err());

    let second_report = coordinator
        .reset_network(
            snapshot(3),
            NetworkResetIntent::Ordinary(NetworkResetReason::InterfaceChanged),
        )
        .await
        .unwrap();
    assert_eq!(second_report.cancelled_runtime_owners(), 0);
    let NetworkRuntimeOwnerCancellation::Reset(signal) =
        socket.closed().expect("first reset terminal reason")
    else {
        panic!("UDP socket retained the wrong terminal reason");
    };
    assert_eq!(signal.target_generation(), 2);
    assert_eq!(signal.intent(), first_intent);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);

    drop(service);
    drop(coordinator);
    assert!(matches!(
        socket.closed(),
        Some(NetworkRuntimeOwnerCancellation::Reset(signal))
            if signal.target_generation() == 2 && signal.intent() == first_intent
    ));
    drop(socket);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn static_mode_uses_bare_sockets_without_owners_and_keeps_the_startup_snapshot() {
    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) =
        service_with_mode(&owners, Arc::clone(&state), NetworkSocketMode::Static);
    let mut stream = service
        .connect_tcp(&DialOptions::default(), &route(), destination(443))
        .await
        .expect("static TCP stream");
    let socket = service
        .open_udp(&DialOptions::default(), &route(), destination(53))
        .expect("static UDP socket");

    assert!(!stream.is_generation_bound());
    assert!(!socket.is_generation_bound());
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(service.published_generation(), 1);
    assert!(service.generation_is_admissible(1));

    let report = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .await
        .unwrap();
    assert_eq!(report.cancelled_runtime_owners(), 0);
    assert_eq!(service.published_generation(), 1);
    assert!(service.generation_is_admissible(1));
    assert!(!service.generation_is_admissible(2));
    assert!(stream.with_stream(|_| ()).is_some());
    stream.write_all(b"still-open").await.unwrap();
    assert_eq!(
        socket.send_to(b"query", destination(5353)).await.unwrap(),
        5
    );
    assert!(!socket.is_closed().await);

    drop(stream);
    drop(socket);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), 1);
    assert_eq!(state.udp_socket_drops.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn central_registry_adds_no_task_per_dynamic_socket_and_bulk_closes_once() {
    const SOCKETS_PER_TRANSPORT: usize = 512;

    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let alive_before = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let mut streams = Vec::with_capacity(SOCKETS_PER_TRANSPORT);
    let mut sockets = Vec::with_capacity(SOCKETS_PER_TRANSPORT);
    for offset in 0..SOCKETS_PER_TRANSPORT {
        streams.push(
            service
                .connect_tcp(
                    &DialOptions::default(),
                    &route(),
                    destination(10_000 + u16::try_from(offset).unwrap()),
                )
                .await
                .expect("dynamic TCP stream"),
        );
        sockets.push(
            service
                .open_udp(
                    &DialOptions::default(),
                    &route(),
                    destination(20_000 + u16::try_from(offset).unwrap()),
                )
                .expect("dynamic UDP socket"),
        );
    }
    tokio::task::yield_now().await;
    assert_eq!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        alive_before,
        "physical sockets must not spawn per-connection monitor tasks"
    );
    assert_eq!(
        owners.snapshot().network_runtime_owners,
        SOCKETS_PER_TRANSPORT * 2
    );

    let report = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::InterfaceChanged),
        )
        .await
        .unwrap();
    assert_eq!(report.cancelled_runtime_owners(), SOCKETS_PER_TRANSPORT * 2);
    assert_eq!(
        state.tcp_stream_drops.load(Ordering::SeqCst),
        SOCKETS_PER_TRANSPORT
    );
    assert_eq!(
        state.udp_socket_drops.load(Ordering::SeqCst),
        SOCKETS_PER_TRANSPORT
    );
    assert_eq!(owners.snapshot().network_runtime_owners, 0);

    drop(streams);
    drop(sockets);
    assert_eq!(
        state.tcp_stream_drops.load(Ordering::SeqCst),
        SOCKETS_PER_TRANSPORT
    );
    assert_eq!(
        state.udp_socket_drops.load(Ordering::SeqCst),
        SOCKETS_PER_TRANSPORT
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_drop_and_reset_reclaim_each_registry_generation_once() {
    const STREAMS: usize = 512;
    const DROP_THREADS: usize = 8;

    let owners = OwnerRegistry::new();
    let state = Arc::new(FakeState::default());
    let (coordinator, service) = service(&owners, Arc::clone(&state));
    let mut streams = Vec::with_capacity(STREAMS);
    for offset in 0..STREAMS {
        streams.push(
            service
                .connect_tcp(
                    &DialOptions::default(),
                    &route(),
                    destination(30_000 + u16::try_from(offset).unwrap()),
                )
                .await
                .expect("dynamic TCP stream"),
        );
    }
    let retained = streams.split_off(STREAMS / 2);
    let mut drop_batches: Vec<Vec<_>> = (0..DROP_THREADS).map(|_| Vec::new()).collect();
    for (index, stream) in streams.into_iter().enumerate() {
        drop_batches[index % DROP_THREADS].push(stream);
    }
    let start = Arc::new(std::sync::Barrier::new(DROP_THREADS + 1));
    let mut droppers = Vec::new();
    for dropping in drop_batches {
        let thread_start = Arc::clone(&start);
        droppers.push(std::thread::spawn(move || {
            thread_start.wait();
            drop(dropping);
        }));
    }
    start.wait();
    let _ = coordinator
        .reset_network(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::UnicastAddressChanged),
        )
        .await
        .unwrap();
    for dropper in droppers {
        dropper.join().expect("drop worker");
    }
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), STREAMS);
    drop(retained);
    assert_eq!(state.tcp_stream_drops.load(Ordering::SeqCst), STREAMS);
}
