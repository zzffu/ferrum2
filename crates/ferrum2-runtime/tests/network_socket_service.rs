use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_runtime::{
    DialOptions, DirectUdpSocket, GenerationBoundTcpStream, InterfaceBinding,
    InterfaceSelectionSource, NetworkInterfaceCatalog, NetworkInterfaceCatalogError,
    NetworkInterfaceObservation, NetworkInterfaceResolver, NetworkResetCoordinator,
    NetworkResetIntent, NetworkResetLimits, NetworkResetReason,
    NetworkRuntimeResourceAdmissionError, NetworkSnapshot, NetworkSnapshotPublisher,
    NetworkSocketOperations, NetworkSocketService, NetworkSocketServiceError, OwnerRegistry,
    ResolvedInterface, RouteNetworkOptions, RuntimeTcpStream, SystemBestRoute,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

#[test]
fn generation_bound_tcp_stream_satisfies_shared_protocol_io_contract() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GenerationBoundTcpStream<RuntimeTcpStream>>();
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
    udp_read_started: tokio::sync::Notify,
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
        Ok(payload.len())
    }

    async fn readable(&self) -> io::Result<()> {
        self.state.udp_read_started.notify_one();
        std::future::pending().await
    }

    async fn recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
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
    let coordinator = coordinator(owners);
    *state.snapshots.lock().unwrap() = Some(coordinator.snapshots());
    let service = NetworkSocketService::new(
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
    assert!(stream.closed().is_some());
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
