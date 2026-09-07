use super::*;
use crate::{
    NetworkResetCoordinator, NetworkResetLimits, NetworkRuntimeOwnerKind, NetworkSnapshotPublisher,
    NetworkSocketOwner, OwnerRegistry,
};
use ferrum2_net::{
    DialOptions, InterfaceBinding, NetworkInterfaceCatalog, NetworkInterfaceCatalogError,
    NetworkInterfaceObservation, NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions,
    SystemBestRoute,
};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
struct PhysicalDrop {
    owners: OwnerRegistry,
    observed_before_ack: Arc<AtomicUsize>,
}
impl Drop for PhysicalDrop {
    fn drop(&mut self) {
        self.observed_before_ack.store(
            self.owners.snapshot().network_runtime_owners,
            Ordering::SeqCst,
        );
    }
}
impl LocalEndpoint for PhysicalDrop {
    fn local_socket_addr(&self) -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }
}
fn context(owners: &OwnerRegistry) -> (NetworkResetCoordinator, ResolvedInterface) {
    let binding = InterfaceBinding::new("synthetic", 1, 1, ["192.0.2.1".parse().unwrap()]).unwrap();
    let snapshot = NetworkSnapshot::new(1, Some(binding), None).unwrap();
    let resolved = NetworkInterfaceResolver::new(Catalog)
        .resolve(
            &DialOptions::default(),
            &RouteNetworkOptions::new(true, None::<&str>),
            "203.0.113.1:1".parse().unwrap(),
            &snapshot,
        )
        .unwrap();
    (
        NetworkResetCoordinator::new(
            NetworkSnapshotPublisher::new(Arc::new(snapshot)),
            NetworkResetLimits::default(),
            owners.clone(),
        ),
        resolved,
    )
}
#[tokio::test(start_paused = true)]
async fn udp_operation_arc_retains_physical_ack_and_monitor_until_actual_drop() {
    let owners = OwnerRegistry::new();
    let (coordinator, resolved) = context(&owners);
    let runtime = coordinator
        .register_runtime_owner(1, NetworkRuntimeOwnerKind::UdpAssociation)
        .unwrap();
    let (registrar, mut owner) =
        NetworkSocketOwner::new(NonZeroUsize::new(1).unwrap(), owners.clone());
    let observed = Arc::new(AtomicUsize::new(0));
    let socket = GenerationBoundUdpSocket::new(
        PhysicalDrop {
            owners: owners.clone(),
            observed_before_ack: Arc::clone(&observed),
        },
        resolved,
        runtime,
        registrar.reserve().unwrap(),
    )
    .unwrap();
    let operation = socket.live_resource().unwrap();
    drop(socket);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), owner.shutdown())
            .await
            .is_err()
    );
    assert_eq!(owners.snapshot().network_runtime_owners, 1);
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    drop(operation);
    owner.shutdown().await.unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
}
#[tokio::test]
async fn tcp_drop_closes_stream_before_ack_and_parent_retains_unpolled_monitor() {
    let owners = OwnerRegistry::new();
    let (coordinator, resolved) = context(&owners);
    let runtime = coordinator
        .register_runtime_owner(1, NetworkRuntimeOwnerKind::TcpConnection)
        .unwrap();
    let (registrar, mut owner) =
        NetworkSocketOwner::new(NonZeroUsize::new(1).unwrap(), owners.clone());
    let observed = Arc::new(AtomicUsize::new(0));
    let stream = GenerationBoundTcpStream::new(
        PhysicalDrop {
            owners: owners.clone(),
            observed_before_ack: Arc::clone(&observed),
        },
        resolved,
        runtime,
        registrar.reserve().unwrap(),
    )
    .unwrap();
    drop(stream);
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(owners.snapshot().network_socket_monitors, 1);
    owner.shutdown().await.unwrap();
    assert_eq!(owners.snapshot().network_socket_monitors, 0);
}
