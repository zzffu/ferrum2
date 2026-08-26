use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum2_net::{
    DialOptions, InterfaceBinding, InterfaceResolutionErrorKind, InterfaceSelectionSource,
    NetworkInterfaceCatalog, NetworkInterfaceCatalogError, NetworkInterfaceObservation,
    NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions, SystemBestRoute,
};
use ferrum2_runtime::{
    NetworkResetCoordinator, NetworkResetIntent, NetworkResetLimits, NetworkResetReason,
    NetworkRuntimeOwnerKind, NetworkRuntimeOwnerRegistrationError,
    NetworkRuntimeResourceAdmissionError, NetworkSnapshotPublisher, OwnerRegistry,
};

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
        _destination: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}

fn binding(generation: u64) -> InterfaceBinding {
    let octet = u8::try_from(generation).expect("test generation fits one octet");
    InterfaceBinding::new(
        format!("underlay-{generation}"),
        generation,
        u32::try_from(generation).expect("test generation fits an index"),
        [IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet))],
    )
    .expect("valid interface")
}

fn snapshot(generation: u64) -> Arc<NetworkSnapshot> {
    Arc::new(
        NetworkSnapshot::new(generation, Some(binding(generation)), None).expect("valid snapshot"),
    )
}

fn coordinator(owners: &OwnerRegistry) -> NetworkResetCoordinator {
    NetworkResetCoordinator::new(
        NetworkSnapshotPublisher::new(snapshot(1)),
        NetworkResetLimits::default(),
        owners.clone(),
    )
}

fn destination() -> SocketAddr {
    SocketAddr::from(([203, 0, 113, 9], 443))
}

#[derive(Debug)]
struct TrackedResource {
    generation: u64,
    drops: Arc<AtomicUsize>,
}

impl Drop for TrackedResource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn successful_admission_returns_resource_resolution_and_exact_owner() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let resolver = NetworkInterfaceResolver::new(Catalog);
    let drops = Arc::new(AtomicUsize::new(0));

    let admitted = coordinator
        .prepare_and_admit_runtime_resource(
            &resolver,
            &DialOptions::default(),
            &RouteNetworkOptions::new(true, None::<&str>),
            destination(),
            NetworkRuntimeOwnerKind::TcpConnection,
            |resolved| {
                Ok::<_, ()>(TrackedResource {
                    generation: resolved.snapshot_generation(),
                    drops: Arc::clone(&drops),
                })
            },
        )
        .expect("current generation is admitted");

    assert_eq!(admitted.resource().generation, 1);
    assert_eq!(admitted.resolved_interface().snapshot_generation(), 1);
    assert_eq!(
        admitted.resolved_interface().selection_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(admitted.owner().generation(), 1);
    assert_eq!(
        admitted.owner().kind(),
        NetworkRuntimeOwnerKind::TcpConnection
    );
    assert_eq!(coordinator.status().registered_runtime_owners(), 1);

    let (resource, resolved, owner) = admitted.into_parts();
    assert_eq!(resource.generation, resolved.snapshot_generation());
    assert_eq!(owner.generation(), resolved.snapshot_generation());
    drop(resource);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(coordinator.status().registered_runtime_owners(), 1);
    drop(owner);
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[test]
fn one_generation_race_drops_stale_resource_then_admits_new_generation() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let snapshots = coordinator.snapshots();
    let resolver = NetworkInterfaceResolver::new(Catalog);
    let attempts = AtomicUsize::new(0);
    let drops = Arc::new(AtomicUsize::new(0));

    let admitted = coordinator
        .prepare_and_admit_runtime_resource(
            &resolver,
            &DialOptions::default(),
            &RouteNetworkOptions::new(true, None::<&str>),
            destination(),
            NetworkRuntimeOwnerKind::UdpAssociation,
            |resolved| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    snapshots
                        .publish_if_current(1, snapshot(2))
                        .expect("publish second generation");
                }
                Ok::<_, ()>(TrackedResource {
                    generation: resolved.snapshot_generation(),
                    drops: Arc::clone(&drops),
                })
            },
        )
        .expect("one complete retry succeeds");

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(admitted.resource().generation, 2);
    assert_eq!(admitted.resolved_interface().snapshot_generation(), 2);
    assert_eq!(admitted.owner().generation(), 2);
    assert_eq!(coordinator.status().registered_runtime_owners(), 1);
    drop(admitted);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[test]
fn second_generation_race_fails_and_never_admits_an_old_owner() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let snapshots = coordinator.snapshots();
    let resolver = NetworkInterfaceResolver::new(Catalog);
    let attempts = AtomicUsize::new(0);
    let drops = Arc::new(AtomicUsize::new(0));

    let result = coordinator.prepare_and_admit_runtime_resource(
        &resolver,
        &DialOptions::default(),
        &RouteNetworkOptions::new(true, None::<&str>),
        destination(),
        NetworkRuntimeOwnerKind::GenerationTask,
        |resolved| {
            attempts.fetch_add(1, Ordering::SeqCst);
            snapshots
                .publish_if_current(
                    resolved.snapshot_generation(),
                    snapshot(resolved.snapshot_generation() + 1),
                )
                .expect("advance generation during preparation");
            Ok::<_, ()>(TrackedResource {
                generation: resolved.snapshot_generation(),
                drops: Arc::clone(&drops),
            })
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("a second generation race must fail"),
    };

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(coordinator.snapshots().generation(), 3);
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(
        error,
        NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
            attempted_source: InterfaceSelectionSource::AutoDetected,
        }
    );
}

#[test]
fn closed_admission_drops_prepared_resource_and_preserves_registration_reason() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let resolver = NetworkInterfaceResolver::new(Catalog);
    let drops = Arc::new(AtomicUsize::new(0));
    coordinator
        .queue_reset(
            snapshot(2),
            NetworkResetIntent::Ordinary(NetworkResetReason::RouteChanged),
        )
        .expect("queue reset closes admission");

    let result = coordinator.prepare_and_admit_runtime_resource(
        &resolver,
        &DialOptions::default(),
        &RouteNetworkOptions::new(true, None::<&str>),
        destination(),
        NetworkRuntimeOwnerKind::TcpConnection,
        |resolved| {
            Ok::<_, ()>(TrackedResource {
                generation: resolved.snapshot_generation(),
                drops: Arc::clone(&drops),
            })
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("closed admission must reject the prepared resource"),
    };

    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
    assert_eq!(
        error,
        NetworkRuntimeResourceAdmissionError::RuntimeOwnerRegistration {
            attempted_source: InterfaceSelectionSource::AutoDetected,
            error: NetworkRuntimeOwnerRegistrationError::AdmissionClosed,
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareError {
    BindFailed,
}

#[test]
fn stable_prepare_failure_retains_error_and_selection_source() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let resolver = NetworkInterfaceResolver::new(Catalog);

    let result = coordinator.prepare_and_admit_runtime_resource::<_, (), _>(
        &resolver,
        &DialOptions::default(),
        &RouteNetworkOptions::new(true, None::<&str>),
        destination(),
        NetworkRuntimeOwnerKind::TcpConnection,
        |_| Err(PrepareError::BindFailed),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("prepare failure must remain closed"),
    };

    assert_eq!(
        error,
        NetworkRuntimeResourceAdmissionError::Preparation {
            attempted_source: InterfaceSelectionSource::AutoDetected,
            error: PrepareError::BindFailed,
        }
    );
    assert_eq!(
        error.attempted_source(),
        InterfaceSelectionSource::AutoDetected
    );
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}

#[test]
fn source_failure_is_observable_and_never_prepares_or_registers() {
    let owners = OwnerRegistry::new();
    let coordinator = coordinator(&owners);
    let resolver = NetworkInterfaceResolver::new(Catalog);
    let prepare_calls = AtomicUsize::new(0);

    let result = coordinator.prepare_and_admit_runtime_resource::<_, (), ()>(
        &resolver,
        &DialOptions::new(Some("missing"), None, None),
        &RouteNetworkOptions::new(true, None::<&str>),
        destination(),
        NetworkRuntimeOwnerKind::TcpConnection,
        |_| {
            prepare_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("missing explicit interface must fail"),
    };

    let NetworkRuntimeResourceAdmissionError::InterfaceResolution(resolution) = error else {
        panic!("interface resolution failure is retained");
    };
    assert_eq!(
        resolution.kind(),
        InterfaceResolutionErrorKind::ExplicitInterfaceMissing
    );
    assert_eq!(
        resolution.attempted_source(),
        InterfaceSelectionSource::OutboundExplicit
    );
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(coordinator.status().registered_runtime_owners(), 0);
    assert_eq!(owners.snapshot().network_runtime_owners, 0);
}
