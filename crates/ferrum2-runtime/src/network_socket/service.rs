use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_net::{
    DialOptions, InterfaceSelectionSource, NetworkInterfaceCatalog, NetworkInterfaceResolver,
    NetworkSnapshot, ResolvedInterface, RouteNetworkOptions,
};

use crate::{
    NetworkResetCoordinator, NetworkRuntimeOwnerCancellation, NetworkRuntimeOwnerKind,
    NetworkRuntimeResourceAdmissionError,
};

use super::generation::{NetworkTcpStream, NetworkUdpSocket};
use super::operations::NetworkSocketOperations;

/// Whether physical sockets follow dynamic generations or retain one startup snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkSocketMode {
    #[default]
    Dynamic,
    Static,
}

/// One shared generation-bound physical socket service.
///
/// All physical callers share the exact snapshot -> four-tier resolve -> unbound socket -> bind ->
/// generation check -> owner admission sequence implemented by this service and the reset
/// coordinator. Generation races retry that whole sequence at most once.
pub struct NetworkSocketService<C, O> {
    mode: NetworkSocketMode,
    coordinator: NetworkResetCoordinator,
    static_snapshot: Option<Arc<NetworkSnapshot>>,
    resolver: NetworkInterfaceResolver<C>,
    operations: O,
}

impl<C, O> NetworkSocketService<C, O> {
    pub const fn new(
        coordinator: NetworkResetCoordinator,
        resolver: NetworkInterfaceResolver<C>,
        operations: O,
    ) -> Self {
        Self {
            mode: NetworkSocketMode::Dynamic,
            coordinator,
            static_snapshot: None,
            resolver,
            operations,
        }
    }

    /// Creates a service with an explicit dynamic or startup-static lifecycle.
    pub fn with_mode(
        mode: NetworkSocketMode,
        coordinator: NetworkResetCoordinator,
        resolver: NetworkInterfaceResolver<C>,
        operations: O,
    ) -> Self {
        let static_snapshot =
            (mode == NetworkSocketMode::Static).then(|| coordinator.snapshots().snapshot());
        Self {
            mode,
            coordinator,
            static_snapshot,
            resolver,
            operations,
        }
    }

    pub const fn mode(&self) -> NetworkSocketMode {
        self.mode
    }

    pub const fn coordinator(&self) -> &NetworkResetCoordinator {
        &self.coordinator
    }

    pub const fn resolver(&self) -> &NetworkInterfaceResolver<C> {
        &self.resolver
    }

    pub const fn operations(&self) -> &O {
        &self.operations
    }

    /// Returns the generation currently published by the shared reset coordinator.
    pub fn published_generation(&self) -> u64 {
        self.static_snapshot.as_ref().map_or_else(
            || self.coordinator.status().published_generation(),
            |snapshot| snapshot.generation(),
        )
    }

    /// Returns whether one frozen generation may still use this service.
    pub fn generation_is_admissible(&self, expected_generation: u64) -> bool {
        match self.mode {
            NetworkSocketMode::Static => self.published_generation() == expected_generation,
            NetworkSocketMode::Dynamic => {
                let status = self.coordinator.status();
                status.admission_open() && status.published_generation() == expected_generation
            }
        }
    }
}

impl<C, O> NetworkSocketService<C, O>
where
    C: NetworkInterfaceCatalog,
    O: NetworkSocketOperations,
{
    fn prepare_static_resource<T>(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        prepare: impl FnOnce(&ResolvedInterface) -> Result<T, O::Error>,
    ) -> Result<(T, ResolvedInterface), NetworkRuntimeResourceAdmissionError<O::Error>> {
        let snapshot = self
            .static_snapshot
            .as_ref()
            .expect("static socket mode retains one startup snapshot");
        let resolved = self
            .resolver
            .resolve(outbound, route, destination, snapshot)
            .map_err(NetworkRuntimeResourceAdmissionError::InterfaceResolution)?;
        let attempted_source = resolved.selection_source();
        let resource = prepare(&resolved).map_err(|error| {
            NetworkRuntimeResourceAdmissionError::Preparation {
                attempted_source,
                error,
            }
        })?;
        Ok((resource, resolved))
    }

    /// Connects one TCP socket while reset cancellation can still close the in-flight attempt.
    pub async fn connect_tcp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<NetworkTcpStream<O::TcpStream>, NetworkSocketServiceError<O::Error>> {
        if self.mode == NetworkSocketMode::Static {
            let (socket, resolved) = self
                .prepare_static_resource(outbound, route, destination, |resolved| {
                    self.operations.prepare_tcp(destination, resolved)
                })
                .map_err(NetworkSocketServiceError::Admission)?;
            let attempted_source = resolved.selection_source();
            let stream = self
                .operations
                .connect_tcp(socket, destination)
                .await
                .map_err(|error| NetworkSocketServiceError::Connection {
                    attempted_source,
                    error,
                })?;
            return Ok(NetworkTcpStream::static_socket(stream, resolved));
        }
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                destination,
                NetworkRuntimeOwnerKind::TcpConnection,
                |resolved| self.operations.prepare_tcp(destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, mut owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        let connect = self.operations.connect_tcp(socket, destination);
        tokio::pin!(connect);
        let stream = tokio::select! {
            biased;
            cancellation = owner.cancelled() => {
                return Err(NetworkSocketServiceError::Cancelled {
                    attempted_source,
                    cancellation,
                });
            }
            result = &mut connect => result.map_err(|error| NetworkSocketServiceError::Connection {
                attempted_source,
                error,
            })?,
        };
        if let Some(cancellation) = owner.cancellation_status_now() {
            drop(stream);
            return Err(NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            });
        }
        NetworkTcpStream::dynamic_socket(stream, resolved, owner).map_err(|cancellation| {
            NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            }
        })
    }

    /// Opens one bound, unconnected UDP socket for a multi-target association.
    ///
    /// `selection_destination` is the first concrete target and is used only for family-aware
    /// interface selection and binding. The returned socket remains unconnected so later
    /// datagrams may use `send_to` and `recv_from` within that selected family.
    pub fn open_udp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        selection_destination: SocketAddr,
    ) -> Result<NetworkUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
        if self.mode == NetworkSocketMode::Static {
            let (socket, resolved) = self
                .prepare_static_resource(outbound, route, selection_destination, |resolved| {
                    self.operations.prepare_udp(selection_destination, resolved)
                })
                .map_err(NetworkSocketServiceError::Admission)?;
            return Ok(NetworkUdpSocket::static_socket(socket, resolved));
        }
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                selection_destination,
                NetworkRuntimeOwnerKind::UdpAssociation,
                |resolved| self.operations.prepare_udp(selection_destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        NetworkUdpSocket::dynamic_socket(socket, resolved, owner).map_err(|cancellation| {
            NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            }
        })
    }

    /// Opens one bound, unconnected UDP socket only for an already-frozen generation.
    ///
    /// This path never retries into a newer generation. It is used by logical UDP associations
    /// whose route and network generation were fixed before their physical socket is opened
    /// lazily; a reset therefore fails the old association closed instead of rebinding it.
    pub fn open_udp_for_generation(
        &self,
        expected_generation: u64,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        selection_destination: SocketAddr,
    ) -> Result<NetworkUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
        if self.mode == NetworkSocketMode::Static {
            let snapshot = self
                .static_snapshot
                .as_ref()
                .expect("static socket mode retains one startup snapshot");
            let resolved = self
                .resolver
                .resolve(outbound, route, selection_destination, snapshot)
                .map_err(|error| {
                    NetworkSocketServiceError::Admission(
                        NetworkRuntimeResourceAdmissionError::InterfaceResolution(error),
                    )
                })?;
            let attempted_source = resolved.selection_source();
            if expected_generation != snapshot.generation() {
                return Err(NetworkSocketServiceError::Admission(
                    NetworkRuntimeResourceAdmissionError::NetworkGenerationChanged {
                        attempted_source,
                    },
                ));
            }
            let socket = self
                .operations
                .prepare_udp(selection_destination, &resolved)
                .map_err(|error| {
                    NetworkSocketServiceError::Admission(
                        NetworkRuntimeResourceAdmissionError::Preparation {
                            attempted_source,
                            error,
                        },
                    )
                })?;
            return Ok(NetworkUdpSocket::static_socket(socket, resolved));
        }
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource_for_generation(
                expected_generation,
                &self.resolver,
                outbound,
                route,
                selection_destination,
                NetworkRuntimeOwnerKind::UdpAssociation,
                |resolved| self.operations.prepare_udp(selection_destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        NetworkUdpSocket::dynamic_socket(socket, resolved, owner).map_err(|cancellation| {
            NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            }
        })
    }

    /// Opens and explicitly connects one UDP socket to a single physical target.
    pub async fn connect_udp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<NetworkUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
        if self.mode == NetworkSocketMode::Static {
            let (socket, resolved) = self
                .prepare_static_resource(outbound, route, destination, |resolved| {
                    self.operations.prepare_udp(destination, resolved)
                })
                .map_err(NetworkSocketServiceError::Admission)?;
            let attempted_source = resolved.selection_source();
            let socket = self
                .operations
                .connect_udp(socket, destination)
                .await
                .map_err(|error| NetworkSocketServiceError::Connection {
                    attempted_source,
                    error,
                })?;
            return Ok(NetworkUdpSocket::static_socket(socket, resolved));
        }
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                destination,
                NetworkRuntimeOwnerKind::UdpAssociation,
                |resolved| self.operations.prepare_udp(destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, mut owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        let connect = self.operations.connect_udp(socket, destination);
        tokio::pin!(connect);
        let socket = tokio::select! {
            biased;
            cancellation = owner.cancelled() => {
                return Err(NetworkSocketServiceError::Cancelled {
                    attempted_source,
                    cancellation,
                });
            }
            result = &mut connect => result.map_err(|error| NetworkSocketServiceError::Connection {
                attempted_source,
                error,
            })?,
        };
        if let Some(cancellation) = owner.cancellation_status_now() {
            drop(socket);
            return Err(NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            });
        }
        NetworkUdpSocket::dynamic_socket(socket, resolved, owner).map_err(|cancellation| {
            NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            }
        })
    }
}

impl<C, O> fmt::Debug for NetworkSocketService<C, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSocketService")
            .field("coordinator", &self.coordinator)
            .finish_non_exhaustive()
    }
}

/// Closed service failure retaining only the selected source and nested closed categories.
#[derive(Eq, PartialEq)]
pub enum NetworkSocketServiceError<E> {
    Admission(NetworkRuntimeResourceAdmissionError<E>),
    Connection {
        attempted_source: InterfaceSelectionSource,
        error: E,
    },
    Cancelled {
        attempted_source: InterfaceSelectionSource,
        cancellation: NetworkRuntimeOwnerCancellation,
    },
}

impl<E> NetworkSocketServiceError<E> {
    pub const fn attempted_source(&self) -> InterfaceSelectionSource {
        match self {
            Self::Admission(error) => error.attempted_source(),
            Self::Connection {
                attempted_source, ..
            }
            | Self::Cancelled {
                attempted_source, ..
            } => *attempted_source,
        }
    }
}

impl<E> fmt::Debug for NetworkSocketServiceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => formatter.debug_tuple("Admission").field(error).finish(),
            Self::Connection {
                attempted_source, ..
            } => formatter
                .debug_struct("Connection")
                .field("attempted_source", attempted_source)
                .field("error", &"[closed]")
                .finish(),
            Self::Cancelled {
                attempted_source,
                cancellation,
            } => formatter
                .debug_struct("Cancelled")
                .field("attempted_source", attempted_source)
                .field("cancellation", cancellation)
                .finish(),
        }
    }
}
