use std::fmt;
use std::net::SocketAddr;

use ferrum2_net::{
    DialOptions, InterfaceSelectionSource, NetworkInterfaceCatalog, NetworkInterfaceResolver,
    RouteNetworkOptions,
};

use crate::{
    NetworkResetCoordinator, NetworkRuntimeOwnerCancellation, NetworkRuntimeOwnerKind,
    NetworkRuntimeResourceAdmissionError,
};

use super::generation::{GenerationBoundTcpStream, GenerationBoundUdpSocket};
use super::operations::NetworkSocketOperations;

/// One shared generation-bound physical socket service.
///
/// All physical callers share the exact snapshot -> four-tier resolve -> unbound socket -> bind ->
/// generation check -> owner admission sequence implemented by this service and the reset
/// coordinator. Generation races retry that whole sequence at most once.
pub struct NetworkSocketService<C, O> {
    coordinator: NetworkResetCoordinator,
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
            coordinator,
            resolver,
            operations,
        }
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
        self.coordinator.status().published_generation()
    }
}

impl<C, O> NetworkSocketService<C, O>
where
    C: NetworkInterfaceCatalog,
    O: NetworkSocketOperations,
{
    /// Connects one TCP socket while reset cancellation can still close the in-flight attempt.
    pub async fn connect_tcp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<GenerationBoundTcpStream<O::TcpStream>, NetworkSocketServiceError<O::Error>> {
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
        Ok(GenerationBoundTcpStream::new(stream, resolved, owner))
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
    ) -> Result<GenerationBoundUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
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
        Ok(GenerationBoundUdpSocket::new(socket, resolved, owner))
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
    ) -> Result<GenerationBoundUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
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
        Ok(GenerationBoundUdpSocket::new(socket, resolved, owner))
    }

    /// Opens and explicitly connects one UDP socket to a single physical target.
    pub async fn connect_udp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<GenerationBoundUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
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
        Ok(GenerationBoundUdpSocket::new(socket, resolved, owner))
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
