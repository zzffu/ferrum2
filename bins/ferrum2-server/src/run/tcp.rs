mod connection;
mod listener;
mod outbound;
mod prefix;
mod selection;
#[cfg(test)]
mod tests;

#[cfg(any(all(not(windows), not(test)), test))]
pub(super) use super::network::prepare_server_network_socket_service;
pub(super) use super::network::{ServerNetworkSocketService, ServerPhysicalTcpStream};
pub(in crate::run) use listener::{ServerTcpListeners, ServerTcpRoot};
pub(in crate::run) use outbound::ServerContext;

#[cfg(test)]
use outbound::{DirectFlowError, open_and_prefix};
#[cfg(test)]
use prefix::{PrefixFailure, forward_initial_payload};
