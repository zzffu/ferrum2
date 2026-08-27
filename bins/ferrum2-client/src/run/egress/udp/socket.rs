#[cfg(test)]
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
#[cfg(any(windows, test))]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use bytes::BytesMut;
#[cfg(test)]
use ferrum2_crypto::SecureRandom;
#[cfg(all(windows, not(test)))]
use ferrum2_net::{DialOptions, RouteNetworkOptions};
#[cfg(any(windows, test))]
use ferrum2_runtime::DirectUdpSocket;
use ferrum2_runtime::{
    DirectUdpSocketFactory, SystemDirectUdpSocket, SystemDirectUdpSocketFactory,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
use tokio::net::UdpSocket;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum UdpIoOperation {
    ApplicationRecv,
    ApplicationSend,
    UpstreamRecv,
    UpstreamSend,
}

#[cfg(test)]
pub(in crate::run) struct UdpIoFaultPlan {
    operation: UdpIoOperation,
    fail_at: usize,
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
pub(in crate::run) struct IdSequenceRandom(Mutex<VecDeque<u8>>);

#[cfg(test)]
impl IdSequenceRandom {
    pub(in crate::run) fn new(draws: impl IntoIterator<Item = u8>) -> Self {
        Self(Mutex::new(draws.into_iter().collect()))
    }
}

#[cfg(test)]
impl SecureRandom for IdSequenceRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ferrum2_crypto::RandomError> {
        let byte = self
            .0
            .lock()
            .expect("ID draw lock")
            .pop_front()
            .ok_or(ferrum2_crypto::RandomError::Unavailable)?;
        destination.fill(byte);
        Ok(())
    }
}

#[cfg(test)]
impl UdpIoFaultPlan {
    pub(in crate::run) fn new(operation: UdpIoOperation, fail_at: usize) -> Self {
        Self {
            operation,
            fail_at,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(in crate::run) fn fails(&self, operation: UdpIoOperation) -> bool {
        self.operation == operation
            && self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.fail_at
    }
}

pub(super) enum ClientDirectUdpSocket {
    System(SystemDirectUdpSocket),
    #[cfg(all(windows, not(test)))]
    Network(ferrum2_runtime::GenerationBoundUdpSocket<UdpSocket>),
    #[cfg(test)]
    Injected(InjectedDirectUdpSocket),
}

pub(super) enum ClientProxyUdpSocket {
    #[cfg(any(not(windows), test))]
    Connected(UdpSocket),
    #[cfg(any(windows, test))]
    Addressed {
        socket: ClientDirectUdpSocket,
        peer: SocketAddr,
    },
}

pub(in crate::run) enum ClientUdpSocketFactory {
    System,
    #[cfg(all(windows, not(test)))]
    Network {
        service: Arc<crate::run::egress::ClientNetworkSocketService>,
        expected_generation: u64,
        dial_options: DialOptions,
        route_network: RouteNetworkOptions,
    },
    #[cfg(test)]
    Injected {
        trace: Arc<InjectedUdpSocketTrace>,
    },
}

#[cfg(test)]
#[derive(Default)]
pub(in crate::run) struct InjectedUdpSocketTrace {
    opened: Mutex<Vec<SocketAddr>>,
    sent: Mutex<Vec<SocketAddr>>,
}

#[cfg(test)]
impl InjectedUdpSocketTrace {
    pub(in crate::run::egress) fn opened(&self) -> Vec<SocketAddr> {
        self.opened.lock().expect("injected UDP opens").clone()
    }

    pub(in crate::run::egress) fn sent(&self) -> Vec<SocketAddr> {
        self.sent.lock().expect("injected UDP sends").clone()
    }

    fn record_open(&self, destination: SocketAddr) {
        self.opened
            .lock()
            .expect("injected UDP opens")
            .push(destination);
    }

    pub(in crate::run::egress) fn record_send(&self, destination: SocketAddr) {
        self.sent
            .lock()
            .expect("injected UDP sends")
            .push(destination);
    }
}

#[cfg(test)]
pub(in crate::run) struct InjectedDirectUdpSocket {
    pub(in crate::run::egress) trace: Arc<InjectedUdpSocketTrace>,
}

impl ClientUdpSocketFactory {
    pub(in crate::run::egress) const fn system() -> Self {
        Self::System
    }

    #[cfg(test)]
    pub(in crate::run::egress) const fn injected(trace: Arc<InjectedUdpSocketTrace>) -> Self {
        Self::Injected { trace }
    }

    #[cfg(all(windows, not(test)))]
    pub(in crate::run::egress) const fn network(
        service: Arc<crate::run::egress::ClientNetworkSocketService>,
        expected_generation: u64,
        dial_options: DialOptions,
        route_network: RouteNetworkOptions,
    ) -> Self {
        Self::Network {
            service,
            expected_generation,
            dial_options,
            route_network,
        }
    }

    pub(super) async fn open(
        &self,
        selection_destination: SocketAddr,
    ) -> io::Result<ClientDirectUdpSocket> {
        match self {
            Self::System => SystemDirectUdpSocketFactory
                .open((), selection_destination)
                .await
                .map(ClientDirectUdpSocket::System),
            #[cfg(all(windows, not(test)))]
            Self::Network {
                service,
                expected_generation,
                dial_options,
                route_network,
            } => service
                .open_udp(
                    *expected_generation,
                    dial_options,
                    route_network,
                    selection_destination,
                )
                .map(ClientDirectUdpSocket::Network)
                .map_err(crate::run::egress::io_error_from_network_service),
            #[cfg(test)]
            Self::Injected { trace } => {
                trace.record_open(selection_destination);
                Ok(ClientDirectUdpSocket::Injected(InjectedDirectUdpSocket {
                    trace: Arc::clone(trace),
                }))
            }
        }
    }

    pub(super) async fn open_proxy<F, Fut>(
        &self,
        peer: SocketAddr,
        bind: &mut F,
    ) -> io::Result<ClientProxyUdpSocket>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = io::Result<UdpSocket>>,
    {
        #[cfg(all(windows, not(test)))]
        {
            let _ = bind;
            return self
                .open(peer)
                .await
                .map(|socket| ClientProxyUdpSocket::Addressed { socket, peer });
        }

        #[cfg(all(not(windows), not(test)))]
        {
            let Self::System = self;
            return open_connected_proxy(peer, bind).await;
        }

        #[cfg(test)]
        match self {
            Self::System => open_connected_proxy(peer, bind).await,
            Self::Injected { .. } => self
                .open(peer)
                .await
                .map(|socket| ClientProxyUdpSocket::Addressed { socket, peer }),
        }
    }
}

#[cfg(any(not(windows), test))]
async fn open_connected_proxy<F, Fut>(
    peer: SocketAddr,
    bind: &mut F,
) -> io::Result<ClientProxyUdpSocket>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let bind_address = SocketAddr::new(
        if peer.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    );
    let socket = bind(bind_address).await?;
    socket.connect(peer).await?;
    Ok(ClientProxyUdpSocket::Connected(socket))
}

impl ClientProxyUdpSocket {
    pub(super) async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(any(not(windows), test))]
            Self::Connected(socket) => socket.send(payload).await,
            #[cfg(any(windows, test))]
            Self::Addressed { socket, peer } => socket.send_to(payload, *peer).await,
        }
    }

    pub(super) async fn receive(&self, payload: &mut BytesMut) -> io::Result<usize> {
        match self {
            #[cfg(any(not(windows), test))]
            Self::Connected(socket) => {
                payload.clear();
                let length = socket.recv_buf(payload).await?;
                validate_response_length(length, payload)
            }
            #[cfg(any(windows, test))]
            Self::Addressed { socket, peer } => loop {
                payload.clear();
                let (length, source) = socket.recv_buf_from(payload).await?;
                let length = validate_response_length(length, payload)?;
                if source == *peer {
                    return Ok(length);
                }
            },
        }
    }

    #[cfg(test)]
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Connected(socket) => socket.local_addr(),
            Self::Addressed { .. } => Err(io::Error::other("UDP socket is opaque")),
        }
    }
}

fn validate_response_length(length: usize, payload: &BytesMut) -> io::Result<usize> {
    if length != payload.len() || length > MAX_UDP_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proxy UDP receive length",
        ));
    }
    Ok(length)
}
