use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;

use bytes::BytesMut;
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_net::UdpResolver;
use ferrum2_runtime::{DirectUdpSocket, MAX_UDP_RESOLVED_CANDIDATES, MAX_UDP_WIRE_DATAGRAM_BYTES};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
use tokio::time::Instant;

use super::socket::{ClientDirectUdpSocket, ClientUdpSocketFactory};

pub(super) const MAX_DIRECT_UDP_READINESS_DRAIN: usize = 32;
pub(super) const DIRECT_UDP_CANDIDATE_HINT_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run::egress) enum DirectUdpResponsePolicy {
    OutstandingPeers,
    TunSink(DirectUdpFamily),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run::egress) enum DirectUdpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run::egress) enum DirectUdpResponseMatch {
    OutstandingPeer(usize),
    TunSink,
}

impl DirectUdpFamily {
    pub(in crate::run::egress) fn matches(self, endpoint: SocketAddr) -> bool {
        matches!(
            (self, endpoint),
            (Self::Ipv4, SocketAddr::V4(_)) | (Self::Ipv6, SocketAddr::V6(_))
        )
    }
}

impl DirectUdpResponsePolicy {
    pub(in crate::run::egress) fn classify(
        self,
        expected_peers: &VecDeque<SocketAddr>,
        source: SocketAddr,
    ) -> Option<DirectUdpResponseMatch> {
        match self {
            Self::OutstandingPeers => expected_peers
                .iter()
                .position(|expected| *expected == source)
                .map(DirectUdpResponseMatch::OutstandingPeer),
            // TUN owns endpoint-independent mapping and its response sink owns
            // ADF/EIF source admission. The direct child only enforces the
            // socket family before handing the datagram to that policy owner.
            Self::TunSink(family) if family.matches(source) => {
                Some(DirectUdpResponseMatch::TunSink)
            }
            Self::TunSink(_) => None,
        }
    }
}

#[derive(Default)]
pub(in crate::run::egress) struct DirectUdpCandidateHints {
    pub(in crate::run::egress) entries: VecDeque<DirectUdpCandidateHint>,
}

pub(in crate::run::egress) struct DirectUdpCandidateHint {
    pub(in crate::run::egress) domain: String,
    port: u16,
    pub(in crate::run::egress) last_successful_index: usize,
}

impl DirectUdpCandidateHints {
    pub(in crate::run::egress) fn start_index(&self, domain: &str, port: u16) -> usize {
        self.entries
            .iter()
            .find(|entry| entry.domain == domain && entry.port == port)
            .map_or(0, |entry| entry.last_successful_index)
    }

    pub(in crate::run::egress) fn record_success(
        &mut self,
        domain: &str,
        port: u16,
        last_successful_index: usize,
    ) {
        if let Some(position) = self
            .entries
            .iter()
            .position(|entry| entry.domain == domain && entry.port == port)
        {
            self.entries.remove(position);
        } else if self.entries.len() >= DIRECT_UDP_CANDIDATE_HINT_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(DirectUdpCandidateHint {
            domain: domain.to_owned(),
            port,
            last_successful_index,
        });
    }
}

impl DirectUdpSocket for ClientDirectUdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::System(socket) => socket.send_to(payload, target).await,
            #[cfg(any(not(windows), test))]
            Self::Raw(socket) => socket.send_to(payload, target).await,
            #[cfg(all(windows, not(test)))]
            Self::Network(socket) => socket.send_to(payload, target).await,
            #[cfg(test)]
            Self::Injected(socket) => {
                socket.trace.record_send(target);
                Ok(payload.len())
            }
        }
    }

    async fn readable(&self) -> io::Result<()> {
        match self {
            Self::System(socket) => socket.readable().await,
            #[cfg(any(not(windows), test))]
            Self::Raw(socket) => socket.readable().await,
            #[cfg(all(windows, not(test)))]
            Self::Network(socket) => socket.readable().await,
            #[cfg(test)]
            Self::Injected(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.recv_buf_from(payload).await,
            #[cfg(any(not(windows), test))]
            Self::Raw(socket) => socket.recv_buf_from(payload).await,
            #[cfg(all(windows, not(test)))]
            Self::Network(socket) => socket.recv_buf_from(payload).await,
            #[cfg(test)]
            Self::Injected(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::System(socket) => socket.try_recv_buf_from(payload),
            #[cfg(any(not(windows), test))]
            Self::Raw(socket) => socket.try_recv_buf_from(payload),
            #[cfg(all(windows, not(test)))]
            Self::Network(socket) => socket.try_recv_buf_from(payload),
            #[cfg(test)]
            Self::Injected(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

pub(in crate::run::egress) async fn send_direct_target_lazy(
    socket: &mut Option<ClientDirectUdpSocket>,
    factory: &ClientUdpSocketFactory,
    resolver: &impl UdpResolver,
    candidate_hints: &mut DirectUdpCandidateHints,
    target: &TargetAddr,
    payload: &[u8],
    timeout: std::time::Duration,
) -> io::Result<(usize, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    if let Some(target) = target.as_socket_addr() {
        if socket.is_none() {
            *socket = Some(factory.open(target).await?);
        }
        let length = send_direct_candidate(
            socket.as_ref().expect("direct UDP socket opened"),
            payload,
            target,
            deadline,
        )
        .await?;
        return Ok((length, target));
    }
    let TargetHostRef::Domain(host) = target.host() else {
        return Err(io::Error::other("direct UDP target unavailable"));
    };
    let port = target.port().get();
    let candidates = tokio::time::timeout_at(deadline, resolver.resolve(host, port))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP resolve timeout"))??;
    let candidates = candidates
        .into_iter()
        .take(MAX_UDP_RESOLVED_CANDIDATES)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(io::Error::other("direct UDP resolution was empty"));
    }
    let first_index = candidate_hints.start_index(host, port) % candidates.len();
    if socket.is_none() {
        *socket = Some(factory.open(candidates[first_index]).await?);
    }
    let (length, peer, last_successful_index) = send_direct_candidates(
        socket.as_ref().expect("direct UDP socket opened"),
        payload,
        &candidates,
        first_index,
        deadline,
    )
    .await?;
    candidate_hints.record_success(host, port, last_successful_index);
    Ok((length, peer))
}

#[cfg(test)]
pub(in crate::run::egress) async fn send_direct_target(
    socket: &impl DirectUdpSocket,
    resolver: &impl UdpResolver,
    candidate_hints: &mut DirectUdpCandidateHints,
    target: &TargetAddr,
    payload: &[u8],
    timeout: std::time::Duration,
) -> io::Result<(usize, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    if let Some(target) = target.as_socket_addr() {
        let length = send_direct_candidate(socket, payload, target, deadline).await?;
        return Ok((length, target));
    }
    let TargetHostRef::Domain(host) = target.host() else {
        return Err(io::Error::other("direct UDP target unavailable"));
    };
    let port = target.port().get();
    let candidates = tokio::time::timeout_at(deadline, resolver.resolve(host, target.port().get()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP resolve timeout"))??;
    let candidates = candidates
        .into_iter()
        .take(MAX_UDP_RESOLVED_CANDIDATES)
        .collect::<Vec<_>>();
    let first_index = candidate_hints.start_index(host, port);
    let (length, peer, last_successful_index) =
        send_direct_candidates(socket, payload, &candidates, first_index, deadline).await?;
    candidate_hints.record_success(host, port, last_successful_index);
    Ok((length, peer))
}

pub(in crate::run::egress) async fn receive_proxy_response(
    socket: &ClientDirectUdpSocket,
    expected_peer: SocketAddr,
    payload: &mut BytesMut,
) -> io::Result<usize> {
    #[cfg(any(not(windows), test))]
    if let ClientDirectUdpSocket::Raw(socket) = socket {
        payload.clear();
        let length = socket.recv_buf(payload).await?;
        return validate_proxy_response_length(length, payload);
    }

    loop {
        payload.clear();
        let (length, source) = socket.recv_buf_from(payload).await?;
        let length = validate_proxy_response_length(length, payload)?;
        if source == expected_peer {
            return Ok(length);
        }
    }
}

pub(in crate::run::egress) async fn send_proxy_request(
    socket: &ClientDirectUdpSocket,
    expected_peer: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    #[cfg(any(not(windows), test))]
    if let ClientDirectUdpSocket::Raw(socket) = socket {
        return socket.send(payload).await;
    }

    socket.send_to(payload, expected_peer).await
}

fn validate_proxy_response_length(length: usize, payload: &BytesMut) -> io::Result<usize> {
    if length != payload.len() || length > MAX_UDP_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proxy UDP receive length",
        ));
    }
    Ok(length)
}

pub(in crate::run::egress) async fn send_direct_candidates(
    socket: &impl DirectUdpSocket,
    payload: &[u8],
    candidates: &[SocketAddr],
    first_index: usize,
    deadline: Instant,
) -> io::Result<(usize, SocketAddr, usize)> {
    if candidates.is_empty() {
        return Err(io::Error::other("direct UDP resolution was empty"));
    }
    let mut last = None;
    for offset in 0..candidates.len() {
        let index = (first_index + offset) % candidates.len();
        let candidate = candidates[index];
        match send_direct_candidate(socket, payload, candidate, deadline).await {
            Ok(length) => return Ok((length, candidate, index)),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("direct UDP resolution was empty")))
}

pub(in crate::run::egress) async fn send_direct_candidate(
    socket: &impl DirectUdpSocket,
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
) -> io::Result<usize> {
    tokio::time::timeout_at(deadline, socket.send_to(payload, target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP send timeout"))?
}

pub(in crate::run::egress) async fn receive_direct_response(
    socket: &impl DirectUdpSocket,
    expected_peers: &VecDeque<SocketAddr>,
    policy: DirectUdpResponsePolicy,
    payload: &mut BytesMut,
) -> io::Result<(usize, SocketAddr, DirectUdpResponseMatch)> {
    loop {
        payload.clear();
        let mut received = socket.recv_buf_from(payload).await?;
        for drained in 1..=MAX_DIRECT_UDP_READINESS_DRAIN {
            if received.0 != payload.len() || received.0 > MAX_UDP_WIRE_DATAGRAM_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid direct UDP receive length",
                ));
            }
            if let Some(response_match) = policy.classify(expected_peers, received.1) {
                return Ok((received.0, received.1, response_match));
            }
            if drained == MAX_DIRECT_UDP_READINESS_DRAIN {
                tokio::task::yield_now().await;
                break;
            }
            payload.clear();
            match socket.try_recv_buf_from(payload) {
                Ok(next) => received = next,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
}
