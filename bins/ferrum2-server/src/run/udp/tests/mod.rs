use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{SystemClock, SystemRandom};
use ferrum2_observability::Metrics;
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpSocketFactory, MAX_UDP_MAX_BUFFERED_BYTES,
    MAX_UDP_WIRE_DATAGRAM_BYTES, OwnerRegistry, UdpDirection, UdpRuntimeError, UdpRuntimeLimits,
    UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{
    ServerResponseCapability, UdpClientSession, UdpPacketError, UdpPacketScratch, UdpServer,
};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, Semaphore};

use super::admission::{
    ServerUdpShared, prepare_udp_server, prepare_udp_server_with_socket_factory,
    udp_runtime_limits, validate_udp_listener_budget,
};
use super::identity::{FrozenUdpIdentity, ServerUdpNetworkReset, UdpMappings};
use super::listener::{
    MAX_UDP_LISTENER_READINESS_DRAIN, ServerUdpListener, ServerUdpResponseHandler,
};
use super::physical::ServerUdpNetworkPolicy;
use super::response_codec::ResponseCodecPool;
use crate::run::dns_egress;
use crate::run::routing::ServerRouting;
use crate::run::routing::ServerTerminalRoute;

mod admission;
mod commit;
mod identity;
mod listener;
mod response_codec;
mod run_loop;
use crate::run::test_support::*;

type CapturedSends = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

struct ScriptedUdpListener {
    request: Mutex<Option<(Vec<u8>, SocketAddr)>>,
    terminal_gate: Arc<Notify>,
    handler_entered: Arc<Notify>,
    response_gate: Arc<Notify>,
    sent: Arc<Mutex<Vec<SocketAddr>>>,
}

impl ServerUdpListener for ScriptedUdpListener {
    async fn recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let request = self.request.lock().expect("scripted UDP request").take();
        let Some((wire, peer)) = request else {
            self.terminal_gate.notified().await;
            return Err(io::Error::other("listener terminal"));
        };
        destination.extend_from_slice(&wire);
        Ok((wire.len(), peer))
    }

    async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.handler_entered.notify_one();
        self.response_gate.notified().await;
        self.sent.lock().expect("scripted sends").push(peer);
        Ok(source.len())
    }
}

struct ConcurrentSendListener {
    entered: Arc<AtomicUsize>,
    entry_changed: Arc<Notify>,
    send_gate: Arc<Semaphore>,
    sent: CapturedSends,
}

struct AdmissionUdpListener {
    request: Mutex<Option<(Vec<u8>, SocketAddr)>>,
}

struct BurstUdpListener {
    requests: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    awaited: AtomicUsize,
    tried: AtomicUsize,
    drain_cap_reached: Notify,
}

impl BurstUdpListener {
    fn receive(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let request = self
            .requests
            .lock()
            .expect("burst UDP requests")
            .pop_front();
        let Some((wire, peer)) = request else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        destination.extend_from_slice(&wire);
        Ok((wire.len(), peer))
    }
}

impl ServerUdpListener for BurstUdpListener {
    async fn recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        self.awaited.fetch_add(1, Ordering::SeqCst);
        match self.receive(destination) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::future::pending().await,
            received => received,
        }
    }

    fn try_recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let tried = self.tried.fetch_add(1, Ordering::SeqCst) + 1;
        let received = self.receive(destination);
        if tried + 1 == MAX_UDP_LISTENER_READINESS_DRAIN {
            self.drain_cap_reached.notify_one();
        }
        received
    }

    async fn send_to(&self, source: &[u8], _peer: SocketAddr) -> io::Result<usize> {
        Ok(source.len())
    }
}

impl ServerUdpListener for AdmissionUdpListener {
    async fn recv_buf_from(&self, destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let request = self.request.lock().expect("admission request").take();
        let Some((wire, peer)) = request else {
            return std::future::pending().await;
        };
        destination.extend_from_slice(&wire);
        Ok((wire.len(), peer))
    }

    async fn send_to(&self, source: &[u8], _peer: SocketAddr) -> io::Result<usize> {
        Ok(source.len())
    }
}

#[derive(Clone)]
struct GatedSocketFactory {
    entered: Arc<AtomicUsize>,
    entry_changed: Arc<Notify>,
    open_gate: Arc<Semaphore>,
}

impl DirectUdpSocketFactory for GatedSocketFactory {
    type Socket = UdpSocket;
    type OpenContext = Option<ServerUdpNetworkPolicy>;

    async fn open(
        &self,
        _policy: Self::OpenContext,
        _selection_destination: SocketAddr,
    ) -> io::Result<Self::Socket> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.entry_changed.notify_waiters();
        let permit = self
            .open_gate
            .acquire()
            .await
            .map_err(|_| io::Error::other("open gate closed"))?;
        permit.forget();
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await
    }
}

fn gated_socket_factory() -> GatedSocketFactory {
    GatedSocketFactory {
        entered: Arc::new(AtomicUsize::new(0)),
        entry_changed: Arc::new(Notify::new()),
        open_gate: Arc::new(Semaphore::new(0)),
    }
}

impl ServerUdpListener for ConcurrentSendListener {
    async fn recv_buf_from(&self, _destination: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }

    async fn send_to(&self, source: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.entry_changed.notify_waiters();
        let _permit = self
            .send_gate
            .acquire()
            .await
            .map_err(|_| io::Error::other("send gate closed"))?;
        self.sent
            .lock()
            .expect("concurrent sends")
            .push((peer, source.to_vec()));
        Ok(source.len())
    }
}

async fn wait_for_send_entries(entered: &AtomicUsize, entry_changed: &Notify, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let changed = entry_changed.notified();
            if entered.load(Ordering::SeqCst) >= expected {
                break;
            }
            changed.await;
        }
    })
    .await
    .expect("response send entry deadline");
}

fn accounted_response(
    client: &mut UdpClientSession,
    protocol: &UdpServer,
    manager: &UdpSessionManager,
    clock: &SystemClock,
    handle: UdpSessionHandle,
    response: (SocketAddr, &'static [u8]),
    scratch: &mut UdpPacketScratch,
) -> AccountedDatagram {
    let (target, payload) = response;
    let wire = encoded_udp_request(
        client,
        clock,
        TargetAddr::ip(target).expect("response source target"),
        payload,
    );
    let pending = protocol
        .prepare_request(clock, &wire, scratch)
        .expect("prepare response payload");
    let (datagram, _commit) = pending.into_parts();
    let capacity = datagram.allocated_capacity();
    manager
        .reserve_datagram(handle, UdpDirection::ToClient, capacity)
        .expect("reserve response payload")
        .commit(datagram, tokio::time::Instant::now())
        .expect("commit response payload");
    manager
        .pop(handle, UdpDirection::ToClient)
        .expect("response generation")
        .expect("accounted response")
}

fn commit_client_response_wire(
    client: &UdpClientSession,
    manager: &UdpSessionManager,
    handle: &mut Option<UdpSessionHandle>,
    clock: &SystemClock,
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
) -> AccountedDatagram {
    let pending = client
        .prepare_response(clock, wire, scratch)
        .expect("prepare client response");
    let capacity = pending.datagram().allocated_capacity();
    let (datagram, commit) = pending.into_parts();
    let now = tokio::time::Instant::now();
    let accepted_handle = match *handle {
        Some(handle) => {
            manager
                .reserve_datagram(handle, UdpDirection::ToClient, capacity)
                .expect("reserve client response")
                .commit_with(datagram, now, || {
                    client.commit_response(commit, clock.monotonic_now())
                })
                .expect("commit client response");
            handle
        }
        None => {
            let session = manager.reserve_session(now).expect("client session");
            let reserved = session
                .reserve_datagram(UdpDirection::ToClient, capacity)
                .expect("reserve first client response");
            session
                .commit_with(reserved, datagram, now, || {
                    client.commit_response(commit, clock.monotonic_now())
                })
                .expect("commit first client response")
        }
    };
    *handle = Some(accepted_handle);
    manager
        .pop(accepted_handle, UdpDirection::ToClient)
        .expect("client response generation")
        .expect("accounted client response")
}

#[allow(clippy::too_many_arguments)]
fn commit_lifecycle_generation(
    client: &mut UdpClientSession,
    protocol: &UdpServer,
    manager: &UdpSessionManager,
    mappings: &UdpMappings,
    clock: &SystemClock,
    target: SocketAddr,
    peer: SocketAddr,
    payload: &'static [u8],
    protocol_now: ferrum2_crypto::MonotonicInstant,
    scratch: &mut UdpPacketScratch,
) -> (ServerResponseCapability, UdpSessionHandle) {
    let wire = encoded_udp_request(
        client,
        clock,
        TargetAddr::ip(target).expect("lifecycle target"),
        payload,
    );
    let pending = protocol
        .prepare_request(clock, &wire, scratch)
        .expect("prepare lifecycle request");
    let now = tokio::time::Instant::now();
    let session = manager.reserve_session(now).expect("reserve generation");
    let reserved = session
        .reserve_datagram(
            UdpDirection::ToTarget,
            pending.datagram().allocated_capacity(),
        )
        .expect("reserve generation datagram");
    let (datagram, commit) = pending.into_parts();
    let mut capability = None;
    let handle = session
        .commit_with(reserved, datagram, now, || {
            // This witness preserves the production T03 reservation
            // boundary around the T02 protocol commit.
            let accepted = protocol.commit_request(commit, peer, protocol_now, &SystemRandom)?;
            capability = Some(accepted.capability());
            Ok::<(), UdpPacketError>(())
        })
        .expect("commit lifecycle generation");
    let capability = capability.expect("lifecycle capability");
    assert_eq!(
        mappings.publish(capability, handle, 0, ServerTerminalRoute::Direct(0),),
        None
    );
    drop(
        manager
            .pop(handle, UdpDirection::ToTarget)
            .expect("lifecycle queue")
            .expect("lifecycle datagram"),
    );
    (capability, handle)
}
