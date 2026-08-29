use std::net::SocketAddr;

use ferrum2_crypto::{Clock as _, SystemClock, SystemRandom};
use ferrum2_net::UdpResolver;
use ferrum2_runtime::{
    DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSessionAdmission, DirectUdpSocketFactory,
    PendingUdpDatagram, UdpCommitError, UdpRuntimeError, UdpSessionHandle,
};
use ferrum2_shadowsocks::{PendingUdpRequest, ServerResponseCapability, UdpPacketError, UdpServer};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::StructuralLocal;

use crate::run::routing::ServerTerminalRoute;

use super::identity::UdpMappings;

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_rejected_request(
    protocol: &UdpServer,
    mappings: &UdpMappings,
    pending: PendingUdpRequest,
    expected: Option<ServerResponseCapability>,
    peer: SocketAddr,
    now: ferrum2_crypto::MonotonicInstant,
    inbound: usize,
    #[cfg(feature = "structural-metrics")] structural: &StructuralLocal,
) -> Result<(), UdpPacketError> {
    let (_datagram, commit) = pending.into_parts();
    #[cfg(feature = "structural-metrics")]
    let accepted =
        protocol.commit_request_structural(commit, peer, now, &SystemRandom, structural)?;
    #[cfg(not(feature = "structural-metrics"))]
    let accepted = protocol.commit_request(commit, peer, now, &SystemRandom)?;
    if expected.is_some_and(|capability| capability != accepted.capability()) {
        return Err(UdpPacketError::Generation);
    }
    if expected.is_none() {
        mappings.publish_rejected(accepted.capability(), inbound);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_existing_direct_request(
    protocol: &UdpServer,
    mappings: &UdpMappings,
    reservation: PendingUdpDatagram,
    pending: PendingUdpRequest,
    expected: ServerResponseCapability,
    handle: UdpSessionHandle,
    peer: SocketAddr,
    clock: &SystemClock,
    #[cfg(feature = "structural-metrics")] structural: &StructuralLocal,
) -> Result<(), UdpCommitError<UdpPacketError>> {
    let (datagram, commit) = pending.into_parts();
    let committed = reservation.commit_with(datagram, tokio::time::Instant::now(), || {
        #[cfg(feature = "structural-metrics")]
        protocol.commit_existing_request_structural(
            commit,
            expected,
            peer,
            clock.monotonic_now(),
            structural,
        )?;
        #[cfg(not(feature = "structural-metrics"))]
        protocol.commit_existing_request(commit, expected, peer, clock.monotonic_now())?;
        Ok(())
    });
    if matches!(
        committed,
        Err(UdpCommitError::Runtime(_)) | Err(UdpCommitError::Protocol(UdpPacketError::Generation))
    ) {
        mappings.invalidate_handle(handle);
    }
    committed
}

pub(super) enum NewDirectCommitError {
    Runtime(UdpRuntimeError),
    Protocol(UdpPacketError),
    Identity,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_new_direct_session<R, F, H>(
    runtime: &mut DirectUdpRuntime<R, F, H>,
    admission: DirectUdpSessionAdmission<F::Socket>,
    pending: PendingUdpRequest,
    resolver: R,
    protocol: &UdpServer,
    mappings: &UdpMappings,
    peer: SocketAddr,
    clock: &SystemClock,
    inbound: usize,
    outbound: usize,
    #[cfg(feature = "structural-metrics")] structural: &StructuralLocal,
) -> Result<UdpSessionHandle, NewDirectCommitError>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    F: DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    let (datagram, commit) = pending.into_parts();
    let mut committed_capability = None;
    let committed = runtime.commit_session_with_resolver(
        admission,
        datagram,
        tokio::time::Instant::now(),
        resolver,
        || {
            // Protocol identity is published only after the runtime session,
            // socket, bytes, and queue are ready to own it.
            #[cfg(feature = "structural-metrics")]
            let accepted = protocol.commit_request_structural(
                commit,
                peer,
                clock.monotonic_now(),
                &SystemRandom,
                structural,
            )?;
            #[cfg(not(feature = "structural-metrics"))]
            let accepted =
                protocol.commit_request(commit, peer, clock.monotonic_now(), &SystemRandom)?;
            committed_capability = Some(accepted.capability());
            Ok(())
        },
    );
    match committed {
        Ok(handle) => {
            let Some(capability) = committed_capability else {
                runtime.remove_session(handle);
                return Err(NewDirectCommitError::Identity);
            };
            if mappings
                .publish(
                    capability,
                    handle,
                    inbound,
                    ServerTerminalRoute::Direct(outbound),
                )
                .is_some()
            {
                mappings.prune_protocol(protocol, clock.monotonic_now());
            }
            Ok(handle)
        }
        Err(UdpCommitError::Runtime(error)) => Err(NewDirectCommitError::Runtime(error)),
        Err(UdpCommitError::Protocol(error)) => Err(NewDirectCommitError::Protocol(error)),
    }
}
