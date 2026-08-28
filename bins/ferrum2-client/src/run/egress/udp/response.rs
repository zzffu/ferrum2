use std::io;

use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_crypto::Clock;
use ferrum2_runtime::{
    AccountedDatagram, PendingUdpDatagram, UdpCommitError, UdpDirection, UdpRuntimeError,
    UdpSessionHandle, UdpSessionManager,
};
use ferrum2_shadowsocks::{
    BorrowedPendingUdpResponse, UdpClientSession, UdpPacketError, UdpResponseCommit,
};
use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;
use tokio::time::Instant;

use crate::run::egress::context::ClientOutboundContext;

use super::association::ClientUdpPlan;
use super::request::composed_udp_plan_limit;

pub(super) fn dns_response_target_matches(expected: &TargetAddr, actual: &TargetAddr) -> bool {
    if expected.port() != actual.port() {
        return false;
    }
    match (expected.host(), actual.host()) {
        (TargetHostRef::Ip(expected), TargetHostRef::Ip(actual)) => expected == actual,
        (TargetHostRef::Domain(expected), TargetHostRef::Domain(actual)) => {
            expected.eq_ignore_ascii_case(actual)
        }
        (TargetHostRef::Domain(_), TargetHostRef::Ip(_)) => true,
        (TargetHostRef::Ip(_), TargetHostRef::Domain(_)) => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_single_udp_response(
    pending: BorrowedPendingUdpResponse<'_>,
    protocol: &UdpClientSession,
    hops: &[usize],
    outbounds: &[ClientOutboundContext],
    manager: &UdpSessionManager,
    handle: UdpSessionHandle,
    meter_global_buffers: bool,
    clock: &(impl Clock + ?Sized),
) -> Result<AccountedDatagram, UdpPlanResponseError> {
    let reservation = reserve_final_udp_response(
        &pending,
        hops,
        outbounds,
        manager,
        handle,
        meter_global_buffers,
    )?;
    let (datagram, commit) = pending.materialize().into_parts();
    reservation
        .commit_immediate_with(datagram, Instant::now(), || {
            protocol.commit_response(commit, clock.monotonic_now())
        })
        .map_err(map_commit_error)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_composed_udp_response(
    pending: BorrowedPendingUdpResponse<'_>,
    plan: &ClientUdpPlan,
    hops: &[usize],
    outbounds: &[ClientOutboundContext],
    mut commits: Vec<UdpResponseCommit>,
    manager: &UdpSessionManager,
    handle: UdpSessionHandle,
    meter_global_buffers: bool,
    clock: &(impl Clock + ?Sized),
) -> Result<AccountedDatagram, UdpPlanResponseError> {
    let reservation = reserve_final_udp_response(
        &pending,
        hops,
        outbounds,
        manager,
        handle,
        meter_global_buffers,
    )?;
    let (datagram, commit) = pending.materialize().into_parts();
    commits.push(commit);
    let sessions = plan
        .legs
        .iter()
        .map(|leg| &leg.protocol)
        .collect::<Vec<_>>();
    reservation
        .commit_immediate_with(datagram, Instant::now(), || {
            UdpClientSession::commit_responses(&sessions, commits, clock.monotonic_now())
        })
        .map_err(map_commit_error)
}

#[allow(clippy::too_many_arguments)]
fn reserve_final_udp_response(
    pending: &BorrowedPendingUdpResponse<'_>,
    hops: &[usize],
    outbounds: &[ClientOutboundContext],
    manager: &UdpSessionManager,
    handle: UdpSessionHandle,
    meter_global_buffers: bool,
) -> Result<PendingUdpDatagram, UdpPlanResponseError> {
    let socks_len = 3_usize
        .checked_add(pending.encoded_target_len())
        .and_then(|len| len.checked_add(pending.payload().len()));
    if socks_len.is_none_or(|len| len > MAX_SOCKS_UDP_DATAGRAM_BYTES)
        || pending.payload().len()
            > composed_udp_plan_limit(outbounds, hops, true, pending.encoded_target_len())
    {
        return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
    }
    if meter_global_buffers {
        manager.reserve_datagram(handle, UdpDirection::ToClient, pending.allocated_capacity())
    } else {
        manager.reserve_unmetered_datagram(
            handle,
            UdpDirection::ToClient,
            pending.allocated_capacity(),
        )
    }
    .map_err(UdpPlanResponseError::Runtime)
}

fn map_commit_error(error: UdpCommitError<UdpPacketError>) -> UdpPlanResponseError {
    match error {
        UdpCommitError::Protocol(error) => UdpPlanResponseError::Packet(error),
        UdpCommitError::Runtime(error) => UdpPlanResponseError::Runtime(error),
    }
}

pub(in crate::run) enum UdpPlanResponseError {
    Packet(UdpPacketError),
    Runtime(UdpRuntimeError),
}

pub(super) fn invalid_dns_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS egress target")
}

pub(super) fn runtime_error(_error: impl Sized) -> io::Error {
    io::Error::other("DNS UDP runtime unavailable")
}
