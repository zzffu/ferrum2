use std::sync::Arc;

use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_runtime::ProcessCancellation;

use crate::run::context::ClientRouting;
use crate::run::routing::{RouteGeneration, RouteGenerationChange};

use super::association::{
    TunUdpPeerReservation, authorize_dns_peer_after_answer, record_tun_udp_response_outcome,
    reserve_tun_udp_peer,
};
use super::route::{
    udp_route_generation_is_current, wait_for_optional_udp_route_generation_change,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_dns_association(
    mut association: ferrum2_tun::UdpAssociation,
    mut pending_datagram: Option<ferrum2_tun::UdpDatagram>,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    routing: Arc<ClientRouting>,
    inbound: usize,
    proxy: Arc<DnsProxy>,
) {
    if !udp_route_generation_is_current(&routing, route_generation) {
        return;
    }
    let response_sink = association.response_sink();
    let peer_policy = association.peer_policy();
    loop {
        if !udp_route_generation_is_current(&routing, route_generation) {
            return;
        }
        if let Some(datagram) = pending_datagram.take() {
            if !answer_tun_udp_dns(
                datagram,
                &proxy,
                inbound,
                &cancellation,
                &session_cancellation,
                Some(route_generation),
                Some(&mut route_change),
                &routing,
                &response_sink,
                &peer_policy,
            )
            .await
            {
                return;
            }
            continue;
        }
        let mut forced = cancellation.clone();
        let datagram = tokio::select! {
            biased;
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            () = &mut route_change => return,
            datagram = association.receive() => datagram,
        };
        let Some(datagram) = datagram else { return };
        pending_datagram = Some(datagram);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn answer_tun_udp_dns(
    datagram: ferrum2_tun::UdpDatagram,
    proxy: &DnsProxy,
    inbound: usize,
    cancellation: &ProcessCancellation,
    session_cancellation: &ferrum2_tun::SessionCancellation,
    route_generation: Option<RouteGeneration>,
    route_change: Option<&mut RouteGenerationChange>,
    routing: &ClientRouting,
    response_sink: &ferrum2_tun::UdpResponseSink,
    peer_policy: &ferrum2_tun::UdpPeerPolicyHandle,
) -> bool {
    if route_generation
        .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
    {
        return false;
    }
    let target = datagram.target();
    let mut answer_forced = cancellation.clone();
    let response = tokio::select! {
        biased;
        () = answer_forced.forced() => return false,
        () = session_cancellation.cancelled() => return false,
        () = wait_for_optional_udp_route_generation_change(route_change) => {
            return false;
        }
        response = proxy.answer(
            ProxyIngress::Ordinary(inbound),
            ProxyTransport::Udp,
            datagram.payload(),
        ) => response,
    };
    if session_cancellation.is_cancelled()
        || route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
    {
        return false;
    }
    if let Some(response) = authorize_dns_peer_after_answer(response, target, |peer| {
        reserve_tun_udp_peer(peer_policy, peer).is_some_and(TunUdpPeerReservation::commit)
    }) {
        if route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
        {
            return false;
        }
        // Local DNS replies retain the per-datagram synthetic or hijacked endpoint.
        let outcome = response_sink.send(target, &response);
        if route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
        {
            return false;
        }
        record_tun_udp_response_outcome(outcome);
    }
    true
}
