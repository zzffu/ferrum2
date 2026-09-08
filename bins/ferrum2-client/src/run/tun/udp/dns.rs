use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};

use super::association::{
    DispatchServices, OrdinaryGeneration, TunUdpPeerReservation, authorize_dns_peer_after_answer,
    record_tun_udp_response_outcome, reserve_tun_udp_peer,
};
use super::route::wait_for_optional_udp_route_generation_change;

pub(super) async fn answer_tun_udp_dns(
    datagram: ferrum2_tun::UdpDatagram,
    proxy: &DnsProxy,
    services: &DispatchServices,
    mut generation: Option<&mut OrdinaryGeneration>,
    response_sink: &ferrum2_tun::UdpResponseSink,
    peer_policy: &ferrum2_tun::UdpPeerPolicyHandle,
) -> bool {
    if !services.current(generation.as_deref()) {
        return false;
    }
    let target = datagram.target();
    let mut forced = services.cancellation.clone();
    let response = tokio::select! {
        biased;
        () = forced.forced() => return false,
        () = services.session_cancellation.cancelled() => return false,
        () = crate::run::context::observation_cancelled(services.observation.as_ref()) => {
            if let Some(observation) = &services.observation { observation.finish("cancelled"); }
            return false;
        },
        () = wait_for_optional_udp_route_generation_change(generation.as_mut().map(|generation| &mut generation.changed)) => return false,
        response = proxy.answer(ProxyIngress::Ordinary(services.inbound), ProxyTransport::Udp, datagram.payload()) => response,
    };
    if let Some(observation) = &services.observation {
        observation.upload(datagram.payload().len());
    }
    if !services.current(generation.as_deref()) {
        return false;
    }
    if let Some(response) = authorize_dns_peer_after_answer(response, target, |peer| {
        reserve_tun_udp_peer(peer_policy, peer).is_some_and(TunUdpPeerReservation::commit)
    }) {
        if !services.current(generation.as_deref()) {
            return false;
        }
        let outcome = response_sink.send(target, &response);
        if !services.current(generation.as_deref()) {
            return false;
        }
        if record_tun_udp_response_outcome(outcome)
            && let Some(observation) = &services.observation
        {
            observation.download(response.len());
        }
    }
    true
}
