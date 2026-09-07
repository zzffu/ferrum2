use super::association::{ClientUdpAssociation, UdpPath};
use super::direct::{DirectSocketState, DirectUdpFamily, DirectUdpResponsePolicy};
use super::direct_association::DirectAssociation;
use super::lease::UdpAssociationLease;
use super::proxy::{ProxyAssociation, ProxyResources};
use crate::run::egress::context::{ClientOutboundContext, ClientRequestOrigin, SelectedEgress};
use crate::run::egress::engine::ClientEgressEngine;
use crate::run::egress::network::ClientPhysicalConnector;
use bytes::BytesMut;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_net::DialOptions;
use ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES;
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpPacketScratch};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::Instant;
pub(in crate::run) async fn prepare<C, T, R, F, Fut>(
    egress: &ClientEgressEngine<C, T, R>,
    origin: ClientRequestOrigin,
    ingress: usize,
    plan: Option<EgressPlanSnapshot>,
    selected: SelectedEgress,
    target: Option<&TargetAddr>,
    mut bind: F,
) -> Result<ClientUdpAssociation, ()>
where
    C: ClientPhysicalConnector,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let expected_network_generation = egress.connector.network_generation();
    let udp = egress.udp.as_ref().ok_or(())?;
    let direct_resolver = match selected {
        SelectedEgress::Direct {
            outbound: Some(outbound),
        } => egress
            .direct_resolvers
            .get(outbound)
            .and_then(Option::as_ref)
            .ok_or(())?
            .for_ingress(ingress),
        SelectedEgress::Direct { outbound: None } | SelectedEgress::Shadowsocks { .. } => {
            egress.application_resolver.for_ingress(ingress)
        }
    };
    let pending_session = udp
        .manager
        .reserve_session(Instant::now())
        .map_err(|_| ())?;
    let budget = match origin {
        ClientRequestOrigin::Tun => udp.tun_budget.clone(),
        ClientRequestOrigin::Socks | ClientRequestOrigin::Dns | ClientRequestOrigin::RuleSet => {
            udp.manager.buffer_budget()
        }
    };
    let fixed_buffer_count = match selected {
        SelectedEgress::Direct { .. } => 1,
        SelectedEgress::Shadowsocks { .. } => {
            if plan.as_ref().ok_or(())?.hops().len() == 1 {
                2
            } else {
                3
            }
        }
    };
    let mut fixed_capacity = Vec::with_capacity(fixed_buffer_count);
    for _ in 0..fixed_buffer_count {
        let capacity = match selected {
            SelectedEgress::Direct { .. } => MAX_UDP_WIRE_DATAGRAM_BYTES,
            SelectedEgress::Shadowsocks { .. } => MAX_UDP_WIRE_LEN,
        };
        fixed_capacity.push(budget.reserve(capacity).map_err(|_| ())?);
    }
    let path = match selected {
        SelectedEgress::Shadowsocks {
            first_outbound,
            first_server,
        } => {
            let dial_options = egress
                .outbounds
                .get(first_outbound)
                .ok_or(())?
                .dial_options();
            let factory = egress.connector.udp_socket_factory(
                expected_network_generation,
                dial_options,
                &egress.route_network,
            );
            let socket = factory
                .open_proxy(first_server, &mut bind)
                .await
                .map_err(|_| ())?;
            UdpPath::Proxy(ProxyAssociation::prepared(
                ProxyResources {
                    plan: plan.ok_or(())?,
                    socket,
                    inner_wire: if fixed_buffer_count == 3 {
                        vec![0_u8; MAX_UDP_WIRE_LEN]
                    } else {
                        Vec::new()
                    },
                    upstream_wire: BytesMut::with_capacity(MAX_UDP_WIRE_LEN),
                    scratch: UdpPacketScratch::new(),
                },
                Arc::clone(&udp.live_ids),
            ))
        }
        SelectedEgress::Direct { outbound } => {
            let default_dial_options = DialOptions::default();
            let dial_options = outbound
                .and_then(|index| egress.outbounds.get(index))
                .map_or(&default_dial_options, ClientOutboundContext::dial_options);
            let factory = egress.connector.udp_socket_factory(
                expected_network_generation,
                dial_options,
                &egress.route_network,
            );
            let policy = match origin {
                ClientRequestOrigin::Tun => {
                    let endpoint = target.and_then(TargetAddr::as_socket_addr).ok_or(())?;
                    DirectUdpResponsePolicy::TunSink(if endpoint.is_ipv4() {
                        DirectUdpFamily::Ipv4
                    } else {
                        DirectUdpFamily::Ipv6
                    })
                }
                ClientRequestOrigin::Socks
                | ClientRequestOrigin::Dns
                | ClientRequestOrigin::RuleSet => DirectUdpResponsePolicy::OutstandingPeers,
            };
            UdpPath::Direct(DirectAssociation::new(
                plan,
                DirectSocketState::Pending(factory),
                direct_resolver,
                egress.phase_deadlines.0,
                policy,
            ))
        }
    };
    if !egress
        .connector
        .network_generation_is_admissible(expected_network_generation)
    {
        return Err(());
    }
    Ok(ClientUdpAssociation {
        lease: UdpAssociationLease::new(
            udp.manager.clone(),
            pending_session,
            budget,
            fixed_capacity,
        ),
        path,
        #[cfg(test)]
        io_fault: None,
    })
}
