use super::lease::UdpAssociationLease;
use super::request::register_udp_plan;
use super::response::{UdpPlanResponseError, commit_final_udp_response};
use super::socket::ClientProxyUdpSocket;
use crate::run::egress::context::ClientOutboundContext;
use crate::run::egress::engine::ClientEgressEngine;
use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{Clock, SecureRandom, UdpSessionId};
use ferrum2_runtime::AccountedDatagram;
use ferrum2_shadowsocks::{UdpClientSession, UdpPacketError, UdpPacketScratch};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub(super) struct ClientUdpLeg {
    pub(super) protocol: UdpClientSession,
    pub(super) id: UdpSessionId,
}
pub(super) struct ClientUdpPlan {
    pub(super) legs: Vec<ClientUdpLeg>,
    live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
}
impl Drop for ClientUdpPlan {
    fn drop(&mut self) {
        if let Ok(mut live_ids) = self.live_ids.lock() {
            for leg in &self.legs {
                live_ids.remove(&leg.id);
            }
        }
    }
}

pub(super) struct ProxyResources {
    pub(super) plan: EgressPlanSnapshot,
    pub(super) socket: ClientProxyUdpSocket,
    pub(super) inner_wire: Vec<u8>,
    pub(super) upstream_wire: BytesMut,
    pub(super) scratch: UdpPacketScratch,
}
// Every phase has the complete, proxy-only resources; Active additionally owns
// the registered protocol lineage. Activation cannot create a partial Active.
enum ProxyPhase {
    Prepared(Arc<Mutex<HashSet<UdpSessionId>>>),
    Active(ClientUdpPlan),
}
pub(super) struct ProxyAssociation {
    pub(super) resources: ProxyResources,
    phase: ProxyPhase,
}
impl ProxyAssociation {
    pub(super) fn prepared(
        resources: ProxyResources,
        live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
    ) -> Self {
        Self {
            resources,
            phase: ProxyPhase::Prepared(live_ids),
        }
    }
    pub(super) fn activate<C, T, R: SecureRandom>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
    ) -> Result<(), ()> {
        let ProxyPhase::Prepared(live_ids) = &self.phase else {
            return Ok(());
        };
        #[cfg(test)]
        let random = egress.udp_id_random.as_deref().unwrap_or(&egress.random);
        #[cfg(not(test))]
        let random = &egress.random;
        let legs = register_udp_plan(
            &egress.outbounds,
            self.resources.plan.hops(),
            random,
            live_ids,
        )?;
        self.phase = ProxyPhase::Active(ClientUdpPlan {
            legs,
            live_ids: live_ids.clone(),
        });
        Ok(())
    }
    pub(in crate::run) fn encode_request<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        datagram: &Datagram,
    ) -> Result<usize, UdpPacketError>
    where
        T: Clock,
        R: SecureRandom,
    {
        let Self {
            resources:
                ProxyResources {
                    plan,
                    inner_wire,
                    upstream_wire,
                    scratch,
                    ..
                },
            phase,
        } = self;
        let hops = plan.hops();
        let ProxyPhase::Active(plan) = phase else {
            return Err(UdpPacketError::StateUnavailable);
        };
        let mut wire_len = 0;
        let mut wire_in_upstream = false;
        for layer in (0..hops.len()).rev() {
            let intermediate;
            let target = if layer + 1 == hops.len() {
                datagram.target()
            } else {
                intermediate = TargetAddr::ip(
                    outbounds
                        .get(hops[layer + 1])
                        .and_then(ClientOutboundContext::shadowsocks)
                        .ok_or(UdpPacketError::StateUnavailable)?
                        .udp_server,
                )
                .map_err(|_| UdpPacketError::Bounds)?;
                &intermediate
            };
            wire_len = if layer + 1 == hops.len() {
                encode_request_layer(
                    &mut plan.legs[layer].protocol,
                    &egress.clock,
                    &egress.random,
                    target,
                    datagram.payload(),
                    upstream_wire,
                    scratch,
                )?
            } else if wire_in_upstream {
                plan.legs[layer].protocol.encode_request_parts(
                    &egress.clock,
                    &egress.random,
                    target,
                    &upstream_wire[..wire_len],
                    0,
                    inner_wire,
                    scratch,
                )?
            } else {
                encode_request_layer(
                    &mut plan.legs[layer].protocol,
                    &egress.clock,
                    &egress.random,
                    target,
                    &inner_wire[..wire_len],
                    upstream_wire,
                    scratch,
                )?
            };
            wire_in_upstream = layer + 1 == hops.len() || !wire_in_upstream;
        }
        if !wire_in_upstream {
            upstream_wire.resize(wire_len, 0);
            upstream_wire[..wire_len].copy_from_slice(&inner_wire[..wire_len]);
        }
        Ok(wire_len)
    }

    pub(in crate::run) fn accept_response<C, T, R>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
        lease: &UdpAssociationLease,
    ) -> Result<AccountedDatagram, UdpPlanResponseError>
    where
        T: Clock,
    {
        let Self {
            resources:
                ProxyResources {
                    plan,
                    inner_wire,
                    upstream_wire,
                    scratch,
                    ..
                },
            phase,
        } = self;
        let hops = plan.hops();
        let ProxyPhase::Active(plan) = phase else {
            return Err(UdpPlanResponseError::Packet(
                UdpPacketError::StateUnavailable,
            ));
        };
        let manager = &lease.manager;
        let handle = lease.handle().map_err(UdpPlanResponseError::Runtime)?;
        let accounting = lease.accounting;
        let outer = plan.legs[0]
            .protocol
            .prepare_response_borrowed(&egress.clock, &upstream_wire[..wire_len], scratch)
            .map_err(UdpPlanResponseError::Packet)?;
        let mut commits = Vec::with_capacity(hops.len());
        if hops.len() == 1 {
            return commit_final_udp_response(
                outer,
                plan,
                hops,
                outbounds,
                commits,
                manager,
                handle,
                accounting,
                &egress.clock,
            );
        }
        let expected = TargetAddr::ip(
            outbounds
                .get(hops[1])
                .and_then(ClientOutboundContext::shadowsocks)
                .ok_or(UdpPlanResponseError::Packet(
                    UdpPacketError::StateUnavailable,
                ))?
                .udp_server,
        )
        .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        if !outer.target_matches(&expected) {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
        }
        let mut inner_len = outer
            .copy_payload_to(inner_wire)
            .map_err(UdpPlanResponseError::Packet)?;
        commits.push(outer.into_commit());
        let mut wire_in_inner = true;
        for layer in 1..hops.len() {
            let pending = if wire_in_inner {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    &egress.clock,
                    &inner_wire[..inner_len],
                    scratch,
                )
            } else {
                plan.legs[layer].protocol.prepare_response_borrowed(
                    &egress.clock,
                    &upstream_wire[..inner_len],
                    scratch,
                )
            }
            .map_err(UdpPlanResponseError::Packet)?;
            if layer + 1 == hops.len() {
                return commit_final_udp_response(
                    pending,
                    plan,
                    hops,
                    outbounds,
                    commits,
                    manager,
                    handle,
                    accounting,
                    &egress.clock,
                );
            }
            let expected = TargetAddr::ip(
                outbounds
                    .get(hops[layer + 1])
                    .and_then(ClientOutboundContext::shadowsocks)
                    .ok_or(UdpPlanResponseError::Packet(
                        UdpPacketError::StateUnavailable,
                    ))?
                    .udp_server,
            )
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
            if !pending.target_matches(&expected) {
                return Err(UdpPlanResponseError::Packet(UdpPacketError::Binding));
            }
            inner_len = if wire_in_inner {
                pending.copy_payload_to(upstream_wire)
            } else {
                pending.copy_payload_to(inner_wire)
            }
            .map_err(UdpPlanResponseError::Packet)?;
            commits.push(pending.into_commit());
            wire_in_inner = !wire_in_inner;
        }
        unreachable!("validated UDP plan has a final layer")
    }
}
fn encode_request_layer<T, R>(
    protocol: &mut UdpClientSession,
    clock: &T,
    random: &R,
    target: &TargetAddr,
    payload: &[u8],
    output: &mut BytesMut,
    scratch: &mut UdpPacketScratch,
) -> Result<usize, UdpPacketError>
where
    T: Clock + ?Sized,
    R: SecureRandom + ?Sized,
{
    let exact_len = protocol.request_wire_len(target, payload.len(), 0)?;
    output.resize(exact_len, 0);
    let wire_len =
        protocol.encode_request_parts(clock, random, target, payload, 0, output, scratch)?;
    debug_assert_eq!(wire_len, exact_len);
    Ok(wire_len)
}
