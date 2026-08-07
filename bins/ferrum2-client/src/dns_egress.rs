use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsIoFuture, DnsTaskRegistrar, DnsUpstreamSpec, DnsUpstreamTransport,
    SystemDnsEgress,
};
use ferrum2_runtime::UdpDirection;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::egress::ClientEgressEngine;
use super::{
    MAX_UDP_WIRE_LEN, PreparedClientUdp, TokioFramed, accept_udp_plan_response, activate_udp_plan,
    encode_udp_plan_request, reserve_application_datagram,
};

type Packet = (Vec<u8>, SocketAddr);
type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>> + Send>,
>;
type DnsUdpPool = Arc<Mutex<Vec<PreparedClientUdp>>>;

pub(super) fn dns_runtime_specs(servers: &[DnsServerConfig]) -> Vec<DnsUpstreamSpec> {
    servers
        .iter()
        .map(|server| {
            let transport = match server.transport {
                DnsTransport::Udp => DnsUpstreamTransport::Udp,
                DnsTransport::Tcp => DnsUpstreamTransport::Tcp,
                DnsTransport::Dot => DnsUpstreamTransport::Dot {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoT server name"),
                },
                DnsTransport::Doh => DnsUpstreamTransport::Doh {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoH server name"),
                    path: server.path.clone().expect("validated DoH path"),
                },
            };
            DnsUpstreamSpec {
                transport,
                address: server.address,
                detour: server.detour.clone(),
            }
        })
        .collect()
}

pub(super) struct ClientDnsEgress {
    engine: Arc<ClientEgressEngine>,
    udp_pool: DnsUdpPool,
}

impl ClientDnsEgress {
    pub(super) fn new(engine: Arc<ClientEgressEngine>) -> Self {
        Self {
            engine,
            udp_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

struct PooledDnsUdp {
    prepared: Option<PreparedClientUdp>,
    pool: DnsUdpPool,
    reusable: bool,
}

impl Drop for PooledDnsUdp {
    fn drop(&mut self) {
        if !self.reusable {
            return;
        }
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        if let Ok(mut pool) = self.pool.lock() {
            pool.push(prepared);
        }
    }
}

impl DnsEgress for ClientDnsEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.connect_tcp(target, None, timeout, tasks);
        };
        let engine = Arc::clone(&self.engine);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
            if plan.hops().iter().any(|hop| *hop >= engine.outbounds.len()) {
                return Err(invalid_target());
            }
            let queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            let (client, mut bridge_front) = tokio::io::duplex(2_048);
            let (mut bridge_back, mut session_io) = tokio::io::duplex(2_048);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_queue, _buffer) = (queue, buffer);
                let _ = tokio::io::copy_bidirectional(&mut bridge_front, &mut bridge_back).await;
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                let Ok(flow) = engine
                    .open_tcp(
                        plan,
                        &target,
                        Some(timeout),
                        #[cfg(test)]
                        None,
                    )
                    .await
                else {
                    return;
                };
                let mut upstream = TokioFramed::new(flow);
                let _ = tokio::io::copy_bidirectional(&mut session_io, &mut upstream).await;
            });
            Ok(Box::new(client) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.bind_udp(target, None, tasks);
        };
        let engine = Arc::clone(&self.engine);
        let pool = Arc::clone(&self.udp_pool);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
            let first_server = plan
                .hops()
                .first()
                .and_then(|hop| engine.outbounds.get(*hop))
                .map(|outbound| outbound.udp_server)
                .ok_or_else(invalid_target)?;
            let (prepared, stale) = {
                let mut idle = pool.lock().map_err(|_| invalid_target())?;
                match idle.iter().position(|prepared| {
                    prepared.static_server == Some(first_server)
                        && prepared.static_plan.as_ref() == Some(&plan)
                }) {
                    Some(index) => (Some(idle.swap_remove(index)), None),
                    None => (None, idle.pop()),
                }
            };
            drop(stale);
            let mut prepared = match prepared {
                Some(prepared) => prepared,
                None => super::prepare_udp_association_with_bind(
                    &engine,
                    Ipv4Addr::LOCALHOST,
                    Some((plan.clone(), first_server)),
                    UdpSocket::bind,
                )
                .await
                .map_err(|_| io::Error::other("DNS UDP egress unavailable"))?,
            };
            activate_udp_plan(&mut prepared, &engine, &engine.outbounds, plan.hops())
                .map_err(|_| invalid_target())?;
            let mut prepared = PooledDnsUdp {
                prepared: Some(prepared),
                pool,
                reusable: true,
            };

            let (outgoing, mut outbound) = mpsc::channel::<Packet>(1);
            let (inbound, incoming) = mpsc::channel::<Packet>(1);
            let (session_requests, mut requests) = mpsc::channel::<Packet>(1);
            let (session_responses, mut responses) = mpsc::channel::<Packet>(1);
            let outbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let inbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let request_queue = tasks.own(DnsEgressResourceKind::Queue);
            let response_queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_outbound_queue, _inbound_queue, _request_queue, _response_queue, _buffer) = (
                    outbound_queue,
                    inbound_queue,
                    request_queue,
                    response_queue,
                    buffer,
                );
                while let Some((packet, destination)) = outbound.recv().await {
                    if destination != target.as_socket_addr().expect("numeric DNS target")
                        || session_requests.send((packet, destination)).await.is_err()
                    {
                        break;
                    }
                    let Some(response) = responses.recv().await else {
                        break;
                    };
                    if inbound.send(response).await.is_err() {
                        break;
                    }
                }
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                while let Some((packet, destination)) = requests.recv().await {
                    prepared.reusable = false;
                    let response = relay_udp_packet(
                        prepared.prepared.as_mut().expect("pooled DNS UDP owner"),
                        &engine,
                        plan.hops(),
                        first_server,
                        destination,
                        packet,
                    )
                    .await;
                    let Ok(response) = response else {
                        break;
                    };
                    prepared.reusable = true;
                    if session_responses.send(response).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(ClientDnsDatagram {
                outgoing,
                reserve: Mutex::new(None),
                incoming: Mutex::new(incoming),
            }) as BoxedDnsDatagramIo)
        })
    }
}

async fn relay_udp_packet(
    prepared: &mut super::PreparedClientUdp,
    engine: &ClientEgressEngine,
    hops: &[usize],
    first_server: std::net::SocketAddrV4,
    destination: SocketAddr,
    packet: Vec<u8>,
) -> io::Result<Packet> {
    if packet.len() > MAX_UDP_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS UDP packet too large",
        ));
    }
    let target = TargetAddr::ip(destination).map_err(|_| invalid_target())?;
    let payload_len = packet.len();
    let reservation = reserve_application_datagram(prepared, payload_len).map_err(runtime_error)?;
    let datagram = Datagram::new(target, packet.as_slice().into(), payload_len)
        .map_err(|_| invalid_target())?;
    let committed = match prepared.pending_session.take() {
        Some(session) => session.commit(reservation, datagram, tokio::time::Instant::now()),
        None => reservation
            .commit(datagram, tokio::time::Instant::now())
            .map(|()| prepared.handle),
    };
    committed.map_err(runtime_error)?;
    let datagram = prepared
        .manager
        .pop(prepared.handle, UdpDirection::ToTarget)
        .map_err(runtime_error)?
        .ok_or_else(|| io::Error::other("DNS UDP queue empty"))?;
    let wire_len = encode_udp_plan_request(
        prepared,
        &engine.outbounds,
        hops,
        datagram.datagram(),
        &engine.clock,
        &engine.random,
    )
    .map_err(|_| io::Error::other("DNS UDP encode failed"))?;
    drop(datagram);
    let sent = prepared
        .upstream
        .send(&prepared.upstream_wire[..wire_len])
        .await?;
    if sent != wire_len {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short DNS UDP send",
        ));
    }
    loop {
        let length = prepared.upstream.recv(&mut prepared.upstream_wire).await?;
        let payload_len = match accept_udp_plan_response(
            prepared,
            &engine.outbounds,
            first_server,
            length,
            &engine.clock,
        ) {
            Ok(Some(payload_len)) => payload_len,
            Ok(None) | Err(_) => continue,
        };
        let response = prepared
            .manager
            .pop(prepared.handle, UdpDirection::ToClient)
            .map_err(runtime_error)?
            .ok_or_else(|| io::Error::other("DNS UDP response queue empty"))?;
        let source = response
            .datagram()
            .target()
            .as_socket_addr()
            .ok_or_else(invalid_target)?;
        let payload = response.datagram().payload();
        if payload.len() != payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP length mismatch",
            ));
        }
        return Ok((payload.to_vec(), source));
    }
}

struct ClientDnsDatagram {
    outgoing: mpsc::Sender<Packet>,
    reserve: Mutex<Option<ReserveFuture>>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
}

impl DnsDatagramIo for ClientDnsDatagram {
    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP receive lock")));
        };
        match incoming.poll_recv(context) {
            Poll::Ready(Some((packet, source))) if packet.len() <= buffer.len() => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP receive too large",
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if buffer.len() > MAX_UDP_WIRE_LEN {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP send too large",
            )));
        }
        let Ok(mut reserve) = self.reserve.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP send lock")));
        };
        if reserve.is_none() {
            *reserve = Some(Box::pin(self.outgoing.clone().reserve_owned()));
        }
        match reserve
            .as_mut()
            .expect("reserve future")
            .as_mut()
            .poll(context)
        {
            Poll::Ready(Ok(permit)) => {
                reserve.take();
                permit.send((buffer.to_vec(), target));
                Poll::Ready(Ok(buffer.len()))
            }
            Poll::Ready(Err(_)) => {
                reserve.take();
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn invalid_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS egress target")
}

fn runtime_error(_error: impl Sized) -> io::Error {
    io::Error::other("DNS UDP runtime unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    use ferrum2_core::route::EgressPlanHandle;

    #[test]
    fn dns_runtime_specs_preserve_validated_server_values() {
        let cases = [
            (DnsTransport::Udp, 5300, None, None, false),
            (DnsTransport::Udp, 5301, None, None, true),
            (DnsTransport::Tcp, 5302, None, None, false),
            (DnsTransport::Tcp, 5303, None, None, true),
            (
                DnsTransport::Dot,
                8530,
                Some("dot-direct.test"),
                None,
                false,
            ),
            (DnsTransport::Dot, 8531, Some("dot-detour.test"), None, true),
            (
                DnsTransport::Doh,
                4430,
                Some("doh-direct.test"),
                Some("/dns-query/direct"),
                false,
            ),
            (
                DnsTransport::Doh,
                4431,
                Some("doh-detour.test"),
                Some("/dns-query/detour"),
                true,
            ),
        ];
        let servers: Vec<_> = cases
            .iter()
            .enumerate()
            .map(
                |(index, &(transport, port, server_name, path, detoured))| DnsServerConfig {
                    transport,
                    address: SocketAddr::from(([192, 0, 2, 53], port)),
                    server_name: server_name.map(Into::into),
                    path: path.map(Into::into),
                    detour: detoured.then(|| EgressPlanHandle::direct(index)),
                },
            )
            .collect();
        let configured_plan_ptrs: Vec<_> = servers
            .iter()
            .map(|server| {
                server
                    .detour
                    .as_ref()
                    .map(|detour| detour.snapshot_owned().hops().as_ptr())
            })
            .collect();

        for (
            index,
            ((spec, (transport, port, server_name, path, detoured)), configured_plan_ptr),
        ) in dns_runtime_specs(&servers)
            .into_iter()
            .zip(cases)
            .zip(configured_plan_ptrs)
            .enumerate()
        {
            assert_eq!(spec.address, SocketAddr::from(([192, 0, 2, 53], port)));
            match (detoured, spec.detour.as_ref()) {
                (true, Some(detour)) => {
                    let converted = detour.snapshot_owned();
                    assert_eq!(converted.hops(), &[index]);
                    assert_eq!(Some(converted.hops().as_ptr()), configured_plan_ptr);
                }
                (false, None) => {}
                _ => panic!("DNS runtime detour mapping drift"),
            }
            match (transport, spec.transport) {
                (DnsTransport::Udp, DnsUpstreamTransport::Udp)
                | (DnsTransport::Tcp, DnsUpstreamTransport::Tcp) => {
                    assert_eq!((server_name, path), (None, None));
                }
                (
                    DnsTransport::Dot,
                    DnsUpstreamTransport::Dot {
                        server_name: actual,
                    },
                ) => {
                    assert_eq!(actual.as_ref(), server_name.expect("DoT name"));
                    assert!(path.is_none());
                }
                (
                    DnsTransport::Doh,
                    DnsUpstreamTransport::Doh {
                        server_name: actual_name,
                        path: actual_path,
                    },
                ) => {
                    assert_eq!(actual_name.as_ref(), server_name.expect("DoH name"));
                    assert_eq!(actual_path.as_ref(), path.expect("DoH path"));
                }
                _ => panic!("DNS runtime transport mapping drift"),
            }
        }

        let source = include_str!("dns_egress.rs");
        assert!(source.contains(&["engine: Arc<", "ClientEgressEngine", ">"].concat()));
        assert!(source.contains(&[".", "open_tcp("].concat()));
        for forbidden in [
            ["Client", "Context"].concat(),
            ["Client", "Routing"].concat(),
            ["open_chain", "_with_deadlines"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "DNS TCP bypass: {forbidden}");
        }

        let engine = [
            include_str!("run/egress/mod.rs"),
            include_str!("run/egress/tcp.rs"),
        ]
        .concat();
        for forbidden in [
            ["Route", "Table"].concat(),
            ["Selector", "Control"].concat(),
            ["Socks5", "Inbound"].concat(),
        ] {
            assert!(
                !engine.contains(&forbidden),
                "TCP engine owns policy/ingress: {forbidden}"
            );
        }
    }
}
