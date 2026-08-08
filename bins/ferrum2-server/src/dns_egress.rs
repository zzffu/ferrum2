#![forbid(unsafe_code)]

//! Server adapters for the shared tagged DNS resolver.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport, ServerDnsRoute};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{ActionTable, EgressPlanSnapshot, Network};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsIoFuture, DnsTaskRegistrar, DnsUpstreamSpec,
    DnsUpstreamTransport, SystemDnsEgress, TaggedResolver,
};
use ferrum2_runtime::{
    MAX_RESOLVED_CANDIDATES, SystemTcpResolver, SystemUdpResolver, TcpResolver, UdpResolver,
};

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

pub(super) struct ServerDnsState {
    route: ActionTable<usize>,
    policy: Option<ServerDnsRoute>,
    resolver: Mutex<Option<Arc<TaggedResolver>>>,
}

impl ServerDnsState {
    pub(super) fn new(route: ActionTable<usize>, policy: Option<ServerDnsRoute>) -> Self {
        Self {
            route,
            policy,
            resolver: Mutex::new(None),
        }
    }

    pub(super) fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        self.policy.as_ref().map_or_else(
            || self.route.select(inbound, network, target),
            |policy| policy.select(inbound, network, target),
        )
    }

    pub(super) fn install(&self, resolver: Arc<TaggedResolver>) -> Result<(), ()> {
        let mut current = self.resolver.lock().map_err(|_| ())?;
        if current.is_some() {
            return Err(());
        }
        *current = Some(resolver);
        Ok(())
    }

    pub(super) fn take(&self) -> Option<Arc<TaggedResolver>> {
        self.resolver.lock().ok()?.take()
    }

    fn resolver(&self) -> io::Result<Arc<TaggedResolver>> {
        self.resolver
            .lock()
            .map_err(|_| io::Error::other("DNS resolver state unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::other("DNS resolver is not active"))
    }
}

#[derive(Clone)]
pub(super) struct ServerDnsResolver {
    state: Option<Arc<ServerDnsState>>,
    inbound: usize,
    network: Network,
}

impl ServerDnsResolver {
    pub(super) fn new(
        state: Option<Arc<ServerDnsState>>,
        inbound: usize,
        network: Network,
    ) -> Self {
        Self {
            state,
            inbound,
            network,
        }
    }

    async fn resolve_candidates(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let Some(state) = &self.state else {
            return match self.network {
                Network::Tcp => SystemTcpResolver.resolve(host, port).await,
                Network::Udp => SystemUdpResolver.resolve(host, port).await,
            };
        };
        let target = TargetAddr::domain(host, port)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS target"))?;
        let selected = state.select(self.inbound, self.network, &target);
        let resolver = state.resolver()?;
        let name = host
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"))?;
        resolver
            .lookup_ips(selected, name)
            .await
            .map_err(|_| io::Error::other("DNS resolution failed"))
            .map(|addresses| {
                addresses
                    .into_iter()
                    .take(MAX_RESOLVED_CANDIDATES)
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            })
    }
}

impl TcpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_candidates(host, port).await
    }
}

impl UdpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        self.resolve_candidates(host, port).await
    }
}

pub(super) struct ServerDnsEgress {
    outbound_count: usize,
}

impl ServerDnsEgress {
    pub(super) fn new(outbound_count: usize) -> Self {
        Self { outbound_count }
    }

    fn validate(&self, plan: &Option<EgressPlanSnapshot>) -> io::Result<()> {
        match plan {
            None => Ok(()),
            Some(plan) if matches!(plan.hops(), [outbound] if *outbound < self.outbound_count) => {
                Ok(())
            }
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid server DNS detour",
            )),
        }
    }
}

impl DnsEgress for ServerDnsEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        if let Err(error) = self.validate(&plan) {
            return Box::pin(async move { Err(error) });
        }
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        if let Err(error) = self.validate(&plan) {
            return Box::pin(async move { Err(error) });
        }
        SystemDnsEgress.bind_udp(target, None, tasks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ferrum2_core::route::EgressPlanHandle;

    use crate::run::test_support::{
        Ipv4Addr, UdpSocket, assert_pending, recv_udp, reserve_address, server_test_config_source,
    };

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
    }

    #[tokio::test]
    async fn tagged_dns_selection_uses_authenticated_original_context_and_final() {
        let listen = reserve_address();
        let selected_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("selected DNS upstream");
        let selected_address = selected_socket.local_addr().expect("selected DNS address");
        let final_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("final DNS upstream");
        let final_address = final_socket.local_addr().expect("final DNS address");
        let dead_address = reserve_address();
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{listen}\"\n\
             [[outbounds]]\n\
             tag = \"direct\"\n\
             [route]\n\
             final = \"direct\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [dns]\n\
             timeout_ms = 100\n\
             [[dns.servers]]\n\
             tag = \"selected\"\n\
             transport = \"udp\"\n\
             address = \"{selected_address}\"\n\
             [[dns.servers]]\n\
             tag = \"dead\"\n\
             transport = \"udp\"\n\
             address = \"{dead_address}\"\n\
             [[dns.servers]]\n\
             tag = \"final\"\n\
             transport = \"udp\"\n\
             address = \"{final_address}\"\n\
             [dns.route]\n\
             final = \"final\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"exact.test\"\n\
             port = 53\n\
             server = \"selected\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"dead.example.com\"\n\
             port = 443\n\
             server = \"dead\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = [\"tcp\", \"udp\"]\n\
             domain_suffix = \"example.com\"\n\
             port_range = \"443:8443\"\n\
             server = \"selected\"\n"
        );
        let (path, config) = server_test_config_source("dns-policy", &source);
        let dns = config.dns.expect("server DNS config");
        let specs = dns_runtime_specs(&dns.servers);
        let state = Arc::new(ServerDnsState::new(dns.route, config.dns_route));
        let exact = TargetAddr::domain("EXACT.TEST.", 53).expect("exact target");
        let suffix_low = TargetAddr::domain("api.example.com.", 443).expect("range low target");
        let suffix_high =
            TargetAddr::domain("deep.api.example.com", 8443).expect("range high target");
        let dead = TargetAddr::domain("dead.example.com", 443).expect("dead target");
        let below = TargetAddr::domain("api.example.com", 442).expect("below range target");
        let above = TargetAddr::domain("api.example.com", 8444).expect("above range target");
        let other = TargetAddr::domain("other.test", 443).expect("final target");

        let selected_task = tokio::spawn(async move {
            let mut request = [0_u8; 4096];
            for (qtype_offset, expected_qtype) in [(24, 1), (24, 28), (29, 1), (29, 28)] {
                let (length, peer) = recv_udp(&selected_socket, &mut request).await;
                assert!(length >= qtype_offset + 4);
                assert_eq!(
                    u16::from_be_bytes([request[qtype_offset], request[qtype_offset + 1]]),
                    expected_qtype
                );
                assert_eq!(&request[qtype_offset + 2..qtype_offset + 4], &[0, 1]);
                request[2] |= 0x80;
                request[3] |= 0x80;
                selected_socket
                    .send_to(&request[..length], peer)
                    .await
                    .expect("selected DNS response");
            }
        });
        let (check_final, start_final_check) = tokio::sync::oneshot::channel();
        let final_task = tokio::spawn(async move {
            let mut request = [0_u8; 4096];
            for expected_qtype in [1, 28] {
                let (length, peer) = recv_udp(&final_socket, &mut request).await;
                assert!(length >= 28);
                assert_eq!(
                    u16::from_be_bytes([request[24], request[25]]),
                    expected_qtype
                );
                assert_eq!(&request[26..28], &[0, 1]);
                request[2] |= 0x80;
                request[3] |= 0x80;
                final_socket
                    .send_to(&request[..length], peer)
                    .await
                    .expect("final DNS response");
            }
            start_final_check.await.expect("start no-fallback check");
            assert_pending(
                final_socket.recv_from(&mut request),
                "selected DNS failure reached the healthy final server",
            )
            .await;
        });
        let egress = Arc::new(ServerDnsEgress::new(config.outbounds.len()));
        let (resolver, mut owner) =
            TaggedResolver::new(specs, dns.timeout, dns.max_inflight, egress)
                .expect("server DNS resolver");
        owner.ready().await.expect("server DNS resolver ready");
        state
            .install(Arc::new(resolver))
            .expect("install server DNS resolver");
        let resolver = ServerDnsResolver::new(Some(Arc::clone(&state)), 0, Network::Tcp);

        assert_eq!(
            TcpResolver::resolve(&resolver, "EXACT.TEST.", 53)
                .await
                .expect("exact DNS resolution"),
            []
        );
        assert_eq!(
            TcpResolver::resolve(&resolver, "api.example.com.", 443)
                .await
                .expect("suffix DNS resolution"),
            []
        );
        assert_eq!(
            TcpResolver::resolve(&resolver, "other.test.", 443)
                .await
                .expect("final DNS resolution"),
            []
        );
        check_final.send(()).expect("arm no-fallback check");
        assert!(
            TcpResolver::resolve(&resolver, "dead.example.com.", 443)
                .await
                .is_err(),
            "selected DNS failure must remain terminal"
        );

        selected_task.await.expect("selected DNS upstream join");
        final_task.await.expect("final DNS upstream join");
        assert_eq!(state.select(0, Network::Tcp, &exact), 0);
        assert_eq!(state.select(0, Network::Tcp, &suffix_low), 0);
        assert_eq!(state.select(0, Network::Udp, &suffix_high), 0);
        assert_eq!(state.select(0, Network::Tcp, &dead), 1);
        assert_eq!(state.select(1, Network::Tcp, &exact), 2);
        assert_eq!(state.select(0, Network::Udp, &exact), 2);
        assert_eq!(state.select(0, Network::Tcp, &below), 2);
        assert_eq!(state.select(0, Network::Tcp, &above), 2);
        assert_eq!(state.select(0, Network::Tcp, &other), 2);
        drop(resolver);
        drop(state.take());
        assert_eq!(
            owner
                .shutdown()
                .await
                .expect("server DNS resolver shutdown")
                .stats,
            ferrum2_dns::RuntimeStats::default()
        );
        std::fs::remove_file(path).expect("remove server DNS policy config");
    }
}
