use super::*;

use tokio::io::AsyncReadExt as _;

use ferrum2_config::{
    ClientV2Resources, CompiledRuleSetResource, finish_client_v2, prepare_client,
};
use ferrum2_core::CanonicalDomain;
use ferrum2_core::Inbound as _;
use ferrum2_core::route::{EgressPlanHandle, Network, compile_egress_plans_with_roots};
use ferrum2_core::selector::{SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan};
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::TaggedResolver;
use ferrum2_rule::{MatchSetBuilder, RuleEngineRegistry, RuleEngineSnapshotBuilder};
use ferrum2_shadowsocks::{MethodKeyAdapter, UdpPacketScratch, UdpServer};

use crate::run::egress::{UdpIoFaultPlan, UdpIoOperation};
use crate::run::test_support::*;
use crate::run::{
    ClientRunResources, dns_egress, run_with_registry_and_metrics,
    run_with_registry_and_metrics_inner,
};

async fn dns_tcp_detour_once(
    listener: TcpListener,
    expected_target: SocketAddr,
    opened: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
) -> usize {
    let (stream, _) = listener.accept().await.expect("DNS detour accept");
    let stream = ferrum2_runtime::RuntimeTcpStream::from_connected(stream)
        .expect("DNS detour runtime stream");
    let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
    let clock = SystemClock::new();
    let random = SystemRandom;
    let replay = TcpReplayStore::new(1024).expect("DNS detour replay");
    let ferrum2_core::Session {
        target,
        stream,
        initial_payload,
        ..
    } = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .accept(TokioTransport::new(stream))
        .await
        .expect("authenticated DNS detour");
    assert_eq!(target.as_socket_addr(), Some(expected_target));
    if let Some(opened) = opened {
        let _ = opened.send(());
    }
    if let Some(release) = release {
        let _ = release.await;
    }
    let mut upstream = tokio::net::TcpStream::connect(expected_target)
        .await
        .expect("DNS detour target");
    upstream
        .write_all(&initial_payload)
        .await
        .expect("DNS detour initial payload");
    let mut stream = TokioFramed::new(stream);
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    1 + usize::from(
        tokio::time::timeout(Duration::from_millis(250), listener.accept())
            .await
            .is_ok(),
    )
}

enum DnsUdpResponsePrefix {
    None,
    Unauthenticated,
    AuthenticatedTarget(TargetAddr),
}

struct DnsUdpHopTarget {
    logical: TargetAddr,
    upstream: SocketAddr,
}

async fn relay_dns_udp_hop_once(
    socket: &UdpSocket,
    server: &UdpServer,
    target: DnsUdpHopTarget,
    clock: &SystemClock,
    random: &SystemRandom,
    scratch: &mut UdpPacketScratch,
    prefix: DnsUdpResponsePrefix,
) {
    let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let mut plain = [0_u8; 4096];
    let (length, peer) = socket
        .recv_from(&mut wire)
        .await
        .expect("encrypted DNS query");
    if matches!(&prefix, DnsUdpResponsePrefix::Unauthenticated) {
        socket
            .send_to(b"bad", peer)
            .await
            .expect("invalid encrypted DNS response");
    }
    let pending = server
        .prepare_request(clock, &wire[..length], scratch)
        .expect("authenticated DNS query");
    assert_eq!(pending.datagram().target(), &target.logical);
    let request = pending.datagram().payload().to_vec();
    let (_, commit) = pending.into_parts();
    let accepted = server
        .commit_request(commit, peer, clock.monotonic_now(), random)
        .expect("commit DNS query");
    socket
        .send_to(&request, target.upstream)
        .await
        .expect("forward plain DNS query");
    let (length, source) = socket
        .recv_from(&mut plain)
        .await
        .expect("plain DNS response");
    assert_eq!(source, target.upstream);
    if let DnsUdpResponsePrefix::AuthenticatedTarget(target) = prefix {
        let response = server
            .encode_response(
                accepted.capability(),
                clock,
                random,
                &test_datagram(target, &plain[..length]),
                0,
                &mut wire,
                scratch,
            )
            .expect("encrypt prefixed DNS response");
        socket
            .send_to(&wire[..response.wire_len()], peer)
            .await
            .expect("send prefixed DNS response");
    }
    let response = server
        .encode_response(
            accepted.capability(),
            clock,
            random,
            &test_datagram(
                TargetAddr::ip(target.upstream).expect("numeric DNS target"),
                &plain[..length],
            ),
            0,
            &mut wire,
            scratch,
        )
        .expect("encrypt DNS response");
    socket
        .send_to(&wire[..response.wire_len()], peer)
        .await
        .expect("encrypted DNS response");
}

mod policy;
mod pool;
mod proxy_lifecycle;
mod proxy_selection;
mod specs;
