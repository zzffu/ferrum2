use super::super::ClientRequestOrigin;

mod chain;
mod deadline;
mod direct;
mod routing;

pub(in crate::run) use chain::assert_open_pending;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_config::RouteAction;
use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, TargetAddr};
use ferrum2_crypto::{Clock, MethodProfile, MethodSinglePskProvider, MethodTcpSalt, SystemClock};
use ferrum2_rule::{RouteMetadata, RouteProgramAction};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, MethodKeyAdapter, ShadowsocksError, ShadowsocksTcpInbound,
    TcpKeyProvider, TcpReplayStore, encode_response_first_write,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::run::test_support::*;

fn selected_plan(
    route: &ferrum2_config::CompiledRoute,
    inbound: usize,
    network: Network,
    target: &TargetAddr,
) -> ferrum2_core::route::EgressPlanSnapshot {
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(inbound, network, target, &mut scratch);
    loop {
        match evaluation.next(RouteMetadata::new(None, None)) {
            Some(RouteProgramAction::Continue(_)) => {}
            Some(RouteProgramAction::Terminal(RouteAction::Route(plan)))
            | Some(RouteProgramAction::Final(RouteAction::Route(plan))) => {
                return plan.snapshot_owned();
            }
            other => panic!("unexpected route action: {other:?}"),
        }
    }
}

fn tcp_chain_test_setup(
    methods: [MethodProfile; 4],
    first_port: u16,
) -> (
    Arc<[ClientOutboundContext]>,
    ferrum2_config::CompiledRoute,
    ferrum2_rule::SelectorControl,
) {
    let servers: [SocketAddrV4; 4] =
        std::array::from_fn(|hop| SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port + hop as u16));
    let outbounds = prepare_client_outbounds(
        servers
            .into_iter()
            .zip(methods)
            .map(
                |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: server.into(),
                    psk: Arc::new(psk_for_method(method)),
                    dial_options: Default::default(),
                },
            )
            .collect(),
    )
    .expect("checked runtime outbounds");
    let listen = reserve_address();
    let mut source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"entry\"\n\
         listen = \"{listen}\"\n\
         outbound = \"manual\"\n"
    );
    for (index, server) in servers.into_iter().enumerate() {
        let tag = ['a', 'b', 'c', 'd'][index];
        source.push_str(&format!(
            "[[outbounds]]\n\
             tag = \"{tag}\"\n\
             type = \"shadowsocks\"\n\
             server = \"{server}\"\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
        ));
    }
    source.push_str(
        "[[chains]]\n\
         tag = \"a-b\"\n\
         hops = [\"a\", \"b\"]\n\
         [[chains]]\n\
         tag = \"c-d\"\n\
         hops = [\"c\", \"d\"]\n\
         [[selectors]]\n\
         tag = \"manual\"\n\
         outbounds = [\"a-b\", \"c-d\"]\n\
         default = \"a-b\"\n",
    );
    let path = write_client_test_source(&source);
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare chain selector");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish chain selector");
    std::fs::remove_file(path).expect("remove chain selector config");
    let selector = config.selector_control();
    (outbounds, config.route, selector)
}

async fn run_timeout_case(
    label: &str,
    runtime: RuntimeConfig,
    connect_delay: Duration,
    handshake: bool,
    timeout_limit: Option<Duration>,
    expected_timeout: Duration,
    key: u8,
) {
    let drops = Arc::new(AtomicUsize::new(0));
    let aborts = Arc::new(AtomicUsize::new(0));
    let connector = DeadlineConnector {
        delay: connect_delay,
        targets: Mutex::new(Vec::new()),
        stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::pending(
            Arc::clone(&drops),
            Arc::clone(&aborts),
        )))),
    };
    let server_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002);
    let server = TargetAddr::ipv4(server_address).expect(label);
    let engine = ClientEgressEngine::new(
        vec![ClientOutboundContext::Shadowsocks(
            ClientShadowsocksContext {
                tcp_server: server,
                udp_server: server_address.into(),
                keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                    ferrum2_crypto::MethodPsk::aes128([key; 16]),
                )),
                dial_options: ferrum2_net::DialOptions::default(),
            },
        )]
        .into(),
        connector,
        SystemClock::new(),
        FixedRandom,
        (runtime.connect_timeout, runtime.handshake_timeout),
        None,
        None,
    );
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect(label);
    let mut opened = Box::pin(engine.open_tcp_for_ingress(
        ClientRequestOrigin::Socks,
        0,
        Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
        &target,
        timeout_limit,
        None,
    ));
    assert_open_pending(&mut opened).await;
    if handshake {
        tokio::time::advance(connect_delay).await;
        assert_open_pending(&mut opened).await;
    }
    tokio::time::advance(expected_timeout - Duration::from_millis(1)).await;
    assert_open_pending(&mut opened).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    let error = match opened.await {
        Ok(_) => panic!("{label}"),
        Err(error) => error,
    };
    assert!(
        if handshake {
            matches!(error, ClientOpenFailure::HandshakeTimeout)
        } else {
            matches!(
                error,
                ClientOpenFailure::Protocol(ShadowsocksError::Connect(ConnectErrorKind::Timeout))
            )
        },
        "{label}"
    );
    drop(engine);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "{label}");
    assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}");
}
