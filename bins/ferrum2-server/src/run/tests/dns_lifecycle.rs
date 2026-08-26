#![allow(unused_imports)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ferrum2_core::{ConnectError, Connector, TargetAddr};
use ferrum2_crypto::{MethodProfile, MethodTcpSalt};
use ferrum2_runtime::OwnerSnapshot;
use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::*;
use crate::run::test_support::*;

use super::support::*;

pub(super) struct ProtocolClientConnector {
    pub(super) inner: TcpConnector,
}

impl Connector for ProtocolClientConnector {
    type Stream = TokioTransport<RuntimeTcpStream>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.inner.connect(target).await.map(TokioTransport::new)
    }
}

pub(super) async fn gated_a_dns(
    expected_name: &'static str,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let dns = udp_loopback().await;
    let address = dns.local_addr().expect("drain DNS address");
    let (query_seen, query_observed) = tokio::sync::oneshot::channel();
    let (release_answer, answer_released) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let (length, peer) = dns.recv_from(&mut wire).await.expect("drain DNS receive");
        let request = Message::from_vec(&wire[..length]).expect("drain DNS request decode");
        let query = request.queries.first().expect("drain DNS query").clone();
        assert_eq!(query.name().to_ascii(), expected_name);
        assert_eq!(query.query_type(), RecordType::A);
        query_seen.send(()).expect("publish drain DNS query");
        answer_released.await.expect("release drain DNS answer");

        let mut response = Message::response(request.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        dns.send_to(&response.to_vec().expect("drain DNS response encode"), peer)
            .await
            .expect("drain DNS response send");
    });
    (address, query_observed, release_answer, task)
}

pub(super) fn operational_dns_drain_source(
    listen: SocketAddrV4,
    dns_address: SocketAddr,
    udp_enabled: bool,
) -> String {
    format!(
        r#"schema_version = 2
[[inbounds]]
tag = "i0"
listen = "{listen}"

[[outbounds]]
tag = "direct"
domain_resolver = "bootstrap"
domain_strategy = "ipv4_only"

[route]
final = "direct"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{dns_address}"

[dns.route]
final = "bootstrap"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[runtime]
shutdown_grace_ms = 2000

[udp]
enabled = {udp_enabled}
idle_timeout_ms = 60000
"#
    )
}

#[tokio::test]
async fn operational_dns_outlives_tcp_quiesce_drain() {
    let listen = reserve_address();
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("drain target listener");
    let target_address = target_listener.local_addr().expect("drain target address");
    let (dns_address, query_observed, release_answer, dns_task) = gated_a_dns("drain.test.").await;
    let source = operational_dns_drain_source(listen, dns_address, false);
    let (config_path, _) = server_test_config_source("dns-drain", &source);
    let config = finish_server_test_config(&config_path);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, mut run_task) = spawn_test_server(config, &registry);
    wait_until_bound(&mut run_task, listen).await;

    let keys = aes_keys();
    let connector = ProtocolClientConnector {
        inner: TcpConnector::new(Duration::from_secs(5)),
    };
    let server_target = TargetAddr::ipv4(listen).expect("drain server target");
    let application_target =
        TargetAddr::domain("drain.test", target_address.port()).expect("drain domain target");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let outbound = ClientTcpOutbound::new(server_target, &keys, &connector, &clock, &random);
    let flow = outbound
        .connect_server()
        .await
        .expect("connect drain server")
        .write_request(&application_target)
        .await
        .expect("write drain request");
    tokio::time::timeout(Duration::from_secs(1), query_observed)
        .await
        .expect("drain DNS query deadline")
        .expect("observe drain DNS query");

    shutdown_sender.send(()).expect("quiesce drain server");
    let quiesce_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = registry.snapshot();
        if snapshot.listeners == baseline.listeners
            && snapshot.connection_tasks == 1
            && snapshot.active_process_roots == baseline.active_process_roots + 2
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < quiesce_deadline,
            "TCP root did not enter quiescing with its accepted flow live: {snapshot:?}"
        );
        tokio::task::yield_now().await;
    }
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    release_answer.send(()).expect("answer drain DNS query");
    let (target_stream, _) = tokio::time::timeout(Duration::from_secs(1), target_listener.accept())
        .await
        .expect("drained target accept deadline")
        .expect("drained target accept");
    drop(flow);
    drop(target_stream);
    dns_task.await.expect("drain DNS task join");

    assert_eq!(run_task.await.expect("drain server task"), Ok(()));
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(config_path).expect("remove drain server config");
}
