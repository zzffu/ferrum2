use super::*;

#[tokio::test]
async fn routed_tcp_selects_after_target_and_never_falls_back() {
    let upstreams = [
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("A"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("B"),
    ];
    let servers: Vec<SocketAddrV4> = upstreams
        .iter()
        .map(|socket| match socket.local_addr().expect("upstream") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
        })
        .collect();
    let listens = [reserve_address(), reserve_address()];
    let mappings = [(listens[0], servers[0]), (listens[1], servers[1])];
    let (path, mut config) = tagged_client_test_config(&mappings, false);
    let dead = reserve_address();
    config
        .outbounds
        .push(ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: dead.into(),
            psk: Arc::new(psk_for_method(MethodProfile::Blake3Aes128Gcm2022)),
            dial_options: Default::default(),
        });
    let route_source = format!(
        r#"schema_version = 2
[[inbounds]]
tag = "i0"
listen = "{}"
[[inbounds]]
tag = "i1"
listen = "{}"
[[outbounds]]
tag = "o0"
type = "direct"
[[outbounds]]
tag = "o1"
type = "direct"
[[outbounds]]
tag = "dead"
type = "direct"
[[selectors]]
tag = "manual"
outbounds = ["o0", "o1", "dead"]
default = "o0"
[route]
final = "manual"
[[route.rules]]
inbound = "i1"
network = "tcp"
action = "route"
outbound = "manual"
[[route.rules]]
network = "tcp"
ip = "192.0.2.1"
port = 80
action = "route"
outbound = "manual"
"#,
        listens[0], listens[1]
    );
    let route_path = write_client_test_source(&route_source);
    let prepared = ferrum2_config::prepare_client(&route_path).expect("prepare selector route");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish selector route");
    std::fs::remove_file(route_path).expect("remove selector route config");
    config.route = route_config.route;
    let selector = config.selector_control();
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    for listen in listens {
        wait_until_bound(listen).await;
    }
    let (mut first, reply) = socks_connect_port(listens[0], 80).await;
    assert_eq!(&reply[..2], &[5, 0]);
    let (mut first_upstream, _) = upstreams[0].accept().await.expect("selected A");
    assert_eq!(
        registry.snapshot().owned_buffers,
        2,
        "single-hop SOCKS generic relay owns both directional buffers"
    );
    let mut wire = [0; 256];
    assert!(
        first_upstream
            .read(&mut wire)
            .await
            .expect("initial A wire")
            > 0
    );
    while first_upstream.try_read(&mut wire).is_ok() {}
    selector.switch("manual", "o1").expect("switch to B");
    first
        .write_all(b"captured A")
        .await
        .expect("open flow write");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), first_upstream.read(&mut wire))
            .await
            .expect("captured A timeout")
            .expect("captured A wire")
            > 0
    );
    for (inbound, port) in [(1, 81), (0, 80), (0, 81)] {
        let (control, reply) = socks_connect_port(listens[inbound], port).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (selected, _) = tokio::time::timeout(Duration::from_secs(2), upstreams[1].accept())
            .await
            .expect("selected B timeout")
            .expect("selected B");
        drop((control, selected));
    }
    drop((first, first_upstream));
    selector
        .switch("manual", "dead")
        .expect("switch to unavailable member");
    let (_, reply) = socks_connect_port(listens[0], 82).await;
    assert_ne!(reply[1], 0);
    assert_eq!(selector.selected("manual"), Ok("dead"));
    let fallback = tokio::join!(
        tokio::time::timeout(Duration::from_millis(50), upstreams[0].accept()),
        tokio::time::timeout(Duration::from_millis(50), upstreams[1].accept()),
    );
    assert!(fallback.0.is_err() && fallback.1.is_err());
    stop.send(()).expect("stop");
    assert_eq!(task.await.expect("client"), Ok(()));
    std::fs::remove_file(path).expect("remove config");
}
