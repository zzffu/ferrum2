use std::collections::BTreeSet;

use ferrum2_observability::{Direction, Inbound, Metrics, Outcome, Reason, Role, Stage};

fn series(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.rsplit_once(' ')
                .expect("sample and value")
                .0
                .to_owned()
        })
        .collect()
}

#[test]
fn registry_preserves_the_fourteen_stable_families_and_allows_additions() {
    let metrics = Metrics::new();
    metrics.connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    metrics.active_connections_inc(Role::Client, Inbound::Socks5);
    metrics.failure(Role::Server, Stage::Shadowsocks, Reason::Authentication);
    metrics.add_bytes(Role::Client, Direction::InboundToOutbound, 123);
    metrics.set_replay_entries(7);
    metrics.replay_rejection(Reason::Replay);
    metrics.forced_shutdown(Role::Server);
    metrics.udp_sessions_active_inc(Role::Server);
    metrics.udp_datagram(Role::Server, Direction::ClientToTarget, Outcome::Accepted);
    metrics.udp_failure(Role::Server, Stage::Direct, Reason::QueueFull);
    metrics.add_udp_bytes(Role::Server, Direction::TargetToClient, 321);
    metrics.set_udp_buffered_bytes(Role::Server, 65_507);
    metrics.udp_replay_rejection(Role::Server, Direction::ClientToTarget, Reason::Duplicate);
    metrics.udp_forced_shutdown(Role::Server);

    let output = metrics.encode_text().expect("encode metrics");
    let help: BTreeSet<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("# HELP "))
        .collect();
    let stable_help = BTreeSet::from([
        "ferrum2_tcp_bytes Authenticated application bytes forwarded.",
        "ferrum2_tcp_connections TCP connection outcomes.",
        "ferrum2_tcp_connections_active Active TCP connections.",
        "ferrum2_tcp_failures Closed TCP failure categories.",
        "ferrum2_tcp_forced_shutdown TCP flows terminated at shutdown deadline.",
        "ferrum2_tcp_replay_entries Current exact TCP replay entries.",
        "ferrum2_tcp_replay_rejections TCP replay-related rejections.",
        "ferrum2_udp_buffered_bytes Allocated user-space UDP bytes.",
        "ferrum2_udp_bytes Authenticated UDP application bytes forwarded.",
        "ferrum2_udp_datagrams UDP datagram outcomes.",
        "ferrum2_udp_failures Closed UDP failure categories.",
        "ferrum2_udp_forced_shutdown UDP sessions terminated at shutdown deadline.",
        "ferrum2_udp_replay_rejections UDP replay-related rejections.",
        "ferrum2_udp_sessions_active Active bounded UDP sessions.",
    ]);
    assert_eq!(stable_help.len(), 14);
    assert!(stable_help.is_subset(&help));

    let types: BTreeSet<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .collect();
    let stable_types = BTreeSet::from([
        "ferrum2_tcp_bytes counter",
        "ferrum2_tcp_connections counter",
        "ferrum2_tcp_connections_active gauge",
        "ferrum2_tcp_failures counter",
        "ferrum2_tcp_forced_shutdown counter",
        "ferrum2_tcp_replay_entries gauge",
        "ferrum2_tcp_replay_rejections counter",
        "ferrum2_udp_buffered_bytes gauge",
        "ferrum2_udp_bytes counter",
        "ferrum2_udp_datagrams counter",
        "ferrum2_udp_failures counter",
        "ferrum2_udp_forced_shutdown counter",
        "ferrum2_udp_replay_rejections counter",
        "ferrum2_udp_sessions_active gauge",
    ]);
    assert!(stable_types.is_subset(&types));

    let samples = series(&output);
    assert!(samples.contains(
        "ferrum2_tcp_connections_total{role=\"client\",inbound=\"socks5\",outcome=\"accepted\"}"
    ));
    assert!(samples.contains("ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"}"));
    assert!(samples.contains(
        "ferrum2_tcp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"}"
    ));
    assert!(
        samples
            .contains("ferrum2_tcp_bytes_total{role=\"client\",direction=\"inbound_to_outbound\"}")
    );
    assert!(samples.contains("ferrum2_tcp_replay_entries"));
    assert!(samples.contains("ferrum2_tcp_replay_rejections_total{reason=\"replay\"}"));
    assert!(samples.contains("ferrum2_tcp_forced_shutdown_total{role=\"server\"}"));
    assert!(samples.contains("ferrum2_udp_sessions_active{role=\"server\"}"));
    assert!(samples.contains(
        "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"}"
    ));
    assert!(samples.contains(
        "ferrum2_udp_failures_total{role=\"server\",stage=\"direct\",reason=\"queue_full\"}"
    ));
    assert!(
        samples.contains("ferrum2_udp_bytes_total{role=\"server\",direction=\"target_to_client\"}")
    );
    assert!(samples.contains("ferrum2_udp_buffered_bytes{role=\"server\"}"));
    assert!(samples.contains(
        "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"}"
    ));
    assert!(samples.contains("ferrum2_udp_forced_shutdown_total{role=\"server\"}"));
    assert!(output.ends_with("# EOF\n"));
}

#[test]
fn text_encoding_is_deterministic_across_insertion_orders() {
    let first = Metrics::new();
    first.connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    first.connection(Role::Server, Inbound::Shadowsocks, Outcome::Failed);
    first.failure(Role::Server, Stage::Direct, Reason::ConnectionRefused);
    first.failure(Role::Client, Stage::Relay, Reason::RelayIo);

    let second = Metrics::new();
    second.failure(Role::Client, Stage::Relay, Reason::RelayIo);
    second.failure(Role::Server, Stage::Direct, Reason::ConnectionRefused);
    second.connection(Role::Server, Inbound::Shadowsocks, Outcome::Failed);
    second.connection(Role::Client, Inbound::Socks5, Outcome::Accepted);

    assert_eq!(
        first.encode_text().expect("first encoding"),
        second.encode_text().expect("second encoding")
    );
}

#[test]
fn one_thousand_destinations_cannot_change_metric_series_identity() {
    let one = Metrics::new();
    one.failure(Role::Server, Stage::Direct, Reason::ConnectionRefused);
    let one_series = series(&one.encode_text().expect("single destination"));

    let many = Metrics::new();
    let destinations: Vec<_> = (0..1_000)
        .map(|index| format!("192.0.2.{}:{}", index % 255, 10_000 + index))
        .collect();
    for _destination in &destinations {
        many.failure(Role::Server, Stage::Direct, Reason::ConnectionRefused);
    }
    let output = many.encode_text().expect("many destinations");
    assert_eq!(series(&output), one_series);
    assert_eq!(series(&output).len(), 2);
    for destination in destinations {
        assert!(!output.contains(&destination));
    }
    assert!(!output.contains("destination="));
    assert!(!output.contains("error="));
}

#[test]
fn udp_secret_and_identity_sentinels_cannot_change_series_identity() {
    const SENTINELS: &[&str] = &[
        "2022-blake3-aes-128-gcm",
        "M2_PSK_SENTINEL",
        "M2_KEY_SENTINEL",
        "M2_NONCE_SENTINEL",
        "M2_SESSION_SENTINEL",
        "M2_PACKET_SENTINEL",
        "198.51.100.21:61000",
        "198.51.100.22:62000",
        "192.0.2.31:65000",
        "example.invalid:53",
        "M2_FREE_TEXT_SENTINEL",
    ];
    let metrics = Metrics::new();
    for _sentinel in SENTINELS {
        metrics.udp_failure(Role::Server, Stage::Shadowsocks, Reason::Authentication);
    }
    let output = metrics.encode_text().expect("UDP metrics");
    assert_eq!(
        series(&output)
            .into_iter()
            .filter(|sample| sample.starts_with("ferrum2_udp_failures"))
            .collect::<Vec<_>>(),
        [
            "ferrum2_udp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"}"
        ]
    );
    for sentinel in SENTINELS {
        assert!(!output.contains(sentinel));
    }
}
