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
fn registry_exposes_exactly_seven_typed_metric_families() {
    let metrics = Metrics::new();
    metrics.connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    metrics.active_connections_inc(Role::Client, Inbound::Socks5);
    metrics.failure(Role::Server, Stage::Shadowsocks, Reason::Authentication);
    metrics.add_bytes(Role::Client, Direction::InboundToOutbound, 123);
    metrics.set_replay_entries(7);
    metrics.replay_rejection(Reason::Replay);
    metrics.forced_shutdown(Role::Server);

    let output = metrics.encode_text().expect("encode metrics");
    let help_names: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("# HELP "))
        .map(|line| line.split_once(' ').expect("help name").0)
        .collect();
    assert_eq!(
        help_names,
        [
            "ferrum2_tcp_bytes",
            "ferrum2_tcp_connections",
            "ferrum2_tcp_connections_active",
            "ferrum2_tcp_failures",
            "ferrum2_tcp_forced_shutdown",
            "ferrum2_tcp_replay_entries",
            "ferrum2_tcp_replay_rejections",
        ]
    );
    assert_eq!(help_names.len(), 7);

    let types: BTreeSet<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .collect();
    assert_eq!(
        types,
        BTreeSet::from([
            "ferrum2_tcp_bytes counter",
            "ferrum2_tcp_connections counter",
            "ferrum2_tcp_connections_active gauge",
            "ferrum2_tcp_failures counter",
            "ferrum2_tcp_forced_shutdown counter",
            "ferrum2_tcp_replay_entries gauge",
            "ferrum2_tcp_replay_rejections counter",
        ])
    );

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
