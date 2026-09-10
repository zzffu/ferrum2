use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ConnectionMetadata, Dashboard, Direction, HISTORY_LIMIT, HISTORY_TTL, LIVE_LIMIT, LOG_LIMIT,
    ObservedIo, lock,
};

fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        protocol: "tcp",
        inbound: "socks5",
        source: Some("127.0.0.1:2000".into()),
        target: Some("example.test:443".into()),
    }
}

#[tokio::test]
async fn cancellation_is_sticky_broadcast_and_not_retirement() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    let clone = connection.clone();
    let id = connection.id();
    assert_eq!(dashboard.close_connections(&[id.clone(), id.clone()]), 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(connection.cancelled(), clone.cancelled());
    })
    .await
    .unwrap();
    assert_eq!(dashboard.close_connections(&[id]), 0);
    assert_eq!(
        dashboard.snapshot()["connections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    connection.finish("cancelled");
    assert!(
        dashboard.snapshot()["connections"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(dashboard.snapshot()["history"][0]["state"], "cancelled");
}

#[test]
fn final_owner_retires_once_and_explicit_finish_wins() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    let clone = connection.clone();
    connection.upload(13);
    drop(connection);
    assert_eq!(
        dashboard.snapshot()["connections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    clone.finish("failed");
    clone.finish("closed");
    clone.upload(100);
    drop(clone);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["history"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["history"][0]["state"], "failed");
    assert_eq!(snapshot["history"][0]["upload_bytes"], "13");
    let automatic = dashboard.begin(metadata());
    let automatic_id = automatic.id();
    drop(automatic);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["history"][1]["id"], automatic_id);
    assert_eq!(snapshot["history"][1]["state"], "closed");
}

#[test]
fn old_leases_cannot_change_replacement_observations() {
    let dashboard = Dashboard::new(true);
    dashboard.start_generation(7);
    let old = dashboard.begin(metadata());
    old.upload(50);
    dashboard.start_generation(8);
    let current = dashboard.begin(metadata());
    old.upload(100);
    old.download(70);
    assert_eq!(dashboard.close_connections(&[old.id()]), 0);
    old.finish("closed");
    current.download(3);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["generation"], "8");
    assert_eq!(snapshot["traffic"]["upload_bytes"], "0");
    assert_eq!(snapshot["traffic"]["download_bytes"], "3");
    assert!(snapshot["history"].as_array().unwrap().is_empty());
    assert_eq!(snapshot["connections"][0]["id"], current.id());
}

#[test]
fn selected_paths_and_closed_history_keep_the_admitted_catalog() {
    let dashboard = Dashboard::new(true);
    dashboard.set_connection_catalog(json!({
        "outbounds": [{"tag": "first"}, {"tag": "second"}],
        "selectors": [{"tag": "manual", "default": "second"}],
        "route": {"final": "manual", "rules": [
            {"domain_suffix": ["old.test"], "port": [443], "action": "route", "outbound": "manual"}
        ]}
    }));
    let old = dashboard.begin(metadata());
    dashboard.set_connection_catalog(json!({
        "outbounds": [{"tag": "replacement"}],
        "route": {"final": "replacement", "rules": []}
    }));
    // Selection can finish after catalog publication; only the captured hop order matters.
    old.set_selected_route(Some(0), &[1, 0]);
    let selected = dashboard.snapshot()["connections"][0].clone();
    assert_eq!(selected["outbound"], "second → first");
    let rule = selected["route"].as_str().unwrap();
    assert!(rule.contains("domain_suffix=[\"old.test\"]"));
    assert!(rule.contains("port=[443]"));
    assert!(rule.contains("action=route"));
    assert!(rule.contains("outbound=\"manual\""));
    old.finish("completed");
    let current = dashboard.begin(metadata());
    current.set_selected_route(None, &[0]);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["history"][0]["route"], selected["route"]);
    assert_eq!(snapshot["history"][0]["outbound"], selected["outbound"]);
    assert_eq!(snapshot["connections"][0]["outbound"], "replacement");
    assert!(
        snapshot["connections"][0]["route"]
            .as_str()
            .unwrap()
            .contains("route.final")
    );
}

#[test]
fn private_conditions_and_unknown_hops_are_not_invented() {
    let dashboard = Dashboard::new(false);
    dashboard.set_connection_catalog(json!({
        "outbounds": [{"tag": "direct"}],
        "route": {"final": "direct", "rules": [
            {"domain": "private.test", "action": "reject"}
        ]}
    }));
    let connection = dashboard.begin(metadata());
    connection.set_selected_route(Some(0), &[0]);
    let snapshot = dashboard.snapshot();
    assert!(snapshot["connections"][0]["route"].is_null());
    assert_eq!(snapshot["connections"][0]["outbound"], "direct");
    connection.set_selected_route(None, &[0, 99]);
    assert!(dashboard.snapshot()["connections"][0]["outbound"].is_null());
    connection.set_tun_dns_route();
    let snapshot = dashboard.snapshot();
    assert!(snapshot["connections"][0]["route"].is_null());
    assert_eq!(snapshot["connections"][0]["outbound"], "DNS 接管");
}

#[test]
fn saturation_counts_bytes_and_retention_remains_bounded() {
    let dashboard = Dashboard::new(false);
    let connections: Vec<_> = (0..LIVE_LIMIT)
        .map(|_| dashboard.begin(metadata()))
        .collect();
    let omitted = dashboard.begin(metadata());
    omitted.upload(41);
    omitted.download(17);
    connections[0].set_target(Some("private.test:443".into()));
    let snapshot = dashboard.snapshot();
    assert_eq!(
        snapshot["connections"].as_array().unwrap().len(),
        LIVE_LIMIT
    );
    assert_eq!(snapshot["omitted_connections"], 1);
    assert_eq!(snapshot["traffic"]["upload_bytes"], "41");
    assert_eq!(snapshot["traffic"]["download_bytes"], "17");
    for entry in snapshot["connections"].as_array().unwrap() {
        assert!(entry["source"].is_null());
        assert!(entry["target"].is_null());
    }
    drop(omitted);
    assert_eq!(dashboard.snapshot()["omitted_connections"], 0);
    drop(connections);
    for index in 0..LOG_LIMIT + 10 {
        dashboard.record_log(json!({"level": "INFO", "index": index}));
    }
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["history"].as_array().unwrap().len(), HISTORY_LIMIT);
    assert_eq!(snapshot["logs"].as_array().unwrap().len(), LOG_LIMIT);
    assert_eq!(snapshot["logs"][0]["event"]["index"], 10);
    // Advance retention timestamps instead of sleeping for the production TTL.
    let generation = lock(&dashboard.0.state).generation.clone();
    for (at, _) in &mut lock(&generation.registry).history {
        *at = Instant::now() - HISTORY_TTL - Duration::from_secs(1);
    }
    dashboard.sample();
    assert!(
        dashboard.snapshot()["history"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn write_counting_preserves_bidirectional_half_close() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    let (inner, mut peer) = tokio::io::duplex(32);
    let mut observed = ObservedIo::new(inner, connection.clone(), Direction::Upload);
    observed.write_all(b"outbound").await.unwrap();
    observed.flush().await.unwrap();
    observed.shutdown().await.unwrap();
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await.unwrap();
    assert_eq!(written, b"outbound");
    assert_eq!(dashboard.snapshot()["traffic"]["upload_bytes"], "8");
    peer.write_all(b"response").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut received = Vec::new();
    observed.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"response");
    assert_eq!(dashboard.snapshot()["traffic"]["upload_bytes"], "8");
    assert_eq!(dashboard.snapshot()["traffic"]["download_bytes"], "0");
    let (inner, mut peer) = tokio::io::duplex(32);
    let mut download = ObservedIo::new(inner, connection, Direction::Download);
    let slices = [std::io::IoSlice::new(b"bo"), std::io::IoSlice::new(b"dy")];
    let count = download.write_vectored(&slices).await.unwrap();
    assert_eq!(
        dashboard.snapshot()["traffic"]["download_bytes"],
        count.to_string()
    );
    download.write_all(&b"body"[count..]).await.unwrap();
    download.shutdown().await.unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"body");
    assert_eq!(dashboard.snapshot()["traffic"]["download_bytes"], "4");
}

#[test]
fn browser_reads_do_not_resample_traffic_rates() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    connection.upload(100);
    lock(&dashboard.0.state).sampled = Instant::now() - Duration::from_secs(1);
    dashboard.sample();
    let rate = dashboard.snapshot()["traffic"]["upload_rate"].clone();
    assert!(rate.as_f64().unwrap() > 0.0);
    connection.upload(500);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["traffic"]["upload_rate"], rate);
    assert_eq!(snapshot["traffic"]["upload_bytes"], "600");
}

#[tokio::test]
async fn close_all_reaches_unindexed_leases_but_not_later_arrivals() {
    let dashboard = Dashboard::new(false);
    let connections: Vec<_> = (0..crate::CANCELLATION_LIMIT + 1)
        .map(|_| dashboard.begin(metadata()))
        .collect();
    let hidden = &connections[LIVE_LIMIT];
    assert_eq!(dashboard.close_connections(&[hidden.id()]), 1);
    let unindexed = connections.last().unwrap();
    assert_eq!(dashboard.close_connections(&[unindexed.id()]), 0);
    assert_eq!(dashboard.close_all_connections(), connections.len());
    let later = dashboard.begin(metadata());
    tokio::time::timeout(Duration::from_secs(1), unindexed.cancelled())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), later.cancelled())
            .await
            .is_err()
    );
    drop(connections);
    assert_eq!(dashboard.close_all_connections(), 1);
    tokio::time::timeout(Duration::from_secs(1), later.cancelled())
        .await
        .unwrap();
    drop(later);
    assert_eq!(dashboard.close_all_connections(), 0);
}

#[tokio::test]
async fn failed_and_pending_writes_never_inflate_totals() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    let (inner, peer) = tokio::io::duplex(1);
    let mut observed = ObservedIo::new(inner, connection, Direction::Upload);
    observed.write_all(b"x").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), observed.write_all(b"y"))
            .await
            .is_err()
    );
    assert_eq!(dashboard.snapshot()["traffic"]["upload_bytes"], "1");
    drop(peer);
    assert!(observed.write_all(b"z").await.is_err());
    assert_eq!(dashboard.snapshot()["traffic"]["upload_bytes"], "1");
}
