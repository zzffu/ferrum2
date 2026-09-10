use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ConnectionMetadata, ConnectionTarget, Dashboard, DecisionMetadata, Direction, HISTORY_LIMIT,
    HISTORY_TTL, LIVE_LIMIT, LOG_LIMIT, ObservedIo, SniffMetadata, lock,
};

fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        protocol: "tcp",
        inbound: "socks5",
        inbound_id: Some(0),
        source: Some("127.0.0.1:2000".parse().unwrap()),
        target: Some(ConnectionTarget::Domain {
            name: "example.test".into(),
            port: 443,
        }),
    }
}

fn decision(rule_index: Option<usize>) -> DecisionMetadata {
    DecisionMetadata {
        kind: crate::wire::ConnectionDecisionKind::Route,
        rule_index,
        rule_generation: Some(9),
        sniff: SniffMetadata {
            status: crate::wire::ConnectionSniffStatus::Matched,
            protocol: Some(crate::wire::ConnectionSniffProtocol::Tls),
            domain: None,
            rule_index: Some(0),
        },
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
    old.set_decision(decision(Some(0)), &[1, 0]);
    let initial = dashboard.snapshot();
    let selected = initial["connections"][0].clone();
    assert_eq!(selected["decision"]["hops"], json!([1, 0]));
    let captured_catalog = initial["connection_catalogs"][0].clone();
    assert_eq!(
        captured_catalog["rules"][0]["conditions"],
        json!([
            {"field": "port", "value": [443]},
            {"field": "domain_suffix", "value": ["old.test"]}
        ])
    );
    assert_eq!(captured_catalog["rules"][0]["outbound"], "manual");
    old.finish("completed");
    let current = dashboard.begin(metadata());
    current.set_decision(decision(None), &[0]);
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["history"][0]["decision"], selected["decision"]);
    assert_eq!(snapshot["history"][0]["catalog_id"], selected["catalog_id"]);
    assert_ne!(
        snapshot["connections"][0]["catalog_id"],
        selected["catalog_id"]
    );
    assert_eq!(snapshot["connection_catalogs"].as_array().unwrap().len(), 2);
    assert!(
        snapshot["connection_catalogs"]
            .as_array()
            .unwrap()
            .contains(&captured_catalog)
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
    connection.set_decision(decision(Some(0)), &[0, 99]);
    let snapshot = dashboard.snapshot();
    let row = &snapshot["connections"][0];
    assert!(row["source"].is_null());
    assert!(row["target"].is_null());
    assert!(row["requested_domain"].is_null());
    assert!(row["decision"]["rule_index"].is_null());
    assert_eq!(row["decision"]["hops"], json!([0, 99]));
    assert_eq!(
        row["decision"]["sniff"],
        json!({
            "status": "redacted", "protocol": null, "domain": null, "rule_index": null
        })
    );
    assert_eq!(snapshot["connection_catalogs"][0]["rules"], json!([]));
    assert_eq!(
        snapshot["connection_catalogs"][0]["outbounds"],
        json!([{"index":0, "tag":"direct"}])
    );
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
    connections[0].set_target(Some(ConnectionTarget::Domain {
        name: "private.test".into(),
        port: 443,
    }));
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

#[test]
fn matched_without_domain_and_finished_evidence_are_preserved() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    connection.set_decision(decision(Some(2)), &[0]);
    connection.upload(13);
    connection.download(21);
    connection.finish("completed");
    let sealed = dashboard.snapshot()["history"][0].clone();
    assert_eq!(
        sealed["decision"]["sniff"],
        json!({
            "status": "matched", "protocol": "tls", "domain": null, "rule_index": 0
        })
    );
    assert_eq!(sealed["upload_bytes"], "13");
    assert_eq!(sealed["download_bytes"], "21");
    connection.set_target(None);
    connection.set_decision(decision(None), &[1]);
    connection.upload(100);
    connection.download(100);
    dashboard.sample();
    assert_eq!(dashboard.snapshot()["history"][0], sealed);
    let encoded: serde_json::Value = serde_json::from_slice(&dashboard.encode_snapshot()).unwrap();
    assert_eq!(encoded["history"][0], sealed);
}

#[test]
fn sampling_and_finish_never_duplicate_or_rewrite_a_row() {
    let dashboard = Dashboard::new(true);
    let connections: Vec<_> = (0..64).map(|_| dashboard.begin(metadata())).collect();
    for connection in &connections {
        connection.upload(7);
        connection.download(11);
    }
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            for connection in &connections {
                connection.finish("completed");
            }
        });
        barrier.wait();
        for _ in 0..64 {
            dashboard.sample();
            let snapshot = dashboard.snapshot();
            let mut ids = std::collections::BTreeSet::new();
            for row in snapshot["connections"]
                .as_array()
                .unwrap()
                .iter()
                .chain(snapshot["history"].as_array().unwrap())
            {
                assert!(ids.insert(row["id"].as_str().unwrap()));
                assert_eq!(row["upload_bytes"], "7");
                assert_eq!(row["download_bytes"], "11");
            }
            assert_eq!(ids.len(), connections.len());
        }
    });
    let snapshot = dashboard.snapshot();
    assert!(snapshot["connections"].as_array().unwrap().is_empty());
    assert_eq!(
        snapshot["history"].as_array().unwrap().len(),
        connections.len()
    );
    assert_eq!(
        snapshot["traffic"]["upload_bytes"],
        (7 * connections.len()).to_string()
    );
}

#[test]
fn catalog_is_emitted_once_and_only_while_referenced() {
    let dashboard = Dashboard::new(true);
    dashboard.set_connection_catalog(json!({
        "inbounds": [{"tag": "local"}],
        "outbounds": [{"tag": "direct"}],
        "route": {"rules": [{
            "origin": "inbound", "inbound": ["local"], "action": "route", "outbound": "direct",
            "password": "not-an-allowed-condition"
        }]}
    }));
    let first = dashboard.begin(metadata());
    let second = dashboard.begin(metadata());
    first.set_decision(decision(Some(0)), &[0]);
    first.finish("completed");
    let snapshot = dashboard.snapshot();
    assert_eq!(snapshot["connection_catalogs"].as_array().unwrap().len(), 1);
    assert_eq!(
        snapshot["connections"][0]["catalog_id"],
        snapshot["history"][0]["catalog_id"]
    );
    assert_eq!(snapshot["connections"][0]["inbound_tag"], "local");
    assert_eq!(
        snapshot["connection_catalogs"][0]["rules"][0],
        json!({
            "index": 0, "origin": "inbound", "action": "route", "outbound": "direct",
            "conditions": [{"field": "inbound", "value": ["local"]}], "sniffers": []
        })
    );
    second.finish("completed");
    let generation = lock(&dashboard.0.state).generation.clone();
    for (at, _) in &mut lock(&generation.registry).history {
        *at = Instant::now() - HISTORY_TTL - Duration::from_secs(1);
    }
    assert_eq!(dashboard.snapshot()["connection_catalogs"], json!([]));
}

#[test]
fn oversized_evidence_is_dropped_without_affecting_traffic() {
    let dashboard = Dashboard::new(true);
    let connection = dashboard.begin(metadata());
    connection.set_decision(decision(None), &[0; 9]);
    connection.upload(23);
    let snapshot = dashboard.snapshot();
    assert!(snapshot["connections"][0]["decision"].is_null());
    assert_eq!(snapshot["traffic"]["upload_bytes"], "23");
}
