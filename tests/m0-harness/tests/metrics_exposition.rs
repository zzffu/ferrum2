#[path = "../src/local_support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use support::{
    ChildGuard, active_child_count, hold_process_spawns, unused_loopback, wait_for_metrics,
    write_client_config, write_server_config,
};

#[test]
fn client_and_server_publish_unique_metric_metadata() {
    let _spawns = hold_process_spawns();
    let baseline = active_child_count();
    let directory = tempfile::tempdir().expect("isolated config directory");
    let client_metrics = unused_loopback();
    let server_metrics = unused_loopback();
    let client = write_client_config(
        directory.path(),
        unused_loopback(),
        unused_loopback(),
        Some(client_metrics),
    )
    .expect("loopback-only client configuration");
    let server = write_server_config(directory.path(), unused_loopback(), Some(server_metrics))
        .expect("loopback-only server configuration");
    for (binary, config, metrics) in [
        ("ferrum2-client", client, client_metrics),
        ("ferrum2-server", server, server_metrics),
    ] {
        let mut child = ChildGuard::spawn_while_holding(binary, &config, &_spawns);
        let text = String::from_utf8(wait_for_metrics(metrics)).expect("metrics UTF-8");
        child.terminate_and_reap(Duration::from_secs(5));
        assert_eq!(active_child_count(), baseline);

        let mut metadata = BTreeSet::new();
        let mut duplicates = BTreeSet::new();
        for line in text.lines() {
            let mut words = line.split_ascii_whitespace();
            if words.next() != Some("#") {
                continue;
            }
            let Some(kind @ ("HELP" | "TYPE")) = words.next() else {
                continue;
            };
            let name = words.next().expect("metric metadata name");
            if !metadata.insert((kind, name)) {
                duplicates.insert((kind, name));
            }
        }
        assert_eq!(duplicates, BTreeSet::new(), "{binary} duplicate metadata");
        assert_eq!(text.lines().filter(|line| *line == "# EOF").count(), 1);
        assert!(text.ends_with("# EOF\n"));
        if binary == "ferrum2-client" {
            assert!(metadata.contains(&("TYPE", "ferrum2_tun_tcp_flows_active")));
            assert!(metadata.contains(&("TYPE", "ferrum2_tun_tcp_flow_owners_active")));
        }
    }
}
