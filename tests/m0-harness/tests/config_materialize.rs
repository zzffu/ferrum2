#[path = "config_cli_support/mod.rs"]
mod support;

use support::*;

#[test]
fn materialized_check_is_opt_in_role_stable_and_reaps_before_returning() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_listener, client_listen) = reserve_loopback();
    let (server_listener, server_udp, server_listen) = reserve_server_tcp_udp();
    let client_cache = directory
        .path()
        .join("client-ruleset-cache")
        .to_string_lossy()
        .replace('\\', "/");
    let server_cache = directory
        .path()
        .join("server-ruleset-cache")
        .to_string_lossy()
        .replace('\\', "/");
    let client_path = directory.path().join("materialized-client.toml");
    let client_source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{client_listen}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://localhost:9/ads.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{client_cache}"
download_timeout_ms = 250
max_redirects = 0
"#
    );
    std::fs::write(&client_path, &client_source).expect("materialized client config");
    let server_path = directory.path().join("materialized-server.toml");
    let server_source = format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{server_listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://localhost:9/ads.srs"
download_resolver = "system"
download_detour = "direct"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{server_cache}"
download_timeout_ms = 250
max_redirects = 0

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
    );
    std::fs::write(&server_path, &server_source).expect("materialized server config");

    assert!(!directory.path().join("client-ruleset-cache").exists());
    assert!(!directory.path().join("server-ruleset-cache").exists());
    assert_materialized_check_failure(
        "ferrum2-client",
        &client_path,
        &directory.path().join("client-ruleset-cache"),
        1,
        b"error[ruleset.download] materialization: RuleSet download failed\n",
    );
    assert_materialized_check_failure(
        "ferrum2-server",
        &server_path,
        &directory.path().join("server-ruleset-cache"),
        2,
        b"error[ruleset.download] materialization: RuleSet download failed\n",
    );
    assert_listener_is_undisturbed(&client_listener, "client materialized validation");
    assert_listener_is_undisturbed(&server_listener, "server materialized validation");
    assert_eq!(
        server_udp.local_addr().expect("occupied server UDP"),
        std::net::SocketAddr::V4(server_listen),
        "server materialized validation disturbed the occupied UDP endpoint"
    );

    // Removing and recreating both cache roots after repeated failures is the
    // filesystem-visible proof that no downloader/cache owner retained a handle.
    for cache in [
        directory.path().join("client-ruleset-cache"),
        directory.path().join("server-ruleset-cache"),
    ] {
        if cache.exists() {
            std::fs::remove_dir_all(&cache).expect("remove materialization cache");
        }
        std::fs::create_dir(&cache).expect("recreate materialization cache");
        std::fs::remove_dir(&cache).expect("release materialization cache");
    }

    let local_client = directory.path().join("local-materialized-client.toml");
    std::fs::write(
        &local_client,
        format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{client_listen}\"\n[[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n[route]\nfinal = \"direct\"\n"
        ),
    )
    .expect("local materialized client config");
    let local_server = directory.path().join("local-materialized-server.toml");
    std::fs::write(
        &local_server,
        format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{server_listen}\"\n[[outbounds]]\ntag = \"direct\"\n[route]\nfinal = \"direct\"\n[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
        ),
    )
    .expect("local materialized server config");
    assert_materialized_check_success("ferrum2-client", &local_client);
    assert_materialized_check_success("ferrum2-server", &local_server);
    assert_listener_is_undisturbed(&client_listener, "successful client materialization");
    assert_listener_is_undisturbed(&server_listener, "successful server materialization");
    assert_eq!(
        server_udp.local_addr().expect("occupied server UDP"),
        std::net::SocketAddr::V4(server_listen),
        "successful server materialization disturbed the occupied UDP endpoint"
    );

    let baseline = write_client_config(directory.path(), client_listen, unused_loopback(), None)
        .expect("materialized-check config");
    assert_materialized_check_success("ferrum2-client", &baseline);
}

#[test]
fn no_side_effects_even_when_all_configured_ports_are_occupied() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client_listener, client_address) = reserve_loopback();
    let (server_listener, server_udp, server_address) = reserve_server_tcp_udp();
    let (client_metrics, client_metrics_address) = reserve_loopback();
    let (server_metrics, server_metrics_address) = reserve_loopback();
    let (dns_listener, dns_udp, dns_address) = reserve_server_tcp_udp();
    let client = write_udp_client_config(
        directory.path(),
        client_address,
        server_address,
        Some(client_metrics_address),
    )
    .expect("client config");
    let client_source = std::fs::read_to_string(&client).expect("client source");
    std::fs::write(
        &client,
        format!(
            "{client_source}\n[dns]\n[[dns.inbounds]]\ntag = \"local-dns\"\nlisten = \"{dns_address}\"\n[[dns.servers]]\ntag = \"direct\"\ntransport = \"udp\"\naddress = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"direct\"\n"
        ),
    )
    .expect("client DNS config");
    let server = write_server_config(
        directory.path(),
        server_address,
        Some(server_metrics_address),
    )
    .expect("server config");

    for (binary, config) in [("ferrum2-client", client), ("ferrum2-server", server)] {
        let output = run_binary(
            binary,
            &[
                "--config",
                config.to_str().expect("UTF-8 path"),
                "--check-config",
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{binary}");
        assert_eq!(output.stdout, b"configuration valid\n", "{binary}");
        assert!(output.stderr.is_empty(), "{binary}");
    }

    for listener in [
        client_listener,
        server_listener,
        client_metrics,
        server_metrics,
        dns_listener,
    ] {
        let address = listener.local_addr().expect("listener address");
        assert!(
            TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1)).is_ok(),
            "pre-existing listener was disturbed"
        );
    }
    assert_eq!(
        server_udp.local_addr().expect("UDP address"),
        std::net::SocketAddr::V4(server_address)
    );
    assert_eq!(
        dns_udp.local_addr().expect("DNS UDP address"),
        std::net::SocketAddr::V4(dns_address)
    );
}
