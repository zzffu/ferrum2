#[path = "socks_udp_support/mod.rs"]
mod support;

use support::*;

#[test]
fn datagram_echo_drop_joins_and_releases_socket() {
    let _spawn_guard = local_support::hold_process_spawns();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("drop-test echo socket");
    let address = socket.local_addr().expect("drop-test echo address");
    drop(echo_datagrams(socket, 2));
    drop(UdpSocket::bind(address).expect("dropped datagram echo rebind"));
}

#[test]
fn direct_udp_real_process_preserves_raw_datagrams_and_association_lifetime() {
    for form in ["static", "rule", "final", "selector"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let client_address = unused_tcp_udp_loopback();
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("direct echo");
        let echo_address = echo.local_addr().expect("direct echo address");
        let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("fallback sentinel");
        fallback
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("fallback timeout");
        let fallback_address = fallback.local_addr().expect("fallback address");
        let root = match form {
            "static" => "outbound = \"exit\"\n".to_owned(),
            "rule" => format!(
                "[route]\nfinal = \"fallback\"\n[[route.rules]]\nnetwork = \"udp\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"exit\"\n",
                echo_address.ip(),
                echo_address.port(),
            ),
            "final" => "[route]\nfinal = \"exit\"\n".to_owned(),
            "selector" => "outbound = \"manual\"\n[[selectors]]\ntag = \"manual\"\noutbounds = [\"exit\", \"fallback\"]\ndefault = \"exit\"\n".to_owned(),
            _ => unreachable!(),
        };
        let proxy = matches!(form, "rule" | "selector").then(|| {
            format!(
                "[[outbounds]]\ntag = \"fallback\"\ntype = \"shadowsocks\"\nserver = \"{fallback_address}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"bTE2LXNlY3JldC1rZXkhIQ==\"\n"
            )
        });
        let config = directory.path().join(format!("m16-direct-udp-{form}.toml"));
        std::fs::write(
            &config,
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"m16-tag-sentinel\"\nlisten = \"{client_address}\"\n{root}[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n{}[udp]\nenabled = true\nmax_sessions = 1\nmax_buffered_bytes = 1048576\n",
                proxy.as_deref().unwrap_or_default(),
            ),
        )
        .expect("direct UDP client config");
        let target = target_wire(echo_address);
        let domain = domain_target_wire("127.0.0.1", echo_address.port());
        let worker = echo_datagrams(echo, if form == "rule" { 2 } else { 3 });
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);

        let (control, application, relay) = udp_associate(client_address, false);
        let mut fragment = socks_datagram_for_target(&target, b"m16-packet-sentinel");
        fragment[2] = 1;
        application
            .send_to(&fragment, relay)
            .expect("fragment candidate");
        assert_no_datagram(&application);
        for payload in [form.as_bytes(), b"direct-two".as_slice()] {
            round_trip(&application, relay, &target, &target, payload);
        }
        if form != "rule" {
            round_trip(&application, relay, &domain, &target, b"direct-domain");
        }
        assert_no_datagram(&fallback);
        drop(control);
        worker.join().expect("direct echo worker");
        let exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
        exit.assert_stderr_excludes(&[
            "m16-tag-sentinel",
            "m16-packet-sentinel",
            &fallback_address.to_string(),
            "bTE2LXNlY3JldC1rZXkhIQ==",
            "m16-secret-key!!",
        ]);
    }
}
