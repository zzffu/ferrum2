#[path = "local_e2e_support/mod.rs"]
mod support;

use support::*;

#[test]
fn echo_worker_drop_joins_and_releases_listener() {
    let _spawn_guard = local_support::hold_process_spawns();
    let (address, worker) = start_echo();
    drop(worker);
    drop(TcpListener::bind(address).expect("dropped echo listener rebind"));
}

#[test]
fn direct_tcp_real_process_preserves_raw_bytes_and_half_close() {
    for form in ["static", "rule", "final", "selector"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let client_address = unused_loopback();
        let (target, echo) = start_echo();
        let fallback = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("fallback sentinel");
        fallback
            .set_nonblocking(true)
            .expect("nonblocking fallback sentinel");
        let fallback_address = fallback.local_addr().expect("fallback address");
        let root = match form {
            "static" => "outbound = \"exit\"\n".to_owned(),
            "rule" => format!(
                "[route]\nfinal = \"fallback\"\n[[route.rules]]\ninbound = \"m16-tag-sentinel\"\nnetwork = \"tcp\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"exit\"\n",
                target.ip(),
                target.port()
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
        let config = directory
            .path()
            .join(format!("m16-direct-{form}-client.toml"));
        std::fs::write(
            &config,
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"m16-tag-sentinel\"\nlisten = \"{client_address}\"\n{root}[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n{}",
                proxy.as_deref().unwrap_or_default(),
            ),
        )
        .expect("direct client config");
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);

        let (mut socks, reply) = socks_connect(client_address, target);
        assert_eq!(&reply[..2], &[5, 0], "{form}");
        socks.write_all(form.as_bytes()).expect("direct payload");
        socks.shutdown(Shutdown::Write).expect("direct half close");
        let mut response = Vec::new();
        socks.read_to_end(&mut response).expect("direct response");
        assert_eq!(response, form.as_bytes(), "{form}");
        assert_eq!(echo.join().expect("direct echo"), form.as_bytes(), "{form}");
        assert!(
            matches!(fallback.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "{form} selected the proxy fallback"
        );
        let exit = client.terminate_and_reap_with_exit(Duration::from_secs(5));
        exit.assert_stderr_excludes(&[
            "m16-tag-sentinel",
            &fallback_address.to_string(),
            "bTE2LXNlY3JldC1rZXkhIQ==",
            "m16-secret-key!!",
        ]);
    }

    let ipv6_loopback = TcpListener::bind("[::1]:0").is_ok_and(|listener| {
        TcpStream::connect(listener.local_addr().expect("IPv6 probe address")).is_ok()
    });
    if ipv6_loopback {
        let directory = tempfile::tempdir().expect("IPv6 temporary directory");
        let client_address = unused_loopback();
        let config = directory.path().join("m16-direct-ipv6-client.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"socks\"\nlisten = \"{client_address}\"\noutbound = \"exit\"\n[[outbounds]]\ntag = \"exit\"\ntype = \"direct\"\n"
            ),
        )
        .expect("IPv6 direct config");
        let (target, echo) = start_echo_at("[::1]:0".parse().expect("IPv6 bind"));
        let mut client = ChildGuard::spawn("ferrum2-client", &config);
        wait_for_listener(&mut client, client_address);
        let mut socks = TcpStream::connect(client_address).expect("IPv6 SOCKS client");
        socks
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("IPv6 SOCKS timeout");
        socks.write_all(&[5, 1, 0]).expect("IPv6 SOCKS greeting");
        let mut method = [0_u8; 2];
        socks.read_exact(&mut method).expect("IPv6 SOCKS method");
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(&address_wire(target));
        socks.write_all(&request).expect("IPv6 SOCKS request");
        let mut reply = [0_u8; 22];
        socks.read_exact(&mut reply).expect("IPv6 SOCKS reply");
        assert_eq!(&reply[..4], &[5, 0, 0, 4]);
        assert_eq!(&reply[4..20], &Ipv6Addr::LOCALHOST.octets());
        socks.write_all(b"ipv6-direct").expect("IPv6 payload");
        socks.shutdown(Shutdown::Write).expect("IPv6 half close");
        let mut response = Vec::new();
        socks.read_to_end(&mut response).expect("IPv6 response");
        assert_eq!(response, b"ipv6-direct");
        assert_eq!(echo.join().expect("IPv6 direct echo"), b"ipv6-direct");
    }
}

#[test]
fn success_bounded_method_matrix_preserves_bytes_and_half_close() {
    let ipv6_loopback = TcpListener::bind("[::1]:0").is_ok_and(|listener| {
        TcpStream::connect(listener.local_addr().expect("IPv6 probe address")).is_ok()
    });
    if !ipv6_loopback {
        eprintln!("SKIP real-process IPv6 row: host IPv6 loopback connect unavailable");
    }
    for (address_class, method) in TCP_METHOD_CONFIGS.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let server_address = unused_loopback();
        let client_address = unused_loopback();
        let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
            .expect("server config");
        let client_config =
            write_client_config(directory.path(), client_address, server_address, None)
                .expect("client config");
        rewrite_config_method(&server_config, method).expect("server method");
        rewrite_config_method(&client_config, method).expect("client method");
        let (target, echo) = match address_class {
            0 => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
            1 => {
                let (target, echo) = start_echo();
                let mut wire = b"\x03\x09127.0.0.1".to_vec();
                wire.extend_from_slice(&target.port().to_be_bytes());
                (wire, echo)
            }
            _ if ipv6_loopback => {
                let (target, echo) =
                    start_echo_at("[::1]:0".parse().expect("IPv6 loopback address"));
                (address_wire(target), echo)
            }
            _ => {
                let (target, echo) = start_echo();
                (address_wire(SocketAddr::V4(target)), echo)
            }
        };

        let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
        wait_for_listener(&mut server, server_address);
        let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
        wait_for_listener(&mut client, client_address);

        let (mut socks, reply) = socks_connect_wire(client_address, &target);
        assert_eq!(&reply[..4], &[5, 0, 0, 1], "{}", method.0);
        let first = method.0.as_bytes();
        let second = vec![0x5a; 16_385];
        socks.write_all(first).expect("first payload");
        socks.write_all(&second).expect("second payload");
        socks.shutdown(Shutdown::Write).expect("client half close");

        let mut echoed = Vec::new();
        socks.read_to_end(&mut echoed).expect("reverse drain");
        let mut expected = first.to_vec();
        expected.extend_from_slice(&second);
        assert_eq!(echoed, expected, "{}", method.0);
        assert_eq!(echo.join().expect("echo thread"), expected, "{}", method.0);
    }
}

#[test]
fn success_reply_uses_exact_opened_shadowsocks_socket_local_endpoint() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let (bridge_address, bridge_peer, bridge) = start_recording_bridge(server_address);
    let client_config = write_client_config(directory.path(), client_address, bridge_address, None)
        .expect("client config");
    let (echo_address, echo) = start_echo();

    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, echo_address);
    let opened_endpoint = bridge_peer
        .recv_timeout(Duration::from_secs(5))
        .expect("opened Shadowsocks endpoint");
    let mut expected = [0_u8; 6];
    expected[..4].copy_from_slice(&opened_endpoint.ip().octets());
    expected[4..].copy_from_slice(&opened_endpoint.port().to_be_bytes());
    assert_eq!(&reply[4..], &expected);

    socks.write_all(b"endpoint").expect("payload");
    socks.shutdown(Shutdown::Write).expect("client half close");
    let mut echoed = Vec::new();
    socks.read_to_end(&mut echoed).expect("reverse drain");
    assert_eq!(echoed, b"endpoint");
    assert_eq!(echo.join().expect("echo thread"), b"endpoint");
    bridge.join().expect("bridge thread");
}

#[test]
fn failures_unauthenticated_request_never_connects_target() {
    const DIFFERENT_SYNTHETIC_PSK: &str = "EBESExQVFhcYGRobHB0eHw==";

    let directory = tempfile::tempdir().expect("temporary directory");
    let target = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("recording target");
    target
        .set_nonblocking(true)
        .expect("nonblocking recording target");
    let target_address = match target.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config_with_psk(
        directory.path(),
        server_address,
        None,
        DIFFERENT_SYNTHETIC_PSK,
    )
    .expect("server config");
    let client_config = write_client_config_with_psk(
        directory.path(),
        client_address,
        server_address,
        None,
        local_support::SYNTHETIC_PSK,
    )
    .expect("client config");
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);

    let (mut socks, reply) = socks_connect(client_address, target_address);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected application byte count after authentication reject: {read}"),
    }
    match target.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("unauthenticated request connected to target"),
        Err(error) => panic!("recording target accept failed: {error}"),
    }
}

#[test]
fn failures_pre_success_connect_and_post_success_target_refusal() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let unavailable_server = unused_loopback();
    let client_address = unused_loopback();
    let client_config =
        write_client_config(directory.path(), client_address, unavailable_server, None)
            .expect("client config");
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (_socks, reply) = socks_connect(client_address, unused_loopback());
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(client);

    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let client_config = write_client_config(directory.path(), client_address, server_address, None)
        .expect("client config");
    let refused_target = unused_loopback();
    let mut server = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_listener(&mut server, server_address);
    let mut client = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_listener(&mut client, client_address);
    let (mut socks, reply) = socks_connect(client_address, refused_target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let mut tail = [0_u8; 1];
    match socks.read(&mut tail) {
        Ok(0) | Err(_) => {}
        Ok(read) => panic!("unexpected second SOCKS reply/application byte count: {read}"),
    }
}
