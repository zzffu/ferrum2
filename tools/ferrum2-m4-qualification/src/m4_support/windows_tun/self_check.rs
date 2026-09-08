use super::contract::{AddressFamily, parse, validate_reset_release};
use super::socket_io::{
    FRAGMENT, IO_LIMIT, bind_udp, connect, datagram, exchange, listen, payload, runtime, udp,
    udp_ack,
};
use std::ffi::OsString;

pub(crate) fn run_self_check() -> Result<(), String> {
    let valid = [
        "--target-ip",
        "198.18.0.1",
        "--tcp-port",
        "32001",
        "--udp-port",
        "32002",
    ]
    .map(OsString::from)
    .to_vec();
    parse(&valid, "probe")?;
    for (flag, value) in [
        ("--target-ip", "198.18.0.2"),
        ("--scenario", "tcp-single"),
        ("--warmup-seconds", "1"),
        ("--diagnostic-ledger", "retired"),
    ] {
        let mut invalid = valid.clone();
        invalid.extend([OsString::from(flag), OsString::from(value)]);
        if parse(&invalid, "probe").is_ok() {
            return Err(format!(
                "qualification accepted duplicate or retired option {flag}"
            ));
        }
    }
    for ip in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "hostname"] {
        let mut invalid = valid.clone();
        invalid[1] = OsString::from(ip);
        if parse(&invalid, "probe").is_ok() {
            return Err("qualification accepted invalid target".into());
        }
    }
    for mode in ["support", "probe", "qualification"] {
        let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mut args = valid.clone();
        if mode == "support" {
            args[0] = OsString::from("--listen-ip");
        }
        if mode == "qualification" {
            args.extend([
                OsString::from("--output"),
                directory.path().join("witness.json").into_os_string(),
            ]);
        }
        for (family, ip, accepted) in [
            ("IPv4", "198.18.0.1", true),
            ("IPv6", "fd00:1234::1", true),
            ("IPv6", "198.18.0.1", false),
            ("IPv4", "fd00:1234::1", false),
            ("IPv6", "::ffff:198.18.0.1", false),
            ("ipv6", "fd00:1234::1", false),
            ("IPv5", "198.18.0.1", false),
        ] {
            let mut selected = args.clone();
            selected[1] = OsString::from(ip);
            selected.extend([OsString::from("--address-family"), OsString::from(family)]);
            if parse(&selected, mode).is_ok() != accepted {
                return Err(format!(
                    "{mode} address-family acceptance mismatch for {family}/{ip}"
                ));
            }
            selected.extend([OsString::from("--address-family"), OsString::from(family)]);
            if parse(&selected, mode).is_ok() {
                return Err(format!("{mode} accepted duplicate address family"));
            }
        }
        args[1] = OsString::from("fd00:1234::1");
        if parse(&args, mode).is_ok() {
            return Err(format!("{mode} accepted IPv6 with the default IPv4 family"));
        }
    }
    for ip in ["::1", "::", "ff02::1"] {
        let mut invalid = valid.clone();
        invalid[1] = OsString::from(ip);
        invalid.extend([OsString::from("--address-family"), OsString::from("IPv6")]);
        if parse(&invalid, "probe").is_ok() {
            return Err("qualification accepted invalid IPv6 target".into());
        }
    }
    for family in [AddressFamily::IPv4, AddressFamily::IPv6] {
        let release = serde_json::json!({
            "schema_version":1, "kind":"ferrum2.windows-tun-reset-release",
            "address_family":family, "generation":2
        });
        validate_reset_release(&release, family)?;
        for (field, value) in [
            (
                "address_family",
                serde_json::json!(if family == AddressFamily::IPv4 {
                    "IPv6"
                } else {
                    "IPv4"
                }),
            ),
            ("address_family", serde_json::json!("ipv6")),
            ("generation", serde_json::json!(1)),
            ("schema_version", serde_json::json!(2)),
            ("extra", serde_json::json!(true)),
        ] {
            let mut invalid = release.clone();
            invalid[field] = value;
            if validate_reset_release(&invalid, family).is_ok() {
                return Err(format!("reset release accepted invalid {field}"));
            }
        }
        let mut missing = release;
        missing
            .as_object_mut()
            .ok_or("reset marker is not an object")?
            .remove("address_family");
        if validate_reset_release(&missing, family).is_ok() {
            return Err("reset release accepted missing family".into());
        }
    }
    if payload(4096, 1, 0, 1) == payload(4096, 2, 0, 1)
        || payload(4096, 1, 0, 1) == payload(4096, 1, 1, 1)
        || payload(4096, 1, 0, 1) == payload(4096, 1, 0, 2)
    {
        return Err("qualification payload identities overlap".into());
    }
    let mut request = payload(4096, 1, 2, 3);
    let reply = super::socket_io::udp_ack(&request)?;
    if reply != *b"F2QA\0\0\x10\0\x01\x02\x03" {
        return Err("UDP acknowledgement does not bind request length and identity".into());
    }
    request[4095] ^= 1;
    if super::socket_io::udp_ack(&request).is_ok() {
        return Err("UDP acknowledgement accepted a corrupt request tail".into());
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| e.to_string())?;
        if ferrum2_platform_windows::enable_ipv6_udp_fragmentation(&socket).is_ok() {
            return Err("IPv6 fragmentation helper accepted an IPv4 socket".into());
        }
    }
    runtime()?.block_on(async {
        for ip in [
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ] {
            tokio::time::timeout(IO_LIMIT, loopback_socket_check(ip))
                .await
                .map_err(|_| "loopback socket self-check deadline")??;
        }
        Ok::<_, String>(())
    })?;
    Ok(())
}

// Unprivileged socket checks are separate from qualification: no route-reset or
// fragment-counter claims are inferred from traffic over a loopback interface.
async fn loopback_socket_check(ip: std::net::IpAddr) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tcp = listen(std::net::SocketAddr::new(ip, 0))?;
    let server_udp = bind_udp(std::net::SocketAddr::new(ip, 0))?;
    let tcp_address = tcp.local_addr().map_err(|e| e.to_string())?;
    let udp_address = server_udp.local_addr().map_err(|e| e.to_string())?;
    if ip.is_ipv6()
        && (!socket2::SockRef::from(&tcp)
            .only_v6()
            .map_err(|e| e.to_string())?
            || !socket2::SockRef::from(&server_udp)
                .only_v6()
                .map_err(|e| e.to_string())?)
    {
        return Err("IPv6 support socket permits dual-stack traffic".into());
    }
    let client = async {
        let mut stream = connect(tcp_address).await?;
        let socket = udp(udp_address).await?;
        if stream.local_addr().map_err(|e| e.to_string())?.ip() != ip
            || socket.local_addr().map_err(|e| e.to_string())?.ip() != ip
        {
            return Err("loopback client endpoint family mismatch".into());
        }
        if ip.is_ipv6()
            && (!socket2::SockRef::from(&stream)
                .only_v6()
                .map_err(|e| e.to_string())?
                || !socket2::SockRef::from(&socket)
                    .only_v6()
                    .map_err(|e| e.to_string())?)
        {
            return Err("IPv6 client socket permits dual-stack traffic".into());
        }
        for generation in 1..=2 {
            exchange(&mut stream, &payload(1024, generation, 0, 1)).await?;
            datagram(&socket, &payload(256, generation, 0, 2)).await?;
            datagram(&socket, &payload(FRAGMENT, generation, 0, 3)).await?;
        }
        let last = payload(1024, 2, 0, 4);
        stream.write_all(&last).await.map_err(|e| e.to_string())?;
        stream.shutdown().await.map_err(|e| e.to_string())?;
        let mut reply = vec![0; last.len()];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        let mut extra = [0];
        if reply != last || stream.read(&mut extra).await.map_err(|e| e.to_string())? != 0 {
            return Err("loopback half-close payload or EOF mismatch".into());
        }
        Ok::<_, String>(())
    };
    let tcp_server = async {
        let (stream, _) = tcp.accept().await.map_err(|e| e.to_string())?;
        super::support::echo(stream).await
    };
    let udp_server = async {
        let mut request = [0; FRAGMENT + 1];
        for _ in 0..4 {
            let (count, peer) = server_udp
                .recv_from(&mut request)
                .await
                .map_err(|e| e.to_string())?;
            let reply = udp_ack(&request[..count])?;
            if server_udp
                .send_to(&reply, peer)
                .await
                .map_err(|e| e.to_string())?
                != reply.len()
            {
                return Err("loopback partial UDP acknowledgement".into());
            }
        }
        Ok::<_, String>(())
    };
    tokio::try_join!(client, tcp_server, udp_server)?;
    Ok(())
}
