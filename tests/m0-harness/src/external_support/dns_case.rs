use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::qualification::{
    DnsCaseSpec, DnsPath, DnsReference, DnsUpstreamTransport, Method, TcpExchangeState,
};

use super::config::{
    ReservedEndpoint, dns_reference_paths, ferrum_binary, path_text, write_config,
};
use super::process_guard::{CaseDeadline, ProcessGuard, sanitize_capture};
use super::provider_artifact::load_dns_pin;
use super::tcp_case::{TcpTarget, exercise_socks_domain_tcp};
use super::udp_case::{wait_for_stable_child, wait_for_tcp_listener};

pub(super) fn run_external_dns_case(case: DnsCaseSpec) {
    let deadline = CaseDeadline::start();
    let coredns = dns_reference_paths(DnsReference::CoreDns, &load_dns_pin(DnsReference::CoreDns));
    let bind = dns_reference_paths(DnsReference::Bind, &load_dns_pin(DnsReference::Bind));
    let directory = tempfile::tempdir().expect("isolated DNS interop directory");
    let mut upstream = ReservedEndpoint::new();
    let mut dns_proxy = ReservedEndpoint::new();
    let mut socks = ReservedEndpoint::new();
    let mut shadowsocks = ReservedEndpoint::new();
    let upstream_address = upstream.address;
    let dns_address = dns_proxy.address;
    let socks_address = socks.address;
    let shadowsocks_address = shadowsocks.address;
    let large = "x".repeat(240);
    let zone = format!(
        concat!(
            "$ORIGIN qualification.test.\n",
            "@ 60 IN SOA ns hostmaster 1 60 60 60 60\n",
            "@ 60 IN NS ns\n",
            "ns 60 IN A 127.0.0.1\n",
            "answer 60 IN A 192.0.2.80\n",
            "answer 60 IN AAAA 2001:db8::80\n",
            "server-answer 60 IN A 127.0.0.1\n",
            "nodata 60 IN TXT \"present-without-address\"\n",
            "large 60 IN TXT \"{0}\" \"{0}\" \"{0}\"\n",
        ),
        large
    );
    let zone_path = write_config(directory.path(), "qualification.zone", &zone);
    let tls = matches!(
        case.upstream,
        DnsUpstreamTransport::Dot | DnsUpstreamTransport::Doh
    )
    .then(|| prepare_coredns_tls(directory.path(), deadline));
    let scheme = match case.upstream {
        DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => "",
        DnsUpstreamTransport::Dot => "tls://",
        DnsUpstreamTransport::Doh => "https://",
    };
    let tls_line = tls
        .as_ref()
        .map(|(cert, key)| format!("  tls {} {}\n", path_text(cert), path_text(key)))
        .unwrap_or_default();
    let corefile = format!(
        "{scheme}qualification.test.:{} {{\n  bind 127.0.0.1\n{tls_line}  file {} qualification.test.\n  errors\n}}\n",
        upstream_address.port(),
        path_text(&zone_path),
    );
    let corefile_path = write_config(directory.path(), "Corefile", &corefile);
    upstream.release();
    let mut command = Command::new(&coredns.binary);
    command.args(["-conf", path_text(&corefile_path)]);
    let mut coredns_process = ProcessGuard::spawn("pinned CoreDNS", &mut command, deadline);
    wait_for_stable_child(&mut coredns_process, deadline, "pinned CoreDNS");

    let mut server_process = None;
    if case.path == DnsPath::Detoured {
        let server_config = format!(
            "schema_version = 2\n[[inbounds]]\ntag = \"proxy\"\nlisten = \"{shadowsocks_address}\"\noutbound = \"direct\"\n\
             [[outbounds]]\ntag = \"direct\"\n\
             [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n[udp]\n",
            Method::Aes128Gcm.canonical_name(),
            Method::Aes128Gcm.synthetic_psk(),
        );
        let server_path = write_config(directory.path(), "ferrum-server.toml", &server_config);
        shadowsocks.release();
        let mut command = Command::new(ferrum_binary("ferrum2-server"));
        command.args(["--config", path_text(&server_path)]);
        let mut process = ProcessGuard::spawn("ferrum DNS detour server", &mut command, deadline);
        wait_for_tcp_listener(
            &mut process,
            shadowsocks_address,
            deadline,
            "ferrum DNS detour server",
        );
        server_process = Some(process);
    }

    let transport = match case.upstream {
        DnsUpstreamTransport::Udp => "udp",
        DnsUpstreamTransport::Tcp => "tcp",
        DnsUpstreamTransport::Dot => "dot",
        DnsUpstreamTransport::Doh => "doh",
    };
    let encryption = match case.upstream {
        DnsUpstreamTransport::Dot => "server_name = \"resolver.test\"\n",
        DnsUpstreamTransport::Doh => "server_name = \"resolver.test\"\npath = \"/dns-query\"\n",
        DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => "",
    };
    let detour = if case.path == DnsPath::Detoured {
        "detour = \"dns-hop\"\n"
    } else {
        ""
    };
    let client_config = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{socks_address}\"\n\
         [[outbounds]]\ntag = \"dns-hop\"\ntype = \"shadowsocks\"\nserver = \"{shadowsocks_address}\"\nmethod = \"{}\"\npsk = \"{}\"\n\
         [route]\nfinal = \"dns-hop\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = 4\n\
         [[dns.inbounds]]\ntag = \"dns-in\"\nlisten = \"{dns_address}\"\n\
         [[dns.servers]]\ntag = \"core\"\ntransport = \"{transport}\"\naddress = \"{upstream_address}\"\n\
         {encryption}{detour}\
         [dns.route]\nfinal = \"core\"\n\
         [udp]\n",
        Method::Aes128Gcm.canonical_name(),
        Method::Aes128Gcm.synthetic_psk(),
    );
    let client_path = write_config(directory.path(), "ferrum-client.toml", &client_config);
    dns_proxy.release();
    socks.release();
    let mut command = Command::new(ferrum_binary("ferrum2-client"));
    command.args(["--config", path_text(&client_path)]);
    let mut client = ProcessGuard::spawn("ferrum DNS qualification client", &mut command, deadline);
    wait_for_tcp_listener(
        &mut client,
        dns_address,
        deadline,
        "ferrum DNS qualification client",
    );

    let tcp = case.bind_tcp;
    let query = |name: &str, record: &str, short: bool| {
        let mut command = Command::new(&bind.binary);
        let server_arg = format!("@{}", dns_address.ip());
        let port_arg = dns_address.port().to_string();
        command.args([
            server_arg.as_str(),
            "-p",
            port_arg.as_str(),
            name,
            record,
            "+time=2",
            "+tries=1",
        ]);
        if tcp {
            command.arg("+tcp");
        }
        if short {
            command.arg("+short");
        } else {
            command.args(["+noall", "+comments", "+answer"]);
        }
        run_dns_probe(&mut command, deadline, "bounded BIND query")
    };
    assert_eq!(
        query("answer.qualification.test.", "A", true).trim(),
        "192.0.2.80"
    );
    assert_eq!(
        query("answer.qualification.test.", "AAAA", true).trim(),
        "2001:db8::80"
    );
    assert!(query("missing.qualification.test.", "A", false).contains("status: NXDOMAIN"));
    let nodata = query("nodata.qualification.test.", "A", false);
    assert!(nodata.contains("status: NOERROR") && !nodata.contains(" IN A "));

    let mut server_target_sentinel = None;
    if case.reference == DnsReference::CoreDns
        && case.upstream == DnsUpstreamTransport::Dot
        && case.path == DnsPath::Direct
    {
        let (process, target) = start_server_resolution_witness(
            directory.path(),
            upstream_address,
            shadowsocks_address,
            socks_address,
            &mut shadowsocks,
            deadline,
        );
        server_process = Some(process);
        server_target_sentinel = Some(target);
    }

    if case.reference == DnsReference::Bind {
        let mut command = Command::new(&bind.binary);
        let server_arg = format!("@{}", dns_address.ip());
        let port_arg = dns_address.port().to_string();
        command.args([
            server_arg.as_str(),
            "-p",
            port_arg.as_str(),
            "large.qualification.test.",
            "TXT",
            "+bufsize=512",
            "+time=2",
            "+tries=1",
            "+noall",
            "+comments",
            "+answer",
        ]);
        if case.bind_tcp {
            command.arg("+tcp");
        } else {
            command.arg("+ignore");
        }
        let output = run_dns_probe(&mut command, deadline, "bounded BIND EDNS query");
        if case.bind_tcp {
            assert!(output.contains(&large));
        } else {
            assert!(output.contains(" flags: qr aa tc"));
        }
    }

    let mut earlier_client_stderr = String::new();
    if matches!(
        case.upstream,
        DnsUpstreamTransport::Dot | DnsUpstreamTransport::Doh
    ) {
        let (_, _, stderr) = client.terminate_captures(deadline);
        earlier_client_stderr = sanitize_capture(stderr);
        drop(UdpSocket::bind(dns_address).expect("encrypted-cycle DNS UDP rebind"));
        drop(TcpListener::bind(dns_address).expect("encrypted-cycle DNS TCP rebind"));
        drop(UdpSocket::bind(socks_address).expect("encrypted-cycle SOCKS UDP rebind"));
        drop(TcpListener::bind(socks_address).expect("encrypted-cycle SOCKS TCP rebind"));
        let negative_config = match case.upstream {
            DnsUpstreamTransport::Dot => client_config.replace(
                "server_name = \"resolver.test\"",
                "server_name = \"wrong.test\"",
            ),
            DnsUpstreamTransport::Doh => {
                client_config.replace("path = \"/dns-query\"", "path = \"/wrong\"")
            }
            DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp => unreachable!(),
        };
        let negative_path = write_config(
            directory.path(),
            "ferrum-client-negative.toml",
            &negative_config,
        );
        let mut command = Command::new(ferrum_binary("ferrum2-client"));
        command.args(["--config", path_text(&negative_path)]);
        client = ProcessGuard::spawn("ferrum DNS negative client", &mut command, deadline);
        wait_for_tcp_listener(
            &mut client,
            dns_address,
            deadline,
            "ferrum DNS negative client",
        );
        assert!(
            query("answer.qualification.test.", "A", false).contains("status: SERVFAIL"),
            "encrypted DNS negative did not fail closed"
        );
    }

    let mut earlier_server_stderr = String::new();
    if case.path == DnsPath::Detoured
        && matches!(
            case.upstream,
            DnsUpstreamTransport::Udp | DnsUpstreamTransport::Tcp
        )
    {
        let mut server = server_process.take().expect("detoured server owner");
        let (_, _, stderr) = server.terminate_captures(deadline);
        earlier_server_stderr = sanitize_capture(stderr);
        assert!(
            query("answer.qualification.test.", "A", false).contains("status: SERVFAIL"),
            "detour failure retried or fell back"
        );
    }

    let (_, _, client_stderr) = client.terminate_captures(deadline);
    let client_stderr = earlier_client_stderr + &sanitize_capture(client_stderr);
    let server_stderr = server_process
        .as_mut()
        .map(|server| {
            let (_, _, stderr) = server.terminate_captures(deadline);
            sanitize_capture(stderr)
        })
        .unwrap_or(earlier_server_stderr);
    let (_, _, coredns_stderr) = coredns_process.terminate_captures(deadline);
    let coredns_stderr = sanitize_capture(coredns_stderr);
    drop(shadowsocks);
    let addresses = [
        upstream_address.to_string(),
        dns_address.to_string(),
        socks_address.to_string(),
        shadowsocks_address.to_string(),
    ];
    for sentinel in [
        "qualification.test",
        "resolver.test",
        "dns-hop",
        "dns-in",
        "server-dns-direct",
        "server-app-direct",
    ]
    .into_iter()
    .chain(addresses.iter().map(String::as_str))
    .chain(server_target_sentinel.iter().map(String::as_str))
    {
        assert!(
            !client_stderr.contains(sentinel)
                && !server_stderr.contains(sentinel)
                && !coredns_stderr.contains(sentinel),
            "DNS child stderr leaked a sentinel"
        );
    }
    for address in [
        upstream_address,
        dns_address,
        socks_address,
        shadowsocks_address,
    ] {
        drop(UdpSocket::bind(address).expect("DNS qualification UDP rebind"));
        drop(TcpListener::bind(address).expect("DNS qualification TCP rebind"));
    }
    directory.close().expect("close DNS interop directory");
}

pub(super) fn start_server_resolution_witness(
    directory: &Path,
    upstream: SocketAddrV4,
    shadowsocks: SocketAddrV4,
    socks: SocketAddrV4,
    shadowsocks_reservation: &mut ReservedEndpoint,
    deadline: CaseDeadline,
) -> (ProcessGuard, String) {
    let mut target = ReservedEndpoint::new();
    let target_address = target.address;
    let trace = Arc::new(Mutex::new(TcpExchangeState::default()));
    let (target_process, target_shutdown) = TcpTarget::start(
        target.tcp.take().expect("server witness TCP target"),
        deadline,
        Arc::clone(&trace),
    );
    let config = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"server-in\"\nlisten = \"{shadowsocks}\"\n\
         [[outbounds]]\ntag = \"server-app-direct\"\ndomain_resolver = \"core\"\ndomain_strategy = \"ipv4_only\"\n\
         [[outbounds]]\ntag = \"server-dns-direct\"\n\
         [route]\nfinal = \"server-app-direct\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = 4\n\
         [[dns.servers]]\ntag = \"core\"\ntransport = \"dot\"\naddress = \"{upstream}\"\n\
         server_name = \"resolver.test\"\ndetour = \"server-dns-direct\"\n\
         [dns.route]\nfinal = \"core\"\n\
         [shadowsocks]\nmethod = \"{}\"\npsk = \"{}\"\n",
        Method::Aes128Gcm.canonical_name(),
        Method::Aes128Gcm.synthetic_psk(),
    );
    let config = write_config(directory, "ferrum-server-resolution.toml", &config);
    shadowsocks_reservation.release();
    let mut command = Command::new(ferrum_binary("ferrum2-server"));
    command.args(["--config", path_text(&config)]);
    let mut server =
        ProcessGuard::spawn("ferrum encrypted resolver server", &mut command, deadline);
    wait_for_tcp_listener(
        &mut server,
        shadowsocks,
        deadline,
        "ferrum encrypted resolver server",
    );
    exercise_socks_domain_tcp(
        socks,
        "server-answer.qualification.test.",
        target_address,
        deadline,
        &trace,
        target_shutdown,
    );
    let target_evidence = target_process.finish(deadline);
    assert!(
        target_evidence.contains("clean_eof=true"),
        "server resolution target evidence"
    );
    assert!(
        trace.lock().expect("server witness trace lock").success(),
        "server resolution exchange order is incomplete"
    );
    drop(target.udp.take().expect("server witness UDP reservation"));
    drop(UdpSocket::bind(target_address).expect("server witness target UDP rebind"));
    drop(TcpListener::bind(target_address).expect("server witness target TCP rebind"));
    (server, target_address.to_string())
}

pub(super) fn prepare_coredns_tls(directory: &Path, deadline: CaseDeadline) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let fixtures = root.join("tests/fixtures/dns-tls");
    let certificate = directory.join("resolver.pem");
    let key = directory.join("resolver-key.pem");
    let mut command = Command::new("openssl");
    command.args([
        "x509",
        "-inform",
        "DER",
        "-in",
        path_text(&fixtures.join("m12-resolver-test.der")),
        "-out",
        path_text(&certificate),
    ]);
    let _ = run_dns_probe(&mut command, deadline, "certificate conversion");
    let mut command = Command::new("openssl");
    command.args([
        "pkey",
        "-inform",
        "DER",
        "-in",
        path_text(&fixtures.join("m12-resolver-test.pk8")),
        "-out",
        path_text(&key),
    ]);
    let _ = run_dns_probe(&mut command, deadline, "private-key conversion");
    (certificate, key)
}

pub(super) fn run_dns_probe(
    command: &mut Command,
    deadline: CaseDeadline,
    label: &'static str,
) -> String {
    let mut process = ProcessGuard::spawn(label, command, deadline);
    let status = process.wait_for_exit(deadline, label);
    let (stdout, stderr) = process.finish_captures(deadline);
    if !status.success() || stdout.truncated || stderr.truncated || !stderr.bytes.is_empty() {
        panic!(
            "DNS probe failed: status={status}, stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        );
    }
    String::from_utf8(stdout.bytes).expect("DNS probe output must be UTF-8")
}
