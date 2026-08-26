use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::qualification::{DnsReference, Method, Reference, Transport};

pub(super) struct Pin {
    pub(super) version: String,
    pub(super) source_commit: String,
    pub(super) expected_version: String,
    pub(super) asset: String,
    pub(super) url: String,
    pub(super) size: u64,
    pub(super) sha256: String,
    pub(super) license_review: String,
}

pub(super) struct ReservedEndpoint {
    pub(super) udp: Option<UdpSocket>,
    pub(super) tcp: Option<TcpListener>,
    pub(super) address: SocketAddrV4,
}

impl ReservedEndpoint {
    pub(super) fn new() -> Self {
        for _ in 0..32 {
            let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .expect("reserve UDP endpoint");
            let address = ipv4_address(udp.local_addr().expect("reserved UDP address"));
            if let Ok(tcp) = TcpListener::bind(address) {
                return Self {
                    udp: Some(udp),
                    tcp: Some(tcp),
                    address,
                };
            }
        }
        panic!("could not reserve paired TCP/UDP endpoint");
    }

    pub(super) fn release(&mut self) {
        drop(self.udp.take().expect("release UDP reservation once"));
        drop(self.tcp.take().expect("release TCP reservation once"));
    }
}

pub(super) struct ReservedPorts {
    pub(super) target: ReservedEndpoint,
    pub(super) proxy: ReservedEndpoint,
    pub(super) shadowsocks: ReservedEndpoint,
}

impl ReservedPorts {
    pub(super) fn new() -> Self {
        let ports = Self {
            target: ReservedEndpoint::new(),
            proxy: ReservedEndpoint::new(),
            shadowsocks: ReservedEndpoint::new(),
        };
        let addresses = [
            ports.target.address,
            ports.proxy.address,
            ports.shadowsocks.address,
        ];
        assert_eq!(
            addresses.iter().collect::<HashSet<_>>().len(),
            addresses.len(),
            "reserved endpoint pool must be distinct"
        );
        ports
    }

    pub(super) fn target_address(&self) -> SocketAddrV4 {
        self.target.address
    }

    pub(super) fn proxy_address(&self) -> SocketAddrV4 {
        self.proxy.address
    }

    pub(super) fn shadowsocks_address(&self) -> SocketAddrV4 {
        self.shadowsocks.address
    }

    pub(super) fn take_target_udp(&mut self) -> UdpSocket {
        drop(
            self.target
                .tcp
                .take()
                .expect("release target TCP reservation once"),
        );
        self.target
            .udp
            .take()
            .expect("release target UDP reservation to echo owner")
    }

    pub(super) fn take_target_tcp(&mut self) -> TcpListener {
        drop(
            self.target
                .udp
                .take()
                .expect("release target UDP reservation once"),
        );
        self.target
            .tcp
            .take()
            .expect("release target TCP reservation to target owner")
    }

    pub(super) fn release_proxy(&mut self) {
        self.proxy.release();
    }

    pub(super) fn release_shadowsocks(&mut self) {
        self.shadowsocks.release();
    }
}

pub(super) fn ipv4_address(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 socket returned IPv6"),
    }
}

pub(super) fn reference_server_config(
    method: Method,
    reference: Reference,
    address: SocketAddrV4,
    transport: Transport,
) -> String {
    let method_name = method.canonical_name();
    let psk = method.synthetic_psk();
    let network = transport.label();
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{},\"network\":\"{network}\",\
             \"method\":\"{method_name}\",\"password\":\"{psk}\"}}],\
             \"outbounds\":[{{\"type\":\"direct\",\"tag\":\"direct\"}}],\
             \"route\":{{\"final\":\"direct\"}}}}",
            address.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{psk}\",\"method\":\"{method_name}\",\
             \"mode\":\"{}_only\"}}",
            address.port(),
            transport.label()
        ),
    }
}

pub(super) fn reference_client_config(
    method: Method,
    reference: Reference,
    server: SocketAddrV4,
    proxy: SocketAddrV4,
    transport: Transport,
) -> String {
    let method_name = method.canonical_name();
    let psk = method.synthetic_psk();
    let network = transport.label();
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"socks\",\"tag\":\"socks-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{}}}],\
             \"outbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-out\",\
             \"server\":\"127.0.0.1\",\"server_port\":{},\"method\":\"{method_name}\",\
             \"password\":\"{psk}\",\"network\":\"{network}\"}}],\
             \"route\":{{\"final\":\"ss-out\"}}}}",
            proxy.port(),
            server.port()
        ),
        Reference::ShadowsocksRust => {
            let mode = if transport == Transport::Udp {
                "tcp_and_udp"
            } else {
                "tcp_only"
            };
            format!(
                "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
             \"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{psk}\",\"method\":\"{method_name}\",\
             \"mode\":\"{mode}\"}}",
                proxy.port(),
                server.port()
            )
        }
    }
}

pub(super) fn reference_command(reference: Reference, binary: &Path, config: &Path) -> Command {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.args(["run", "-c", path_text(config)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-c", path_text(config)]);
        }
    }
    command
}

pub(super) fn write_config(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write isolated config");
    path
}

pub(super) fn path_text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 generated path")
}

pub(super) fn target_profile_directory() -> PathBuf {
    std::env::current_exe()
        .expect("qualification executable")
        .parent()
        .expect("Cargo target profile directory")
        .to_path_buf()
}

pub(super) fn ferrum_binary(name: &str) -> PathBuf {
    let path = target_profile_directory().join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "required current-worktree ferrum binary is missing"
    );
    path
}

pub(super) struct ReferencePaths {
    pub(super) archive: PathBuf,
    pub(super) extraction_root: PathBuf,
    pub(super) server: PathBuf,
    pub(super) client: Option<PathBuf>,
    pub(super) license: Option<PathBuf>,
}

pub(super) struct DnsReferencePaths {
    pub(super) archive: PathBuf,
    pub(super) extraction_root: PathBuf,
    pub(super) binary: PathBuf,
    pub(super) license: PathBuf,
}

pub(super) fn dns_reference_paths(reference: DnsReference, pin: &Pin) -> DnsReferencePaths {
    let runner_temp = PathBuf::from(
        std::env::var_os("RUNNER_TEMP")
            .expect("GitHub runner did not provide the fixed RUNNER_TEMP directory"),
    );
    match reference {
        DnsReference::CoreDns => {
            let extraction_root = runner_temp.join(format!("coredns-{}", pin.version));
            DnsReferencePaths {
                archive: runner_temp.join(&pin.asset),
                binary: extraction_root.join("coredns"),
                license: extraction_root.join("LICENSE"),
                extraction_root,
            }
        }
        DnsReference::Bind => {
            let extraction_root = runner_temp.join(format!("bind-{}", pin.version));
            DnsReferencePaths {
                archive: runner_temp.join(&pin.asset),
                binary: extraction_root.join("bin/dig/dig"),
                license: extraction_root.join("LICENSE"),
                extraction_root,
            }
        }
    }
}

pub(super) fn reference_paths(reference: Reference, pin: &Pin) -> ReferencePaths {
    let runner_temp = PathBuf::from(
        std::env::var_os("RUNNER_TEMP")
            .expect("GitHub runner did not provide the fixed RUNNER_TEMP directory"),
    );
    let archive = runner_temp.join(&pin.asset);
    match reference {
        Reference::SingBox => {
            let extraction_root = runner_temp.join(format!("sing-box-{}", pin.version));
            let directory =
                extraction_root.join(format!("sing-box-{}-linux-amd64-glibc", pin.version));
            let binary = directory.join("sing-box");
            ReferencePaths {
                archive,
                extraction_root,
                server: binary.clone(),
                client: Some(binary),
                license: Some(directory.join("LICENSE")),
            }
        }
        Reference::ShadowsocksRust => {
            let extraction_root = runner_temp.join(format!("shadowsocks-rust-{}", pin.version));
            ReferencePaths {
                archive,
                server: extraction_root.join("ssserver"),
                client: Some(extraction_root.join("sslocal")),
                extraction_root,
                license: None,
            }
        }
    }
}

pub(super) fn verify_binary_location(binary: &Path, extraction_root: &Path) {
    assert!(
        binary.is_file(),
        "required reviewed reference executable is missing"
    );
    let canonical_root = extraction_root
        .canonicalize()
        .expect("canonical reviewed extraction root");
    let canonical_binary = binary
        .canonicalize()
        .expect("canonical reviewed reference executable");
    assert!(
        canonical_binary.starts_with(&canonical_root),
        "reference executable escaped the reviewed extraction root"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&canonical_binary)
            .expect("reference executable metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "reviewed reference file is not executable");
    }
}
