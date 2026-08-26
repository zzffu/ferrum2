use crate::qualification::{CaseSpec, Direction, Transport};

use super::config::{ReservedPorts, reference_paths};
use super::process_guard::CaseDeadline;
use super::provider_artifact::load_pin;
use super::tcp_case::run_tcp_transport;
use super::udp_case::run_udp_transport;

pub(super) fn run_case(case: CaseSpec) {
    let deadline = CaseDeadline::start();
    let pin = load_pin(case.reference);
    let paths = reference_paths(case.reference, &pin);
    let reference_binary = match case.direction {
        Direction::FerrumClient => &paths.server,
        Direction::ReferenceClient => paths.client.as_ref().unwrap_or(&paths.server),
    };
    let directory = tempfile::tempdir().expect("isolated interop directory");
    let directory_path = directory.path().to_path_buf();
    let mut ports = ReservedPorts::new();
    let target = ports.target_address();
    let proxy = ports.proxy_address();
    let shadowsocks = ports.shadowsocks_address();
    let (config_checksum, process_evidence, target_evidence) = match case.transport {
        Transport::Tcp => run_tcp_transport(
            case,
            reference_binary,
            directory.path(),
            &mut ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
        Transport::Udp => run_udp_transport(
            case,
            reference_binary,
            directory.path(),
            &mut ports,
            shadowsocks,
            proxy,
            target,
            deadline,
        ),
    };
    drop(ports);
    directory
        .close()
        .unwrap_or_else(|error| panic!("explicit temporary directory close: {error}"));
    assert!(
        !directory_path.exists(),
        "temporary interop directory remains"
    );
    deadline.check("final interop evidence");
    eprintln!(
        "{} interop evidence: case_id={}, method={}, reference={:?}, direction={:?}, \
         asset_sha256={}, config_sha256={config_checksum}, command_category=black-box-process, \
         process={process_evidence}, target={target_evidence}, result=success",
        case.transport.label(),
        case.id,
        case.method.canonical_name(),
        case.reference,
        case.direction,
        pin.sha256
    );
}
