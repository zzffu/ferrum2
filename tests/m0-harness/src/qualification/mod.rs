use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reference {
    SingBox,
    ShadowsocksRust,
}

impl Reference {
    pub const fn provision_root(self) -> &'static str {
        match self {
            Self::SingBox => "provision-sing-box",
            Self::ShadowsocksRust => "provision-shadowsocks-rust",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    FerrumClient,
    ReferenceClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub const fn synthetic_psk(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AAECAwQFBgcICQoLDA0ODw==",
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => {
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseSpec {
    pub id: &'static str,
    root: &'static str,
    pub transport: Transport,
    pub method: Method,
    pub reference: Reference,
    pub direction: Direction,
}

impl CaseSpec {
    pub const fn case_root(self) -> &'static str {
        self.root
    }
}

macro_rules! case {
    ($id:literal, $transport:expr, $method:expr, $reference:expr, $direction:expr) => {
        CaseSpec {
            id: $id,
            root: concat!("case-", $id),
            transport: $transport,
            method: $method,
            reference: $reference,
            direction: $direction,
        }
    };
}

use Direction::{FerrumClient as Ferrum, ReferenceClient as RefClient};
use Method::{Aes128Gcm as Aes128, Aes256Gcm as Aes256, ChaCha20Poly1305 as ChaCha};
use Reference::{ShadowsocksRust, SingBox};
use Transport::{Tcp, Udp};

pub const TCP_CASES: [CaseSpec; 12] = [
    case!("M1-INT-001", Tcp, Aes128, SingBox, Ferrum),
    case!("M1-INT-002", Tcp, Aes128, ShadowsocksRust, Ferrum),
    case!("M1-INT-003", Tcp, Aes128, SingBox, RefClient),
    case!("M1-INT-004", Tcp, Aes128, ShadowsocksRust, RefClient),
    case!("M1-INT-005", Tcp, Aes256, SingBox, Ferrum),
    case!("M1-INT-006", Tcp, Aes256, ShadowsocksRust, Ferrum),
    case!("M1-INT-007", Tcp, Aes256, SingBox, RefClient),
    case!("M1-INT-008", Tcp, Aes256, ShadowsocksRust, RefClient),
    case!("M1-INT-009", Tcp, ChaCha, SingBox, Ferrum),
    case!("M1-INT-010", Tcp, ChaCha, ShadowsocksRust, Ferrum),
    case!("M1-INT-011", Tcp, ChaCha, SingBox, RefClient),
    case!("M1-INT-012", Tcp, ChaCha, ShadowsocksRust, RefClient),
];

pub const UDP_CASES: [CaseSpec; 12] = [
    case!("M2-UDP-INT-001", Udp, Aes128, SingBox, Ferrum),
    case!("M2-UDP-INT-002", Udp, Aes128, ShadowsocksRust, Ferrum),
    case!("M2-UDP-INT-003", Udp, Aes128, SingBox, RefClient),
    case!("M2-UDP-INT-004", Udp, Aes128, ShadowsocksRust, RefClient),
    case!("M2-UDP-INT-005", Udp, Aes256, SingBox, Ferrum),
    case!("M2-UDP-INT-006", Udp, Aes256, ShadowsocksRust, Ferrum),
    case!("M2-UDP-INT-007", Udp, Aes256, SingBox, RefClient),
    case!("M2-UDP-INT-008", Udp, Aes256, ShadowsocksRust, RefClient),
    case!("M2-UDP-INT-009", Udp, ChaCha, SingBox, Ferrum),
    case!("M2-UDP-INT-010", Udp, ChaCha, ShadowsocksRust, Ferrum),
    case!("M2-UDP-INT-011", Udp, ChaCha, SingBox, RefClient),
    case!("M2-UDP-INT-012", Udp, ChaCha, ShadowsocksRust, RefClient),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsReference {
    CoreDns,
    Bind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsUpstreamTransport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPath {
    Direct,
    Detoured,
}

impl DnsReference {
    pub const fn provision_root(self) -> &'static str {
        match self {
            Self::CoreDns => "provision-coredns",
            Self::Bind => "provision-bind",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCaseSpec {
    pub id: &'static str,
    pub reference: DnsReference,
    pub upstream: DnsUpstreamTransport,
    pub path: DnsPath,
    pub bind_tcp: bool,
    root: &'static str,
}

impl DnsCaseSpec {
    pub const fn case_root(self) -> &'static str {
        self.root
    }
}

macro_rules! dns_case {
    ($id:literal, $reference:expr, $upstream:expr, $path:expr, $bind_tcp:expr) => {
        DnsCaseSpec {
            id: $id,
            reference: $reference,
            upstream: $upstream,
            path: $path,
            bind_tcp: $bind_tcp,
            root: concat!("case-", $id),
        }
    };
}

pub const DNS_CASES: [DnsCaseSpec; 12] = [
    dns_case!(
        "M12-DNS-coredns-udp-direct",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Udp,
        DnsPath::Direct,
        false
    ),
    dns_case!(
        "M12-DNS-coredns-tcp-direct",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Tcp,
        DnsPath::Direct,
        true
    ),
    dns_case!(
        "M12-DNS-coredns-dot-direct",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Dot,
        DnsPath::Direct,
        true
    ),
    dns_case!(
        "M12-DNS-coredns-doh-direct",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Doh,
        DnsPath::Direct,
        true
    ),
    dns_case!(
        "M12-DNS-coredns-udp-detour",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Udp,
        DnsPath::Detoured,
        false
    ),
    dns_case!(
        "M12-DNS-coredns-tcp-detour",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Tcp,
        DnsPath::Detoured,
        true
    ),
    dns_case!(
        "M12-DNS-coredns-dot-detour",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Dot,
        DnsPath::Detoured,
        true
    ),
    dns_case!(
        "M12-DNS-coredns-doh-detour",
        DnsReference::CoreDns,
        DnsUpstreamTransport::Doh,
        DnsPath::Detoured,
        true
    ),
    dns_case!(
        "M12-DNS-bind-dig-udp-direct",
        DnsReference::Bind,
        DnsUpstreamTransport::Udp,
        DnsPath::Direct,
        false
    ),
    dns_case!(
        "M12-DNS-bind-dig-tcp-direct",
        DnsReference::Bind,
        DnsUpstreamTransport::Udp,
        DnsPath::Direct,
        true
    ),
    dns_case!(
        "M12-DNS-bind-dig-udp-detour",
        DnsReference::Bind,
        DnsUpstreamTransport::Udp,
        DnsPath::Detoured,
        false
    ),
    dns_case!(
        "M12-DNS-bind-dig-tcp-detour",
        DnsReference::Bind,
        DnsUpstreamTransport::Udp,
        DnsPath::Detoured,
        true
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseFailure {
    canonical_root: &'static str,
}

impl CaseFailure {
    pub const fn new(canonical_root: &'static str) -> Self {
        Self { canonical_root }
    }
}

pub trait QualificationOps {
    fn provision(&mut self, reference: Reference) -> Result<(), CaseFailure>;
    fn run_case(&mut self, case: CaseSpec) -> Result<(), CaseFailure>;
    fn finish_cleanup(&mut self) -> Result<(), CaseFailure>;
}

pub trait DnsQualificationOps {
    fn provision_dns(&mut self, reference: DnsReference) -> Result<(), CaseFailure>;
    fn run_dns_case(&mut self, case: DnsCaseSpec) -> Result<(), CaseFailure>;
    fn finish_dns_cleanup(&mut self) -> Result<(), CaseFailure>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupState {
    children: isize,
    workers: isize,
    failed: bool,
}

#[allow(dead_code)]
impl CleanupState {
    pub fn child_started(&mut self) {
        self.children += 1;
    }

    pub fn child_reaped(&mut self) {
        self.children -= 1;
        self.failed |= self.children < 0;
    }

    pub fn worker_started(&mut self) {
        self.workers += 1;
    }

    pub fn worker_joined(&mut self) {
        self.workers -= 1;
        self.failed |= self.workers < 0;
    }

    pub fn fail(&mut self) {
        self.failed = true;
    }

    pub const fn success(self) -> bool {
        !self.failed && self.children == 0 && self.workers == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpExchangeEvent {
    ForwardMatched,
    ReverseMatched,
    ApplicationShutdown,
    TargetCleanEof,
    TargetShutdown,
    ApplicationCleanEof,
}

pub const TCP_EXCHANGE_ORDER: [TcpExchangeEvent; 6] = [
    TcpExchangeEvent::ForwardMatched,
    TcpExchangeEvent::ReverseMatched,
    TcpExchangeEvent::ApplicationShutdown,
    TcpExchangeEvent::TargetCleanEof,
    TcpExchangeEvent::TargetShutdown,
    TcpExchangeEvent::ApplicationCleanEof,
];

#[derive(Debug, Default)]
pub struct TcpExchangeState(usize);

impl TcpExchangeState {
    pub fn record(&mut self, event: TcpExchangeEvent) -> Result<(), &'static str> {
        if TCP_EXCHANGE_ORDER.get(self.0) != Some(&event) {
            return Err("TCP exchange event is out of order");
        }
        self.0 += 1;
        Ok(())
    }

    pub fn success(&self) -> bool {
        self.0 == TCP_EXCHANGE_ORDER.len()
    }
}

type GateResult = Result<(), String>;

pub struct TcpTargetGate(SyncSender<GateResult>, Receiver<GateResult>);
pub struct TcpApplicationGate(Receiver<GateResult>, SyncSender<GateResult>);

pub fn tcp_shutdown_gate() -> (TcpTargetGate, TcpApplicationGate) {
    let (target, application_wait) = mpsc::sync_channel(1);
    let (application, target_wait) = mpsc::sync_channel(1);
    (
        TcpTargetGate(target, target_wait),
        TcpApplicationGate(application_wait, application),
    )
}

impl TcpTargetGate {
    pub fn finish<T>(&self, result: Result<T, String>, timeout: Duration) -> Result<T, String> {
        self.0
            .send(result.as_ref().map(|_| ()).map_err(Clone::clone))
            .map_err(|error| error.to_string())?;
        let acknowledgement = self.1.recv_timeout(timeout).map_err(|e| e.to_string())?;
        match result {
            Ok(value) => acknowledgement.map(|()| value),
            Err(error) => Err(error),
        }
    }
}

impl TcpApplicationGate {
    pub fn wait(self, timeout: Duration) -> Result<SyncSender<GateResult>, String> {
        let outcome = self
            .0
            .recv_timeout(timeout)
            .unwrap_or_else(|e| Err(e.to_string()));
        match outcome {
            Ok(()) => Ok(self.1),
            Err(error) => {
                let _ = self.1.send(Err(error.clone()));
                Err(error)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupAvailability {
    sing_box: bool,
    shadowsocks_rust: bool,
}

impl SetupAvailability {
    pub fn from_provider_status(sing_box: Option<&str>, shadowsocks_rust: Option<&str>) -> Self {
        Self {
            sing_box: sing_box == Some("0"),
            shadowsocks_rust: shadowsocks_rust == Some("0"),
        }
    }

    pub const fn is_ready(self, reference: Reference) -> bool {
        match reference {
            Reference::SingBox => self.sing_box,
            Reference::ShadowsocksRust => self.shadowsocks_rust,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsSetupAvailability {
    coredns: bool,
    bind: bool,
}

impl DnsSetupAvailability {
    pub fn from_provider_status(coredns: Option<&str>, bind: Option<&str>) -> Self {
        Self {
            coredns: coredns == Some("0"),
            bind: bind == Some("0"),
        }
    }

    pub const fn is_ready(self, reference: DnsReference) -> bool {
        match reference {
            DnsReference::CoreDns => self.coredns,
            DnsReference::Bind => self.bind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaseStatus {
    Pass,
    Fail(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseResult {
    case: CaseSpec,
    status: CaseStatus,
}

#[derive(Debug, Eq, PartialEq)]
pub struct QualificationReport {
    results: [[CaseResult; 12]; 2],
    cleanup: CaseStatus,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DnsQualificationReport {
    results: [DnsCaseResult; 12],
    cleanup: CaseStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DnsCaseResult {
    case: DnsCaseSpec,
    status: CaseStatus,
}

impl DnsQualificationReport {
    pub fn success(&self) -> bool {
        self.results
            .iter()
            .all(|result| result.status == CaseStatus::Pass)
            && self.cleanup == CaseStatus::Pass
    }

    pub fn summary_lines(&self) -> [String; 12] {
        self.results.map(|result| {
            let status = match result.status {
                CaseStatus::Pass => "PASS".to_owned(),
                CaseStatus::Fail(root) => format!("FAIL canonical_root={root}"),
            };
            format!("transport=dns case_id={} status={status}", result.case.id)
        })
    }

    pub fn completion_line(&self, context: &HostedContext<'_>) -> String {
        let status = |passed| if passed { "PASS" } else { "FAIL" };
        format!(
            "qualification transport=dns status={} cleanup={} sha={} run_id={} run_attempt={}",
            status(self.success()),
            status(self.cleanup == CaseStatus::Pass),
            context.head_sha,
            context.run_id.unwrap_or("missing"),
            context.run_attempt.unwrap_or("missing")
        )
    }
}

impl QualificationReport {
    pub fn success(&self) -> bool {
        self.transport_success(Transport::Tcp)
            && self.transport_success(Transport::Udp)
            && self.cleanup == CaseStatus::Pass
    }

    pub const fn cleanup_success(&self) -> bool {
        matches!(self.cleanup, CaseStatus::Pass)
    }

    pub fn transport_success(&self, transport: Transport) -> bool {
        self.results(transport)
            .iter()
            .all(|result| result.status == CaseStatus::Pass)
    }

    pub fn pass_count(&self, transport: Transport) -> usize {
        self.results(transport)
            .iter()
            .filter(|result| result.status == CaseStatus::Pass)
            .count()
    }

    pub fn completion_line(&self, transport: Transport, context: &HostedContext<'_>) -> String {
        let status = |passed| if passed { "PASS" } else { "FAIL" };
        format!(
            "qualification transport={} status={} cases={}/12 cleanup={} sha={} run_id={} \
             run_attempt={}",
            transport.label(),
            status(self.transport_success(transport) && self.cleanup_success()),
            self.pass_count(transport),
            status(self.cleanup_success()),
            context.head_sha,
            context.run_id.unwrap_or("missing"),
            context.run_attempt.unwrap_or("missing")
        )
    }

    pub fn summary_lines(&self, transport: Transport) -> [String; 12] {
        self.results(transport).map(|result| {
            let status = match result.status {
                CaseStatus::Pass => "PASS".to_owned(),
                CaseStatus::Fail(root) => format!("FAIL canonical_root={root}"),
            };
            format!(
                "transport={} case_id={} status={status}",
                transport.label(),
                result.case.id
            )
        })
    }

    fn results(&self, transport: Transport) -> [CaseResult; 12] {
        self.results[usize::from(transport == Transport::Udp)]
    }
}

pub fn execute_with_setup(
    setup: SetupAvailability,
    ops: &mut impl QualificationOps,
) -> QualificationReport {
    let sing_box = provision_if_ready(setup, ops, Reference::SingBox);
    let shadowsocks_rust = provision_if_ready(setup, ops, Reference::ShadowsocksRust);
    let provision = |reference| match reference {
        Reference::SingBox => sing_box,
        Reference::ShadowsocksRust => shadowsocks_rust,
    };

    let mut run_plan = |cases: [CaseSpec; 12]| {
        cases.map(|case| {
            let status = match provision(case.reference) {
                Err(failure) => CaseStatus::Fail(failure.canonical_root),
                Ok(()) => match catch_unwind(AssertUnwindSafe(|| ops.run_case(case))) {
                    Ok(Ok(())) => CaseStatus::Pass,
                    Ok(Err(failure)) => CaseStatus::Fail(failure.canonical_root),
                    Err(_) => CaseStatus::Fail(case.case_root()),
                },
            };
            CaseResult { case, status }
        })
    };
    let tcp_results = run_plan(TCP_CASES);
    let udp_results = run_plan(UDP_CASES);

    let cleanup = match catch_unwind(AssertUnwindSafe(|| ops.finish_cleanup())) {
        Ok(Ok(())) => CaseStatus::Pass,
        Ok(Err(failure)) => CaseStatus::Fail(failure.canonical_root),
        Err(_) => CaseStatus::Fail("cleanup"),
    };

    QualificationReport {
        results: [tcp_results, udp_results],
        cleanup,
    }
}

pub fn execute_hosted(
    context: &HostedContext<'_>,
    setup: SetupAvailability,
    ops: &mut impl QualificationOps,
) -> Result<QualificationReport, &'static str> {
    validate_hosted(context)?;
    Ok(execute_with_setup(setup, ops))
}

pub fn execute_dns_with_setup(
    setup: DnsSetupAvailability,
    ops: &mut impl DnsQualificationOps,
) -> DnsQualificationReport {
    let mut provision = |reference| {
        if !setup.is_ready(reference) {
            return Err(CaseFailure::new(reference.provision_root()));
        }
        match catch_unwind(AssertUnwindSafe(|| ops.provision_dns(reference))) {
            Ok(result) => result,
            Err(_) => Err(CaseFailure::new(reference.provision_root())),
        }
    };
    let coredns = provision(DnsReference::CoreDns);
    let bind = provision(DnsReference::Bind);
    let results = DNS_CASES.map(|case| {
        let ready = coredns.and(bind);
        let status = match ready {
            Err(failure) => CaseStatus::Fail(failure.canonical_root),
            Ok(()) => match catch_unwind(AssertUnwindSafe(|| ops.run_dns_case(case))) {
                Ok(Ok(())) => CaseStatus::Pass,
                Ok(Err(failure)) => CaseStatus::Fail(failure.canonical_root),
                Err(_) => CaseStatus::Fail(case.case_root()),
            },
        };
        DnsCaseResult { case, status }
    });
    let cleanup = match catch_unwind(AssertUnwindSafe(|| ops.finish_dns_cleanup())) {
        Ok(Ok(())) => CaseStatus::Pass,
        Ok(Err(failure)) => CaseStatus::Fail(failure.canonical_root),
        Err(_) => CaseStatus::Fail("cleanup"),
    };
    DnsQualificationReport { results, cleanup }
}

pub fn execute_dns_hosted(
    context: &HostedContext<'_>,
    setup: DnsSetupAvailability,
    ops: &mut impl DnsQualificationOps,
) -> Result<DnsQualificationReport, &'static str> {
    validate_dns_hosted(context)?;
    Ok(execute_dns_with_setup(setup, ops))
}

fn provision_if_ready(
    setup: SetupAvailability,
    ops: &mut impl QualificationOps,
    reference: Reference,
) -> Result<(), CaseFailure> {
    if setup.is_ready(reference) {
        provision(ops, reference)
    } else {
        Err(CaseFailure::new(reference.provision_root()))
    }
}

fn provision(ops: &mut impl QualificationOps, reference: Reference) -> Result<(), CaseFailure> {
    match catch_unwind(AssertUnwindSafe(|| ops.provision(reference))) {
        Ok(result) => result,
        Err(_) => Err(CaseFailure::new(reference.provision_root())),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedContext<'a> {
    pub argument_count: usize,
    pub github_actions: Option<&'a str>,
    pub runner_os: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub run_attempt: Option<&'a str>,
    pub github_sha: Option<&'a str>,
    pub head_sha: &'a str,
    pub checkout_clean: bool,
}

pub fn validate_hosted(context: &HostedContext<'_>) -> Result<(), &'static str> {
    validate_hosted_with_arguments(context, 1)
}

pub fn validate_dns_hosted(context: &HostedContext<'_>) -> Result<(), &'static str> {
    validate_hosted_with_arguments(context, 2)
}

fn validate_hosted_with_arguments(
    context: &HostedContext<'_>,
    expected_argument_count: usize,
) -> Result<(), &'static str> {
    if context.argument_count != expected_argument_count {
        return Err("qualification accepts no arguments");
    }
    if context.github_actions != Some("true") {
        return Err("qualification requires GitHub Actions");
    }
    if context.runner_os != Some("Linux") {
        return Err("qualification requires the fixed Linux runner");
    }
    if !context.run_id.is_some_and(valid_run_number)
        || !context.run_attempt.is_some_and(valid_run_number)
    {
        return Err("qualification requires one numeric run and attempt");
    }
    let github_sha = context.github_sha.ok_or("GITHUB_SHA is missing")?;
    if !valid_sha(github_sha) || !valid_sha(context.head_sha) {
        return Err("checkout identity must be a full hexadecimal SHA");
    }
    if github_sha != context.head_sha {
        return Err("checkout HEAD does not equal GITHUB_SHA");
    }
    if !context.checkout_clean {
        return Err("checkout is not clean");
    }
    Ok(())
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_run_number(value: &str) -> bool {
    (1..=20).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte != b'0')
}
