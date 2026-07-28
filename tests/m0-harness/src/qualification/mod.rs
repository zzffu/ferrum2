use std::panic::{AssertUnwindSafe, catch_unwind};

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
    pub method: Method,
    pub reference: Reference,
    pub direction: Direction,
}

impl CaseSpec {
    pub fn case_root(self) -> &'static str {
        match self.id {
            "M1-INT-001" => "case-M1-INT-001",
            "M1-INT-002" => "case-M1-INT-002",
            "M1-INT-003" => "case-M1-INT-003",
            "M1-INT-004" => "case-M1-INT-004",
            "M1-INT-005" => "case-M1-INT-005",
            "M1-INT-006" => "case-M1-INT-006",
            "M1-INT-007" => "case-M1-INT-007",
            "M1-INT-008" => "case-M1-INT-008",
            "M1-INT-009" => "case-M1-INT-009",
            "M1-INT-010" => "case-M1-INT-010",
            "M1-INT-011" => "case-M1-INT-011",
            "M1-INT-012" => "case-M1-INT-012",
            _ => "case-unknown",
        }
    }
}

const fn case(
    id: &'static str,
    method: Method,
    reference: Reference,
    direction: Direction,
) -> CaseSpec {
    CaseSpec {
        id,
        method,
        reference,
        direction,
    }
}

use Direction::{FerrumClient as Ferrum, ReferenceClient as RefClient};
use Method::{Aes128Gcm as Aes128, Aes256Gcm as Aes256, ChaCha20Poly1305 as ChaCha};
use Reference::{ShadowsocksRust, SingBox};

pub const CASES: [CaseSpec; 12] = [
    case("M1-INT-001", Aes128, SingBox, Ferrum),
    case("M1-INT-002", Aes128, ShadowsocksRust, Ferrum),
    case("M1-INT-003", Aes128, SingBox, RefClient),
    case("M1-INT-004", Aes128, ShadowsocksRust, RefClient),
    case("M1-INT-005", Aes256, SingBox, Ferrum),
    case("M1-INT-006", Aes256, ShadowsocksRust, Ferrum),
    case("M1-INT-007", Aes256, SingBox, RefClient),
    case("M1-INT-008", Aes256, ShadowsocksRust, RefClient),
    case("M1-INT-009", ChaCha, SingBox, Ferrum),
    case("M1-INT-010", ChaCha, ShadowsocksRust, Ferrum),
    case("M1-INT-011", ChaCha, SingBox, RefClient),
    case("M1-INT-012", ChaCha, ShadowsocksRust, RefClient),
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
    results: [CaseResult; 12],
}

impl QualificationReport {
    pub fn success(&self) -> bool {
        self.results
            .iter()
            .all(|result| result.status == CaseStatus::Pass)
    }

    pub fn summary_lines(&self) -> [String; 12] {
        self.results.map(|result| match result.status {
            CaseStatus::Pass => format!("case_id={} status=PASS", result.case.id),
            CaseStatus::Fail(root) => format!(
                "case_id={} status=FAIL canonical_root={root}",
                result.case.id
            ),
        })
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

    let results = CASES.map(|case| {
        let status = match provision(case.reference) {
            Err(failure) => CaseStatus::Fail(failure.canonical_root),
            Ok(()) => match catch_unwind(AssertUnwindSafe(|| ops.run_case(case))) {
                Ok(Ok(())) => CaseStatus::Pass,
                Ok(Err(failure)) => CaseStatus::Fail(failure.canonical_root),
                Err(_) => CaseStatus::Fail(case.case_root()),
            },
        };
        CaseResult { case, status }
    });

    QualificationReport { results }
}

pub fn execute_hosted(
    context: &HostedContext<'_>,
    setup: SetupAvailability,
    ops: &mut impl QualificationOps,
) -> Result<QualificationReport, &'static str> {
    validate_hosted(context)?;
    Ok(execute_with_setup(setup, ops))
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
    pub github_sha: Option<&'a str>,
    pub head_sha: &'a str,
    pub checkout_clean: bool,
}

pub fn validate_hosted(context: &HostedContext<'_>) -> Result<(), &'static str> {
    if context.argument_count != 1 {
        return Err("qualification accepts no arguments");
    }
    if context.github_actions != Some("true") {
        return Err("qualification requires GitHub Actions");
    }
    if context.runner_os != Some("Linux") {
        return Err("qualification requires the fixed Linux runner");
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
