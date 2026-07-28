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
pub struct CaseSpec {
    pub id: &'static str,
    pub reference: Reference,
    pub direction: Direction,
}

impl CaseSpec {
    pub fn case_root(self) -> &'static str {
        match self.id {
            "M0-INT-001" => "case-M0-INT-001",
            "M0-INT-002" => "case-M0-INT-002",
            "M0-INT-003" => "case-M0-INT-003",
            "M0-INT-004" => "case-M0-INT-004",
            _ => "case-unknown",
        }
    }
}

pub const CASES: [CaseSpec; 4] = [
    CaseSpec {
        id: "M0-INT-001",
        reference: Reference::SingBox,
        direction: Direction::FerrumClient,
    },
    CaseSpec {
        id: "M0-INT-002",
        reference: Reference::ShadowsocksRust,
        direction: Direction::FerrumClient,
    },
    CaseSpec {
        id: "M0-INT-003",
        reference: Reference::SingBox,
        direction: Direction::ReferenceClient,
    },
    CaseSpec {
        id: "M0-INT-004",
        reference: Reference::ShadowsocksRust,
        direction: Direction::ReferenceClient,
    },
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
    results: [CaseResult; 4],
}

impl QualificationReport {
    pub fn success(&self) -> bool {
        self.results
            .iter()
            .all(|result| result.status == CaseStatus::Pass)
    }

    pub fn summary_lines(&self) -> [String; 4] {
        self.results.map(|result| match result.status {
            CaseStatus::Pass => format!("case_id={} status=PASS", result.case.id),
            CaseStatus::Fail(root) => format!(
                "case_id={} status=FAIL canonical_root={root}",
                result.case.id
            ),
        })
    }
}

pub fn execute(ops: &mut impl QualificationOps) -> QualificationReport {
    let sing_box = provision(ops, Reference::SingBox);
    let shadowsocks_rust = provision(ops, Reference::ShadowsocksRust);
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
    ops: &mut impl QualificationOps,
) -> Result<QualificationReport, &'static str> {
    validate_hosted(context)?;
    Ok(execute(ops))
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
