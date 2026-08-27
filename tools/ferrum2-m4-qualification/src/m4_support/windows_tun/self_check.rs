mod cli_contract;
mod diagnostic;
mod workload;

use super::support::self_check_support_backlog;

const SELF_CHECK_DIAGNOSTIC_TRIAL_SEQUENCE: u16 = 43;

pub(crate) fn run_self_check() -> Result<(), String> {
    cli_contract::check()?;
    let payload = workload::check_basics()?;
    diagnostic::check()?;
    workload::check_recipe(&payload)?;
    self_check_support_backlog()
}
