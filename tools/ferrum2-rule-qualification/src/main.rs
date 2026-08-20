use std::process::ExitCode;

use clap::Parser;
use ferrum2_rule_qualification::{Args, execute};

fn main() -> ExitCode {
    match execute(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rule qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}
