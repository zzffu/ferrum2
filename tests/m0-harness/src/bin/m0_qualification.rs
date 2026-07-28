#[path = "../external_support/mod.rs"]
mod external_support;
#[path = "../qualification/mod.rs"]
mod qualification;

use qualification::{HostedContext, SetupAvailability, execute_hosted};
use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("m0 qualification rejected: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let head = git(&["rev-parse", "HEAD"])?;
    let status = git(&["status", "--porcelain=v1"])?;
    let argument_count = env::args_os().count();
    let github_actions = env::var("GITHUB_ACTIONS").ok();
    let runner_os = env::var("RUNNER_OS").ok();
    let github_sha = env::var("GITHUB_SHA").ok();
    let sing_box_setup_status = env::var("M0_SING_BOX_SETUP_STATUS").ok();
    let shadowsocks_rust_setup_status = env::var("M0_SHADOWSOCKS_RUST_SETUP_STATUS").ok();
    let context = HostedContext {
        argument_count,
        github_actions: github_actions.as_deref(),
        runner_os: runner_os.as_deref(),
        github_sha: github_sha.as_deref(),
        head_sha: head.trim(),
        checkout_clean: status.is_empty(),
    };
    let setup = SetupAvailability::from_provider_status(
        sing_box_setup_status.as_deref(),
        shadowsocks_rust_setup_status.as_deref(),
    );
    let mut operations = external_support::HostedOperations::new();
    let report = execute_hosted(&context, setup, &mut operations).map_err(str::to_owned)?;
    for line in report.summary_lines() {
        println!("{line}");
    }
    if report.success() {
        Ok(())
    } else {
        Err("one or more required cases failed".to_owned())
    }
}

fn git(arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .output()
        .map_err(|error| format!("fixed checkout identity probe did not start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "fixed checkout identity probe failed with {}",
            output.status
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "fixed checkout identity probe returned non-UTF-8 output".to_owned())
}
