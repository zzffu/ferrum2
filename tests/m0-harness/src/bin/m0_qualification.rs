#[path = "../external_support/mod.rs"]
mod external_support;
#[path = "../qualification/mod.rs"]
mod qualification;

use qualification::{
    DnsSetupAvailability, HostedContext, SetupAvailability, Transport, execute_dns_hosted,
    execute_hosted,
};
use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hosted qualification rejected: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args_os().collect();
    let dns_only = match arguments.as_slice() {
        [_] => false,
        [_, argument] if argument == "--dns-only" => true,
        _ => return Err("qualification accepts only --dns-only".to_owned()),
    };
    let head = git(&["rev-parse", "HEAD"])?;
    let status = git(&["status", "--porcelain=v1"])?;
    let argument_count = arguments.len();
    let github_actions = env::var("GITHUB_ACTIONS").ok();
    let runner_os = env::var("RUNNER_OS").ok();
    let run_id = env::var("GITHUB_RUN_ID").ok();
    let run_attempt = env::var("GITHUB_RUN_ATTEMPT").ok();
    let github_sha = env::var("GITHUB_SHA").ok();
    let sing_box_setup_status = env::var("M2_SING_BOX_SETUP_STATUS").ok();
    let shadowsocks_rust_setup_status = env::var("M2_SHADOWSOCKS_RUST_SETUP_STATUS").ok();
    let coredns_setup_status = env::var("M12_COREDNS_SETUP_STATUS").ok();
    let bind_setup_status = env::var("M12_BIND_SETUP_STATUS").ok();
    let context = HostedContext {
        argument_count,
        github_actions: github_actions.as_deref(),
        runner_os: runner_os.as_deref(),
        run_id: run_id.as_deref(),
        run_attempt: run_attempt.as_deref(),
        github_sha: github_sha.as_deref(),
        head_sha: head.trim(),
        checkout_clean: status.is_empty(),
    };
    let mut operations = external_support::HostedOperations::new();
    if dns_only {
        let setup = DnsSetupAvailability::from_provider_status(
            coredns_setup_status.as_deref(),
            bind_setup_status.as_deref(),
        );
        let report = execute_dns_hosted(&context, setup, &mut operations).map_err(str::to_owned)?;
        for line in report.summary_lines() {
            println!("{line}");
        }
        println!("{}", report.completion_line(&context));
        return report
            .success()
            .then_some(())
            .ok_or_else(|| "one or more required DNS cases failed".to_owned());
    }
    let setup = SetupAvailability::from_provider_status(
        sing_box_setup_status.as_deref(),
        shadowsocks_rust_setup_status.as_deref(),
    );
    let report = execute_hosted(&context, setup, &mut operations).map_err(str::to_owned)?;
    for transport in [Transport::Tcp, Transport::Udp] {
        for line in report.summary_lines(transport) {
            println!("{line}");
        }
        println!("{}", report.completion_line(transport, &context));
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
