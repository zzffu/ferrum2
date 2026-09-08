#![forbid(unsafe_code)]

mod cli;
mod dashboard;
mod run;

use std::process::ExitCode;

use clap::Parser as _;
use ferrum2_config::prepare_client;

use crate::cli::Cli;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(code as u8);
        }
    };
    if let Some(listen) = cli.dashboard_listen {
        let options = dashboard::Options {
            listen,
            token_file: cli
                .dashboard_token_file
                .expect("clap requires authentication"),
            details: cli.dashboard_details,
        };
        return match dashboard::run(cli.config, options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(code) => {
                eprintln!("error[{code}] dashboard: management failed");
                ExitCode::FAILURE
            }
        };
    }
    let prepared = match prepare_client(&cli.config) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if prepared.has_tun() && !cli::tun_target_supported() {
        eprintln!("error[config.semantic] tun: configuration value is invalid");
        return ExitCode::from(2);
    }
    if cli.check_config {
        if cli.materialize
            && let Err(error) = run::validate_prepared_materialization(prepared)
        {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
        println!("configuration valid");
        return ExitCode::SUCCESS;
    }

    let result = run::run_prepared(prepared);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
