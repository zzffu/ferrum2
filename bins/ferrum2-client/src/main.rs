#![forbid(unsafe_code)]

mod cli;
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
        if cli.materialize {
            if let Err(error) = run::validate_prepared_materialization(prepared) {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
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
