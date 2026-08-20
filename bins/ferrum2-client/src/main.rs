#![forbid(unsafe_code)]

mod cli;
mod run;

use std::process::ExitCode;

use clap::Parser as _;
use ferrum2_config::{PreparedClientConfig, prepare_client};

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
    let has_tun = match &prepared {
        PreparedClientConfig::V1(config) => config.tun.is_some(),
        PreparedClientConfig::V2(prepared) => prepared.has_tun(),
    };
    if has_tun && !cli::tun_target_supported() {
        eprintln!("error[config.semantic] tun: configuration value is invalid");
        return ExitCode::from(2);
    }
    if cli.check_config {
        if cli.materialize {
            let result = match prepared {
                PreparedClientConfig::V1(_) => Ok(()),
                PreparedClientConfig::V2(prepared) => {
                    run::validate_prepared_materialization(*prepared)
                }
            };
            if let Err(error) = result {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        }
        println!("configuration valid");
        return ExitCode::SUCCESS;
    }

    let result = match prepared {
        PreparedClientConfig::V1(config) => run::run(*config),
        PreparedClientConfig::V2(prepared) => run::run_prepared(*prepared),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
