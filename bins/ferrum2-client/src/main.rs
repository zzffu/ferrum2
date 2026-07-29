#![forbid(unsafe_code)]

mod cli;
mod run;

use std::process::ExitCode;

use clap::Parser as _;
use ferrum2_config::load_client;

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
    let config = match load_client(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if cli.check_config {
        println!("configuration valid");
        return ExitCode::SUCCESS;
    }

    match run::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
