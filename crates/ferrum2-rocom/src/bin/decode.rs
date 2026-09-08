use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "ferrum2-rocom-decode",
    about = "Decode sensitive Ferrum2 rocom evidence offline"
)]
struct Arguments {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    proto_dir: Option<PathBuf>,
}
fn main() -> ExitCode {
    // clap's usual invalid-value diagnostics can echo sensitive path arguments.
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            eprintln!("rocom_decode: cli_arguments");
            return ExitCode::from(2);
        }
    };
    match ferrum2_rocom::decode::run(
        &arguments.input,
        &arguments.output,
        arguments.proto_dir.as_deref(),
    ) {
        Ok(report) => {
            eprintln!(
                "rocom_decode: messages={} failed={} integrity_errors={} complete={}",
                report.messages, report.failed, report.integrity_errors, report.complete
            );
            ExitCode::from(report.exit_code())
        }
        Err(error) => {
            eprintln!("rocom_decode: {error}");
            ExitCode::FAILURE
        }
    }
}
