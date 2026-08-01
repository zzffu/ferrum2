mod m4_support;

use std::process::ExitCode;

fn main() -> ExitCode {
    match m4_support::run(std::env::args_os().skip(1)) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("M4 qualification rejected: {error}");
            ExitCode::FAILURE
        }
    }
}
