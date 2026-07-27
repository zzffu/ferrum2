use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ferrum2-client", version, about = "ferrum2 SOCKS5 client")]
pub(crate) struct Cli {
    /// Path to the schema version 1 TOML configuration.
    #[arg(long, value_name = "PATH")]
    pub(crate) config: PathBuf,

    /// Validate configuration without creating runtime resources.
    #[arg(long)]
    pub(crate) check_config: bool,
}
