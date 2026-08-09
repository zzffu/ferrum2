use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ferrum2-client", version, about = "ferrum2 SOCKS5 client")]
pub(crate) struct Cli {
    /// Path to the schema version 1 or 2 TOML configuration.
    #[arg(long, value_name = "PATH")]
    pub(crate) config: PathBuf,

    /// Validate configuration without creating runtime resources.
    #[arg(long)]
    pub(crate) check_config: bool,
}

/// Pure compile-target gate used before either offline success or runtime setup.
pub(crate) const fn tun_target_supported() -> bool {
    cfg!(all(windows, target_arch = "x86_64"))
}
