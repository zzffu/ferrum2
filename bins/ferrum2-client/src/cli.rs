use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ferrum2-client", version, about = "ferrum2 SOCKS5 client")]
pub(crate) struct Cli {
    /// Path to the schema version 2 TOML configuration.
    #[arg(long, value_name = "PATH")]
    pub(crate) config: PathBuf,

    /// Validate configuration without creating runtime resources.
    #[arg(long)]
    pub(crate) check_config: bool,

    /// Resolve and compile all schema-v2 resources during validation.
    #[arg(long, requires = "check_config")]
    pub(crate) materialize: bool,
}

/// Pure compile-target gate used before either offline success or runtime setup.
pub(crate) const fn tun_target_supported() -> bool {
    cfg!(all(windows, target_arch = "x86_64"))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Cli;

    #[test]
    fn materialize_requires_check_config() {
        let error =
            Cli::try_parse_from(["ferrum2-client", "--config", "client.toml", "--materialize"])
                .expect_err("standalone materialize must be rejected");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn materialize_with_check_config_is_accepted() {
        let cli = Cli::try_parse_from([
            "ferrum2-client",
            "--config",
            "client.toml",
            "--check-config",
            "--materialize",
        ])
        .expect("validation materialization arguments");
        assert!(cli.check_config);
        assert!(cli.materialize);
    }
}
