use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ferrum2-server", version, about = "ferrum2 Shadowsocks server")]
pub(crate) struct Cli {
    /// Path to the TOML configuration.
    #[arg(long, value_name = "PATH")]
    pub(crate) config: PathBuf,

    /// Validate configuration without creating runtime resources.
    #[arg(long)]
    pub(crate) check_config: bool,

    /// Resolve fixed endpoints and load RuleSets during config validation.
    #[arg(long, requires = "check_config")]
    pub(crate) materialize: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Cli;

    #[test]
    fn materialize_requires_check_config() {
        assert!(
            Cli::try_parse_from(["ferrum2-server", "--config", "server.toml", "--materialize"])
                .is_err()
        );
    }

    #[test]
    fn check_config_accepts_optional_materialization() {
        let offline = Cli::try_parse_from([
            "ferrum2-server",
            "--config",
            "server.toml",
            "--check-config",
        ])
        .expect("offline check CLI");
        assert!(offline.check_config);
        assert!(!offline.materialize);

        let networked = Cli::try_parse_from([
            "ferrum2-server",
            "--config",
            "server.toml",
            "--check-config",
            "--materialize",
        ])
        .expect("materialized check CLI");
        assert!(networked.check_config);
        assert!(networked.materialize);
    }
}
