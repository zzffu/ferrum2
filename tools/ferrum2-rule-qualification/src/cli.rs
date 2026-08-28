use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use serde::Serialize;

#[cfg(test)]
use crate::measurement::allocation::allocator_test_lock;

pub(crate) const DEFAULT_SMOKE_SAMPLES: usize = 101;
pub(crate) const DEFAULT_QUALIFICATION_SAMPLES: usize = 101;
pub(crate) const MIN_SAMPLES: usize = 5;
pub(crate) const MAX_SAMPLES: usize = 1_001;
pub(crate) const MAX_BASE_ITERATIONS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Smoke,
    Qualification,
}

impl Profile {
    pub(crate) fn match_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![64, 65, 100],
            Self::Qualification => vec![64, 65, 100, 1_000, 10_000],
        }
    }

    pub(crate) fn route_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![1, 32, 64],
            Self::Qualification => vec![1, 32, 64, 1_000, 10_000],
        }
    }

    pub(crate) fn dns_rule_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![1],
            Self::Qualification => vec![1, 64, 65, 100, 1_000, 10_000],
        }
    }

    pub(crate) const fn default_samples(self) -> usize {
        match self {
            Self::Smoke => DEFAULT_SMOKE_SAMPLES,
            Self::Qualification => DEFAULT_QUALIFICATION_SAMPLES,
        }
    }

    pub(crate) const fn default_base_iterations(self) -> u64 {
        match self {
            Self::Smoke | Self::Qualification => 8_192,
        }
    }

    pub(crate) const fn includes_generated_binary_srs(self) -> bool {
        matches!(self, Self::Qualification)
    }
}

/// Reproducible rule and DNS-policy qualification runner.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    /// Bounded scenario matrix. Qualification adds the 1k/10k scales.
    #[arg(long, value_enum, default_value_t = Profile::Smoke)]
    pub profile: Profile,

    /// Explicitly append the expensive 100,000-value MatchSet scale.
    #[arg(long)]
    pub include_100k: bool,

    /// Odd or even independent timing samples retained verbatim in JSON.
    #[arg(long)]
    pub samples: Option<usize>,

    /// Base operations per timing sample; large programs are scaled down.
    #[arg(long)]
    pub iterations_per_sample: Option<u64>,

    /// Workspace containing Cargo.toml and tests/fixtures/srs.
    #[arg(long, default_value = ".")]
    pub workspace_root: PathBuf,

    /// Optionally write the exact stdout JSON bytes to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug)]
pub struct QualificationError(String);

impl QualificationError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for QualificationError {}

pub(crate) type Result<T> = std::result::Result<T, QualificationError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_bounded_and_one_hundred_thousand_is_opt_in() {
        let _guard = allocator_test_lock();
        assert_eq!(Profile::Smoke.match_sizes(), vec![64, 65, 100]);
        assert_eq!(
            Profile::Qualification.match_sizes(),
            vec![64, 65, 100, 1_000, 10_000]
        );
        assert!(!Profile::Qualification.match_sizes().contains(&100_000));
        assert_eq!(
            Profile::Qualification.route_sizes(),
            vec![1, 32, 64, 1_000, 10_000]
        );
        assert_eq!(Profile::Smoke.dns_rule_sizes(), vec![1]);
        assert_eq!(
            Profile::Qualification.dns_rule_sizes(),
            vec![1, 64, 65, 100, 1_000, 10_000]
        );
        assert_eq!(Profile::Smoke.default_samples(), 101);
        assert_eq!(Profile::Qualification.default_samples(), 101);
        assert!(!Profile::Smoke.includes_generated_binary_srs());
        assert!(Profile::Qualification.includes_generated_binary_srs());
    }
}
