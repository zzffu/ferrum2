#![forbid(unsafe_code)]

mod cli;
mod dns_policy;
mod execute;
mod match_set {
    pub(crate) mod benchmark;
    pub(crate) mod generated;
    pub(crate) mod srs;
    #[cfg(test)]
    mod tests;
}
mod measurement {
    pub(crate) mod allocation;
    pub(crate) mod statistics;
    pub(crate) mod timing;
}
mod report;
mod route_program;

pub use cli::{Args, Profile, QualificationError};
pub use execute::execute;
