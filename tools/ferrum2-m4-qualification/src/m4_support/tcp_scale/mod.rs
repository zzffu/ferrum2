mod contract;
mod execution;
mod flow;
mod outcome;
mod self_check;
mod setup;

pub(super) use contract::SCALE_PAYLOAD_BYTES;
pub(super) use outcome::run_scale;
pub(super) use self_check::run_scale_self_check;
