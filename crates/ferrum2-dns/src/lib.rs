#![forbid(unsafe_code)]

//! Bounded tagged DNS composition backed by Hickory.

mod error;
mod resolver;
mod runtime_owner;
mod runtime_provider;

pub use error::DnsError;
pub use runtime_owner::{RuntimeStats, ShutdownReport, TaggedResolver};
pub use runtime_provider::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsIoFuture, DnsTcpIo,
    PlanSnapshot, SystemDnsEgress,
};
