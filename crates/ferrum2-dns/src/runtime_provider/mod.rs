mod admission;
mod egress;
mod hickory;
mod tracking;

pub use egress::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsIoFuture, DnsTcpIo,
    SystemDnsEgress,
};
pub use tracking::{DnsEgressResourceKind, DnsEgressTaskKind, DnsResourceGuard, DnsTaskRegistrar};

pub(crate) use admission::{DNS_QUERY_SCOPE, DnsQueryContext, RuntimeCounters};
pub(crate) use egress::hickory_placeholder;
pub(crate) use hickory::FerrumRuntimeProvider;
pub(crate) use tracking::TaskSet;

#[cfg(test)]
mod tests;
