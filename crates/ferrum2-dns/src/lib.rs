#![forbid(unsafe_code)]

//! Bounded tagged DNS composition backed by Hickory.

mod error;
mod proxy;
mod resolver;
mod runtime_owner;
mod runtime_provider;

pub use error::DnsError;
pub use proxy::{DnsProxy, DnsProxyListeners, DnsProxySockets, ProxyIngress, ProxyTransport};
pub use resolver::{DnsUpstreamSpec, DnsUpstreamTransport};
pub use runtime_owner::{RuntimeStats, ShutdownReport, TaggedResolver, TaggedResolverOwner};
pub use runtime_provider::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsIoFuture, DnsResourceGuard, DnsTaskRegistrar, DnsTcpIo, SystemDnsEgress,
};
