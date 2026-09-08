mod association;
mod direct;
mod direct_association;
mod f2p;
mod lease;
mod prepare;
mod proxy;
mod request;
mod response;
mod socket;

pub(super) use association::MAX_UDP_PLAN_HOPS;
pub(in crate::run) use association::{ClientUdpAssociation, ClientUdpContext};
#[cfg(test)]
pub(in crate::run::egress) use direct::send_direct_target;
pub(in crate::run) use request::composed_udp_plan_limit;
#[cfg(test)]
pub(in crate::run) use request::{composed_udp_request_limit, composed_udp_response_limit};
pub(in crate::run) use response::UdpPlanResponseError;
pub(in crate::run) use socket::ClientUdpSocketFactory;
#[cfg(test)]
pub(in crate::run) use socket::{
    IdSequenceRandom, InjectedUdpSocketTrace, UdpIoFaultPlan, UdpIoOperation,
};

#[cfg(test)]
mod tests;

pub(in crate::run) use prepare::prepare;
