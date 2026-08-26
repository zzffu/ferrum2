pub(super) mod v2;
pub(crate) use v2::validate_version;

const MAX_INTERFACE_NAME_UTF16_UNITS: usize = 256;

mod client;
mod common;
mod graph;
mod server;
mod tun;

pub(super) use client::validate_client_prepared;
pub(super) use common::validate_direct_domain_resolver;
pub(super) use common::validate_tag;
pub(super) use server::validate_server_prepared;
pub(super) use tun::{finish_client_tun_targets, validate_finished_client_endpoints};
