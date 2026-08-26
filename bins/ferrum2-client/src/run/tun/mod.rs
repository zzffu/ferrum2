mod network_lifecycle;
mod observation;
mod root;
mod tcp;
mod udp;

#[cfg(all(windows, not(test)))]
pub(in crate::run) use network_lifecycle::network_change_process_root;
pub(in crate::run) use network_lifecycle::{TunNetworkServices, network_reset_coordinator};
pub(in crate::run) use root::process_root;

#[cfg(test)]
mod tests;
