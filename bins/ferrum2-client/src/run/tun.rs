use ferrum2_config::TunConfig;
use ferrum2_runtime::ProcessRoot;

use super::RunError;

pub(super) fn process_root(config: TunConfig) -> ProcessRoot<RunError> {
    ferrum2_tun::process_root(
        ferrum2_tun::Config {
            adapter_name: config.adapter_name,
            ipv4: config.ipv4_address.addr(),
            ipv4_prefix: config.ipv4_address.prefix_len(),
            ipv6: config.ipv6_address.addr(),
            ipv6_prefix: config.ipv6_address.prefix_len(),
            mtu: config.mtu,
            ring_capacity: config.ring_capacity,
            ready_timeout: config.ready_timeout,
            max_tcp_flows: config.max_tcp_flows,
            tcp_buffer_bytes: config.tcp_buffer_bytes,
            max_udp_mappings: config.max_udp_mappings,
            max_udp_buffered_bytes: config.max_udp_buffered_bytes,
            owned_buffer_bytes: config.owned_buffer_bytes,
        },
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
    )
}
