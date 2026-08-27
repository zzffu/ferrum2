use std::time::Duration;

use crate::Config;

pub(super) fn runtime_limits_are_exact(config: &Config) -> bool {
    (1..=4096).contains(&config.max_tcp_flows)
        && (4096..=262_144).contains(&config.tcp_buffer_bytes)
        && (Duration::from_secs(1)..=Duration::from_secs(86_400)).contains(&config.tcp_timeout)
        && (ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT..=ferrum2_runtime::MAX_UDP_IDLE_TIMEOUT)
            .contains(&config.udp_timeout)
        && (1..=8192).contains(&config.max_udp_mappings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UdpFiltering;

    fn valid_config() -> Config {
        Config {
            adapter_name: "test".into(),
            ipv4: None,
            ipv6: None,
            mtu: 1_500,
            ring_capacity: 1 << 20,
            ready_timeout: Duration::from_secs(1),
            max_tcp_flows: 1,
            tcp_buffer_bytes: 4_096,
            tcp_timeout: Duration::from_secs(1),
            udp_timeout: ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT,
            max_udp_mappings: 1,
            udp_filtering: UdpFiltering::EndpointIndependent,
            capture_routes: Vec::new(),
            physical_endpoints: Vec::new(),
            default_binder: false,
            ipv4_dns_address: None,
            ipv6_dns_address: None,
            strict_route: false,
        }
    }

    #[test]
    fn only_tun_owned_runtime_limits_are_checked_here() {
        assert!(runtime_limits_are_exact(&valid_config()));

        let mut invalid = valid_config();
        invalid.max_tcp_flows = 0;
        assert!(!runtime_limits_are_exact(&invalid));

        let mut invalid = valid_config();
        invalid.tcp_buffer_bytes = 262_145;
        assert!(!runtime_limits_are_exact(&invalid));

        let mut invalid = valid_config();
        invalid.tcp_timeout = Duration::from_secs(86_401);
        assert!(!runtime_limits_are_exact(&invalid));

        let mut invalid = valid_config();
        invalid.udp_timeout = ferrum2_runtime::MAX_UDP_IDLE_TIMEOUT + Duration::from_millis(1);
        assert!(!runtime_limits_are_exact(&invalid));

        let mut invalid = valid_config();
        invalid.max_udp_mappings = 8_193;
        assert!(!runtime_limits_are_exact(&invalid));
    }
}
