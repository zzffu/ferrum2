use crate::model::{ClientOutboundConfig, UdpConfig};

use super::model::{
    DialEndpoint, PreparedClientOutboundDescriptor, PreparedClientOutboundKind, PreparedClientV2,
    PreparedDependencyNode, PreparedDnsEndpoint, PreparedFixedEndpointDescriptor,
    PreparedFixedEndpointTarget, PreparedServerOutboundDescriptor, PreparedServerV2,
};

impl PreparedClientV2 {
    /// Reports whether a validated TUN is present without exposing its values.
    pub fn has_tun(&self) -> bool {
        self.validated.tun.is_some()
    }

    /// Reports whether the validated TUN requests automatic route installation.
    /// Configurations without a TUN deliberately return `false`.
    pub fn tun_auto_route(&self) -> bool {
        self.validated
            .tun
            .as_ref()
            .is_some_and(|tun| tun.auto_route)
    }

    /// Reports the source-level strict-route request, including an ineffective request.
    pub fn tun_strict_route_requested(&self) -> bool {
        self.validated
            .tun
            .as_ref()
            .is_some_and(|tun| tun.strict_route_requested())
    }

    /// Reports the effective strict-route value after applying the automatic-route gate.
    pub fn tun_strict_route_effective(&self) -> bool {
        self.validated
            .tun
            .as_ref()
            .is_some_and(|tun| tun.strict_route_effective())
    }

    pub fn outbound_endpoints(&self) -> &[Option<DialEndpoint>] {
        &self.outbound_endpoints
    }

    pub const fn udp(&self) -> Option<UdpConfig> {
        self.validated.udp
    }

    pub fn outbound_count(&self) -> usize {
        self.validated.outbounds.len()
    }

    pub fn outbound(&self, index: u32) -> Option<PreparedClientOutboundDescriptor<'_>> {
        let index_usize = usize::try_from(index).ok()?;
        let outbound = self.validated.outbounds.get(index_usize)?;
        let endpoint = self.outbound_endpoints.get(index_usize)?.as_ref();
        let (kind, psk) = match outbound {
            ClientOutboundConfig::Direct { .. } => (PreparedClientOutboundKind::Direct, None),
            ClientOutboundConfig::Shadowsocks { psk, .. } => {
                (PreparedClientOutboundKind::Shadowsocks, Some(psk))
            }
        };
        Some(PreparedClientOutboundDescriptor {
            index,
            kind,
            method: outbound.method(),
            psk,
            endpoint,
            domain_resolver: outbound.direct_domain_resolver(),
            dial_options: outbound.dial_options(),
        })
    }

    pub fn fixed_endpoint_for_node(
        &self,
        node: PreparedDependencyNode,
    ) -> Option<PreparedFixedEndpointDescriptor<'_>> {
        match node {
            PreparedDependencyNode::DnsServer(index) => self
                .dns_endpoints
                .get(usize::try_from(index).ok()?)
                .and_then(PreparedDnsEndpoint::fixed_endpoint)
                .map(|endpoint| {
                    PreparedFixedEndpointDescriptor::new(
                        PreparedFixedEndpointTarget::DnsServer(index),
                        endpoint,
                    )
                }),
            PreparedDependencyNode::Outbound(index) => self
                .outbound_endpoints
                .get(usize::try_from(index).ok()?)?
                .as_ref()
                .map(|endpoint| {
                    PreparedFixedEndpointDescriptor::new(
                        PreparedFixedEndpointTarget::Outbound(index),
                        endpoint,
                    )
                }),
            _ => None,
        }
    }
}

impl PreparedServerV2 {
    pub const fn udp(&self) -> UdpConfig {
        self.validated.udp
    }

    pub fn outbound_count(&self) -> usize {
        self.validated.outbounds.len()
    }

    pub fn outbound(&self, index: u32) -> Option<PreparedServerOutboundDescriptor<'_>> {
        let outbound = self.validated.outbounds.get(usize::try_from(index).ok()?)?;
        Some(PreparedServerOutboundDescriptor {
            index,
            domain_resolver: outbound.domain_resolver,
            dial_options: &outbound.dial_options,
        })
    }

    pub fn fixed_endpoint_for_node(
        &self,
        node: PreparedDependencyNode,
    ) -> Option<PreparedFixedEndpointDescriptor<'_>> {
        let PreparedDependencyNode::DnsServer(index) = node else {
            return None;
        };
        self.dns_endpoints
            .get(usize::try_from(index).ok()?)
            .and_then(PreparedDnsEndpoint::fixed_endpoint)
            .map(|endpoint| {
                PreparedFixedEndpointDescriptor::new(
                    PreparedFixedEndpointTarget::DnsServer(index),
                    endpoint,
                )
            })
    }
}
