use serde_json::Value;

use crate::wire::{
    ConnectionCatalogView, ConnectionConditionView, ConnectionNameView, ConnectionRuleOrigin,
    ConnectionRuleView,
};

/// Only already-allowlisted configuration facts are admitted, never raw configuration.
pub(crate) fn catalog(id: u64, catalog: &Value, details: bool) -> ConnectionCatalogView {
    let names = |key: &str| {
        catalog[key]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, row)| {
                Some(ConnectionNameView {
                    index,
                    tag: row["tag"].as_str()?.to_owned(),
                })
            })
            .collect()
    };
    let rules = if details {
        catalog["route"]["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, row)| {
                let conditions = [
                    "inbound",
                    "network",
                    "protocol",
                    "rule_set",
                    "port",
                    "port_range",
                    "domain",
                    "domain_suffix",
                    "domain_keyword",
                    "ip",
                    "ip_cidr",
                ]
                .into_iter()
                .filter_map(|field| {
                    row.get(field).map(|value| ConnectionConditionView {
                        field: field.to_owned(),
                        value: value.clone(),
                    })
                })
                .collect();
                Some(ConnectionRuleView {
                    index,
                    origin: if row["origin"] == "inbound" {
                        ConnectionRuleOrigin::Inbound
                    } else {
                        ConnectionRuleOrigin::Configured
                    },
                    conditions,
                    action: row["action"].as_str()?.to_owned(),
                    outbound: row["outbound"].as_str().map(str::to_owned),
                    sniffers: row["sniffers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    ConnectionCatalogView {
        id: id.to_string(),
        rules,
        final_outbound: details
            .then(|| catalog["route"]["final"].as_str().map(str::to_owned))
            .flatten(),
        outbounds: names("outbounds"),
        inbounds: names("inbounds"),
    }
}
