use serde_json::Value;

/// Immutable generation metadata; concrete paths are supplied by the routing owner.
#[derive(Default)]
pub(crate) struct RouteCatalog {
    rules: Vec<Option<String>>,
    final_route: Option<String>,
    outbounds: Vec<Option<String>>,
}

impl RouteCatalog {
    pub(crate) fn new(catalog: &Value, details: bool) -> Self {
        let outbounds = catalog["outbounds"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|row| row["tag"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let rules = if details {
            catalog["route"]["rules"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .enumerate()
                        .map(|(index, row)| {
                            let fields = row.as_object()?;
                            let conditions = fields
                                .iter()
                                .filter(|(key, _)| {
                                    !matches!(
                                        key.as_str(),
                                        "action" | "outbound" | "server" | "sniffers"
                                    )
                                })
                                .map(|(key, value)| format!("{key}={value}"))
                                .collect::<Vec<_>>()
                                .join("；");
                            let action = fields.get("action")?.as_str()?;
                            let mut result = format!(
                                "规则 {}：{}；action={action}",
                                index + 1,
                                if conditions.is_empty() {
                                    "全部匹配"
                                } else {
                                    &conditions
                                }
                            );
                            for key in ["outbound", "server", "sniffers"] {
                                if let Some(value) = fields.get(key) {
                                    result.push_str(&format!("；{key}={value}"));
                                }
                            }
                            Some(result)
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let final_route = details
            .then(|| {
                catalog["route"]["final"]
                    .as_str()
                    .map(|tag| format!("默认路由（route.final）：{tag}"))
            })
            .flatten();
        Self {
            rules,
            final_route,
            outbounds,
        }
    }

    pub(crate) fn rule(&self, index: Option<usize>) -> Option<String> {
        match index {
            Some(index) => self.rules.get(index).cloned().flatten(),
            None => self.final_route.clone(),
        }
    }

    pub(crate) fn path(&self, hops: &[usize]) -> Option<String> {
        let mut result = String::new();
        for &hop in hops {
            let tag = self.outbounds.get(hop)?.as_deref()?;
            if !result.is_empty() {
                result.push_str(" → ");
            }
            result.push_str(tag);
        }
        (!result.is_empty()).then_some(result)
    }
}
