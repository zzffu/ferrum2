use crate::dimension::closed_dimension;

use std::fmt;
use std::fmt::Write as _;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use super::Metrics;
use super::family::{
    CachedCounter, CachedGauge, CachedHistogram, SharedClosedFamily, pair_index, pair_labels,
    single_labels, triple_index, triple_labels, u64_gauge, usize_gauge,
};

closed_dimension! {
    /// Closed outcomes for loading or refreshing a RuleSet.
    pub enum RuleSetResult {
        Success => "success",
        Failure => "failure",
        Unchanged => "unchanged",
    }
}

closed_dimension! {
    /// Closed matcher categories used by compiled RuleSet entry gauges.
    pub enum CompiledMatchType {
        Domain => "domain",
        DomainSuffix => "domain_suffix",
        DomainKeyword => "domain_keyword",
        IpCidr => "ip_cidr",
    }
}

closed_dimension! {
    /// Closed rule programs which share the matching engine.
    pub enum RuleProgram {
        Route => "route",
        DnsQuery => "dns_query",
        DnsResponse => "dns_response",
    }
}

closed_dimension! {
    /// Closed implementations available to a compiled rule program.
    pub enum RuleProgramMode {
        SmallLinear => "small_linear",
        Indexed => "indexed",
    }
}

closed_dimension! {
    /// Closed origins for route and DNS rule matchers.
    pub enum RuleSource {
        Inline => "inline",
        RuleSet => "rule_set",
    }
}

closed_dimension! {
    /// Closed rule matcher categories. No concrete value is accepted as a label.
    pub enum RuleMatchType {
        Domain => "domain",
        DomainSuffix => "domain_suffix",
        DomainKeyword => "domain_keyword",
        IpCidr => "ip_cidr",
        Scalar => "scalar",
    }
}

closed_dimension! {
    /// Closed results for one rule-matching source and category.
    pub enum RuleMatchResult {
        Matched => "matched",
        Missed => "missed",
    }
}

closed_dimension! {
    /// Closed resolver classes. Configured resolver tags are deliberately excluded.
    pub enum DnsResolverKind {
        System => "system",
        Configured => "configured",
    }
}

closed_dimension! {
    /// Closed purposes for DNS resolution.
    pub enum DnsResolvePurpose {
        Application => "application",
        FixedEndpoint => "fixed_endpoint",
        RuleSetDownload => "ruleset_download",
    }
}

closed_dimension! {
    /// Closed DNS resolution results.
    pub enum DnsResolveResult {
        Success => "success",
        Failure => "failure",
    }
}

closed_dimension! {
    /// Closed DNS query types used by the shared cache metrics.
    pub enum DnsQueryType {
        A => "a",
        Aaaa => "aaaa",
        Other => "other",
    }
}

closed_dimension! {
    /// Closed components whose dial targets may be resolved in different places.
    /// Concrete DNS server, RuleSet, domain, and URL identities are excluded.
    pub enum TargetResolutionComponent {
        DnsUpstream => "dns_upstream",
        RuleSetDownload => "ruleset_download",
    }
}

closed_dimension! {
    /// Closed locations at which a DNS upstream or RuleSet target is resolved.
    pub enum TargetResolutionMode {
        Numeric => "numeric",
        ClientResolvedSystem => "client_resolved_system",
        ClientResolvedConfigured => "client_resolved_configured",
        DeferredToDetour => "deferred_to_detour",
    }
}

macro_rules! impl_closed_display {
    ($type:ty) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

macro_rules! impl_label_value {
    ($type:ty) => {
        impl EncodeLabelValue for $type {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> fmt::Result {
                encoder.write_str(self.as_str())
            }
        }
    };
}

impl_closed_display!(RuleSetResult);
impl_closed_display!(CompiledMatchType);
impl_closed_display!(RuleProgram);
impl_closed_display!(RuleProgramMode);
impl_closed_display!(RuleSource);
impl_closed_display!(RuleMatchType);
impl_closed_display!(RuleMatchResult);
impl_closed_display!(DnsResolverKind);
impl_closed_display!(DnsResolvePurpose);
impl_closed_display!(DnsResolveResult);
impl_closed_display!(DnsQueryType);
impl_closed_display!(TargetResolutionComponent);
impl_closed_display!(TargetResolutionMode);
impl_label_value!(RuleSetResult);
impl_label_value!(CompiledMatchType);
impl_label_value!(RuleProgram);
impl_label_value!(RuleProgramMode);
impl_label_value!(RuleSource);
impl_label_value!(RuleMatchType);
impl_label_value!(RuleMatchResult);
impl_label_value!(DnsResolverKind);
impl_label_value!(DnsResolvePurpose);
impl_label_value!(DnsResolveResult);
impl_label_value!(DnsQueryType);
impl_label_value!(TargetResolutionComponent);
impl_label_value!(TargetResolutionMode);

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleSetResultLabels {
    result: RuleSetResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct CompiledMatchLabels {
    r#type: CompiledMatchType,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleProgramLabels {
    program: RuleProgram,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleProgramModeLabels {
    program: RuleProgram,
    mode: RuleProgramMode,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleMatchLabels {
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsResolveLabels {
    resolver: DnsResolverKind,
    purpose: DnsResolvePurpose,
    result: DnsResolveResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsQueryTypeLabels {
    qtype: DnsQueryType,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsResolvePurposeLabels {
    purpose: DnsResolvePurpose,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TargetResolutionLabels {
    component: TargetResolutionComponent,
    mode: TargetResolutionMode,
}

const RULE_PROGRAM_CANDIDATE_BUCKETS: &[f64] = &[
    0.0, 1.0, 4.0, 16.0, 64.0, 256.0, 1_024.0, 4_096.0, 16_384.0, 65_536.0,
];
const RULE_PROGRAM_MATCH_NS_BUCKETS: &[f64] = &[
    100.0,
    500.0,
    1_000.0,
    5_000.0,
    10_000.0,
    50_000.0,
    100_000.0,
    500_000.0,
    1_000_000.0,
    5_000_000.0,
    10_000_000.0,
];

const RULESET_RESULT_SERIES: usize = RuleSetResult::ALL.len();
const COMPILED_MATCH_SERIES: usize = CompiledMatchType::ALL.len();
const RULE_PROGRAM_SERIES: usize = RuleProgram::ALL.len();
const RULE_PROGRAM_MODE_SERIES: usize = RuleProgram::ALL.len() * RuleProgramMode::ALL.len();
const RULE_MATCH_SERIES: usize =
    RuleSource::ALL.len() * RuleMatchType::ALL.len() * RuleMatchResult::ALL.len();
const DNS_RESOLVE_SERIES: usize =
    DnsResolverKind::ALL.len() * DnsResolvePurpose::ALL.len() * DnsResolveResult::ALL.len();
const DNS_QUERY_TYPE_SERIES: usize = DnsQueryType::ALL.len();
const DNS_RESOLVE_PURPOSE_SERIES: usize = DnsResolvePurpose::ALL.len();
const TARGET_RESOLUTION_SERIES: usize =
    TargetResolutionComponent::ALL.len() * TargetResolutionMode::ALL.len();

type RuleSetResultFamily =
    SharedClosedFamily<RuleSetResultLabels, CachedCounter, RULESET_RESULT_SERIES>;
type CompiledMatchFamily =
    SharedClosedFamily<CompiledMatchLabels, CachedGauge, COMPILED_MATCH_SERIES>;
type RuleProgramGaugeFamily =
    SharedClosedFamily<RuleProgramLabels, CachedGauge, RULE_PROGRAM_SERIES>;
type RuleProgramHistogramFamily =
    SharedClosedFamily<RuleProgramLabels, CachedHistogram, RULE_PROGRAM_SERIES>;
type RuleProgramModeFamily =
    SharedClosedFamily<RuleProgramModeLabels, CachedGauge, RULE_PROGRAM_MODE_SERIES>;
type RuleMatchFamily = SharedClosedFamily<RuleMatchLabels, CachedCounter, RULE_MATCH_SERIES>;
type DnsResolveFamily = SharedClosedFamily<DnsResolveLabels, CachedCounter, DNS_RESOLVE_SERIES>;
type DnsQueryTypeFamily =
    SharedClosedFamily<DnsQueryTypeLabels, CachedCounter, DNS_QUERY_TYPE_SERIES>;
type DnsResolvePurposeFamily =
    SharedClosedFamily<DnsResolvePurposeLabels, CachedCounter, DNS_RESOLVE_PURPOSE_SERIES>;
type TargetResolutionFamily =
    SharedClosedFamily<TargetResolutionLabels, CachedCounter, TARGET_RESOLUTION_SERIES>;

pub(super) struct RulesDnsMetrics {
    ruleset_loads: RuleSetResultFamily,
    ruleset_refreshes: RuleSetResultFamily,
    ruleset_generation: Gauge,
    ruleset_compiled_entries: CompiledMatchFamily,
    ruleset_last_success_timestamp: Gauge,
    rule_program_mode: RuleProgramModeFamily,
    rule_program_rules: RuleProgramGaugeFamily,
    rule_program_candidate_count: RuleProgramHistogramFamily,
    rule_program_match_ns: RuleProgramHistogramFamily,
    route_matches: RuleMatchFamily,
    dns_rule_query_matches: RuleMatchFamily,
    dns_rule_response_matches: RuleMatchFamily,
    dns_resolves: DnsResolveFamily,
    dns_cache_hits: DnsQueryTypeFamily,
    dns_cache_misses: DnsQueryTypeFamily,
    dns_explicit_system_resolves: DnsResolvePurposeFamily,
    dns_implicit_system_fallbacks: Counter,
    target_resolutions: TargetResolutionFamily,
}

impl RulesDnsMetrics {
    pub(super) fn register(registry: &mut Registry) -> Self {
        let ruleset_loads = RuleSetResultFamily::new(single_labels(RuleSetResult::ALL, |result| {
            RuleSetResultLabels { result }
        }));
        let ruleset_refreshes =
            RuleSetResultFamily::new(single_labels(RuleSetResult::ALL, |result| {
                RuleSetResultLabels { result }
            }));
        let ruleset_generation = Gauge::default();
        let ruleset_compiled_entries =
            CompiledMatchFamily::new(single_labels(CompiledMatchType::ALL, |r#type| {
                CompiledMatchLabels { r#type }
            }));
        let ruleset_last_success_timestamp = Gauge::default();
        let rule_program_mode = RuleProgramModeFamily::new(pair_labels(
            RuleProgram::ALL,
            RuleProgramMode::ALL,
            |program, mode| RuleProgramModeLabels { program, mode },
        ));
        let rule_program_rules =
            RuleProgramGaugeFamily::new(single_labels(RuleProgram::ALL, |program| {
                RuleProgramLabels { program }
            }));
        let rule_program_candidate_count = RuleProgramHistogramFamily::new_with(
            single_labels(RuleProgram::ALL, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_CANDIDATE_BUCKETS.iter().copied()),
        );
        let rule_program_match_ns = RuleProgramHistogramFamily::new_with(
            single_labels(RuleProgram::ALL, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_MATCH_NS_BUCKETS.iter().copied()),
        );
        let make_rule_match_labels = || {
            triple_labels(
                RuleSource::ALL,
                RuleMatchType::ALL,
                RuleMatchResult::ALL,
                |source, r#type, result| RuleMatchLabels {
                    source,
                    r#type,
                    result,
                },
            )
        };
        let route_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_rule_query_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_rule_response_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_resolves = DnsResolveFamily::new(triple_labels(
            DnsResolverKind::ALL,
            DnsResolvePurpose::ALL,
            DnsResolveResult::ALL,
            |resolver, purpose, result| DnsResolveLabels {
                resolver,
                purpose,
                result,
            },
        ));
        let dns_cache_hits = DnsQueryTypeFamily::new(single_labels(DnsQueryType::ALL, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_cache_misses = DnsQueryTypeFamily::new(single_labels(DnsQueryType::ALL, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_explicit_system_resolves =
            DnsResolvePurposeFamily::new(single_labels(DnsResolvePurpose::ALL, |purpose| {
                DnsResolvePurposeLabels { purpose }
            }));
        let dns_implicit_system_fallbacks = Counter::default();
        let target_resolutions = TargetResolutionFamily::new(pair_labels(
            TargetResolutionComponent::ALL,
            TargetResolutionMode::ALL,
            |component, mode| TargetResolutionLabels { component, mode },
        ));

        registry.register(
            "ferrum2_ruleset_load",
            "RuleSet initial load outcomes aggregated without RuleSet identity",
            ruleset_loads.clone(),
        );
        registry.register(
            "ferrum2_ruleset_refresh",
            "RuleSet refresh outcomes aggregated without RuleSet identity",
            ruleset_refreshes.clone(),
        );
        registry.register(
            "ferrum2_ruleset_generation",
            "Current atomically published RuleSet snapshot generation",
            ruleset_generation.clone(),
        );
        registry.register(
            "ferrum2_ruleset_compiled_entries",
            "Compiled RuleSet entries aggregated by closed matcher type",
            ruleset_compiled_entries.clone(),
        );
        registry.register(
            "ferrum2_ruleset_last_success_timestamp",
            "Unix timestamp of the latest successful RuleSet load or refresh",
            ruleset_last_success_timestamp.clone(),
        );
        registry.register(
            "ferrum2_rule_program_mode",
            "One-hot selected implementation mode for each closed rule program",
            rule_program_mode.clone(),
        );
        registry.register(
            "ferrum2_rule_program_rules",
            "Compiled rule count for each closed rule program",
            rule_program_rules.clone(),
        );
        registry.register(
            "ferrum2_rule_program_candidate_count",
            "Candidate rule count per evaluation for each closed rule program",
            rule_program_candidate_count.clone(),
        );
        registry.register(
            "ferrum2_rule_program_match_ns",
            "Rule matching duration in nanoseconds for each closed rule program",
            rule_program_match_ns.clone(),
        );
        registry.register(
            "ferrum2_route_match",
            "Route matcher outcomes by closed source and matcher type",
            route_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_rule_query_match",
            "DNS query rule matcher outcomes by closed source and matcher type",
            dns_rule_query_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_rule_response_match",
            "DNS response rule matcher outcomes by closed source and matcher type",
            dns_rule_response_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_resolve",
            "DNS resolution outcomes by closed resolver class and purpose",
            dns_resolves.clone(),
        );
        registry.register(
            "ferrum2_dns_cache_hit",
            "Shared DNS cache hits aggregated across configured server identities",
            dns_cache_hits.clone(),
        );
        registry.register(
            "ferrum2_dns_cache_miss",
            "Shared DNS cache misses aggregated across configured server identities",
            dns_cache_misses.clone(),
        );
        registry.register(
            "ferrum2_dns_explicit_system_resolve",
            "Explicitly authorized system DNS resolutions by closed purpose",
            dns_explicit_system_resolves.clone(),
        );
        registry.register(
            "ferrum2_dns_implicit_system_fallback",
            "Invariant violations that attempted an implicit system DNS fallback",
            dns_implicit_system_fallbacks.clone(),
        );
        registry.register(
            "ferrum2_target_resolution",
            "Target resolution locations by closed component and mode",
            target_resolutions.clone(),
        );
        Self {
            ruleset_loads,
            ruleset_refreshes,
            ruleset_generation,
            ruleset_compiled_entries,
            ruleset_last_success_timestamp,
            rule_program_mode,
            rule_program_rules,
            rule_program_candidate_count,
            rule_program_match_ns,
            route_matches,
            dns_rule_query_matches,
            dns_rule_response_matches,
            dns_resolves,
            dns_cache_hits,
            dns_cache_misses,
            dns_explicit_system_resolves,
            dns_implicit_system_fallbacks,
            target_resolutions,
        }
    }
}

fn record_rule_match(
    family: &RuleMatchFamily,
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
) {
    record_rule_matches(family, source, r#type, result, 1);
}

fn record_rule_matches(
    family: &RuleMatchFamily,
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
    count: u64,
) {
    if count == 0 {
        return;
    }
    family
        .metric(triple_index(
            source.index(),
            r#type.index(),
            result.index(),
            RuleMatchType::ALL.len(),
            RuleMatchResult::ALL.len(),
        ))
        .inc_by(count);
}

impl Metrics {
    /// Records an initial RuleSet load without exposing its tag or source URL.
    pub fn ruleset_load(&self, result: RuleSetResult) {
        self.rules_dns.ruleset_loads.metric(result.index()).inc();
    }

    /// Records a RuleSet refresh without exposing its tag or source URL.
    pub fn ruleset_refresh(&self, result: RuleSetResult) {
        self.rules_dns
            .ruleset_refreshes
            .metric(result.index())
            .inc();
    }

    /// Sets the current fully published RuleSet snapshot generation.
    pub fn set_ruleset_generation(&self, generation: u64) {
        self.rules_dns.ruleset_generation.set(u64_gauge(generation));
    }

    /// Sets the aggregate compiled entry count for one closed matcher type.
    pub fn set_ruleset_compiled_entries(&self, r#type: CompiledMatchType, entries: usize) {
        self.rules_dns
            .ruleset_compiled_entries
            .metric(r#type.index())
            .set(usize_gauge(entries));
    }

    /// Sets the Unix timestamp of the latest successful RuleSet publication.
    pub fn set_ruleset_last_success_timestamp(&self, unix_seconds: u64) {
        self.rules_dns
            .ruleset_last_success_timestamp
            .set(u64_gauge(unix_seconds));
    }

    /// Selects one implementation mode for a closed rule program.
    ///
    /// Both mode series are updated as a one-hot pair, so a later mode change
    /// cannot leave the prior mode reporting `1`.
    pub fn set_rule_program_mode(&self, program: RuleProgram, selected: RuleProgramMode) {
        for mode in RuleProgramMode::ALL {
            self.rules_dns
                .rule_program_mode
                .metric(pair_index(
                    program.index(),
                    mode.index(),
                    RuleProgramMode::ALL.len(),
                ))
                .set(i64::from(*mode == selected));
        }
    }

    /// Sets the compiled rule count for a closed rule program.
    pub fn set_rule_program_rules(&self, program: RuleProgram, rules: usize) {
        self.rules_dns
            .rule_program_rules
            .metric(program.index())
            .set(usize_gauge(rules));
    }

    /// Observes the number of candidates considered by one program evaluation.
    pub fn observe_rule_program_candidate_count(&self, program: RuleProgram, candidates: usize) {
        self.rules_dns
            .rule_program_candidate_count
            .metric(program.index())
            .observe(candidates as f64);
    }

    /// Observes the matching duration of one program evaluation in nanoseconds.
    pub fn observe_rule_program_match_ns(&self, program: RuleProgram, match_ns: u64) {
        self.rules_dns
            .rule_program_match_ns
            .metric(program.index())
            .observe(match_ns as f64);
    }

    /// Records one route matcher result using closed, identity-free labels.
    pub fn route_match(&self, source: RuleSource, r#type: RuleMatchType, result: RuleMatchResult) {
        record_rule_match(&self.rules_dns.route_matches, source, r#type, result);
    }

    /// Records one DNS query-rule matcher result using closed labels.
    pub fn dns_rule_query_match(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
    ) {
        record_rule_match(
            &self.rules_dns.dns_rule_query_matches,
            source,
            r#type,
            result,
        );
    }

    /// Records a fixed aggregate of DNS query-rule matcher results.
    pub fn dns_rule_query_matches(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
        count: u64,
    ) {
        record_rule_matches(
            &self.rules_dns.dns_rule_query_matches,
            source,
            r#type,
            result,
            count,
        );
    }

    /// Records one DNS response-rule matcher result using closed labels.
    pub fn dns_rule_response_match(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
    ) {
        record_rule_match(
            &self.rules_dns.dns_rule_response_matches,
            source,
            r#type,
            result,
        );
    }

    /// Records a fixed aggregate of DNS response-rule matcher results.
    pub fn dns_rule_response_matches(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
        count: u64,
    ) {
        record_rule_matches(
            &self.rules_dns.dns_rule_response_matches,
            source,
            r#type,
            result,
            count,
        );
    }

    /// Records one DNS resolution without accepting a configured resolver tag.
    pub fn dns_resolve(
        &self,
        resolver: DnsResolverKind,
        purpose: DnsResolvePurpose,
        result: DnsResolveResult,
    ) {
        self.rules_dns
            .dns_resolves
            .metric(triple_index(
                resolver.index(),
                purpose.index(),
                result.index(),
                DnsResolvePurpose::ALL.len(),
                DnsResolveResult::ALL.len(),
            ))
            .inc();
    }

    /// Records a shared DNS cache hit without accepting a server identity.
    pub fn dns_cache_hit(&self, qtype: DnsQueryType) {
        self.rules_dns.dns_cache_hits.metric(qtype.index()).inc();
    }

    /// Records a shared DNS cache miss without accepting a server identity.
    pub fn dns_cache_miss(&self, qtype: DnsQueryType) {
        self.rules_dns.dns_cache_misses.metric(qtype.index()).inc();
    }

    /// Records an authorized use of the system resolver.
    ///
    /// Callers must use this only for system application mode or an explicit
    /// `domain_resolver`/`download_resolver = "system"` configuration.
    pub fn dns_explicit_system_resolve(&self, purpose: DnsResolvePurpose) {
        self.rules_dns
            .dns_explicit_system_resolves
            .metric(purpose.index())
            .inc();
    }

    /// Records an invariant violation that attempted an implicit system fallback.
    ///
    /// This is intentionally the only API which can increment the fallback
    /// counter. Normal resolution and explicit-system APIs leave it at zero.
    pub fn record_dns_implicit_system_fallback_violation(&self) {
        self.rules_dns.dns_implicit_system_fallbacks.inc();
    }

    /// Records where a DNS upstream or RuleSet dial target is resolved.
    ///
    /// The closed component and mode enums prevent target, resolver, detour,
    /// domain, URL, or configured-tag identities from becoming labels.
    pub fn target_resolution(
        &self,
        component: TargetResolutionComponent,
        mode: TargetResolutionMode,
    ) {
        self.rules_dns
            .target_resolutions
            .metric(pair_index(
                component.index(),
                mode.index(),
                TargetResolutionMode::ALL.len(),
            ))
            .inc();
    }
}
