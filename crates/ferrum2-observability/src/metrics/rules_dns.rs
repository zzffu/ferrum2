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

/// Closed outcomes for loading or refreshing a RuleSet.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleSetResult {
    Success,
    Failure,
    Unchanged,
}

impl RuleSetResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Closed matcher categories used by compiled RuleSet entry gauges.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompiledMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
}

impl CompiledMatchType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain_suffix",
            Self::DomainKeyword => "domain_keyword",
            Self::IpCidr => "ip_cidr",
        }
    }
}

/// Closed rule programs which share the matching engine.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleProgram {
    Route,
    DnsQuery,
    DnsResponse,
}

impl RuleProgram {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::DnsQuery => "dns_query",
            Self::DnsResponse => "dns_response",
        }
    }
}

/// Closed implementations available to a compiled rule program.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleProgramMode {
    SmallLinear,
    Indexed,
}

impl RuleProgramMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SmallLinear => "small_linear",
            Self::Indexed => "indexed",
        }
    }
}

/// Closed origins for route and DNS rule matchers.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleSource {
    Inline,
    RuleSet,
}

impl RuleSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::RuleSet => "rule_set",
        }
    }
}

/// Closed rule matcher categories. No concrete value is accepted as a label.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Scalar,
}

impl RuleMatchType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain_suffix",
            Self::DomainKeyword => "domain_keyword",
            Self::IpCidr => "ip_cidr",
            Self::Scalar => "scalar",
        }
    }
}

/// Closed results for one rule-matching source and category.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleMatchResult {
    Matched,
    Missed,
}

impl RuleMatchResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Missed => "missed",
        }
    }
}

/// Closed resolver classes. Configured resolver tags are deliberately excluded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolverKind {
    System,
    Configured,
}

impl DnsResolverKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Configured => "configured",
        }
    }
}

/// Closed purposes for DNS resolution.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolvePurpose {
    Application,
    FixedEndpoint,
    RuleSetDownload,
}

impl DnsResolvePurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::FixedEndpoint => "fixed_endpoint",
            Self::RuleSetDownload => "ruleset_download",
        }
    }
}

/// Closed DNS resolution results.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolveResult {
    Success,
    Failure,
}

impl DnsResolveResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed DNS query types used by the shared cache metrics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Other,
}

impl DnsQueryType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Other => "other",
        }
    }
}

/// Closed components whose dial targets may be resolved in different places.
/// Concrete DNS server, RuleSet, domain, and URL identities are excluded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetResolutionComponent {
    DnsUpstream,
    RuleSetDownload,
}

impl TargetResolutionComponent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DnsUpstream => "dns_upstream",
            Self::RuleSetDownload => "ruleset_download",
        }
    }
}

/// Closed locations at which a DNS upstream or RuleSet target is resolved.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetResolutionMode {
    Numeric,
    ClientResolvedSystem,
    ClientResolvedConfigured,
    DeferredToDetour,
}

impl TargetResolutionMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Numeric => "numeric",
            Self::ClientResolvedSystem => "client_resolved_system",
            Self::ClientResolvedConfigured => "client_resolved_configured",
            Self::DeferredToDetour => "deferred_to_detour",
        }
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

const RULESET_RESULTS: &[RuleSetResult] = &[
    RuleSetResult::Success,
    RuleSetResult::Failure,
    RuleSetResult::Unchanged,
];
const COMPILED_MATCH_TYPES: &[CompiledMatchType] = &[
    CompiledMatchType::Domain,
    CompiledMatchType::DomainSuffix,
    CompiledMatchType::DomainKeyword,
    CompiledMatchType::IpCidr,
];
const RULE_PROGRAMS: &[RuleProgram] = &[
    RuleProgram::Route,
    RuleProgram::DnsQuery,
    RuleProgram::DnsResponse,
];
const RULE_PROGRAM_MODES: &[RuleProgramMode] =
    &[RuleProgramMode::SmallLinear, RuleProgramMode::Indexed];
const RULE_SOURCES: &[RuleSource] = &[RuleSource::Inline, RuleSource::RuleSet];
const RULE_MATCH_TYPES: &[RuleMatchType] = &[
    RuleMatchType::Domain,
    RuleMatchType::DomainSuffix,
    RuleMatchType::DomainKeyword,
    RuleMatchType::IpCidr,
    RuleMatchType::Scalar,
];
const RULE_MATCH_RESULTS: &[RuleMatchResult] = &[RuleMatchResult::Matched, RuleMatchResult::Missed];
const DNS_RESOLVER_KINDS: &[DnsResolverKind] =
    &[DnsResolverKind::System, DnsResolverKind::Configured];
const DNS_RESOLVE_PURPOSES: &[DnsResolvePurpose] = &[
    DnsResolvePurpose::Application,
    DnsResolvePurpose::FixedEndpoint,
    DnsResolvePurpose::RuleSetDownload,
];
const DNS_RESOLVE_RESULTS: &[DnsResolveResult] =
    &[DnsResolveResult::Success, DnsResolveResult::Failure];
const DNS_QUERY_TYPES: &[DnsQueryType] =
    &[DnsQueryType::A, DnsQueryType::Aaaa, DnsQueryType::Other];
const TARGET_RESOLUTION_COMPONENTS: &[TargetResolutionComponent] = &[
    TargetResolutionComponent::DnsUpstream,
    TargetResolutionComponent::RuleSetDownload,
];
const TARGET_RESOLUTION_MODES: &[TargetResolutionMode] = &[
    TargetResolutionMode::Numeric,
    TargetResolutionMode::ClientResolvedSystem,
    TargetResolutionMode::ClientResolvedConfigured,
    TargetResolutionMode::DeferredToDetour,
];

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

const RULESET_RESULT_SERIES: usize = RULESET_RESULTS.len();
const COMPILED_MATCH_SERIES: usize = COMPILED_MATCH_TYPES.len();
const RULE_PROGRAM_SERIES: usize = RULE_PROGRAMS.len();
const RULE_PROGRAM_MODE_SERIES: usize = RULE_PROGRAMS.len() * RULE_PROGRAM_MODES.len();
const RULE_MATCH_SERIES: usize =
    RULE_SOURCES.len() * RULE_MATCH_TYPES.len() * RULE_MATCH_RESULTS.len();
const DNS_RESOLVE_SERIES: usize =
    DNS_RESOLVER_KINDS.len() * DNS_RESOLVE_PURPOSES.len() * DNS_RESOLVE_RESULTS.len();
const DNS_QUERY_TYPE_SERIES: usize = DNS_QUERY_TYPES.len();
const DNS_RESOLVE_PURPOSE_SERIES: usize = DNS_RESOLVE_PURPOSES.len();
const TARGET_RESOLUTION_SERIES: usize =
    TARGET_RESOLUTION_COMPONENTS.len() * TARGET_RESOLUTION_MODES.len();

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
        let ruleset_loads = RuleSetResultFamily::new(single_labels(RULESET_RESULTS, |result| {
            RuleSetResultLabels { result }
        }));
        let ruleset_refreshes =
            RuleSetResultFamily::new(single_labels(RULESET_RESULTS, |result| {
                RuleSetResultLabels { result }
            }));
        let ruleset_generation = Gauge::default();
        let ruleset_compiled_entries =
            CompiledMatchFamily::new(single_labels(COMPILED_MATCH_TYPES, |r#type| {
                CompiledMatchLabels { r#type }
            }));
        let ruleset_last_success_timestamp = Gauge::default();
        let rule_program_mode = RuleProgramModeFamily::new(pair_labels(
            RULE_PROGRAMS,
            RULE_PROGRAM_MODES,
            |program, mode| RuleProgramModeLabels { program, mode },
        ));
        let rule_program_rules =
            RuleProgramGaugeFamily::new(single_labels(RULE_PROGRAMS, |program| {
                RuleProgramLabels { program }
            }));
        let rule_program_candidate_count = RuleProgramHistogramFamily::new_with(
            single_labels(RULE_PROGRAMS, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_CANDIDATE_BUCKETS.iter().copied()),
        );
        let rule_program_match_ns = RuleProgramHistogramFamily::new_with(
            single_labels(RULE_PROGRAMS, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_MATCH_NS_BUCKETS.iter().copied()),
        );
        let make_rule_match_labels = || {
            triple_labels(
                RULE_SOURCES,
                RULE_MATCH_TYPES,
                RULE_MATCH_RESULTS,
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
            DNS_RESOLVER_KINDS,
            DNS_RESOLVE_PURPOSES,
            DNS_RESOLVE_RESULTS,
            |resolver, purpose, result| DnsResolveLabels {
                resolver,
                purpose,
                result,
            },
        ));
        let dns_cache_hits = DnsQueryTypeFamily::new(single_labels(DNS_QUERY_TYPES, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_cache_misses = DnsQueryTypeFamily::new(single_labels(DNS_QUERY_TYPES, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_explicit_system_resolves =
            DnsResolvePurposeFamily::new(single_labels(DNS_RESOLVE_PURPOSES, |purpose| {
                DnsResolvePurposeLabels { purpose }
            }));
        let dns_implicit_system_fallbacks = Counter::default();
        let target_resolutions = TargetResolutionFamily::new(pair_labels(
            TARGET_RESOLUTION_COMPONENTS,
            TARGET_RESOLUTION_MODES,
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
            source as usize,
            r#type as usize,
            result as usize,
            RULE_MATCH_TYPES.len(),
            RULE_MATCH_RESULTS.len(),
        ))
        .inc_by(count);
}

impl Metrics {
    /// Records an initial RuleSet load without exposing its tag or source URL.
    pub fn ruleset_load(&self, result: RuleSetResult) {
        self.rules_dns.ruleset_loads.metric(result as usize).inc();
    }

    /// Records a RuleSet refresh without exposing its tag or source URL.
    pub fn ruleset_refresh(&self, result: RuleSetResult) {
        self.rules_dns
            .ruleset_refreshes
            .metric(result as usize)
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
            .metric(r#type as usize)
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
        for mode in RULE_PROGRAM_MODES {
            self.rules_dns
                .rule_program_mode
                .metric(pair_index(
                    program as usize,
                    *mode as usize,
                    RULE_PROGRAM_MODES.len(),
                ))
                .set(i64::from(*mode == selected));
        }
    }

    /// Sets the compiled rule count for a closed rule program.
    pub fn set_rule_program_rules(&self, program: RuleProgram, rules: usize) {
        self.rules_dns
            .rule_program_rules
            .metric(program as usize)
            .set(usize_gauge(rules));
    }

    /// Observes the number of candidates considered by one program evaluation.
    pub fn observe_rule_program_candidate_count(&self, program: RuleProgram, candidates: usize) {
        self.rules_dns
            .rule_program_candidate_count
            .metric(program as usize)
            .observe(candidates as f64);
    }

    /// Observes the matching duration of one program evaluation in nanoseconds.
    pub fn observe_rule_program_match_ns(&self, program: RuleProgram, match_ns: u64) {
        self.rules_dns
            .rule_program_match_ns
            .metric(program as usize)
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
                resolver as usize,
                purpose as usize,
                result as usize,
                DNS_RESOLVE_PURPOSES.len(),
                DNS_RESOLVE_RESULTS.len(),
            ))
            .inc();
    }

    /// Records a shared DNS cache hit without accepting a server identity.
    pub fn dns_cache_hit(&self, qtype: DnsQueryType) {
        self.rules_dns.dns_cache_hits.metric(qtype as usize).inc();
    }

    /// Records a shared DNS cache miss without accepting a server identity.
    pub fn dns_cache_miss(&self, qtype: DnsQueryType) {
        self.rules_dns.dns_cache_misses.metric(qtype as usize).inc();
    }

    /// Records an authorized use of the system resolver.
    ///
    /// Callers must use this only for system application mode or an explicit
    /// `domain_resolver`/`download_resolver = "system"` configuration.
    pub fn dns_explicit_system_resolve(&self, purpose: DnsResolvePurpose) {
        self.rules_dns
            .dns_explicit_system_resolves
            .metric(purpose as usize)
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
                component as usize,
                mode as usize,
                TARGET_RESOLUTION_MODES.len(),
            ))
            .inc();
    }
}
