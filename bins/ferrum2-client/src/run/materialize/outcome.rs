use ferrum2_dns::{DnsCache, FixedEndpointMaterializeError};
use ferrum2_ruleset::{RuleSetLoadError, RuleSetLoadErrorKind};

use super::ruleset::{ClientV2RuntimeRoot, PendingClientV2Runtime};
use crate::run::RunError;

pub(super) enum MaterializedRuleSetPhase {
    Absent,
    Pending(Box<PendingClientV2Runtime>),
}

pub(in crate::run) struct MaterializedClientV2 {
    config: ferrum2_config::ValidatedClientConfig,
    rule_sets: MaterializedRuleSetPhase,
    cache: Option<DnsCache>,
}

pub(in crate::run) struct MaterializedRunParts {
    pub(in crate::run) config: ferrum2_config::ValidatedClientConfig,
    pub(in crate::run) materialization_root: Option<ClientV2RuntimeRoot>,
    pub(in crate::run) cache: Option<DnsCache>,
}

impl MaterializedClientV2 {
    pub(super) fn new(
        config: ferrum2_config::ValidatedClientConfig,
        rule_sets: MaterializedRuleSetPhase,
        cache: Option<DnsCache>,
    ) -> Self {
        Self {
            config,
            rule_sets,
            cache,
        }
    }

    pub(in crate::run) fn config(&self) -> &ferrum2_config::ValidatedClientConfig {
        &self.config
    }

    /// Completes materialized validation without transferring any background
    /// resource to the process supervisor.
    pub(in crate::run) fn validate_only(
        self,
    ) -> Result<ferrum2_config::ValidatedClientConfig, RunError> {
        let policy_validation = validate_dns_policy_adapter(&self.config);
        let Self {
            config,
            rule_sets,
            cache: _,
        } = self;
        drop(rule_sets);
        policy_validation?;
        Ok(config)
    }

    pub(in crate::run) async fn into_run_parts(self) -> Result<MaterializedRunParts, RunError> {
        let Self {
            config,
            rule_sets,
            cache,
        } = self;
        let materialization_root = rule_sets.into_runtime_root(&config).await?;
        Ok(MaterializedRunParts {
            config,
            materialization_root,
            cache,
        })
    }
}

pub(super) fn validate_dns_policy_adapter(
    config: &ferrum2_config::ValidatedClientConfig,
) -> Result<(), RunError> {
    let Some(binding) = config
        .dns_route
        .as_ref()
        .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
    else {
        return Ok(());
    };
    let registry = binding.registry();
    ferrum2_dns::DnsPolicyProgram::try_from_blueprint(
        binding.blueprint().clone(),
        &registry.snapshot(),
    )
    .map(drop)
    .map_err(crate::run::dns::run_error_for_dns_policy_compile)
}

pub(super) fn classify_config_materialization_error(
    error: ferrum2_config::ConfigError,
) -> RunError {
    match error.kind() {
        ferrum2_config::ConfigErrorKind::RuleCompile => RunError::RuleCompile,
        ferrum2_config::ConfigErrorKind::RuleAllocation => RunError::RuleAllocation,
        ferrum2_config::ConfigErrorKind::Io
        | ferrum2_config::ConfigErrorKind::TooLarge
        | ferrum2_config::ConfigErrorKind::Syntax
        | ferrum2_config::ConfigErrorKind::Semantic
        | ferrum2_config::ConfigErrorKind::DnsResolverRequired
        | ferrum2_config::ConfigErrorKind::DnsReservedResolverName
        | ferrum2_config::ConfigErrorKind::DnsDependencyCycle
        | ferrum2_config::ConfigErrorKind::ResourceMaterialization => {
            RunError::ConfigResourceMaterialization
        }
    }
}

pub(super) const fn classify_fixed_endpoint_error(
    error: FixedEndpointMaterializeError,
) -> RunError {
    match error {
        FixedEndpointMaterializeError::Resolve(_)
        | FixedEndpointMaterializeError::InvalidAnswer
        | FixedEndpointMaterializeError::NoCandidates
        | FixedEndpointMaterializeError::Cache(_) => RunError::DnsResolve,
        FixedEndpointMaterializeError::Allocation => RunError::RuleAllocation,
        FixedEndpointMaterializeError::DuplicateDnsServer
        | FixedEndpointMaterializeError::MissingResolver
        | FixedEndpointMaterializeError::InvalidDependencyOrder => {
            RunError::ConfigResourceMaterialization
        }
    }
}

pub(super) const fn classify_rule_set_load_error(error: RuleSetLoadError) -> RunError {
    classify_rule_set_load_error_kind(error.kind())
}

pub(super) const fn classify_rule_set_load_error_kind(kind: RuleSetLoadErrorKind) -> RunError {
    match kind {
        RuleSetLoadErrorKind::InvalidCacheName
        | RuleSetLoadErrorKind::InvalidSource
        | RuleSetLoadErrorKind::InvalidLoaderConfig => RunError::ConfigResourceMaterialization,
        RuleSetLoadErrorKind::CacheDirectory
        | RuleSetLoadErrorKind::CacheRead
        | RuleSetLoadErrorKind::CacheMetadata
        | RuleSetLoadErrorKind::CacheDigest
        | RuleSetLoadErrorKind::CacheWrite
        | RuleSetLoadErrorKind::NotModifiedWithoutCache => RunError::RuleSetCache,
        RuleSetLoadErrorKind::Download(_)
        | RuleSetLoadErrorKind::DownloadTimeout
        | RuleSetLoadErrorKind::DownloadBody
        | RuleSetLoadErrorKind::DownloadOverflow
        | RuleSetLoadErrorKind::Task => RunError::RuleSetDownload,
        RuleSetLoadErrorKind::Allocation => RunError::RuleAllocation,
        RuleSetLoadErrorKind::Decode(kind) => match kind {
            ferrum2_rule::srs::SrsErrorKind::UnsupportedMatcher => {
                RunError::RuleSetUnsupportedMatcher
            }
            ferrum2_rule::srs::SrsErrorKind::Allocation => RunError::RuleAllocation,
            ferrum2_rule::srs::SrsErrorKind::Compile => RunError::RuleSetCompile,
            _ => RunError::RuleSetFormat,
        },
        RuleSetLoadErrorKind::RegistryCompile | RuleSetLoadErrorKind::RegistryPublish => {
            RunError::RuleSetCompile
        }
    }
}

impl MaterializedRuleSetPhase {
    async fn into_runtime_root(
        self,
        config: &ferrum2_config::ValidatedClientConfig,
    ) -> Result<Option<ClientV2RuntimeRoot>, RunError> {
        let Self::Pending(pending) = self else {
            return Ok(None);
        };
        let registry = config.route.rule_registry().or_else(|| {
            config
                .dns_route
                .as_ref()
                .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
                .map(ferrum2_config::DnsPolicyBlueprintBinding::registry)
        });
        let Some(registry) = registry else {
            return Err(RunError::StartupProtocol);
        };
        (*pending).into_prepared_root(registry).await.map(Some)
    }
}
