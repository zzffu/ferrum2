use std::error::Error;
use std::fmt;

use crate::RuleCompileError;

/// Matcher carried by a valid SRS structure that Ferrum2 intentionally rejects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedSrsMatcher {
    QueryType,
    Network,
    DomainRegex,
    SourceIpCidr,
    SourcePort,
    SourcePortRange,
    Port,
    PortRange,
    ProcessName,
    ProcessPath,
    ProcessPathRegex,
    PackageName,
    PackageNameRegex,
    WifiSsid,
    WifiBssid,
    AdGuardDomain,
    NetworkType,
    NetworkIsExpensive,
    NetworkIsConstrained,
    NetworkInterfaceAddress,
    DefaultInterfaceAddress,
    LogicalRule,
    Invert,
}

impl UnsupportedSrsMatcher {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueryType => "query_type",
            Self::Network => "network",
            Self::DomainRegex => "domain_regex",
            Self::SourceIpCidr => "source_ip_cidr",
            Self::SourcePort => "source_port",
            Self::SourcePortRange => "source_port_range",
            Self::Port => "port",
            Self::PortRange => "port_range",
            Self::ProcessName => "process_name",
            Self::ProcessPath => "process_path",
            Self::ProcessPathRegex => "process_path_regex",
            Self::PackageName => "package_name",
            Self::PackageNameRegex => "package_name_regex",
            Self::WifiSsid => "wifi_ssid",
            Self::WifiBssid => "wifi_bssid",
            Self::AdGuardDomain => "adguard_domain",
            Self::NetworkType => "network_type",
            Self::NetworkIsExpensive => "network_is_expensive",
            Self::NetworkIsConstrained => "network_is_constrained",
            Self::NetworkInterfaceAddress => "network_interface_address",
            Self::DefaultInterfaceAddress => "default_interface_address",
            Self::LogicalRule => "logical",
            Self::Invert => "invert",
        }
    }
}

/// Stable SRS decoder failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SrsErrorKind {
    Io,
    InvalidMagic,
    UnsupportedVersion,
    Compression,
    Truncated,
    NonCanonicalVarint,
    IntegerOverflow,
    Allocation,
    InvalidRuleType,
    InvalidLogicalMode,
    LogicalDepth,
    InvalidItem,
    DuplicateItem,
    InvalidBoolean,
    InvalidUtf8,
    InvalidDomainSet,
    InvalidIpSet,
    UnsupportedMatcher,
    Empty,
    TrailingPayload,
    TrailingFileData,
    Compile,
}

impl SrsErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "ruleset.format.io",
            Self::InvalidMagic => "ruleset.format.magic",
            Self::UnsupportedVersion => "ruleset.format.version",
            Self::Compression => "ruleset.format.compression",
            Self::Truncated => "ruleset.format.truncated",
            Self::NonCanonicalVarint => "ruleset.format.varint",
            Self::IntegerOverflow => "ruleset.format.overflow",
            Self::Allocation => "rule.allocation",
            Self::InvalidRuleType => "ruleset.format.rule_type",
            Self::InvalidLogicalMode => "ruleset.format.logical_mode",
            Self::LogicalDepth => "ruleset.format.logical_depth",
            Self::InvalidItem => "ruleset.format.item",
            Self::DuplicateItem => "ruleset.format.duplicate_item",
            Self::InvalidBoolean => "ruleset.format.boolean",
            Self::InvalidUtf8 => "ruleset.format.utf8",
            Self::InvalidDomainSet => "ruleset.format.domain_set",
            Self::InvalidIpSet => "ruleset.format.ip_set",
            Self::UnsupportedMatcher => "ruleset.unsupported_matcher",
            Self::Empty => "ruleset.format.empty",
            Self::TrailingPayload => "ruleset.format.trailing_payload",
            Self::TrailingFileData => "ruleset.format.trailing_file_data",
            Self::Compile => "ruleset.compile",
        }
    }
}

/// Strict, value-redacted SRS decoding or compilation failure.
#[derive(Debug)]
pub struct SrsError {
    kind: SrsErrorKind,
    version: Option<u8>,
    rule_index: Option<u64>,
    item: Option<u8>,
    unsupported: Option<UnsupportedSrsMatcher>,
}

impl SrsError {
    pub(crate) const fn new(kind: SrsErrorKind) -> Self {
        Self {
            kind,
            version: None,
            rule_index: None,
            item: None,
            unsupported: None,
        }
    }

    pub(crate) const fn with_version(mut self, version: u8) -> Self {
        self.version = Some(version);
        self
    }

    pub(crate) const fn at_rule(mut self, rule_index: u64) -> Self {
        if self.rule_index.is_none() {
            self.rule_index = Some(rule_index);
        }
        self
    }

    pub(crate) const fn at_item(mut self, item: u8) -> Self {
        self.item = Some(item);
        self
    }

    pub(crate) const fn unsupported(
        matcher: UnsupportedSrsMatcher,
        version: u8,
        rule_index: u64,
    ) -> Self {
        Self {
            kind: SrsErrorKind::UnsupportedMatcher,
            version: Some(version),
            rule_index: Some(rule_index),
            item: None,
            unsupported: Some(matcher),
        }
    }

    pub const fn kind(&self) -> SrsErrorKind {
        self.kind
    }

    pub const fn version(&self) -> Option<u8> {
        self.version
    }

    pub const fn rule_index(&self) -> Option<u64> {
        self.rule_index
    }

    pub const fn item(&self) -> Option<u8> {
        self.item
    }

    pub const fn unsupported_matcher(&self) -> Option<UnsupportedSrsMatcher> {
        self.unsupported
    }
}

impl From<RuleCompileError> for SrsError {
    fn from(error: RuleCompileError) -> Self {
        let kind = match error {
            RuleCompileError::Allocation => SrsErrorKind::Allocation,
            _ => SrsErrorKind::Compile,
        };
        Self::new(kind)
    }
}

impl fmt::Display for SrsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "error[{}] rule-set", self.kind.code())?;
        if let Some(version) = self.version {
            write!(formatter, " version {version}")?;
        }
        if let Some(rule_index) = self.rule_index {
            write!(formatter, " rule[{rule_index}]")?;
        }
        if let Some(matcher) = self.unsupported {
            write!(formatter, ": unsupported matcher `{}`", matcher.as_str())
        } else if let Some(item) = self.item {
            write!(formatter, ": invalid item {item}")
        } else {
            formatter.write_str(": invalid binary SRS")
        }
    }
}

impl Error for SrsError {}
