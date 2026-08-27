//! Fortress Engineering Standard registry primitives.
//!
//! The registry exposes stable rule metadata independently from repository
//! observation, execution, certification, and presentation.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

use crate::finding::FindingCategory;
use crate::identity::{RuleId, RuleIdError, StableId, StableIdError};

const DRAFT_RULES: &[RuleDescriptor] = &[
    RuleDescriptor {
        id: "STD-ID-001",
        title: "Stable serialized identity",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "ARCH-DEPENDENCY-001",
        title: "Acyclic declared component dependencies",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "ARCH-OWNERSHIP-001",
        title: "Exact declared repository file ownership",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
];

/// Release state of a rule exposed by a standard registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleStatus {
    /// The rule is mutable pre-release work and cannot support a stable claim.
    Draft,
    /// The rule is a release candidate awaiting final gates and authorization.
    Candidate,
    /// The rule belongs to an immutable released standard edition.
    Released,
    /// The rule remains addressable for history but is no longer active.
    Retired,
}

/// Minimal discoverable metadata for a Fortress rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleDescriptor {
    id: &'static str,
    title: &'static str,
    status: RuleStatus,
    integrity_tier: u8,
}

impl RuleDescriptor {
    /// Returns the stable public rule identity.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Returns the human-readable rule title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        self.title
    }

    /// Returns the rule release state.
    #[must_use]
    pub const fn status(&self) -> RuleStatus {
        self.status
    }

    /// Returns the rule integrity tier from zero through four.
    #[must_use]
    pub const fn integrity_tier(&self) -> u8 {
        self.integrity_tier
    }
}

/// Read-only registry for one precise Fortress Engineering Standard identity.
#[derive(Clone, Copy, Debug)]
pub struct StandardRegistry {
    edition: &'static str,
    status: RuleStatus,
    rules: &'static [RuleDescriptor],
}

impl StandardRegistry {
    /// Returns the initial draft path toward Fortress Engineering Standard
    /// 1.0.0.
    #[must_use]
    pub const fn draft_1_0() -> Self {
        Self {
            edition: "1.0.0-draft.1",
            status: RuleStatus::Draft,
            rules: DRAFT_RULES,
        }
    }

    /// Returns the exact standard edition identity.
    #[must_use]
    pub const fn edition(&self) -> &'static str {
        self.edition
    }

    /// Returns the standard bundle status.
    #[must_use]
    pub const fn status(&self) -> RuleStatus {
        self.status
    }

    /// Iterates through registered rules in canonical manifest order.
    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &RuleDescriptor> {
        self.rules.iter()
    }

    /// Finds a registered rule by exact stable identity.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&RuleDescriptor> {
        self.rules.iter().find(|rule| rule.id == id)
    }

    /// Validates registered rule identities, uniqueness, and integrity tiers.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] for an invalid ID, duplicate ID, or tier
    /// outside the zero-through-four range.
    pub fn validate(&self) -> Result<(), RegistryError> {
        for (index, rule) in self.rules.iter().enumerate() {
            RuleId::parse(rule.id).map_err(|source| RegistryError::InvalidRuleId {
                id: rule.id,
                source,
            })?;

            if rule.integrity_tier > 4 {
                return Err(RegistryError::InvalidIntegrityTier {
                    id: rule.id,
                    tier: rule.integrity_tier,
                });
            }

            if self.rules[..index]
                .iter()
                .any(|existing| existing.id == rule.id)
            {
                return Err(RegistryError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }
}

/// Explains why a standard registry is structurally invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A rule does not have a valid stable rule identity.
    InvalidRuleId {
        /// Invalid rule value.
        id: &'static str,
        /// Identity validation failure.
        source: RuleIdError,
    },
    /// A stable rule identity appears more than once.
    DuplicateRuleId(&'static str),
    /// A rule declared an integrity tier outside zero through four.
    InvalidIntegrityTier {
        /// Invalid rule identity.
        id: &'static str,
        /// Invalid tier value.
        tier: u8,
    },
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRuleId { id, source } => {
                write!(
                    formatter,
                    "registered rule `{id}` has an invalid identity: {source}"
                )
            }
            Self::DuplicateRuleId(id) => write!(formatter, "rule identity `{id}` is duplicated"),
            Self::InvalidIntegrityTier { id, tier } => {
                write!(formatter, "rule `{id}` has invalid integrity tier {tier}")
            }
        }
    }
}

impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRuleId { source, .. } => Some(source),
            Self::DuplicateRuleId(_) | Self::InvalidIntegrityTier { .. } => None,
        }
    }
}

/// A validated standard bundle loaded from exact manifest and rule documents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardBundle {
    id: String,
    title: String,
    edition: String,
    status: String,
    rules: Vec<StandardRule>,
}

impl StandardBundle {
    /// Loads and validates a standard manifest plus its exact referenced rules.
    ///
    /// Rule documents are keyed by their manifest-relative paths, such as
    /// `rules/ARCH-DEPENDENCY-001.json`. Missing, extra, or duplicate documents
    /// are rejected so evaluator discovery cannot silently use a partial bundle.
    ///
    /// # Errors
    ///
    /// Returns [`StandardLoadError`] for malformed JSON, unsupported schema or
    /// status, invalid identity/metadata, or manifest/document disagreement.
    pub fn from_json_documents(
        manifest_source: &str,
        rule_documents: &[(&str, &str)],
    ) -> Result<Self, StandardLoadError> {
        let manifest: StandardManifestWire =
            serde_json::from_str(manifest_source).map_err(|source| StandardLoadError::Json {
                document: "standard manifest".into(),
                source,
            })?;
        validate_non_empty("manifest.$schema", &manifest.schema)?;
        if manifest.schema_version != 1 {
            return Err(StandardLoadError::UnsupportedSchemaVersion(
                manifest.schema_version,
            ));
        }
        StableId::parse(&manifest.id).map_err(StandardLoadError::InvalidStandardId)?;
        validate_non_empty("manifest.title", &manifest.title)?;
        validate_non_empty("manifest.edition", &manifest.edition)?;
        validate_status("manifest.status", &manifest.status)?;

        let mut supplied = HashMap::with_capacity(rule_documents.len());
        for &(path, source) in rule_documents {
            if !is_canonical_relative_path(path) {
                return Err(StandardLoadError::InvalidRulePath(path.into()));
            }
            if supplied.insert(path, source).is_some() {
                return Err(StandardLoadError::DuplicateRulePath(path.into()));
            }
        }

        let mut declared_paths = HashSet::with_capacity(manifest.rules.len());
        let mut rule_ids = HashSet::with_capacity(manifest.rules.len());
        let mut rules = Vec::with_capacity(manifest.rules.len());
        for path in manifest.rules {
            if !is_canonical_relative_path(&path) {
                return Err(StandardLoadError::InvalidRulePath(path.into()));
            }
            if !declared_paths.insert(path.clone()) {
                return Err(StandardLoadError::DuplicateRulePath(path.into()));
            }
            let source = supplied
                .remove(path.as_str())
                .ok_or_else(|| StandardLoadError::MissingRuleDocument(path.clone().into()))?;
            let wire: StandardRuleWire =
                serde_json::from_str(source).map_err(|source| StandardLoadError::Json {
                    document: path.clone().into(),
                    source,
                })?;
            validate_non_empty("rule.$schema", &wire.schema)?;
            if wire.schema_version != 1 {
                return Err(StandardLoadError::UnsupportedSchemaVersion(
                    wire.schema_version,
                ));
            }
            RuleId::parse(&wire.id).map_err(|source| StandardLoadError::InvalidRuleId {
                value: wire.id.clone().into(),
                source,
            })?;
            if !rule_ids.insert(wire.id.clone()) {
                return Err(StandardLoadError::DuplicateRuleId(wire.id.into()));
            }
            validate_non_empty("rule.title", &wire.title)?;
            validate_status("rule.status", &wire.status)?;
            validate_non_empty("rule.applicability", &wire.applicability)?;
            validate_non_empty("rule.remediation", &wire.remediation)?;
            if wire.integrity_tier > 4 {
                return Err(StandardLoadError::InvalidIntegrityTier {
                    rule_id: wire.id.into(),
                    tier: wire.integrity_tier,
                });
            }
            let mut capabilities = HashSet::with_capacity(wire.required_capabilities.len());
            for capability in &wire.required_capabilities {
                if capability.is_empty() {
                    return Err(StandardLoadError::EmptyField("rule.required_capabilities"));
                }
                if !capabilities.insert(capability.as_str()) {
                    return Err(StandardLoadError::DuplicateRequiredCapability(
                        capability.clone().into(),
                    ));
                }
            }
            rules.push(StandardRule {
                id: wire.id,
                title: wire.title,
                status: wire.status,
                applicability: wire.applicability,
                category: wire.category,
                integrity_tier: wire.integrity_tier,
                remediation: wire.remediation,
                required_capabilities: wire.required_capabilities,
            });
        }
        if let Some(path) = supplied.keys().min() {
            return Err(StandardLoadError::UndeclaredRuleDocument((*path).into()));
        }

        Ok(Self {
            id: manifest.id,
            title: manifest.title,
            edition: manifest.edition,
            status: manifest.status,
            rules,
        })
    }

    /// Returns the stable standard identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the standard display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the exact standard edition.
    #[must_use]
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// Returns the standard bundle status.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Returns validated rules in manifest order.
    #[must_use]
    pub fn rules(&self) -> &[StandardRule] {
        &self.rules
    }
}

/// Validated metadata for one standard rule document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardRule {
    id: String,
    title: String,
    status: String,
    applicability: String,
    category: FindingCategory,
    integrity_tier: u8,
    remediation: String,
    required_capabilities: Vec<String>,
}

impl StandardRule {
    /// Returns the stable rule identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the rule title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the rule document status.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Returns the normative applicability description.
    #[must_use]
    pub fn applicability(&self) -> &str {
        &self.applicability
    }

    /// Returns the normalized finding category.
    #[must_use]
    pub const fn category(&self) -> FindingCategory {
        self.category
    }

    /// Returns the rule integrity tier.
    #[must_use]
    pub const fn integrity_tier(&self) -> u8 {
        self.integrity_tier
    }

    /// Returns governed remediation text.
    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Returns evaluator/analyzer capabilities named by the rule.
    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }
}

/// Explains invalid standard bundle input.
#[derive(Debug)]
pub enum StandardLoadError {
    /// A manifest or rule was not valid JSON for its typed contract.
    Json {
        /// Document identity or path.
        document: Box<str>,
        /// JSON parsing failure.
        source: serde_json::Error,
    },
    /// A document used an unsupported schema family.
    UnsupportedSchemaVersion(u16),
    /// The standard identity was invalid.
    InvalidStandardId(StableIdError),
    /// A rule identity was invalid.
    InvalidRuleId {
        /// Invalid rule identity.
        value: Box<str>,
        /// Rule identity validation failure.
        source: RuleIdError,
    },
    /// A required string field was empty.
    EmptyField(&'static str),
    /// A manifest or rule status was unsupported.
    InvalidStatus {
        /// Field containing the status.
        field: &'static str,
        /// Unsupported status value.
        value: Box<str>,
    },
    /// A manifest rule path was not canonical and relative.
    InvalidRulePath(Box<str>),
    /// A rule document path was repeated.
    DuplicateRulePath(Box<str>),
    /// A manifest-declared rule document was not supplied.
    MissingRuleDocument(Box<str>),
    /// A supplied rule document was absent from the manifest.
    UndeclaredRuleDocument(Box<str>),
    /// A stable rule identity was repeated across documents.
    DuplicateRuleId(Box<str>),
    /// A rule integrity tier exceeded four.
    InvalidIntegrityTier {
        /// Rule containing the invalid tier.
        rule_id: Box<str>,
        /// Invalid tier value.
        tier: u8,
    },
    /// A required analyzer/evaluator capability was repeated.
    DuplicateRequiredCapability(Box<str>),
}

impl Display for StandardLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { document, source } => {
                write!(
                    formatter,
                    "standard document `{document}` is invalid JSON: {source}"
                )
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "standard schema version {version} is unsupported"
                )
            }
            Self::InvalidStandardId(error) => write!(formatter, "invalid standard ID: {error}"),
            Self::InvalidRuleId { value, source } => {
                write!(formatter, "invalid standard rule ID `{value}`: {source}")
            }
            Self::EmptyField(field) => write!(formatter, "standard field `{field}` is empty"),
            Self::InvalidStatus { field, value } => {
                write!(
                    formatter,
                    "standard field `{field}` has invalid status `{value}`"
                )
            }
            Self::InvalidRulePath(path) => write!(formatter, "rule path `{path}` is invalid"),
            Self::DuplicateRulePath(path) => write!(formatter, "rule path `{path}` is duplicated"),
            Self::MissingRuleDocument(path) => {
                write!(
                    formatter,
                    "manifest rule document `{path}` was not supplied"
                )
            }
            Self::UndeclaredRuleDocument(path) => {
                write!(formatter, "supplied rule document `{path}` is not declared")
            }
            Self::DuplicateRuleId(id) => write!(formatter, "standard rule ID `{id}` is duplicated"),
            Self::InvalidIntegrityTier { rule_id, tier } => {
                write!(
                    formatter,
                    "standard rule `{rule_id}` has invalid tier {tier}"
                )
            }
            Self::DuplicateRequiredCapability(capability) => write!(
                formatter,
                "standard required capability `{capability}` is duplicated"
            ),
        }
    }
}

impl Error for StandardLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json { source, .. } => Some(source),
            Self::InvalidStandardId(error) => Some(error),
            Self::InvalidRuleId { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardManifestWire {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    title: String,
    edition: String,
    status: String,
    #[serde(rename = "release_digest")]
    _release_digest: Option<String>,
    rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardRuleWire {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    title: String,
    status: String,
    #[serde(rename = "statement")]
    _statement: String,
    #[serde(rename = "rationale")]
    _rationale: String,
    #[serde(rename = "failure_prevented")]
    _failure_prevented: String,
    applicability: String,
    category: FindingCategory,
    integrity_tier: u8,
    #[serde(rename = "evaluation")]
    _evaluation: String,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(rename = "finding")]
    _finding: serde_json::Value,
    remediation: String,
    #[serde(rename = "valid_example")]
    _valid_example: String,
    #[serde(rename = "invalid_example")]
    _invalid_example: String,
    #[serde(rename = "exception_policy")]
    _exception_policy: String,
    #[serde(rename = "introduced")]
    _introduced: String,
    #[serde(rename = "history")]
    _history: Vec<String>,
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), StandardLoadError> {
    if value.is_empty() {
        return Err(StandardLoadError::EmptyField(field));
    }
    Ok(())
}

fn validate_status(field: &'static str, value: &str) -> Result<(), StandardLoadError> {
    if matches!(value, "draft" | "candidate" | "released" | "retired") {
        return Ok(());
    }
    Err(StandardLoadError::InvalidStatus {
        field,
        value: value.into(),
    })
}

fn is_canonical_relative_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_path = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !value.is_empty()
        && !drive_path
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::{RuleStatus, StandardBundle, StandardLoadError, StandardRegistry};

    const MANIFEST: &str = include_str!("../../../standard/drafts/1.0.0/manifest.json");
    const STD_ID: &str = include_str!("../../../standard/drafts/1.0.0/rules/STD-ID-001.json");
    const ARCH_DEPENDENCY: &str =
        include_str!("../../../standard/drafts/1.0.0/rules/ARCH-DEPENDENCY-001.json");
    const ARCH_OWNERSHIP: &str =
        include_str!("../../../standard/drafts/1.0.0/rules/ARCH-OWNERSHIP-001.json");

    /// `T-AF-STANDARD-REGISTRY-0001-R02-001`
    #[test]
    fn draft_registry_is_structurally_valid() {
        let registry = StandardRegistry::draft_1_0();
        assert_eq!(registry.status(), RuleStatus::Draft);
        assert_eq!(registry.rules().len(), 3);
        assert!(registry.validate().is_ok());
    }

    /// `T-AF-STANDARD-REGISTRY-0001-R02-002`
    #[test]
    fn draft_registry_exposes_stable_rule_metadata() {
        let registry = StandardRegistry::draft_1_0();
        let descriptor = registry.find("STD-ID-001");
        assert_eq!(
            descriptor.map(super::RuleDescriptor::title),
            Some("Stable serialized identity")
        );
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-001`
    #[test]
    fn exact_draft_standard_documents_load_as_one_validated_bundle() {
        let bundle = StandardBundle::from_json_documents(
            MANIFEST,
            &[
                ("rules/STD-ID-001.json", STD_ID),
                ("rules/ARCH-DEPENDENCY-001.json", ARCH_DEPENDENCY),
                ("rules/ARCH-OWNERSHIP-001.json", ARCH_OWNERSHIP),
            ],
        )
        .expect("draft bundle must validate");
        assert_eq!(bundle.edition(), "1.0.0-draft.1");
        assert_eq!(bundle.rules().len(), 3);
        assert!(matches!(
            StandardBundle::from_json_documents(MANIFEST, &[("rules/STD-ID-001.json", STD_ID)]),
            Err(StandardLoadError::MissingRuleDocument(_))
        ));
    }
}
