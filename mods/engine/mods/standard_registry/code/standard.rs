//! Fortress Engineering Standard registry primitives.
//!
//! The registry exposes stable rule metadata independently from repository
//! observation, execution, certification, and presentation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{RuleId, RuleIdError, StableId, StableIdError};

const INSTALLED_STANDARD_MANIFEST: &str = include_str!("../data/standard_manifest.json");
pub(crate) const STD_ID_RULE_SOURCE: &str = include_str!("../data/std_id_rule.json");

/// Returns the exact Standard manifest authority installed with Fortress.
#[must_use]
pub const fn installed_standard_manifest() -> &'static str {
    INSTALLED_STANDARD_MANIFEST
}

/// Rule category attached to normative metadata and normalized findings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    /// Architecture topology, ownership, or boundary integrity.
    Architecture,
    /// Intended behavioral-flow coherence.
    Behavior,
    /// Declared or observed dependency integrity.
    Dependency,
    /// Project contract integrity.
    Contract,
    /// Hand-authored source integrity.
    Source,
    /// Documentation integrity.
    Documentation,
    /// Behavioral evidence and traceability integrity.
    Testing,
    /// Certification and evidence integrity.
    Certification,
    /// Pipeline contract integrity.
    Pipeline,
    /// Temporal change integrity.
    Change,
    /// Onboarding-only governance integrity.
    Onboarding,
    /// Security policy integrity.
    Security,
    /// External/environmental outcome and recovery integrity.
    Environment,
    /// Repository layout and artifact integrity.
    Repository,
    /// Standard bundle integrity.
    Standard,
}

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
        id: "ARCH-REALIZATION-001",
        title: "Observed implementation conforms to declared architectural dependencies",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "ARCH-SEMANTIC-001",
        title: "Declared Module semantic policy governs supported operational consequences",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "BEHAVIOR-FLOW-001",
        title: "Modeled Feature behavior forms a coherent intended flow",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "BEHAVIOR-REALIZATION-001",
        title: "Opted-in modeled behavior is realized consistently",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "BEHAVIOR-BYPASS-001",
        title: "Supported realized behavior preserves intended mandatory passage",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "PROGRAM-DOMAIN-001",
        title: "Supported interprocedural value domains satisfy declared function contracts",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-STATE-001",
        title: "Supported object-state transitions satisfy declared typestate obligations",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-EFFECT-001",
        title: "Supported function effects remain within authored effect policy",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-INFOFLOW-001",
        title: "Supported information flows satisfy declared trust and confidentiality constraints",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-ENVIRONMENT-001",
        title: "Modeled environmental outcomes have defined coherent handling",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-RETRY-001",
        title: "External retries preserve completion and idempotency semantics",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "PROGRAM-RECOVERY-001",
        title: "Modeled interruption preserves recovery-state obligations",
        status: RuleStatus::Draft,
        integrity_tier: 3,
    },
    RuleDescriptor {
        id: "ARCH-OWNERSHIP-001",
        title: "Exact declared repository file ownership",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "TEST-TRACEABILITY-001",
        title: "Active requirement and test traceability",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "TEST-BOUNDARY-001",
        title: "Recursive parent-local Feature verification boundaries",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "REPO-MODULE-001",
        title: "Canonical recursive repository Module grammar",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "REPO-DOCS-001",
        title: "Canonical Module documentation and contract synchronization",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "REPO-REFERENCE-001",
        title: "Relocation-transparent cross-Module references",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "SOURCE-PROFILE-001",
        title: "Universal Source Profile contract conformance",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "SOURCE-ARTIFACT-001",
        title: "Governed source artifact structural coherence",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "CONTRACT-COHERENCY-001",
        title: "Contract Coherency Graph compilation and supported logical coherency",
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
    digest: String,
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
            let rule = validate_rule_wire(path, wire, sha256(source.as_bytes()))?;
            if !rule_ids.insert(rule.id.clone()) {
                return Err(StandardLoadError::DuplicateRuleId(rule.id.into()));
            }
            rules.push(rule);
        }
        if let Some(path) = supplied.keys().min() {
            return Err(StandardLoadError::UndeclaredRuleDocument((*path).into()));
        }
        validate_rule_logic(&rules)?;

        let digest = bundle_digest(manifest_source, rule_documents);
        Ok(Self {
            id: manifest.id,
            title: manifest.title,
            edition: manifest.edition,
            status: manifest.status,
            digest,
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

    /// Returns the SHA-256 identity of the exact manifest and rule bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
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
    logic: RuleLogic,
    source_path: String,
    source_digest: String,
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

    /// Returns formal implication and conflict metadata used by the CCG.
    #[must_use]
    pub const fn logic(&self) -> &RuleLogic {
        &self.logic
    }

    /// Returns the canonical repository-relative rule document path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns the exact rule-document SHA-256 identity.
    #[must_use]
    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }
}

/// Machine-readable logical relations authored by one standard rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleLogic {
    implies: Vec<String>,
    conflicts_with: Vec<String>,
}

impl RuleLogic {
    /// Returns directly implied rule identities in canonical order.
    #[must_use]
    pub fn implies(&self) -> &[String] {
        &self.implies
    }

    /// Returns directly authored conflict identities in canonical order.
    #[must_use]
    pub fn conflicts_with(&self) -> &[String] {
        &self.conflicts_with
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
    /// A rule-logic array was not sorted or repeated an identity.
    NoncanonicalRuleLogic {
        /// Rule-logic field.
        field: &'static str,
        /// Repeated or out-of-order value.
        value: Box<str>,
    },
    /// A rule-logic identity did not satisfy the rule ID grammar.
    InvalidLogicRuleId {
        /// Rule-logic field.
        field: &'static str,
        /// Invalid target identity.
        value: Box<str>,
        /// Identity parsing failure.
        source: RuleIdError,
    },
    /// A formal implication or conflict referenced no rule in the bundle.
    UnknownLogicRule {
        /// Declaring rule identity.
        rule_id: Box<str>,
        /// Rule-logic field.
        field: &'static str,
        /// Missing target identity.
        target: Box<str>,
    },
    /// A rule declared itself as a conflict.
    SelfConflictingRule(Box<str>),
    /// Applying one rule necessarily activates a conflicting rule pair.
    InherentlyUnsatisfiableRule {
        /// Rule whose implication closure is impossible.
        rule_id: Box<str>,
        /// First conflicting effective rule.
        first: Box<str>,
        /// Second conflicting effective rule.
        second: Box<str>,
    },
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
            Self::NoncanonicalRuleLogic { field, value } => write!(
                formatter,
                "standard rule field `{field}` is not strictly sorted and unique at `{value}`"
            ),
            Self::InvalidLogicRuleId {
                field,
                value,
                source,
            } => write!(
                formatter,
                "standard rule field `{field}` contains invalid rule ID `{value}`: {source}"
            ),
            Self::UnknownLogicRule {
                rule_id,
                field,
                target,
            } => write!(
                formatter,
                "standard rule `{rule_id}` field `{field}` references unknown rule `{target}`"
            ),
            Self::SelfConflictingRule(rule_id) => {
                write!(formatter, "standard rule `{rule_id}` conflicts with itself")
            }
            Self::InherentlyUnsatisfiableRule {
                rule_id,
                first,
                second,
            } => write!(
                formatter,
                "standard rule `{rule_id}` is inherently unsatisfiable because its implication closure contains conflicting rules `{first}` and `{second}`"
            ),
        }
    }
}

impl Error for StandardLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json { source, .. } => Some(source),
            Self::InvalidStandardId(error) => Some(error),
            Self::InvalidRuleId { source, .. } | Self::InvalidLogicRuleId { source, .. } => {
                Some(source)
            }
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
    logic: RuleLogicWire,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleLogicWire {
    implies: Vec<String>,
    conflicts_with: Vec<String>,
}

fn validate_rule_wire(
    source_path: String,
    wire: StandardRuleWire,
    source_digest: String,
) -> Result<StandardRule, StandardLoadError> {
    RuleId::parse(&wire.id).map_err(|source| StandardLoadError::InvalidRuleId {
        value: wire.id.clone().into(),
        source,
    })?;
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
    Ok(StandardRule {
        id: wire.id,
        title: wire.title,
        status: wire.status,
        applicability: wire.applicability,
        category: wire.category,
        integrity_tier: wire.integrity_tier,
        remediation: wire.remediation,
        required_capabilities: wire.required_capabilities,
        logic: RuleLogic {
            implies: validate_logic_references("logic.implies", &wire.logic.implies)?,
            conflicts_with: validate_logic_references(
                "logic.conflicts_with",
                &wire.logic.conflicts_with,
            )?,
        },
        source_path,
        source_digest,
    })
}

fn validate_logic_references(
    field: &'static str,
    values: &[String],
) -> Result<Vec<String>, StandardLoadError> {
    for value in values {
        RuleId::parse(value).map_err(|source| StandardLoadError::InvalidLogicRuleId {
            field,
            value: value.clone().into(),
            source,
        })?;
    }
    if let Some(pair) = values.windows(2).find(|pair| pair[0] >= pair[1]) {
        return Err(StandardLoadError::NoncanonicalRuleLogic {
            field,
            value: pair[1].clone().into(),
        });
    }
    Ok(values.to_vec())
}

fn validate_rule_logic(rules: &[StandardRule]) -> Result<(), StandardLoadError> {
    let known: BTreeSet<&str> = rules.iter().map(StandardRule::id).collect();
    for rule in rules {
        for (field, targets) in [
            ("logic.implies", rule.logic.implies()),
            ("logic.conflicts_with", rule.logic.conflicts_with()),
        ] {
            for target in targets {
                if !known.contains(target.as_str()) {
                    return Err(StandardLoadError::UnknownLogicRule {
                        rule_id: rule.id().into(),
                        field,
                        target: target.clone().into(),
                    });
                }
            }
        }
        if rule.logic.conflicts_with().iter().any(|id| id == rule.id()) {
            return Err(StandardLoadError::SelfConflictingRule(rule.id().into()));
        }
    }

    let implications: BTreeMap<&str, Vec<&str>> = rules
        .iter()
        .map(|rule| {
            (
                rule.id(),
                rule.logic.implies().iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let conflicts: BTreeSet<(&str, &str)> = rules
        .iter()
        .flat_map(|rule| {
            rule.logic.conflicts_with().iter().map(move |target| {
                if rule.id() < target.as_str() {
                    (rule.id(), target.as_str())
                } else {
                    (target.as_str(), rule.id())
                }
            })
        })
        .collect();
    for rule in rules {
        let mut closure = BTreeSet::new();
        let mut queue = VecDeque::from([rule.id()]);
        while let Some(current) = queue.pop_front() {
            if !closure.insert(current) {
                continue;
            }
            if let Some(targets) = implications.get(current) {
                queue.extend(targets.iter().copied());
            }
        }
        for first in &closure {
            for second in closure.range(*first..) {
                let pair = if first < second {
                    (*first, *second)
                } else {
                    (*second, *first)
                };
                if conflicts.contains(&pair) {
                    return Err(StandardLoadError::InherentlyUnsatisfiableRule {
                        rule_id: rule.id().into(),
                        first: pair.0.into(),
                        second: pair.1.into(),
                    });
                }
            }
        }
    }
    Ok(())
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

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn bundle_digest(manifest_source: &str, rule_documents: &[(&str, &str)]) -> String {
    let mut documents = rule_documents.to_vec();
    documents.sort_unstable_by_key(|(path, _)| *path);
    let mut hasher = Sha256::new();
    update_digest(&mut hasher, b"standard_manifest");
    update_digest(&mut hasher, manifest_source.as_bytes());
    for (path, source) in documents {
        update_digest(&mut hasher, path.as_bytes());
        update_digest(&mut hasher, source.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn update_digest(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}
