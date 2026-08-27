//! Canonical Fortress Module Contract v2 loading and CCG compilation.
//!
//! Filesystem containment remains authoritative for Module location, parentage,
//! direct elemental ownership, and child membership. A contract owns stable
//! architectural intent that containment cannot safely express. Repository-wide
//! compilation produces the one canonical Contract Coherency Graph.

#[path = "graph.rs"]
mod graph;

pub use graph::*;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{RuleId, StableId};
use crate::standard::StandardBundle;

/// Exact Module Contract v2 schema identity.
pub const MODULE_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v2:module-contract";

/// Current and only supported Module Contract schema version.
pub const MODULE_CONTRACT_SCHEMA_VERSION: u16 = 2;

/// A validated canonical Module Contract v2 document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleContract {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<ContractEcosystem>,
    provides: Vec<ProvidedCapability>,
    requires: Vec<RequiredCapability>,
    relationships: Vec<ModuleRelationship>,
    constraints: Vec<ModuleConstraint>,
    guarantees: Vec<ModuleGuarantee>,
    features: Vec<ContractFeature>,
    behavior: Vec<BehaviorCheckpoint>,
}

impl ModuleContract {
    /// Parses, validates, and byte-checks one canonical v2 contract.
    ///
    /// # Errors
    ///
    /// Returns an explicit unsupported-version error for v1, a JSON error for
    /// malformed structure, a model error for invalid local semantics, or a
    /// canonical-serialization error when valid meaning is formatted
    /// noncanonically.
    pub fn from_json_str(source: &str) -> Result<Self, ModuleContractLoadError> {
        let value: serde_json::Value =
            serde_json::from_str(source).map_err(ModuleContractLoadError::Json)?;
        let version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok());
        if version != Some(MODULE_CONTRACT_SCHEMA_VERSION) {
            return Err(ModuleContractLoadError::UnsupportedSchemaVersion(version));
        }
        let contract: Self =
            serde_json::from_value(value).map_err(ModuleContractLoadError::Json)?;
        contract
            .validate_local()
            .map_err(ModuleContractLoadError::Model)?;
        let canonical = contract
            .to_canonical_json()
            .map_err(ModuleContractLoadError::Serialization)?;
        if source.as_bytes() != canonical.as_bytes() {
            return Err(ModuleContractLoadError::NoncanonicalSerialization);
        }
        Ok(contract)
    }

    /// Serializes the contract using the mandatory canonical JSON layout.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the typed contract cannot be
    /// represented.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut value| {
            value.push('\n');
            value
        })
    }

    /// Returns the stable Module identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the canonical human display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the root-only ecosystem selection, when present.
    #[must_use]
    pub const fn ecosystem(&self) -> Option<&ContractEcosystem> {
        self.ecosystem.as_ref()
    }

    /// Returns provided capabilities in canonical identity order.
    #[must_use]
    pub fn provides(&self) -> &[ProvidedCapability] {
        &self.provides
    }

    /// Returns direct functional requirements in canonical order.
    #[must_use]
    pub fn requires(&self) -> &[RequiredCapability] {
        &self.requires
    }

    /// Returns typed non-functional relationships in canonical order.
    #[must_use]
    pub fn relationships(&self) -> &[ModuleRelationship] {
        &self.relationships
    }

    /// Returns locally declared constraints in canonical order.
    #[must_use]
    pub fn constraints(&self) -> &[ModuleConstraint] {
        &self.constraints
    }

    /// Returns guarantees in canonical identity order.
    #[must_use]
    pub fn guarantees(&self) -> &[ModuleGuarantee] {
        &self.guarantees
    }

    /// Returns Features owned by this Module in canonical identity order.
    #[must_use]
    pub fn features(&self) -> &[ContractFeature] {
        &self.features
    }

    /// Returns behavioral checkpoints in canonical identity order.
    #[must_use]
    pub fn behavior(&self) -> &[BehaviorCheckpoint] {
        &self.behavior
    }

    #[allow(clippy::too_many_lines)]
    fn validate_local(&self) -> Result<(), ModuleContractModelError> {
        if self.schema != MODULE_CONTRACT_SCHEMA {
            return Err(model_error(format!(
                "`$schema` must be `{MODULE_CONTRACT_SCHEMA}`"
            )));
        }
        if self.schema_version != MODULE_CONTRACT_SCHEMA_VERSION {
            return Err(model_error(format!(
                "schema version {} is unsupported",
                self.schema_version
            )));
        }
        stable_id("id", &self.id)?;
        nonempty("display_name", &self.display_name)?;
        if let Some(ecosystem) = &self.ecosystem {
            if ecosystem.repository_grammar == 0 {
                return Err(model_error("ecosystem.repository_grammar must be positive"));
            }
            stable_id("ecosystem.standard.id", &ecosystem.standard.id)?;
            nonempty("ecosystem.standard.edition", &ecosystem.standard.edition)?;
        }

        strictly_sorted(
            "provides",
            self.provides.iter().map(|item| item.id.as_str()),
        )?;
        for capability in &self.provides {
            stable_namespace("provides.id", &capability.id, "CAP")?;
            Version::parse(&capability.version).map_err(|error| {
                model_error(format!(
                    "provided capability `{}` has invalid SemVer `{}`: {error}",
                    capability.id, capability.version
                ))
            })?;
        }

        strictly_sorted(
            "requires",
            self.requires
                .iter()
                .map(|item| (item.provider.as_str(), item.capability.as_str())),
        )?;
        for requirement in &self.requires {
            stable_id("requires.provider", &requirement.provider)?;
            stable_namespace("requires.capability", &requirement.capability, "CAP")?;
            if requirement.provider == self.id {
                return Err(model_error(format!(
                    "Module `{}` must not require itself",
                    self.id
                )));
            }
            VersionReq::parse(&requirement.version).map_err(|error| {
                model_error(format!(
                    "requirement for `{}` has invalid SemVer requirement `{}`: {error}",
                    requirement.capability, requirement.version
                ))
            })?;
        }

        strictly_sorted(
            "relationships",
            self.relationships
                .iter()
                .map(|item| (item.kind, item.target.as_str())),
        )?;
        for relationship in &self.relationships {
            stable_id("relationships.target", &relationship.target)?;
            if relationship.target == self.id {
                return Err(model_error(format!(
                    "Module `{}` must not relate to itself",
                    self.id
                )));
            }
            strictly_sorted(
                "relationships.subjects",
                relationship.subjects.iter().map(String::as_str),
            )?;
            for subject in &relationship.subjects {
                stable_id("relationships.subjects", subject)?;
            }
        }

        strictly_sorted(
            "constraints",
            self.constraints
                .iter()
                .map(|item| (item.rule.as_str(), item.scope)),
        )?;
        for constraint in &self.constraints {
            RuleId::parse(&constraint.rule).map_err(|error| {
                model_error(format!(
                    "constraint rule `{}` is not a canonical rule ID: {error}",
                    constraint.rule
                ))
            })?;
        }

        strictly_sorted(
            "guarantees",
            self.guarantees.iter().map(|item| item.id.as_str()),
        )?;
        strictly_sorted(
            "features",
            self.features.iter().map(|item| item.id.as_str()),
        )?;
        let local_capabilities: BTreeSet<&str> =
            self.provides.iter().map(|item| item.id.as_str()).collect();
        let local_features: BTreeSet<&str> =
            self.features.iter().map(|item| item.id.as_str()).collect();
        let mut local_requirements = BTreeSet::new();
        for feature in &self.features {
            stable_id("features.id", &feature.id)?;
            Version::parse(&feature.version).map_err(|error| {
                model_error(format!(
                    "Feature `{}` has invalid SemVer `{}`: {error}",
                    feature.id, feature.version
                ))
            })?;
            strictly_sorted(
                "features.requirements",
                feature.requirements.iter().map(|item| item.id.as_str()),
            )?;
            for requirement in &feature.requirements {
                stable_id("features.requirements.id", &requirement.id)?;
                nonempty("features.requirements.statement", &requirement.statement)?;
                if requirement.tests.is_empty() {
                    return Err(model_error(format!(
                        "requirement `{}` must declare test evidence",
                        requirement.id
                    )));
                }
                strictly_sorted(
                    "features.requirements.tests",
                    requirement.tests.iter().map(String::as_str),
                )?;
                for test in &requirement.tests {
                    stable_namespace("features.requirements.tests", test, "T")?;
                }
                local_requirements.insert(requirement.id.as_str());
            }
        }
        for guarantee in &self.guarantees {
            stable_namespace("guarantees.id", &guarantee.id, "GUA")?;
            stable_id("guarantees.subject.id", &guarantee.subject.id)?;
            match guarantee.subject.kind {
                GuaranteeSubjectKind::Module if guarantee.subject.id != self.id => {
                    return Err(model_error(format!(
                        "guarantee `{}` module subject must be its declaring Module `{}`",
                        guarantee.id, self.id
                    )));
                }
                GuaranteeSubjectKind::Capability
                    if !local_capabilities.contains(guarantee.subject.id.as_str()) =>
                {
                    return Err(model_error(format!(
                        "guarantee `{}` names nonlocal capability `{}`",
                        guarantee.id, guarantee.subject.id
                    )));
                }
                GuaranteeSubjectKind::Feature
                    if !local_features.contains(guarantee.subject.id.as_str()) =>
                {
                    return Err(model_error(format!(
                        "guarantee `{}` names nonlocal Feature `{}`",
                        guarantee.id, guarantee.subject.id
                    )));
                }
                _ => {}
            }
            if guarantee.requirements.is_empty() {
                return Err(model_error(format!(
                    "guarantee `{}` must reference at least one local requirement",
                    guarantee.id
                )));
            }
            strictly_sorted(
                "guarantees.requirements",
                guarantee.requirements.iter().map(String::as_str),
            )?;
            for requirement in &guarantee.requirements {
                if !local_requirements.contains(requirement.as_str()) {
                    return Err(model_error(format!(
                        "guarantee `{}` references unknown local requirement `{requirement}`",
                        guarantee.id
                    )));
                }
            }
        }

        strictly_sorted(
            "behavior",
            self.behavior.iter().map(|item| item.id.as_str()),
        )?;
        for checkpoint in &self.behavior {
            stable_namespace("behavior.id", &checkpoint.id, "CHK")?;
            stable_id("behavior.feature", &checkpoint.feature)?;
            if let Some(outcome) = &checkpoint.outcome {
                nonempty("behavior.outcome", outcome)?;
            }
            strictly_sorted(
                "behavior.transitions",
                checkpoint
                    .transitions
                    .iter()
                    .map(|item| (item.outcome.as_deref(), item.target.as_str())),
            )?;
            for transition in &checkpoint.transitions {
                stable_namespace("behavior.transitions.target", &transition.target, "CHK")?;
                if let Some(outcome) = &transition.outcome {
                    nonempty("behavior.transitions.outcome", outcome)?;
                }
            }
            checkpoint.validate_shape()?;
        }
        Ok(())
    }
}

/// Root-only ecosystem and standard interpretation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractEcosystem {
    repository_grammar: u16,
    standard: ContractStandardReference,
}

impl ContractEcosystem {
    /// Returns the selected recursive repository grammar version.
    #[must_use]
    pub const fn repository_grammar(&self) -> u16 {
        self.repository_grammar
    }

    /// Returns the selected standard identity and edition.
    #[must_use]
    pub const fn standard(&self) -> &ContractStandardReference {
        &self.standard
    }
}

/// Root contract reference to the applicable Fortress Standard.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractStandardReference {
    id: String,
    edition: String,
}

impl ContractStandardReference {
    /// Returns the selected standard identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the selected standard edition.
    #[must_use]
    pub fn edition(&self) -> &str {
        &self.edition
    }
}

/// A semantic capability provided by one exact Module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedCapability {
    id: String,
    version: String,
    visibility: CapabilityVisibility,
}

impl ProvidedCapability {
    /// Returns the globally unique capability identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact provided `SemVer` version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the declared consumption visibility.
    #[must_use]
    pub const fn visibility(&self) -> CapabilityVisibility {
        self.visibility
    }
}

/// Initial capability visibility vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityVisibility {
    /// Consumable within the governed project ecosystem.
    Project,
    /// Intentionally exposed beyond the internal project ecosystem.
    Public,
}

/// A direct functional dependency on one provider capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapability {
    provider: String,
    capability: String,
    version: String,
}

impl RequiredCapability {
    /// Returns the exact provider Module identity.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the exact required capability identity.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Returns the canonical `SemVer` requirement.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// One typed non-functional outbound relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRelationship {
    #[serde(rename = "type")]
    kind: ModuleRelationshipType,
    target: String,
    subjects: Vec<String>,
}

impl ModuleRelationship {
    /// Returns the implemented relationship type.
    #[must_use]
    pub const fn kind(&self) -> ModuleRelationshipType {
        self.kind
    }

    /// Returns the target Module identity.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns target-owned Feature, guarantee, or requirement subjects.
    #[must_use]
    pub fn subjects(&self) -> &[String] {
        &self.subjects
    }
}

/// Non-functional relationship types with implemented v2 semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleRelationshipType {
    /// The source supplies verification evidence for the target or subjects.
    Verifies,
}

impl ModuleRelationshipType {
    /// Returns the canonical serialized spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verifies => "verifies",
        }
    }
}

/// A standard rule obligation declared for one Module or subtree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConstraint {
    rule: String,
    scope: ConstraintScope,
}

impl ModuleConstraint {
    /// Returns the selected standard rule identity.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns whether the rule applies to self or subtree.
    #[must_use]
    pub const fn scope(&self) -> ConstraintScope {
        self.scope
    }
}

/// Implemented constraint inheritance scopes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintScope {
    /// Applies only to the declaring Module.
    #[serde(rename = "self")]
    SelfOnly,
    /// Applies to the declaring Module and every descendant Module.
    Subtree,
}

/// A requirement-backed promise exported by one Module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleGuarantee {
    id: String,
    subject: GuaranteeSubject,
    requirements: Vec<String>,
}

impl ModuleGuarantee {
    /// Returns the globally unique guarantee identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the local subject whose property is promised.
    #[must_use]
    pub const fn subject(&self) -> &GuaranteeSubject {
        &self.subject
    }

    /// Returns the local requirements defining the promise semantics.
    #[must_use]
    pub fn requirements(&self) -> &[String] {
        &self.requirements
    }
}

/// Local Module, capability, or Feature subject of a guarantee.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeSubject {
    kind: GuaranteeSubjectKind,
    id: String,
}

impl GuaranteeSubject {
    /// Returns the subject class.
    #[must_use]
    pub const fn kind(&self) -> GuaranteeSubjectKind {
        self.kind
    }

    /// Returns the subject identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Implemented guarantee subject classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeSubjectKind {
    /// The declaring Module as a whole.
    Module,
    /// One capability provided by the declaring Module.
    Capability,
    /// One Feature owned by the declaring Module.
    Feature,
}

/// A versioned Feature and its authoritative requirements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractFeature {
    id: String,
    version: String,
    requirements: Vec<ContractRequirement>,
}

impl ContractFeature {
    /// Returns the globally unique Feature identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the first formal contract version of the Feature.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns requirements in canonical identity order.
    #[must_use]
    pub fn requirements(&self) -> &[ContractRequirement] {
        &self.requirements
    }
}

/// One authoritative Feature requirement and its test evidence references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractRequirement {
    id: String,
    statement: String,
    tests: Vec<String>,
}

impl ContractRequirement {
    /// Returns the globally unique requirement identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the authoritative semantic statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns canonical test evidence identities.
    #[must_use]
    pub fn tests(&self) -> &[String] {
        &self.tests
    }
}

/// A future behavioral-flow semantic checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorCheckpoint {
    id: String,
    feature: String,
    kind: CheckpointKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    transitions: Vec<CheckpointTransition>,
}

impl BehaviorCheckpoint {
    /// Returns the globally unique checkpoint identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the modeled Feature identity.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns the checkpoint semantic kind.
    #[must_use]
    pub const fn kind(&self) -> CheckpointKind {
        self.kind
    }

    /// Returns the terminal outcome when this is a terminal checkpoint.
    #[must_use]
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Returns outgoing transitions in canonical order.
    #[must_use]
    pub fn transitions(&self) -> &[CheckpointTransition] {
        &self.transitions
    }

    fn validate_shape(&self) -> Result<(), ModuleContractModelError> {
        match self.kind {
            CheckpointKind::Trigger | CheckpointKind::Action => {
                if self.outcome.is_some() || self.transitions.is_empty() {
                    return Err(model_error(format!(
                        "{} checkpoint `{}` must have transitions and no checkpoint outcome",
                        self.kind.as_str(),
                        self.id
                    )));
                }
                if self
                    .transitions
                    .iter()
                    .any(|transition| transition.outcome.is_some())
                {
                    return Err(model_error(format!(
                        "{} checkpoint `{}` transitions must not label outcomes",
                        self.kind.as_str(),
                        self.id
                    )));
                }
            }
            CheckpointKind::Decision => {
                if self.outcome.is_some() || self.transitions.len() < 2 {
                    return Err(model_error(format!(
                        "decision checkpoint `{}` needs at least two labeled transitions and no checkpoint outcome",
                        self.id
                    )));
                }
                let mut outcomes = BTreeSet::new();
                for transition in &self.transitions {
                    let Some(outcome) = transition.outcome.as_deref() else {
                        return Err(model_error(format!(
                            "decision checkpoint `{}` has an unlabeled transition",
                            self.id
                        )));
                    };
                    if !outcomes.insert(outcome) {
                        return Err(model_error(format!(
                            "decision checkpoint `{}` repeats outcome `{outcome}`",
                            self.id
                        )));
                    }
                }
            }
            CheckpointKind::Terminal => {
                if self.outcome.is_none() || !self.transitions.is_empty() {
                    return Err(model_error(format!(
                        "terminal checkpoint `{}` must declare its outcome and have no transitions",
                        self.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Implemented checkpoint kinds for the future Behavioral Flow Graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    /// Feature-entry event.
    Trigger,
    /// Performed behavior.
    Action,
    /// Outcome-selecting branch.
    Decision,
    /// Feature-terminal result.
    Terminal,
}

impl CheckpointKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Action => "action",
            Self::Decision => "decision",
            Self::Terminal => "terminal",
        }
    }
}

/// One deterministic checkpoint transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTransition {
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    target: String,
}

impl CheckpointTransition {
    /// Returns the decision outcome label, when required.
    #[must_use]
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Returns the target checkpoint identity.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

/// Minimal actual-standard index used while resolving contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractStandardIndex {
    id: String,
    edition: String,
    digest: String,
    rule_ids: BTreeSet<String>,
    status: String,
    rules: BTreeMap<String, IndexedRuleLogic>,
}

impl ContractStandardIndex {
    /// Builds an index from the exact loaded standard bundle.
    #[must_use]
    pub fn from_bundle(bundle: &StandardBundle) -> Self {
        Self {
            id: bundle.id().into(),
            edition: bundle.edition().into(),
            digest: bundle.digest().into(),
            rule_ids: bundle
                .rules()
                .iter()
                .map(|rule| rule.id().to_owned())
                .collect(),
            status: bundle.status().into(),
            rules: bundle
                .rules()
                .iter()
                .map(|rule| {
                    (
                        rule.id().to_owned(),
                        IndexedRuleLogic {
                            implies: rule.logic().implies().to_vec(),
                            conflicts_with: rule.logic().conflicts_with().to_vec(),
                            source_path: rule.source_path().to_owned(),
                            source_digest: rule.source_digest().to_owned(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Builds an explicit index for deterministic contract fixtures.
    #[must_use]
    pub fn new<I, S>(id: impl Into<String>, edition: impl Into<String>, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        let edition = edition.into();
        let rule_ids: BTreeSet<String> = rules.into_iter().map(Into::into).collect();
        let digest_material = format!(
            "{id}\n{edition}\n{}",
            rule_ids.iter().cloned().collect::<Vec<_>>().join("\n")
        );
        Self {
            id,
            edition,
            digest: sha256_bytes(digest_material.as_bytes()),
            rule_ids,
            status: "draft".into(),
            rules: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IndexedRuleLogic {
    implies: Vec<String>,
    conflicts_with: Vec<String>,
    source_path: String,
    source_digest: String,
}

/// Resolves every Module contract in a canonical repository inventory.
#[must_use]
pub fn compile_contract_coherency_graph(
    files: &BTreeMap<String, Vec<u8>>,
    standard: &ContractStandardIndex,
    observed_tests: Option<&[CcgObservedTestFact]>,
) -> CcgCompilation {
    Resolver::new(files, standard, observed_tests).resolve()
}

/// Deterministic success or violations from repository-wide contract resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CcgCompilation {
    graph: Option<ContractCoherencyGraph>,
    violations: Vec<CcgViolation>,
    test_reference_resolution_supported: bool,
}

impl CcgCompilation {
    /// Returns whether all implemented checks passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.graph.is_some() && self.violations.is_empty()
    }

    /// Returns the compiled graph when structural compilation produced one.
    #[must_use]
    pub const fn graph(&self) -> Option<&ContractCoherencyGraph> {
        self.graph.as_ref()
    }

    /// Returns deterministic contract violations.
    #[must_use]
    pub fn violations(&self) -> &[CcgViolation] {
        &self.violations
    }

    /// Returns whether test references were checked against observed evidence.
    #[must_use]
    pub const fn test_reference_resolution_supported(&self) -> bool {
        self.test_reference_resolution_supported
    }
}

/// One precise contract source violation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CcgViolation {
    code: String,
    path: String,
    pointer: String,
    message: String,
    input_facts: Vec<String>,
    provenance_closure: Vec<CcgSourceProvenance>,
}

impl CcgViolation {
    /// Returns the stable semantic violation code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the contract or expected contract path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the canonical JSON pointer or repository concern.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Returns the deterministic explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the canonical source or derived facts that make the violation true.
    #[must_use]
    pub fn input_facts(&self) -> &[String] {
        &self.input_facts
    }

    /// Returns the complete source provenance closure for the violation.
    #[must_use]
    pub fn provenance_closure(&self) -> &[CcgSourceProvenance] {
        &self.provenance_closure
    }
}

impl Display for CcgViolation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}: {}",
            self.path, self.pointer, self.message
        )
    }
}

/// Canonical derived semantic graph of the governed contract ecosystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCoherencyGraph {
    modules: BTreeMap<String, ResolvedModule>,
    module_paths: BTreeMap<String, String>,
    capabilities: BTreeMap<String, ResolvedCapability>,
    features: BTreeMap<String, OwnedIdentity>,
    requirements: BTreeMap<String, ResolvedRequirement>,
    guarantees: BTreeMap<String, OwnedIdentity>,
    checkpoints: BTreeMap<String, ResolvedCheckpoint>,
    direct_requirements: Vec<ResolvedCapabilityRequirement>,
    relationships: Vec<ResolvedTypedRelationship>,
    effective_constraints: BTreeMap<String, Vec<ResolvedConstraint>>,
    containment: BTreeMap<String, Option<String>>,
    consumers: BTreeMap<String, Vec<String>>,
    expected_readme_relationships:
        BTreeMap<String, BTreeMap<String, BTreeSet<ResolvedRelationshipType>>>,
    standard: ContractStandardIndex,
    observed_tests: Option<Vec<CcgObservedTestFact>>,
    coherency_findings: Vec<CcgViolation>,
}

impl ContractCoherencyGraph {
    /// Returns Modules keyed by stable identity.
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<String, ResolvedModule> {
        &self.modules
    }

    /// Returns Module paths keyed by stable identity.
    #[must_use]
    pub const fn module_paths(&self) -> &BTreeMap<String, String> {
        &self.module_paths
    }

    /// Returns capability providers keyed by globally unique capability ID.
    #[must_use]
    pub const fn capabilities(&self) -> &BTreeMap<String, ResolvedCapability> {
        &self.capabilities
    }

    /// Returns Feature ownership keyed by globally unique Feature ID.
    #[must_use]
    pub const fn features(&self) -> &BTreeMap<String, OwnedIdentity> {
        &self.features
    }

    /// Returns requirement ownership and Feature context.
    #[must_use]
    pub const fn requirements(&self) -> &BTreeMap<String, ResolvedRequirement> {
        &self.requirements
    }

    /// Returns guarantee ownership keyed by globally unique guarantee ID.
    #[must_use]
    pub const fn guarantees(&self) -> &BTreeMap<String, OwnedIdentity> {
        &self.guarantees
    }

    /// Returns checkpoint ownership and Feature context.
    #[must_use]
    pub const fn checkpoints(&self) -> &BTreeMap<String, ResolvedCheckpoint> {
        &self.checkpoints
    }

    /// Returns direct capability requirements in canonical source order.
    #[must_use]
    pub fn direct_requirements(&self) -> &[ResolvedCapabilityRequirement] {
        &self.direct_requirements
    }

    /// Returns typed non-functional relationships in canonical source order.
    #[must_use]
    pub fn relationships(&self) -> &[ResolvedTypedRelationship] {
        &self.relationships
    }

    /// Returns inherited and local effective constraints by Module ID.
    #[must_use]
    pub const fn effective_constraints(&self) -> &BTreeMap<String, Vec<ResolvedConstraint>> {
        &self.effective_constraints
    }

    /// Returns physical parent identities inferred from filesystem containment.
    #[must_use]
    pub const fn containment(&self) -> &BTreeMap<String, Option<String>> {
        &self.containment
    }

    /// Returns capability consumers derived inversely by provider Module ID.
    #[must_use]
    pub const fn consumers(&self) -> &BTreeMap<String, Vec<String>> {
        &self.consumers
    }

    /// Returns outbound README relationship types grouped by source and target.
    #[must_use]
    pub const fn expected_readme_relationships(
        &self,
    ) -> &BTreeMap<String, BTreeMap<String, BTreeSet<ResolvedRelationshipType>>> {
        &self.expected_readme_relationships
    }

    /// Returns the root contract.
    #[must_use]
    pub fn root(&self) -> Option<&ResolvedModule> {
        self.modules.values().find(|module| module.path.is_empty())
    }
}

/// One resolved Module with inferred physical context and computed digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedModule {
    path: String,
    contract_path: String,
    parent_id: Option<String>,
    digest: String,
    contract: ModuleContract,
}

impl ResolvedModule {
    /// Returns the Module root path; empty means repository root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the canonical contract path.
    #[must_use]
    pub fn contract_path(&self) -> &str {
        &self.contract_path
    }

    /// Returns the inferred parent Module identity.
    #[must_use]
    pub fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    /// Returns the computed SHA-256 identity of canonical contract bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the validated authored contract.
    #[must_use]
    pub const fn contract(&self) -> &ModuleContract {
        &self.contract
    }
}

/// Provenance for one resolved contract fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractProvenance {
    contract_path: String,
    pointer: String,
}

impl ContractProvenance {
    /// Returns the canonical source contract path.
    #[must_use]
    pub fn contract_path(&self) -> &str {
        &self.contract_path
    }

    /// Returns the canonical JSON pointer.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}

/// One globally indexed provided capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCapability {
    provider: String,
    version: String,
    visibility: CapabilityVisibility,
    provenance: ContractProvenance,
}

impl ResolvedCapability {
    /// Returns the provider Module ID.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the exact provided version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the capability visibility.
    #[must_use]
    pub const fn visibility(&self) -> CapabilityVisibility {
        self.visibility
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// Ownership provenance for a globally unique entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedIdentity {
    owner: String,
    provenance: ContractProvenance,
}

impl OwnedIdentity {
    /// Returns the owning Module ID.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// One globally unique requirement with owner and Feature identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRequirement {
    owner: String,
    feature: String,
    statement: String,
    tests: Vec<String>,
    provenance: ContractProvenance,
}

impl ResolvedRequirement {
    /// Returns the owning Module ID.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the owning Feature ID.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns the requirement statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns declared test evidence.
    #[must_use]
    pub fn tests(&self) -> &[String] {
        &self.tests
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// One globally unique behavioral checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCheckpoint {
    owner: String,
    feature: String,
    provenance: ContractProvenance,
}

impl ResolvedCheckpoint {
    /// Returns the declaring Module ID.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the modeled Feature ID.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// One resolved direct functional capability dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCapabilityRequirement {
    consumer: String,
    provider: String,
    capability: String,
    version_requirement: String,
    provenance: ContractProvenance,
}

impl ResolvedCapabilityRequirement {
    /// Returns the consuming Module ID.
    #[must_use]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    /// Returns the provider Module ID.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the required capability ID.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Returns the authored `SemVer` requirement.
    #[must_use]
    pub fn version_requirement(&self) -> &str {
        &self.version_requirement
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// One resolved non-functional relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTypedRelationship {
    source: String,
    kind: ModuleRelationshipType,
    target: String,
    subjects: Vec<String>,
    provenance: ContractProvenance,
}

impl ResolvedTypedRelationship {
    /// Returns the source Module ID.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the relationship kind.
    #[must_use]
    pub const fn kind(&self) -> ModuleRelationshipType {
        self.kind
    }

    /// Returns the target Module ID.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns target-owned verification subjects.
    #[must_use]
    pub fn subjects(&self) -> &[String] {
        &self.subjects
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// One local or inherited effective rule constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConstraint {
    rule: String,
    declared_by: String,
    declared_scope: ConstraintScope,
    inherited: bool,
    provenance: ContractProvenance,
}

impl ResolvedConstraint {
    /// Returns the applicable standard rule ID.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Returns the Module that authored the constraint.
    #[must_use]
    pub fn declared_by(&self) -> &str {
        &self.declared_by
    }

    /// Returns the authored constraint scope.
    #[must_use]
    pub const fn declared_scope(&self) -> ConstraintScope {
        self.declared_scope
    }

    /// Returns whether this effective obligation was inherited.
    #[must_use]
    pub const fn inherited(&self) -> bool {
        self.inherited
    }

    /// Returns authored source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ContractProvenance {
        &self.provenance
    }
}

/// Relationship types projected into canonical README documentation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResolvedRelationshipType {
    /// Derived from an exact capability requirement.
    DependsOn,
    /// Authored non-functional verification relationship.
    Verifies,
}

impl ResolvedRelationshipType {
    /// Returns the canonical Markdown type spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DependsOn => "depends_on",
            Self::Verifies => "verifies",
        }
    }
}

struct Resolver<'a> {
    files: &'a BTreeMap<String, Vec<u8>>,
    standard: &'a ContractStandardIndex,
    observed_tests: Option<&'a [CcgObservedTestFact]>,
    violations: Vec<CcgViolation>,
}

impl<'a> Resolver<'a> {
    fn new(
        files: &'a BTreeMap<String, Vec<u8>>,
        standard: &'a ContractStandardIndex,
        observed_tests: Option<&'a [CcgObservedTestFact]>,
    ) -> Self {
        Self {
            files,
            standard,
            observed_tests,
            violations: Vec::new(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn resolve(mut self) -> CcgCompilation {
        let module_paths = discover_module_paths(self.files.keys().map(String::as_str));
        let mut loaded = BTreeMap::<String, (String, ModuleContract, String)>::new();
        for module_path in &module_paths {
            let contract_path = child_path(module_path, "contract.json");
            let Some(bytes) = self.files.get(&contract_path) else {
                self.violation(contract_path, "/", "canonical Module has no contract.json");
                continue;
            };
            let Ok(source) = std::str::from_utf8(bytes) else {
                self.violation(contract_path, "/", "contract is not valid UTF-8");
                continue;
            };
            match ModuleContract::from_json_str(source) {
                Ok(contract) => {
                    loaded.insert(
                        module_path.clone(),
                        (contract_path, contract, sha256_bytes(bytes)),
                    );
                }
                Err(error) => self.violation(contract_path, "/", error.to_string()),
            }
        }
        if !self.violations.is_empty() {
            return self.failure();
        }

        let mut id_to_path = BTreeMap::<String, String>::new();
        for (module_path, (contract_path, contract, _)) in &loaded {
            if let Some(first_path) = id_to_path.insert(contract.id.clone(), module_path.clone()) {
                self.violation(
                    contract_path,
                    "/id",
                    format!(
                        "Module ID `{}` duplicates `{}`",
                        contract.id,
                        child_path(&first_path, "contract.json")
                    ),
                );
            }
        }
        let Some((root_contract_path, root_contract, _)) = loaded.get("") else {
            return self.failure();
        };
        match root_contract.ecosystem.as_ref() {
            None => self.violation(
                root_contract_path,
                "/ecosystem",
                "root contract must declare ecosystem interpretation",
            ),
            Some(ecosystem) => {
                if ecosystem.standard.id != self.standard.id
                    || ecosystem.standard.edition != self.standard.edition
                {
                    self.violation(
                        root_contract_path,
                        "/ecosystem/standard",
                        format!(
                            "selected standard `{}` edition `{}` does not match loaded registry `{}` edition `{}`",
                            ecosystem.standard.id,
                            ecosystem.standard.edition,
                            self.standard.id,
                            self.standard.edition
                        ),
                    );
                }
            }
        }
        for (module_path, (contract_path, contract, _)) in &loaded {
            if !module_path.is_empty() && contract.ecosystem.is_some() {
                self.violation(
                    contract_path,
                    "/ecosystem",
                    "descendant contract must not author ecosystem interpretation",
                );
            }
        }

        let mut capabilities = BTreeMap::<String, ResolvedCapability>::new();
        let mut features = BTreeMap::<String, OwnedIdentity>::new();
        let mut requirements = BTreeMap::<String, ResolvedRequirement>::new();
        let mut guarantees = BTreeMap::<String, OwnedIdentity>::new();
        let mut checkpoints = BTreeMap::<String, ResolvedCheckpoint>::new();
        for (contract_path, contract, _) in loaded.values() {
            for (index, capability) in contract.provides.iter().enumerate() {
                let resolved = ResolvedCapability {
                    provider: contract.id.clone(),
                    version: capability.version.clone(),
                    visibility: capability.visibility,
                    provenance: provenance(contract_path, format!("/provides/{index}")),
                };
                if let Some(previous) = capabilities.insert(capability.id.clone(), resolved) {
                    self.violation(
                        contract_path,
                        format!("/provides/{index}/id"),
                        format!(
                            "capability ID `{}` duplicates provider `{}`",
                            capability.id, previous.provider
                        ),
                    );
                }
            }
            for (feature_index, feature) in contract.features.iter().enumerate() {
                let owned = OwnedIdentity {
                    owner: contract.id.clone(),
                    provenance: provenance(contract_path, format!("/features/{feature_index}/id")),
                };
                if let Some(previous) = features.insert(feature.id.clone(), owned) {
                    self.violation(
                        contract_path,
                        format!("/features/{feature_index}/id"),
                        format!(
                            "Feature ID `{}` duplicates owner `{}`",
                            feature.id, previous.owner
                        ),
                    );
                }
                for (requirement_index, requirement) in feature.requirements.iter().enumerate() {
                    let resolved = ResolvedRequirement {
                        owner: contract.id.clone(),
                        feature: feature.id.clone(),
                        statement: requirement.statement.clone(),
                        tests: requirement.tests.clone(),
                        provenance: provenance(
                            contract_path,
                            format!("/features/{feature_index}/requirements/{requirement_index}"),
                        ),
                    };
                    if let Some(previous) = requirements.insert(requirement.id.clone(), resolved) {
                        self.violation(
                            contract_path,
                            format!(
                                "/features/{feature_index}/requirements/{requirement_index}/id"
                            ),
                            format!(
                                "requirement ID `{}` duplicates owner `{}`",
                                requirement.id, previous.owner
                            ),
                        );
                    }
                    if let Some(observed) = self.observed_tests {
                        for test in &requirement.tests {
                            if !observed.iter().any(|fact| fact.id() == test) {
                                self.violation(
                                    contract_path,
                                    format!(
                                        "/features/{feature_index}/requirements/{requirement_index}/tests"
                                    ),
                                    format!("test reference `{test}` does not exist in the supported evidence inventory"),
                                );
                            }
                        }
                    }
                }
            }
            for (index, guarantee) in contract.guarantees.iter().enumerate() {
                let owned = OwnedIdentity {
                    owner: contract.id.clone(),
                    provenance: provenance(contract_path, format!("/guarantees/{index}/id")),
                };
                if let Some(previous) = guarantees.insert(guarantee.id.clone(), owned) {
                    self.violation(
                        contract_path,
                        format!("/guarantees/{index}/id"),
                        format!(
                            "guarantee ID `{}` duplicates owner `{}`",
                            guarantee.id, previous.owner
                        ),
                    );
                }
            }
            for (index, checkpoint) in contract.behavior.iter().enumerate() {
                let resolved = ResolvedCheckpoint {
                    owner: contract.id.clone(),
                    feature: checkpoint.feature.clone(),
                    provenance: provenance(contract_path, format!("/behavior/{index}/id")),
                };
                if let Some(previous) = checkpoints.insert(checkpoint.id.clone(), resolved) {
                    self.violation(
                        contract_path,
                        format!("/behavior/{index}/id"),
                        format!(
                            "checkpoint ID `{}` duplicates owner `{}`",
                            checkpoint.id, previous.owner
                        ),
                    );
                }
            }
        }

        let mut direct_requirements = Vec::new();
        let mut relationships = Vec::new();
        let mut expected =
            BTreeMap::<String, BTreeMap<String, BTreeSet<ResolvedRelationshipType>>>::new();
        let mut consumers = BTreeMap::<String, BTreeSet<String>>::new();
        for (contract_path, contract, _) in loaded.values() {
            for (index, requirement) in contract.requires.iter().enumerate() {
                if !id_to_path.contains_key(&requirement.provider) {
                    self.violation(
                        contract_path,
                        format!("/requires/{index}/provider"),
                        format!("provider Module `{}` does not exist", requirement.provider),
                    );
                    continue;
                }
                let Some(capability) = capabilities.get(&requirement.capability) else {
                    self.violation(
                        contract_path,
                        format!("/requires/{index}/capability"),
                        format!(
                            "capability `{}` does not exist on provider `{}`",
                            requirement.capability, requirement.provider
                        ),
                    );
                    continue;
                };
                if capability.provider != requirement.provider {
                    self.violation(
                        contract_path,
                        format!("/requires/{index}/capability"),
                        format!(
                            "capability `{}` is provided by `{}`, not declared provider `{}`",
                            requirement.capability, capability.provider, requirement.provider
                        ),
                    );
                    continue;
                }
                let version = Version::parse(&capability.version)
                    .expect("provided version was locally validated");
                let requirement_version = VersionReq::parse(&requirement.version)
                    .expect("required version was locally validated");
                if !requirement_version.matches(&version) {
                    self.violation(
                        contract_path,
                        format!("/requires/{index}/version"),
                        format!(
                            "provided version `{}` does not satisfy `{}` for capability `{}`",
                            capability.version, requirement.version, requirement.capability
                        ),
                    );
                }
                direct_requirements.push(ResolvedCapabilityRequirement {
                    consumer: contract.id.clone(),
                    provider: requirement.provider.clone(),
                    capability: requirement.capability.clone(),
                    version_requirement: requirement.version.clone(),
                    provenance: provenance(contract_path, format!("/requires/{index}")),
                });
                expected
                    .entry(contract.id.clone())
                    .or_default()
                    .entry(requirement.provider.clone())
                    .or_default()
                    .insert(ResolvedRelationshipType::DependsOn);
                consumers
                    .entry(requirement.provider.clone())
                    .or_default()
                    .insert(contract.id.clone());
            }
            for (index, relationship) in contract.relationships.iter().enumerate() {
                if !id_to_path.contains_key(&relationship.target) {
                    self.violation(
                        contract_path,
                        format!("/relationships/{index}/target"),
                        format!("target Module `{}` does not exist", relationship.target),
                    );
                    continue;
                }
                for subject in &relationship.subjects {
                    let valid = guarantees
                        .get(subject)
                        .is_some_and(|value| value.owner == relationship.target)
                        || requirements
                            .get(subject)
                            .is_some_and(|value| value.owner == relationship.target)
                        || features
                            .get(subject)
                            .is_some_and(|value| value.owner == relationship.target);
                    if !valid {
                        self.violation(
                            contract_path,
                            format!("/relationships/{index}/subjects"),
                            format!(
                                "verification subject `{subject}` is not a Feature, guarantee, or requirement owned by target `{}`",
                                relationship.target
                            ),
                        );
                    }
                }
                relationships.push(ResolvedTypedRelationship {
                    source: contract.id.clone(),
                    kind: relationship.kind,
                    target: relationship.target.clone(),
                    subjects: relationship.subjects.clone(),
                    provenance: provenance(contract_path, format!("/relationships/{index}")),
                });
                expected
                    .entry(contract.id.clone())
                    .or_default()
                    .entry(relationship.target.clone())
                    .or_default()
                    .insert(ResolvedRelationshipType::Verifies);
            }
        }

        let containment = derive_containment(&loaded, &id_to_path);
        let effective_constraints = self.resolve_constraints(&loaded, &id_to_path, &containment);
        self.validate_behavior(&loaded, &id_to_path, &features, &checkpoints);
        if !self.violations.is_empty() {
            return self.failure();
        }

        let modules = loaded
            .into_iter()
            .map(|(path, (contract_path, contract, digest))| {
                let id = contract.id.clone();
                let parent_id = containment.get(&id).cloned().flatten();
                (
                    id,
                    ResolvedModule {
                        path,
                        contract_path,
                        parent_id,
                        digest,
                        contract,
                    },
                )
            })
            .collect();
        let mut graph = ContractCoherencyGraph {
            modules,
            module_paths: id_to_path,
            capabilities,
            features,
            requirements,
            guarantees,
            checkpoints,
            direct_requirements,
            relationships,
            effective_constraints,
            containment,
            consumers: consumers
                .into_iter()
                .map(|(provider, values)| (provider, values.into_iter().collect()))
                .collect(),
            expected_readme_relationships: expected,
            standard: self.standard.clone(),
            observed_tests: self.observed_tests.map(<[_]>::to_vec),
            coherency_findings: Vec::new(),
        };
        let semantic_violations = graph.analyze_coherency();
        graph.coherency_findings.clone_from(&semantic_violations);
        CcgCompilation {
            graph: Some(graph),
            violations: semantic_violations,
            test_reference_resolution_supported: self.observed_tests.is_some(),
        }
    }

    fn resolve_constraints(
        &mut self,
        loaded: &BTreeMap<String, (String, ModuleContract, String)>,
        id_to_path: &BTreeMap<String, String>,
        containment: &BTreeMap<String, Option<String>>,
    ) -> BTreeMap<String, Vec<ResolvedConstraint>> {
        let path_to_id: BTreeMap<&str, &str> = id_to_path
            .iter()
            .map(|(id, path)| (path.as_str(), id.as_str()))
            .collect();
        let mut order: Vec<&str> = loaded.keys().map(String::as_str).collect();
        order.sort_by_key(|path| (path.matches('/').count(), *path));
        let mut effective = BTreeMap::<String, Vec<ResolvedConstraint>>::new();
        for path in order {
            let Some(id) = path_to_id.get(path).copied() else {
                continue;
            };
            let (contract_path, contract, _) = &loaded[path];
            let mut values = containment
                .get(id)
                .and_then(Option::as_deref)
                .and_then(|parent| effective.get(parent))
                .map(|parent_values| {
                    parent_values
                        .iter()
                        .filter(|value| value.declared_scope == ConstraintScope::Subtree)
                        .cloned()
                        .map(|mut value| {
                            value.inherited = true;
                            value
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let inherited_subtree_rules: BTreeSet<String> = values
                .iter()
                .filter(|value| value.declared_scope == ConstraintScope::Subtree)
                .map(|value| value.rule.clone())
                .collect();
            for (index, constraint) in contract.constraints.iter().enumerate() {
                if !self.standard.rule_ids.contains(&constraint.rule) {
                    self.violation(
                        contract_path,
                        format!("/constraints/{index}/rule"),
                        format!(
                            "constraint rule `{}` does not exist in selected standard",
                            constraint.rule
                        ),
                    );
                }
                if constraint.scope == ConstraintScope::Subtree
                    && inherited_subtree_rules.contains(&constraint.rule)
                {
                    self.violation(
                        contract_path,
                        format!("/constraints/{index}"),
                        format!(
                            "subtree constraint `{}` redundantly redeclares an inherited obligation",
                            constraint.rule
                        ),
                    );
                }
                values.push(ResolvedConstraint {
                    rule: constraint.rule.clone(),
                    declared_by: id.into(),
                    declared_scope: constraint.scope,
                    inherited: false,
                    provenance: provenance(contract_path, format!("/constraints/{index}")),
                });
            }
            values.sort_by(|left, right| {
                (
                    left.rule.as_str(),
                    left.declared_by.as_str(),
                    left.declared_scope,
                )
                    .cmp(&(
                        right.rule.as_str(),
                        right.declared_by.as_str(),
                        right.declared_scope,
                    ))
            });
            effective.insert(id.into(), values);
        }
        effective
    }

    #[allow(clippy::too_many_lines)]
    fn validate_behavior(
        &mut self,
        loaded: &BTreeMap<String, (String, ModuleContract, String)>,
        id_to_path: &BTreeMap<String, String>,
        features: &BTreeMap<String, OwnedIdentity>,
        checkpoints: &BTreeMap<String, ResolvedCheckpoint>,
    ) {
        for (module_path, (contract_path, contract, _)) in loaded {
            for (index, checkpoint) in contract.behavior.iter().enumerate() {
                let Some(feature) = features.get(&checkpoint.feature) else {
                    self.violation(
                        contract_path,
                        format!("/behavior/{index}/feature"),
                        format!("Feature `{}` does not exist", checkpoint.feature),
                    );
                    continue;
                };
                let owner_path = &id_to_path[&feature.owner];
                if !is_same_or_descendant_module(module_path, owner_path) {
                    self.violation(
                        contract_path,
                        format!("/behavior/{index}/feature"),
                        format!(
                            "Feature `{}` is not owned by this Module or an ancestor",
                            checkpoint.feature
                        ),
                    );
                }
                for transition in &checkpoint.transitions {
                    match checkpoints.get(&transition.target) {
                        None => self.violation(
                            contract_path,
                            format!("/behavior/{index}/transitions"),
                            format!("transition target `{}` does not exist", transition.target),
                        ),
                        Some(target) if target.feature != checkpoint.feature => self.violation(
                            contract_path,
                            format!("/behavior/{index}/transitions"),
                            format!(
                                "transition `{}` crosses from Feature `{}` to `{}`",
                                transition.target, checkpoint.feature, target.feature
                            ),
                        ),
                        Some(_) => {}
                    }
                }
            }
        }
    }

    fn violation(
        &mut self,
        path: impl Into<String>,
        pointer: impl Into<String>,
        message: impl Into<String>,
    ) {
        let path = path.into();
        let pointer = pointer.into();
        self.violations.push(CcgViolation {
            code: "CCG-CONTRACT-INVALID".into(),
            input_facts: vec![format!("source:{path}:{pointer}")],
            provenance_closure: vec![CcgSourceProvenance::new(&path, &pointer)],
            path,
            pointer,
            message: message.into(),
        });
    }

    fn failure(mut self) -> CcgCompilation {
        self.violations.sort();
        self.violations.dedup();
        CcgCompilation {
            graph: None,
            violations: self.violations,
            test_reference_resolution_supported: self.observed_tests.is_some(),
        }
    }
}

fn derive_containment(
    loaded: &BTreeMap<String, (String, ModuleContract, String)>,
    id_to_path: &BTreeMap<String, String>,
) -> BTreeMap<String, Option<String>> {
    let path_to_id: BTreeMap<&str, &str> = id_to_path
        .iter()
        .map(|(id, path)| (path.as_str(), id.as_str()))
        .collect();
    loaded
        .iter()
        .map(|(path, (_, contract, _))| {
            let parent = parent_module_path(path)
                .and_then(|parent| path_to_id.get(parent).copied())
                .map(str::to_owned);
            (contract.id.clone(), parent)
        })
        .collect()
}

fn discover_module_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut modules = BTreeSet::from([String::new()]);
    for path in paths {
        let segments: Vec<&str> = path.split('/').collect();
        for index in 0..segments.len().saturating_sub(1) {
            if segments[index] == "mods" && index + 1 < segments.len() {
                modules.insert(segments[..=index + 1].join("/"));
            }
        }
    }
    modules
}

fn parent_module_path(path: &str) -> Option<&str> {
    if path.is_empty() {
        None
    } else {
        path.rsplit_once("/mods/")
            .map_or(Some(""), |(parent, _)| Some(parent))
    }
}

fn is_same_or_descendant_module(candidate: &str, ancestor: &str) -> bool {
    candidate == ancestor
        || if ancestor.is_empty() {
            true
        } else {
            candidate.starts_with(&format!("{ancestor}/mods/"))
        }
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}

fn provenance(path: &str, pointer: String) -> ContractProvenance {
    ContractProvenance {
        contract_path: path.into(),
        pointer,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn stable_id(field: &str, value: &str) -> Result<StableId, ModuleContractModelError> {
    StableId::parse(value)
        .map_err(|error| model_error(format!("`{field}` identity `{value}` is invalid: {error}")))
}

fn stable_namespace(
    field: &str,
    value: &str,
    namespace: &str,
) -> Result<(), ModuleContractModelError> {
    let stable = stable_id(field, value)?;
    if stable.namespace() != namespace {
        return Err(model_error(format!(
            "`{field}` identity `{value}` must use `{namespace}` namespace"
        )));
    }
    Ok(())
}

fn nonempty(field: &str, value: &str) -> Result<(), ModuleContractModelError> {
    if value.is_empty() || value.trim() != value {
        return Err(model_error(format!(
            "`{field}` must contain canonical nonempty text without surrounding whitespace"
        )));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(
    field: &str,
    values: impl IntoIterator<Item = T>,
) -> Result<(), ModuleContractModelError> {
    let values: Vec<T> = values.into_iter().collect();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(model_error(format!(
            "`{field}` must be strictly sorted and contain no duplicates"
        )));
    }
    Ok(())
}

fn model_error(message: impl Into<String>) -> ModuleContractModelError {
    ModuleContractModelError {
        message: message.into().into_boxed_str(),
    }
}

/// Explains why one Module contract could not be loaded.
#[derive(Debug)]
pub enum ModuleContractLoadError {
    /// JSON syntax or typed structure was invalid.
    Json(serde_json::Error),
    /// The schema version was absent, invalid, or unsupported.
    UnsupportedSchemaVersion(Option<u16>),
    /// Parsed local semantics violated the v2 contract model.
    Model(ModuleContractModelError),
    /// Serialization of the validated typed representation failed.
    Serialization(serde_json::Error),
    /// Source bytes did not equal mandatory canonical JSON serialization.
    NoncanonicalSerialization,
}

impl Display for ModuleContractLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "Module Contract JSON is invalid: {error}"),
            Self::UnsupportedSchemaVersion(Some(version)) => write!(
                formatter,
                "Module Contract schema version {version} is unsupported; v2 is required"
            ),
            Self::UnsupportedSchemaVersion(None) => formatter
                .write_str("Module Contract schema version is absent or invalid; v2 is required"),
            Self::Model(error) => write!(formatter, "Module Contract is invalid: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "Module Contract serialization failed: {error}")
            }
            Self::NoncanonicalSerialization => formatter
                .write_str("Module Contract is semantically valid but not canonically serialized"),
        }
    }
}

impl Error for ModuleContractLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) | Self::Serialization(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::UnsupportedSchemaVersion(_) | Self::NoncanonicalSerialization => None,
        }
    }
}

/// One deterministic local contract-model violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleContractModelError {
    message: Box<str>,
}

impl Display for ModuleContractModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ModuleContractModelError {}
