//! Typed machine authority for one canonical Fortress Module.
//!
//! Filesystem containment owns parentage, children, and direct elemental
//! membership. This contract owns only stable Module identity and explicitly
//! typed outbound architectural relationships.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::identity::{StableId, StableIdError};

/// Current supported Module contract schema family.
pub const MODULE_CONTRACT_SCHEMA_VERSION: u16 = 1;

/// A validated canonical Module contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModuleContract {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    display_name: String,
    relationships: Vec<ModuleRelationship>,
}

impl ModuleContract {
    /// Parses and validates one Module contract document.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleContractLoadError::Json`] for invalid JSON or field
    /// types and [`ModuleContractLoadError::Model`] for domain violations.
    pub fn from_json_str(source: &str) -> Result<Self, ModuleContractLoadError> {
        let contract: Self = serde_json::from_str(source).map_err(ModuleContractLoadError::Json)?;
        contract
            .validate()
            .map_err(ModuleContractLoadError::Model)?;
        Ok(contract)
    }

    /// Validates canonical identity, display name, and relationship ordering.
    ///
    /// Target existence is a repository-level invariant evaluated after every
    /// Module contract has been loaded.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic contract-model violation.
    pub fn validate(&self) -> Result<(), ModuleContractModelError> {
        if self.schema.trim().is_empty() {
            return Err(ModuleContractModelError::EmptyField("$schema"));
        }
        if self.schema_version != MODULE_CONTRACT_SCHEMA_VERSION {
            return Err(ModuleContractModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        StableId::parse(&self.id).map_err(ModuleContractModelError::InvalidIdentity)?;
        if self.display_name.trim().is_empty() || self.display_name != self.display_name.trim() {
            return Err(ModuleContractModelError::InvalidDisplayName);
        }

        let mut previous_target: Option<&str> = None;
        for relationship in &self.relationships {
            StableId::parse(&relationship.target).map_err(|source| {
                ModuleContractModelError::InvalidRelationshipTarget {
                    target: relationship.target.clone().into(),
                    source,
                }
            })?;
            if relationship.target == self.id {
                return Err(ModuleContractModelError::SelfRelationship(
                    relationship.target.clone().into(),
                ));
            }
            if relationship.types.is_empty() {
                return Err(ModuleContractModelError::EmptyRelationshipTypes(
                    relationship.target.clone().into(),
                ));
            }
            if previous_target.is_some_and(|previous| previous >= relationship.target.as_str()) {
                return Err(if previous_target == Some(relationship.target.as_str()) {
                    ModuleContractModelError::DuplicateRelationshipTarget(
                        relationship.target.clone().into(),
                    )
                } else {
                    ModuleContractModelError::NoncanonicalRelationshipOrder
                });
            }
            if relationship.types.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ModuleContractModelError::NoncanonicalRelationshipTypes(
                    relationship.target.clone().into(),
                ));
            }
            previous_target = Some(&relationship.target);
        }
        Ok(())
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

    /// Returns outbound relationships sorted by target identity.
    #[must_use]
    pub fn relationships(&self) -> &[ModuleRelationship] {
        &self.relationships
    }
}

/// One target-grouped outbound architectural relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModuleRelationship {
    target: String,
    types: Vec<ModuleRelationshipType>,
}

impl ModuleRelationship {
    /// Returns the stable target Module identity.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the canonical sorted relationship types for the target.
    #[must_use]
    pub fn types(&self) -> &[ModuleRelationshipType] {
        &self.types
    }
}

/// Currently enforceable outbound Module relationship types.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleRelationshipType {
    /// The source Module requires behavior or facts owned by the target.
    DependsOn,
    /// The source Module provides verification evidence for the target.
    Verifies,
}

impl ModuleRelationshipType {
    /// Returns the canonical serialized spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DependsOn => "depends_on",
            Self::Verifies => "verifies",
        }
    }
}

/// Explains why a Module contract could not be loaded.
#[derive(Debug)]
pub enum ModuleContractLoadError {
    /// JSON syntax or structural deserialization failed.
    Json(serde_json::Error),
    /// Parsed data violated a Module contract invariant.
    Model(ModuleContractModelError),
}

impl Display for ModuleContractLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "Module contract JSON is invalid: {error}"),
            Self::Model(error) => write!(formatter, "Module contract is invalid: {error}"),
        }
    }
}

impl Error for ModuleContractLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Model(error) => Some(error),
        }
    }
}

/// Explains a violated Module contract invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModuleContractModelError {
    /// The schema family is unsupported.
    UnsupportedSchemaVersion(u16),
    /// A required field is empty.
    EmptyField(&'static str),
    /// The stable Module identity is invalid.
    InvalidIdentity(StableIdError),
    /// The display name is empty or has surrounding whitespace.
    InvalidDisplayName,
    /// A relationship target identity is invalid.
    InvalidRelationshipTarget {
        /// Invalid target value.
        target: Box<str>,
        /// Stable identity violation.
        source: StableIdError,
    },
    /// A Module relates to itself.
    SelfRelationship(Box<str>),
    /// A target has no typed relationship.
    EmptyRelationshipTypes(Box<str>),
    /// A target appears more than once instead of grouping its types.
    DuplicateRelationshipTarget(Box<str>),
    /// Target groups are not in stable identity order.
    NoncanonicalRelationshipOrder,
    /// Relationship types are duplicated or not canonically ordered.
    NoncanonicalRelationshipTypes(Box<str>),
}

impl Display for ModuleContractModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "Module contract schema version {version} is unsupported"
                )
            }
            Self::EmptyField(field) => write!(formatter, "field `{field}` must not be empty"),
            Self::InvalidIdentity(error) => {
                write!(formatter, "Module identity is invalid: {error}")
            }
            Self::InvalidDisplayName => formatter.write_str(
                "display_name must contain canonical text without surrounding whitespace",
            ),
            Self::InvalidRelationshipTarget { target, source } => {
                write!(
                    formatter,
                    "relationship target `{target}` is invalid: {source}"
                )
            }
            Self::SelfRelationship(target) => {
                write!(
                    formatter,
                    "Module must not declare a relationship to itself (`{target}`)"
                )
            }
            Self::EmptyRelationshipTypes(target) => {
                write!(
                    formatter,
                    "relationship target `{target}` has no relationship type"
                )
            }
            Self::DuplicateRelationshipTarget(target) => write!(
                formatter,
                "relationship target `{target}` is duplicated; group its types once"
            ),
            Self::NoncanonicalRelationshipOrder => {
                formatter.write_str("relationship targets are not in stable identity order")
            }
            Self::NoncanonicalRelationshipTypes(target) => write!(
                formatter,
                "relationship types for `{target}` are duplicated or not in canonical order"
            ),
        }
    }
}

impl Error for ModuleContractModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIdentity(error) => Some(error),
            Self::InvalidRelationshipTarget { source, .. } => Some(source),
            _ => None,
        }
    }
}
