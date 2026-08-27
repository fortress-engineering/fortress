//! Declared Fortress project model loading and validation.
//!
//! The loader preserves the distinction between declared project state and
//! future repository observations. Parsing a manifest does not claim that the
//! repository conforms to its declarations.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

use crate::identity::{StableId, StableIdError};

/// Current supported project manifest schema family.
pub const PROJECT_SCHEMA_VERSION: u16 = 1;

/// A validated declared Fortress project manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProjectManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    name: String,
    standard: StandardReference,
    archetypes: Vec<String>,
    capabilities: Vec<String>,
    languages: Vec<String>,
    model: ModelPaths,
}

impl ProjectManifest {
    /// Parses a JSON manifest and validates its domain invariants.
    ///
    /// Parsing establishes only a valid declaration. It does not observe the
    /// repository or certify that declared paths and relationships are true.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectLoadError::Json`] for invalid JSON or structural type
    /// mismatches and [`ProjectLoadError::Model`] for a violated project-model
    /// invariant.
    pub fn from_json_str(source: &str) -> Result<Self, ProjectLoadError> {
        let manifest: Self = serde_json::from_str(source).map_err(ProjectLoadError::Json)?;
        manifest.validate().map_err(ProjectLoadError::Model)?;
        Ok(manifest)
    }

    /// Validates the declared project model without observing the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectModelError`] when a schema-family, identity,
    /// uniqueness, syntax, standard-state, or relative-path invariant fails.
    pub fn validate(&self) -> Result<(), ProjectModelError> {
        if self.schema.is_empty() {
            return Err(ProjectModelError::EmptyField("$schema"));
        }
        if self.schema_version != PROJECT_SCHEMA_VERSION {
            return Err(ProjectModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        StableId::parse(&self.id).map_err(|source| ProjectModelError::InvalidIdentity {
            field: "id",
            source,
        })?;
        if self.name.is_empty() {
            return Err(ProjectModelError::EmptyField("name"));
        }
        self.standard.validate()?;

        validate_unique_non_empty(CollectionKind::Archetype, &self.archetypes)?;
        if self.archetypes.iter().any(|value| !is_dotted_name(value)) {
            return Err(ProjectModelError::InvalidCollectionValue {
                kind: CollectionKind::Archetype,
                value: self
                    .archetypes
                    .iter()
                    .find(|value| !is_dotted_name(value))
                    .map_or_else(|| "<unknown>".into(), |value| value.clone().into()),
            });
        }

        validate_unique(CollectionKind::Capability, &self.capabilities)?;
        for capability in &self.capabilities {
            StableId::parse(capability).map_err(|source| ProjectModelError::InvalidIdentity {
                field: "capabilities",
                source,
            })?;
        }

        validate_unique_non_empty(CollectionKind::Language, &self.languages)?;
        if self.languages.iter().any(|value| !is_lower_name(value)) {
            return Err(ProjectModelError::InvalidCollectionValue {
                kind: CollectionKind::Language,
                value: self
                    .languages
                    .iter()
                    .find(|value| !is_lower_name(value))
                    .map_or_else(|| "<unknown>".into(), |value| value.clone().into()),
            });
        }

        self.model.validate()
    }

    /// Returns the stable project identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the project display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared standard reference.
    #[must_use]
    pub const fn standard(&self) -> &StandardReference {
        &self.standard
    }

    /// Returns the declared archetype identifiers.
    #[must_use]
    pub fn archetypes(&self) -> &[String] {
        &self.archetypes
    }

    /// Returns the declared capability identities.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns the declared implementation languages.
    #[must_use]
    pub fn languages(&self) -> &[String] {
        &self.languages
    }

    /// Returns paths to the remaining declared model documents.
    #[must_use]
    pub const fn model(&self) -> &ModelPaths {
        &self.model
    }
}

/// Standard edition referenced by a project manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct StandardReference {
    id: String,
    edition: String,
    status: StandardStatus,
    digest: Option<String>,
}

impl StandardReference {
    fn validate(&self) -> Result<(), ProjectModelError> {
        StableId::parse(&self.id).map_err(|source| ProjectModelError::InvalidIdentity {
            field: "standard.id",
            source,
        })?;
        if self.edition.is_empty() {
            return Err(ProjectModelError::EmptyField("standard.edition"));
        }
        if self.status == StandardStatus::Released && self.digest.is_none() {
            return Err(ProjectModelError::ReleasedStandardWithoutDigest);
        }
        if let Some(digest) = &self.digest {
            validate_sha256(digest)?;
        }
        Ok(())
    }

    /// Returns the stable standard identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact declared edition.
    #[must_use]
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// Returns whether the project uses a draft, candidate, or released bundle.
    #[must_use]
    pub const fn status(&self) -> StandardStatus {
        self.status
    }

    /// Returns the immutable standard digest when one is declared.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// Release state of a project-referenced standard bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StandardStatus {
    /// Mutable pre-release standard work.
    Draft,
    /// Pre-release candidate undergoing final validation.
    Candidate,
    /// Immutable released standard edition.
    Released,
}

/// Repository-relative locations of declared model documents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ModelPaths {
    architecture: String,
    features: Vec<String>,
    commands: String,
    certifications: String,
    active_changes: Vec<String>,
}

impl ModelPaths {
    fn validate(&self) -> Result<(), ProjectModelError> {
        validate_relative_path("model.architecture", &self.architecture)?;
        validate_unique_non_empty(CollectionKind::FeaturePath, &self.features)?;
        for path in &self.features {
            validate_relative_path("model.features", path)?;
        }
        validate_relative_path("model.commands", &self.commands)?;
        validate_relative_path("model.certifications", &self.certifications)?;
        validate_unique(CollectionKind::ActiveChangePath, &self.active_changes)?;
        for path in &self.active_changes {
            validate_relative_path("model.active_changes", path)?;
        }
        Ok(())
    }

    /// Returns the architecture declaration path.
    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Returns feature and capability ownership manifest paths.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.features
    }

    /// Returns the command registry path.
    #[must_use]
    pub fn commands(&self) -> &str {
        &self.commands
    }

    /// Returns the certification declaration path.
    #[must_use]
    pub fn certifications(&self) -> &str {
        &self.certifications
    }

    /// Returns active temporal change record paths.
    #[must_use]
    pub fn active_changes(&self) -> &[String] {
        &self.active_changes
    }
}

/// Collection whose syntax or uniqueness invariant failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionKind {
    /// Project archetype names.
    Archetype,
    /// Stable capability identities.
    Capability,
    /// Implementation language names.
    Language,
    /// Feature ownership manifest paths.
    FeaturePath,
    /// Active temporal change paths.
    ActiveChangePath,
}

impl Display for CollectionKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Archetype => "archetypes",
            Self::Capability => "capabilities",
            Self::Language => "languages",
            Self::FeaturePath => "model.features",
            Self::ActiveChangePath => "model.active_changes",
        })
    }
}

/// Explains why a project manifest could not be loaded.
#[derive(Debug)]
pub enum ProjectLoadError {
    /// JSON parsing or structural deserialization failed.
    Json(serde_json::Error),
    /// Parsed data violated a Fortress project-model invariant.
    Model(ProjectModelError),
}

impl Display for ProjectLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "project manifest JSON is invalid: {error}"),
            Self::Model(error) => write!(formatter, "project manifest model is invalid: {error}"),
        }
    }
}

impl Error for ProjectLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Model(error) => Some(error),
        }
    }
}

/// Explains a violated Fortress project-model invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectModelError {
    /// The schema-family version is not supported by this implementation.
    UnsupportedSchemaVersion(u16),
    /// A required string was empty.
    EmptyField(&'static str),
    /// A stable identity did not satisfy `STD-ID-001`.
    InvalidIdentity {
        /// Field containing the invalid identity.
        field: &'static str,
        /// Stable identity validation failure.
        source: StableIdError,
    },
    /// A collection repeated a value whose identity must be unique.
    DuplicateValue {
        /// Collection containing the duplicate.
        kind: CollectionKind,
        /// Repeated value.
        value: Box<str>,
    },
    /// A collection required at least one declared value.
    EmptyCollection(CollectionKind),
    /// A collection entry did not satisfy its canonical syntax.
    InvalidCollectionValue {
        /// Collection containing the invalid entry.
        kind: CollectionKind,
        /// Invalid entry.
        value: Box<str>,
    },
    /// A model path was empty, absolute, used backslashes, or escaped the root.
    InvalidRelativePath {
        /// Field containing the path.
        field: &'static str,
        /// Invalid path value.
        value: Box<str>,
    },
    /// A released standard reference omitted its immutable digest.
    ReleasedStandardWithoutDigest,
    /// A declared digest was not a canonical lowercase SHA-256 identity.
    InvalidSha256Digest(Box<str>),
}

impl Display for ProjectModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "project schema version {version} is unsupported")
            }
            Self::EmptyField(field) => write!(formatter, "field `{field}` must not be empty"),
            Self::InvalidIdentity { field, source } => {
                write!(
                    formatter,
                    "field `{field}` has an invalid identity: {source}"
                )
            }
            Self::DuplicateValue { kind, value } => {
                write!(formatter, "collection `{kind}` repeats `{value}`")
            }
            Self::EmptyCollection(kind) => {
                write!(formatter, "collection `{kind}` must not be empty")
            }
            Self::InvalidCollectionValue { kind, value } => {
                write!(
                    formatter,
                    "collection `{kind}` contains invalid value `{value}`"
                )
            }
            Self::InvalidRelativePath { field, value } => {
                write!(
                    formatter,
                    "field `{field}` contains invalid relative path `{value}`"
                )
            }
            Self::ReleasedStandardWithoutDigest => {
                formatter.write_str("released standard reference has no immutable digest")
            }
            Self::InvalidSha256Digest(value) => {
                write!(
                    formatter,
                    "digest `{value}` is not canonical lowercase SHA-256"
                )
            }
        }
    }
}

impl Error for ProjectModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIdentity { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_unique(kind: CollectionKind, values: &[String]) -> Result<(), ProjectModelError> {
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(ProjectModelError::DuplicateValue {
                kind,
                value: value.clone().into(),
            });
        }
    }
    Ok(())
}

fn validate_unique_non_empty(
    kind: CollectionKind,
    values: &[String],
) -> Result<(), ProjectModelError> {
    if values.is_empty() {
        return Err(ProjectModelError::EmptyCollection(kind));
    }
    validate_unique(kind, values)
}

fn is_lower_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_dotted_name(value: &str) -> bool {
    value.contains('.') && value.split('.').all(is_lower_name)
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), ProjectModelError> {
    let invalid = value.is_empty()
        || value.contains('\\')
        || value.starts_with('/')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".." || segment == ".");
    if invalid {
        return Err(ProjectModelError::InvalidRelativePath {
            field,
            value: value.into(),
        });
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ProjectModelError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ProjectModelError::InvalidSha256Digest(value.into()));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProjectModelError::InvalidSha256Digest(value.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProjectManifest, ProjectModelError, StandardStatus, validate_sha256};

    const MINIMAL_PROJECT: &str = r#"{
        "$schema": "schemas/v1/project.schema.json",
        "schema_version": 1,
        "id": "PF-FORTRESS",
        "name": "Fortress",
        "standard": {
            "id": "STD-FORTRESS-ENGINEERING",
            "edition": "1.0.0-draft.1",
            "status": "draft",
            "digest": null
        },
        "archetypes": ["package.library"],
        "capabilities": [],
        "languages": ["rust"],
        "model": {
            "architecture": ".fortress/architecture.json",
            "features": [".fortress/features.json"],
            "commands": ".fortress/commands.json",
            "certifications": ".fortress/certifications.json",
            "active_changes": []
        }
    }"#;

    /// `T-AF-PROJECT-MODEL-0001-R01-001`
    #[test]
    fn minimal_project_boundary_is_valid() {
        let project = ProjectManifest::from_json_str(MINIMAL_PROJECT).expect("fixture is valid");
        assert_eq!(project.standard().status(), StandardStatus::Draft);
        assert!(project.capabilities().is_empty());
    }

    /// `T-AF-PROJECT-MODEL-0001-R01-002`
    #[test]
    fn uppercase_sha256_is_not_canonical() {
        let digest = format!("sha256:{}", "A".repeat(64));
        assert!(matches!(
            validate_sha256(&digest),
            Err(ProjectModelError::InvalidSha256Digest(_))
        ));
    }
}
