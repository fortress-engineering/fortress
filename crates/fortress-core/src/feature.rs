//! Typed feature and requirement declarations used by Snapshot Governance.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

/// Current supported feature-contract schema family.
pub const FEATURE_SCHEMA_VERSION: u16 = 1;

/// One feature contract bound to its canonical repository-relative source path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureContract {
    source_path: String,
    features: Vec<FeatureDeclaration>,
}

impl FeatureContract {
    /// Loads a typed feature contract without interpreting requirement evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FeatureLoadError`] for an unsafe source path, invalid JSON, or
    /// an unsupported schema family.
    pub fn from_json_str(source_path: &str, source: &str) -> Result<Self, FeatureLoadError> {
        if !is_canonical_relative_path(source_path) {
            return Err(FeatureLoadError::InvalidSourcePath(source_path.into()));
        }
        let wire: FeatureContractWire =
            serde_json::from_str(source).map_err(FeatureLoadError::Json)?;
        if wire.schema_version != FEATURE_SCHEMA_VERSION {
            return Err(FeatureLoadError::UnsupportedSchemaVersion(
                wire.schema_version,
            ));
        }
        if wire.schema.is_empty() {
            return Err(FeatureLoadError::EmptySchema);
        }
        Ok(Self {
            source_path: source_path.into(),
            features: wire.features,
        })
    }

    /// Returns the canonical contract path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns declared features in source order.
    #[must_use]
    pub fn features(&self) -> &[FeatureDeclaration] {
        &self.features
    }
}

/// One declared product or implementation capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FeatureDeclaration {
    id: String,
    title: String,
    status: FeatureStatus,
    parent: Option<String>,
    owner: String,
    zone: String,
    owned_paths: Vec<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    requirements: Vec<RequirementDeclaration>,
}

impl FeatureDeclaration {
    /// Returns the stable feature identity as declared.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the feature lifecycle status.
    #[must_use]
    pub const fn status(&self) -> FeatureStatus {
        self.status
    }

    /// Returns the feature's requirement declarations.
    #[must_use]
    pub fn requirements(&self) -> &[RequirementDeclaration] {
        &self.requirements
    }

    /// Returns whether required descriptive and ownership fields are populated.
    #[must_use]
    pub fn has_complete_declaration(&self) -> bool {
        !self.title.is_empty()
            && !self.owner.is_empty()
            && !self.zone.is_empty()
            && !self.owned_paths.is_empty()
            && self.parent.as_ref().is_none_or(|parent| !parent.is_empty())
            && self
                .dependencies
                .iter()
                .all(|dependency| !dependency.is_empty())
    }
}

/// Supported feature lifecycle states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureStatus {
    /// Declared future capability, not mandatory for current traceability.
    Planned,
    /// Current mandatory capability.
    Active,
    /// Still addressable but scheduled for retirement.
    Deprecated,
    /// Historical capability no longer evaluated as active.
    Retired,
}

/// One requirement and its declared evidence IDs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequirementDeclaration {
    id: String,
    statement: String,
    tests: Vec<String>,
}

impl RequirementDeclaration {
    /// Returns the declared requirement identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the normative requirement statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns test evidence IDs in declaration order.
    #[must_use]
    pub fn tests(&self) -> &[String] {
        &self.tests
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeatureContractWire {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    features: Vec<FeatureDeclaration>,
}

/// Explains why a feature contract could not be loaded.
#[derive(Debug)]
pub enum FeatureLoadError {
    /// Source path was not canonical and repository-relative.
    InvalidSourcePath(Box<str>),
    /// Contract JSON did not match the typed representation.
    Json(serde_json::Error),
    /// Schema family is not implemented.
    UnsupportedSchemaVersion(u16),
    /// Schema reference was empty.
    EmptySchema,
}

impl Display for FeatureLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourcePath(path) => {
                write!(formatter, "feature contract path `{path}` is invalid")
            }
            Self::Json(error) => write!(formatter, "feature contract JSON is invalid: {error}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "feature schema version {version} is unsupported")
            }
            Self::EmptySchema => formatter.write_str("feature contract schema reference is empty"),
        }
    }
}

impl Error for FeatureLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
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
