//! Non-architectural repository operation configuration.
//!
//! Root Module Contract v2 owns project identity, display name, repository
//! grammar, and standard selection. This Data document retains only explicit
//! local observation policy that cannot be inferred from containment.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

/// Current supported operational project configuration schema.
pub const PROJECT_CONFIGURATION_SCHEMA_VERSION: u16 = 2;

/// Exact operational configuration schema identity.
pub const PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v2:project-configuration";

/// Validated non-architectural repository operation configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfiguration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    observation_exclusions: Vec<String>,
}

impl ProjectConfiguration {
    /// Parses and validates the operational configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectConfigurationLoadError::Json`] for invalid JSON and
    /// [`ProjectConfigurationLoadError::Model`] for schema or path violations.
    pub fn from_json_str(source: &str) -> Result<Self, ProjectConfigurationLoadError> {
        let configuration: Self =
            serde_json::from_str(source).map_err(ProjectConfigurationLoadError::Json)?;
        configuration
            .validate()
            .map_err(ProjectConfigurationLoadError::Model)?;
        Ok(configuration)
    }

    /// Returns explicit canonical observation exclusion prefixes.
    #[must_use]
    pub fn observation_exclusions(&self) -> &[String] {
        &self.observation_exclusions
    }

    fn validate(&self) -> Result<(), ProjectConfigurationModelError> {
        if self.schema != PROJECT_CONFIGURATION_SCHEMA {
            return Err(ProjectConfigurationModelError::InvalidSchema(
                self.schema.clone().into(),
            ));
        }
        if self.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION {
            return Err(ProjectConfigurationModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        let mut seen = BTreeSet::new();
        for path in &self.observation_exclusions {
            if !is_canonical_relative_path(path) {
                return Err(ProjectConfigurationModelError::InvalidExclusion(
                    path.clone().into(),
                ));
            }
            if !seen.insert(path.as_str()) {
                return Err(ProjectConfigurationModelError::DuplicateExclusion(
                    path.clone().into(),
                ));
            }
        }
        Ok(())
    }
}

/// Explains why project operation configuration could not be loaded.
#[derive(Debug)]
pub enum ProjectConfigurationLoadError {
    /// JSON syntax or typed shape was invalid.
    Json(serde_json::Error),
    /// The parsed configuration violated a model invariant.
    Model(ProjectConfigurationModelError),
}

impl Display for ProjectConfigurationLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => {
                write!(formatter, "project configuration JSON is invalid: {error}")
            }
            Self::Model(error) => write!(formatter, "project configuration is invalid: {error}"),
        }
    }
}

impl Error for ProjectConfigurationLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Model(error) => Some(error),
        }
    }
}

/// One deterministic project configuration invariant violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectConfigurationModelError {
    /// The schema identity did not select project configuration v2.
    InvalidSchema(Box<str>),
    /// The configuration schema version is unsupported.
    UnsupportedSchemaVersion(u16),
    /// An exclusion was not canonical and repository-relative.
    InvalidExclusion(Box<str>),
    /// An exclusion prefix appeared more than once.
    DuplicateExclusion(Box<str>),
}

impl Display for ProjectConfigurationModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema(value) => write!(
                formatter,
                "schema `{value}` is unsupported; `{PROJECT_CONFIGURATION_SCHEMA}` is required"
            ),
            Self::UnsupportedSchemaVersion(version) => write!(
                formatter,
                "project configuration schema version {version} is unsupported"
            ),
            Self::InvalidExclusion(value) => {
                write!(
                    formatter,
                    "observation exclusion `{value}` is not canonical"
                )
            }
            Self::DuplicateExclusion(value) => {
                write!(formatter, "observation exclusion `{value}` is duplicated")
            }
        }
    }
}

impl Error for ProjectConfigurationModelError {}

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
    use super::{ProjectConfiguration, ProjectConfigurationLoadError};

    /// `T-AF-PROJECT-MODEL-0001-R01-001`
    #[test]
    fn minimal_operational_configuration_is_valid() {
        let source = r#"{
          "$schema": "urn:fortress:schema:v2:project-configuration",
          "schema_version": 2,
          "observation_exclusions": [".git"]
        }"#;
        let configuration =
            ProjectConfiguration::from_json_str(source).expect("configuration validates");
        assert_eq!(configuration.observation_exclusions(), [".git"]);
    }

    /// `T-AF-PROJECT-MODEL-0001-R01-002`
    #[test]
    fn invalid_or_duplicate_exclusions_fail() {
        let invalid = r#"{
          "$schema": "urn:fortress:schema:v2:project-configuration",
          "schema_version": 2,
          "observation_exclusions": ["../outside"]
        }"#;
        assert!(matches!(
            ProjectConfiguration::from_json_str(invalid),
            Err(ProjectConfigurationLoadError::Model(_))
        ));
    }
}
