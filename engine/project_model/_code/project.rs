//! Repository operation and logical source-placement configuration.
//!
//! Root and descendant Module Contracts remain the sole semantic identity and
//! intent authority. This Data document owns observation policy plus the narrow
//! index that locates independently stored contracts and binds observed paths to
//! their stable IDs; a path never defines Module meaning.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::identity::StableId;

/// Current supported operational project configuration schema.
pub const PROJECT_CONFIGURATION_SCHEMA_VERSION: u16 = 3;

/// Exact operational configuration schema identity.
pub const PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v3:project-configuration";

const LEGACY_PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v2:project-configuration";

/// Validated repository operation and logical source-placement configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfiguration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    observation_exclusions: Vec<String>,
    #[serde(default)]
    logical_modules: Vec<LogicalModuleDeclaration>,
}

/// One authored semantic Module whose contract and implementation are not
/// required to share a physical directory.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalModuleDeclaration {
    module: String,
    contract: String,
    parent: String,
    bindings: Vec<SourcePathBinding>,
}

impl LogicalModuleDeclaration {
    /// Returns the stable authored Module identity.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns the repository-relative authoritative contract location.
    #[must_use]
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Returns the stable semantic parent Module identity.
    #[must_use]
    pub fn parent(&self) -> &str {
        &self.parent
    }

    /// Returns the canonical implementation membership selectors.
    #[must_use]
    pub fn bindings(&self) -> &[SourcePathBinding] {
        &self.bindings
    }
}

/// Closed deterministic source membership selector vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePathBindingKind {
    /// Match exactly one repository-relative source file.
    File,
    /// Match every source at or beneath one repository-relative prefix.
    Directory,
}

/// One canonical repository-relative source membership selector.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePathBinding {
    kind: SourcePathBindingKind,
    path: String,
}

impl SourcePathBinding {
    /// Creates one binding for programmatic integration and fixtures.
    #[must_use]
    pub fn new(kind: SourcePathBindingKind, path: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
        }
    }

    /// Returns the selector kind.
    #[must_use]
    pub const fn kind(&self) -> SourcePathBindingKind {
        self.kind
    }

    /// Returns the canonical repository-relative selector path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether this selector contains the supplied source path.
    #[must_use]
    pub fn matches(&self, source_path: &str) -> bool {
        match self.kind {
            SourcePathBindingKind::File => source_path == self.path,
            SourcePathBindingKind::Directory => {
                source_path == self.path || source_path.starts_with(&format!("{}/", self.path))
            }
        }
    }

    /// Returns deterministic specificity; exact files outrank every prefix.
    #[must_use]
    pub fn specificity(&self) -> (bool, usize) {
        (self.kind == SourcePathBindingKind::File, self.path.len())
    }
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

    /// Returns authored logical Module contract and source-placement bindings.
    #[must_use]
    pub fn logical_modules(&self) -> &[LogicalModuleDeclaration] {
        &self.logical_modules
    }

    fn validate(&self) -> Result<(), ProjectConfigurationModelError> {
        let supported_legacy = self.schema == LEGACY_PROJECT_CONFIGURATION_SCHEMA
            && self.schema_version == 2
            && self.logical_modules.is_empty();
        if self.schema != PROJECT_CONFIGURATION_SCHEMA && !supported_legacy {
            return Err(ProjectConfigurationModelError::InvalidSchema(
                self.schema.clone().into(),
            ));
        }
        if self.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION && !supported_legacy {
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
        let mut modules = BTreeSet::new();
        let mut contracts = BTreeSet::new();
        let mut selectors = BTreeSet::<(SourcePathBindingKind, &str)>::new();
        let mut previous_module = None;
        for declaration in &self.logical_modules {
            StableId::parse(declaration.module()).map_err(|_| {
                ProjectConfigurationModelError::InvalidModuleId(declaration.module.clone().into())
            })?;
            StableId::parse(declaration.parent()).map_err(|_| {
                ProjectConfigurationModelError::InvalidModuleId(declaration.parent.clone().into())
            })?;
            if declaration.module == declaration.parent {
                return Err(ProjectConfigurationModelError::SelfParent(
                    declaration.module.clone().into(),
                ));
            }
            if previous_module.is_some_and(|previous| previous >= declaration.module.as_str()) {
                return Err(ProjectConfigurationModelError::NoncanonicalModuleOrder);
            }
            previous_module = Some(declaration.module.as_str());
            if !modules.insert(declaration.module.as_str()) {
                return Err(ProjectConfigurationModelError::DuplicateModule(
                    declaration.module.clone().into(),
                ));
            }
            if !is_canonical_relative_path(declaration.contract())
                || declaration.contract == "contract.json"
                || !declaration.contract.ends_with("/contract.json")
            {
                return Err(ProjectConfigurationModelError::InvalidContractPath(
                    declaration.contract.clone().into(),
                ));
            }
            if !contracts.insert(declaration.contract.as_str()) {
                return Err(ProjectConfigurationModelError::DuplicateContractPath(
                    declaration.contract.clone().into(),
                ));
            }
            if declaration.bindings.is_empty() {
                return Err(ProjectConfigurationModelError::MissingBindings(
                    declaration.module.clone().into(),
                ));
            }
            if declaration
                .bindings
                .windows(2)
                .any(|pair| (pair[0].path(), pair[0].kind()) >= (pair[1].path(), pair[1].kind()))
            {
                return Err(ProjectConfigurationModelError::NoncanonicalBindingOrder(
                    declaration.module.clone().into(),
                ));
            }
            for binding in &declaration.bindings {
                if !is_canonical_relative_path(binding.path()) {
                    return Err(ProjectConfigurationModelError::InvalidBindingPath(
                        binding.path.clone().into(),
                    ));
                }
                if !selectors.insert((binding.kind(), binding.path())) {
                    return Err(ProjectConfigurationModelError::ConflictingBinding(
                        binding.path.clone().into(),
                    ));
                }
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
    /// A logical Module identity or parent identity was not canonical.
    InvalidModuleId(Box<str>),
    /// A logical Module attempted to parent itself.
    SelfParent(Box<str>),
    /// Logical Module declarations were not strictly ordered by identity.
    NoncanonicalModuleOrder,
    /// A logical Module identity appeared more than once.
    DuplicateModule(Box<str>),
    /// A logical Module contract path was not canonical or independent.
    InvalidContractPath(Box<str>),
    /// Two declarations referenced the same contract location.
    DuplicateContractPath(Box<str>),
    /// A logical Module declaration had no source membership selector.
    MissingBindings(Box<str>),
    /// Bindings were not strictly ordered and unique.
    NoncanonicalBindingOrder(Box<str>),
    /// A source membership path was not canonical and repository-relative.
    InvalidBindingPath(Box<str>),
    /// Equal selectors assigned one source territory ambiguously.
    ConflictingBinding(Box<str>),
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
            Self::InvalidModuleId(value) => {
                write!(formatter, "logical Module identity `{value}` is invalid")
            }
            Self::SelfParent(value) => {
                write!(formatter, "logical Module `{value}` cannot parent itself")
            }
            Self::NoncanonicalModuleOrder => {
                write!(
                    formatter,
                    "logical Modules must be strictly sorted by stable identity"
                )
            }
            Self::DuplicateModule(value) => {
                write!(formatter, "logical Module `{value}` is duplicated")
            }
            Self::InvalidContractPath(value) => write!(
                formatter,
                "logical Module contract `{value}` must be a canonical non-root `contract.json` path"
            ),
            Self::DuplicateContractPath(value) => {
                write!(
                    formatter,
                    "logical Module contract path `{value}` is duplicated"
                )
            }
            Self::MissingBindings(value) => {
                write!(formatter, "logical Module `{value}` has no source bindings")
            }
            Self::NoncanonicalBindingOrder(value) => write!(
                formatter,
                "logical Module `{value}` bindings must be strictly sorted and unique"
            ),
            Self::InvalidBindingPath(value) => {
                write!(
                    formatter,
                    "logical source binding `{value}` is not canonical"
                )
            }
            Self::ConflictingBinding(value) => write!(
                formatter,
                "logical source binding `{value}` is assigned with equal authority more than once"
            ),
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
