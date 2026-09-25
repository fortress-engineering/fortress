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
use crate::profile::{ModuleProfileSelectionInput, ProfileReferenceInput, ProfileSelectionInput};

#[path = "evaluation_key.rs"]
mod evaluation_key;

pub use evaluation_key::{AuthorityBinding, EvaluationKey};

/// Current supported operational project configuration schema.
pub const PROJECT_CONFIGURATION_SCHEMA_VERSION: u16 = 4;

/// Exact operational configuration schema identity.
pub const PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v4:project-configuration";

const LEGACY_PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v2:project-configuration";
const PREVIOUS_PROJECT_CONFIGURATION_SCHEMA: &str = "urn:fortress:schema:v3:project-configuration";

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
    #[serde(default)]
    governance: Option<GovernanceSelection>,
    #[serde(default)]
    assurance_profiles: Vec<ProfileReference>,
}

/// Exact immutable Standard-owned profile identity selected by a project.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReference {
    id: String,
    version: String,
    digest: String,
}

impl ProfileReference {
    /// Returns the stable profile identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact selected profile version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the exact selected profile definition digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// A project-wide coverage threshold protected by project authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageFloor {
    minimum_semantic_functions: u64,
    minimum_evaluable_basis_points: u16,
}

impl CoverageFloor {
    /// Returns the minimum number of functions that must receive semantic analysis.
    #[must_use]
    pub const fn minimum_semantic_functions(&self) -> u64 {
        self.minimum_semantic_functions
    }

    /// Returns the required evaluable share in basis points.
    #[must_use]
    pub const fn minimum_evaluable_basis_points(&self) -> u16 {
        self.minimum_evaluable_basis_points
    }
}

/// Explicit versioned governance composition for the whole project.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceSelection {
    default_layout: String,
    selected_profiles: Vec<ProfileReference>,
    #[serde(default)]
    module_overrides: Vec<ModuleProfileOverride>,
    #[serde(default)]
    coverage_floor: Option<CoverageFloor>,
}

impl GovernanceSelection {
    /// Returns the selected default layout interpretation.
    #[must_use]
    pub fn default_layout(&self) -> &str {
        &self.default_layout
    }

    /// Returns project-wide governance profile references.
    #[must_use]
    pub fn selected_profiles(&self) -> &[ProfileReference] {
        &self.selected_profiles
    }

    /// Returns stable Module-scoped profile overrides.
    #[must_use]
    pub fn module_overrides(&self) -> &[ModuleProfileOverride] {
        &self.module_overrides
    }

    /// Returns the optional protected semantic coverage floor.
    #[must_use]
    pub const fn coverage_floor(&self) -> Option<&CoverageFloor> {
        self.coverage_floor.as_ref()
    }
}

/// Explicit profile selection for one stable semantic Module identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleProfileOverride {
    module: String,
    selected_profiles: Vec<ProfileReference>,
    #[serde(default)]
    assurance_profiles: Vec<ProfileReference>,
}

impl ModuleProfileOverride {
    /// Returns the stable Module identity; physical paths are never accepted here.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns governance profiles selected for this Module.
    #[must_use]
    pub fn selected_profiles(&self) -> &[ProfileReference] {
        &self.selected_profiles
    }

    /// Returns assurance profiles selected for this Module.
    #[must_use]
    pub fn assurance_profiles(&self) -> &[ProfileReference] {
        &self.assurance_profiles
    }
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
        crate::wire::reject_duplicate_json_keys(source)
            .map_err(ProjectConfigurationLoadError::Json)?;
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

    /// Returns explicit project governance selection, or `None` for legacy native defaults.
    #[must_use]
    pub const fn governance(&self) -> Option<&GovernanceSelection> {
        self.governance.as_ref()
    }

    /// Returns project-wide assurance profile references.
    #[must_use]
    pub fn assurance_profiles(&self) -> &[ProfileReference] {
        &self.assurance_profiles
    }

    /// Projects authored selection into the Standard Registry resolver boundary.
    /// Legacy v2/v3 configurations return `None` and therefore receive the
    /// reviewed native default without inventing new project authority bytes.
    #[must_use]
    pub fn profile_selection(&self) -> Option<ProfileSelectionInput> {
        self.governance.as_ref().map(|governance| {
            ProfileSelectionInput::new(
                &governance.default_layout,
                governance
                    .selected_profiles
                    .iter()
                    .map(profile_reference_input)
                    .collect(),
                governance
                    .module_overrides
                    .iter()
                    .map(|profile_override| {
                        ModuleProfileSelectionInput::new(
                            &profile_override.module,
                            profile_override
                                .selected_profiles
                                .iter()
                                .map(profile_reference_input)
                                .collect(),
                            profile_override
                                .assurance_profiles
                                .iter()
                                .map(profile_reference_input)
                                .collect(),
                        )
                    })
                    .collect(),
                self.assurance_profiles
                    .iter()
                    .map(profile_reference_input)
                    .collect(),
            )
        })
    }

    fn validate(&self) -> Result<(), ProjectConfigurationModelError> {
        self.validate_schema()?;
        self.validate_observation_exclusions()?;
        self.validate_governance()?;
        self.validate_logical_modules()
    }

    fn validate_schema(&self) -> Result<(), ProjectConfigurationModelError> {
        let supported_legacy = self.schema == LEGACY_PROJECT_CONFIGURATION_SCHEMA
            && self.schema_version == 2
            && self.logical_modules.is_empty()
            && self.governance.is_none()
            && self.assurance_profiles.is_empty();
        let supported_previous = self.schema == PREVIOUS_PROJECT_CONFIGURATION_SCHEMA
            && self.schema_version == 3
            && self.governance.is_none()
            && self.assurance_profiles.is_empty();
        if self.schema != PROJECT_CONFIGURATION_SCHEMA && !supported_previous && !supported_legacy {
            return Err(ProjectConfigurationModelError::InvalidSchema(
                self.schema.clone().into(),
            ));
        }
        if self.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION
            && !supported_previous
            && !supported_legacy
        {
            return Err(ProjectConfigurationModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.schema == PROJECT_CONFIGURATION_SCHEMA && self.governance.is_none() {
            return Err(ProjectConfigurationModelError::MissingGovernanceSelection);
        }
        Ok(())
    }

    fn validate_governance(&self) -> Result<(), ProjectConfigurationModelError> {
        if let Some(governance) = &self.governance {
            validate_layout_id(&governance.default_layout)?;
            if governance.selected_profiles.is_empty() {
                return Err(ProjectConfigurationModelError::MissingGovernanceProfile);
            }
            validate_profile_references(&governance.selected_profiles)?;
            if governance
                .coverage_floor
                .as_ref()
                .is_some_and(|floor| floor.minimum_evaluable_basis_points > 10_000)
            {
                return Err(ProjectConfigurationModelError::InvalidCoverageFloor);
            }
            let mut override_modules = BTreeSet::new();
            for profile_override in &governance.module_overrides {
                StableId::parse(profile_override.module()).map_err(|_| {
                    ProjectConfigurationModelError::InvalidModuleId(
                        profile_override.module.clone().into(),
                    )
                })?;
                if !override_modules.insert(profile_override.module()) {
                    return Err(ProjectConfigurationModelError::DuplicateModuleOverride(
                        profile_override.module.clone().into(),
                    ));
                }
                if profile_override.selected_profiles.is_empty() {
                    return Err(ProjectConfigurationModelError::MissingModuleProfile(
                        profile_override.module.clone().into(),
                    ));
                }
                validate_profile_references(&profile_override.selected_profiles)?;
                validate_profile_references(&profile_override.assurance_profiles)?;
            }
        }
        validate_profile_references(&self.assurance_profiles)
    }

    fn validate_logical_modules(&self) -> Result<(), ProjectConfigurationModelError> {
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
                || declaration.contract.starts_with("__fortress/")
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
                if binding.path() == "__fortress" || binding.path().starts_with("__fortress/") {
                    return Err(ProjectConfigurationModelError::ControlSourceBinding(
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

    fn validate_observation_exclusions(&self) -> Result<(), ProjectConfigurationModelError> {
        let mut seen = BTreeSet::new();
        for path in &self.observation_exclusions {
            if !is_canonical_relative_path(path) {
                return Err(ProjectConfigurationModelError::InvalidExclusion(
                    path.clone().into(),
                ));
            }
            if path == "__fortress" || path.starts_with("__fortress/") {
                return Err(ProjectConfigurationModelError::ControlAuthorityExcluded(
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
    /// An observation exclusion attempted to hide active control authority.
    ControlAuthorityExcluded(Box<str>),
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
    /// A logical source binding attempted to treat control storage as application source.
    ControlSourceBinding(Box<str>),
    /// Equal selectors assigned one source territory ambiguously.
    ConflictingBinding(Box<str>),
    /// Current configuration omitted explicit governance composition.
    MissingGovernanceSelection,
    /// Governance composition selected no immutable profile.
    MissingGovernanceProfile,
    /// A layout identity was empty or noncanonical.
    InvalidLayoutId(Box<str>),
    /// A profile reference was malformed.
    InvalidProfileReference(Box<str>),
    /// A profile reference appeared more than once.
    DuplicateProfileReference(Box<str>),
    /// A Module override appeared more than once.
    DuplicateModuleOverride(Box<str>),
    /// A Module override selected no governance profile.
    MissingModuleProfile(Box<str>),
    /// A configured coverage floor exceeded its closed range.
    InvalidCoverageFloor,
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
            Self::ControlAuthorityExcluded(value) => write!(
                formatter,
                "observation exclusion `{value}` cannot suppress the control namespace"
            ),
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
            Self::ControlSourceBinding(value) => write!(
                formatter,
                "logical source binding `{value}` cannot enter the control namespace"
            ),
            Self::ConflictingBinding(value) => write!(
                formatter,
                "logical source binding `{value}` is assigned with equal authority more than once"
            ),
            Self::MissingGovernanceSelection => formatter
                .write_str("project configuration v4 requires one explicit governance composition"),
            Self::MissingGovernanceProfile => {
                formatter.write_str("governance composition must select at least one profile")
            }
            Self::InvalidLayoutId(value) => {
                write!(formatter, "layout identity `{value}` is not canonical")
            }
            Self::InvalidProfileReference(value) => {
                write!(formatter, "profile reference `{value}` is invalid")
            }
            Self::DuplicateProfileReference(value) => {
                write!(formatter, "profile reference `{value}` is duplicated")
            }
            Self::DuplicateModuleOverride(value) => {
                write!(formatter, "Module profile override `{value}` is duplicated")
            }
            Self::MissingModuleProfile(value) => write!(
                formatter,
                "Module profile override `{value}` selects no governance profile"
            ),
            Self::InvalidCoverageFloor => formatter
                .write_str("coverage floor evaluability must be between 0 and 10000 basis points"),
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

fn validate_layout_id(value: &str) -> Result<(), ProjectConfigurationModelError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ProjectConfigurationModelError::InvalidLayoutId(
            value.into(),
        ));
    }
    Ok(())
}

fn validate_profile_references(
    profiles: &[ProfileReference],
) -> Result<(), ProjectConfigurationModelError> {
    let mut seen = BTreeSet::new();
    for profile in profiles {
        let valid_id = !profile.id.is_empty()
            && profile
                .id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-');
        let components = profile.version.split('.').collect::<Vec<_>>();
        let valid_version = components.len() == 3
            && components.iter().all(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            });
        let valid_digest = profile.digest.strip_prefix("sha256:").is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        if !valid_id || !valid_version || !valid_digest {
            return Err(ProjectConfigurationModelError::InvalidProfileReference(
                profile.id.clone().into(),
            ));
        }
        if !seen.insert((profile.id.as_str(), profile.version.as_str())) {
            return Err(ProjectConfigurationModelError::DuplicateProfileReference(
                profile.id.clone().into(),
            ));
        }
    }
    Ok(())
}

fn profile_reference_input(reference: &ProfileReference) -> ProfileReferenceInput {
    ProfileReferenceInput::new(&reference.id, &reference.version, &reference.digest)
}
