//! Fixed repository control namespace and its closed role registry.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Only supported repository control root.
pub const CONTROL_ROOT: &str = "__fortress";
/// Only supported active project configuration path.
pub const PROJECT_CONFIGURATION_PATH: &str = "__fortress/.fsconfig";
/// Previous project configuration location accepted only by migration tooling.
pub const LEGACY_PROJECT_CONFIGURATION_PATH: &str = "_data/project.json";
/// Fixed generated evidence tree; it is never recursively application source.
pub const EVIDENCE_ROOT: &str = "__fortress/evidence";

/// Declarative layout bytes shared by all compiled adapters.
pub const CONTROL_LAYOUT_SOURCE: &str = include_str!("../_data/control_layout_v1.json");

/// Whether a control entry participates in the current source subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlSourceBinding {
    /// Authored active input whose exact path and bytes remain bound.
    Required,
    /// Generated material validated separately and excluded from recursive source input.
    Nonrecursive,
}

/// Closed initial control role vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlRole {
    /// Operational repository configuration.
    ProjectConfiguration,
    /// Finding lifecycle and exception authority.
    FindingGovernance,
    /// Root information-flow authority.
    GlobalInformationFlowPolicy,
    /// Current assessment selection index.
    AssessmentSelectionIndex,
    /// Immutable assessment generation manifest.
    GenerationManifest,
    /// Registered immutable assessment payload.
    GeneratedAssessmentPayload,
    /// Entry beneath the namespace that has no registered role.
    Unrecognized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ControlRoleRecord {
    path: String,
    role: ControlRole,
    owner: String,
    source_binding: ControlSourceBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ManifestMember {
    name: String,
    owner: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ArtifactStorage {
    Included,
    ExternalMaterialization,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProductionGroup {
    Semantic,
    Certification,
    Certificate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ControlArtifactRecord {
    id: String,
    logical_path: String,
    owner: String,
    schema_ref: String,
    producer_semantic_version: String,
    production_group: ProductionGroup,
    storage: ArtifactStorage,
    member_name: Option<String>,
}

/// Installed immutable control layout registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlLayout {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    root: String,
    config: String,
    roles: Vec<ControlRoleRecord>,
    manifest_member: ManifestMember,
    artifact_registry: Vec<ControlArtifactRecord>,
}

/// One path resolved against the installed control registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedControlEntry {
    path: String,
    role: ControlRole,
    owner: String,
    source_binding: ControlSourceBinding,
}

impl ResolvedControlEntry {
    /// Returns the canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the exact registered role.
    #[must_use]
    pub const fn role(&self) -> ControlRole {
        self.role
    }
    /// Returns the owning Module responsibility.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Returns whether the entry participates in source identity.
    #[must_use]
    pub const fn source_binding(&self) -> ControlSourceBinding {
        self.source_binding
    }
}

impl ControlLayout {
    /// Loads and validates the installed declarative registry.
    ///
    /// # Panics
    /// Panics only when bundled release data contradicts the compiled contract.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_json_str(CONTROL_LAYOUT_SOURCE).expect("installed control layout must be valid")
    }

    /// Parses one layout registry and enforces fixed root and canonical ordering.
    ///
    /// # Errors
    /// Returns an error for malformed, duplicate, unsafe, or noncanonical data.
    pub fn from_json_str(source: &str) -> Result<Self, ControlLayoutError> {
        crate::wire::reject_duplicate_json_keys(source).map_err(ControlLayoutError::Json)?;
        let value: Self = serde_json::from_str(source).map_err(ControlLayoutError::Json)?;
        value.validate()?;
        Ok(value)
    }

    /// Returns a stable digest of the exact installed registry bytes.
    #[must_use]
    pub fn digest(&self) -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(CONTROL_LAYOUT_SOURCE.as_bytes())
        )
    }

    /// Resolves a path under the control root. Paths outside return `None`.
    #[must_use]
    pub fn resolve(&self, path: &str) -> Option<ResolvedControlEntry> {
        if path != CONTROL_ROOT && !path.starts_with("__fortress/") {
            return None;
        }
        if let Some(record) = self.roles.iter().find(|record| record.path == path) {
            return Some(ResolvedControlEntry {
                path: path.into(),
                role: record.role,
                owner: record.owner.clone(),
                source_binding: record.source_binding,
            });
        }
        if let Some(remainder) = path.strip_prefix("__fortress/evidence/generations/") {
            let mut parts = remainder.split('/');
            let digest = parts.next().unwrap_or_default();
            let member = parts.next().unwrap_or_default();
            if parts.next().is_none() && is_sha256_hex(digest) {
                if member == self.manifest_member.name {
                    return Some(ResolvedControlEntry {
                        path: path.into(),
                        role: ControlRole::GenerationManifest,
                        owner: self.manifest_member.owner.clone(),
                        source_binding: ControlSourceBinding::Nonrecursive,
                    });
                }
                if let Some(record) = self
                    .artifact_registry
                    .iter()
                    .find(|record| record.member_name.as_deref() == Some(member))
                {
                    return Some(ResolvedControlEntry {
                        path: path.into(),
                        role: ControlRole::GeneratedAssessmentPayload,
                        owner: record.owner.clone(),
                        source_binding: ControlSourceBinding::Nonrecursive,
                    });
                }
            }
        }
        Some(ResolvedControlEntry {
            path: path.into(),
            role: ControlRole::Unrecognized,
            owner: "project_model".into(),
            source_binding: ControlSourceBinding::Nonrecursive,
        })
    }

    /// Returns the closed set of registered included generation artifact IDs.
    #[must_use]
    pub fn artifact_ids(&self) -> Vec<&str> {
        self.artifact_registry
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    }

    /// Returns every registered logical command output path.
    #[must_use]
    pub fn artifact_logical_paths(&self) -> Vec<&str> {
        self.artifact_registry
            .iter()
            .map(|item| item.logical_path.as_str())
            .collect()
    }

    fn validate(&self) -> Result<(), ControlLayoutError> {
        if self.schema != "urn:fortress:schema:v1:control-layout"
            || self.schema_version != 1
            || self.id != "fortress-control-layout-v1"
            || self.root != CONTROL_ROOT
            || self.config != PROJECT_CONFIGURATION_PATH
        {
            return Err(ControlLayoutError::UnsupportedLayout);
        }
        let mut paths = BTreeSet::new();
        for role in &self.roles {
            if !role.path.starts_with("__fortress/")
                || role.owner.is_empty()
                || !paths.insert(role.path.as_str())
            {
                return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
            }
        }
        if !paths.contains(PROJECT_CONFIGURATION_PATH) {
            return Err(ControlLayoutError::MissingConfiguration);
        }
        if self.manifest_member.name != "manifest.json" || self.manifest_member.owner.is_empty() {
            return Err(ControlLayoutError::MissingManifest);
        }
        let mut logical_paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut members = BTreeSet::new();
        let mut production_counts = [0_u8; 3];
        let mut prior_id: Option<&str> = None;
        for artifact in &self.artifact_registry {
            let common_valid = !artifact.id.is_empty()
                && artifact.logical_path.starts_with("_info/")
                && is_safe_member(artifact.logical_path.trim_start_matches("_info/"))
                && !artifact.owner.is_empty()
                && !artifact.schema_ref.is_empty()
                && !artifact.producer_semantic_version.is_empty()
                && ids.insert(artifact.id.as_str())
                && logical_paths.insert(artifact.logical_path.as_str())
                && prior_id.is_none_or(|prior| prior < artifact.id.as_str());
            let storage_valid = match artifact.storage {
                ArtifactStorage::Included => artifact
                    .member_name
                    .as_deref()
                    .is_some_and(|name| is_safe_member(name) && members.insert(name)),
                ArtifactStorage::ExternalMaterialization => artifact.member_name.is_none(),
            };
            if !common_valid || !storage_valid {
                return Err(ControlLayoutError::InvalidEntry(artifact.id.clone().into()));
            }
            match artifact.production_group {
                ProductionGroup::Semantic => production_counts[0] += 1,
                ProductionGroup::Certification => production_counts[1] += 1,
                ProductionGroup::Certificate => production_counts[2] += 1,
            }
            if artifact.production_group == ProductionGroup::Certificate
                && artifact.id != "quality-certificate"
            {
                return Err(ControlLayoutError::InvalidEntry(artifact.id.clone().into()));
            }
            prior_id = Some(&artifact.id);
        }
        if ids.len() != 15 || members.len() != 7 || production_counts != [11, 3, 1] {
            return Err(ControlLayoutError::IncompleteArtifactRegistry);
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn is_safe_member(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['/', '\\'])
        && value != "."
        && value != ".."
        && value.strip_suffix(".json").is_some()
}

/// Control layout registry validation failure.
#[derive(Debug)]
pub enum ControlLayoutError {
    /// JSON syntax or typed shape failed.
    Json(serde_json::Error),
    /// Schema, version, root, or identifier is unsupported.
    UnsupportedLayout,
    /// An entry is duplicated or unsafe.
    InvalidEntry(Box<str>),
    /// The fixed configuration role is absent.
    MissingConfiguration,
    /// The generation manifest member is absent.
    MissingManifest,
    /// The closed artifact registry has the wrong cardinality.
    IncompleteArtifactRegistry,
}

impl Display for ControlLayoutError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "control layout JSON is invalid: {error}"),
            Self::UnsupportedLayout => formatter.write_str("unsupported control layout"),
            Self::InvalidEntry(path) => write!(formatter, "invalid control layout entry `{path}`"),
            Self::MissingConfiguration => {
                formatter.write_str("control layout configuration role is absent")
            }
            Self::MissingManifest => {
                formatter.write_str("control layout manifest member is absent")
            }
            Self::IncompleteArtifactRegistry => {
                formatter.write_str("control layout artifact registry is incomplete")
            }
        }
    }
}

impl Error for ControlLayoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}
