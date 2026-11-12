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
pub const CONTROL_LAYOUT_SOURCE: &str = include_str!("../_data/control_layout_v8.json");
/// Retained seventh edition; hypothetical evidence identities remain unchanged.
pub const CONTROL_LAYOUT_V7_SOURCE: &str = include_str!("../_data/control_layout_v7.json");
/// Retained sixth edition; migration evidence identities are never rewritten.
pub const CONTROL_LAYOUT_V6_SOURCE: &str = include_str!("../_data/control_layout_v6.json");
/// Retained fifth edition; historical artifact identities remain unchanged.
pub const CONTROL_LAYOUT_V5_SOURCE: &str = include_str!("../_data/control_layout_v5.json");
/// Retained fourth edition, including provider evidence roles.
pub const CONTROL_LAYOUT_V4_SOURCE: &str = include_str!("../_data/control_layout_v4.json");
/// Retained third edition; historical artifact identities remain unchanged.
pub const CONTROL_LAYOUT_V3_SOURCE: &str = include_str!("../_data/control_layout_v3.json");
/// Retained second layout edition; historical digest meaning is unchanged.
pub const CONTROL_LAYOUT_V2_SOURCE: &str = include_str!("../_data/control_layout_v2.json");
/// Retained declarative layout bytes for historical records.
pub const LEGACY_CONTROL_LAYOUT_SOURCE: &str = include_str!("../_data/control_layout_v1.json");
/// Exact project-local effect-summary authority location.
pub const EFFECT_SUMMARY_AUTHORITY_PATH: &str =
    "__fortress/governance/effect_summaries/catalog.json";
/// Authored selectors for actual externally verified Requirements.
pub const VERIFICATION_BINDINGS_PATH: &str = "__fortress/governance/verification_bindings.json";

/// Whether a control entry participates in the current source subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlSourceBinding {
    /// Authored active input whose exact path and bytes remain bound.
    Required,
    /// Generated material validated separately and excluded from recursive source input.
    Nonrecursive,
}

/// Closed versioned control role vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlRole {
    /// Retained reviewed onboarding intent; never active authority or actual evidence.
    OnboardingProposal,
    /// Retained exact hypothetical proposal; never active authority or actual evidence.
    HypotheticalProposal,
    /// Explicitly exported reviewed migration plan; never active authority.
    ReviewedMigrationPlan,
    /// Immutable completed migration receipt; never present-state authority.
    MigrationReceipt,
    /// Operational repository configuration.
    ProjectConfiguration,
    /// Finding lifecycle and exception authority.
    FindingGovernance,
    /// Root information-flow authority.
    GlobalInformationFlowPolicy,
    /// Exact-context operation-summary selection and override authority.
    EffectSummaryAuthority,
    /// Authored Requirement selectors, without host acceptance authority.
    VerificationBindings,
    /// Retained exact external provider metadata.
    ProviderEnvelope,
    /// Original external provider bytes.
    ProviderPayload,
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
    Application,
    Qualification,
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
    /// Registered nonrecursive migration output roots, without excluding other control input.
    #[must_use]
    pub fn migration_record_roots(&self) -> Vec<&str> {
        [
            ControlRole::ReviewedMigrationPlan,
            ControlRole::MigrationReceipt,
            ControlRole::HypotheticalProposal,
            ControlRole::OnboardingProposal,
        ]
        .into_iter()
        .filter_map(|role| self.role_path(role)?.rsplit_once('/').map(|pair| pair.0))
        .collect()
    }
    /// Resolves an immutable reviewed plan through its registered family.
    #[must_use]
    pub fn migration_plan_path(&self, digest: &str) -> Option<String> {
        self.migration_record_path(digest, ControlRole::ReviewedMigrationPlan)
    }
    /// Resolves an immutable completed receipt through its registered family.
    #[must_use]
    pub fn migration_receipt_path(&self, digest: &str) -> Option<String> {
        self.migration_record_path(digest, ControlRole::MigrationReceipt)
    }
    /// Resolves an explicitly retained hypothetical proposal through its nonrecursive role.
    #[must_use]
    pub fn hypothetical_proposal_path(&self, digest: &str) -> Option<String> {
        self.migration_record_path(digest, ControlRole::HypotheticalProposal)
    }
    /// Resolves a reviewed onboarding proposal through its nonrecursive role.
    #[must_use]
    pub fn onboarding_proposal_path(&self, digest: &str) -> Option<String> {
        self.migration_record_path(digest, ControlRole::OnboardingProposal)
    }
    fn migration_record_path(&self, digest: &str, role: ControlRole) -> Option<String> {
        let hex = digest.strip_prefix("sha256:")?;
        if !is_sha256_hex(hex) {
            return None;
        }
        let path = self.role_path(role)?.replace("{sha256}", hex);
        self.resolve(&path)
            .filter(|entry| entry.role() == role)
            .map(|_| path)
    }
    /// Returns the registered logical projection path for an artifact identity.
    #[must_use]
    pub fn artifact_logical_path(&self, id: &str) -> Option<&str> {
        self.artifact_registry
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.logical_path.as_str())
    }
    /// Resolves a singleton registered role without duplicating its location.
    #[must_use]
    pub fn role_path(&self, role: ControlRole) -> Option<&str> {
        self.roles
            .iter()
            .find(|record| record.role == role)
            .map(|record| record.path.as_str())
    }

    /// Resolves an immutable generation member through the installed registry.
    #[must_use]
    pub fn generation_path(&self, digest: &str, artifact: Option<&str>) -> Option<String> {
        let hex = digest.strip_prefix("sha256:")?;
        if !is_sha256_hex(hex) {
            return None;
        }
        let member = match artifact {
            None => self.manifest_member.name.as_str(),
            Some(id) => self
                .artifact_registry
                .iter()
                .find(|record| record.id == id)?
                .member_name
                .as_deref()?,
        };
        let path = format!(
            "{}/generations/{hex}/{member}",
            self.role_path(ControlRole::AssessmentSelectionIndex)?
                .rsplit_once('/')?
                .0
        );
        self.resolve(&path)
            .filter(|entry| {
                matches!(
                    entry.role(),
                    ControlRole::GenerationManifest | ControlRole::GeneratedAssessmentPayload
                )
            })
            .map(|_| path)
    }

    /// Resolves an exact immutable provider import through its registered role.
    #[must_use]
    pub fn provider_path(&self, digest: &str, role: ControlRole) -> Option<String> {
        let hex = digest.strip_prefix("sha256:")?;
        if !is_sha256_hex(hex) {
            return None;
        }
        let member = match role {
            ControlRole::ProviderEnvelope => "envelope.json",
            ControlRole::ProviderPayload => "payload.bin",
            _ => return None,
        };
        let path = format!("__fortress/evidence/imports/{hex}/{member}");
        self.resolve(&path)
            .filter(|entry| entry.role() == role)
            .map(|_| path)
    }

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
            Sha256::digest(self.authority_source().as_bytes())
        )
    }

    /// Exact registered layout bytes used for portable authority verification.
    #[must_use]
    pub fn authority_source(&self) -> &'static str {
        match self.schema_version {
            1 => LEGACY_CONTROL_LAYOUT_SOURCE,
            2 => CONTROL_LAYOUT_V2_SOURCE,
            3 => CONTROL_LAYOUT_V3_SOURCE,
            4 => CONTROL_LAYOUT_V4_SOURCE,
            5 => CONTROL_LAYOUT_V5_SOURCE,
            6 => CONTROL_LAYOUT_V6_SOURCE,
            7 => CONTROL_LAYOUT_V7_SOURCE,
            _ => CONTROL_LAYOUT_SOURCE,
        }
    }

    /// Returns whether a directory is needed by a registered role or generation.
    ///
    /// Role ancestors are exact component prefixes. Admission of a parent does
    /// not admit arbitrary files or descendants beneath that directory.
    #[must_use]
    pub fn allows_directory(&self, path: &str) -> bool {
        path == self.root
            || self.roles.iter().any(|record| {
                record
                    .path
                    .strip_prefix(path)
                    .is_some_and(|remainder| remainder.starts_with('/'))
            })
            || path == "__fortress/evidence/generations"
            || path
                .strip_prefix("__fortress/evidence/generations/")
                .is_some_and(is_sha256_hex)
            || (self.schema_version >= 4
                && (path == "__fortress/evidence/imports"
                    || path
                        .strip_prefix("__fortress/evidence/imports/")
                        .is_some_and(is_sha256_hex)))
    }

    /// Resolves a path under the control root. Paths outside return `None`.
    #[must_use]
    pub fn resolve(&self, path: &str) -> Option<ResolvedControlEntry> {
        if path != CONTROL_ROOT && !path.starts_with("__fortress/") {
            return None;
        }
        if let Some(record) = self
            .roles
            .iter()
            .find(|record| record.path == path && !record.path.contains("{sha256}"))
        {
            return Some(ResolvedControlEntry {
                path: path.into(),
                role: record.role,
                owner: record.owner.clone(),
                source_binding: record.source_binding,
            });
        }
        if self.schema_version >= 6 {
            for record in &self.roles {
                if let Some((prefix, suffix)) = record.path.split_once("{sha256}")
                    && let Some(hex) = path
                        .strip_prefix(prefix)
                        .and_then(|s| s.strip_suffix(suffix))
                    && is_sha256_hex(hex)
                {
                    return Some(ResolvedControlEntry {
                        path: path.into(),
                        role: record.role,
                        owner: record.owner.clone(),
                        source_binding: record.source_binding,
                    });
                }
            }
        }
        if self.schema_version >= 4
            && let Some(remainder) = path.strip_prefix("__fortress/evidence/imports/")
        {
            let mut parts = remainder.split('/');
            let digest = parts.next().unwrap_or_default();
            let member = parts.next().unwrap_or_default();
            if parts.next().is_none() && is_sha256_hex(digest) {
                let role = match member {
                    "envelope.json" => Some(ControlRole::ProviderEnvelope),
                    "payload.bin" => Some(ControlRole::ProviderPayload),
                    _ => None,
                };
                if let Some(role) = role {
                    return Some(ResolvedControlEntry {
                        path: path.into(),
                        role,
                        owner: "certification".into(),
                        source_binding: ControlSourceBinding::Nonrecursive,
                    });
                }
            }
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

    /// Resolves one exact logical output to its associated registered artifact ID.
    #[must_use]
    pub fn artifact_id_for_path(&self, path: &str) -> Option<&str> {
        self.artifact_registry
            .iter()
            .find(|record| record.logical_path == path)
            .map(|record| record.id.as_str())
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), ControlLayoutError> {
        let supported_version = matches!(
            (self.schema.as_str(), self.schema_version, self.id.as_str()),
            (
                "urn:fortress:schema:v1:control-layout",
                1,
                "fortress-control-layout-v1"
            ) | (
                "urn:fortress:schema:v2:control-layout",
                2,
                "fortress-control-layout-v2"
            ) | (
                "urn:fortress:schema:v3:control-layout",
                3,
                "fortress-control-layout-v3"
            ) | (
                "urn:fortress:schema:v4:control-layout",
                4,
                "fortress-control-layout-v4"
            ) | (
                "urn:fortress:schema:v5:control-layout",
                5,
                "fortress-control-layout-v5"
            ) | (
                "urn:fortress:schema:v6:control-layout",
                6,
                "fortress-control-layout-v6"
            ) | (
                "urn:fortress:schema:v7:control-layout",
                7,
                "fortress-control-layout-v7"
            ) | (
                "urn:fortress:schema:v8:control-layout",
                8,
                "fortress-control-layout-v8"
            )
        );
        if !supported_version
            || self.root != CONTROL_ROOT
            || self.config != PROJECT_CONFIGURATION_PATH
        {
            return Err(ControlLayoutError::UnsupportedLayout);
        }
        let mut paths = BTreeSet::new();
        for role in &self.roles {
            if role.role == ControlRole::OnboardingProposal {
                if self.schema_version < 8
                    || role.path != "__fortress/proposals/onboarding/{sha256}.json"
                    || role.owner != "snapshot_governance"
                    || role.source_binding != ControlSourceBinding::Nonrecursive
                    || !paths.insert(role.path.as_str())
                {
                    return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
                }
                continue;
            }
            if role.role == ControlRole::HypotheticalProposal {
                if self.schema_version < 7
                    || role.path != "__fortress/proposals/candidates/{sha256}.json"
                    || role.owner != "snapshot_governance"
                    || role.source_binding != ControlSourceBinding::Nonrecursive
                    || !paths.insert(role.path.as_str())
                {
                    return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
                }
                continue;
            }
            let migration_path = match role.role {
                ControlRole::ReviewedMigrationPlan => {
                    Some("__fortress/proposals/migrations/{sha256}.json")
                }
                ControlRole::MigrationReceipt => {
                    Some("__fortress/records/migrations/{sha256}.json")
                }
                _ => None,
            };
            if let Some(path) = migration_path {
                if self.schema_version < 6
                    || role.path != path
                    || role.owner != "migration_governance"
                    || role.source_binding != ControlSourceBinding::Nonrecursive
                {
                    return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
                }
            } else if role.path.contains('{') || role.path.contains('}') {
                return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
            }
            if !role.path.starts_with("__fortress/")
                || role.owner.is_empty()
                || !paths.insert(role.path.as_str())
                || (role.role == ControlRole::EffectSummaryAuthority
                    && (self.schema_version < 2
                        || role.path != EFFECT_SUMMARY_AUTHORITY_PATH
                        || role.owner != "state_effect_analysis"
                        || role.source_binding != ControlSourceBinding::Required))
                || (role.role == ControlRole::VerificationBindings
                    && (self.schema_version < 4
                        || role.path != VERIFICATION_BINDINGS_PATH
                        || role.owner != "certification"
                        || role.source_binding != ControlSourceBinding::Required))
            {
                return Err(ControlLayoutError::InvalidEntry(role.path.clone().into()));
            }
        }
        if !paths.contains(PROJECT_CONFIGURATION_PATH) {
            return Err(ControlLayoutError::MissingConfiguration);
        }
        if self.schema_version >= 8
            && self
                .roles
                .iter()
                .filter(|r| r.role == ControlRole::OnboardingProposal)
                .count()
                != 1
        {
            return Err(ControlLayoutError::UnsupportedLayout);
        }
        if self.schema_version >= 7
            && self
                .roles
                .iter()
                .filter(|r| r.role == ControlRole::HypotheticalProposal)
                .count()
                != 1
        {
            return Err(ControlLayoutError::UnsupportedLayout);
        }
        if self.schema_version >= 6
            && [
                ControlRole::ReviewedMigrationPlan,
                ControlRole::MigrationReceipt,
            ]
            .iter()
            .any(|role| {
                self.roles
                    .iter()
                    .filter(|record| record.role == *role)
                    .count()
                    != 1
            })
        {
            return Err(ControlLayoutError::UnsupportedLayout);
        }
        if self.schema_version >= 4
            && !self.roles.iter().any(|r| {
                r.role == ControlRole::VerificationBindings
                    && r.path == VERIFICATION_BINDINGS_PATH
                    && r.owner == "certification"
                    && r.source_binding == ControlSourceBinding::Required
            })
        {
            return Err(ControlLayoutError::InvalidEntry(
                VERIFICATION_BINDINGS_PATH.into(),
            ));
        }
        if self.schema_version >= 2
            && !self.roles.iter().any(|role| {
                role.path == EFFECT_SUMMARY_AUTHORITY_PATH
                    && role.role == ControlRole::EffectSummaryAuthority
                    && role.owner == "state_effect_analysis"
                    && role.source_binding == ControlSourceBinding::Required
            })
        {
            return Err(ControlLayoutError::InvalidEntry(
                EFFECT_SUMMARY_AUTHORITY_PATH.into(),
            ));
        }
        if self.manifest_member.name != "manifest.json" || self.manifest_member.owner.is_empty() {
            return Err(ControlLayoutError::MissingManifest);
        }
        let mut logical_paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut members = BTreeSet::new();
        let mut production_counts = [0_u8; 5];
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
                ProductionGroup::Application => production_counts[3] += 1,
                ProductionGroup::Qualification => production_counts[4] += 1,
            }
            if artifact.production_group == ProductionGroup::Certificate
                && artifact.id != "quality-certificate"
            {
                return Err(ControlLayoutError::InvalidEntry(artifact.id.clone().into()));
            }
            prior_id = Some(&artifact.id);
        }
        let (expected_ids, expected_members, expected_counts) = if self.schema_version >= 5 {
            (18, 10, [11, 3, 1, 2, 1])
        } else if self.schema_version >= 3 {
            (17, 9, [11, 3, 1, 2, 0])
        } else {
            (15, 7, [11, 3, 1, 0, 0])
        };
        if ids.len() != expected_ids
            || members.len() != expected_members
            || production_counts != expected_counts
        {
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
