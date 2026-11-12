//! Pure validation for immutable assessment generations and their selection index.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current assessment generation manifest schema identity.
pub const GENERATION_MANIFEST_SCHEMA: &str =
    "urn:fortress:derived:v8:assessment-generation-manifest";
/// Retained seventh edition with hypothetical proposal roles.
pub const GENERATION_MANIFEST_V7_SCHEMA: &str =
    "urn:fortress:derived:v7:assessment-generation-manifest";
/// Retained sixth edition with migration record roles.
pub const GENERATION_MANIFEST_V6_SCHEMA: &str =
    "urn:fortress:derived:v6:assessment-generation-manifest";
/// Retained fifth edition; original qualification evidence is not rewritten.
pub const GENERATION_MANIFEST_V5_SCHEMA: &str =
    "urn:fortress:derived:v5:assessment-generation-manifest";
/// Retained fourth edition with selected provider context.
pub const GENERATION_MANIFEST_V4_SCHEMA: &str =
    "urn:fortress:derived:v4:assessment-generation-manifest";
/// Retained third edition, without selected provider context.
pub const GENERATION_MANIFEST_V3_SCHEMA: &str =
    "urn:fortress:derived:v3:assessment-generation-manifest";
/// Retained second edition; its bytes and digest meaning remain unchanged.
pub const GENERATION_MANIFEST_V2_SCHEMA: &str =
    "urn:fortress:derived:v2:assessment-generation-manifest";
/// Retained assessment generation manifest schema identity.
pub const LEGACY_GENERATION_MANIFEST_SCHEMA: &str =
    "urn:fortress:derived:v1:assessment-generation-manifest";
/// Current assessment selection index schema identity.
pub const SELECTION_INDEX_SCHEMA: &str = "urn:fortress:derived:v1:assessment-selection-index";

/// Immutable description of one complete assessment generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentGenerationManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    generation_kind: String,
    project: String,
    profile: String,
    selection_key: String,
    source: GenerationSource,
    control_layout: GenerationControlLayout,
    artifacts: Vec<ArtifactDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_provenance: Option<Vec<OriginProvenance>>,
    #[serde(
        default,
        deserialize_with = "present_selection_context",
        skip_serializing_if = "Option::is_none"
    )]
    selection_context: Option<ApplicationSelectionContext>,
}

fn present_selection_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ApplicationSelectionContext>, D::Error> {
    ApplicationSelectionContext::deserialize(deserializer).map(Some)
}

/// Exact application profile/scope/context selection, independent of source freshness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSelectionContext {
    /// Complete associated profile composition digest.
    pub profile_digest: String,
    /// Current contract supports an exact repository endpoint.
    pub scope: String,
    /// Exact `ProgramContext` identity, not merely its family.
    pub context_ref: String,
    /// Exact provider selection, absent only in historical generation v3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_input_digest: Option<String>,
}

impl ApplicationSelectionContext {
    /// Recomputes the exact current-index selection key.
    ///
    /// # Errors
    /// Rejects invalid identity or unsupported scope.
    pub fn selection_key(&self, project: &str) -> Result<String, ControlManifestError> {
        validate_digest(&self.profile_digest)?;
        validate_digest(&self.context_ref)?;
        if self.scope != "repository" || project.is_empty() {
            return Err(ControlManifestError::UnsupportedRecord);
        }
        if let Some(input) = &self.evidence_input_digest {
            validate_digest(input)?;
            let bytes = serde_json_canonicalizer::to_vec(&(
                "application-selection-v2",
                project,
                &self.profile_digest,
                &self.scope,
                &self.context_ref,
                input,
            ))
            .map_err(|e| ControlManifestError::Json(serde::ser::Error::custom(e)))?;
            return Ok(format!("sha256:{:x}", Sha256::digest(bytes)));
        }
        let bytes = serde_json_canonicalizer::to_vec(&(
            "application-selection-v1",
            project,
            &self.profile_digest,
            &self.scope,
            &self.context_ref,
        ))
        .map_err(|e| ControlManifestError::Json(serde::ser::Error::custom(e)))?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationSource {
    fingerprint: String,
    file_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationControlLayout {
    id: String,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginProvenance {
    id: String,
    path: String,
    content_digest: String,
}

/// One logical artifact carried by or referenced from a generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    id: String,
    producer_id: String,
    schema_ref: String,
    producer_semantic_version: String,
    content_digest: String,
    byte_count: u64,
    disposition: ArtifactDisposition,
    storage: ArtifactStorage,
}

/// Whether the selected profile requires an artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactDisposition {
    /// The selected profile cannot be verified without this artifact.
    Required,
    /// The artifact may be absent without invalidating the generation.
    Optional,
}

/// Physical inclusion or external logical materialization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ArtifactStorage {
    /// Payload is an exact safe sibling of the manifest.
    Included {
        /// Safe generation-relative member basename.
        member_name: String,
    },
    /// Payload is reproducible in the external subject cache.
    ExternalMaterialization {
        /// Registry identifier used to reconstruct the external bytes.
        logical_artifact_id: String,
    },
}

/// Versioned mapping from context selection keys to immutable generations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSelectionIndex {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    selections: Vec<AssessmentSelection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct AssessmentSelection {
    selection_key: String,
    generation_digest: String,
}

impl AssessmentGenerationManifest {
    /// Returns the generation's project identity for registered cache resolution.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }
    /// Returns the exact source subject recorded by this generation.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source.fingerprint
    }
    /// Parses and validates one strict public manifest.
    ///
    /// # Errors
    /// Returns an error for malformed data, unsafe locators, or noncanonical order.
    pub fn from_json_str(source: &str) -> Result<Self, ControlManifestError> {
        let value: Self =
            crate::wire::parse_public_json(source).map_err(ControlManifestError::Wire)?;
        value.validate()?;
        Ok(value)
    }

    /// Returns SHA-256 over RFC 8785 canonical manifest bytes.
    ///
    /// # Errors
    /// Returns an error when the validated record cannot be serialized canonically.
    pub fn generation_digest(&self) -> Result<String, ControlManifestError> {
        let source = serde_json::to_string(self).map_err(ControlManifestError::Json)?;
        let bytes =
            crate::wire::canonicalize_public_json(&source).map_err(ControlManifestError::Wire)?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    /// Returns artifacts in their canonical logical order.
    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactDescriptor] {
        &self.artifacts
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), ControlManifestError> {
        let supported_layout_pair = matches!(
            (
                self.schema.as_str(),
                self.schema_version,
                self.control_layout.id.as_str(),
            ),
            (
                LEGACY_GENERATION_MANIFEST_SCHEMA,
                1,
                "fortress-control-layout-v1"
            ) | (
                GENERATION_MANIFEST_V2_SCHEMA,
                2,
                "fortress-control-layout-v2"
            ) | (
                GENERATION_MANIFEST_V3_SCHEMA,
                3,
                "fortress-control-layout-v3"
            ) | (
                GENERATION_MANIFEST_V4_SCHEMA,
                4,
                "fortress-control-layout-v4"
            ) | (
                GENERATION_MANIFEST_V5_SCHEMA,
                5,
                "fortress-control-layout-v5"
            ) | (
                GENERATION_MANIFEST_V6_SCHEMA,
                6,
                "fortress-control-layout-v6"
            ) | (
                GENERATION_MANIFEST_V7_SCHEMA,
                7,
                "fortress-control-layout-v7"
            ) | (GENERATION_MANIFEST_SCHEMA, 8, "fortress-control-layout-v8")
        );
        if !supported_layout_pair
            || !matches!(
                self.generation_kind.as_str(),
                "LOCAL_QUALITY" | "HISTORICAL_MIGRATION" | "APPLICATION"
            )
            || self.project.is_empty()
            || self.profile.is_empty()
            || self.source.file_count == 0
            || self.source.file_count > crate::wire::MAX_EXACT_PUBLIC_INTEGER
        {
            return Err(ControlManifestError::UnsupportedRecord);
        }
        if self.generation_kind == "APPLICATION" {
            let context = self
                .selection_context
                .as_ref()
                .ok_or(ControlManifestError::UnsupportedRecord)?;
            if !matches!(self.schema_version, 3..=8)
                || (self.schema_version == 3 && context.evidence_input_digest.is_some())
                || (self.schema_version >= 4 && context.evidence_input_digest.is_none())
                || self.profile != context.profile_digest
                || self.selection_key != context.selection_key(&self.project)?
            {
                return Err(ControlManifestError::UnsupportedRecord);
            }
        } else if self.selection_context.is_some() {
            return Err(ControlManifestError::UnsupportedRecord);
        }
        for digest in [
            &self.selection_key,
            &self.source.fingerprint,
            &self.control_layout.digest,
        ] {
            validate_digest(digest)?;
        }
        let mut prior = None;
        let mut members = BTreeSet::new();
        for artifact in &self.artifacts {
            if artifact.id.is_empty()
                || artifact.producer_id.is_empty()
                || artifact.schema_ref.is_empty()
                || artifact.producer_semantic_version.is_empty()
                || artifact.byte_count == 0
                || artifact.byte_count > crate::wire::MAX_EXACT_PUBLIC_INTEGER
                || prior.is_some_and(|value| value >= artifact.id.as_str())
            {
                return Err(ControlManifestError::InvalidArtifact(
                    artifact.id.clone().into(),
                ));
            }
            validate_digest(&artifact.content_digest)?;
            prior = Some(artifact.id.as_str());
            match &artifact.storage {
                ArtifactStorage::Included { member_name } => {
                    if !safe_member(member_name)
                        || member_name == "manifest.json"
                        || !members.insert(member_name.as_str())
                    {
                        return Err(ControlManifestError::InvalidArtifact(
                            artifact.id.clone().into(),
                        ));
                    }
                }
                ArtifactStorage::ExternalMaterialization {
                    logical_artifact_id,
                } if logical_artifact_id != &artifact.id => {
                    return Err(ControlManifestError::InvalidArtifact(
                        artifact.id.clone().into(),
                    ));
                }
                ArtifactStorage::ExternalMaterialization { .. } => {}
            }
        }
        if self.artifacts.is_empty() {
            return Err(ControlManifestError::UnsupportedRecord);
        }
        if let Some(origins) = &self.origin_provenance {
            if origins.is_empty() || origins.windows(2).any(|pair| pair[0].id >= pair[1].id) {
                return Err(ControlManifestError::UnsupportedRecord);
            }
            for origin in origins {
                validate_digest(&origin.content_digest)?;
                if !origin.path.starts_with("_info/")
                    || !safe_member(origin.path.trim_start_matches("_info/"))
                {
                    return Err(ControlManifestError::InvalidArtifact(
                        origin.id.clone().into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ArtifactDescriptor {
    /// Returns the exact immutable payload digest.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
    /// Returns the exact declared payload size.
    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }
    /// Returns the logical artifact identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the checked storage descriptor.
    #[must_use]
    pub fn storage(&self) -> &ArtifactStorage {
        &self.storage
    }
}

impl AssessmentSelectionIndex {
    /// Returns all exact context selections without choosing a latest result.
    pub fn selections(&self) -> impl Iterator<Item = (&str, &str)> {
        self.selections
            .iter()
            .map(|item| (item.selection_key.as_str(), item.generation_digest.as_str()))
    }
    /// Parses a strict, sorted and duplicate-free selection index.
    ///
    /// # Errors
    /// Returns an error for malformed fields, digests, or ordering.
    pub fn from_json_str(source: &str) -> Result<Self, ControlManifestError> {
        let value: Self =
            crate::wire::parse_public_json(source).map_err(ControlManifestError::Wire)?;
        if value.schema != SELECTION_INDEX_SCHEMA
            || value.schema_version != 1
            || value
                .selections
                .windows(2)
                .any(|pair| pair[0].selection_key >= pair[1].selection_key)
        {
            return Err(ControlManifestError::UnsupportedRecord);
        }
        for selection in &value.selections {
            validate_digest(&selection.selection_key)?;
            validate_digest(&selection.generation_digest)?;
        }
        Ok(value)
    }

    /// Resolves one exact selection without timestamp or latest-green fallback.
    #[must_use]
    pub fn generation(&self, selection_key: &str) -> Option<&str> {
        self.selections
            .iter()
            .find(|item| item.selection_key == selection_key)
            .map(|item| item.generation_digest.as_str())
    }
}

fn validate_digest(value: &str) -> Result<(), ControlManifestError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ControlManifestError::InvalidDigest(value.into()));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ControlManifestError::InvalidDigest(value.into()));
    }
    Ok(())
}
fn safe_member(value: &str) -> bool {
    value.strip_suffix(".json").is_some()
        && !value.contains(['/', '\\'])
        && value != "."
        && value != ".."
}

/// Generation manifest or selection-index validation failure.
#[derive(Debug)]
pub enum ControlManifestError {
    /// Strict public JSON parsing or canonicalization failed.
    Wire(crate::wire::WireError),
    /// Serialization of a validated in-memory record failed.
    Json(serde_json::Error),
    /// Schema, version, required fields, or canonical order is unsupported.
    UnsupportedRecord,
    /// A digest was not a lowercase SHA-256 identifier.
    InvalidDigest(Box<str>),
    /// An artifact descriptor was unsafe, duplicate, or malformed.
    InvalidArtifact(Box<str>),
}
impl Display for ControlManifestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "control record wire error: {e}"),
            Self::Json(e) => write!(f, "control record serialization error: {e}"),
            Self::UnsupportedRecord => f.write_str("unsupported or noncanonical control record"),
            Self::InvalidDigest(v) => write!(f, "invalid control digest `{v}`"),
            Self::InvalidArtifact(v) => write!(f, "invalid control artifact `{v}`"),
        }
    }
}
impl Error for ControlManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}
