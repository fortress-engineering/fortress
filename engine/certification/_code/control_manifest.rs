//! Pure validation for immutable assessment generations and their selection index.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Assessment generation manifest schema identity.
pub const GENERATION_MANIFEST_SCHEMA: &str =
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

    fn validate(&self) -> Result<(), ControlManifestError> {
        if self.schema != GENERATION_MANIFEST_SCHEMA
            || self.schema_version != 1
            || !matches!(
                self.generation_kind.as_str(),
                "LOCAL_QUALITY" | "HISTORICAL_MIGRATION"
            )
            || self.project.is_empty()
            || self.profile.is_empty()
            || self.source.file_count == 0
            || self.control_layout.id != "fortress-control-layout-v1"
        {
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
    /// Parses a strict, sorted and duplicate-free selection index.
    ///
    /// # Errors
    /// Returns an error for malformed fields, digests, or ordering.
    pub fn from_json_str(source: &str) -> Result<Self, ControlManifestError> {
        let value: Self =
            crate::wire::parse_public_json(source).map_err(ControlManifestError::Wire)?;
        if value.schema != SELECTION_INDEX_SCHEMA
            || value.schema_version != 1
            || value.selections.windows(2).any(|pair| pair[0] >= pair[1])
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
