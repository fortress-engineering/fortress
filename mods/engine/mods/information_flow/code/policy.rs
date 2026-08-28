//! Canonical project information-flow policy loading and finite facet algebra.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical project policy schema identity.
pub const INFORMATION_FLOW_POLICY_SCHEMA: &str = "urn:fortress:schema:v1:information-flow-policy";
/// Canonical project policy schema version.
pub const INFORMATION_FLOW_POLICY_SCHEMA_VERSION: u16 = 1;

/// Direction that gives an ordered facet its conservative security meaning.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FacetDirection {
    /// Higher levels represent stronger integrity/trust.
    HigherIsStronger,
    /// Higher levels represent greater confidentiality restriction.
    HigherIsMoreRestricted,
}

/// One validated project-defined information classification facet.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationFacet {
    id: String,
    direction: FacetDirection,
    levels: Vec<String>,
}

impl InformationFacet {
    /// Returns the stable project facet identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the ordered project level vocabulary.
    #[must_use]
    pub fn levels(&self) -> &[String] {
        &self.levels
    }

    /// Returns the project-defined lattice direction.
    #[must_use]
    pub const fn direction(&self) -> FacetDirection {
        self.direction
    }

    /// Returns the zero-based order of one level.
    #[must_use]
    pub fn index_of(&self, level: &str) -> Option<usize> {
        self.levels.iter().position(|candidate| candidate == level)
    }

    /// Returns the canonical level at an order index.
    #[must_use]
    pub fn level_at(&self, index: usize) -> Option<&str> {
        self.levels.get(index).map(String::as_str)
    }

    /// Returns whether `to` is an explicit security-sensitive improvement over `from`.
    #[must_use]
    pub fn is_trusted_transition(&self, from: usize, to: usize) -> bool {
        match self.direction {
            FacetDirection::HigherIsStronger => to > from,
            FacetDirection::HigherIsMoreRestricted => to < from,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    facets: Vec<InformationFacet>,
}

/// One snapshot-bound project policy source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationFlowPolicySource {
    path: String,
    source: String,
}

impl InformationFlowPolicySource {
    /// Creates one candidate project-root policy source.
    #[must_use]
    pub fn new(path: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
        }
    }
}

/// Validated project-defined facet vocabulary and ordering authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InformationFlowPolicy {
    facets: Vec<InformationFacet>,
    #[serde(skip)]
    by_id: BTreeMap<String, usize>,
    digest: String,
    source_path: Option<String>,
}

impl InformationFlowPolicy {
    /// Returns ordered facets.
    pub fn facets(&self) -> impl Iterator<Item = &InformationFacet> {
        self.facets.iter()
    }

    /// Returns one facet by stable identity.
    #[must_use]
    pub fn facet(&self, id: &str) -> Option<&InformationFacet> {
        self.by_id.get(id).and_then(|index| self.facets.get(*index))
    }

    /// Returns the content identity of the optional canonical policy.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns whether the project has authored a policy.
    #[must_use]
    pub fn is_authored(&self) -> bool {
        self.source_path.is_some()
    }
}

/// Loads the optional single project-root information-flow policy.
///
/// # Errors
///
/// Returns [`InformationFlowPolicyError`] for duplicate/non-root authority,
/// invalid JSON, noncanonical bytes, or malformed finite facet algebra.
pub fn load_information_flow_policy(
    sources: Vec<InformationFlowPolicySource>,
) -> Result<InformationFlowPolicy, InformationFlowPolicyError> {
    match sources.as_slice() {
        [] => Ok(InformationFlowPolicy {
            facets: Vec::new(),
            by_id: BTreeMap::new(),
            digest: format!(
                "sha256:{:x}",
                Sha256::digest(b"absent-information-flow-policy")
            ),
            source_path: None,
        }),
        [source] => {
            if source.path != "data/information_flow_policy.json" {
                return Err(InformationFlowPolicyError::NonRootPolicy(
                    source.path.clone(),
                ));
            }
            let document: PolicyDocument =
                serde_json::from_str(&source.source).map_err(|error| {
                    InformationFlowPolicyError::InvalidJson {
                        path: source.path.clone(),
                        detail: error.to_string(),
                    }
                })?;
            if document.schema != INFORMATION_FLOW_POLICY_SCHEMA
                || document.schema_version != INFORMATION_FLOW_POLICY_SCHEMA_VERSION
            {
                return Err(InformationFlowPolicyError::UnsupportedSchema(
                    source.path.clone(),
                ));
            }
            if canonical_document(&document)? != source.source {
                return Err(InformationFlowPolicyError::NonCanonical(
                    source.path.clone(),
                ));
            }
            validate_facets(&document.facets, &source.path)?;
            let by_id = document
                .facets
                .iter()
                .enumerate()
                .map(|(index, facet)| (facet.id.clone(), index))
                .collect();
            Ok(InformationFlowPolicy {
                facets: document.facets,
                by_id,
                digest: format!("sha256:{:x}", Sha256::digest(source.source.as_bytes())),
                source_path: Some(source.path.clone()),
            })
        }
        _ => Err(InformationFlowPolicyError::DuplicatePolicy(
            sources.into_iter().map(|source| source.path).collect(),
        )),
    }
}

/// Formats one policy into canonical two-space JSON with one trailing LF.
///
/// # Errors
///
/// Returns a typed error when parsing or serialization fails.
pub fn canonicalize_information_flow_policy_json(
    path: &str,
    source: &str,
) -> Result<String, InformationFlowPolicyError> {
    let document: PolicyDocument =
        serde_json::from_str(source).map_err(|error| InformationFlowPolicyError::InvalidJson {
            path: path.into(),
            detail: error.to_string(),
        })?;
    canonical_document(&document)
}

fn validate_facets(
    facets: &[InformationFacet],
    path: &str,
) -> Result<(), InformationFlowPolicyError> {
    if !facets.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return Err(InformationFlowPolicyError::NonCanonicalOrder(path.into()));
    }
    for facet in facets {
        if !stable_flow_id(&facet.id) {
            return Err(InformationFlowPolicyError::InvalidFacet {
                path: path.into(),
                facet: facet.id.clone(),
                detail: "facet IDs must use FLOW-* uppercase stable identity syntax".into(),
            });
        }
        if facet.levels.len() < 2 {
            return Err(InformationFlowPolicyError::InvalidFacet {
                path: path.into(),
                facet: facet.id.clone(),
                detail: "facets require at least two ordered levels".into(),
            });
        }
        let unique = facet.levels.iter().collect::<BTreeSet<_>>();
        if unique.len() != facet.levels.len()
            || facet.levels.iter().any(|level| !stable_level(level))
        {
            return Err(InformationFlowPolicyError::InvalidFacet {
                path: path.into(),
                facet: facet.id.clone(),
                detail: "levels must be unique nonempty uppercase stable tokens".into(),
            });
        }
    }
    Ok(())
}

fn stable_flow_id(value: &str) -> bool {
    value.starts_with("FLOW-")
        && value.len() > "FLOW-".len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn stable_level(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn canonical_document(document: &PolicyDocument) -> Result<String, InformationFlowPolicyError> {
    let mut output = serde_json::to_string_pretty(document)
        .map_err(|error| InformationFlowPolicyError::Serialization(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Explains why project information-flow policy authority is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InformationFlowPolicyError {
    /// JSON could not be parsed.
    InvalidJson {
        /// Repository-relative path.
        path: String,
        /// Parser detail.
        detail: String,
    },
    /// Schema identity/version is unsupported.
    UnsupportedSchema(String),
    /// Valid JSON is not byte-canonical.
    NonCanonical(String),
    /// Facets are not sorted and unique.
    NonCanonicalOrder(String),
    /// The policy was not authored at the root Data location.
    NonRootPolicy(String),
    /// More than one project policy exists.
    DuplicatePolicy(Vec<String>),
    /// One facet or level algebra is malformed.
    InvalidFacet {
        /// Source path.
        path: String,
        /// Facet identity.
        facet: String,
        /// Precise rejection detail.
        detail: String,
    },
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for InformationFlowPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => {
                write!(
                    formatter,
                    "invalid information-flow policy `{path}`: {detail}"
                )
            }
            Self::UnsupportedSchema(path) => {
                write!(
                    formatter,
                    "unsupported information-flow policy schema in `{path}`"
                )
            }
            Self::NonCanonical(path) => {
                write!(
                    formatter,
                    "information-flow policy `{path}` is not canonical JSON"
                )
            }
            Self::NonCanonicalOrder(path) => {
                write!(
                    formatter,
                    "information-flow policy facets are not canonical in `{path}`"
                )
            }
            Self::NonRootPolicy(path) => write!(
                formatter,
                "information-flow policy `{path}` is not root-owned `data/information_flow_policy.json`"
            ),
            Self::DuplicatePolicy(paths) => write!(
                formatter,
                "multiple information-flow policies exist: {}",
                paths.join(", ")
            ),
            Self::InvalidFacet {
                path,
                facet,
                detail,
            } => write!(formatter, "invalid facet `{facet}` in `{path}`: {detail}"),
            Self::Serialization(detail) => {
                write!(
                    formatter,
                    "information-flow policy serialization failed: {detail}"
                )
            }
        }
    }
}

impl Error for InformationFlowPolicyError {}
