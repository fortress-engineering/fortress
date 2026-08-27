//! Stabilized, content-addressed repository snapshots.
//!
//! A snapshot binds declared project inputs to two identical repository
//! observations. It records observed facts and reproducible digests without
//! creating certification evidence or using wall-clock metadata.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::module_contract::ResolvedContractSet;
use crate::observation::{
    ObservationError, ObservationPolicy, ObservedFile, RepositoryObservation, observe_repository,
};
use crate::standard::StandardBundle;

/// Current canonical repository snapshot schema family.
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 2;

/// Fortress engine version participating in snapshot interpretation.
pub const SNAPSHOT_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Raw declared documents whose exact bytes participate in snapshot identity.
#[derive(Clone, Debug)]
pub struct SnapshotDocuments<'a> {
    standard_manifest: &'a [u8],
    standard_documents: Vec<SnapshotDocument<'a>>,
    project_configuration: &'a [u8],
    module_contracts: Vec<SnapshotDocument<'a>>,
}

impl<'a> SnapshotDocuments<'a> {
    /// Creates the complete declared input set for one repository snapshot.
    ///
    /// Feature contract paths are repository-relative identities and their
    /// bytes are hashed exactly as supplied. Validation and canonical ordering
    /// occur while the snapshot is built.
    pub fn new<S, I, P, F, Q>(
        standard_manifest_path: S,
        standard_manifest: &'a [u8],
        standard_rule_documents: I,
        project_configuration: &'a [u8],
        module_contracts: F,
    ) -> Self
    where
        S: Into<String>,
        I: IntoIterator<Item = (P, &'a [u8])>,
        P: Into<String>,
        F: IntoIterator<Item = (Q, &'a [u8])>,
        Q: Into<String>,
    {
        let mut standard_documents = vec![SnapshotDocument {
            path: standard_manifest_path.into(),
            bytes: standard_manifest,
        }];
        standard_documents.extend(standard_rule_documents.into_iter().map(|(path, bytes)| {
            SnapshotDocument {
                path: path.into(),
                bytes,
            }
        }));
        Self {
            standard_manifest,
            standard_documents,
            project_configuration,
            module_contracts: module_contracts
                .into_iter()
                .map(|(path, bytes)| SnapshotDocument {
                    path: path.into(),
                    bytes,
                })
                .collect(),
        }
    }
}

/// A deterministic stabilized repository snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositorySnapshot {
    schema_version: u16,
    project_id: String,
    standard: SnapshotStandard,
    inputs: SnapshotInputDigests,
    observation_policy: SnapshotObservationPolicy,
    files: Vec<ObservedFile>,
    repository_content_fingerprint: String,
    engine: SnapshotEngine,
    provenance: SnapshotProvenance,
    snapshot_fingerprint: String,
}

impl RepositorySnapshot {
    /// Returns the snapshot schema family.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the stable declared project identity.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Returns the exact declared standard edition.
    #[must_use]
    pub fn standard_edition(&self) -> &str {
        &self.standard.edition
    }

    /// Returns the declared standard status.
    #[must_use]
    pub fn standard_status(&self) -> &str {
        &self.standard.status
    }

    /// Returns the applicable released bundle digest when one was declared.
    #[must_use]
    pub fn declared_standard_digest(&self) -> Option<&str> {
        self.standard.declared_bundle_digest.as_deref()
    }

    /// Returns the digest of the exact standard manifest bytes supplied.
    #[must_use]
    pub fn standard_manifest_digest(&self) -> &str {
        &self.standard.manifest_digest
    }

    /// Returns the canonical digest of all supplied standard input documents.
    #[must_use]
    pub fn standard_input_fingerprint(&self) -> &str {
        &self.standard.input_fingerprint
    }

    /// Returns observed ordinary files in canonical repository-path order.
    #[must_use]
    pub fn files(&self) -> &[ObservedFile] {
        &self.files
    }

    /// Returns the explicit canonical exclusion prefixes.
    #[must_use]
    pub fn excluded_prefixes(&self) -> &[String] {
        &self.observation_policy.excluded_prefixes
    }

    /// Returns the content identity of the stabilized observed inventory.
    #[must_use]
    pub fn repository_content_fingerprint(&self) -> &str {
        &self.repository_content_fingerprint
    }

    /// Returns the content identity of declarations, policy, engine, and files.
    #[must_use]
    pub fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    /// Serializes the snapshot as deterministic pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns the serialization error if the snapshot cannot be represented
    /// by the version-one JSON contract.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Observes a repository twice and requires identical canonical file facts.
///
/// # Errors
///
/// Returns [`SnapshotError::Observation`] when either pass cannot observe the
/// repository and [`SnapshotError::UnstableRepository`] when path sets, sizes,
/// or content digests differ between passes.
pub fn observe_repository_stably(
    root: impl AsRef<Path>,
    policy: &ObservationPolicy,
) -> Result<RepositoryObservation, SnapshotError> {
    observe_repository_stably_with(root.as_ref(), policy, || {})
}

/// Builds a stabilized, content-addressed snapshot from validated declarations.
///
/// # Errors
///
/// Returns [`SnapshotError`] when document paths are invalid or duplicated,
/// repository observation fails or changes between passes, or canonical JSON
/// serialization fails.
pub fn build_repository_snapshot(
    root: impl AsRef<Path>,
    policy: &ObservationPolicy,
    contracts: &ResolvedContractSet,
    standard_bundle: &StandardBundle,
    documents: &SnapshotDocuments<'_>,
) -> Result<RepositorySnapshot, SnapshotError> {
    let standard_documents =
        canonical_document_digests(&documents.standard_documents, "standard input")?;
    let module_contracts =
        canonical_document_digests(&documents.module_contracts, "Module contract")?;
    let observation = observe_repository_stably(root, policy)?;
    let repository_content_fingerprint = canonical_sha256(&observation)?;

    let standard_input_fingerprint = canonical_sha256(&standard_documents)?;
    let standard = SnapshotStandard {
        id: standard_bundle.id().to_owned(),
        edition: standard_bundle.edition().to_owned(),
        status: standard_bundle.status().to_owned(),
        declared_bundle_digest: None,
        manifest_digest: sha256_bytes(documents.standard_manifest),
        input_documents: standard_documents,
        input_fingerprint: standard_input_fingerprint,
    };
    let contract_set_fingerprint = canonical_sha256(&module_contracts)?;
    let inputs = SnapshotInputDigests {
        project_configuration_digest: sha256_bytes(documents.project_configuration),
        module_contracts,
        contract_set_fingerprint,
    };
    let observation_policy = SnapshotObservationPolicy {
        excluded_prefixes: policy.excluded_prefixes().to_vec(),
    };
    let engine = SnapshotEngine {
        name: "fortress",
        version: SNAPSHOT_ENGINE_VERSION,
    };
    let provenance = SnapshotProvenance {
        observation_passes: 2,
        hash_algorithm: "sha256",
        symlink_policy: "reject",
        root_kind: "caller-supplied-local-directory",
    };
    let files = observation.files().to_vec();

    let material = SnapshotIdentityMaterial {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        project_id: contracts
            .root()
            .map(|module| module.contract().id())
            .ok_or(SnapshotError::MissingRootContract)?,
        standard: &standard,
        inputs: &inputs,
        observation_policy: &observation_policy,
        files: &files,
        repository_content_fingerprint: &repository_content_fingerprint,
        engine: &engine,
        provenance: &provenance,
    };
    let snapshot_fingerprint = canonical_sha256(&material)?;

    Ok(RepositorySnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        project_id: contracts
            .root()
            .map(|module| module.contract().id().to_owned())
            .ok_or(SnapshotError::MissingRootContract)?,
        standard,
        inputs,
        observation_policy,
        files,
        repository_content_fingerprint,
        engine,
        provenance,
        snapshot_fingerprint,
    })
}

/// Explains why a canonical repository snapshot could not be created.
#[derive(Debug)]
pub enum SnapshotError {
    /// A supposedly resolved contract set had no root Module contract.
    MissingRootContract,
    /// A repository observation pass failed.
    Observation(ObservationError),
    /// The two canonical observations did not describe identical content.
    UnstableRepository {
        /// Content fingerprint produced by the first pass.
        first_fingerprint: String,
        /// Content fingerprint produced by the second pass.
        second_fingerprint: String,
    },
    /// A declared input path was not canonical and repository-relative.
    InvalidDocumentPath {
        /// Input collection containing the invalid path.
        collection: &'static str,
        /// Invalid path value.
        path: PathBuf,
    },
    /// More than one declared input used the same path identity.
    DuplicateDocumentPath {
        /// Input collection containing the duplicate path.
        collection: &'static str,
        /// Duplicate path value.
        path: PathBuf,
    },
    /// Canonical snapshot material could not be serialized.
    Serialization(serde_json::Error),
}

impl Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRootContract => {
                formatter.write_str("resolved contract set has no root Module contract")
            }
            Self::Observation(error) => write!(formatter, "repository observation failed: {error}"),
            Self::UnstableRepository {
                first_fingerprint,
                second_fingerprint,
            } => write!(
                formatter,
                "repository changed between observation passes ({first_fingerprint} != {second_fingerprint})"
            ),
            Self::InvalidDocumentPath { collection, path } => write!(
                formatter,
                "{collection} path is not canonical and repository-relative: {}",
                path.display()
            ),
            Self::DuplicateDocumentPath { collection, path } => write!(
                formatter,
                "{collection} path is duplicated: {}",
                path.display()
            ),
            Self::Serialization(error) => {
                write!(
                    formatter,
                    "canonical snapshot serialization failed: {error}"
                )
            }
        }
    }
}

impl Error for SnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Observation(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::MissingRootContract
            | Self::UnstableRepository { .. }
            | Self::InvalidDocumentPath { .. }
            | Self::DuplicateDocumentPath { .. } => None,
        }
    }
}

impl From<ObservationError> for SnapshotError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

#[derive(Clone, Debug)]
struct SnapshotDocument<'a> {
    path: String,
    bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotStandard {
    id: String,
    edition: String,
    status: String,
    declared_bundle_digest: Option<String>,
    manifest_digest: String,
    input_documents: Vec<SnapshotDocumentDigest>,
    input_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotInputDigests {
    project_configuration_digest: String,
    module_contracts: Vec<SnapshotDocumentDigest>,
    contract_set_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotDocumentDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotObservationPolicy {
    excluded_prefixes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotEngine {
    name: &'static str,
    version: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotProvenance {
    observation_passes: u8,
    hash_algorithm: &'static str,
    symlink_policy: &'static str,
    root_kind: &'static str,
}

#[derive(Serialize)]
struct SnapshotIdentityMaterial<'a> {
    schema_version: u16,
    project_id: &'a str,
    standard: &'a SnapshotStandard,
    inputs: &'a SnapshotInputDigests,
    observation_policy: &'a SnapshotObservationPolicy,
    files: &'a [ObservedFile],
    repository_content_fingerprint: &'a str,
    engine: &'a SnapshotEngine,
    provenance: &'a SnapshotProvenance,
}

/// Performs stabilized two-pass observation with a caller-controlled action
/// between passes, allowing deterministic verification of mutation handling.
///
/// # Errors
///
/// Returns [`SnapshotError`] when either pass fails or their content facts differ.
pub fn observe_repository_stably_with<F>(
    root: &Path,
    policy: &ObservationPolicy,
    after_first: F,
) -> Result<RepositoryObservation, SnapshotError>
where
    F: FnOnce(),
{
    let first = observe_repository(root, policy)?;
    after_first();
    let second = observe_repository(root, policy)?;
    if first == second {
        return Ok(second);
    }

    Err(SnapshotError::UnstableRepository {
        first_fingerprint: canonical_sha256(&first)?,
        second_fingerprint: canonical_sha256(&second)?,
    })
}

fn canonical_document_digests(
    documents: &[SnapshotDocument<'_>],
    collection: &'static str,
) -> Result<Vec<SnapshotDocumentDigest>, SnapshotError> {
    let mut seen = HashSet::with_capacity(documents.len());
    let mut digests = Vec::with_capacity(documents.len());
    for document in documents {
        if !is_canonical_relative_path(&document.path) {
            return Err(SnapshotError::InvalidDocumentPath {
                collection,
                path: document.path.clone().into(),
            });
        }
        if !seen.insert(document.path.as_str()) {
            return Err(SnapshotError::DuplicateDocumentPath {
                collection,
                path: document.path.clone().into(),
            });
        }
        digests.push(SnapshotDocumentDigest {
            path: document.path.clone(),
            sha256: sha256_bytes(document.bytes),
        });
    }
    digests.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(digests)
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, SnapshotError> {
    let bytes = serde_json::to_vec(value).map_err(SnapshotError::Serialization)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_canonical_relative_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_path = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !value.is_empty()
        && !drive_path
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
