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

use crate::observation::{
    ObservationError, ObservationPolicy, ObservedFile, RepositoryObservation, observe_repository,
};
use crate::project::{ProjectManifest, StandardStatus};

/// Current canonical repository snapshot schema family.
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 1;

/// Fortress engine version participating in snapshot interpretation.
pub const SNAPSHOT_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Raw declared documents whose exact bytes participate in snapshot identity.
#[derive(Clone, Debug)]
pub struct SnapshotDocuments<'a> {
    standard_manifest: &'a [u8],
    standard_documents: Vec<SnapshotDocument<'a>>,
    project_declaration: &'a [u8],
    architecture_declaration: &'a [u8],
    feature_contracts: Vec<SnapshotDocument<'a>>,
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
        project_declaration: &'a [u8],
        architecture_declaration: &'a [u8],
        feature_contracts: F,
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
            project_declaration,
            architecture_declaration,
            feature_contracts: feature_contracts
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
    project: &ProjectManifest,
    documents: &SnapshotDocuments<'_>,
) -> Result<RepositorySnapshot, SnapshotError> {
    let standard_documents =
        canonical_document_digests(&documents.standard_documents, "standard input")?;
    let feature_contracts =
        canonical_document_digests(&documents.feature_contracts, "feature contract")?;
    let observation = observe_repository_stably(root, policy)?;
    let repository_content_fingerprint = canonical_sha256(&observation)?;

    let standard_input_fingerprint = canonical_sha256(&standard_documents)?;
    let standard = SnapshotStandard {
        edition: project.standard().edition().to_owned(),
        status: standard_status_name(project.standard().status()).to_owned(),
        declared_bundle_digest: project.standard().digest().map(str::to_owned),
        manifest_digest: sha256_bytes(documents.standard_manifest),
        input_documents: standard_documents,
        input_fingerprint: standard_input_fingerprint,
    };
    let inputs = SnapshotInputDigests {
        project_declaration_digest: sha256_bytes(documents.project_declaration),
        architecture_declaration_digest: sha256_bytes(documents.architecture_declaration),
        feature_contracts,
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
        project_id: project.id(),
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
        project_id: project.id().to_owned(),
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
            Self::UnstableRepository { .. }
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
    edition: String,
    status: String,
    declared_bundle_digest: Option<String>,
    manifest_digest: String,
    input_documents: Vec<SnapshotDocumentDigest>,
    input_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SnapshotInputDigests {
    project_declaration_digest: String,
    architecture_declaration_digest: String,
    feature_contracts: Vec<SnapshotDocumentDigest>,
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

fn observe_repository_stably_with<F>(
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

fn standard_status_name(status: StandardStatus) -> &'static str {
    match status {
        StandardStatus::Draft => "draft",
        StandardStatus::Candidate => "candidate",
        StandardStatus::Released => "released",
    }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::observation::ObservationPolicy;
    use crate::project::ProjectManifest;

    use super::{
        SnapshotDocuments, SnapshotError, build_repository_snapshot, observe_repository_stably_with,
    };

    static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(0);

    struct TestRepository(PathBuf);

    impl TestRepository {
        fn new(name: &str) -> Self {
            let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "fortress-snapshot-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("test repository must be created");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test parent must be created");
            }
            fs::write(path, contents).expect("test file must be written");
        }
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test repository must be removed");
        }
    }

    fn project() -> ProjectManifest {
        ProjectManifest::from_json_str(
            r#"{
                "$schema": "urn:fortress:schema:v1:project",
                "schema_version": 1,
                "id": "PF-SNAPSHOT-TEST",
                "name": "Snapshot test",
                "standard": {
                    "id": "STD-FORTRESS-ENGINEERING",
                    "edition": "1.0.0-draft.1",
                    "status": "draft",
                    "digest": null,
                    "manifest": "mods/engine/mods/standard_registry/data/standard_manifest.json"
                },
                "archetypes": ["package.library"],
                "capabilities": ["AF-SNAPSHOT-GOVERNANCE-0001"],
                "languages": ["rust"],
                "model": {
                    "architecture": "data/architecture.json",
                    "features": ["data/features.json"],
                    "commands": "mods/cli/data/commands.json",
                    "certifications": "data/certification.json",
                    "active_changes": [],
                    "observation_exclusions": [".git", "target"]
                }
            }"#,
        )
        .expect("test project must validate")
    }

    fn documents() -> SnapshotDocuments<'static> {
        SnapshotDocuments::new(
            "mods/engine/mods/standard_registry/data/standard_manifest.json",
            b"standard",
            [(
                "mods/engine/mods/standard_registry/data/std_id_rule.json",
                &b"rule"[..],
            )],
            b"project",
            b"architecture",
            [("data/features.json", &b"features"[..])],
        )
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-001`
    #[test]
    fn stable_repository_produces_a_snapshot() {
        let repository = TestRepository::new("stable");
        repository.write("source.txt", "stable");
        let snapshot = build_repository_snapshot(
            repository.path(),
            &ObservationPolicy::default(),
            &project(),
            &documents(),
        )
        .expect("stable repository must produce a snapshot");
        assert_eq!(snapshot.files().len(), 1);
        assert!(snapshot.snapshot_fingerprint().starts_with("sha256:"));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-002`
    #[test]
    fn ordering_and_fingerprints_are_deterministic() {
        let repository = TestRepository::new("deterministic");
        repository.write("z.txt", "last");
        repository.write("a.txt", "first");
        let first = build_repository_snapshot(
            repository.path(),
            &ObservationPolicy::default(),
            &project(),
            &documents(),
        )
        .expect("first snapshot must succeed");
        let second = build_repository_snapshot(
            repository.path(),
            &ObservationPolicy::default(),
            &project(),
            &documents(),
        )
        .expect("second snapshot must succeed");
        assert_eq!(first, second);
        assert_eq!(first.files()[0].path(), "a.txt");
        assert_eq!(first.to_json_pretty().ok(), second.to_json_pretty().ok());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-003`
    #[test]
    fn empty_repository_and_explicit_exclusions_are_supported() {
        let empty = TestRepository::new("empty");
        let observation =
            observe_repository_stably_with(empty.path(), &ObservationPolicy::default(), || {})
                .expect("empty repository is a valid boundary");
        assert!(observation.files().is_empty());

        let excluded = TestRepository::new("excluded");
        excluded.write("state/cache.txt", "first");
        let policy = ObservationPolicy::new(["state"]).expect("policy must validate");
        let observation = observe_repository_stably_with(excluded.path(), &policy, || {
            excluded.write("state/cache.txt", "second");
        })
        .expect("excluded mutation must not destabilize governed content");
        assert!(observation.files().is_empty());
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-001`
    #[test]
    fn changed_file_between_passes_is_rejected() {
        let repository = TestRepository::new("changed");
        repository.write("file.txt", "first");
        let result = observe_repository_stably_with(
            repository.path(),
            &ObservationPolicy::default(),
            || repository.write("file.txt", "second"),
        );
        assert!(matches!(
            result,
            Err(SnapshotError::UnstableRepository { .. })
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-002`
    #[test]
    fn added_file_between_passes_is_rejected() {
        let repository = TestRepository::new("added");
        repository.write("first.txt", "first");
        let result = observe_repository_stably_with(
            repository.path(),
            &ObservationPolicy::default(),
            || repository.write("added.txt", "added"),
        );
        assert!(matches!(
            result,
            Err(SnapshotError::UnstableRepository { .. })
        ));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-003`
    #[test]
    fn removed_file_between_passes_is_rejected() {
        let repository = TestRepository::new("removed");
        repository.write("removed.txt", "removed");
        let result = observe_repository_stably_with(
            repository.path(),
            &ObservationPolicy::default(),
            || {
                fs::remove_file(repository.path().join("removed.txt"))
                    .expect("test file must be removed");
            },
        );
        assert!(matches!(
            result,
            Err(SnapshotError::UnstableRepository { .. })
        ));
    }
}
