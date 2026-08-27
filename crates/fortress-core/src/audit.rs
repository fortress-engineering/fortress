//! End-to-end provider-independent Snapshot Governance repository audit.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::architecture::{ArchitectureLoadError, ArchitectureManifest};
use crate::evaluation::{EvaluationError, RuleExecution, SnapshotRuleEngine};
use crate::feature::{FeatureContract, FeatureLoadError};
use crate::finding::CanonicalFinding;
use crate::observation::{ObservationError, ObservationPolicy};
use crate::project::{ProjectLoadError, ProjectManifest};
use crate::rust_test_analyzer::{RustAnalyzerError, analyze_snapshot_rust_tests};
use crate::snapshot::{
    RepositorySnapshot, SnapshotDocuments, SnapshotError, build_repository_snapshot,
};
use crate::standard::{StandardBundle, StandardLoadError};

/// Current stable machine-readable snapshot audit schema family.
pub const AUDIT_RESULT_SCHEMA_VERSION: u16 = 1;

/// Deterministic repository audit result; this is not certification evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditResult {
    schema_version: u16,
    project_id: String,
    standard: AuditStandard,
    snapshot_fingerprint: String,
    repository_content_fingerprint: String,
    outcome: AuditOutcome,
    summary: AuditSummary,
    rules: Vec<RuleExecution>,
    findings: Vec<CanonicalFinding>,
}

impl AuditResult {
    /// Returns whether all actually evaluated mandatory rules had no findings.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome == AuditOutcome::Pass
    }

    /// Returns the exact stabilized snapshot fingerprint.
    #[must_use]
    pub fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    /// Returns deterministic audit summary counts.
    #[must_use]
    pub const fn summary(&self) -> &AuditSummary {
        &self.summary
    }

    /// Returns canonical findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Serializes stable pretty JSON with deterministic collection ordering.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the version-one contract cannot be represented.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Renders concise deterministic terminal output.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut output = format!(
            "Fortress Snapshot Audit\nStandard: {}\nSnapshot: {}\n\nRules evaluated: {}\nPASS: {}\nFAIL: {}\nUnsupported: {}\n\nFindings:\n",
            self.standard.edition,
            self.snapshot_fingerprint,
            self.summary.rules_evaluated,
            self.summary.passed,
            self.summary.failed,
            self.summary.unsupported
        );
        if self.findings.is_empty() {
            output.push_str("None\n");
        } else {
            for finding in &self.findings {
                let location = finding.location().path().unwrap_or("repository");
                output.push_str(&format!(
                    "- [{}] {}: {}\n",
                    finding.rule_id(),
                    location,
                    finding.message()
                ));
            }
        }
        output
    }
}

/// Standard identity reported by an audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AuditStandard {
    edition: String,
    status: String,
}

/// Overall evaluated-rule outcome, excluding explicitly unsupported rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AuditOutcome {
    Pass,
    Fail,
}

/// Stable audit rule counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuditSummary {
    rules_evaluated: usize,
    passed: usize,
    failed: usize,
    unsupported: usize,
}

impl AuditSummary {
    /// Returns actually evaluated rule count.
    #[must_use]
    pub const fn rules_evaluated(&self) -> usize {
        self.rules_evaluated
    }

    /// Returns evaluated pass count.
    #[must_use]
    pub const fn passed(&self) -> usize {
        self.passed
    }

    /// Returns evaluated failure count.
    #[must_use]
    pub const fn failed(&self) -> usize {
        self.failed
    }

    /// Returns applicable unsupported rule count.
    #[must_use]
    pub const fn unsupported(&self) -> usize {
        self.unsupported
    }
}

/// Audits one repository root using only its declared model and stabilized facts.
///
/// # Errors
///
/// Returns [`AuditError`] for invalid/missing declarations, unstable or
/// inconsistent snapshot inputs, analyzer failure, or rule-evaluation failure.
pub fn audit_repository(root: impl AsRef<Path>) -> Result<AuditResult, AuditError> {
    let root = root.as_ref();
    let project_document = read_document(root, ".fortress/project.json")?;
    let project =
        ProjectManifest::from_json_str(project_document.source()?).map_err(AuditError::Project)?;
    let standard_manifest = read_document(root, project.standard().manifest())?;
    let index: StandardManifestIndex = serde_json::from_str(standard_manifest.source()?)
        .map_err(AuditError::StandardManifestIndex)?;
    let standard_root = Path::new(project.standard().manifest())
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let rule_documents: Vec<LoadedDocument> = index
        .rules
        .iter()
        .map(|relative| read_document(root, &canonical_join(standard_root, relative)))
        .collect::<Result<_, _>>()?;
    let rule_sources: Vec<(&str, &str)> = rule_documents
        .iter()
        .zip(&index.rules)
        .map(|(document, relative)| Ok((relative.as_str(), document.source()?)))
        .collect::<Result<_, AuditError>>()?;
    let standard = StandardBundle::from_json_documents(standard_manifest.source()?, &rule_sources)
        .map_err(AuditError::Standard)?;
    if standard.id() != project.standard().id()
        || standard.edition() != project.standard().edition()
        || standard.status() != project.standard().status().as_str()
    {
        return Err(AuditError::StandardClaimMismatch {
            declared: format!(
                "{} {} {}",
                project.standard().id(),
                project.standard().edition(),
                project.standard().status().as_str()
            )
            .into(),
            loaded: format!(
                "{} {} {}",
                standard.id(),
                standard.edition(),
                standard.status()
            )
            .into(),
        });
    }

    let architecture_document = read_document(root, project.model().architecture())?;
    let architecture = ArchitectureManifest::from_json_str(architecture_document.source()?)
        .map_err(AuditError::Architecture)?;
    let feature_documents: Vec<LoadedDocument> = project
        .model()
        .features()
        .iter()
        .map(|path| read_document(root, path))
        .collect::<Result<_, _>>()?;
    let features: Vec<FeatureContract> = feature_documents
        .iter()
        .map(|document| {
            FeatureContract::from_json_str(&document.path, document.source()?).map_err(|source| {
                AuditError::Feature {
                    path: document.path.clone().into(),
                    source,
                }
            })
        })
        .collect::<Result<_, _>>()?;

    let documents = SnapshotDocuments::new(
        &standard_manifest.path,
        &standard_manifest.bytes,
        rule_documents
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
        &project_document.bytes,
        &architecture_document.bytes,
        feature_documents
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
    );
    let policy = ObservationPolicy::new(project.model().observation_exclusions().iter().cloned())
        .map_err(AuditError::ObservationPolicy)?;
    let snapshot = build_repository_snapshot(root, &policy, &project, &documents)
        .map_err(AuditError::Snapshot)?;
    verify_loaded_inputs(
        &snapshot,
        std::iter::once(&project_document)
            .chain(std::iter::once(&standard_manifest))
            .chain(rule_documents.iter())
            .chain(std::iter::once(&architecture_document))
            .chain(feature_documents.iter()),
    )?;
    let rust_tests =
        analyze_snapshot_rust_tests(root, &snapshot).map_err(AuditError::RustAnalyzer)?;
    let evaluation = SnapshotRuleEngine::builtin()
        .evaluate_with_traceability(&standard, &snapshot, &architecture, &features, &rust_tests)
        .map_err(AuditError::Evaluation)?;
    Ok(result_from_evaluation(&project, &snapshot, &evaluation))
}

fn result_from_evaluation(
    project: &ProjectManifest,
    snapshot: &RepositorySnapshot,
    evaluation: &crate::evaluation::SnapshotEvaluation,
) -> AuditResult {
    let summary = AuditSummary {
        rules_evaluated: evaluation.evaluated_count(),
        passed: evaluation.passed_count(),
        failed: evaluation.failed_count(),
        unsupported: evaluation.unsupported_count(),
    };
    AuditResult {
        schema_version: AUDIT_RESULT_SCHEMA_VERSION,
        project_id: project.id().into(),
        standard: AuditStandard {
            edition: snapshot.standard_edition().into(),
            status: snapshot.standard_status().into(),
        },
        snapshot_fingerprint: snapshot.snapshot_fingerprint().into(),
        repository_content_fingerprint: snapshot.repository_content_fingerprint().into(),
        outcome: if summary.failed == 0 {
            AuditOutcome::Pass
        } else {
            AuditOutcome::Fail
        },
        summary,
        rules: evaluation.rules().to_vec(),
        findings: evaluation.findings().to_vec(),
    }
}

#[derive(Deserialize)]
struct StandardManifestIndex {
    rules: Vec<String>,
}

struct LoadedDocument {
    path: String,
    bytes: Vec<u8>,
}

impl LoadedDocument {
    fn source(&self) -> Result<&str, AuditError> {
        std::str::from_utf8(&self.bytes).map_err(|_| AuditError::NonUtf8(self.path.clone().into()))
    }
}

fn read_document(root: &Path, path: &str) -> Result<LoadedDocument, AuditError> {
    let absolute = root.join(path);
    let bytes = fs::read(&absolute).map_err(|source| AuditError::Io {
        path: absolute,
        source,
    })?;
    Ok(LoadedDocument {
        path: path.into(),
        bytes,
    })
}

fn canonical_join(parent: &Path, child: &str) -> String {
    parent.join(child).to_string_lossy().replace('\\', "/")
}

fn verify_loaded_inputs<'a>(
    snapshot: &RepositorySnapshot,
    documents: impl IntoIterator<Item = &'a LoadedDocument>,
) -> Result<(), AuditError> {
    for document in documents {
        let digest = format!("sha256:{:x}", Sha256::digest(&document.bytes));
        let size = u64::try_from(document.bytes.len())
            .map_err(|_| AuditError::InputMismatch(document.path.clone().into()))?;
        let matches = snapshot.files().iter().any(|file| {
            file.path() == document.path && file.size() == size && file.sha256() == digest
        });
        if !matches {
            return Err(AuditError::InputMismatch(document.path.clone().into()));
        }
    }
    Ok(())
}

/// Explains why repository audit construction could not complete.
#[derive(Debug)]
pub enum AuditError {
    /// A required document could not be read.
    Io {
        /// Filesystem path used for the read.
        path: PathBuf,
        /// Underlying read failure.
        source: std::io::Error,
    },
    /// A required JSON document was not UTF-8.
    NonUtf8(Box<str>),
    /// Project declaration was invalid.
    Project(ProjectLoadError),
    /// Standard manifest rule index was invalid JSON.
    StandardManifestIndex(serde_json::Error),
    /// Exact standard bundle was invalid.
    Standard(StandardLoadError),
    /// Loaded standard identity did not match the project claim.
    StandardClaimMismatch {
        /// Project-declared identity, edition, and status.
        declared: Box<str>,
        /// Loaded bundle identity, edition, and status.
        loaded: Box<str>,
    },
    /// Architecture declaration was invalid.
    Architecture(ArchitectureLoadError),
    /// Feature declaration was invalid.
    Feature {
        /// Canonical feature-contract path.
        path: Box<str>,
        /// Typed feature load failure.
        source: FeatureLoadError,
    },
    /// Observation exclusions were invalid.
    ObservationPolicy(ObservationError),
    /// Stabilized snapshot construction failed.
    Snapshot(SnapshotError),
    /// Loaded input bytes did not match the stabilized inventory.
    InputMismatch(Box<str>),
    /// Snapshot-bound Rust analysis failed.
    RustAnalyzer(RustAnalyzerError),
    /// Rule evaluation failed.
    Evaluation(EvaluationError),
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::NonUtf8(path) => write!(formatter, "audit input `{path}` is not UTF-8"),
            Self::Project(error) => write!(formatter, "invalid project state: {error}"),
            Self::StandardManifestIndex(error) => {
                write!(formatter, "invalid standard manifest rule index: {error}")
            }
            Self::Standard(error) => write!(formatter, "invalid standard bundle: {error}"),
            Self::StandardClaimMismatch { declared, loaded } => write!(
                formatter,
                "project standard claim `{declared}` does not match loaded bundle `{loaded}`"
            ),
            Self::Architecture(error) => write!(formatter, "invalid architecture state: {error}"),
            Self::Feature { path, source } => {
                write!(formatter, "invalid feature contract `{path}`: {source}")
            }
            Self::ObservationPolicy(error) => {
                write!(formatter, "invalid observation policy: {error}")
            }
            Self::Snapshot(error) => write!(formatter, "snapshot construction failed: {error}"),
            Self::InputMismatch(path) => write!(
                formatter,
                "loaded input `{path}` does not match the stabilized snapshot"
            ),
            Self::RustAnalyzer(error) => write!(formatter, "Rust test analysis failed: {error}"),
            Self::Evaluation(error) => {
                write!(formatter, "snapshot rule evaluation failed: {error}")
            }
        }
    }
}

impl Error for AuditError {}
