//! End-to-end provider-independent Snapshot Governance repository audit.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::architecture::ArchitectureManifest;
use crate::contract::evaluate_contract_coherency;
use crate::documentation::{DocumentationEvaluationError, evaluate_repository_documentation};
use crate::evaluation::{
    CompleteEvaluationInputs, EvaluationError, RuleExecution, SnapshotRuleEngine,
};
use crate::finding::CanonicalFinding;
use crate::module_contract::{ContractStandardIndex, resolve_contracts};
use crate::observation::{ObservationError, ObservationPolicy, RepositoryObservation};
use crate::project::{ProjectConfiguration, ProjectConfigurationLoadError};
use crate::rust_test_analyzer::{RustAnalyzerError, analyze_snapshot_rust_tests};
use crate::snapshot::{
    RepositorySnapshot, SnapshotDocuments, SnapshotError, build_repository_snapshot,
    observe_repository_stably,
};
use crate::standard::{StandardBundle, StandardLoadError};
use crate::traceability::requirements_from_resolved;

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

    /// Returns deterministic execution records for every applicable standard rule.
    #[must_use]
    pub fn rules(&self) -> &[RuleExecution] {
        &self.rules
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
                output.push_str("- [");
                output.push_str(finding.rule_id());
                output.push_str("] ");
                output.push_str(location);
                output.push_str(": ");
                output.push_str(finding.message());
                output.push('\n');
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
    let project_document = read_document(root, "data/project.json")?;
    let project = ProjectConfiguration::from_json_str(project_document.source()?)
        .map_err(AuditError::Project)?;
    let policy = ObservationPolicy::new(project.observation_exclusions().iter().cloned())
        .map_err(AuditError::ObservationPolicy)?;
    let initial_observation =
        observe_repository_stably(root, &policy).map_err(AuditError::Snapshot)?;
    let observed_files = read_observed_files(root, &initial_observation)?;
    let standard_manifest_path = find_standard_manifest(&observed_files)?;
    let standard_manifest = read_document(root, &standard_manifest_path)?;
    let index: StandardManifestIndex = serde_json::from_str(standard_manifest.source()?)
        .map_err(AuditError::StandardManifestIndex)?;
    let rule_documents: Vec<LoadedDocument> = index
        .rules
        .iter()
        .map(|relative| read_document(root, relative))
        .collect::<Result<_, _>>()?;
    let rule_sources: Vec<(&str, &str)> = rule_documents
        .iter()
        .zip(&index.rules)
        .map(|(document, relative)| Ok((relative.as_str(), document.source()?)))
        .collect::<Result<_, AuditError>>()?;
    let standard = StandardBundle::from_json_documents(standard_manifest.source()?, &rule_sources)
        .map_err(AuditError::Standard)?;
    let standard_index = ContractStandardIndex::from_bundle(&standard);
    let initial_contract_resolution = resolve_contracts(&observed_files, &standard_index, None);
    let initial_contracts = initial_contract_resolution.resolved().ok_or_else(|| {
        AuditError::ContractState(
            initial_contract_resolution
                .violations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
                .into(),
        )
    })?;
    let contract_documents: Vec<LoadedDocument> = observed_files
        .iter()
        .filter(|(path, _)| path.as_str() == "contract.json" || path.ends_with("/contract.json"))
        .map(|(path, bytes)| LoadedDocument {
            path: path.clone(),
            bytes: bytes.clone(),
        })
        .collect();

    let documents = SnapshotDocuments::new(
        &standard_manifest.path,
        &standard_manifest.bytes,
        rule_documents
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
        &project_document.bytes,
        contract_documents
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
    );
    let snapshot =
        build_repository_snapshot(root, &policy, initial_contracts, &standard, &documents)
            .map_err(AuditError::Snapshot)?;
    verify_loaded_inputs(
        &snapshot,
        std::iter::once(&project_document)
            .chain(std::iter::once(&standard_manifest))
            .chain(rule_documents.iter())
            .chain(contract_documents.iter()),
    )?;
    let rust_tests =
        analyze_snapshot_rust_tests(root, &snapshot).map_err(AuditError::RustAnalyzer)?;
    let observed_test_ids: BTreeSet<String> =
        rust_tests.iter().map(|test| test.id().to_owned()).collect();
    let contract_resolution =
        resolve_contracts(&observed_files, &standard_index, Some(&observed_test_ids));
    let documentation = evaluate_repository_documentation(root, &snapshot, standard.edition())
        .map_err(AuditError::Documentation)?;
    let contract_coherency =
        evaluate_contract_coherency(contract_resolution, &documentation, standard.edition())
            .map_err(EvaluationError::Finding)
            .map_err(AuditError::Evaluation)?;
    let paths: Vec<String> = snapshot
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let architecture = ArchitectureManifest::from_resolved_contracts(initial_contracts, &paths);
    let requirements = requirements_from_resolved(initial_contracts);
    let evaluation = SnapshotRuleEngine::builtin()
        .evaluate_complete(
            &standard,
            &snapshot,
            &architecture,
            CompleteEvaluationInputs::new(
                &requirements,
                &rust_tests,
                &documentation,
                &contract_coherency,
            ),
        )
        .map_err(AuditError::Evaluation)?;
    Ok(result_from_evaluation(&snapshot, &evaluation))
}

fn result_from_evaluation(
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
        project_id: snapshot.project_id().into(),
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

fn read_observed_files(
    root: &Path,
    observation: &RepositoryObservation,
) -> Result<BTreeMap<String, Vec<u8>>, AuditError> {
    observation
        .files()
        .iter()
        .map(|file| {
            let document = read_document(root, file.path())?;
            Ok((document.path, document.bytes))
        })
        .collect()
}

fn find_standard_manifest(files: &BTreeMap<String, Vec<u8>>) -> Result<String, AuditError> {
    let candidates: Vec<String> = files
        .keys()
        .filter(|path| {
            path.as_str() == "standard_manifest.json" || path.ends_with("/standard_manifest.json")
        })
        .cloned()
        .collect();
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(AuditError::StandardManifestDiscovery(
            "no standard_manifest.json exists in the stabilized repository".into(),
        )),
        _ => Err(AuditError::StandardManifestDiscovery(
            format!(
                "multiple standard_manifest.json candidates exist: {}",
                candidates.join(", ")
            )
            .into(),
        )),
    }
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
    /// Operational project configuration was invalid.
    Project(ProjectConfigurationLoadError),
    /// The applicable standard manifest could not be discovered unambiguously.
    StandardManifestDiscovery(Box<str>),
    /// Standard manifest rule index was invalid JSON.
    StandardManifestIndex(serde_json::Error),
    /// Exact standard bundle was invalid.
    Standard(StandardLoadError),
    /// Contracts could not form the minimum resolved state needed for snapshot identity.
    ContractState(Box<str>),
    /// Observation exclusions were invalid.
    ObservationPolicy(ObservationError),
    /// Stabilized snapshot construction failed.
    Snapshot(SnapshotError),
    /// Loaded input bytes did not match the stabilized inventory.
    InputMismatch(Box<str>),
    /// Snapshot-bound Rust analysis failed.
    RustAnalyzer(RustAnalyzerError),
    /// Snapshot-bound documentation and contract evaluation failed.
    Documentation(DocumentationEvaluationError),
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
            Self::StandardManifestDiscovery(error) => {
                write!(formatter, "standard manifest discovery failed: {error}")
            }
            Self::StandardManifestIndex(error) => {
                write!(formatter, "invalid standard manifest rule index: {error}")
            }
            Self::Standard(error) => write!(formatter, "invalid standard bundle: {error}"),
            Self::ContractState(error) => write!(formatter, "invalid contract state: {error}"),
            Self::ObservationPolicy(error) => {
                write!(formatter, "invalid observation policy: {error}")
            }
            Self::Snapshot(error) => write!(formatter, "snapshot construction failed: {error}"),
            Self::InputMismatch(path) => write!(
                formatter,
                "loaded input `{path}` does not match the stabilized snapshot"
            ),
            Self::RustAnalyzer(error) => write!(formatter, "Rust test analysis failed: {error}"),
            Self::Documentation(error) => {
                write!(formatter, "documentation evaluation failed: {error}")
            }
            Self::Evaluation(error) => {
                write!(formatter, "snapshot rule evaluation failed: {error}")
            }
        }
    }
}

impl Error for AuditError {}
