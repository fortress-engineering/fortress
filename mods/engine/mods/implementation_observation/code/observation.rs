//! Language-neutral, snapshot-bound implementation observation facts.
//!
//! This module records what supported analyzers can establish from exact source
//! bytes. It deliberately contains no contract dependency authorization and no
//! architectural judgment; those belong to the CCG and Architecture Evaluation.

#[path = "rust.rs"]
mod rust;

pub use rust::observe_rust_implementation;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Stable language identity of the implemented analyzer.
pub const RUST_LANGUAGE_ID: &str = "rust";

/// Semantic version of Rust implementation observation behavior.
pub const RUST_ANALYZER_VERSION: &str = "1.0.0";

/// One exact source file whose bytes are bound to a stabilized snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotBoundFile {
    path: String,
    expected_size: u64,
    expected_sha256: String,
    bytes: Vec<u8>,
}

impl SnapshotBoundFile {
    /// Creates a snapshot-bound file with an explicit expected content identity.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        expected_size: u64,
        expected_sha256: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            path: path.into(),
            expected_size,
            expected_sha256: expected_sha256.into(),
            bytes: bytes.into(),
        }
    }

    /// Creates a self-consistent file input for deterministic analyzer fixtures.
    #[must_use]
    pub fn from_bytes(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let expected_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let expected_sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
        Self::new(path, expected_size, expected_sha256, bytes)
    }

    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the snapshot-bound bytes after identity verification.
    pub(crate) fn verified_bytes(&self) -> Result<&[u8], ImplementationObservationError> {
        let actual_size = u64::try_from(self.bytes.len()).map_err(|_| {
            ImplementationObservationError::SnapshotIdentityMismatch(self.path.clone().into())
        })?;
        let actual_sha256 = format!("sha256:{:x}", Sha256::digest(&self.bytes));
        if actual_size != self.expected_size || actual_sha256 != self.expected_sha256 {
            return Err(ImplementationObservationError::SnapshotIdentityMismatch(
                self.path.clone().into(),
            ));
        }
        Ok(&self.bytes)
    }
}

/// One physical Fortress Module territory used only for source ownership.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModuleTerritory {
    id: String,
    path: String,
}

impl ModuleTerritory {
    /// Creates one Module identity/path pair inferred from canonical containment.
    #[must_use]
    pub fn new(id: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
        }
    }

    /// Returns the stable Module identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the canonical Module root path; empty means repository root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Complete immutable analyzer input bound to one snapshot identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationObservationInput {
    snapshot_fingerprint: String,
    files: Vec<SnapshotBoundFile>,
    modules: Vec<ModuleTerritory>,
}

impl ImplementationObservationInput {
    /// Creates deterministically ordered snapshot-bound analyzer input.
    #[must_use]
    pub fn new(
        snapshot_fingerprint: impl Into<String>,
        mut files: Vec<SnapshotBoundFile>,
        mut modules: Vec<ModuleTerritory>,
    ) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        modules.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            snapshot_fingerprint: snapshot_fingerprint.into(),
            files,
            modules,
        }
    }

    pub(crate) fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    pub(crate) fn files(&self) -> &[SnapshotBoundFile] {
        &self.files
    }

    pub(crate) fn modules(&self) -> &[ModuleTerritory] {
        &self.modules
    }
}

/// Language-neutral implementation relation kind supported in v1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationRelationKind {
    /// A source-level dependency reference.
    SourceDependency,
}

/// Architectural classification of an observed target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetClassification {
    /// A source target owned by a governed Fortress Module.
    GovernedModule,
    /// A dependency outside the governed Fortress Module ecosystem.
    ExternalDependency,
    /// A supported reference whose target could not be established confidently.
    Unresolved,
}

/// Confidence/result state for one analyzed reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// The supported reference resolved deterministically.
    Resolved,
    /// The supported reference did not resolve confidently.
    Unresolved,
}

/// Whether a source relationship is syntactically conditional.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Conditionality {
    /// No supported conditional attribute guards the reference.
    Unconditional,
    /// A supported `cfg` attribute guards the reference.
    Conditional,
}

/// Stable one-based source position.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceLocation {
    line: u32,
    column: u32,
}

impl SourceLocation {
    /// Creates a one-based source position.
    #[must_use]
    pub const fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }

    /// Returns the one-based source line.
    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    /// Returns the one-based source column.
    #[must_use]
    pub const fn column(self) -> u32 {
        self.column
    }
}

/// Exact source evidence supporting one observed relationship.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ObservationProvenance {
    source_path: String,
    source_module: String,
    reference: String,
    location: SourceLocation,
    resolved_target: Option<String>,
}

impl ObservationProvenance {
    /// Creates exact deterministic source evidence.
    #[must_use]
    pub fn new(
        source_path: impl Into<String>,
        source_module: impl Into<String>,
        reference: impl Into<String>,
        location: SourceLocation,
        resolved_target: Option<String>,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            source_module: source_module.into(),
            reference: reference.into(),
            location,
            resolved_target,
        }
    }

    /// Returns the exact repository-relative source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns the physical owner of the source artifact.
    #[must_use]
    pub fn source_module(&self) -> &str {
        &self.source_module
    }

    /// Returns the canonical Rust reference spelling.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the stable source position.
    #[must_use]
    pub const fn location(&self) -> SourceLocation {
        self.location
    }

    /// Returns the resolved target identity or external name when known.
    #[must_use]
    pub fn resolved_target(&self) -> Option<&str> {
        self.resolved_target.as_deref()
    }
}

/// One low-level language-neutral source observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImplementationObservation {
    source_module: String,
    source_artifact: String,
    target_classification: TargetClassification,
    target_module: Option<String>,
    external_target: Option<String>,
    relation_kind: ImplementationRelationKind,
    language: String,
    conditionality: Conditionality,
    provenance: ObservationProvenance,
    resolution_status: ResolutionStatus,
}

impl ImplementationObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source_module: impl Into<String>,
        source_artifact: impl Into<String>,
        target_classification: TargetClassification,
        target_module: Option<String>,
        external_target: Option<String>,
        conditionality: Conditionality,
        provenance: ObservationProvenance,
        resolution_status: ResolutionStatus,
    ) -> Self {
        Self {
            source_module: source_module.into(),
            source_artifact: source_artifact.into(),
            target_classification,
            target_module,
            external_target,
            relation_kind: ImplementationRelationKind::SourceDependency,
            language: RUST_LANGUAGE_ID.into(),
            conditionality,
            provenance,
            resolution_status,
        }
    }

    /// Creates a resolved governed-Module source dependency fact.
    #[must_use]
    pub fn governed(
        source_module: impl Into<String>,
        source_artifact: impl Into<String>,
        target_module: impl Into<String>,
        conditionality: Conditionality,
        provenance: ObservationProvenance,
    ) -> Self {
        Self::new(
            source_module,
            source_artifact,
            TargetClassification::GovernedModule,
            Some(target_module.into()),
            None,
            conditionality,
            provenance,
            ResolutionStatus::Resolved,
        )
    }

    /// Creates a resolved external dependency fact.
    #[must_use]
    pub fn external(
        source_module: impl Into<String>,
        source_artifact: impl Into<String>,
        external_target: impl Into<String>,
        conditionality: Conditionality,
        provenance: ObservationProvenance,
    ) -> Self {
        Self::new(
            source_module,
            source_artifact,
            TargetClassification::ExternalDependency,
            None,
            Some(external_target.into()),
            conditionality,
            provenance,
            ResolutionStatus::Resolved,
        )
    }

    /// Creates a supported but unresolved source dependency fact.
    #[must_use]
    pub fn unresolved(
        source_module: impl Into<String>,
        source_artifact: impl Into<String>,
        conditionality: Conditionality,
        provenance: ObservationProvenance,
    ) -> Self {
        Self::new(
            source_module,
            source_artifact,
            TargetClassification::Unresolved,
            None,
            None,
            conditionality,
            provenance,
            ResolutionStatus::Unresolved,
        )
    }

    /// Returns the physical source Module.
    #[must_use]
    pub fn source_module(&self) -> &str {
        &self.source_module
    }

    /// Returns the exact source artifact path.
    #[must_use]
    pub fn source_artifact(&self) -> &str {
        &self.source_artifact
    }

    /// Returns the target classification.
    #[must_use]
    pub const fn target_classification(&self) -> TargetClassification {
        self.target_classification
    }

    /// Returns the governed target Module when resolved.
    #[must_use]
    pub fn target_module(&self) -> Option<&str> {
        self.target_module.as_deref()
    }

    /// Returns the external crate identity when applicable.
    #[must_use]
    pub fn external_target(&self) -> Option<&str> {
        self.external_target.as_deref()
    }

    /// Returns source evidence.
    #[must_use]
    pub const fn provenance(&self) -> &ObservationProvenance {
        &self.provenance
    }

    /// Returns the target resolution state.
    #[must_use]
    pub const fn resolution_status(&self) -> ResolutionStatus {
        self.resolution_status
    }
}

impl Ord for ImplementationObservation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.source_module
            .cmp(&other.source_module)
            .then_with(|| self.target_classification.cmp(&other.target_classification))
            .then_with(|| self.target_module.cmp(&other.target_module))
            .then_with(|| self.external_target.cmp(&other.external_target))
            .then_with(|| self.source_artifact.cmp(&other.source_artifact))
            .then_with(|| self.provenance.cmp(&other.provenance))
            .then_with(|| self.conditionality.cmp(&other.conditionality))
            .then_with(|| self.resolution_status.cmp(&other.resolution_status))
    }
}

impl PartialOrd for ImplementationObservation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One normalized direct Module dependency with all supporting source evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ObservedModuleDependency {
    source_module: String,
    target_module: String,
    evidence: Vec<ObservationProvenance>,
}

impl ObservedModuleDependency {
    /// Returns the source Module identity.
    #[must_use]
    pub fn source_module(&self) -> &str {
        &self.source_module
    }

    /// Returns the direct target Module identity.
    #[must_use]
    pub fn target_module(&self) -> &str {
        &self.target_module
    }

    /// Returns every deterministic supporting source reference.
    #[must_use]
    pub fn evidence(&self) -> &[ObservationProvenance] {
        &self.evidence
    }
}

/// Analyzer coverage or invalidity that cannot be represented as a resolved edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ObservationIssue {
    kind: ObservationIssueKind,
    source_path: String,
    detail: String,
}

impl ObservationIssue {
    /// Creates an explicit unsupported or invalid analyzer issue.
    #[must_use]
    pub fn new(
        kind: ObservationIssueKind,
        source_path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            source_path: source_path.into(),
            detail: detail.into(),
        }
    }

    /// Returns the issue semantic class.
    #[must_use]
    pub const fn kind(&self) -> ObservationIssueKind {
        self.kind
    }

    /// Returns the relevant source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns deterministic issue detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Analyzer issue vocabulary kept distinct from reconciliation state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationIssueKind {
    /// The analyzer does not implement the necessary language semantics.
    Unsupported,
    /// Governed source or Cargo structure is invalid for supported analysis.
    Invalid,
}

/// Deterministic observed implementation derived from one exact snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedImplementation {
    snapshot_fingerprint: String,
    analyzer_id: String,
    analyzer_version: String,
    observations: Vec<ImplementationObservation>,
    module_dependencies: Vec<ObservedModuleDependency>,
    issues: Vec<ObservationIssue>,
}

impl ObservedImplementation {
    pub(crate) fn compile(
        snapshot_fingerprint: impl Into<String>,
        observations: Vec<ImplementationObservation>,
        issues: Vec<ObservationIssue>,
    ) -> Self {
        Self::from_facts(
            snapshot_fingerprint,
            "fortress-rust-implementation-observer",
            RUST_ANALYZER_VERSION,
            observations,
            issues,
        )
    }

    /// Builds a deterministic result from language-analyzer facts.
    ///
    /// This is the language-neutral analyzer boundary, not a plugin registry and
    /// not an architectural interpretation surface.
    #[must_use]
    pub fn from_facts(
        snapshot_fingerprint: impl Into<String>,
        analyzer_id: impl Into<String>,
        analyzer_version: impl Into<String>,
        mut observations: Vec<ImplementationObservation>,
        mut issues: Vec<ObservationIssue>,
    ) -> Self {
        observations.sort();
        observations.dedup();
        issues.sort();
        issues.dedup();
        let mut grouped = BTreeMap::<(String, String), Vec<ObservationProvenance>>::new();
        for observation in &observations {
            if observation.target_classification == TargetClassification::GovernedModule
                && let Some(target) = &observation.target_module
                && target != &observation.source_module
            {
                grouped
                    .entry((observation.source_module.clone(), target.clone()))
                    .or_default()
                    .push(observation.provenance.clone());
            }
        }
        let module_dependencies = grouped
            .into_iter()
            .map(|((source_module, target_module), mut evidence)| {
                evidence.sort();
                evidence.dedup();
                ObservedModuleDependency {
                    source_module,
                    target_module,
                    evidence,
                }
            })
            .collect();
        Self {
            snapshot_fingerprint: snapshot_fingerprint.into(),
            analyzer_id: analyzer_id.into(),
            analyzer_version: analyzer_version.into(),
            observations,
            module_dependencies,
            issues,
        }
    }

    /// Returns the exact input snapshot identity.
    #[must_use]
    pub fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    /// Returns the stable analyzer identity.
    #[must_use]
    pub fn analyzer_id(&self) -> &str {
        &self.analyzer_id
    }

    /// Returns the analyzer semantic version.
    #[must_use]
    pub fn analyzer_version(&self) -> &str {
        &self.analyzer_version
    }

    /// Returns all low-level observations in canonical order.
    #[must_use]
    pub fn observations(&self) -> &[ImplementationObservation] {
        &self.observations
    }

    /// Returns normalized direct governed Module dependencies.
    #[must_use]
    pub fn module_dependencies(&self) -> &[ObservedModuleDependency] {
        &self.module_dependencies
    }

    /// Returns explicit unsupported and invalid analyzer facts.
    #[must_use]
    pub fn issues(&self) -> &[ObservationIssue] {
        &self.issues
    }
}

/// Explains why snapshot-bound implementation observation could not complete.
#[derive(Debug)]
pub enum ImplementationObservationError {
    /// Supplied source bytes differ from their stabilized snapshot identity.
    SnapshotIdentityMismatch(Box<str>),
    /// A Cargo manifest is not valid UTF-8.
    NonUtf8Manifest(Box<str>),
    /// A Cargo manifest could not be parsed structurally.
    InvalidCargoManifest {
        /// Repository-relative manifest path.
        path: Box<str>,
        /// TOML parse failure.
        source: toml::de::Error,
    },
    /// Rust source is not valid UTF-8.
    NonUtf8Rust(Box<str>),
    /// Rust source could not be parsed structurally.
    InvalidRustSource {
        /// Repository-relative source path.
        path: Box<str>,
        /// Rust parse failure.
        source: syn::Error,
    },
}

impl Display for ImplementationObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotIdentityMismatch(path) => write!(
                formatter,
                "implementation source `{path}` differs from its stabilized snapshot identity"
            ),
            Self::NonUtf8Manifest(path) => {
                write!(formatter, "Cargo manifest `{path}` is not UTF-8")
            }
            Self::InvalidCargoManifest { path, source } => {
                write!(formatter, "Cargo manifest `{path}` is invalid: {source}")
            }
            Self::NonUtf8Rust(path) => write!(formatter, "Rust source `{path}` is not UTF-8"),
            Self::InvalidRustSource { path, source } => {
                write!(formatter, "Rust source `{path}` is invalid: {source}")
            }
        }
    }
}

impl Error for ImplementationObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidCargoManifest { source, .. } => Some(source),
            Self::InvalidRustSource { source, .. } => Some(source),
            Self::SnapshotIdentityMismatch(_) | Self::NonUtf8Manifest(_) | Self::NonUtf8Rust(_) => {
                None
            }
        }
    }
}
