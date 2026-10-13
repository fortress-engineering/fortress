//! Resident composition over immutable inputs and the production evaluator.
//!
//! Watcher messages are hints. Publication checks the entire observed inventory
//! again; reusable units remain private to the single coordinator. Reader pins
//! own their resource charges even after the coordinator closes.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use sha2::{Digest, Sha256};

pub use crate::audit::EvaluationPhaseMeasurement;

use crate::affected_analysis::{
    AuthorityInputKind, SessionDependencyIndex, SessionInputDescriptor, SessionInputRole,
    SessionInvalidation, SessionInvalidationStatus, classify_authority_path,
};
use crate::audit::{
    AuditError, AuditResult, EvaluationPhaseRecorder, ResidentEvaluation, ResidentWork,
    observe_resident_source_bounded,
};
use crate::certification::RustSuiteExecution;
use crate::control_layout::{
    ControlLayout, ControlRole, ControlSourceBinding, EVIDENCE_ROOT, PROJECT_CONFIGURATION_PATH,
};
use crate::heavy_admission::DirectoryIdentity;
use crate::observation::{
    CandidateChangeSet, ChangeOperation, ObservationError, SourceManifest, SourceView,
};
use crate::program_semantics::{ProgramSemanticModel, ProgramSemanticWork};
use crate::project::ProjectConfiguration;
use crate::resident_worker::{ResidentWorker, WorkerEvaluation, WorkerLimits};
use crate::runtime_storage::{RunWorkspace, RuntimeStorage, StoragePolicy, StorageReport};
use crate::semantic_analysis::{SemanticAnalysisEvaluation, SemanticPreparationWork};
use crate::snapshot::SnapshotError;
use crate::state_effect_analysis::{StateEffectAnalysisEvaluation, StateEffectPreparationWork};

const MIB: usize = 1024 * 1024;

/// Locally configurable admission and retention limits, excluded from semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Maximum source bytes checked before source-buffer allocation.
    pub max_source_bytes: usize,
    /// Maximum observed ordinary source files.
    pub max_files: usize,
    /// Maximum completed executable symbols.
    pub max_symbols: usize,
    /// Maximum completed call facts.
    pub max_calls: usize,
    /// Maximum completed dependency reads.
    pub max_dependencies: usize,
    /// Maximum simultaneous charged generations, including retired reader pins.
    pub max_generations: usize,
    /// Maximum retained isolated candidate buffers.
    pub max_candidates: usize,
    /// Maximum conservative resident allocation charge across live pins and work.
    /// This operational estimate is not a hard process-RSS bound.
    pub max_accounted_bytes: usize,
    /// Maximum retained coordinator preparation charge; larger caches are evicted.
    pub max_preparation_bytes: usize,
    /// Maximum retained parse/body and fixed-point trajectory units.
    pub max_preparation_units: usize,
    /// Maximum cumulative tokenization input admission per parser thread epoch.
    /// A dedicated worker is joined before an exhausted epoch is replaced.
    pub max_parser_bytes: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 128 * MIB,
            max_files: 50_000,
            max_symbols: 500_000,
            max_calls: 1_000_000,
            max_dependencies: 4_000_000,
            max_generations: 16,
            max_candidates: 16,
            max_accounted_bytes: 16384 * MIB,
            max_preparation_bytes: 1024 * MIB,
            max_preparation_units: 1_000_000,
            max_parser_bytes: 64 * MIB,
        }
    }
}

/// Operational session options and unchanged external execution evidence.
#[derive(Clone, Debug, Default)]
pub struct SessionOptions {
    /// Resident admission and preparation-retention limits.
    pub limits: SessionLimits,
    /// Installed runtime storage policy.
    pub storage_policy: StoragePolicy,
    /// Actual execution evidence supplied by the execution boundary.
    /// Its source identity, eligibility and pass flags are never freshened here.
    pub suite_execution: Option<RustSuiteExecution>,
}

/// An optional expected base and nonauthoritative watcher path hints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceDelta {
    /// Exact immutable input revision expected by the requesting client.
    pub expected_input_revision: Option<String>,
    /// Paths reported by a watcher; full observation detects omitted changes.
    pub hinted_paths: Vec<String>,
}

impl SourceDelta {
    /// Creates a refresh request bound to an exact prior input revision.
    #[must_use]
    pub fn for_base(revision: impl Into<String>) -> Self {
        Self {
            expected_input_revision: Some(revision.into()),
            hinted_paths: Vec::new(),
        }
    }
}

/// Operational outcome, separate from all canonical semantic verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDisposition {
    /// Exact inputs were unchanged and retained units were available.
    InputUnchanged,
    /// Complete owner-local proofs admitted some reusable work.
    SelectiveRebuild,
    /// A missing or incomplete proof required the unchanged full producer.
    FullReevaluationRequired,
}

impl SessionDisposition {
    fn from_work(
        reuse: bool,
        complete_preparation: bool,
        work: &ResidentWork,
        invalidation: Option<&SessionInvalidation>,
        unchanged: bool,
    ) -> Self {
        if !reuse
            || !complete_preparation
            || work.full_reevaluation_required()
            || invalidation.is_some_and(|invalidation| {
                invalidation.status() == SessionInvalidationStatus::FullReevaluationRequired
            })
        {
            Self::FullReevaluationRequired
        } else if unchanged {
            Self::InputUnchanged
        } else {
            Self::SelectiveRebuild
        }
    }
}

/// Whether immutable results describe actual or isolated hypothetical bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationSubject {
    /// Stabilized actual repository inputs validated before publication.
    Actual,
    /// An isolated supplied source view, never published as actual state.
    Candidate,
}

/// Actual owner work counts from one preparation; never semantic identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionWork {
    /// Program parse, declaration, body, caller and graph work.
    pub program: ProgramSemanticWork,
    /// Domain and component round work.
    pub semantic: SemanticPreparationWork,
    /// Direct effect, closure, edge and component round work.
    pub state_effect: StateEffectPreparationWork,
    /// Actual tokenization operations, including a discarded epoch retry.
    pub tokenizations: usize,
    /// Exact source/string bytes submitted to actual tokenization operations.
    pub input_bytes_tokenized: usize,
    /// Checked admission charges added by this request, including a retry.
    pub parser_admission_bytes_added: usize,
    /// Whether a joined parser epoch required a fresh cold attempt.
    pub parser_epoch_rotated: bool,
    /// Actual tokenizations discarded before a fresh epoch retry.
    pub discarded_tokenizations: usize,
    /// Input bytes discarded before a fresh epoch retry.
    pub discarded_input_bytes: usize,
    /// Admission bytes discarded before a fresh epoch retry.
    pub discarded_parser_bytes: usize,
    /// Current epoch's retained admission bytes, independent of request work.
    pub retained_parser_bytes: usize,
    /// Current epoch's retained input bytes.
    pub retained_parser_input_bytes: usize,
    /// Current epoch's actual cumulative tokenizations.
    pub retained_parser_tokenizations: usize,
    /// Conservative current parser allocation charge, below its lifetime permit.
    pub retained_parser_charge: usize,
    /// Units in the newly prepared cache, zero when retention was rejected.
    pub prepared_units: usize,
    /// Measured owner-phase costs, excluded from canonical semantic identity.
    pub phase_measurements: Vec<EvaluationPhaseMeasurement>,
    /// Produced preparation charge before the retention decision; not RSS.
    pub preparation_bytes_before_eviction: usize,
    /// Produced owner-unit count before the retention decision.
    pub preparation_units_before_eviction: usize,
    /// Program, domain and effect owner charges, in that order, before eviction.
    pub preparation_bytes_by_owner: [usize; 3],
}

impl From<ResidentWork> for SessionWork {
    fn from(work: ResidentWork) -> Self {
        Self {
            program: work.program,
            semantic: work.semantic,
            state_effect: work.state_effect,
            phase_measurements: work.phase_measurements,
            ..Self::default()
        }
    }
}

impl From<&WorkerEvaluation> for SessionWork {
    fn from(produced: &WorkerEvaluation) -> Self {
        let mut request_work: Self = produced.work.clone().into();
        request_work.tokenizations = produced.tokenizations;
        request_work.input_bytes_tokenized = produced.input_bytes_tokenized;
        request_work.parser_admission_bytes_added = produced.admission_bytes_added;
        request_work.parser_epoch_rotated = produced.parser_rotated;
        request_work.discarded_tokenizations = produced.discarded_tokenizations;
        request_work.discarded_input_bytes = produced.discarded_input_bytes;
        request_work.discarded_parser_bytes = produced.discarded_parser_bytes;
        request_work.retained_parser_bytes = produced.parser_bytes;
        request_work.retained_parser_input_bytes = produced.parser_input_bytes;
        request_work.retained_parser_tokenizations = produced.parser_tokenizations;
        request_work.retained_parser_charge = produced.parser_resident_charge;
        request_work.prepared_units = produced.preparation_units;
        request_work.preparation_bytes_before_eviction = produced.preparation_bytes_before_eviction;
        request_work.preparation_units_before_eviction = produced.preparation_units_before_eviction;
        request_work.preparation_bytes_by_owner = produced.preparation_bytes_by_owner;
        request_work
    }
}

/// A completed immutable result. Pins remain valid for their original subject.
pub struct Generation {
    repository_identity: String,
    id: String,
    subject: GenerationSubject,
    evaluation: ResidentEvaluation,
    dependency_index: SessionDependencyIndex,
    availability: BTreeMap<String, String>,
    _charge: AllocationCharge,
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Generation")
            .field("generation_id", &self.id)
            .field("input_revision", &self.input_revision())
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl Generation {
    /// Returns the physical machine-local repository identity.
    #[must_use]
    pub fn repository_identity(&self) -> &str {
        &self.repository_identity
    }
    /// Returns this coordinator's opaque publication identity.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.id
    }
    /// Returns the exact source-view revision.
    #[must_use]
    pub fn input_revision(&self) -> &str {
        self.evaluation.source_view.digest()
    }
    /// Returns the exact frontend and program context binding.
    #[must_use]
    pub fn context_digest(&self) -> &str {
        self.evaluation.evaluation_key.program_context_digest()
    }
    /// Returns the exact selected authority binding.
    #[must_use]
    pub fn authority_digest(&self) -> &str {
        self.evaluation.evaluation_key.authority_binding_digest()
    }
    /// Returns actual or hypothetical subject provenance.
    #[must_use]
    pub const fn subject(&self) -> GenerationSubject {
        self.subject
    }
    /// Returns the immutable source bytes used by every finished model.
    #[must_use]
    pub const fn source_view(&self) -> &SourceView {
        &self.evaluation.source_view
    }
    /// Returns the exact canonical source manifest bound by the evaluation key.
    #[must_use]
    pub const fn source_manifest(&self) -> &SourceManifest {
        &self.evaluation.source_manifest
    }
    /// Returns whether unchanged external suite execution was supplied.
    #[must_use]
    pub const fn execution_evidence_present(&self) -> bool {
        self.evaluation.execution_evidence_present
    }
    /// Returns the finished Program Semantic Model.
    #[must_use]
    pub fn psm(&self) -> &ProgramSemanticModel {
        &self.evaluation.psm
    }
    /// Returns the finished domain evaluation.
    #[must_use]
    pub fn semantic(&self) -> &SemanticAnalysisEvaluation {
        &self.evaluation.semantic
    }
    /// Returns the finished State/Effect evaluation.
    #[must_use]
    pub fn state_effect(&self) -> &StateEffectAnalysisEvaluation {
        &self.evaluation.state_effect
    }
    /// Returns canonical production artifact bytes for this exact input context.
    /// The three execution-dependent members require supplied real suite evidence.
    #[must_use]
    pub const fn canonical_artifacts(&self) -> &BTreeMap<String, String> {
        &self.evaluation.canonical_artifacts
    }
    /// Returns the audit from the same production semantic stack.
    #[must_use]
    pub const fn audit(&self) -> &AuditResult {
        &self.evaluation.audit
    }
    /// Returns the completed dependency index, including unsuccessful lookups.
    #[must_use]
    pub const fn dependency_index(&self) -> &SessionDependencyIndex {
        &self.dependency_index
    }
    /// Returns nonrecursive availability observations at this generation's capture.
    #[must_use]
    pub const fn observed_availability(&self) -> &BTreeMap<String, String> {
        &self.availability
    }
}

/// Completed work and its operational publication/reuse disposition.
#[derive(Debug)]
pub struct SessionUpdate {
    /// Immutable actual or isolated result.
    pub generation: Arc<Generation>,
    /// Operational reuse decision, independent of findings and certification.
    pub disposition: SessionDisposition,
    /// Actual producer work.
    pub work: SessionWork,
    /// Stable operational fallback or retention explanations.
    pub reasons: Vec<String>,
    /// Nonrecursive history changes, which never change source semantic identity.
    pub availability_changes: Vec<String>,
}

/// One isolated client buffer and its completed hypothetical evaluation.
#[derive(Debug)]
pub struct CandidateEvaluation {
    /// Session-local buffer identity.
    pub candidate_id: String,
    /// Exact actual base revision used by the operations.
    pub base_input_revision: String,
    /// Exact proposal identity including ordered preimages and operations.
    pub change_digest: String,
    /// Finished hypothetical generation.
    pub generation: Arc<Generation>,
    /// Operational reuse disposition.
    pub disposition: SessionDisposition,
    /// Actual producer work.
    pub work: SessionWork,
    /// Operational fallback reasons.
    pub reasons: Vec<String>,
}

/// Typed operational failures; none asserts a favorable semantic result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionErrorKind {
    /// Cancellation won the publication boundary.
    Cancelled,
    /// Current physical inputs or the client's base changed.
    StaleBase,
    /// Bounded resource admission or retention failed.
    ResourceLimit,
    /// The supplied view cannot prove a complete input inventory for cold evaluation.
    FullReevaluationRequired,
    /// The coordinator has closed.
    Closed,
    /// Candidate operations or options are invalid.
    InvalidInput,
    /// The unchanged production evaluator rejected an input.
    Evaluation,
    /// Operational storage or native admission failed.
    Storage,
}

/// Owned neutral diagnostic, suitable for an external facade to transport.
#[derive(Debug)]
pub struct SessionError {
    kind: SessionErrorKind,
    detail: String,
}

impl SessionError {
    pub(crate) fn new(kind: SessionErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
    /// Returns the typed operational failure.
    #[must_use]
    pub const fn kind(&self) -> SessionErrorKind {
        self.kind
    }
    /// Returns the owned diagnostic without frontend thread-local objects.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}
impl Error for SessionError {}

fn evaluation_error(error: &AuditError) -> SessionError {
    let kind = if matches!(
        error,
        AuditError::ResidentSourceLimit { .. }
            | AuditError::Snapshot(SnapshotError::Observation(
                ObservationError::ResourceLimit { .. }
            ))
    ) {
        SessionErrorKind::ResourceLimit
    } else {
        SessionErrorKind::Evaluation
    };
    SessionError::new(kind, error.to_string())
}
fn storage_error(error: &io::Error) -> SessionError {
    SessionError::new(SessionErrorKind::Storage, error.to_string())
}
fn resource_error(detail: &str) -> SessionError {
    SessionError::new(SessionErrorKind::ResourceLimit, detail)
}

struct InputCharge {
    source_bytes: usize,
    metadata_bytes: usize,
    pending: usize,
}

impl InputCharge {
    fn new(
        view: &SourceView,
        availability: &BTreeMap<String, String>,
        limits: &SessionLimits,
    ) -> Result<Self, SessionError> {
        let source_bytes = source_size(view)?;
        let source_metadata = view.keys().try_fold(0_usize, |total, path| {
            path.len()
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(512))
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or_else(|| resource_error("input metadata charge overflow"))
        })?;
        let metadata_bytes =
            availability
                .iter()
                .try_fold(source_metadata, |total, (path, digest)| {
                    path.len()
                        .checked_add(digest.len())
                        .and_then(|bytes| bytes.checked_mul(4))
                        .and_then(|bytes| bytes.checked_add(512))
                        .and_then(|bytes| total.checked_add(bytes))
                        .ok_or_else(|| resource_error("availability metadata charge overflow"))
                })?;
        if source_bytes > limits.max_source_bytes || view.len() > limits.max_files {
            return Err(resource_error("isolated source view exceeds input limits"));
        }
        // Reserve producer buffers before preparation. This estimate is not RSS.
        let pending = source_bytes
            .checked_mul(256)
            .and_then(|bytes| bytes.checked_add(256 * MIB))
            .and_then(|bytes| bytes.checked_add(limits.max_preparation_bytes))
            .and_then(|bytes| {
                metadata_bytes
                    .checked_mul(8)
                    .and_then(|metadata| bytes.checked_add(metadata))
            })
            .ok_or_else(|| resource_error("pending producer charge overflow"))?;
        Ok(Self {
            source_bytes,
            metadata_bytes,
            pending,
        })
    }

    fn completed(&self, evaluation: &ResidentEvaluation) -> Result<usize, SessionError> {
        let canonical_bytes =
            evaluation
                .canonical_artifacts
                .values()
                .try_fold(0_usize, |sum, bytes| {
                    sum.checked_add(bytes.len())
                        .ok_or_else(|| resource_error("artifact byte count overflow"))
                })?;
        self.source_bytes
            .checked_mul(128)
            .and_then(|bytes| {
                self.metadata_bytes
                    .checked_mul(8)
                    .and_then(|metadata| bytes.checked_add(metadata))
            })
            .and_then(|bytes| {
                canonical_bytes
                    .checked_mul(8)
                    .and_then(|artifacts| bytes.checked_add(artifacts))
            })
            .and_then(|bytes| {
                evaluation
                    .dependencies
                    .len()
                    .checked_mul(512)
                    .and_then(|dependencies| bytes.checked_add(dependencies))
            })
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| resource_error("completed generation charge overflow"))
    }
}

fn generation_dependencies(
    evaluation: &ResidentEvaluation,
    availability: &BTreeMap<String, String>,
) -> Result<SessionDependencyIndex, SessionError> {
    let (mut descriptors, authorities) = input_descriptors(evaluation)?;
    for (path, digest) in availability {
        descriptors.push(
            SessionInputDescriptor::new(path, digest, SessionInputRole::Availability).map_err(
                |error| SessionError::new(SessionErrorKind::Evaluation, error.to_string()),
            )?,
        );
    }
    SessionDependencyIndex::new(
        &evaluation.affected_snapshot,
        &evaluation.psm,
        &evaluation.dependencies,
        evaluation.evaluation_key.authority_binding_digest(),
        &authorities,
        &descriptors,
    )
    .map_err(|error| SessionError::new(SessionErrorKind::Evaluation, error.to_string()))
}

#[derive(Default)]
struct ResourceState {
    bytes: usize,
    generations: usize,
    max_bytes: usize,
    max_generations: usize,
}
struct ResourceAccount(Mutex<ResourceState>);
static ACCOUNTS: OnceLock<Mutex<BTreeMap<String, Weak<ResourceAccount>>>> = OnceLock::new();

impl ResourceAccount {
    fn for_repository(identity: &str, limits: &SessionLimits) -> Result<Arc<Self>, SessionError> {
        let mut accounts = ACCOUNTS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| resource_error("resource account lock is unavailable"))?;
        accounts.retain(|_, account| account.strong_count() > 0);
        if let Some(account) = accounts.get(identity).and_then(Weak::upgrade) {
            let mut state = account
                .0
                .lock()
                .map_err(|_| resource_error("resource account lock is unavailable"))?;
            state.max_bytes = state.max_bytes.min(limits.max_accounted_bytes);
            state.max_generations = state.max_generations.min(limits.max_generations);
            drop(state);
            return Ok(account);
        }
        let account = Arc::new(Self(Mutex::new(ResourceState {
            max_bytes: limits.max_accounted_bytes,
            max_generations: limits.max_generations,
            ..ResourceState::default()
        })));
        accounts.insert(identity.into(), Arc::downgrade(&account));
        Ok(account)
    }

    fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        generation: bool,
    ) -> Result<AllocationCharge, SessionError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| resource_error("resource account lock is unavailable"))?;
        let next_bytes = state
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| resource_error("resident charge overflow"))?;
        let next_generations = state
            .generations
            .checked_add(usize::from(generation))
            .ok_or_else(|| resource_error("generation count overflow"))?;
        if next_bytes > state.max_bytes || next_generations > state.max_generations {
            return Err(resource_error(
                "live pins and pending work exceed resident limits",
            ));
        }
        state.bytes = next_bytes;
        state.generations = next_generations;
        Ok(AllocationCharge {
            account: Arc::clone(self),
            bytes,
            generation,
        })
    }
}

struct AllocationCharge {
    account: Arc<ResourceAccount>,
    bytes: usize,
    generation: bool,
}
impl AllocationCharge {
    fn split(&mut self, bytes: usize) -> Result<Self, SessionError> {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| resource_error("allocation charge split overflow"))?;
        Ok(Self {
            account: Arc::clone(&self.account),
            bytes,
            generation: false,
        })
    }
    fn resize(&mut self, bytes: usize) -> Result<(), SessionError> {
        let mut state = self
            .account
            .0
            .lock()
            .map_err(|_| resource_error("resource account lock is unavailable"))?;
        let next = state
            .bytes
            .checked_sub(self.bytes)
            .and_then(|prior| prior.checked_add(bytes))
            .ok_or_else(|| resource_error("resident charge overflow"))?;
        if next > state.max_bytes {
            return Err(resource_error(
                "completed allocation charge exceeds resident limits",
            ));
        }
        state.bytes = next;
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for AllocationCharge {
    fn drop(&mut self) {
        if let Ok(mut state) = self.account.0.lock() {
            state.bytes = state.bytes.saturating_sub(self.bytes);
            state.generations = state
                .generations
                .saturating_sub(usize::from(self.generation));
        }
    }
}

struct PublicationState {
    open: bool,
    current: Option<Arc<Generation>>,
    serial: u64,
}
struct SharedControl {
    publication: Mutex<PublicationState>,
    cancellation: AtomicU64,
}

/// Operational progress boundaries, excluded from all semantic identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStage {
    /// Exact input capture has completed.
    InputsCaptured,
    /// The production evaluator has returned complete immutable results.
    ModelsPrepared,
    /// Whole-input publication validation is about to begin.
    ValidatingInputs,
}

/// A thread-safe cancellation port with no access to mutable preparation units.
#[derive(Clone)]
pub struct SessionControl(Arc<SharedControl>);
impl SessionControl {
    /// Cancels pending work; the coordinator checks this at publication.
    pub fn cancel(&self) {
        // Cancellation and publication have one ordered commit boundary.
        if let Ok(_publication) = self.0.publication.lock() {
            self.0.cancellation.fetch_add(1, Ordering::AcqRel);
        }
    }
}

// Field order also joins the native thread before releasing its lifetime charge.
struct WorkerResources {
    worker: ResidentWorker,
    _parser_charge: AllocationCharge,
}

/// Single coordinator with immutable concurrent-reader generations.
pub struct Session {
    root: PathBuf,
    directory: DirectoryIdentity,
    options: SessionOptions,
    account: Arc<ResourceAccount>,
    control: Arc<SharedControl>,
    consumed_cancellation: u64,
    worker: Option<WorkerResources>,
    preparation_charge: Option<AllocationCharge>,
    pending_preparation_charge: Option<AllocationCharge>,
    candidates: BTreeMap<String, Arc<Generation>>,
    workspace: Option<RunWorkspace>,
    nonce: String,
    observer: Option<Arc<dyn Fn(SessionStage) + Send + Sync>>,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Opens installed storage and publishes a stabilized initial generation.
    ///
    /// # Errors
    /// Returns typed storage, resource or unchanged-evaluator failures.
    pub fn open(
        root: &Path,
        storage_root: &Path,
        options: SessionOptions,
    ) -> Result<Self, SessionError> {
        if options.limits.max_accounted_bytes == 0
            || options.limits.max_generations == 0
            || options.limits.max_files == 0
        {
            return Err(SessionError::new(
                SessionErrorKind::InvalidInput,
                "nonzero resident admission limits are required",
            ));
        }
        if let Some(suite) = &options.suite_execution {
            suite.validate().map_err(|error| {
                SessionError::new(SessionErrorKind::InvalidInput, error.to_string())
            })?;
        }
        let root = root.canonicalize().map_err(|error| storage_error(&error))?;
        let directory = DirectoryIdentity::capture(&root).map_err(|error| storage_error(&error))?;
        let account = ResourceAccount::for_repository(directory.key(), &options.limits)?;
        let runtime = RuntimeStorage::new(&root, storage_root, options.storage_policy.clone())
            .map_err(|error| storage_error(&error))?;
        let workspace = runtime
            .acquire_workspace()
            .map_err(|error| storage_error(&error))?;
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|error| SessionError::new(SessionErrorKind::Storage, error.to_string()))?;
        let mut nonce = String::with_capacity(24);
        for byte in random {
            write!(nonce, "{byte:02x}").expect("writing a string is infallible");
        }
        let worker = ResidentWorker::start(
            &root,
            options.suite_execution.clone(),
            WorkerLimits {
                parser_bytes: options.limits.max_parser_bytes,
                preparation_bytes: options.limits.max_preparation_bytes,
                preparation_units: options.limits.max_preparation_units,
            },
        )?;
        let parser_charge = account.reserve(worker.maximum_parser_charge(), false)?;
        let mut session = Self {
            root,
            directory,
            options,
            account,
            control: Arc::new(SharedControl {
                publication: Mutex::new(PublicationState {
                    open: true,
                    current: None,
                    serial: 0,
                }),
                cancellation: AtomicU64::new(0),
            }),
            consumed_cancellation: 0,
            worker: Some(WorkerResources {
                worker,
                _parser_charge: parser_charge,
            }),
            preparation_charge: None,
            pending_preparation_charge: None,
            candidates: BTreeMap::new(),
            workspace: Some(workspace),
            nonce,
            observer: None,
        };
        session.refresh(&SourceDelta::default())?;
        Ok(session)
    }

    /// Returns a thread-safe cancellation handle.
    #[must_use]
    pub fn control(&self) -> SessionControl {
        SessionControl(Arc::clone(&self.control))
    }

    /// Cancels current or next pending preparation without changing prior truth.
    pub fn cancel(&self) {
        self.control().cancel();
    }

    /// Installs an operational progress observer outside publication locks.
    /// The callback can request cancellation without touching semantic inputs.
    pub fn set_progress_observer(
        &mut self,
        observer: impl Fn(SessionStage) + Send + Sync + 'static,
    ) {
        self.observer = Some(Arc::new(observer));
    }

    fn progress(&self, stage: SessionStage) {
        if let Some(observer) = &self.observer {
            observer(stage);
        }
    }

    fn current(&self) -> Result<Option<Arc<Generation>>, SessionError> {
        let state = self
            .control
            .publication
            .lock()
            .map_err(|_| resource_error("publication lock is unavailable"))?;
        if !state.open {
            return Err(SessionError::new(
                SessionErrorKind::Closed,
                "resident coordinator is closed",
            ));
        }
        Ok(state.current.clone())
    }

    fn begin(&mut self) -> Result<(u64, Option<Arc<Generation>>), SessionError> {
        let current = self.current()?;
        let cancellation = self.control.cancellation.load(Ordering::Acquire);
        if cancellation != self.consumed_cancellation {
            self.consumed_cancellation = cancellation;
            return Err(SessionError::new(
                SessionErrorKind::Cancelled,
                "pending work was cancelled",
            ));
        }
        self.workspace
            .as_ref()
            .ok_or_else(|| {
                SessionError::new(SessionErrorKind::Closed, "resident storage was released")
            })?
            .reserve(0)
            .map_err(|error| storage_error(&error))?;
        Ok((cancellation, current))
    }

    fn check_cancel(&mut self, token: u64) -> Result<(), SessionError> {
        let current = self.control.cancellation.load(Ordering::Acquire);
        if current != token {
            self.consumed_cancellation = current;
            return Err(SessionError::new(
                SessionErrorKind::Cancelled,
                "cancellation won the publication boundary",
            ));
        }
        Ok(())
    }

    fn capture(
        &self,
    ) -> Result<(SourceView, BTreeMap<String, String>, AllocationCharge), SessionError> {
        if !self
            .directory
            .matches(&self.root)
            .map_err(|error| storage_error(&error))?
        {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "physical repository directory changed",
            ));
        }
        // Both source and history inventories admit at most 512 relative-path
        // bytes per entry in aggregate. Reserve their repeated path/map copies
        // separately from node metadata and native absolute-root prefixes.
        let path_entry_charge = self
            .root
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(2 * (512 * 8 + 512)))
            .ok_or_else(|| resource_error("capture path charge overflow"))?;
        let capture_bytes = self
            .options
            .limits
            .max_source_bytes
            .checked_mul(4)
            .and_then(|bytes| {
                self.options
                    .limits
                    .max_files
                    .checked_mul(path_entry_charge)
                    .and_then(|files| bytes.checked_add(files))
            })
            .ok_or_else(|| resource_error("source capture charge overflow"))?;
        let charge = self.account.reserve(capture_bytes, false)?;
        let (view, _) = observe_resident_source_bounded(
            &self.root,
            self.options.limits.max_source_bytes,
            self.options.limits.max_files,
        )
        .map_err(|error| evaluation_error(&error))?;
        let availability = observe_session_availability(&self.root, self.options.limits.max_files)?;
        Ok((view, availability, charge))
    }

    /// Acquires a reader pin only after revalidating the full current inputs.
    ///
    /// # Errors
    /// Returns `STALE_BASE` when any missed source or authority mutation is found.
    pub fn acquire_generation(&self) -> Result<Arc<Generation>, SessionError> {
        let current = self.current()?.ok_or_else(|| {
            SessionError::new(SessionErrorKind::Closed, "no generation is published")
        })?;
        let (view, availability, _capture) = self.capture()?;
        if view != current.evaluation.source_view || availability != current.availability {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "physical inputs or availability no longer match the published generation",
            ));
        }
        let state = self
            .control
            .publication
            .lock()
            .map_err(|_| resource_error("publication lock is unavailable"))?;
        if !state.open
            || state
                .current
                .as_ref()
                .is_none_or(|generation| !Arc::ptr_eq(generation, &current))
        {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "publication changed during reader acquisition",
            ));
        }
        Ok(current)
    }

    /// Reobserves actual inputs and publishes only a fully validated generation.
    ///
    /// # Errors
    /// Returns typed cancellation, stale-base, resource, storage or evaluation failures.
    pub fn refresh(&mut self, delta: &SourceDelta) -> Result<SessionUpdate, SessionError> {
        let result = self.refresh_inner(delta);
        if result.is_err() {
            self.discard_pending()?;
        }
        result
    }

    fn refresh_inner(&mut self, delta: &SourceDelta) -> Result<SessionUpdate, SessionError> {
        let (token, base) = self.begin()?;
        if delta
            .expected_input_revision
            .as_deref()
            .is_some_and(|expected| {
                base.as_ref()
                    .is_none_or(|base| base.input_revision() != expected)
            })
        {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "refresh expected a different input revision",
            ));
        }
        let (view, availability, _capture) = self.capture()?;
        self.progress(SessionStage::InputsCaptured);
        self.check_cancel(token)?;
        let update = self.evaluate(
            view,
            availability,
            self.preparation_charge.is_some(),
            GenerationSubject::Actual,
            base.as_deref(),
        )?;
        self.progress(SessionStage::ModelsPrepared);
        self.check_cancel(token)?;
        self.progress(SessionStage::ValidatingInputs);
        let (current_view, current_availability, _validation) = self.capture()?;
        if current_view != update.generation.evaluation.source_view
            || current_availability != update.generation.availability
        {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "physical inputs or availability changed during evaluation",
            ));
        }
        self.check_cancel(token)?;
        {
            let control = Arc::clone(&self.control);
            let mut state = control
                .publication
                .lock()
                .map_err(|_| resource_error("publication lock is unavailable"))?;
            if self.control.cancellation.load(Ordering::Acquire) != token {
                return Err(SessionError::new(
                    SessionErrorKind::Cancelled,
                    "cancellation won the publication boundary",
                ));
            }
            if !state.open || !same_generation(state.current.as_ref(), base.as_ref()) {
                return Err(SessionError::new(
                    SessionErrorKind::StaleBase,
                    "publication base changed before commit",
                ));
            }
            let next_serial = state
                .serial
                .checked_add(1)
                .ok_or_else(|| resource_error("publication serial overflow"))?;
            let workspace = self.workspace.as_mut().ok_or_else(|| {
                SessionError::new(SessionErrorKind::Closed, "resident storage was released")
            })?;
            workspace
                .validating()
                .map_err(|error| storage_error(&error))?;
            workspace
                .publish(update.generation.generation_id())
                .map_err(|error| storage_error(&error))?;
            // All fallible acknowledgements precede the immutable head replacement.
            self.worker
                .as_mut()
                .ok_or_else(|| {
                    SessionError::new(SessionErrorKind::Closed, "resident worker was released")
                })?
                .worker
                .commit(true)?;
            self.preparation_charge = self.pending_preparation_charge.take();
            state.serial = next_serial;
            state.current = Some(Arc::clone(&update.generation));
        }
        Ok(update)
    }

    fn evaluate(
        &mut self,
        view: SourceView,
        availability: BTreeMap<String, String>,
        reuse: bool,
        subject: GenerationSubject,
        base: Option<&Generation>,
    ) -> Result<SessionUpdate, SessionError> {
        let inputs = InputCharge::new(&view, &availability, &self.options.limits)?;
        let mut charge = Some(self.account.reserve(inputs.pending, true)?);
        let result = (|| {
            let produced = self.produce(view, reuse)?;
            let mut request_work = SessionWork::from(&produced);
            let evaluation = produced.evaluation;
            let work = produced.work;
            let mut measurements = EvaluationPhaseRecorder::new();
            if evaluation.psm.symbols().len() > self.options.limits.max_symbols
                || evaluation.psm.calls().len() > self.options.limits.max_calls
                || evaluation.dependencies.len() > self.options.limits.max_dependencies
            {
                return Err(resource_error(
                    "completed semantic inventory exceeds resident limits",
                ));
            }
            let dependency_index = generation_dependencies(&evaluation, &availability)?;
            measurements.record("session_dependency_index");
            let completed = inputs.completed(&evaluation)?;
            // Preparation is live during final assembly and must fit before its retention decision.
            charge
                .as_mut()
                .ok_or_else(|| resource_error("missing producer permit"))?
                .resize(
                    completed
                        .checked_add(produced.preparation_bytes)
                        .ok_or_else(|| resource_error("preparation charge overflow"))?,
                )?;
            measurements.record("session_completed_accounting");
            let mut reasons = work.fallback_reasons();
            reasons.extend(produced.reasons);
            let invalidation = base.map(|base| base.dependency_index.invalidate(&dependency_index));
            let disposition = SessionDisposition::from_work(
                reuse,
                produced.complete_prior_owner_preparation
                    && !produced.parser_rotated
                    && produced.retained_preparation_bytes > 0,
                &work,
                invalidation.as_ref(),
                base.is_some_and(|base| base.input_revision() == evaluation.source_view.digest()),
            );
            let availability_changes =
                invalidation.as_ref().map_or_else(Vec::new, |invalidation| {
                    invalidation.availability_changes().to_vec()
                });
            if let Some(invalidation) = invalidation {
                reasons.extend(invalidation.reasons().iter().cloned());
            }
            measurements.record("session_invalidation");
            reasons.sort();
            reasons.dedup();
            // The coordinator retains a separately charged preparation; the immutable
            // model's permit follows its Arc pins and never releases on coordinator close.
            self.pending_preparation_charge = Some(
                charge
                    .as_mut()
                    .ok_or_else(|| resource_error("missing producer permit"))?
                    .split(produced.preparation_bytes)?,
            );
            let serial = self
                .control
                .publication
                .lock()
                .map_err(|_| resource_error("publication lock is unavailable"))?
                .serial;
            let generation = Arc::new(Generation {
                repository_identity: self.directory.key().into(),
                id: format!(
                    "{}:{}:{}",
                    self.nonce,
                    serial,
                    evaluation.evaluation_key.digest()
                ),
                subject,
                evaluation,
                dependency_index,
                availability,
                _charge: charge
                    .take()
                    .ok_or_else(|| resource_error("missing producer permit"))?,
            });
            measurements.record("session_generation_assembly");
            request_work
                .phase_measurements
                .extend(measurements.finish());
            Ok(SessionUpdate {
                generation,
                disposition,
                work: request_work,
                reasons,
                availability_changes,
            })
        })();
        if result.is_err() {
            // Pending parser handles are dropped before the producer permit.
            self.discard_pending()?;
        }
        result
    }

    fn produce(&mut self, view: SourceView, reuse: bool) -> Result<WorkerEvaluation, SessionError> {
        let produced_result = self
            .worker
            .as_mut()
            .ok_or_else(|| {
                SessionError::new(SessionErrorKind::Closed, "resident worker was released")
            })?
            .worker
            .evaluate(view, reuse);
        if self
            .worker
            .as_ref()
            .is_some_and(|resources| resources.worker.retained_preparation_bytes() == 0)
        {
            // A joined epoch has actually dropped the previous preparation.
            self.preparation_charge = None;
        }
        produced_result
    }

    fn discard_pending(&mut self) -> Result<(), SessionError> {
        let result = self
            .worker
            .as_mut()
            .map_or(Ok(()), |resources| resources.worker.discard());
        if result.is_err() {
            if let Some(resources) = &mut self.worker {
                let _ = resources.worker.close();
            }
            self.preparation_charge = None;
        }
        self.pending_preparation_charge = None;
        result
    }

    /// Evaluates isolated operations without mutating source or the actual head.
    ///
    /// # Errors
    /// Returns typed stale-base, resource, cancellation or input/evaluation failures.
    pub fn evaluate_delta(
        &mut self,
        candidate_id: &str,
        expected_base: &str,
        operations: Vec<ChangeOperation>,
    ) -> Result<CandidateEvaluation, SessionError> {
        let result = self.evaluate_delta_inner(candidate_id, expected_base, operations);
        self.discard_pending()?;
        result
    }

    fn evaluate_delta_inner(
        &mut self,
        candidate_id: &str,
        expected_base: &str,
        operations: Vec<ChangeOperation>,
    ) -> Result<CandidateEvaluation, SessionError> {
        let (token, base) = self.begin()?;
        let base = base.ok_or_else(|| {
            SessionError::new(SessionErrorKind::Closed, "no actual base is published")
        })?;
        if base.input_revision() != expected_base {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "candidate expected a different actual base",
            ));
        }
        self.validate_candidate_id(candidate_id)?;
        let (actual, availability, _capture) = self.capture()?;
        if actual != base.evaluation.source_view || availability != base.availability {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "actual candidate base is stale",
            ));
        }
        let operation_bytes = operation_size(&operations)?;
        validate_candidate_paths(&actual, &operations)?;
        let candidate_bytes = source_size(&actual)?
            .checked_add(operation_bytes)
            .ok_or_else(|| resource_error("candidate byte count overflow"))?;
        if candidate_bytes > self.options.limits.max_source_bytes {
            return Err(resource_error(
                "candidate input reservation exceeds source limit",
            ));
        }
        let _candidate_buffers = self.account.reserve(
            candidate_bytes
                .checked_mul(4)
                .ok_or_else(|| resource_error("candidate copy charge overflow"))?,
            false,
        )?;
        let changes = CandidateChangeSet::new(
            &actual,
            base.context_digest(),
            base.authority_digest(),
            operations,
        )
        .map_err(|error| SessionError::new(SessionErrorKind::InvalidInput, error.to_string()))?;
        validate_candidate_inventory(&actual, changes.view())?;
        let update = self.evaluate(
            changes.view().clone(),
            availability.clone(),
            self.preparation_charge.is_some(),
            GenerationSubject::Candidate,
            Some(&base),
        )?;
        self.progress(SessionStage::ModelsPrepared);
        self.check_cancel(token)?;
        let (current, current_availability, _validation) = self.capture()?;
        if current != actual
            || current_availability != availability
            || !same_generation(self.current()?.as_ref(), Some(&base))
        {
            return Err(SessionError::new(
                SessionErrorKind::StaleBase,
                "actual candidate base changed during evaluation",
            ));
        }
        self.check_cancel(token)?;
        {
            let state = self
                .control
                .publication
                .lock()
                .map_err(|_| resource_error("publication lock is unavailable"))?;
            if self.control.cancellation.load(Ordering::Acquire) != token {
                return Err(SessionError::new(
                    SessionErrorKind::Cancelled,
                    "cancellation won candidate retention",
                ));
            }
            if !state.open || !same_generation(state.current.as_ref(), Some(&base)) {
                return Err(SessionError::new(
                    SessionErrorKind::StaleBase,
                    "candidate base changed before retention",
                ));
            }
            self.candidates
                .insert(candidate_id.into(), Arc::clone(&update.generation));
        }
        Ok(CandidateEvaluation {
            candidate_id: candidate_id.into(),
            base_input_revision: base.input_revision().into(),
            change_digest: changes.digest().into(),
            generation: update.generation,
            disposition: update.disposition,
            work: update.work,
            reasons: update.reasons,
        })
    }

    fn validate_candidate_id(&self, candidate_id: &str) -> Result<(), SessionError> {
        if candidate_id.is_empty()
            || candidate_id.len() > 128
            || !candidate_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || self.candidates.contains_key(candidate_id)
        {
            return Err(SessionError::new(
                SessionErrorKind::InvalidInput,
                "candidate identity is invalid or already retained",
            ));
        }
        if self.candidates.len() >= self.options.limits.max_candidates {
            return Err(resource_error("candidate buffer limit reached"));
        }
        Ok(())
    }

    /// Runs the unchanged cold production stack for an isolated immutable view.
    /// This diagnostic/reference port shares admission, never publishes, and
    /// consumes exactly the same supplied execution context as prepared evaluation.
    ///
    /// # Errors
    /// Returns resource, cancellation, input or unchanged-producer failures.
    pub fn evaluate_view_cold(&mut self, view: SourceView) -> Result<SessionUpdate, SessionError> {
        let (token, base) = self.begin()?;
        let availability = base
            .as_ref()
            .map_or_else(BTreeMap::new, |base| base.availability.clone());
        let result = self
            .evaluate(
                view,
                availability,
                false,
                GenerationSubject::Candidate,
                base.as_deref(),
            )
            .and_then(|update| {
                self.check_cancel(token)?;
                Ok(update)
            });
        self.discard_pending()?;
        result
    }

    /// Releases a retained candidate; external pins keep their own charges.
    pub fn release_candidate(&mut self, candidate_id: &str) {
        self.candidates.remove(candidate_id);
    }

    /// Evicts reusable coordinator units without changing any immutable result.
    ///
    /// # Errors
    /// Returns an error if the worker cannot acknowledge eviction.
    pub fn evict_preparation(&mut self) -> Result<(), SessionError> {
        self.worker
            .as_mut()
            .ok_or_else(|| {
                SessionError::new(SessionErrorKind::Closed, "resident worker was released")
            })?
            .worker
            .evict()?;
        self.pending_preparation_charge = None;
        self.preparation_charge = None;
        Ok(())
    }

    /// Returns current conservative resident charge and live generation count.
    ///
    /// # Errors
    /// Returns a resource error if accounting cannot be inspected.
    pub fn resource_usage(&self) -> Result<(usize, usize), SessionError> {
        let state = self
            .account
            .0
            .lock()
            .map_err(|_| resource_error("resource account lock is unavailable"))?;
        Ok((state.bytes, state.generations))
    }

    /// Closes the coordinator and releases owned staging; reader pins survive.
    ///
    /// # Errors
    /// Returns storage cleanup errors or CLOSED when already released.
    pub fn close(&mut self) -> Result<StorageReport, SessionError> {
        self.cancel();
        {
            let mut state = self
                .control
                .publication
                .lock()
                .map_err(|_| resource_error("publication lock is unavailable"))?;
            state.open = false;
            state.current = None;
        }
        // Joining ends all parser TLS storage before any lifetime charge is freed.
        let worker_result = self
            .worker
            .as_mut()
            .map_or(Ok(()), |resources| resources.worker.close());
        self.worker = None;
        self.candidates.clear();
        self.pending_preparation_charge = None;
        self.preparation_charge = None;
        let report = self
            .workspace
            .take()
            .ok_or_else(|| {
                SessionError::new(
                    SessionErrorKind::Closed,
                    "resident storage was already released",
                )
            })?
            .release()
            .map_err(|error| storage_error(&error));
        worker_result?;
        report
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.workspace.is_some() {
            let _ = self.close();
        }
    }
}

fn same_generation(left: Option<&Arc<Generation>>, right: Option<&Arc<Generation>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

fn source_size(view: &SourceView) -> Result<usize, SessionError> {
    view.values().try_fold(0_usize, |sum, bytes| {
        sum.checked_add(bytes.len())
            .ok_or_else(|| resource_error("source byte count overflow"))
    })
}

fn operation_size(operations: &[ChangeOperation]) -> Result<usize, SessionError> {
    operations.iter().try_fold(0_usize, |sum, operation| {
        let bytes = match operation {
            ChangeOperation::Create {
                candidate_bytes, ..
            } => candidate_bytes.len(),
            ChangeOperation::Replace {
                base_bytes,
                candidate_bytes,
                ..
            } => base_bytes
                .len()
                .checked_add(candidate_bytes.len())
                .ok_or_else(|| resource_error("operation byte count overflow"))?,
            ChangeOperation::Delete { base_bytes, .. }
            | ChangeOperation::Move { base_bytes, .. } => base_bytes.len(),
        };
        sum.checked_add(bytes)
            .ok_or_else(|| resource_error("operation byte count overflow"))
    })
}

fn input_descriptors(
    evaluation: &ResidentEvaluation,
) -> Result<(Vec<SessionInputDescriptor>, BTreeSet<String>), SessionError> {
    let layout = ControlLayout::standard();
    let mut descriptors = Vec::with_capacity(evaluation.affected_snapshot.inputs().len());
    let mut authorities = BTreeSet::new();
    for input in evaluation.affected_snapshot.inputs() {
        let role = layout.resolve(input.path()).map_or_else(
            || match classify_authority_path(input.path()) {
                AuthorityInputKind::Source | AuthorityInputKind::RepositoryInput => {
                    SessionInputRole::Source
                }
                _ => SessionInputRole::Authority,
            },
            |entry| match (entry.role(), entry.source_binding()) {
                (ControlRole::Unrecognized, _) => SessionInputRole::Unsupported,
                (_, ControlSourceBinding::Required) => SessionInputRole::Authority,
                (_, ControlSourceBinding::Nonrecursive) => SessionInputRole::Availability,
            },
        );
        if role == SessionInputRole::Authority {
            authorities.insert(input.path().into());
        }
        descriptors.push(
            SessionInputDescriptor::new(input.path(), input.digest(), role).map_err(|error| {
                SessionError::new(SessionErrorKind::Evaluation, error.to_string())
            })?,
        );
    }
    Ok((descriptors, authorities))
}

fn validate_candidate_inventory(
    base: &SourceView,
    candidate: &SourceView,
) -> Result<(), SessionError> {
    let read = |view: &SourceView| -> Result<ProjectConfiguration, SessionError> {
        let bytes = view.bytes(PROJECT_CONFIGURATION_PATH).ok_or_else(|| {
            SessionError::new(
                SessionErrorKind::InvalidInput,
                "candidate requires valid project configuration",
            )
        })?;
        let source = std::str::from_utf8(bytes).map_err(|error| {
            SessionError::new(SessionErrorKind::InvalidInput, error.to_string())
        })?;
        ProjectConfiguration::from_json_str(source)
            .map_err(|error| SessionError::new(SessionErrorKind::InvalidInput, error.to_string()))
    };
    let prior = read(base)?;
    let current = read(candidate)?;
    for excluded in prior.observation_exclusions() {
        if !current.observation_exclusions().iter().any(|selector| {
            excluded == selector
                || excluded
                    .strip_prefix(selector)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            return Err(SessionError::new(
                SessionErrorKind::FullReevaluationRequired,
                "candidate configuration reveals unobserved inputs; a complete source view is required",
            ));
        }
    }
    Ok(())
}

fn validate_candidate_paths(
    base: &SourceView,
    operations: &[ChangeOperation],
) -> Result<(), SessionError> {
    let bytes = base.bytes(PROJECT_CONFIGURATION_PATH).ok_or_else(|| {
        SessionError::new(
            SessionErrorKind::InvalidInput,
            "candidate requires project configuration",
        )
    })?;
    let configuration =
        ProjectConfiguration::from_json_str(std::str::from_utf8(bytes).map_err(|error| {
            SessionError::new(SessionErrorKind::InvalidInput, error.to_string())
        })?)
        .map_err(|error| SessionError::new(SessionErrorKind::InvalidInput, error.to_string()))?;
    let layout = ControlLayout::standard();
    for operation in operations {
        let paths = match operation {
            ChangeOperation::Create { path, .. }
            | ChangeOperation::Replace { path, .. }
            | ChangeOperation::Delete { path, .. } => vec![path.as_str()],
            ChangeOperation::Move {
                source,
                destination,
                ..
            } => vec![source.as_str(), destination.as_str()],
        };
        for path in paths {
            let excluded = path == ".git"
                || path.starts_with(".git/")
                || configuration.observation_exclusions().iter().any(|prefix| {
                    path == prefix
                        || path
                            .strip_prefix(prefix)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                });
            let nonrecursive = layout
                .resolve(path)
                .is_some_and(|entry| entry.source_binding() == ControlSourceBinding::Nonrecursive);
            if excluded || nonrecursive {
                return Err(SessionError::new(
                    SessionErrorKind::FullReevaluationRequired,
                    "candidate operations require observed source/authority preimages; excluded or nonrecursive inputs need their own complete inventory",
                ));
            }
        }
    }
    Ok(())
}

/// Observes closed control-history roles separately from source semantics.
///
/// # Errors
/// Returns an error for uncertain filesystem entries or resource exhaustion.
pub fn observe_session_availability(
    root: &Path,
    max_entries: usize,
) -> Result<BTreeMap<String, String>, SessionError> {
    let mut budget = AvailabilityBudget::new(max_entries)?;
    let layout = ControlLayout::standard();
    let mut result = BTreeMap::new();
    let mut pending = vec![root.join(EVIDENCE_ROOT)];
    let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
    while let Some(path) = pending.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(storage_error(&error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(SessionError::new(
                SessionErrorKind::InvalidInput,
                "linked history inventory is unsupported",
            ));
        }
        if metadata.is_dir() {
            if !layout.allows_directory(&history_relative_path(root, &path)?) {
                return Err(SessionError::new(
                    SessionErrorKind::InvalidInput,
                    "history directory has no registered control role",
                ));
            }
            for entry in fs::read_dir(&path).map_err(|error| storage_error(&error))? {
                let entry = entry.map_err(|error| storage_error(&error))?;
                let parent_bytes = history_relative_path(root, &path)?.len();
                let filename = entry.file_name();
                let filename = filename.to_str().ok_or_else(|| {
                    SessionError::new(SessionErrorKind::InvalidInput, "nonportable history path")
                })?;
                let path_bytes = parent_bytes
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(filename.len()))
                    .ok_or_else(|| resource_error("history availability path charge overflow"))?;
                budget.admit(path_bytes)?;
                pending.push(entry.path());
            }
        } else if metadata.is_file() {
            let relative = history_relative_path(root, &path)?;
            let entry = layout.resolve(&relative).ok_or_else(|| {
                SessionError::new(
                    SessionErrorKind::InvalidInput,
                    "history has no registered control role",
                )
            })?;
            if entry.role() == ControlRole::Unrecognized
                || entry.source_binding() != ControlSourceBinding::Nonrecursive
            {
                return Err(SessionError::new(
                    SessionErrorKind::InvalidInput,
                    "history has an invalid control role",
                ));
            }
            let mut file = File::open(&path).map_err(|error| storage_error(&error))?;
            let mut hasher = Sha256::new();
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| storage_error(&error))?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            result.insert(relative, format!("sha256:{:x}", hasher.finalize()));
        } else {
            return Err(SessionError::new(
                SessionErrorKind::InvalidInput,
                "unsupported history filesystem entry",
            ));
        }
    }
    Ok(result)
}

struct AvailabilityBudget {
    entries: usize,
    path_bytes: usize,
    max_entries: usize,
    max_path_bytes: usize,
}

impl AvailabilityBudget {
    fn new(max_entries: usize) -> Result<Self, SessionError> {
        let max_path_bytes = max_entries
            .checked_mul(512)
            .ok_or_else(|| resource_error("history availability path limit overflow"))?;
        let mut budget = Self {
            entries: 0,
            path_bytes: 0,
            max_entries,
            max_path_bytes,
        };
        budget.admit(EVIDENCE_ROOT.len())?;
        Ok(budget)
    }

    fn admit(&mut self, path_bytes: usize) -> Result<(), SessionError> {
        let entries = self
            .entries
            .checked_add(1)
            .filter(|count| *count <= self.max_entries)
            .ok_or_else(|| resource_error("history availability entry limit reached"))?;
        let total_path_bytes = self
            .path_bytes
            .checked_add(path_bytes)
            .filter(|bytes| *bytes <= self.max_path_bytes)
            .ok_or_else(|| resource_error("history availability path limit reached"))?;
        self.entries = entries;
        self.path_bytes = total_path_bytes;
        Ok(())
    }
}

fn history_relative_path(root: &Path, path: &Path) -> Result<String, SessionError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| SessionError::new(SessionErrorKind::InvalidInput, error.to_string()))?;
    relative
        .to_str()
        .map(|path| path.replace('\\', "/"))
        .ok_or_else(|| {
            SessionError::new(SessionErrorKind::InvalidInput, "nonportable history path")
        })
}
