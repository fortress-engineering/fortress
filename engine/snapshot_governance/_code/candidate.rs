//! Exact hypothetical composition and read-only post-write reconciliation.
//! All source mutation, leases, journals, recovery and receipts remain MIGRATE-owned.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::development_governance::{ApplicationAuthorityRecord, ApplicationAuthorization};
use crate::migration_adapter::CanonicalMigrationEvaluator;
use crate::migration_governance::{
    MigrationAuthority, MigrationError, MigrationEvaluation, MigrationEvaluator,
    MigrationOperation, MigrationValidation, MigrationValidationState, OperationGraph,
};
use crate::observation::{CandidateChangeSet, SourceView};
use crate::session::{Generation, Session, SessionDisposition, SessionOptions};
use crate::state_governance::{
    ComparisonContext, ComparisonState, TransitionAnalysis, compare_states,
};

const MAX_RECORD_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 256 * 1024 * 1024;
const MAX_CANDIDATES: usize = 16;

fn error(code: &str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}
fn convert(e: impl std::fmt::Display) -> MigrationError {
    error("INVALID_INPUT", e.to_string())
}
fn session_error(e: &crate::session::SessionError) -> MigrationError {
    use crate::session::SessionErrorKind as K;
    let code = match e.kind() {
        K::Cancelled => "CANCELLED",
        K::StaleBase => "STALE_BASE",
        K::ResourceLimit => "RESOURCE_LIMIT",
        K::FullReevaluationRequired => "FULL_REEVALUATION_REQUIRED",
        K::Closed => "CLOSED",
        K::InvalidInput => "INVALID_INPUT",
        K::Evaluation => "EVALUATION_FAILED",
        K::Storage => "STORAGE_UNAVAILABLE",
    };
    error(code, e.to_string())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, MigrationError> {
    crate::declaration::canonical(value).map_err(convert)
}
fn digest<T: Serialize>(value: &T) -> Result<String, MigrationError> {
    Ok(format!("sha256:{:x}", Sha256::digest(canonical(value)?)))
}
fn check_cancelled(cancelled: &AtomicBool) -> Result<(), MigrationError> {
    if cancelled.load(Ordering::Acquire) {
        Err(error(
            "CANCELLED",
            "candidate work cancelled; actual state was not published",
        ))
    } else {
        Ok(())
    }
}
fn proposed_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "hypothetical results cannot assert actual_state",
        ));
    }
    Ok(false)
}
fn key(client: &str, candidate: &str) -> Result<(String, String), MigrationError> {
    for id in [client, candidate] {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(error(
                "INVALID_IDENTITY",
                "client and candidate IDs require 1..128 portable identifier bytes",
            ));
        }
    }
    Ok((client.into(), candidate.into()))
}

/// Explicit exact base, evaluation context and bounded operations. This is never permission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    /// Explicit supported request edition; adjacent meanings are never inferred.
    pub schema_version: u16,
    /// Exact physical base inventory, including authority outside source exclusions.
    pub base_source_ref: String,
    /// Original canonical context, obtained from this workspace's base description.
    pub context_ref: String,
    /// Existing MIGRATE operation vocabulary; no separate source writer is introduced.
    pub operations: Vec<MigrationOperation>,
    /// Explicit original comparison inputs and unverified approval citations.
    #[serde(default)]
    pub comparison_context: ComparisonContext,
}

/// Portable, digest-bound proposed assessment. Parsing establishes integrity only.
/// It cannot construct a retained candidate, a grant, an actual certificate or a write capability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypotheticalEvaluation {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    evaluation_ref: String,
    status: String,
    #[serde(deserialize_with = "proposed_only")]
    actual_state: bool,
    base_generation: String,
    base_subject: String,
    candidate_digest: String,
    context_ref: String,
    trusted_base_authority: Option<String>,
    predicted_state_ref: String,
    base_inventory_ref: String,
    predicted_inventory_ref: String,
    operations: Vec<MigrationOperation>,
    comparison_context: ComparisonContext,
    #[serde(with = "crate::state_governance::projection")]
    base_state: ComparisonState,
    #[serde(with = "crate::state_governance::projection")]
    predicted_state: ComparisonState,
    transition: TransitionAnalysis,
    change_decision: Option<ApplicationAuthorityRecord>,
    authorization_error: Option<MigrationError>,
    finding_lifecycle: serde_json::Value,
    affected_analysis: Option<crate::affected_analysis::AffectedAnalysis>,
    #[serde(with = "crate::state_governance::projection::sequence")]
    historical_states: Vec<ComparisonState>,
    validation_facts:
        BTreeMap<MigrationValidation, crate::migration_governance::MigrationValidationFact>,
    evaluation_mode: String,
    fallback_reasons: Vec<String>,
    materialization_dependencies: Vec<MaterializationDependency>,
    limitations: Vec<String>,
}

/// Exact retained-input requirement, without treating a reference as available evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationDependency {
    /// Existing source or authority role whose complete bytes must be supplied.
    pub role: String,
    /// Exact immutable identity; an absent independently executed result has no invented ref.
    pub content_ref: Option<String>,
    /// Whether this proposal embeds all required bytes for that input.
    pub included: bool,
    /// Which conclusion requires this materialization, and what remains unverified.
    pub requirement: String,
}
impl HypotheticalEvaluation {
    /// Deterministic assessment identity, independent of client, cache and timing.
    #[must_use]
    pub fn evaluation_ref(&self) -> &str {
        &self.evaluation_ref
    }
    /// Exact operation/base/context/target-authority identity used by AUTHORITY.
    #[must_use]
    pub fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
    /// Original four-axis comparison; no verdict-only causality is added.
    #[must_use]
    pub const fn transition(&self) -> &TransitionAnalysis {
        &self.transition
    }
    /// Original endpoint and uncertainty, never current certification.
    #[must_use]
    pub const fn predicted_state(&self) -> &ComparisonState {
        &self.predicted_state
    }
    /// Whether qualified reuse or conservative full reconstruction ran.
    #[must_use]
    pub fn evaluation_mode(&self) -> &str {
        &self.evaluation_mode
    }
    fn identity(&self) -> Result<String, MigrationError> {
        let mut value = serde_json::to_value(self).map_err(convert)?;
        for k in ["evaluation_ref", "evaluation_mode", "fallback_reasons"] {
            value.as_object_mut().expect("record").remove(k);
        }
        digest(&value)
    }
    fn validate(&self) -> Result<(), MigrationError> {
        if self.schema != "urn:fortress:derived:v1:hypothetical-evaluation"
            || self.schema_version != 1
            || self.status != "PROPOSED"
            || self.actual_state
        {
            return Err(error(
                "UNSUPPORTED_VERSION",
                "only proposed hypothetical v1 records are admitted; actual-state assertions are forbidden",
            ));
        }
        if ![
            "SELECTIVE_REBUILD",
            "INPUT_UNCHANGED",
            "FULL_REEVALUATION_REQUIRED",
        ]
        .contains(&self.evaluation_mode.as_str())
        {
            return Err(error(
                "INVALID_RESULT",
                "unknown operational evaluation mode",
            ));
        }
        self.validate_materialization()?;
        for r in [
            &self.evaluation_ref,
            &self.base_generation,
            &self.base_subject,
            &self.candidate_digest,
            &self.context_ref,
            &self.predicted_state_ref,
            &self.base_inventory_ref,
            &self.predicted_inventory_ref,
        ] {
            if !crate::declaration::is_digest(r) {
                return Err(error("INVALID_IDENTITY", r));
            }
        }
        self.base_state.validate().map_err(convert)?;
        self.predicted_state.validate().map_err(convert)?;
        self.validate_original_states()?;
        let transition = compare_states(
            &self.base_state,
            &self.predicted_state,
            &self.comparison_context,
        )
        .map_err(convert)?;
        if self.identity()? != self.evaluation_ref
            || self.base_state.digest().map_err(convert)? != self.base_generation
            || self.predicted_state.digest().map_err(convert)? != self.predicted_state_ref
            || transition.digest().map_err(convert)? != self.transition.digest().map_err(convert)?
            || self.base_state.governing_identity().map_err(convert)? != self.trusted_base_authority
            || self.base_state.source_ref.as_deref() != Some(&self.base_subject)
        {
            return Err(error(
                "TAMPERED_CANDIDATE",
                "candidate content, original authority or comparison binding differs",
            ));
        }
        if let Some(decision) = &self.change_decision {
            decision.digest().map_err(convert)?;
            if decision.change_set_ref != self.candidate_digest
                || decision.base_state_ref != self.base_generation
                || decision.candidate_state_ref != self.predicted_state_ref
                || decision.transition_ref != self.transition.digest().map_err(convert)?
                || self.authorization_error.is_some()
            {
                return Err(error(
                    "INVALID_BINDING",
                    "authorization preview is not exact candidate provenance",
                ));
            }
        } else if self.authorization_error.is_none() {
            return Err(error(
                "INVALID_BINDING",
                "missing authorization knowledge must remain explicit",
            ));
        }
        Ok(())
    }
    fn validate_materialization(&self) -> Result<(), MigrationError> {
        if self.materialization_dependencies.len() != 3
            || self.materialization_dependencies.iter().any(|d| d.included)
            || self.materialization_dependencies[0].role != "COMPLETE_BASE_PHYSICAL_SOURCE"
            || self.materialization_dependencies[0].content_ref.as_deref()
                != Some(&self.base_inventory_ref)
            || self.materialization_dependencies[1].role != "ORIGINAL_SEMANTIC_AUTHORITY"
            || self.materialization_dependencies[1].content_ref != self.trusted_base_authority
            || self.materialization_dependencies[2].role != "INDEPENDENT_ACTUAL_EXECUTION"
            || self.materialization_dependencies[2].content_ref.is_some()
        {
            return Err(error(
                "INVALID_BINDING",
                "proposal must explicitly retain its unmaterialized base, original authority and absent actual execution requirements",
            ));
        }
        Ok(())
    }
    fn validate_original_states(&self) -> Result<(), MigrationError> {
        if self.historical_states.len() > 16 {
            return Err(error(
                "RESOURCE_LIMIT",
                "too many historical original states",
            ));
        }
        let mut original_ids = std::collections::BTreeSet::new();
        let mut original_bytes = 0usize;
        for state in &self.historical_states {
            original_bytes =
                original_bytes.saturating_add(state.to_canonical_bytes().map_err(convert)?.len());
            if !original_ids.insert(state.digest().map_err(convert)?) {
                return Err(error(
                    "AMBIGUOUS_IDENTITY",
                    "duplicate historical original state",
                ));
            }
        }
        if original_bytes > 64 * 1024 * 1024 {
            return Err(error(
                "RESOURCE_LIMIT",
                "historical originals exceed admission",
            ));
        }
        Ok(())
    }
    /// Strict public reader. Unsigned records remain unauthenticated proposals.
    /// # Errors
    /// Rejects duplicate keys, malformed versions, altered identities and oversized records.
    pub fn from_json_str(text: &str) -> Result<Self, MigrationError> {
        if text.len() > MAX_RECORD_BYTES {
            return Err(error(
                "RESOURCE_LIMIT",
                "candidate record exceeds admission",
            ));
        }
        let value: Self = crate::wire::parse_public_json(text).map_err(convert)?;
        value.validate()?;
        Ok(value)
    }
    /// Canonical JCS projection. This is deliberately not a certification schema.
    /// # Errors
    /// Rejects inconsistent bindings and excessive output.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate()?;
        let bytes = canonical(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(error(
                "RESOURCE_LIMIT",
                "candidate projection exceeds admission",
            ));
        }
        Ok(bytes)
    }
    /// Renders every underlying machine field without additional analysis.
    /// # Panics
    /// Panics only if the fixed producer-owned records cannot be serialized.
    #[must_use]
    pub fn to_human(&self) -> String {
        crate::query::render_inspection_value(
            &serde_json::to_value(self).expect("serializable candidate"),
        )
    }
    /// Explicitly retains exact reviewed proposal bytes through the registered CONTROL role
    /// and the common existing immutable-record writer. Never changes active authority.
    /// # Errors
    /// Refuses unsafe paths, conflicting existing bytes, invalid records and missing roles.
    pub fn export_proposal(&self, root: &Path) -> Result<String, MigrationError> {
        let bytes = self.to_canonical_bytes()?;
        // The retained record address includes operational provenance; semantic candidate
        // identity remains independent of cache availability and client identifiers.
        let record_ref = format!("sha256:{:x}", Sha256::digest(&bytes));
        let path = crate::control_layout::ControlLayout::standard()
            .hypothetical_proposal_path(&record_ref)
            .ok_or_else(|| error("UNAVAILABLE_ROLE", "hypothetical proposal role unavailable"))?;
        crate::migration_governance::export_proposal_record(root, path, &bytes)
    }
}

type CandidateTarget = (
    MigrationEvaluation,
    Option<crate::audit::CandidateOwnerFacts>,
    Option<Arc<Generation>>,
    &'static str,
    Vec<String>,
);

struct RetainedCandidate {
    assessment: HypotheticalEvaluation,
    base: MigrationEvaluation,
    target: MigrationEvaluation,
    changes: CandidateChangeSet,
    _generation: Option<Arc<Generation>>,
    bytes: usize,
}

/// A bounded, physical-repository-bound owner of isolated client buffers.
/// It never changes files, publishes actual evidence, or implements a transaction engine.
pub struct CandidateWorkspace {
    root: PathBuf,
    physical_base: SourceView,
    base: MigrationEvaluation,
    base_owner_facts: Option<crate::audit::CandidateOwnerFacts>,
    directory: crate::heavy_admission::DirectoryIdentity,
    session: Option<Session>,
    context_ref: String,
    candidates: BTreeMap<(String, String), RetainedCandidate>,
    historical_states: BTreeMap<String, ComparisonState>,
}
impl CandidateWorkspace {
    /// Captures complete physical inputs before any proposed exclusions are interpreted.
    /// # Errors
    /// Refuses unstable/unsafe inventories, incomplete migration, storage/resource limits and invalid authority.
    pub fn open(
        root: &Path,
        storage: &Path,
        options: SessionOptions,
    ) -> Result<Self, MigrationError> {
        Self::open_internal(root, Some((storage, options)))
    }
    /// Opens a read-only full-evaluation workspace without resident storage or reuse.
    /// # Errors
    /// Refuses unsafe, incomplete or changing physical inputs.
    pub fn open_cold(root: &Path) -> Result<Self, MigrationError> {
        Self::open_internal(root, None)
    }
    fn open_internal(
        root: &Path,
        resident: Option<(&Path, SessionOptions)>,
    ) -> Result<Self, MigrationError> {
        let root = root.canonicalize().map_err(convert)?;
        crate::heavy_admission::assert_no_incomplete_migration(&root).map_err(convert)?;
        let directory =
            crate::heavy_admission::DirectoryIdentity::capture(&root).map_err(convert)?;
        let physical_base = crate::audit::observe_candidate_source(&root).map_err(convert)?;
        let (base, base_owner_facts) =
            crate::audit::evaluate_candidate_source(&physical_base, None).map_err(convert)?;
        let session = if let Some((storage, options)) = resident.filter(|_| {
            base.state
                .view
                .as_ref()
                .is_some_and(|s| s.application.is_some())
        }) {
            Some(Session::open(&root, storage, options).map_err(|e| session_error(&e))?)
        } else {
            None
        };
        let context_ref = base
            .state
            .view
            .as_ref()
            .and_then(|v| v.application.as_ref())
            .map(|a| a.declaration.binding.context_ref.clone())
            .unwrap_or(digest(&(
                "UNGOVERNED_CONTEXT",
                base.state.governing_identity().map_err(convert)?,
            ))?);
        if crate::audit::observe_candidate_source(&root).map_err(convert)? != physical_base {
            return Err(error(
                "STALE_BASE",
                "physical base changed while opening candidate workspace",
            ));
        }
        crate::heavy_admission::assert_no_incomplete_migration(&root).map_err(convert)?;
        if !directory.matches(&root).map_err(convert)? {
            return Err(error(
                "SOURCE_DRIFT",
                "physical repository changed while opening candidate workspace",
            ));
        }
        Ok(Self {
            root,
            physical_base,
            base,
            base_owner_facts,
            directory,
            session,
            context_ref,
            candidates: BTreeMap::new(),
            historical_states: BTreeMap::new(),
        })
    }
    /// Attaches exact immutable historical original states before retaining candidates.
    /// No historical finding, authority, provenance or verdict is reinterpreted or rewritten.
    /// # Errors
    /// Refuses duplicate/ambiguous identities, malformed states and aggregate resource exhaustion.
    pub fn with_original_states(
        mut self,
        states: Vec<ComparisonState>,
    ) -> Result<Self, MigrationError> {
        if !self.historical_states.is_empty() || !self.candidates.is_empty() || states.len() > 16 {
            return Err(error(
                "RESOURCE_LIMIT",
                "attach at most sixteen original states once, before candidate evaluation",
            ));
        }
        let mut bytes = 0usize;
        for state in states {
            bytes = bytes
                .checked_add(state.to_canonical_bytes().map_err(convert)?.len())
                .filter(|n| *n <= 64 * 1024 * 1024)
                .ok_or_else(|| {
                    error(
                        "RESOURCE_LIMIT",
                        "original historical state bytes exceed admission",
                    )
                })?;
            let id = state.digest().map_err(convert)?;
            if self.historical_states.insert(id, state).is_some() {
                return Err(error(
                    "AMBIGUOUS_IDENTITY",
                    "duplicate original state identity",
                ));
            }
        }
        Ok(self)
    }
    fn observe(&self) -> Result<SourceView, MigrationError> {
        crate::heavy_admission::assert_no_incomplete_migration(&self.root).map_err(convert)?;
        if !self.directory.matches(&self.root).map_err(convert)? {
            return Err(error(
                "SOURCE_DRIFT",
                "physical repository identity changed",
            ));
        }
        let source = crate::audit::observe_candidate_source(&self.root).map_err(convert)?;
        crate::heavy_admission::assert_no_incomplete_migration(&self.root).map_err(convert)?;
        if !self.directory.matches(&self.root).map_err(convert)? {
            return Err(error(
                "SOURCE_DRIFT",
                "physical repository identity changed during observation",
            ));
        }
        Ok(source)
    }
    fn finding_lifecycle(
        &self,
        target: &MigrationEvaluation,
        facts: Option<&crate::audit::CandidateOwnerFacts>,
        context: &ComparisonContext,
    ) -> Result<serde_json::Value, MigrationError> {
        let path = crate::control_layout::ControlLayout::standard()
            .role_path(crate::control_layout::ControlRole::FindingGovernance)
            .ok_or_else(|| error("UNAVAILABLE_ROLE", "finding governance role missing"))?
            .to_owned();
        let authority = match self.physical_base.bytes(&path) {
            Some(bytes) => crate::finding_governance::FindingGovernanceDocument::from_json_str(
                std::str::from_utf8(bytes).map_err(convert)?,
            )
            .map_err(convert)?,
            None => crate::finding_governance::FindingGovernanceDocument::empty_current(),
        };
        let baseline = self.baseline_retirements(target, &authority, context);
        let originals = self.base_owner_facts.as_ref().map(|f| {
            crate::state_governance::assess_original_findings(
                &self.base.state,
                &target.state,
                &f.findings,
                &authority,
                context,
            )
        });
        let mut errors = Vec::new();
        let baseline = match baseline {
            Ok(v) => v,
            Err(e) => {
                errors.push(error(&e.code, e.message));
                vec![]
            }
        };
        let originals = match originals {
            Some(Ok(v)) => v,
            Some(Err(e)) => {
                errors.push(error(&e.code, e.message));
                vec![]
            }
            None => vec![],
        };
        Ok(
            serde_json::json!({"base_raw_findings":self.base_owner_facts.as_ref().map(|f| &f.findings),"predicted_raw_findings":facts.map(|f| &f.findings),"base_governance":self.base_owner_facts.as_ref().map(|f| &f.governance),"predicted_governance":facts.map(|f| &f.governance),"original_finding_resolution":originals,"baseline_retirement_evidence":baseline,"errors":errors,"interpretation":"Existing Finding Model lifecycle and disposition are separate from transition introduction/removal. Only existing State Governance comparable proof may establish RESOLVED; no record changes a baseline or grants permission."}),
        )
    }
    fn baseline_retirements(
        &self,
        target: &MigrationEvaluation,
        authority: &crate::finding_governance::FindingGovernanceDocument,
        context: &ComparisonContext,
    ) -> Result<
        Vec<crate::finding_governance::RetirementEvidenceV2>,
        crate::state_governance::TransitionError,
    > {
        let mut records = crate::state_governance::assess_retirements(
            &self.base.state,
            &target.state,
            authority,
            context,
        )?;
        let mut cache =
            BTreeMap::<String, Vec<crate::finding_governance::RetirementEvidenceV2>>::new();
        for record in &mut records {
            if let Some(anchor) = authority
                .lifecycle()
                .and_then(|g| g.anchors.get(&record.finding_id))
                && let Some(original) = self.historical_states.get(&anchor.from_state)
            {
                if !cache.contains_key(&anchor.from_state) {
                    // Current-base counterfactual cells are not historical evidence:
                    // even governance-only changes alter their governing identity.
                    // Reuse only the original owner's exact unchanged-subject cell.
                    let mut historical_context = ComparisonContext {
                        counterfactuals: vec![],
                        ..context.clone()
                    };
                    crate::migration_governance::reuse_original_cell(
                        original,
                        &target.state,
                        &mut historical_context,
                    )
                    .map_err(|e| crate::state_governance::TransitionError {
                        code: e.code,
                        message: e.message,
                    })?;
                    cache.insert(
                        anchor.from_state.clone(),
                        crate::state_governance::assess_retirements(
                            original,
                            &target.state,
                            authority,
                            &historical_context,
                        )?,
                    );
                }
                if let Some(exact) = cache[&anchor.from_state]
                    .iter()
                    .find(|r| r.finding_id == record.finding_id)
                {
                    *record = exact.clone();
                }
            }
        }
        Ok(records)
    }
    /// Exact physical source/inventory identity clients must submit unchanged.
    #[must_use]
    pub fn base_source_ref(&self) -> &str {
        self.physical_base.digest()
    }
    /// Exact original analysis context, never selected from a candidate grant claim.
    #[must_use]
    pub fn context_ref(&self) -> &str {
        &self.context_ref
    }
    /// Existing original canonical endpoint for explicit trusted policy selection.
    #[must_use]
    pub const fn base_state(&self) -> &ComparisonState {
        &self.base.state
    }
    /// Existing SESSION cancellation boundary; available to an independent host thread.
    #[must_use]
    pub fn session_control(&self) -> Option<crate::session::SessionControl> {
        self.session.as_ref().map(Session::control)
    }
    /// Attaches the existing resident progress port; callbacks cannot change semantic input.
    /// # Errors
    /// Reports unavailable residency; cold evaluation remains supported independently.
    pub fn set_progress_observer(
        &mut self,
        observer: impl Fn(crate::session::SessionStage) + Send + Sync + 'static,
    ) -> Result<(), MigrationError> {
        self.session
            .as_mut()
            .ok_or_else(|| {
                error(
                    "RESIDENT_UNAVAILABLE",
                    "cold evaluation has no resident progress port",
                )
            })?
            .set_progress_observer(observer);
        Ok(())
    }
    /// Evaluates exact immutable edits. No approval, write or current-state publication occurs.
    /// # Errors
    /// Refuses stale base/context, duplicate buffers, conflicts, cancellation and exhausted admission.
    pub fn evaluate(
        &mut self,
        client: &str,
        candidate: &str,
        request: CandidateRequest,
        authority: &impl MigrationAuthority,
        cancelled: &AtomicBool,
    ) -> Result<HypotheticalEvaluation, MigrationError> {
        check_cancelled(cancelled)?;
        if request.schema_version != 1 {
            return Err(error(
                "UNSUPPORTED_VERSION",
                "only candidate request v1 is supported",
            ));
        }
        let key = key(client, candidate)?;
        if self.candidates.contains_key(&key) {
            return Err(error(
                "CANDIDATE_EXISTS",
                "release the existing client buffer before replacing it",
            ));
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err(error(
                "RESOURCE_LIMIT",
                "candidate count admission exhausted",
            ));
        }
        if request.base_source_ref != self.physical_base.digest()
            || request.context_ref != self.context_ref
            || self.observe()? != self.physical_base
        {
            return Err(error(
                "STALE_BASE",
                "complete physical base or original context changed",
            ));
        }
        let graph = OperationGraph::compile(
            &self.physical_base,
            request.operations,
            &self.base.ownership,
        )?;
        check_cancelled(cancelled)?;
        let (target, owner_facts, generation, mode, reasons) =
            self.evaluate_target(graph.target())?;
        let mut context = request.comparison_context;
        crate::migration_governance::reuse_original_cell(
            &self.base.state,
            &target.state,
            &mut context,
        )?;
        let transition =
            compare_states(&self.base.state, &target.state, &context).map_err(convert)?;
        let changes = CandidateChangeSet::new_simultaneous(
            &self.physical_base,
            &transition.comparison_context,
            crate::development_governance::application_target_authority_ref(&target.state)
                .map_err(convert)?,
            graph.operations().iter().map(MigrationOperation::neutral),
        )
        .map_err(convert)?;
        let (change_decision, authorization_error) =
            match authority.preview(&self.base, &target, &self.physical_base, &changes, &context) {
                Ok(d) => (Some(d), None),
                Err(e) => (None, Some(e)),
            };
        let finding_lifecycle = self.finding_lifecycle(&target, owner_facts.as_ref(), &context)?;
        let affected_analysis = self.affected_analysis(owner_facts.as_ref());
        let mut assessment = HypotheticalEvaluation {
            schema: "urn:fortress:derived:v1:hypothetical-evaluation".into(), schema_version: 1, evaluation_ref: String::new(), status: "PROPOSED".into(), actual_state: false,
            base_generation: self.base.state.digest().map_err(convert)?, base_subject: self.base.state.source_ref.clone().ok_or_else(|| error("INCOMPLETE_BASE", "canonical base has no subject"))?, candidate_digest: changes.digest().into(), context_ref: self.context_ref.clone(), trusted_base_authority: self.base.state.governing_identity().map_err(convert)?, predicted_state_ref: target.state.digest().map_err(convert)?, base_inventory_ref: self.physical_base.digest().into(), predicted_inventory_ref: graph.target().digest().into(), operations: graph.operations().to_vec(), comparison_context: context, base_state: self.base.state.clone(), predicted_state: target.state.clone(), transition, change_decision, authorization_error, finding_lifecycle, affected_analysis, historical_states: self.historical_states.values().cloned().collect(), validation_facts: target.validations.clone(), evaluation_mode: mode.into(), fallback_reasons: reasons,
            materialization_dependencies: vec![MaterializationDependency { role: "COMPLETE_BASE_PHYSICAL_SOURCE".into(), content_ref: Some(self.physical_base.digest().into()), included: false, requirement: "Independent candidate materialization requires the complete immutable base SourceView, including excluded ordinary inputs and authority. Operations embed exact changed preimages/postimages; unchanged source bytes are not copied into this proposal.".into() }, MaterializationDependency { role: "ORIGINAL_SEMANTIC_AUTHORITY".into(), content_ref: self.base.state.governing_identity().map_err(convert)?, included: false, requirement: "Independent semantic replay requires the original registered Standard/profile/producer authority. Embedded comparison facts preserve conclusions and provenance without authenticating or reimplementing that evaluator.".into() }, MaterializationDependency { role: "INDEPENDENT_ACTUAL_EXECUTION".into(), content_ref: None, included: false, requirement: "Actual-state certification requires independently established current execution on the reobserved physical result; a hypothetical proposal contains none.".into() }],
            limitations: vec!["PROPOSED only: static hypothetical results cannot satisfy actual-source certification, authenticate a producer, prove runtime execution or authorize writing.".into(), "Missing/unsupported coverage and original-authority comparisons retain the existing owner outcomes. Historical findings and exceptions are not rewritten.".into(), "MIGRATE or an independently authorized host exclusively owns writes, concurrency mediation, recovery and receipts. Reconciliation is read-only and is not a filesystem-wide atomic guarantee.".into()],
        };
        assessment.evaluation_ref = assessment.identity()?;
        let bytes = assessment.to_canonical_bytes()?.len();
        if bytes.saturating_add(self.candidates.values().map(|c| c.bytes).sum())
            > MAX_RETAINED_BYTES
        {
            return Err(error(
                "RESOURCE_LIMIT",
                "retained candidate record admission exhausted",
            ));
        }
        check_cancelled(cancelled)?;
        if self.observe()? != self.physical_base {
            return Err(error(
                "STALE_BASE",
                "base changed before isolated candidate retention",
            ));
        }
        check_cancelled(cancelled)?;
        self.candidates.insert(
            key,
            RetainedCandidate {
                assessment: assessment.clone(),
                base: self.base.clone(),
                target,
                changes,
                _generation: generation,
                bytes,
            },
        );
        Ok(assessment)
    }
    fn affected_analysis(
        &self,
        target: Option<&crate::audit::CandidateOwnerFacts>,
    ) -> Option<crate::affected_analysis::AffectedAnalysis> {
        self.base_owner_facts
            .as_ref()
            .zip(target)
            .map(|(base, target)| {
                crate::affected_analysis::analyze_affected(
                    &base.affected_snapshot,
                    &target.affected_snapshot,
                )
            })
    }
    fn evaluate_target(&mut self, target: &SourceView) -> Result<CandidateTarget, MigrationError> {
        Ok(if target == &self.physical_base {
            (
                self.base.clone(),
                self.base_owner_facts.clone(),
                None,
                "INPUT_UNCHANGED",
                vec![],
            )
        } else if let Some(session) = &mut self.session {
            let base = session
                .acquire_generation()
                .map_err(|e| session_error(&e))?;
            let update = session
                .evaluate_overlay_view(base.input_revision(), target.clone())
                .map_err(|e| session_error(&e))?;
            let (endpoint, owner_facts) = update
                .generation
                .candidate_endpoint(target)
                .map_err(convert)?;
            let mode = match update.disposition {
                SessionDisposition::InputUnchanged => "INPUT_UNCHANGED",
                SessionDisposition::SelectiveRebuild => "SELECTIVE_REBUILD",
                SessionDisposition::FullReevaluationRequired => "FULL_REEVALUATION_REQUIRED",
            };
            (
                endpoint,
                owner_facts,
                Some(update.generation),
                mode,
                update.reasons,
            )
        } else {
            {
                let (endpoint, facts) =
                    crate::audit::evaluate_candidate_source(target, None).map_err(convert)?;
                (endpoint, facts, None, "FULL_REEVALUATION_REQUIRED", vec!["No qualified resident generation; complete canonical immutable evaluation performed.".into()])
            }
        })
    }

    /// Releases only this client's isolated buffer; the actual coordinator head is unchanged.
    pub fn release(&mut self, client: &str, candidate: &str) {
        self.candidates.remove(&(client.into(), candidate.into()));
    }
    /// Rechecks the complete physical base and obtains existing non-transferable AUTHORITY proof.
    /// This performs no mutation; a host must still enforce its own atomic write boundary.
    /// # Errors
    /// Refuses stale state, missing or changed governing requirements and absent external grants.
    pub fn authorize_before_write(
        &self,
        client: &str,
        candidate: &str,
        authority: &impl MigrationAuthority,
        cancelled: &AtomicBool,
    ) -> Result<CandidateWritePermit, MigrationError> {
        check_cancelled(cancelled)?;
        let retained = self.retained(client, candidate)?;
        if self.observe()? != self.physical_base
            || CanonicalMigrationEvaluator
                .evaluate(&self.physical_base)?
                .state
                .digest()
                .map_err(convert)?
                != retained.assessment.base_generation
        {
            return Err(error(
                "STALE_BASE",
                "candidate base or original evaluation context changed",
            ));
        }
        let permission = self.authorize(retained, authority)?;
        check_cancelled(cancelled)?;
        if self.observe()? != self.physical_base {
            return Err(error(
                "STALE_BASE",
                "base changed while obtaining authorization",
            ));
        }
        Ok(CandidateWritePermit {
            candidate_ref: retained.assessment.evaluation_ref.clone(),
            permission,
        })
    }
    fn retained(
        &self,
        client: &str,
        candidate: &str,
    ) -> Result<&RetainedCandidate, MigrationError> {
        self.candidates
            .get(&key(client, candidate)?)
            .ok_or_else(|| error("NOT_FOUND", "candidate is not retained for this client"))
    }
    fn authorize(
        &self,
        retained: &RetainedCandidate,
        authority: &impl MigrationAuthority,
    ) -> Result<ApplicationAuthorization, MigrationError> {
        let predicted = retained
            .assessment
            .change_decision
            .as_ref()
            .ok_or_else(|| {
                error(
                    "REASSESSMENT_REQUIRED",
                    "candidate lacks an exact governing requirement preview",
                )
            })?;
        let permission = authority.authorize(
            &retained.base,
            &retained.target,
            &self.physical_base,
            &retained.changes,
            &retained.assessment.comparison_context,
        )?;
        if permission
            .record()
            .requirement_contract_ref()
            .map_err(convert)?
            != predicted.requirement_contract_ref().map_err(convert)?
        {
            return Err(error(
                "AUTHORITY_BINDING_MISMATCH",
                "actual authorization does not bind the original candidate requirements",
            ));
        }
        Ok(permission)
    }
}

/// Process-local proof that original physical inputs and existing external authorization
/// were checked before writing. No JSON record can construct it. It is not a writer lease.
pub struct CandidateWritePermit {
    candidate_ref: String,
    permission: ApplicationAuthorization,
}

/// Trusted host/EVIDENCE execution port, independent of candidate files and CLI JSON.
/// Implementations must establish real canonical execution on this exact independently
/// reobserved subject, including freshness and the actual eligible inventory. A serialized
/// assertion, predicted suite result, old certificate or matching digest alone is insufficient.
/// This port does not authenticate providers or create another execution engine.
pub trait ActualExecutionEvidence {
    /// Supplies independently established execution, or `None` when unavailable.
    /// # Errors
    /// Reports invalid, stale, unsupported or unavailable execution without favorability.
    fn current_execution(
        &self,
        root: &Path,
        subject: &str,
    ) -> Result<Option<crate::certification::RustSuiteExecution>, MigrationError>;
}
/// Read-only clients never fabricate execution from static predictions.
pub struct NoActualExecution;
impl ActualExecutionEvidence for NoActualExecution {
    fn current_execution(
        &self,
        _: &Path,
        _: &str,
    ) -> Result<Option<crate::certification::RustSuiteExecution>, MigrationError> {
        Ok(None)
    }
}

/// Read-only reconciliation outcome, never a migration receipt or publication instruction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReconciliation {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    reconciliation_ref: String,
    candidate_ref: String,
    predicted_inventory_ref: String,
    observed_inventory_ref: String,
    predicted_state_ref: String,
    observed_state_ref: Option<String>,
    status: String,
    actual_state: bool,
    certification_ref: Option<String>,
    reasons: Vec<String>,
    limitations: Vec<String>,
}
impl CandidateReconciliation {
    /// Exact agreement and complete independent actual verification are both required.
    #[must_use]
    pub const fn actual_state(&self) -> bool {
        self.actual_state
    }
    /// Reconciliation is independent from permission, execution and provider authenticity.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
    /// Canonical deterministic projection; cannot restore the process-local permit.
    /// # Errors
    /// Rejects serialization failures.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        canonical(self)
    }
}

/// Reobserves a retained proposal without reconstructing missing historical state or grants.
/// This inspection can establish exact static agreement only, never verified actual execution.
/// # Errors
/// Refuses malformed proposals, unsafe/in-progress repositories, drift and cancelled work.
pub fn inspect_post_write(
    root: &Path,
    proposal: &HypotheticalEvaluation,
    cancelled: &AtomicBool,
) -> Result<CandidateReconciliation, MigrationError> {
    proposal.validate()?;
    check_cancelled(cancelled)?;
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(convert)?;
    let source = crate::audit::observe_candidate_source(root).map_err(convert)?;
    let mut result = CandidateReconciliation { schema: "urn:fortress:derived:v1:candidate-reconciliation".into(), schema_version: 1, reconciliation_ref: String::new(), candidate_ref: proposal.evaluation_ref.clone(), predicted_inventory_ref: proposal.predicted_inventory_ref.clone(), observed_inventory_ref: source.digest().into(), predicted_state_ref: proposal.predicted_state_ref.clone(), observed_state_ref: None, status: "DIVERGED".into(), actual_state: false, certification_ref: None, reasons: vec![], limitations: vec!["Unsigned retained proposals are unauthenticated provenance. This read-only inspection restores neither the original-state write permit nor independently established execution evidence, and never publishes actual certification.".into()] };
    if source.digest() == proposal.predicted_inventory_ref {
        let actual = CanonicalMigrationEvaluator.evaluate(&source)?;
        let actual_ref = actual.state.digest().map_err(convert)?;
        if actual_ref == proposal.predicted_state_ref
            && canonical(&actual.validations)? == canonical(&proposal.validation_facts)?
        {
            result.status = "EXACT_MATCH_UNVERIFIED".into();
            result.reasons.push("Exact physical inventory, canonical context/authority and static results agree; independent current execution and original-state authorization remain unverified.".into());
        } else {
            result.reasons.push(
                "Canonical context/authority or outcomes differ; reassessment required.".into(),
            );
        }
        result.observed_state_ref = Some(actual_ref);
    } else {
        result.reasons.push("Actual physical inventory differs; prediction invalidated, including independent modifications or partial writes.".into());
    }
    check_cancelled(cancelled)?;
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(convert)?;
    if crate::audit::observe_candidate_source(root).map_err(convert)? != source {
        return Err(error(
            "SOURCE_DRIFT",
            "physical state changed during inspection",
        ));
    }
    result.reconciliation_ref = digest(&result)?;
    Ok(result)
}
impl CandidateWorkspace {
    /// Independently reobserves physical bytes, full canonical endpoint and execution after
    /// an authorized external writer has finished. It never repairs or publishes state.
    /// Missing evidence remains unverified; diverged input invalidates the prediction.
    /// # Errors
    /// Refuses incomplete MIGRATE application, unsafe observation, cancellation and resource failures.
    pub fn reconcile(
        &self,
        client: &str,
        candidate: &str,
        permit: Option<&CandidateWritePermit>,
        authority: &impl MigrationAuthority,
        execution: &impl ActualExecutionEvidence,
        cancelled: &AtomicBool,
    ) -> Result<CandidateReconciliation, MigrationError> {
        check_cancelled(cancelled)?;
        let retained = self.retained(client, candidate)?;
        let observed = self.observe()?;
        let mut result = CandidateReconciliation {
            schema: "urn:fortress:derived:v1:candidate-reconciliation".into(), schema_version: 1, reconciliation_ref: String::new(), candidate_ref: retained.assessment.evaluation_ref.clone(), predicted_inventory_ref: retained.changes.view().digest().into(), observed_inventory_ref: observed.digest().into(), predicted_state_ref: retained.assessment.predicted_state_ref.clone(), observed_state_ref: None, status: "DIVERGED".into(), actual_state: false, certification_ref: None, reasons: vec![],
            limitations: vec!["Read-only source-bound observation, not a write receipt, provider authentication or enduring freshness claim. A subsequent edit invalidates this observation.".into(), "Actual certification remains owned by Certification; publication and transaction completion remain owned by their existing boundaries.".into()],
        };
        if observed == *retained.changes.view() {
            let actual = CanonicalMigrationEvaluator.evaluate(&observed)?;
            let state_ref = actual.state.digest().map_err(convert)?;
            result.observed_state_ref = Some(state_ref.clone());
            if state_ref != result.predicted_state_ref
                || canonical(&actual.validations)? != canonical(&retained.target.validations)?
            {
                result.reasons.push("Physical bytes agree but canonical context/authority/results differ; prediction invalidated.".into());
            } else {
                result.status = "EXACT_MATCH_UNVERIFIED".into();
                let permission = permit.filter(|p| p.candidate_ref == result.candidate_ref);
                let authorized = permission.map(|p| {
                    self.authorize(retained, authority).and_then(|now| {
                        if now.record().requirement_contract_ref().map_err(convert)?
                            != p.permission
                                .record()
                                .requirement_contract_ref()
                                .map_err(convert)?
                        {
                            return Err(error(
                                "AUTHORITY_BINDING_MISMATCH",
                                "post-write permission differs from original-state requirements",
                            ));
                        }
                        Ok(())
                    })
                });
                match authorized {
                    Some(Ok(())) => {
                        if let Some(suite) = execution.current_execution(&self.root, actual.state.source_ref.as_deref().ok_or_else(|| error("INCOMPLETE_EVIDENCE", "actual subject missing"))?)? {
                            suite.validate().map_err(convert)?;
                            if !suite.canonical_unfiltered || !suite.passed || Some(suite.certification_source_digest.as_str()) != actual.state.source_ref.as_deref() {
                                result.reasons.push("Execution is failed, filtered, or bound to a different actual source.".into());
                            } else {
                                let products = crate::audit::compile_repository_certification(&self.root, suite).map_err(convert)?;
                                products.evidence_graph.validate().map_err(convert)?;
                                if products.certification.status() == crate::certification::CertificationStatus::Pass && products.evidence_graph.subject() == actual.state.source_ref.as_deref().unwrap_or("") && actual.validations.values().all(|v| matches!(v.state, MigrationValidationState::Satisfied | MigrationValidationState::NotApplicable)) {
                                    result.status = "VERIFIED_ACTUAL".into();
                                    result.actual_state = true;
                                    result.certification_ref = Some(products.certification.certification_digest().into());
                                } else { result.reasons.push("Canonical actual certification or required owner validation is not satisfied; matching bytes alone are insufficient.".into()); }
                            }
                        } else { result.reasons.push("Exact static agreement has no independently established current execution evidence.".into()); }
                    }
                    Some(Err(e)) => result.reasons.push(format!("Post-write authorization is unresolved: {e}")),
                    None => result.reasons.push("No exact process-local original-state pre-write permit; serialized references are not permission.".into()),
                }
            }
        } else {
            result.reasons.push("Actual complete physical inventory/bytes differ from the evaluated candidate; reassessment is required.".into());
        }
        check_cancelled(cancelled)?;
        if self.observe()? != observed {
            return Err(error(
                "SOURCE_DRIFT",
                "physical repository changed during reconciliation; no actual conclusion retained",
            ));
        }
        result.reconciliation_ref = digest(&result)?;
        Ok(result)
    }
}
