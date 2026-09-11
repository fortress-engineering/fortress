//! Module semantic-policy evaluation over canonical State/Effect evidence.

pub(crate) const SEMANTIC_CONFORMANCE_RULE_SOURCE: &str =
    include_str!("../_data/semantic_conformance_rule.json");

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::architecture_realization::{ArchitectureRealization, ReconciliationState};
use crate::contract_coherency::{ContractCoherencyGraph, ModuleSemanticPolicy, ResolvedModule};
use crate::finding::{
    CanonicalFinding, Defeater, DefeaterError, DefeaterKind, DefeaterRetirementCondition,
    DefeaterScope, DefeaterScopeKind, DefeaterStrength, EvaluatorProvenance, FindingCategory,
    FindingError, FindingLocation, FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::implementation_observation::{SourceOwnership, SourceOwnershipAuthority};
use crate::program_semantics::{ExecutionProvenance, ProgramSemanticModel};
use crate::semantic_analysis::FunctionEffect;
use crate::state_effect_analysis::{
    EffectCapability, EffectEvidenceKind, StateEffectAnalysisModel,
};

/// Normative Module semantic-conformance rule identity.
pub const ARCH_SEMANTIC_RULE_ID: &str = "ARCH-SEMANTIC-001";
/// Canonical semantic-conformance projection schema identity.
pub const SEMANTIC_CONFORMANCE_SCHEMA: &str = "urn:fortress:schema:v6:semantic-conformance";
/// Canonical semantic-conformance projection schema version.
pub const SEMANTIC_CONFORMANCE_SCHEMA_VERSION: u16 = 6;
/// Semantic version of the evaluator.
pub const SEMANTIC_CONFORMANCE_VERSION: &str = "4.0.0";
/// Stable evaluator identity used in canonical findings.
pub const SEMANTIC_CONFORMANCE_EVALUATOR_ID: &str = "fortress-semantic-conformance";
/// Stable reason for governed source that produced no PSM symbols.
pub const NO_SEMANTIC_COVERAGE: &str = "NO_SEMANTIC_COVERAGE";
/// Stable enforcement limitation for exclusively test-only violating evidence.
pub const TEST_ONLY_EVIDENCE: &str = "TEST_ONLY_EVIDENCE";
/// Stable enforcement limitation for violating evidence with unknown execution provenance.
pub const UNKNOWN_EXECUTION_PROVENANCE: &str = "UNKNOWN_EXECUTION_PROVENANCE";
/// Versioned namespace for stable authored semantic-policy claim identities.
pub const SEMANTIC_CLAIM_ID_PREFIX: &str = "semantic_claim:v1:sha256";

const REMEDIATION: &str = "Change the implementation so the forbidden semantic consequence is unreachable, or explicitly revise the owning Module Contract policy after architectural review. Do not infer permission from current behavior.";
const COVERAGE_REMEDIATION: &str = "Resolve the identified opaque operation or narrow the authored policy claim to semantics Fortress can currently evaluate. Do not treat missing semantic authority as conformance.";

/// Authored disposition for one stable policy target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDisposition {
    /// The Module explicitly permits the target semantic consequence.
    Allow,
    /// The Module explicitly prohibits the target semantic consequence.
    Deny,
}

/// Namespace of one authored semantic-policy target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyTargetKind {
    /// Architectural capability consequence.
    Capability,
    /// Refined operational effect.
    Effect,
}

/// Truthful conformance state for one Module or policy claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticConformanceState {
    /// All applicable supported evidence satisfies the authored claim.
    Pass,
    /// Supported evidence proves a contradiction.
    Fail,
    /// Claim-relative semantic authority is insufficient.
    Unknown,
    /// No authored semantic-policy claim applies.
    NotApplicable,
}

/// Authored authorization state, independent of implementation conformance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationState {
    /// The Module Contract explicitly permits the named semantic consequence.
    Authorised,
}

impl AuthorizationState {
    /// Returns the stable serialized authorization identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorised => "AUTHORISED",
        }
    }
}

/// Central eligibility classification for enforcement decisions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockingEligibility {
    /// Complete supported causal evidence permits a blocking violation.
    BlockSupported,
    /// The result is informative and cannot itself create a blocking violation.
    AdvisoryOnly,
    /// Missing semantic authority prevents evaluation of the authored claim.
    NotEvaluable,
}

/// Reflexion state for declared-versus-observed dependency evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyConvergenceState {
    /// Declared and observed dependency authority agree.
    Convergence,
    /// An observed dependency lacks direct declared authority.
    Divergence,
    /// A declared relationship has no supported observed realization.
    Absence,
    /// Observed behavior is outside declared Module architecture.
    Unmatched,
    /// Current observation cannot establish a safe comparison.
    Unknown,
}

/// Exact source-level semantic coverage for one declared Module.
///
/// The ratio is serialized as an unreduced rational so its numerator and
/// denominator remain visibly identical to the measured source counts.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticSourceCoverage {
    governed_source_files: usize,
    analysed_source_files: usize,
    ratio: Option<String>,
}

impl SemanticSourceCoverage {
    fn from_counts(governed_source_files: usize, analysed_source_files: usize) -> Self {
        Self {
            governed_source_files,
            analysed_source_files,
            ratio: (governed_source_files > 0)
                .then(|| format!("{analysed_source_files}/{governed_source_files}")),
        }
    }

    /// Returns observed source artifacts owned by the declared Module.
    #[must_use]
    pub const fn governed_source_files(&self) -> usize {
        self.governed_source_files
    }

    /// Returns distinct owned source paths represented by at least one PSM symbol.
    #[must_use]
    pub const fn analysed_source_files(&self) -> usize {
        self.analysed_source_files
    }

    /// Returns the exact `analysed/governed` rational, or `None` without a subject.
    #[must_use]
    pub fn ratio(&self) -> Option<&str> {
        self.ratio.as_deref()
    }

    const fn has_governed_subject(&self) -> bool {
        self.governed_source_files > 0
    }

    const fn has_no_semantic_coverage(&self) -> bool {
        self.has_governed_subject() && self.analysed_source_files == 0
    }
}

/// Computes Module semantic coverage from canonical ownership and actual PSM symbols.
///
/// This deliberately does not consume the aggregate PSM `coverage.source_files`
/// counter: opening a source file is not evidence that it produced semantic facts.
#[must_use]
pub fn compute_semantic_source_coverage(
    ownerships: &[SourceOwnership],
    psm: &ProgramSemanticModel,
) -> BTreeMap<String, SemanticSourceCoverage> {
    let mut governed_paths = BTreeMap::<String, BTreeSet<String>>::new();
    for ownership in ownerships
        .iter()
        .filter(|ownership| ownership.authority() == SourceOwnershipAuthority::DeclaredModule)
    {
        governed_paths
            .entry(ownership.owner().to_owned())
            .or_default()
            .insert(ownership.source_path().to_owned());
    }
    let mut analysed_paths = BTreeMap::<String, BTreeSet<String>>::new();
    for symbol in psm.symbols() {
        if governed_paths
            .get(symbol.fortress_module())
            .is_some_and(|paths| paths.contains(symbol.source_path()))
        {
            analysed_paths
                .entry(symbol.fortress_module().to_owned())
                .or_default()
                .insert(symbol.source_path().to_owned());
        }
    }
    governed_paths
        .into_iter()
        .map(|(module, paths)| {
            let analysed = analysed_paths.get(&module).map_or(0, BTreeSet::len);
            (
                module,
                SemanticSourceCoverage::from_counts(paths.len(), analysed),
            )
        })
        .collect()
}

/// One exact direct or transitive effect attributed to a declared Module symbol.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ModuleEffectObservation {
    module: String,
    effect: FunctionEffect,
    capability: Option<EffectCapability>,
    evidence_kind: EffectEvidenceKind,
    entry_symbol: String,
    entry_execution_provenance: ExecutionProvenance,
    source_symbol: String,
    source_execution_provenance: ExecutionProvenance,
    operation: String,
    operation_site_id: String,
    authority: String,
    path: String,
    line: u32,
    column: u32,
    call_chain: Vec<String>,
    policy_target_kind: Option<PolicyTargetKind>,
    policy_target: Option<String>,
    policy_disposition: Option<PolicyDisposition>,
}

impl ModuleEffectObservation {
    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect(&self) -> FunctionEffect {
        self.effect
    }

    /// Returns the derived capability consequence, when one exists.
    #[must_use]
    pub const fn capability(&self) -> Option<EffectCapability> {
        self.capability
    }

    /// Returns the semantic operation that caused the effect.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the stable underlying operation-site identity.
    #[must_use]
    pub fn operation_site_id(&self) -> &str {
        &self.operation_site_id
    }

    /// Returns the Module entry symbol receiving this direct or transitive evidence.
    #[must_use]
    pub fn entry_symbol(&self) -> &str {
        &self.entry_symbol
    }

    /// Returns the executable symbol where the underlying operation originates.
    #[must_use]
    pub fn source_symbol(&self) -> &str {
        &self.source_symbol
    }

    /// Returns execution provenance for the entry path receiving this evidence.
    #[must_use]
    pub const fn entry_execution_provenance(&self) -> ExecutionProvenance {
        self.entry_execution_provenance
    }

    /// Returns execution provenance for the direct operation source.
    #[must_use]
    pub const fn source_execution_provenance(&self) -> ExecutionProvenance {
        self.source_execution_provenance
    }

    /// Returns the proven call path from Module entry symbol to direct origin.
    #[must_use]
    pub fn call_chain(&self) -> &[String] {
        &self.call_chain
    }

    /// Returns whether the evidence is direct or transitively propagated.
    #[must_use]
    pub const fn evidence_kind(&self) -> EffectEvidenceKind {
        self.evidence_kind
    }

    /// Returns the canonical repository-relative evidence path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the one-based source line carried as diagnostic evidence.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }

    /// Returns the one-based source column carried as diagnostic evidence.
    #[must_use]
    pub const fn column(&self) -> u32 {
        self.column
    }

    /// Returns the analyzer/classifier authority supporting the effect.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the effective authored disposition, when this observation is governed.
    #[must_use]
    pub const fn policy_disposition(&self) -> Option<PolicyDisposition> {
        self.policy_disposition
    }

    /// Returns the namespace of the authored policy target matched by this evidence.
    #[must_use]
    pub const fn policy_target_kind(&self) -> Option<PolicyTargetKind> {
        self.policy_target_kind
    }

    /// Returns the authored effect or capability target matched by this evidence.
    #[must_use]
    pub fn policy_target(&self) -> Option<&str> {
        self.policy_target.as_deref()
    }
}

/// Canonical provenance composition for observations supporting one policy entry.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EvidenceProvenanceSummary {
    #[serde(rename = "production_capable_observations")]
    production_capable: usize,
    #[serde(rename = "test_only_observations")]
    test_only: usize,
    #[serde(rename = "unknown_observations")]
    unknown: usize,
}

impl EvidenceProvenanceSummary {
    fn from_observations(observations: &[&ModuleEffectObservation]) -> Self {
        let mut summary = Self::default();
        for observation in observations {
            match observation.entry_execution_provenance {
                ExecutionProvenance::ProductionCapable => {
                    summary.production_capable += 1;
                }
                ExecutionProvenance::TestOnly => summary.test_only += 1,
                ExecutionProvenance::Unknown => summary.unknown += 1,
            }
        }
        summary
    }

    /// Returns supported observations reachable through production-capable entries.
    #[must_use]
    pub const fn production_capable_observations(self) -> usize {
        self.production_capable
    }

    /// Returns supported observations reachable only through test-only entries.
    #[must_use]
    pub const fn test_only_observations(self) -> usize {
        self.test_only
    }

    /// Returns supported observations whose entry provenance is unknown.
    #[must_use]
    pub const fn unknown_observations(self) -> usize {
        self.unknown
    }
}

/// One authored policy entry and its authorization or conformance result.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticPolicyConclusion {
    id: String,
    target_kind: PolicyTargetKind,
    target: String,
    disposition: PolicyDisposition,
    authorization: Option<AuthorizationState>,
    conformance: Option<SemanticConformanceState>,
    blocking_eligibility: Option<BlockingEligibility>,
    matching_observations: usize,
    evidence_provenance: EvidenceProvenanceSummary,
    coverage: SemanticSourceCoverage,
    defeater_refs: Vec<String>,
}

impl SemanticPolicyConclusion {
    /// Returns the stable authored semantic-policy claim identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the policy target namespace.
    #[must_use]
    pub const fn target_kind(&self) -> PolicyTargetKind {
        self.target_kind
    }

    /// Returns the stable effect or capability identity.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the authored allow/deny disposition.
    #[must_use]
    pub const fn disposition(&self) -> PolicyDisposition {
        self.disposition
    }

    /// Returns authored authorization for an ALLOW entry.
    #[must_use]
    pub const fn authorization(&self) -> Option<AuthorizationState> {
        self.authorization
    }

    /// Returns raw conformance only for an evaluative DENY claim.
    #[must_use]
    pub const fn conformance(&self) -> Option<SemanticConformanceState> {
        self.conformance
    }

    /// Returns enforcement eligibility only for an evaluative DENY claim.
    #[must_use]
    pub const fn blocking_eligibility(&self) -> Option<BlockingEligibility> {
        self.blocking_eligibility
    }

    /// Returns supported observations that exercise this policy entry.
    #[must_use]
    pub const fn matching_observation_count(&self) -> usize {
        self.matching_observations
    }

    /// Returns execution provenance composition for matching observations.
    #[must_use]
    pub const fn evidence_provenance(&self) -> EvidenceProvenanceSummary {
        self.evidence_provenance
    }

    /// Returns exact source-level semantic coverage for the owning Module.
    #[must_use]
    pub const fn coverage(&self) -> &SemanticSourceCoverage {
        &self.coverage
    }

    /// Returns canonical derived evidence that limits this claim.
    #[must_use]
    pub fn defeater_refs(&self) -> &[String] {
        &self.defeater_refs
    }
}

/// One Module-level semantic-policy conclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModuleSemanticConformance {
    module: String,
    contract_path: String,
    policy_state: String,
    state: SemanticConformanceState,
    conclusions: Vec<SemanticPolicyConclusion>,
    observations: Vec<ModuleEffectObservation>,
    ungoverned_observations: usize,
    coverage: SemanticSourceCoverage,
    defeater_refs: Vec<String>,
}

impl ModuleSemanticConformance {
    /// Returns the stable authored Module identity.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns the aggregate raw conformance truth.
    #[must_use]
    pub const fn state(&self) -> SemanticConformanceState {
        self.state
    }

    /// Returns evaluated authored claims.
    #[must_use]
    pub fn conclusions(&self) -> &[SemanticPolicyConclusion] {
        &self.conclusions
    }

    /// Returns supported effect evidence attributed to the Module.
    #[must_use]
    pub fn observations(&self) -> &[ModuleEffectObservation] {
        &self.observations
    }

    /// Returns `DECLARED` or `UNDECLARED` authored policy state.
    #[must_use]
    pub fn policy_state(&self) -> &str {
        &self.policy_state
    }

    /// Returns the canonical Module Contract location.
    #[must_use]
    pub fn contract_path(&self) -> &str {
        &self.contract_path
    }

    /// Returns exact source-level semantic coverage for this Module.
    #[must_use]
    pub const fn coverage(&self) -> &SemanticSourceCoverage {
        &self.coverage
    }

    /// Returns canonical defeaters attached to this Module's policy entries.
    #[must_use]
    pub fn defeater_refs(&self) -> &[String] {
        &self.defeater_refs
    }

    /// Serializes this focused Module view deterministically.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }
}

/// One dependency comparison projected from Architecture Realization authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DependencyConvergence {
    source_module: String,
    target_module: Option<String>,
    external_target: Option<String>,
    state: DependencyConvergenceState,
    declared_capabilities: Vec<String>,
    declared_path: Vec<String>,
}

/// Aggregate semantic-conformance counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SemanticConformanceSummary {
    declared_modules: usize,
    modules_with_policy: usize,
    modules_passed: usize,
    modules_failed: usize,
    modules_unknown: usize,
    modules_not_applicable: usize,
    authored_authorizations: usize,
    authorizations_with_observed_usage: usize,
    authorization_observations: usize,
    evaluative_deny_claims: usize,
    deny_claims_passed: usize,
    deny_claims_failed: usize,
    deny_claims_unknown: usize,
    deny_claims_not_applicable: usize,
    supported_observations: usize,
    governed_observations: usize,
    ungoverned_observations: usize,
    analysis_only_observations: usize,
    forbidden_capability_findings: usize,
    forbidden_effect_findings: usize,
    block_supported_findings: usize,
    advisory_findings: usize,
    test_only_advisory_claims: usize,
    unknown_provenance_advisory_claims: usize,
    not_evaluable_findings: usize,
    no_semantic_coverage_claims: usize,
}

impl SemanticConformanceSummary {
    /// Returns the number of Modules with authored semantic policy.
    #[must_use]
    pub const fn modules_with_policy(self) -> usize {
        self.modules_with_policy
    }

    /// Returns explicit ALLOW authorizations, none of which are conformance claims.
    #[must_use]
    pub const fn authored_authorizations(self) -> usize {
        self.authored_authorizations
    }

    /// Returns authorizations exercised by at least one supported observation.
    #[must_use]
    pub const fn authorizations_with_observed_usage(self) -> usize {
        self.authorizations_with_observed_usage
    }

    /// Returns supported observations matched to authored authorizations.
    #[must_use]
    pub const fn authorization_observations(self) -> usize {
        self.authorization_observations
    }

    /// Returns evaluative DENY claims independently of authorizations.
    #[must_use]
    pub const fn evaluative_deny_claims(self) -> usize {
        self.evaluative_deny_claims
    }

    /// Returns favorable evaluative DENY conclusions.
    #[must_use]
    pub const fn deny_claims_passed(self) -> usize {
        self.deny_claims_passed
    }

    /// Returns proved evaluative DENY contradictions.
    #[must_use]
    pub const fn deny_claims_failed(self) -> usize {
        self.deny_claims_failed
    }

    /// Returns evaluative DENY claims that current authority cannot decide.
    #[must_use]
    pub const fn deny_claims_unknown(self) -> usize {
        self.deny_claims_unknown
    }

    /// Returns evaluative DENY claims without a governed implementation subject.
    #[must_use]
    pub const fn deny_claims_not_applicable(self) -> usize {
        self.deny_claims_not_applicable
    }

    /// Returns supported semantic-policy contradictions eligible to block enforcement.
    #[must_use]
    pub const fn blocking_findings(self) -> usize {
        self.block_supported_findings
    }

    /// Returns raw semantic violations whose evidence cannot independently block.
    #[must_use]
    pub const fn advisory_findings(self) -> usize {
        self.advisory_findings
    }

    /// Returns claims made advisory because all supported evidence is test-only.
    #[must_use]
    pub const fn test_only_advisory_claims(self) -> usize {
        self.test_only_advisory_claims
    }

    /// Returns claims made advisory because all non-test evidence has unknown provenance.
    #[must_use]
    pub const fn unknown_provenance_advisory_claims(self) -> usize {
        self.unknown_provenance_advisory_claims
    }

    /// Returns claim-relative coverage failures.
    #[must_use]
    pub const fn not_evaluable_findings(self) -> usize {
        self.not_evaluable_findings
    }

    /// Returns authored claims made unevaluable by zero symbol-bearing source.
    #[must_use]
    pub const fn no_semantic_coverage_claims(self) -> usize {
        self.no_semantic_coverage_claims
    }

    /// Returns effect evidence owned only by mechanical analysis territories.
    #[must_use]
    pub const fn analysis_only_observations(self) -> usize {
        self.analysis_only_observations
    }

    /// Returns supported observations controlled by explicit policy entries.
    #[must_use]
    pub const fn governed_observations(self) -> usize {
        self.governed_observations
    }
}

/// Canonical snapshot-bound Module semantic-conformance projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SemanticConformanceModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: Option<String>,
    standard_edition: String,
    ccg_digest: String,
    psm_digest: String,
    state_effect_digest: String,
    defeaters: Vec<Defeater>,
    modules: Vec<ModuleSemanticConformance>,
    dependency_convergence: Vec<DependencyConvergence>,
    summary: SemanticConformanceSummary,
    unsupported_semantics: Vec<String>,
}

impl SemanticConformanceModel {
    /// Returns canonical derived evidence limiting semantic-policy claims.
    #[must_use]
    pub fn defeaters(&self) -> &[Defeater] {
        &self.defeaters
    }

    /// Resolves one content-addressed defeater.
    #[must_use]
    pub fn defeater(&self, id: &str) -> Option<&Defeater> {
        self.defeaters
            .binary_search_by(|defeater| defeater.id().cmp(id))
            .ok()
            .map(|index| &self.defeaters[index])
    }

    /// Returns canonical Module conclusions.
    #[must_use]
    pub fn modules(&self) -> &[ModuleSemanticConformance] {
        &self.modules
    }

    /// Finds one declared Module conclusion by stable identity.
    #[must_use]
    pub fn module(&self, id: &str) -> Option<&ModuleSemanticConformance> {
        self.modules.iter().find(|module| module.module == id)
    }

    /// Returns aggregate counts.
    #[must_use]
    pub const fn summary(&self) -> SemanticConformanceSummary {
        self.summary
    }

    /// Returns semantic limits that this evaluator never upgrades to favorable proof.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[String] {
        &self.unsupported_semantics
    }

    /// Serializes deterministic two-space JSON with one trailing LF.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }

    /// Computes SHA-256 over canonical model bytes.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if serialization fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_json()?.as_bytes())
        ))
    }
}

/// Rule-facing Module semantic-conformance result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticConformanceEvaluation {
    model: SemanticConformanceModel,
    findings: Vec<CanonicalFinding>,
    coverage_findings: Vec<CanonicalFinding>,
    symbol_display_names: BTreeMap<String, String>,
}

impl SemanticConformanceEvaluation {
    /// Returns the deterministic derived model.
    #[must_use]
    pub const fn model(&self) -> &SemanticConformanceModel {
        &self.model
    }

    /// Returns all raw canonical semantic contradictions, including advisory evidence.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns canonical claim-relative coverage findings that are not block eligible.
    #[must_use]
    pub fn coverage_findings(&self) -> &[CanonicalFinding] {
        &self.coverage_findings
    }

    /// Returns the canonical qualified name for a stable PSM symbol identity.
    ///
    /// The lookup is presentation authority only; stable machine identity remains
    /// the symbol ID carried by the semantic model.
    #[must_use]
    pub fn symbol_display_name(&self, symbol_id: &str) -> Option<&str> {
        self.symbol_display_names.get(symbol_id).map(String::as_str)
    }

    /// Returns whether at least one Module declared semantic policy.
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        self.model
            .modules
            .iter()
            .any(|module| module.state != SemanticConformanceState::NotApplicable)
    }

    /// Returns whether every applicable Module policy claim passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.findings.is_empty() && self.coverage_findings.is_empty()
    }
}

/// Evaluates authored Module semantic policy against canonical State/Effect facts.
///
/// # Errors
///
/// Returns an error only when source digests or canonical findings cannot be built.
#[allow(clippy::too_many_lines)]
pub fn evaluate_semantic_conformance(
    ccg: &ContractCoherencyGraph,
    psm: &ProgramSemanticModel,
    state_effect: &StateEffectAnalysisModel,
    architecture_realization: &ArchitectureRealization,
    ownerships: &[SourceOwnership],
    standard_edition: &str,
) -> Result<SemanticConformanceEvaluation, SemanticConformanceError> {
    let psm_digest = psm.digest()?;
    let state_effect_digest = state_effect.digest()?;
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let symbol_display_names = symbols
        .iter()
        .map(|(id, symbol)| ((*id).to_owned(), symbol.qualified_name().to_owned()))
        .collect();
    let legacy_symbol_ids = symbols
        .iter()
        .filter_map(|(id, symbol)| {
            symbol
                .legacy_ids()
                .first()
                .map(|legacy| (*id, legacy.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let declared = ccg
        .modules()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let source_coverage = compute_semantic_source_coverage(ownerships, psm);
    let mut by_module = BTreeMap::<String, Vec<ModuleEffectObservation>>::new();
    let mut opaque_by_module = BTreeMap::<String, BTreeMap<String, BTreeSet<String>>>::new();
    let mut analysis_only_observations = 0;

    for summary in state_effect.summaries() {
        let Some(symbol) = symbols.get(summary.symbol()) else {
            continue;
        };
        let owner = symbol.fortress_module();
        if !declared.contains(owner) {
            analysis_only_observations += summary.effect_evidence().len();
            continue;
        }
        for reason in summary.uncertainty().iter().filter(|reason| {
            reason.starts_with("opaque_call:")
                || reason.starts_with("unclassified_external_operation:")
                || reason.starts_with("unsupported_construct:")
                || reason.starts_with("analyser_limit:")
                || matches!(
                    reason.as_str(),
                    "external_operation_identity_missing" | "transitive_opaque_effect"
                )
        }) {
            opaque_by_module
                .entry(owner.into())
                .or_default()
                .entry(summary.symbol().into())
                .or_default()
                .insert(reason.clone());
        }
        for evidence in summary.effect_evidence() {
            by_module
                .entry(owner.into())
                .or_default()
                .push(ModuleEffectObservation {
                    module: owner.into(),
                    effect: evidence.effect(),
                    capability: evidence.capability(),
                    evidence_kind: evidence.kind(),
                    entry_symbol: evidence.entry_symbol().into(),
                    entry_execution_provenance: evidence.entry_execution_provenance(),
                    source_symbol: evidence.source_symbol().into(),
                    source_execution_provenance: evidence.source_execution_provenance(),
                    operation: evidence.operation().into(),
                    operation_site_id: evidence.operation_site_id().into(),
                    authority: evidence.classification_authority().into(),
                    path: evidence.path().into(),
                    line: evidence.line(),
                    column: evidence.column(),
                    call_chain: evidence.call_chain().to_vec(),
                    policy_target_kind: None,
                    policy_target: None,
                    policy_disposition: None,
                });
        }
    }
    for observations in by_module.values_mut() {
        observations.sort();
        observations.dedup();
    }

    let mut findings = Vec::new();
    let mut finding_positions = BTreeMap::new();
    let mut coverage_findings = Vec::new();
    let mut defeaters = BTreeMap::<String, Defeater>::new();
    let mut modules = Vec::new();
    let mut summary = SemanticConformanceSummary {
        declared_modules: ccg.modules().len(),
        analysis_only_observations,
        ..SemanticConformanceSummary::default()
    };
    for (module_id, module) in ccg.modules() {
        let policy = module.contract().semantic_policy();
        let opaque = opaque_by_module.remove(module_id).unwrap_or_default();
        let coverage = source_coverage.get(module_id).cloned().unwrap_or_default();
        let mut observations = by_module.remove(module_id).unwrap_or_default();
        summary.supported_observations += observations.len();
        let (conclusions, state, ungoverned) = if let Some(policy) = policy {
            apply_policy(
                module_id,
                module,
                policy,
                &mut observations,
                &opaque,
                &coverage,
                &psm_digest,
                &state_effect_digest,
                &legacy_symbol_ids,
                standard_edition,
                &mut findings,
                &mut finding_positions,
                &mut coverage_findings,
                &mut defeaters,
                &mut summary,
            )?
        } else {
            (
                Vec::new(),
                SemanticConformanceState::NotApplicable,
                observations.len(),
            )
        };
        if policy.is_some() {
            summary.modules_with_policy += 1;
        }
        match state {
            SemanticConformanceState::Pass => summary.modules_passed += 1,
            SemanticConformanceState::Fail => summary.modules_failed += 1,
            SemanticConformanceState::Unknown => summary.modules_unknown += 1,
            SemanticConformanceState::NotApplicable => summary.modules_not_applicable += 1,
        }
        summary.ungoverned_observations += ungoverned;
        summary.governed_observations += observations.len().saturating_sub(ungoverned);
        let mut module_defeater_refs = conclusions
            .iter()
            .flat_map(|conclusion| conclusion.defeater_refs.iter().cloned())
            .collect::<Vec<_>>();
        module_defeater_refs.sort();
        module_defeater_refs.dedup();
        modules.push(ModuleSemanticConformance {
            module: module_id.clone(),
            contract_path: module.contract_path().into(),
            policy_state: if policy.is_some() {
                "DECLARED".into()
            } else {
                "UNDECLARED".into()
            },
            state,
            conclusions,
            observations,
            ungoverned_observations: ungoverned,
            coverage,
            defeater_refs: module_defeater_refs,
        });
    }
    modules.sort_by(|left, right| left.module.cmp(&right.module));
    findings.sort();
    coverage_findings.sort();
    let dependency_convergence = architecture_realization
        .records()
        .iter()
        .map(|record| DependencyConvergence {
            source_module: record.source_module().into(),
            target_module: record.target_module().map(str::to_owned),
            external_target: record.external_target().map(str::to_owned),
            state: match record.state() {
                ReconciliationState::DeclaredAndObserved => DependencyConvergenceState::Convergence,
                ReconciliationState::ObservedUndeclared
                | ReconciliationState::ObservedTransitiveBypass => {
                    DependencyConvergenceState::Divergence
                }
                ReconciliationState::DeclaredUnobserved => DependencyConvergenceState::Absence,
                ReconciliationState::External => DependencyConvergenceState::Unmatched,
                ReconciliationState::Unresolved => DependencyConvergenceState::Unknown,
            },
            declared_capabilities: record.declared_capabilities().to_vec(),
            declared_path: record.declared_path().to_vec(),
        })
        .collect();
    let model = SemanticConformanceModel {
        schema: SEMANTIC_CONFORMANCE_SCHEMA.into(),
        schema_version: SEMANTIC_CONFORMANCE_SCHEMA_VERSION,
        semantic_version: SEMANTIC_CONFORMANCE_VERSION.into(),
        project_id: psm.project_id().map(str::to_owned),
        standard_edition: standard_edition.into(),
        ccg_digest: ccg.digest()?,
        psm_digest,
        state_effect_digest,
        defeaters: defeaters.into_values().collect(),
        modules,
        dependency_convergence,
        summary,
        unsupported_semantics: vec![
            "capability_permission_inference_from_implementation".into(),
            "claim_coverage_beyond_resolved_static_call_closure".into(),
            "dynamic_dispatch_effect_closure".into(),
            "module_policy_for_analysis_only_territories".into(),
        ],
    };
    Ok(SemanticConformanceEvaluation {
        model,
        findings,
        coverage_findings,
        symbol_display_names,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_policy(
    module_id: &str,
    module: &ResolvedModule,
    policy: &ModuleSemanticPolicy,
    observations: &mut [ModuleEffectObservation],
    opaque: &BTreeMap<String, BTreeSet<String>>,
    coverage: &SemanticSourceCoverage,
    psm_digest: &str,
    state_effect_digest: &str,
    legacy_symbol_ids: &BTreeMap<&str, &str>,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
    finding_positions: &mut BTreeMap<String, usize>,
    coverage_findings: &mut Vec<CanonicalFinding>,
    defeaters: &mut BTreeMap<String, Defeater>,
    summary: &mut SemanticConformanceSummary,
) -> Result<
    (
        Vec<SemanticPolicyConclusion>,
        SemanticConformanceState,
        usize,
    ),
    SemanticConformanceError,
> {
    let mut claims = Vec::new();
    claims.extend(policy.capabilities().allow().iter().map(|target| {
        (
            PolicyTargetKind::Capability,
            target.clone(),
            PolicyDisposition::Allow,
        )
    }));
    claims.extend(policy.capabilities().deny().iter().map(|target| {
        (
            PolicyTargetKind::Capability,
            target.clone(),
            PolicyDisposition::Deny,
        )
    }));
    claims.extend(policy.effects().allow().iter().map(|target| {
        (
            PolicyTargetKind::Effect,
            target.clone(),
            PolicyDisposition::Allow,
        )
    }));
    claims.extend(policy.effects().deny().iter().map(|target| {
        (
            PolicyTargetKind::Effect,
            target.clone(),
            PolicyDisposition::Deny,
        )
    }));
    claims.sort();

    for observation in observations.iter_mut() {
        if let Some(disposition) =
            policy_disposition(policy.effects(), observation.effect.stable_id())
        {
            observation.policy_target_kind = Some(PolicyTargetKind::Effect);
            observation.policy_target = Some(observation.effect.stable_id().into());
            observation.policy_disposition = Some(disposition);
        } else if let Some(capability) = observation.capability
            && let Some(disposition) =
                policy_disposition(policy.capabilities(), capability.stable_id())
        {
            observation.policy_target_kind = Some(PolicyTargetKind::Capability);
            observation.policy_target = Some(capability.stable_id().into());
            observation.policy_disposition = Some(disposition);
        }
    }

    let mut conclusions = Vec::new();
    for (target_kind, target, disposition) in claims {
        let claim_id = semantic_claim_id(module_id, target_kind, &target, disposition);
        let matching = observations
            .iter()
            .filter(|observation| {
                observation.policy_target_kind == Some(target_kind)
                    && observation.policy_target.as_deref() == Some(target.as_str())
                    && observation.policy_disposition == Some(disposition)
            })
            .collect::<Vec<_>>();
        let evidence_provenance = EvidenceProvenanceSummary::from_observations(&matching);
        let mut claim_defeater_refs = Vec::new();
        if coverage.has_governed_subject()
            && coverage.analysed_source_files() < coverage.governed_source_files()
        {
            let (kind, strength, reason, retirement) = if coverage.has_no_semantic_coverage() {
                (
                    DefeaterKind::NoSemanticCoverage,
                    DefeaterStrength::Defeating,
                    NO_SEMANTIC_COVERAGE,
                    DefeaterRetirementCondition::SemanticCoverageEstablished,
                )
            } else {
                (
                    DefeaterKind::PartialSemanticCoverage,
                    DefeaterStrength::Limiting,
                    DefeaterKind::PartialSemanticCoverage.as_str(),
                    DefeaterRetirementCondition::FullSemanticCoverageEstablished,
                )
            };
            let detail = BTreeMap::from([
                (
                    "analysed_source_files".into(),
                    coverage.analysed_source_files().to_string(),
                ),
                (
                    "governed_source_files".into(),
                    coverage.governed_source_files().to_string(),
                ),
                (
                    "ratio".into(),
                    coverage.ratio().unwrap_or("UNDEFINED").into(),
                ),
            ]);
            insert_defeater(
                defeaters,
                &mut claim_defeater_refs,
                Defeater::new(
                    kind,
                    strength,
                    SEMANTIC_CONFORMANCE_EVALUATOR_ID,
                    SEMANTIC_CONFORMANCE_VERSION,
                    DefeaterScope::new(DefeaterScopeKind::Module, module_id)?,
                    reason,
                    detail,
                    vec![module_id.into(), psm_digest.into()],
                    retirement,
                )?,
            );
        }
        for (symbol, reasons) in opaque {
            for reason in reasons {
                insert_defeater(
                    defeaters,
                    &mut claim_defeater_refs,
                    opaque_defeater(symbol, module_id, reason, psm_digest, state_effect_digest)?,
                );
            }
        }
        let (authorization, conformance, blocking_eligibility) = if disposition
            == PolicyDisposition::Allow
        {
            summary.authored_authorizations += 1;
            summary.authorization_observations += matching.len();
            if !matching.is_empty() {
                summary.authorizations_with_observed_usage += 1;
            }
            (Some(AuthorizationState::Authorised), None, None)
        } else if !matching.is_empty() {
            for observation in &matching {
                let mut finding = forbidden_finding(
                    module_id,
                    module,
                    target_kind,
                    &target,
                    observation,
                    legacy_symbol_ids,
                    standard_edition,
                )?;
                if observation.entry_execution_provenance != ExecutionProvenance::ProductionCapable
                {
                    finding = finding.with_advisory_enforcement(
                        match observation.entry_execution_provenance {
                            ExecutionProvenance::TestOnly => TEST_ONLY_EVIDENCE,
                            ExecutionProvenance::Unknown => UNKNOWN_EXECUTION_PROVENANCE,
                            ExecutionProvenance::ProductionCapable => unreachable!(),
                        },
                    )?;
                }
                if let Some(position) = finding_positions.get(finding.finding_fingerprint()) {
                    for alias in finding.legacy_finding_ids() {
                        findings[*position].add_legacy_finding_id(alias.clone());
                    }
                } else {
                    finding_positions
                        .insert(finding.finding_fingerprint().to_owned(), findings.len());
                    if observation.entry_execution_provenance
                        == ExecutionProvenance::ProductionCapable
                    {
                        summary.block_supported_findings += 1;
                    } else {
                        summary.advisory_findings += 1;
                    }
                    findings.push(finding);
                    match target_kind {
                        PolicyTargetKind::Capability => {
                            summary.forbidden_capability_findings += 1;
                        }
                        PolicyTargetKind::Effect => {
                            summary.forbidden_effect_findings += 1;
                        }
                    }
                }
            }
            if evidence_provenance.production_capable_observations() == 0 {
                if evidence_provenance.test_only_observations() > 0 {
                    insert_defeater(
                        defeaters,
                        &mut claim_defeater_refs,
                        provenance_defeater(
                            &claim_id,
                            TEST_ONLY_EVIDENCE,
                            &matching,
                            state_effect_digest,
                        )?,
                    );
                    summary.test_only_advisory_claims += 1;
                }
                if evidence_provenance.unknown_observations() > 0 {
                    insert_defeater(
                        defeaters,
                        &mut claim_defeater_refs,
                        provenance_defeater(
                            &claim_id,
                            UNKNOWN_EXECUTION_PROVENANCE,
                            &matching,
                            state_effect_digest,
                        )?,
                    );
                    summary.unknown_provenance_advisory_claims += 1;
                }
            }
            (
                None,
                Some(SemanticConformanceState::Fail),
                Some(
                    if evidence_provenance.production_capable_observations() > 0 {
                        BlockingEligibility::BlockSupported
                    } else {
                        BlockingEligibility::AdvisoryOnly
                    },
                ),
            )
        } else if !coverage.has_governed_subject() {
            (
                None,
                Some(SemanticConformanceState::NotApplicable),
                Some(BlockingEligibility::AdvisoryOnly),
            )
        } else if has_defeating_defeater(&claim_defeater_refs, defeaters) {
            let reasons = claim_defeater_refs
                .iter()
                .filter_map(|id| defeaters.get(id))
                .filter(|defeater| defeater.strength() == DefeaterStrength::Defeating)
                .map(|defeater| defeater.reason().to_owned())
                .collect::<Vec<_>>();
            coverage_findings.push(coverage_finding(
                module_id,
                module,
                target_kind,
                &target,
                &reasons,
                coverage,
                standard_edition,
            )?);
            summary.not_evaluable_findings += 1;
            if coverage.has_no_semantic_coverage() {
                summary.no_semantic_coverage_claims += 1;
            }
            (
                None,
                Some(SemanticConformanceState::Unknown),
                Some(BlockingEligibility::NotEvaluable),
            )
        } else {
            (
                None,
                Some(SemanticConformanceState::Pass),
                Some(BlockingEligibility::AdvisoryOnly),
            )
        };
        if let Some(state) = conformance {
            summary.evaluative_deny_claims += 1;
            match state {
                SemanticConformanceState::Pass => summary.deny_claims_passed += 1,
                SemanticConformanceState::Fail => summary.deny_claims_failed += 1,
                SemanticConformanceState::Unknown => summary.deny_claims_unknown += 1,
                SemanticConformanceState::NotApplicable => {
                    summary.deny_claims_not_applicable += 1;
                }
            }
        }
        claim_defeater_refs.sort();
        claim_defeater_refs.dedup();
        conclusions.push(SemanticPolicyConclusion {
            id: claim_id,
            target_kind,
            target,
            disposition,
            authorization,
            conformance,
            blocking_eligibility,
            matching_observations: matching.len(),
            evidence_provenance,
            coverage: coverage.clone(),
            defeater_refs: claim_defeater_refs,
        });
    }
    let deny_conclusions = conclusions
        .iter()
        .filter(|conclusion| conclusion.disposition == PolicyDisposition::Deny)
        .collect::<Vec<_>>();
    let state = if deny_conclusions.is_empty()
        || deny_conclusions.iter().all(|conclusion| {
            conclusion.conformance == Some(SemanticConformanceState::NotApplicable)
        }) {
        SemanticConformanceState::NotApplicable
    } else if deny_conclusions
        .iter()
        .any(|conclusion| conclusion.conformance == Some(SemanticConformanceState::Fail))
    {
        SemanticConformanceState::Fail
    } else if deny_conclusions
        .iter()
        .any(|conclusion| conclusion.conformance == Some(SemanticConformanceState::Unknown))
    {
        SemanticConformanceState::Unknown
    } else {
        SemanticConformanceState::Pass
    };
    let ungoverned = observations
        .iter()
        .filter(|observation| observation.policy_disposition.is_none())
        .count();
    Ok((conclusions, state, ungoverned))
}

fn semantic_claim_id(
    module_id: &str,
    target_kind: PolicyTargetKind,
    target: &str,
    disposition: PolicyDisposition,
) -> String {
    let material = (module_id, target_kind, target, disposition);
    format!(
        "{SEMANTIC_CLAIM_ID_PREFIX}:{:x}",
        Sha256::digest(serde_json::to_vec(&material).expect("semantic claim identity serializes"))
    )
}

fn insert_defeater(
    defeaters: &mut BTreeMap<String, Defeater>,
    refs: &mut Vec<String>,
    defeater: Defeater,
) {
    let id = defeater.id().to_owned();
    if let Some(previous) = defeaters.get(&id) {
        debug_assert_eq!(previous, &defeater, "content-addressed defeater collision");
    } else {
        defeaters.insert(id.clone(), defeater);
    }
    refs.push(id);
}

fn has_defeating_defeater(refs: &[String], defeaters: &BTreeMap<String, Defeater>) -> bool {
    refs.iter().any(|id| {
        defeaters
            .get(id)
            .is_some_and(|defeater| defeater.strength() == DefeaterStrength::Defeating)
    })
}

fn opaque_defeater(
    symbol: &str,
    module_id: &str,
    uncertainty: &str,
    psm_digest: &str,
    state_effect_digest: &str,
) -> Result<Defeater, DefeaterError> {
    let (kind, retirement) = if uncertainty.starts_with("unclassified_external_operation:") {
        (
            DefeaterKind::UnclassifiedOperation,
            DefeaterRetirementCondition::OperationClassified,
        )
    } else if uncertainty.starts_with("unsupported_construct:")
        || uncertainty == "opaque_call:Unsupported"
    {
        (
            DefeaterKind::UnsupportedConstruct,
            DefeaterRetirementCondition::ConstructSupported,
        )
    } else if uncertainty.starts_with("analyser_limit:") {
        (
            DefeaterKind::AnalyserLimit,
            DefeaterRetirementCondition::AnalyserSupportEstablished,
        )
    } else {
        (
            DefeaterKind::UnresolvedCallPath,
            DefeaterRetirementCondition::CallResolved,
        )
    };
    Defeater::new(
        kind,
        DefeaterStrength::Defeating,
        SEMANTIC_CONFORMANCE_EVALUATOR_ID,
        SEMANTIC_CONFORMANCE_VERSION,
        DefeaterScope::new(DefeaterScopeKind::Symbol, symbol)?,
        kind.as_str(),
        BTreeMap::from([
            ("module".into(), module_id.into()),
            ("symbol".into(), symbol.into()),
            ("uncertainty".into(), uncertainty.into()),
        ]),
        vec![symbol.into(), psm_digest.into(), state_effect_digest.into()],
        retirement,
    )
}

fn provenance_defeater(
    claim_id: &str,
    reason: &str,
    observations: &[&ModuleEffectObservation],
    state_effect_digest: &str,
) -> Result<Defeater, DefeaterError> {
    let relevant = observations
        .iter()
        .filter(|observation| match reason {
            TEST_ONLY_EVIDENCE => {
                observation.entry_execution_provenance == ExecutionProvenance::TestOnly
            }
            UNKNOWN_EXECUTION_PROVENANCE => {
                observation.entry_execution_provenance == ExecutionProvenance::Unknown
            }
            _ => false,
        })
        .collect::<Vec<_>>();
    let mut inputs = relevant
        .iter()
        .flat_map(|observation| {
            [
                observation.operation_site_id.clone(),
                observation.entry_symbol.clone(),
            ]
        })
        .collect::<Vec<_>>();
    inputs.push(state_effect_digest.into());
    Defeater::new(
        DefeaterKind::EvidenceProvenanceDoubt,
        DefeaterStrength::Limiting,
        SEMANTIC_CONFORMANCE_EVALUATOR_ID,
        SEMANTIC_CONFORMANCE_VERSION,
        DefeaterScope::new(DefeaterScopeKind::SemanticClaim, claim_id)?,
        reason,
        BTreeMap::from([("supporting_observations".into(), relevant.len().to_string())]),
        inputs,
        DefeaterRetirementCondition::ProductionCapableEvidenceEstablished,
    )
}

fn policy_disposition(
    policy: &crate::contract_coherency::SemanticPolicySet,
    target: &str,
) -> Option<PolicyDisposition> {
    if policy
        .allow()
        .binary_search_by(|value| value.as_str().cmp(target))
        .is_ok()
    {
        Some(PolicyDisposition::Allow)
    } else if policy
        .deny()
        .binary_search_by(|value| value.as_str().cmp(target))
        .is_ok()
    {
        Some(PolicyDisposition::Deny)
    } else {
        None
    }
}

fn forbidden_finding(
    module_id: &str,
    module: &ResolvedModule,
    target_kind: PolicyTargetKind,
    target: &str,
    observation: &ModuleEffectObservation,
    legacy_symbol_ids: &BTreeMap<&str, &str>,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let kind = match target_kind {
        PolicyTargetKind::Capability => "FORBIDDEN_CAPABILITY_EXERCISED",
        PolicyTargetKind::Effect => "FORBIDDEN_EFFECT_EXERCISED",
    };
    let material = (
        kind,
        module_id,
        target_kind,
        target,
        observation.operation_site_id.as_str(),
        observation.operation.as_str(),
    );
    let discriminator = format!(
        "{kind}:v2:sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&material).expect("finding identity serializes"))
    );
    let message = format!(
        "Module `{module_id}` explicitly forbids {} `{target}`, but `{}` produces `{}` through {} evidence along `{}`",
        match target_kind {
            PolicyTargetKind::Capability => "capability",
            PolicyTargetKind::Effect => "effect",
        },
        observation.entry_symbol,
        observation.operation,
        match observation.evidence_kind {
            EffectEvidenceKind::Direct => "direct",
            EffectEvidenceKind::Transitive => "transitive",
        },
        observation.call_chain.join(" -> ")
    );
    let mut finding = canonical_finding(
        module_id,
        module,
        &discriminator,
        &message,
        REMEDIATION,
        Some(observation),
        standard_edition,
    )?;
    let legacy_entry = legacy_symbol_ids
        .get(observation.entry_symbol.as_str())
        .copied()
        .unwrap_or(observation.entry_symbol.as_str());
    let legacy_source = legacy_symbol_ids
        .get(observation.source_symbol.as_str())
        .copied()
        .unwrap_or(observation.source_symbol.as_str());
    let legacy_chain = observation
        .call_chain
        .iter()
        .map(|symbol| {
            legacy_symbol_ids
                .get(symbol.as_str())
                .copied()
                .unwrap_or(symbol.as_str())
        })
        .collect::<Vec<_>>();
    let legacy_material = format!(
        "{kind}\0{module_id}\0{target}\0{legacy_entry}\0{legacy_source}\0{}\0{}",
        observation.operation,
        legacy_chain.join("\0")
    );
    let legacy_discriminator = format!(
        "{kind}:sha256:{:x}",
        Sha256::digest(legacy_material.as_bytes())
    );
    let legacy_finding = canonical_finding(
        module_id,
        module,
        &legacy_discriminator,
        &message,
        REMEDIATION,
        Some(observation),
        standard_edition,
    )?;
    finding.add_legacy_finding_id(legacy_finding.finding_id().to_owned());
    Ok(finding)
}

fn coverage_finding(
    module_id: &str,
    module: &ResolvedModule,
    target_kind: PolicyTargetKind,
    target: &str,
    reasons: &[String],
    coverage: &SemanticSourceCoverage,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let discriminator = format!(
        "SEMANTIC_POLICY_NOT_EVALUABLE:{}:{target}",
        match target_kind {
            PolicyTargetKind::Capability => "CAPABILITY",
            PolicyTargetKind::Effect => "EFFECT",
        }
    );
    let message = if reasons == [NO_SEMANTIC_COVERAGE] {
        format!(
            "Module `{module_id}` policy for `{target}` is UNKNOWN because the Module owns {} governed source file(s), but the PSM produced semantic symbols for none of them ({NO_SEMANTIC_COVERAGE})",
            coverage.governed_source_files
        )
    } else {
        format!(
            "Module `{module_id}` policy for `{target}` is UNKNOWN because claim-relevant semantic operations remain opaque: {}",
            reasons.join(", ")
        )
    };
    canonical_finding(
        module_id,
        module,
        &discriminator,
        &message,
        COVERAGE_REMEDIATION,
        None,
        standard_edition,
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_finding(
    module_id: &str,
    module: &ResolvedModule,
    discriminator: &str,
    message: &str,
    remediation: &str,
    observation: Option<&ModuleEffectObservation>,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let definition = RuleFindingDefinition::new(
        ARCH_SEMANTIC_RULE_ID,
        3,
        FindingCategory::Architecture,
        remediation,
    )?;
    let location = observation.map_or_else(
        || FindingLocation::at_path(module.contract_path()),
        |observation| {
            FindingLocation::at_path(&observation.path)?
                .with_span(SourceSpan::new(
                    observation.line,
                    observation.column,
                    observation.line,
                    observation.column,
                )?)
                .with_symbol(observation.entry_symbol.clone())
        },
    )?;
    let occurrence = FindingOccurrence::new(vec![module_id.into()], location, message)?
        .with_discriminator(discriminator)?;
    CanonicalFinding::failure(
        definition,
        occurrence,
        EvaluatorProvenance::new(
            SEMANTIC_CONFORMANCE_EVALUATOR_ID,
            SEMANTIC_CONFORMANCE_VERSION,
        )?,
        standard_edition,
    )
}

/// Semantic-conformance construction failure.
#[derive(Debug)]
pub enum SemanticConformanceError {
    /// Canonical input or output serialization failed.
    Serialization(serde_json::Error),
    /// Canonical finding construction failed.
    Finding(FindingError),
    /// Canonical defeater construction failed.
    Defeater(DefeaterError),
}

impl Display for SemanticConformanceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => write!(formatter, "serialization failed: {error}"),
            Self::Finding(error) => write!(formatter, "finding construction failed: {error}"),
            Self::Defeater(error) => write!(formatter, "defeater construction failed: {error}"),
        }
    }
}

impl Error for SemanticConformanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::Defeater(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for SemanticConformanceError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<FindingError> for SemanticConformanceError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}

impl From<DefeaterError> for SemanticConformanceError {
    fn from(value: DefeaterError) -> Self {
        Self::Defeater(value)
    }
}
