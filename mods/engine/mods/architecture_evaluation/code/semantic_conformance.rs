//! Module semantic-policy evaluation over canonical State/Effect evidence.

pub(crate) const SEMANTIC_CONFORMANCE_RULE_SOURCE: &str =
    include_str!("../data/semantic_conformance_rule.json");

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::architecture_realization::{ArchitectureRealization, ReconciliationState};
use crate::contract_coherency::{ContractCoherencyGraph, ModuleSemanticPolicy, ResolvedModule};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::program_semantics::ProgramSemanticModel;
use crate::semantic_analysis::FunctionEffect;
use crate::state_effect_analysis::{
    EffectCapability, EffectEvidenceKind, StateEffectAnalysisModel,
};

/// Normative Module semantic-conformance rule identity.
pub const ARCH_SEMANTIC_RULE_ID: &str = "ARCH-SEMANTIC-001";
/// Canonical semantic-conformance projection schema identity.
pub const SEMANTIC_CONFORMANCE_SCHEMA: &str = "urn:fortress:schema:v1:semantic-conformance";
/// Canonical semantic-conformance projection schema version.
pub const SEMANTIC_CONFORMANCE_SCHEMA_VERSION: u16 = 1;
/// Semantic version of the evaluator.
pub const SEMANTIC_CONFORMANCE_VERSION: &str = "1.0.0";
/// Stable evaluator identity used in canonical findings.
pub const SEMANTIC_CONFORMANCE_EVALUATOR_ID: &str = "fortress-semantic-conformance";

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

/// One exact direct or transitive effect attributed to a declared Module symbol.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ModuleEffectObservation {
    module: String,
    effect: FunctionEffect,
    capability: Option<EffectCapability>,
    evidence_kind: EffectEvidenceKind,
    entry_symbol: String,
    source_symbol: String,
    operation: String,
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
}

/// One authored policy claim and its independent semantic conclusion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticPolicyConclusion {
    target_kind: PolicyTargetKind,
    target: String,
    disposition: PolicyDisposition,
    state: SemanticConformanceState,
    blocking_eligibility: BlockingEligibility,
    observations: usize,
    coverage_reasons: Vec<String>,
}

impl SemanticPolicyConclusion {
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

    /// Returns the raw claim conformance state.
    #[must_use]
    pub const fn state(&self) -> SemanticConformanceState {
        self.state
    }

    /// Returns whether the claim is block-ready, advisory, or not evaluable.
    #[must_use]
    pub const fn blocking_eligibility(&self) -> BlockingEligibility {
        self.blocking_eligibility
    }

    /// Returns the number of supported observations matched by the claim.
    #[must_use]
    pub const fn observation_count(&self) -> usize {
        self.observations
    }

    /// Returns claim-relative reasons that prevented evaluation.
    #[must_use]
    pub fn coverage_reasons(&self) -> &[String] {
        &self.coverage_reasons
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
    coverage_reasons: Vec<String>,
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
    supported_observations: usize,
    governed_observations: usize,
    ungoverned_observations: usize,
    analysis_only_observations: usize,
    forbidden_capability_findings: usize,
    forbidden_effect_findings: usize,
    not_evaluable_findings: usize,
}

impl SemanticConformanceSummary {
    /// Returns the number of Modules with authored semantic policy.
    #[must_use]
    pub const fn modules_with_policy(self) -> usize {
        self.modules_with_policy
    }

    /// Returns supported semantic-policy contradictions.
    #[must_use]
    pub const fn blocking_findings(self) -> usize {
        self.forbidden_capability_findings + self.forbidden_effect_findings
    }

    /// Returns claim-relative coverage failures.
    #[must_use]
    pub const fn not_evaluable_findings(self) -> usize {
        self.not_evaluable_findings
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
    modules: Vec<ModuleSemanticConformance>,
    dependency_convergence: Vec<DependencyConvergence>,
    summary: SemanticConformanceSummary,
    unsupported_semantics: Vec<String>,
}

impl SemanticConformanceModel {
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
}

impl SemanticConformanceEvaluation {
    /// Returns the deterministic derived model.
    #[must_use]
    pub const fn model(&self) -> &SemanticConformanceModel {
        &self.model
    }

    /// Returns block-eligible canonical semantic contradictions.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns canonical claim-relative coverage findings that are not block eligible.
    #[must_use]
    pub fn coverage_findings(&self) -> &[CanonicalFinding] {
        &self.coverage_findings
    }

    /// Returns whether at least one Module declared semantic policy.
    #[must_use]
    pub const fn is_applicable(&self) -> bool {
        self.model.summary.modules_with_policy > 0
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
    standard_edition: &str,
) -> Result<SemanticConformanceEvaluation, SemanticConformanceError> {
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let declared = ccg
        .modules()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut by_module = BTreeMap::<String, Vec<ModuleEffectObservation>>::new();
    let mut opaque_by_module = BTreeMap::<String, BTreeSet<String>>::new();
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
                || matches!(
                    reason.as_str(),
                    "external_operation_identity_missing" | "transitive_opaque_effect"
                )
        }) {
            opaque_by_module
                .entry(owner.into())
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
                    source_symbol: evidence.source_symbol().into(),
                    operation: evidence.operation().into(),
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
    let mut finding_ids = BTreeSet::new();
    let mut coverage_findings = Vec::new();
    let mut modules = Vec::new();
    let mut summary = SemanticConformanceSummary {
        declared_modules: ccg.modules().len(),
        analysis_only_observations,
        ..SemanticConformanceSummary::default()
    };
    for (module_id, module) in ccg.modules() {
        let policy = module.contract().semantic_policy();
        let opaque = opaque_by_module.remove(module_id).unwrap_or_default();
        let mut observations = by_module.remove(module_id).unwrap_or_default();
        summary.supported_observations += observations.len();
        let (conclusions, state, ungoverned) = if let Some(policy) = policy {
            apply_policy(
                module_id,
                module,
                policy,
                &mut observations,
                &opaque,
                standard_edition,
                &mut findings,
                &mut finding_ids,
                &mut coverage_findings,
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
            coverage_reasons: opaque.into_iter().collect(),
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
        psm_digest: psm.digest()?,
        state_effect_digest: state_effect.digest()?,
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
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_policy(
    module_id: &str,
    module: &ResolvedModule,
    policy: &ModuleSemanticPolicy,
    observations: &mut [ModuleEffectObservation],
    opaque: &BTreeSet<String>,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
    finding_ids: &mut BTreeSet<String>,
    coverage_findings: &mut Vec<CanonicalFinding>,
    summary: &mut SemanticConformanceSummary,
) -> Result<
    (
        Vec<SemanticPolicyConclusion>,
        SemanticConformanceState,
        usize,
    ),
    FindingError,
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
        let matching = observations
            .iter()
            .filter(|observation| {
                observation.policy_target_kind == Some(target_kind)
                    && observation.policy_target.as_deref() == Some(target.as_str())
                    && observation.policy_disposition == Some(disposition)
            })
            .collect::<Vec<_>>();
        let (state, blocking_eligibility, coverage_reasons) =
            if disposition == PolicyDisposition::Deny && !matching.is_empty() {
                for observation in &matching {
                    let finding = forbidden_finding(
                        module_id,
                        module,
                        target_kind,
                        &target,
                        observation,
                        standard_edition,
                    )?;
                    if finding_ids.insert(finding.finding_fingerprint().to_owned()) {
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
                (
                    SemanticConformanceState::Fail,
                    BlockingEligibility::BlockSupported,
                    Vec::new(),
                )
            } else if disposition == PolicyDisposition::Deny && !opaque.is_empty() {
                coverage_findings.push(coverage_finding(
                    module_id,
                    module,
                    target_kind,
                    &target,
                    opaque,
                    standard_edition,
                )?);
                summary.not_evaluable_findings += 1;
                (
                    SemanticConformanceState::Unknown,
                    BlockingEligibility::NotEvaluable,
                    opaque.iter().cloned().collect(),
                )
            } else {
                (
                    SemanticConformanceState::Pass,
                    BlockingEligibility::AdvisoryOnly,
                    Vec::new(),
                )
            };
        conclusions.push(SemanticPolicyConclusion {
            target_kind,
            target,
            disposition,
            state,
            blocking_eligibility,
            observations: matching.len(),
            coverage_reasons,
        });
    }
    let state = if conclusions.is_empty() {
        SemanticConformanceState::NotApplicable
    } else if conclusions
        .iter()
        .any(|conclusion| conclusion.state == SemanticConformanceState::Fail)
    {
        SemanticConformanceState::Fail
    } else if conclusions
        .iter()
        .any(|conclusion| conclusion.state == SemanticConformanceState::Unknown)
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
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let kind = match target_kind {
        PolicyTargetKind::Capability => "FORBIDDEN_CAPABILITY_EXERCISED",
        PolicyTargetKind::Effect => "FORBIDDEN_EFFECT_EXERCISED",
    };
    let material = format!(
        "{kind}\0{module_id}\0{target}\0{}\0{}\0{}\0{}",
        observation.entry_symbol,
        observation.source_symbol,
        observation.operation,
        observation.call_chain.join("\0")
    );
    let discriminator = format!("{kind}:sha256:{:x}", Sha256::digest(material.as_bytes()));
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
    canonical_finding(
        module_id,
        module,
        &discriminator,
        &message,
        REMEDIATION,
        Some(observation),
        standard_edition,
    )
}

fn coverage_finding(
    module_id: &str,
    module: &ResolvedModule,
    target_kind: PolicyTargetKind,
    target: &str,
    opaque: &BTreeSet<String>,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let discriminator = format!(
        "SEMANTIC_POLICY_NOT_EVALUABLE:{}:{target}",
        match target_kind {
            PolicyTargetKind::Capability => "CAPABILITY",
            PolicyTargetKind::Effect => "EFFECT",
        }
    );
    let message = format!(
        "Module `{module_id}` policy for `{target}` is UNKNOWN because claim-relevant semantic operations remain opaque: {}",
        opaque.iter().cloned().collect::<Vec<_>>().join(", ")
    );
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
}

impl Display for SemanticConformanceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => write!(formatter, "serialization failed: {error}"),
            Self::Finding(error) => write!(formatter, "finding construction failed: {error}"),
        }
    }
}

impl Error for SemanticConformanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
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
