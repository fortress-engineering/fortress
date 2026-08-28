//! Deterministic external outcome, retry, and bounded recovery semantics.

#[path = "environment_contract.rs"]
mod environment_contract;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::information_flow::InformationFlowEvaluation;
use crate::program_semantics::{CallResolutionState, ExecutableSymbol, ProgramSemanticModel};
use crate::semantic_analysis::{
    FunctionEffect, ResolvedFunctionContracts, SemanticAnalysisEvaluation, SemanticDomain,
    resolve_domain,
};
use crate::state_effect_analysis::{StateEffectAnalysisEvaluation, TypestateClassification};

pub use environment_contract::{
    AtomicitySemantics, CompletionSemantics, DeliverySemantics, DuplicateStrategy,
    ENVIRONMENT_CONTRACT_SCHEMA, ENVIRONMENT_CONTRACT_SCHEMA_VERSION, EffectStep,
    EnvironmentContractError, EnvironmentContractSource, EnvironmentOperation, ExternalOutcome,
    ExternalResultClass, IdempotencySemantics, OutcomeFlowLabel, OutcomeHandling, RecoveryContract,
    ResolvedEnvironmentContracts, ResourceKind, ResponseCardinality, RestartSemantics, RetryPolicy,
    TimingSemantics, canonicalize_environment_contract_json, load_environment_contracts,
};

/// Canonical Environmental Analysis schema identity.
pub const ENVIRONMENTAL_ANALYSIS_SCHEMA: &str = "urn:fortress:schema:v1:environmental-analysis";
/// Canonical Environmental Analysis schema version.
pub const ENVIRONMENTAL_ANALYSIS_SCHEMA_VERSION: u16 = 1;
/// Environmental analyzer semantic version.
pub const ENVIRONMENTAL_ANALYSIS_VERSION: &str = "1.0.0";
/// Stable analyzer identity.
pub const ENVIRONMENTAL_ANALYZER_ID: &str = "fortress-environmental-semantics";
/// Handling-totality rule identity.
pub const PROGRAM_ENVIRONMENT_RULE_ID: &str = "PROGRAM-ENVIRONMENT-001";
/// Retry/idempotency rule identity.
pub const PROGRAM_RETRY_RULE_ID: &str = "PROGRAM-RETRY-001";
/// Interruption/recovery rule identity.
pub const PROGRAM_RECOVERY_RULE_ID: &str = "PROGRAM-RECOVERY-001";

const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_os_and_hardware_failure_modeling",
    "byzantine_external_actors",
    "complete_database_transaction_semantics",
    "concurrency_interleaving_theorem_proving",
    "distributed_consensus_model_checking",
    "numeric_real_time_verification",
    "probabilistic_failure_analysis",
    "provider_specific_external_api_semantics",
];

/// Outcome handling conclusion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandlingStatus {
    /// Exact declared continuation exists and is reachable under supported calls.
    Handled,
    /// A continuation is declared but opaque calls prevent complete proof.
    PartiallyHandled,
    /// No supported continuation exists.
    Unhandled,
    /// The boundary is known but continuation semantics remain unknown.
    Unknown,
    /// The semantic class is outside v1.
    Unsupported,
}

/// Independent epistemic state for one environmental property.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnvironmentalCoverage {
    /// Supported semantics establish the property.
    Proven,
    /// Some supported facts exist while relevant opacity remains.
    Partial,
    /// No conclusion is available.
    Unknown,
    /// The property is outside v1.
    Unsupported,
}

/// Supported environmental contradiction class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentalViolationKind {
    /// An admissible outcome has no supported continuation.
    UnhandledOutcome,
    /// An outcome reaches an effect it explicitly forbids.
    ForbiddenEffect,
    /// A retry occurs under a NEVER or incompatible CONDITIONAL policy.
    RetryForbidden,
    /// Unknown completion is retried despite non-idempotency.
    UnknownCompletionRetry,
    /// A required idempotency/deduplication identity is not preserved.
    UnprovenIdempotencyKey,
    /// Duplicate delivery lacks an idempotent or deduplicating continuation.
    DuplicateUnsafe,
    /// Non-atomic durable steps lack supported recovery.
    MissingRecovery,
    /// Recovery retries a non-idempotent operation unsafely.
    UnsafeRecoveryRetry,
    /// An outcome exposes a state forbidden by recovery authority.
    ForbiddenRecoveryState,
}

/// One normalized environmental contradiction and its abstract scenario.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EnvironmentalViolation {
    id: String,
    rule_id: String,
    kind: EnvironmentalViolationKind,
    operation: String,
    outcome: Option<String>,
    boundary: String,
    scenario: Vec<String>,
    message: String,
    path: String,
    line: u32,
    column: u32,
}

/// One deterministic verification scenario derived from an admissible outcome.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FailureTestObligation {
    id: String,
    operation: String,
    outcome: String,
    injection: String,
    expected_continuation: Option<String>,
    expected_state: Option<String>,
    contract_provenance: String,
}

/// One compiled outcome and its handling/retry/security consequences.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EnvironmentalOutcomeSummary {
    id: String,
    completion: CompletionSemantics,
    response: ResponseCardinality,
    timing: TimingSemantics,
    result: ExternalResultClass,
    local_result_domain: Option<SemanticDomain>,
    information_flow: Vec<OutcomeFlowLabel>,
    resulting_state: Option<String>,
    forbidden_effects: Vec<FunctionEffect>,
    resource: Option<ResourceKind>,
    handling: HandlingStatus,
    continuation: Option<String>,
    terminal: bool,
    retries: bool,
    retry_safety: EnvironmentalCoverage,
    duplicate_safety: EnvironmentalCoverage,
    timing_handling: EnvironmentalCoverage,
    provenance: String,
}

impl EnvironmentalOutcomeSummary {
    /// Returns the project-defined outcome identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact continuation symbol, when one is declared.
    #[must_use]
    pub fn continuation(&self) -> Option<&str> {
        self.continuation.as_deref()
    }

    /// Returns whether the outcome is a declared terminal continuation.
    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }

    /// Returns the normalized handling conclusion.
    #[must_use]
    pub const fn handling(&self) -> HandlingStatus {
        self.handling
    }

    /// Returns exact Environment Contract provenance.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// One external boundary's deterministic environmental summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnvironmentalOperationSummary {
    operation: String,
    actor: String,
    boundary: String,
    boundary_module: String,
    external_call_sites: usize,
    retry_policy: RetryPolicy,
    idempotency: IdempotencySemantics,
    delivery: DeliverySemantics,
    atomicity: AtomicitySemantics,
    interruption_sensitive: bool,
    direct_effects: Vec<FunctionEffect>,
    transitive_effects: Vec<FunctionEffect>,
    outcomes: Vec<EnvironmentalOutcomeSummary>,
    contract_binding: EnvironmentalCoverage,
    outcome_enumeration: EnvironmentalCoverage,
    handling_totality: EnvironmentalCoverage,
    retry_safety: EnvironmentalCoverage,
    duplicate_safety: EnvironmentalCoverage,
    completion_certainty: EnvironmentalCoverage,
    timing_handling: EnvironmentalCoverage,
    recovery_consistency: EnvironmentalCoverage,
    information_flow: EnvironmentalCoverage,
    provenance: String,
}

impl EnvironmentalOperationSummary {
    /// Returns the external operation identity.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the governed integration-boundary symbol.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Returns the Module owning the integration boundary.
    #[must_use]
    pub fn boundary_module(&self) -> &str {
        &self.boundary_module
    }

    /// Returns all admissible outcome summaries.
    #[must_use]
    pub fn outcomes(&self) -> &[EnvironmentalOutcomeSummary] {
        &self.outcomes
    }

    /// Returns exact Environment Contract provenance.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// Aggregate deterministic environmental counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EnvironmentalCoverageSummary {
    operations: usize,
    outcomes: usize,
    handled: usize,
    partially_handled: usize,
    unhandled: usize,
    unknown: usize,
    retries: usize,
    retry_checks: usize,
    idempotency_checks: usize,
    unknown_completion_paths: usize,
    duplicate_delivery_checks: usize,
    interruption_checks: usize,
    recovery_checks: usize,
    atomic_groups: usize,
    non_atomic_groups: usize,
    unknown_atomicity_groups: usize,
    failure_test_obligations: usize,
    violations: usize,
}

impl EnvironmentalCoverageSummary {
    /// Returns operation count.
    #[must_use]
    pub const fn operations(self) -> usize {
        self.operations
    }

    /// Returns supported contradiction count.
    #[must_use]
    pub const fn violations(self) -> usize {
        self.violations
    }
}

/// Canonical Environmental Analysis v1 derived information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnvironmentalAnalysisModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: String,
    psm_digest: String,
    semantic_analysis_digest: String,
    state_effect_digest: String,
    information_flow_digest: String,
    environment_contract_digest: String,
    function_contract_digest: String,
    operations: Vec<EnvironmentalOperationSummary>,
    failure_test_obligations: Vec<FailureTestObligation>,
    violations: Vec<EnvironmentalViolation>,
    coverage: EnvironmentalCoverageSummary,
    unsupported_semantics: Vec<String>,
}

impl EnvironmentalAnalysisModel {
    /// Returns compiled operation summaries.
    #[must_use]
    pub fn operations(&self) -> &[EnvironmentalOperationSummary] {
        &self.operations
    }

    /// Returns deterministic fault-injection test obligations.
    #[must_use]
    pub fn failure_test_obligations(&self) -> &[FailureTestObligation] {
        &self.failure_test_obligations
    }

    /// Returns supported contradictions.
    #[must_use]
    pub fn violations(&self) -> &[EnvironmentalViolation] {
        &self.violations
    }

    /// Returns aggregate coverage and counts.
    #[must_use]
    pub const fn coverage(&self) -> EnvironmentalCoverageSummary {
        self.coverage
    }

    /// Returns explicit unsupported semantic classes.
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

    /// Computes SHA-256 over canonical bytes.
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

/// Rule-facing environmental evaluation split by normative proposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentalAnalysisEvaluation {
    model: EnvironmentalAnalysisModel,
    environment_findings: Vec<CanonicalFinding>,
    retry_findings: Vec<CanonicalFinding>,
    recovery_findings: Vec<CanonicalFinding>,
}

impl EnvironmentalAnalysisEvaluation {
    /// Returns the canonical derived model.
    #[must_use]
    pub const fn model(&self) -> &EnvironmentalAnalysisModel {
        &self.model
    }

    /// Returns PROGRAM-ENVIRONMENT-001 findings.
    #[must_use]
    pub fn environment_findings(&self) -> &[CanonicalFinding] {
        &self.environment_findings
    }

    /// Returns PROGRAM-RETRY-001 findings.
    #[must_use]
    pub fn retry_findings(&self) -> &[CanonicalFinding] {
        &self.retry_findings
    }

    /// Returns PROGRAM-RECOVERY-001 findings.
    #[must_use]
    pub fn recovery_findings(&self) -> &[CanonicalFinding] {
        &self.recovery_findings
    }
}

/// Compiles external nondeterminism against the canonical semantic stack.
///
/// # Errors
///
/// Returns a typed error for missing validated symbols/types, serialization,
/// or normalized finding construction.
#[allow(clippy::too_many_lines)]
pub fn analyze_environmental_semantics(
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisEvaluation,
    state_effect: &StateEffectAnalysisEvaluation,
    information_flow: &InformationFlowEvaluation,
    contracts: &ResolvedEnvironmentContracts,
    function_contracts: &ResolvedFunctionContracts,
    standard_edition: &str,
) -> Result<EnvironmentalAnalysisEvaluation, EnvironmentalAnalysisError> {
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let types = psm
        .types()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let adjacency = call_adjacency(psm);
    let state_summaries = state_effect
        .model()
        .summaries()
        .iter()
        .map(|summary| (summary.symbol(), summary))
        .collect::<BTreeMap<_, _>>();
    let mut operation_summaries = Vec::new();
    let mut violations = Vec::new();
    let mut obligations = Vec::new();
    let mut counts = EnvironmentalCounts::default();
    for operation in contracts.operations() {
        let boundary = symbols
            .get(operation.boundary())
            .copied()
            .ok_or_else(|| EnvironmentalAnalysisError::MissingBoundary(operation.id().into()))?;
        let return_type = types
            .get(boundary.return_type().type_id())
            .ok_or_else(|| EnvironmentalAnalysisError::MissingReturnType(operation.id().into()))?;
        let external_call_sites = psm
            .calls()
            .iter()
            .filter(|call| {
                call.caller() == operation.boundary()
                    && call.state() == CallResolutionState::External
            })
            .map(|call| call.evidence().len())
            .sum();
        let incomplete_boundary_calls = psm.calls().iter().any(|call| {
            call.caller() == operation.boundary()
                && matches!(
                    call.state(),
                    CallResolutionState::DynamicDispatch
                        | CallResolutionState::Unresolved
                        | CallResolutionState::Unsupported
                )
        });
        let state_summary = state_summaries.get(operation.boundary()).copied();
        let direct_effects = state_summary
            .map_or(&[][..], |summary| summary.direct_effects())
            .to_vec();
        let transitive_effects = state_summary
            .map_or(&[][..], |summary| summary.transitive_effects())
            .to_vec();
        let source_path = contracts
            .source_path(operation.id())
            .unwrap_or("contract.json");
        let mut outcome_summaries = Vec::new();
        for outcome in operation.outcomes() {
            counts.outcomes += 1;
            let (handling, continuation, terminal) = handling_status(
                operation,
                outcome,
                &symbols,
                &adjacency,
                incomplete_boundary_calls,
            );
            match handling {
                HandlingStatus::Handled => counts.handled += 1,
                HandlingStatus::PartiallyHandled => counts.partially_handled += 1,
                HandlingStatus::Unhandled => counts.unhandled += 1,
                HandlingStatus::Unknown | HandlingStatus::Unsupported => counts.unknown += 1,
            }
            if handling == HandlingStatus::Unhandled {
                violations.push(violation(
                    PROGRAM_ENVIRONMENT_RULE_ID,
                    EnvironmentalViolationKind::UnhandledOutcome,
                    operation,
                    Some(outcome),
                    boundary,
                    source_path,
                    vec![
                        format!("admissible_outcome:{}", outcome.id()),
                        "supported_continuation:none".into(),
                    ],
                    format!(
                        "Environment operation `{}` admits outcome `{}` but has no supported defined continuation.",
                        operation.id(),
                        outcome.id()
                    ),
                ));
            }
            for effect in outcome.forbidden_effects() {
                if transitive_effects.binary_search(effect).is_ok() {
                    violations.push(violation(
                        PROGRAM_ENVIRONMENT_RULE_ID,
                        EnvironmentalViolationKind::ForbiddenEffect,
                        operation,
                        Some(outcome),
                        boundary,
                        source_path,
                        vec![
                            format!("outcome:{}", outcome.id()),
                            format!("observed_effect:{effect:?}"),
                        ],
                        format!(
                            "Environment operation `{}` outcome `{}` forbids supported transitive effect `{effect:?}`.",
                            operation.id(),
                            outcome.id()
                        ),
                    ));
                }
            }
            if let (Some(expected), Some(summary)) = (outcome.state(), state_summary)
                && let Some(TypestateClassification::Exact { state }) =
                    summary.output_receiver_state()
                && state != expected
            {
                violations.push(violation(
                    PROGRAM_ENVIRONMENT_RULE_ID,
                    EnvironmentalViolationKind::ForbiddenEffect,
                    operation,
                    Some(outcome),
                    boundary,
                    source_path,
                    vec![
                        format!("declared_outcome_state:{expected}"),
                        format!("supported_output_state:{state}"),
                    ],
                    format!(
                        "Environment operation `{}` outcome `{}` declares state `{expected}` but supported execution yields `{state}`.",
                        operation.id(),
                        outcome.id()
                    ),
                ));
            }
            let retry_safety = retry_analysis(
                operation,
                outcome,
                boundary,
                source_path,
                &mut violations,
                &mut counts,
            );
            let duplicate_safety = duplicate_analysis(
                operation,
                outcome,
                boundary,
                source_path,
                &mut violations,
                &mut counts,
            );
            if outcome.completion() == CompletionSemantics::UnknownCompletion {
                counts.unknown_completion_paths += 1;
            }
            let domain = outcome
                .domain()
                .map(|specification| resolve_domain(specification, return_type))
                .transpose()
                .map_err(|detail| EnvironmentalAnalysisError::Domain {
                    operation: operation.id().into(),
                    outcome: outcome.id().into(),
                    detail,
                })?;
            obligations.push(failure_test_obligation(
                operation,
                outcome,
                source_path,
                continuation.as_deref(),
            ));
            outcome_summaries.push(EnvironmentalOutcomeSummary {
                id: outcome.id().into(),
                completion: outcome.completion(),
                response: outcome.response(),
                timing: outcome.timing(),
                result: outcome.result(),
                local_result_domain: domain,
                information_flow: outcome.information_flow().to_vec(),
                resulting_state: outcome.state().map(str::to_owned),
                forbidden_effects: outcome.forbidden_effects().to_vec(),
                resource: outcome.resource(),
                handling,
                continuation,
                terminal,
                retries: outcome.handling().is_some_and(OutcomeHandling::retries),
                retry_safety,
                duplicate_safety,
                timing_handling: if handling == HandlingStatus::Handled {
                    EnvironmentalCoverage::Proven
                } else if handling == HandlingStatus::PartiallyHandled {
                    EnvironmentalCoverage::Partial
                } else {
                    EnvironmentalCoverage::Unknown
                },
                provenance: format!(
                    "{source_path}#/operations/{}/outcomes/{}",
                    counts.operations,
                    outcome_summaries.len()
                ),
            });
        }
        let recovery_consistency = recovery_analysis(
            operation,
            boundary,
            source_path,
            &symbols,
            &adjacency,
            &mut violations,
            &mut obligations,
            &mut counts,
        );
        let handling_totality = aggregate_handling(&outcome_summaries);
        let retry_safety =
            aggregate_coverage(outcome_summaries.iter().map(|outcome| outcome.retry_safety));
        let duplicate_safety = aggregate_coverage(
            outcome_summaries
                .iter()
                .map(|outcome| outcome.duplicate_safety),
        );
        let timing_handling = aggregate_coverage(
            outcome_summaries
                .iter()
                .map(|outcome| outcome.timing_handling),
        );
        let completion_certainty = if operation
            .outcomes()
            .iter()
            .any(|outcome| outcome.completion() == CompletionSemantics::UnknownCompletion)
        {
            EnvironmentalCoverage::Partial
        } else {
            EnvironmentalCoverage::Proven
        };
        let information_flow_coverage = if operation
            .outcomes()
            .iter()
            .any(|outcome| !outcome.information_flow().is_empty())
        {
            EnvironmentalCoverage::Proven
        } else {
            EnvironmentalCoverage::Unknown
        };
        operation_summaries.push(EnvironmentalOperationSummary {
            operation: operation.id().into(),
            actor: operation.actor().into(),
            boundary: operation.boundary().into(),
            boundary_module: boundary.fortress_module().into(),
            external_call_sites,
            retry_policy: operation.retry_policy(),
            idempotency: operation.idempotency(),
            delivery: operation.delivery(),
            atomicity: operation.atomicity(),
            interruption_sensitive: operation.interruption_sensitive(),
            direct_effects,
            transitive_effects,
            outcomes: outcome_summaries,
            contract_binding: if external_call_sites > 0 {
                EnvironmentalCoverage::Proven
            } else if incomplete_boundary_calls {
                EnvironmentalCoverage::Partial
            } else {
                EnvironmentalCoverage::Unknown
            },
            outcome_enumeration: EnvironmentalCoverage::Proven,
            handling_totality,
            retry_safety,
            duplicate_safety,
            completion_certainty,
            timing_handling,
            recovery_consistency,
            information_flow: information_flow_coverage,
            provenance: format!("{source_path}#/operations/{}", counts.operations),
        });
        counts.operations += 1;
    }
    operation_summaries.sort_by(|left, right| left.operation.cmp(&right.operation));
    obligations.sort();
    obligations.dedup();
    violations.sort();
    violations.dedup();
    let environment_findings =
        findings_for_rule(&violations, PROGRAM_ENVIRONMENT_RULE_ID, standard_edition)?;
    let retry_findings = findings_for_rule(&violations, PROGRAM_RETRY_RULE_ID, standard_edition)?;
    let recovery_findings =
        findings_for_rule(&violations, PROGRAM_RECOVERY_RULE_ID, standard_edition)?;
    let coverage = EnvironmentalCoverageSummary {
        operations: counts.operations,
        outcomes: counts.outcomes,
        handled: counts.handled,
        partially_handled: counts.partially_handled,
        unhandled: counts.unhandled,
        unknown: counts.unknown,
        retries: counts.retries,
        retry_checks: counts.retry_checks,
        idempotency_checks: counts.idempotency_checks,
        unknown_completion_paths: counts.unknown_completion_paths,
        duplicate_delivery_checks: counts.duplicate_delivery_checks,
        interruption_checks: counts.interruption_checks,
        recovery_checks: counts.recovery_checks,
        atomic_groups: counts.atomic_groups,
        non_atomic_groups: counts.non_atomic_groups,
        unknown_atomicity_groups: counts.unknown_atomicity_groups,
        failure_test_obligations: obligations.len(),
        violations: violations.len(),
    };
    let model = EnvironmentalAnalysisModel {
        schema: ENVIRONMENTAL_ANALYSIS_SCHEMA.into(),
        schema_version: ENVIRONMENTAL_ANALYSIS_SCHEMA_VERSION,
        semantic_version: ENVIRONMENTAL_ANALYSIS_VERSION.into(),
        project_id: psm.project_id().into(),
        psm_digest: psm.digest()?,
        semantic_analysis_digest: semantic.model().digest()?,
        state_effect_digest: state_effect.model().digest()?,
        information_flow_digest: information_flow.model().digest()?,
        environment_contract_digest: contracts.digest().into(),
        function_contract_digest: function_contracts.digest().into(),
        operations: operation_summaries,
        failure_test_obligations: obligations,
        violations,
        coverage,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
    };
    Ok(EnvironmentalAnalysisEvaluation {
        model,
        environment_findings,
        retry_findings,
        recovery_findings,
    })
}

#[derive(Default)]
struct EnvironmentalCounts {
    operations: usize,
    outcomes: usize,
    handled: usize,
    partially_handled: usize,
    unhandled: usize,
    unknown: usize,
    retries: usize,
    retry_checks: usize,
    idempotency_checks: usize,
    unknown_completion_paths: usize,
    duplicate_delivery_checks: usize,
    interruption_checks: usize,
    recovery_checks: usize,
    atomic_groups: usize,
    non_atomic_groups: usize,
    unknown_atomicity_groups: usize,
}

fn call_adjacency(psm: &ProgramSemanticModel) -> BTreeMap<String, BTreeSet<String>> {
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for call in psm.calls() {
        if let Some(callee) = call.callee() {
            adjacency
                .entry(call.caller().into())
                .or_default()
                .insert(callee.into());
        }
    }
    adjacency
}

fn reachable(start: &str, target: &str, adjacency: &BTreeMap<String, BTreeSet<String>>) -> bool {
    if start == target {
        return true;
    }
    let mut queue = VecDeque::from([start]);
    let mut seen = BTreeSet::from([start]);
    while let Some(current) = queue.pop_front() {
        if let Some(next) = adjacency.get(current) {
            for candidate in next {
                if candidate == target {
                    return true;
                }
                if seen.insert(candidate) {
                    queue.push_back(candidate);
                }
            }
        }
    }
    false
}

fn handling_status(
    operation: &EnvironmentOperation,
    outcome: &ExternalOutcome,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    incomplete_boundary_calls: bool,
) -> (HandlingStatus, Option<String>, bool) {
    let Some(handling) = outcome.handling() else {
        return (HandlingStatus::Unhandled, None, false);
    };
    if !symbols.contains_key(handling.continuation()) {
        return (
            HandlingStatus::Unknown,
            Some(handling.continuation().into()),
            handling.terminal(),
        );
    }
    if reachable(operation.boundary(), handling.continuation(), adjacency) {
        return (
            HandlingStatus::Handled,
            Some(handling.continuation().into()),
            handling.terminal(),
        );
    }
    if incomplete_boundary_calls {
        (
            HandlingStatus::PartiallyHandled,
            Some(handling.continuation().into()),
            handling.terminal(),
        )
    } else {
        (
            HandlingStatus::Unhandled,
            Some(handling.continuation().into()),
            handling.terminal(),
        )
    }
}

fn retry_analysis(
    operation: &EnvironmentOperation,
    outcome: &ExternalOutcome,
    boundary: &ExecutableSymbol,
    path: &str,
    violations: &mut Vec<EnvironmentalViolation>,
    counts: &mut EnvironmentalCounts,
) -> EnvironmentalCoverage {
    let Some(handling) = outcome.handling() else {
        return EnvironmentalCoverage::Unknown;
    };
    if !handling.retries() {
        return EnvironmentalCoverage::Proven;
    }
    counts.retries += 1;
    counts.retry_checks += 1;
    let policy_allows = match operation.retry_policy() {
        RetryPolicy::Never => false,
        RetryPolicy::Safe => true,
        RetryPolicy::Conditional => operation
            .retryable_outcomes()
            .binary_search_by(|candidate| candidate.as_str().cmp(outcome.id()))
            .is_ok(),
        RetryPolicy::Unknown => return EnvironmentalCoverage::Unknown,
    };
    if !policy_allows {
        violations.push(violation(
            PROGRAM_RETRY_RULE_ID,
            EnvironmentalViolationKind::RetryForbidden,
            operation,
            Some(outcome),
            boundary,
            path,
            vec![
                format!("retry_policy:{:?}", operation.retry_policy()),
                format!("outcome:{}", outcome.id()),
                "implementation_continuation:retry".into(),
            ],
            format!(
                "Environment operation `{}` retries outcome `{}` despite retry policy `{:?}`.",
                operation.id(),
                outcome.id(),
                operation.retry_policy()
            ),
        ));
        return EnvironmentalCoverage::Proven;
    }
    if outcome.completion() == CompletionSemantics::UnknownCompletion
        && operation.idempotency() == IdempotencySemantics::NonIdempotent
    {
        counts.idempotency_checks += 1;
        violations.push(violation(
            PROGRAM_RETRY_RULE_ID,
            EnvironmentalViolationKind::UnknownCompletionRetry,
            operation,
            Some(outcome),
            boundary,
            path,
            vec![
                "first_attempt:may_have_completed".into(),
                "response:lost_or_absent".into(),
                "second_attempt:may_repeat_external_effect".into(),
            ],
            format!(
                "Environment operation `{}` retries non-idempotent outcome `{}` after UNKNOWN_COMPLETION.",
                operation.id(),
                outcome.id()
            ),
        ));
    }
    if operation.idempotency() == IdempotencySemantics::IdempotentWithKey {
        counts.idempotency_checks += 1;
        if operation.idempotency_key_parameter() != handling.idempotency_key_parameter() {
            violations.push(violation(
                PROGRAM_RETRY_RULE_ID,
                EnvironmentalViolationKind::UnprovenIdempotencyKey,
                operation,
                Some(outcome),
                boundary,
                path,
                vec![
                    format!("required_key:{:?}", operation.idempotency_key_parameter()),
                    format!("retry_key:{:?}", handling.idempotency_key_parameter()),
                ],
                format!(
                    "Environment operation `{}` retry of `{}` does not preserve the declared idempotency key parameter.",
                    operation.id(),
                    outcome.id()
                ),
            ));
        }
    }
    EnvironmentalCoverage::Proven
}

fn duplicate_analysis(
    operation: &EnvironmentOperation,
    outcome: &ExternalOutcome,
    boundary: &ExecutableSymbol,
    path: &str,
    violations: &mut Vec<EnvironmentalViolation>,
    counts: &mut EnvironmentalCounts,
) -> EnvironmentalCoverage {
    let duplicate_possible = operation.delivery() != DeliverySemantics::AtMostOnce
        || outcome.response() == ResponseCardinality::MultipleResponses;
    if !duplicate_possible {
        return EnvironmentalCoverage::Proven;
    }
    counts.duplicate_delivery_checks += 1;
    let Some(handling) = outcome.handling() else {
        return EnvironmentalCoverage::Unknown;
    };
    match handling.duplicate_strategy() {
        DuplicateStrategy::IdempotentHandler => EnvironmentalCoverage::Proven,
        DuplicateStrategy::DeduplicationKey => {
            counts.idempotency_checks += 1;
            if operation.idempotency_key_parameter() == handling.idempotency_key_parameter() {
                EnvironmentalCoverage::Proven
            } else {
                violations.push(violation(
                    PROGRAM_RETRY_RULE_ID,
                    EnvironmentalViolationKind::UnprovenIdempotencyKey,
                    operation,
                    Some(outcome),
                    boundary,
                    path,
                    vec![
                        "delivery:duplicate_capable".into(),
                        "deduplication_key:not_proven_stable".into(),
                    ],
                    format!(
                        "Environment operation `{}` duplicate outcome `{}` lacks a stable deduplication key.",
                        operation.id(),
                        outcome.id()
                    ),
                ));
                EnvironmentalCoverage::Proven
            }
        }
        DuplicateStrategy::None => {
            violations.push(violation(
                PROGRAM_RETRY_RULE_ID,
                EnvironmentalViolationKind::DuplicateUnsafe,
                operation,
                Some(outcome),
                boundary,
                path,
                vec![
                    format!("delivery:{:?}", operation.delivery()),
                    format!("response:{:?}", outcome.response()),
                    "duplicate_strategy:NONE".into(),
                ],
                format!(
                    "Environment operation `{}` admits duplicate outcome `{}` without supported idempotent handling or deduplication.",
                    operation.id(),
                    outcome.id()
                ),
            ));
            EnvironmentalCoverage::Proven
        }
        DuplicateStrategy::Unknown => EnvironmentalCoverage::Unknown,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn recovery_analysis(
    operation: &EnvironmentOperation,
    boundary: &ExecutableSymbol,
    path: &str,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    violations: &mut Vec<EnvironmentalViolation>,
    obligations: &mut Vec<FailureTestObligation>,
    counts: &mut EnvironmentalCounts,
) -> EnvironmentalCoverage {
    match operation.atomicity() {
        AtomicitySemantics::Atomic => counts.atomic_groups += 1,
        AtomicitySemantics::NonAtomic => counts.non_atomic_groups += 1,
        AtomicitySemantics::Unknown => counts.unknown_atomicity_groups += 1,
    }
    if !operation.interruption_sensitive() {
        return EnvironmentalCoverage::Proven;
    }
    counts.interruption_checks += 1;
    obligations.push(interruption_obligation(operation, path));
    match operation.atomicity() {
        AtomicitySemantics::Atomic => EnvironmentalCoverage::Proven,
        AtomicitySemantics::Unknown => EnvironmentalCoverage::Unknown,
        AtomicitySemantics::NonAtomic => {
            let durable_steps = operation
                .effect_steps()
                .iter()
                .filter(|step| step.durable())
                .count();
            if durable_steps < 2 {
                return EnvironmentalCoverage::Partial;
            }
            counts.recovery_checks += 1;
            let Some(recovery) = operation.recovery() else {
                violations.push(violation(
                    PROGRAM_RECOVERY_RULE_ID,
                    EnvironmentalViolationKind::MissingRecovery,
                    operation,
                    None,
                    boundary,
                    path,
                    operation
                        .effect_steps()
                        .iter()
                        .map(|step| format!("durable_step:{}", step.id()))
                        .collect(),
                    format!(
                        "Interruption-sensitive operation `{}` has multiple non-atomic durable steps but no recovery continuation.",
                        operation.id()
                    ),
                ));
                return EnvironmentalCoverage::Proven;
            };
            if !symbols.contains_key(recovery.handler())
                || !reachable(operation.boundary(), recovery.handler(), adjacency)
            {
                violations.push(violation(
                    PROGRAM_RECOVERY_RULE_ID,
                    EnvironmentalViolationKind::MissingRecovery,
                    operation,
                    None,
                    boundary,
                    path,
                    vec![
                        format!("interruption_boundary:between_{}_durable_steps", durable_steps),
                        format!("recovery_handler:{}", recovery.handler()),
                        "supported_reachability:false".into(),
                    ],
                    format!(
                        "Environment operation `{}` recovery handler is not reachable from its boundary.",
                        operation.id()
                    ),
                ));
            }
            if recovery.restart() == RestartSemantics::RetryOperation
                && operation.idempotency() == IdempotencySemantics::NonIdempotent
            {
                violations.push(violation(
                    PROGRAM_RECOVERY_RULE_ID,
                    EnvironmentalViolationKind::UnsafeRecoveryRetry,
                    operation,
                    None,
                    boundary,
                    path,
                    vec![
                        "process:interrupted_after_possible_effect".into(),
                        "restart:retry_operation".into(),
                        "idempotency:NON_IDEMPOTENT".into(),
                    ],
                    format!(
                        "Environment operation `{}` recovery unsafely retries a non-idempotent operation.",
                        operation.id()
                    ),
                ));
            }
            if operation.idempotency() == IdempotencySemantics::IdempotentWithKey
                && recovery.restart() == RestartSemantics::RetryOperation
                && operation.idempotency_key_parameter() != recovery.idempotency_key_parameter()
            {
                violations.push(violation(
                    PROGRAM_RECOVERY_RULE_ID,
                    EnvironmentalViolationKind::UnprovenIdempotencyKey,
                    operation,
                    None,
                    boundary,
                    path,
                    vec![
                        format!("required_key:{:?}", operation.idempotency_key_parameter()),
                        format!("recovery_key:{:?}", recovery.idempotency_key_parameter()),
                    ],
                    format!(
                        "Environment operation `{}` recovery does not preserve the idempotency key.",
                        operation.id()
                    ),
                ));
            }
            for outcome in operation.outcomes() {
                if let Some(state) = outcome.state()
                    && recovery
                        .forbidden_states()
                        .binary_search_by(|candidate| candidate.as_str().cmp(state))
                        .is_ok()
                {
                    violations.push(violation(
                        PROGRAM_RECOVERY_RULE_ID,
                        EnvironmentalViolationKind::ForbiddenRecoveryState,
                        operation,
                        Some(outcome),
                        boundary,
                        path,
                        vec![
                            format!("outcome_state:{state}"),
                            "recovery_state:forbidden".into(),
                        ],
                        format!(
                            "Environment operation `{}` outcome `{}` may expose recovery-forbidden state `{state}`.",
                            operation.id(),
                            outcome.id()
                        ),
                    ));
                }
            }
            EnvironmentalCoverage::Proven
        }
    }
}

fn aggregate_handling(outcomes: &[EnvironmentalOutcomeSummary]) -> EnvironmentalCoverage {
    if outcomes
        .iter()
        .all(|outcome| outcome.handling == HandlingStatus::Handled)
    {
        EnvironmentalCoverage::Proven
    } else if outcomes.iter().any(|outcome| {
        matches!(
            outcome.handling,
            HandlingStatus::Handled | HandlingStatus::PartiallyHandled
        )
    }) {
        EnvironmentalCoverage::Partial
    } else {
        EnvironmentalCoverage::Unknown
    }
}

fn aggregate_coverage(
    values: impl IntoIterator<Item = EnvironmentalCoverage>,
) -> EnvironmentalCoverage {
    let values = values.into_iter().collect::<Vec<_>>();
    if values
        .iter()
        .all(|value| *value == EnvironmentalCoverage::Proven)
    {
        EnvironmentalCoverage::Proven
    } else if values.iter().any(|value| {
        matches!(
            value,
            EnvironmentalCoverage::Proven | EnvironmentalCoverage::Partial
        )
    }) {
        EnvironmentalCoverage::Partial
    } else if values.contains(&EnvironmentalCoverage::Unsupported) {
        EnvironmentalCoverage::Unsupported
    } else {
        EnvironmentalCoverage::Unknown
    }
}

fn failure_test_obligation(
    operation: &EnvironmentOperation,
    outcome: &ExternalOutcome,
    path: &str,
    continuation: Option<&str>,
) -> FailureTestObligation {
    let material = format!("{}:{}", operation.id(), outcome.id());
    FailureTestObligation {
        id: format!(
            "SCN-{}",
            &format!("{:X}", Sha256::digest(material.as_bytes()))[..16]
        ),
        operation: operation.id().into(),
        outcome: outcome.id().into(),
        injection: format!(
            "inject:{:?}:{:?}:{:?}:{:?}",
            outcome.completion(),
            outcome.response(),
            outcome.timing(),
            outcome.result()
        ),
        expected_continuation: continuation.map(str::to_owned),
        expected_state: outcome.state().map(str::to_owned),
        contract_provenance: format!("{path}#outcome={}", outcome.id()),
    }
}

fn interruption_obligation(operation: &EnvironmentOperation, path: &str) -> FailureTestObligation {
    let material = format!("{}:PROCESS_INTERRUPTED", operation.id());
    FailureTestObligation {
        id: format!(
            "SCN-{}",
            &format!("{:X}", Sha256::digest(material.as_bytes()))[..16]
        ),
        operation: operation.id().into(),
        outcome: "PROCESS_INTERRUPTED".into(),
        injection: "interrupt_between_declared_effect_steps".into(),
        expected_continuation: operation.recovery().map(|value| value.handler().into()),
        expected_state: None,
        contract_provenance: format!("{path}#operation={}", operation.id()),
    }
}

#[allow(clippy::too_many_arguments)]
fn violation(
    rule_id: &str,
    kind: EnvironmentalViolationKind,
    operation: &EnvironmentOperation,
    outcome: Option<&ExternalOutcome>,
    boundary: &ExecutableSymbol,
    path: &str,
    scenario: Vec<String>,
    message: String,
) -> EnvironmentalViolation {
    #[derive(Serialize)]
    struct Identity<'a> {
        rule_id: &'a str,
        kind: EnvironmentalViolationKind,
        operation: &'a str,
        outcome: Option<&'a str>,
        scenario: &'a [String],
    }
    let identity = Identity {
        rule_id,
        kind,
        operation: operation.id(),
        outcome: outcome.map(ExternalOutcome::id),
        scenario: &scenario,
    };
    EnvironmentalViolation {
        id: format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&identity).expect("violation identity serializes"))
        ),
        rule_id: rule_id.into(),
        kind,
        operation: operation.id().into(),
        outcome: outcome.map(|value| value.id().into()),
        boundary: operation.boundary().into(),
        scenario,
        message,
        path: path.into(),
        line: boundary.provenance().location().line(),
        column: boundary.provenance().location().column(),
    }
}

fn findings_for_rule(
    violations: &[EnvironmentalViolation],
    rule_id: &str,
    edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    violations
        .iter()
        .filter(|violation| violation.rule_id == rule_id)
        .map(|violation| finding(violation, edition))
        .collect()
}

fn finding(
    violation: &EnvironmentalViolation,
    edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let remediation = match violation.rule_id.as_str() {
        PROGRAM_ENVIRONMENT_RULE_ID => {
            "Add a defined supported continuation for every admissible outcome or correct the truthful environmental authority without deleting possible failures."
        }
        PROGRAM_RETRY_RULE_ID => {
            "Stop the retry, establish truthful idempotency, or preserve a proven stable idempotency/deduplication identity across attempts."
        }
        _ => {
            "Add a reachable recovery continuation, preserve permitted durable states, or make the effect group truthfully atomic without hiding interruption uncertainty."
        }
    };
    let definition = RuleFindingDefinition::new(
        &violation.rule_id,
        3,
        FindingCategory::Environment,
        remediation,
    )?;
    let location = FindingLocation::at_path(&violation.path)?
        .with_span(SourceSpan::new(
            violation.line.max(1),
            violation.column.max(1),
            violation.line.max(1),
            violation.column.max(1),
        )?)
        .with_symbol(&violation.boundary)?;
    let occurrence = FindingOccurrence::new(
        vec![violation.operation.clone()],
        location,
        &violation.message,
    )?;
    CanonicalFinding::failure(
        definition,
        occurrence,
        EvaluatorProvenance::new(ENVIRONMENTAL_ANALYZER_ID, ENVIRONMENTAL_ANALYSIS_VERSION)?,
        edition,
        None,
    )
}

/// Explains why environmental analysis could not be constructed.
#[derive(Debug)]
pub enum EnvironmentalAnalysisError {
    /// A validated boundary disappeared from the supplied PSM.
    MissingBoundary(String),
    /// Boundary return type disappeared from the supplied PSM.
    MissingReturnType(String),
    /// An outcome domain could not be resolved.
    Domain {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
        /// Domain detail.
        detail: String,
    },
    /// Canonical serialization failed.
    Serialization(serde_json::Error),
    /// Normalized finding construction failed.
    Finding(FindingError),
}

impl Display for EnvironmentalAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBoundary(operation) => write!(
                formatter,
                "Environmental operation `{operation}` lost its PSM boundary"
            ),
            Self::MissingReturnType(operation) => write!(
                formatter,
                "Environmental operation `{operation}` lost its PSM return type"
            ),
            Self::Domain {
                operation,
                outcome,
                detail,
            } => write!(
                formatter,
                "Environmental operation `{operation}` outcome `{outcome}` domain failed: {detail}"
            ),
            Self::Serialization(error) => {
                write!(
                    formatter,
                    "Environmental Analysis serialization failed: {error}"
                )
            }
            Self::Finding(error) => {
                write!(
                    formatter,
                    "Environmental finding normalization failed: {error}"
                )
            }
        }
    }
}

impl Error for EnvironmentalAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for EnvironmentalAnalysisError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<FindingError> for EnvironmentalAnalysisError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}
