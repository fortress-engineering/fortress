//! Function Contract and interprocedural semantic-domain analysis.
//!
//! This Module consumes PSM facts and authored Function Contract v1 sources.
//! It does not parse Rust, modify the CCG, or map functions to BFG checkpoints.

#[path = "domain.rs"]
mod domain;
#[path = "function_contract.rs"]
mod function_contract;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub use domain::{IntegerInterval, SemanticDomain};
pub use function_contract::{
    DomainSpecification, FUNCTION_CONTRACT_SCHEMA, FUNCTION_CONTRACT_SCHEMA_VERSION,
    FunctionContractError, FunctionContractSource, ResolvedFunctionContracts,
    canonicalize_function_contract_json, load_function_contracts,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::program_semantics::{
    CallResolutionState, ExecutableSymbol, ProgramBody, ProgramCall, ProgramExpression,
    ProgramPattern, ProgramProvenance, ProgramSemanticModel, ProgramStatement, ProgramType,
    SemanticType, ValueTransferKind,
};

/// Draft rule governing supported function-domain consistency.
pub const PROGRAM_DOMAIN_RULE_ID: &str = "PROGRAM-DOMAIN-001";
/// Canonical Semantic Analysis artifact schema identity.
pub const SEMANTIC_ANALYSIS_SCHEMA: &str = "urn:fortress:schema:v1:semantic-analysis";
/// Canonical Semantic Analysis artifact schema version.
pub const SEMANTIC_ANALYSIS_SCHEMA_VERSION: u16 = 1;
/// Semantic version of the abstract interpreter.
pub const SEMANTIC_ANALYSIS_VERSION: &str = "1.0.0";
/// Stable evaluator identity used by normalized findings.
pub const SEMANTIC_ANALYZER_ID: &str = "fortress-semantic-domain-analysis";

const WIDEN_AFTER_ITERATION: usize = 8;

const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_dynamic_dispatch",
    "arbitrary_pointer_provenance",
    "authentication_authorization_state",
    "behavioral_realization",
    "concurrency_interleaving_analysis",
    "cross_thread_flow",
    "database_state",
    "external_api_nondeterminism",
    "floating_point_theorem_proving",
    "general_effect_inference",
    "general_panic_freedom",
    "general_string_language_refinement",
    "heap_object_field_alias_analysis",
    "macro_generated_semantic_expansion",
    "natural_language_requirement_inference",
    "regex_domain_proof",
    "resource_typestate",
    "security_information_flow_proof",
    "smt_general_symbolic_execution",
    "taint_trust_flow",
    "units_currency_semantics",
];

fn fixed_point_iteration_limit() -> usize {
    32
}

/// Per-property epistemic state; absence of proof is never represented as safe.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalysisCoverageState {
    /// The supported semantics establish the property.
    Proven,
    /// Some relevant semantics were established and some remained uncertain.
    Partial,
    /// The model retained the full unknown domain.
    Unknown,
    /// Required semantics are outside this analyzer version.
    Unsupported,
}

/// Kind of one semantic compatibility conclusion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainCheckKind {
    /// Caller argument against callee precondition.
    CallPrecondition,
    /// Inferred return against authored postcondition.
    FunctionPostcondition,
    /// Built-in partial operation precondition.
    PartialOperation,
    /// Reachability of an impossible-state assertion.
    ImpossibleStateAssertion,
}

/// Result of one supported domain proof attempt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DomainCheck {
    id: String,
    kind: DomainCheckKind,
    producer_symbol: String,
    consumer_symbol: String,
    possible_domain: SemanticDomain,
    required_domain: SemanticDomain,
    state: AnalysisCoverageState,
    provenance: SemanticProvenance,
}

/// One exact source position supporting semantic analysis.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticProvenance {
    path: String,
    line: u32,
    column: u32,
    symbol: String,
    derivation: String,
    inputs: Vec<String>,
}

impl SemanticProvenance {
    fn from_program(
        provenance: &ProgramProvenance,
        symbol: impl Into<String>,
        derivation: impl Into<String>,
        mut inputs: Vec<String>,
    ) -> Self {
        inputs.sort();
        inputs.dedup();
        Self {
            path: provenance.path().into(),
            line: provenance.location().line(),
            column: provenance.location().column(),
            symbol: symbol.into(),
            derivation: derivation.into(),
            inputs,
        }
    }
}

/// Supported semantic contradiction with an abstract counter-domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticViolation {
    fingerprint: String,
    kind: DomainCheckKind,
    producer_symbol: String,
    consumer_symbol: String,
    producer_domain: SemanticDomain,
    required_domain: SemanticDomain,
    counter_domain: Option<SemanticDomain>,
    flow: Vec<String>,
    message: String,
    provenance: SemanticProvenance,
}

impl SemanticViolation {
    /// Returns deterministic violation identity.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the supported contradiction category.
    #[must_use]
    pub const fn kind(&self) -> DomainCheckKind {
        self.kind
    }

    /// Returns the exact abstract counter-domain when representable.
    #[must_use]
    pub const fn counter_domain(&self) -> Option<&SemanticDomain> {
        self.counter_domain.as_ref()
    }

    /// Returns the deterministic human-readable conclusion.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Property-specific coverage for one function summary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionCoverage {
    precondition_compatibility: AnalysisCoverageState,
    postcondition: AnalysisCoverageState,
    partial_operations: AnalysisCoverageState,
    heap_alias_effects: AnalysisCoverageState,
    concurrency: AnalysisCoverageState,
}

/// One deterministic function semantic summary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FunctionSemanticSummary {
    symbol: String,
    input_domains: BTreeMap<String, SemanticDomain>,
    authored_preconditions: Vec<String>,
    inferred_output_domain: SemanticDomain,
    authored_postcondition: Option<SemanticDomain>,
    postcondition_proven: bool,
    exceptional_outcomes: Vec<String>,
    callees: Vec<String>,
    unsupported_semantics: Vec<String>,
    coverage: FunctionCoverage,
    provenance: Vec<SemanticProvenance>,
}

impl FunctionSemanticSummary {
    /// Returns the PSM executable identity.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the inferred possible result domain.
    #[must_use]
    pub const fn inferred_output_domain(&self) -> &SemanticDomain {
        &self.inferred_output_domain
    }

    /// Returns property-specific proof coverage.
    #[must_use]
    pub const fn coverage(&self) -> &FunctionCoverage {
        &self.coverage
    }
}

/// Aggregate self-analysis counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SemanticAnalysisCoverage {
    functions_analyzed: usize,
    function_contracts: usize,
    function_summaries: usize,
    interprocedural_transfers: usize,
    fixed_point_iterations: usize,
    recursive_components: usize,
    precondition_checks: usize,
    postcondition_proofs: usize,
    partial_operation_checks: usize,
    proven_properties: usize,
    partial_properties: usize,
    unknown_properties: usize,
    unsupported_properties: usize,
    violations: usize,
}

impl SemanticAnalysisCoverage {
    /// Returns analyzed function count.
    #[must_use]
    pub const fn functions_analyzed(self) -> usize {
        self.functions_analyzed
    }

    /// Returns authored Function Contract count.
    #[must_use]
    pub const fn function_contracts(self) -> usize {
        self.function_contracts
    }

    /// Returns supported contradiction count.
    #[must_use]
    pub const fn violations(self) -> usize {
        self.violations
    }
}

/// Canonical Semantic Analysis v1 derived Info document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SemanticAnalysisModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: String,
    psm_digest: String,
    function_contract_digest: String,
    summaries: Vec<FunctionSemanticSummary>,
    checks: Vec<DomainCheck>,
    violations: Vec<SemanticViolation>,
    coverage: SemanticAnalysisCoverage,
    unsupported_semantics: Vec<String>,
    provenance: SemanticAnalysisProvenance,
}

impl SemanticAnalysisModel {
    /// Returns function summaries in canonical symbol order.
    #[must_use]
    pub fn summaries(&self) -> &[FunctionSemanticSummary] {
        &self.summaries
    }

    /// Returns supported semantic contradictions.
    #[must_use]
    pub fn violations(&self) -> &[SemanticViolation] {
        &self.violations
    }

    /// Returns aggregate analysis counts.
    #[must_use]
    pub const fn coverage(&self) -> SemanticAnalysisCoverage {
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
    /// Returns an error when the model cannot be serialized.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Computes SHA-256 over canonical bytes without embedding the digest.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_json()?.as_bytes())
        ))
    }
}

/// Provenance envelope binding analysis to exact authorities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SemanticAnalysisProvenance {
    psm_authority: String,
    function_contract_authority: String,
    interpretation: String,
}

/// Rule-facing evaluation of one semantic-analysis model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticAnalysisEvaluation {
    model: SemanticAnalysisModel,
    findings: Vec<CanonicalFinding>,
}

impl SemanticAnalysisEvaluation {
    /// Returns the canonical derived model.
    #[must_use]
    pub const fn model(&self) -> &SemanticAnalysisModel {
        &self.model
    }

    /// Returns normalized `PROGRAM-DOMAIN-001` findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Performs deterministic fixed-point semantic analysis over one PSM.
///
/// # Errors
///
/// Returns [`SemanticAnalysisError`] only when canonical model/finding
/// construction fails. Unsupported program semantics remain explicit coverage.
pub fn analyze_program_domains(
    psm: &ProgramSemanticModel,
    contracts: &ResolvedFunctionContracts,
    standard_edition: &str,
) -> Result<SemanticAnalysisEvaluation, SemanticAnalysisError> {
    let context = AnalysisContext::new(psm, contracts);
    let (outputs, fixed_point_iterations) = context.derive_fixed_point();
    let mut state = AnalysisState::default();
    let mut summaries = context
        .symbols
        .values()
        .map(|symbol| context.summarize(symbol, &outputs, &mut state))
        .collect::<Vec<_>>();
    summaries.sort();
    state.checks.sort();
    state.checks.dedup();
    state.violations.sort();
    state
        .violations
        .dedup_by(|left, right| left.fingerprint == right.fingerprint);
    let recursive_components = psm
        .call_topology()
        .strongly_connected_components()
        .iter()
        .filter(|component| component.is_recursive())
        .count();
    let interprocedural_transfers = psm
        .value_transfers()
        .iter()
        .filter(|transfer| {
            matches!(
                transfer.kind(),
                ValueTransferKind::ArgumentToParameter | ValueTransferKind::ReturnToConsumer
            )
        })
        .count();
    let coverage = aggregate_coverage(
        &summaries,
        contracts.len(),
        fixed_point_iterations,
        recursive_components,
        interprocedural_transfers,
        &state,
    );
    let model = SemanticAnalysisModel {
        schema: SEMANTIC_ANALYSIS_SCHEMA.into(),
        schema_version: SEMANTIC_ANALYSIS_SCHEMA_VERSION,
        semantic_version: SEMANTIC_ANALYSIS_VERSION.into(),
        project_id: psm.project_id().into(),
        psm_digest: psm.digest().map_err(SemanticAnalysisError::Serialization)?,
        function_contract_digest: contracts.digest().into(),
        summaries,
        checks: state.checks,
        violations: state.violations,
        coverage,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
        provenance: SemanticAnalysisProvenance {
            psm_authority: "canonical_program_semantic_model_v1".into(),
            function_contract_authority: "distributed_function_contract_v1".into(),
            interpretation: "deterministic_abstract_interpretation_fixed_point".into(),
        },
    };
    let findings = model
        .violations
        .iter()
        .map(|violation| finding_from_violation(violation, standard_edition))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SemanticAnalysisEvaluation { model, findings })
}

struct AnalysisContext<'a> {
    psm: &'a ProgramSemanticModel,
    contracts: &'a ResolvedFunctionContracts,
    symbols: BTreeMap<&'a str, &'a ExecutableSymbol>,
    types: BTreeMap<&'a str, &'a ProgramType>,
    bodies: BTreeMap<&'a str, &'a ProgramBody>,
    local_types: BTreeMap<(&'a str, &'a str), &'a str>,
}

impl<'a> AnalysisContext<'a> {
    fn new(psm: &'a ProgramSemanticModel, contracts: &'a ResolvedFunctionContracts) -> Self {
        let symbols = psm
            .symbols()
            .iter()
            .map(|symbol| (symbol.id(), symbol))
            .collect();
        let types = psm
            .types()
            .iter()
            .map(|value| (value.id(), value))
            .collect();
        let bodies = psm
            .bodies()
            .iter()
            .map(|body| (body.symbol(), body))
            .collect();
        let local_types = psm
            .value_transfers()
            .iter()
            .filter(|transfer| {
                matches!(
                    transfer.kind(),
                    ValueTransferKind::ParameterToBinding
                        | ValueTransferKind::ExpressionToBinding
                        | ValueTransferKind::Assignment
                )
            })
            .filter_map(|transfer| {
                transfer.consumer().static_type().map(|type_id| {
                    (
                        (transfer.consumer().symbol(), transfer.consumer().name()),
                        type_id,
                    )
                })
            })
            .collect();
        Self {
            psm,
            contracts,
            symbols,
            types,
            bodies,
            local_types,
        }
    }

    fn static_domain(&self, type_id: &str) -> SemanticDomain {
        self.types.get(type_id).map_or_else(
            || SemanticDomain::Top {
                type_id: type_id.into(),
            },
            |value| SemanticDomain::from_static_type(type_id, value.semantic()),
        )
    }

    fn contract_input_domains(
        &self,
        symbol: &ExecutableSymbol,
    ) -> BTreeMap<String, SemanticDomain> {
        let contract = self.contracts.get(symbol.id());
        symbol
            .parameters()
            .iter()
            .map(|parameter| {
                let full = self.static_domain(parameter.parameter_type().type_id());
                let domain = contract
                    .and_then(|contract| {
                        contract
                            .requires()
                            .iter()
                            .find(|requirement| requirement.parameter() == parameter.name())
                    })
                    .and_then(|requirement| {
                        self.types
                            .get(parameter.parameter_type().type_id())
                            .and_then(|type_fact| {
                                function_contract::resolve_domain(requirement.domain(), type_fact)
                                    .ok()
                            })
                    })
                    .unwrap_or(full);
                (parameter.name().into(), domain)
            })
            .collect()
    }

    fn contract_output_domain(&self, symbol: &ExecutableSymbol) -> Option<SemanticDomain> {
        let guarantee = self.contracts.get(symbol.id())?.return_guarantee()?;
        let type_fact = self.types.get(symbol.return_type().type_id())?;
        function_contract::resolve_domain(guarantee.domain(), type_fact).ok()
    }

    fn derive_fixed_point(&self) -> (BTreeMap<String, SemanticDomain>, usize) {
        let mut outputs = self
            .symbols
            .values()
            .map(|symbol| {
                let output = if self.bodies.contains_key(symbol.id()) {
                    SemanticDomain::bottom(symbol.return_type().type_id())
                } else {
                    self.static_domain(symbol.return_type().type_id())
                };
                (symbol.id().into(), output)
            })
            .collect::<BTreeMap<_, _>>();
        for iteration in 1..=fixed_point_iteration_limit() {
            let mut changed = false;
            let mut next = outputs.clone();
            for symbol in self.symbols.values() {
                let mut discarded = AnalysisState::default();
                let inferred = self.interpret_symbol(symbol, &outputs, &mut discarded);
                let previous = outputs
                    .get(symbol.id())
                    .expect("every PSM symbol has an initialized summary");
                let joined = if iteration > WIDEN_AFTER_ITERATION {
                    previous.widen(&inferred)
                } else {
                    previous.join(&inferred)
                };
                if &joined != previous {
                    next.insert(symbol.id().into(), joined);
                    changed = true;
                }
            }
            outputs = next;
            if !changed {
                return (outputs, iteration);
            }
        }
        (outputs, fixed_point_iteration_limit())
    }

    #[allow(clippy::too_many_lines)]
    fn summarize(
        &self,
        symbol: &ExecutableSymbol,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
    ) -> FunctionSemanticSummary {
        let input_domains = self.contract_input_domains(symbol);
        let start_checks = state.checks.len();
        let start_violations = state.violations.len();
        let inferred_output_domain = self.interpret_symbol(symbol, outputs, state);
        let authored_postcondition = self.contract_output_domain(symbol);
        let postcondition_proven = authored_postcondition
            .as_ref()
            .is_none_or(|required| inferred_output_domain.is_subset_of(required));
        if let Some(required) = &authored_postcondition {
            let provenance =
                symbol_provenance(symbol, "function_postcondition", vec![symbol.id().into()]);
            state.add_check(
                DomainCheckKind::FunctionPostcondition,
                symbol.id(),
                symbol.id(),
                inferred_output_domain.clone(),
                required.clone(),
                if postcondition_proven {
                    AnalysisCoverageState::Proven
                } else {
                    AnalysisCoverageState::Partial
                },
                provenance,
                vec![symbol.id().into(), "return".into()],
            );
        }
        let local_checks = &state.checks[start_checks..];
        let local_violation = state.violations.len() > start_violations;
        let unsupported = self.symbol_unsupported(symbol);
        let precondition_compatibility = coverage_for_checks(
            local_checks
                .iter()
                .filter(|check| check.kind == DomainCheckKind::CallPrecondition),
            local_violation,
            !unsupported.is_empty(),
        );
        let partial_operations = coverage_for_checks(
            local_checks.iter().filter(|check| {
                matches!(
                    check.kind,
                    DomainCheckKind::PartialOperation | DomainCheckKind::ImpossibleStateAssertion
                )
            }),
            local_violation,
            !unsupported.is_empty(),
        );
        let postcondition = if authored_postcondition.is_none() {
            AnalysisCoverageState::Unknown
        } else if postcondition_proven {
            AnalysisCoverageState::Proven
        } else {
            AnalysisCoverageState::Partial
        };
        let mut exceptional_outcomes = state
            .exceptional
            .get(symbol.id())
            .cloned()
            .unwrap_or_default();
        exceptional_outcomes.sort();
        exceptional_outcomes.dedup();
        let callees = self
            .psm
            .calls()
            .iter()
            .filter(|call| call.caller() == symbol.id())
            .filter_map(ProgramCall::callee)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        FunctionSemanticSummary {
            symbol: symbol.id().into(),
            input_domains,
            authored_preconditions: self.contracts.get(symbol.id()).map_or_else(
                Vec::new,
                |contract| {
                    contract
                        .requires()
                        .iter()
                        .map(|requirement| requirement.parameter().into())
                        .collect()
                },
            ),
            inferred_output_domain,
            authored_postcondition,
            postcondition_proven,
            exceptional_outcomes,
            callees,
            unsupported_semantics: unsupported,
            coverage: FunctionCoverage {
                precondition_compatibility,
                postcondition,
                partial_operations,
                heap_alias_effects: AnalysisCoverageState::Unsupported,
                concurrency: AnalysisCoverageState::Unsupported,
            },
            provenance: vec![symbol_provenance(
                symbol,
                "function_summary",
                vec![symbol.id().into()],
            )],
        }
    }

    fn symbol_unsupported(&self, symbol: &ExecutableSymbol) -> Vec<String> {
        let mut unsupported = self
            .psm
            .calls()
            .iter()
            .filter(|call| call.caller() == symbol.id())
            .filter_map(|call| match call.state() {
                CallResolutionState::DynamicDispatch => Some("dynamic_dispatch"),
                CallResolutionState::Unresolved => Some("unresolved_call_target"),
                CallResolutionState::Unsupported => Some("unsupported_call_semantics"),
                CallResolutionState::Invalid => Some("invalid_call_semantics"),
                CallResolutionState::ResolvedStatic | CallResolutionState::External => None,
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        unsupported.sort();
        unsupported.dedup();
        unsupported
    }

    fn interpret_symbol(
        &self,
        symbol: &ExecutableSymbol,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
    ) -> SemanticDomain {
        let Some(body) = self.bodies.get(symbol.id()) else {
            return self.static_domain(symbol.return_type().type_id());
        };
        let environment = Environment {
            values: self.contract_input_domains(symbol),
            reachable: true,
        };
        let mut output = SemanticDomain::bottom(symbol.return_type().type_id());
        self.interpret_statements(
            symbol,
            body.statements(),
            environment,
            outputs,
            state,
            &mut output,
        );
        if output.is_bottom()
            && matches!(
                self.types
                    .get(symbol.return_type().type_id())
                    .map(|value| value.semantic()),
                Some(SemanticType::Unit)
            )
        {
            return self.static_domain(symbol.return_type().type_id());
        }
        output
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    fn interpret_statements(
        &self,
        symbol: &ExecutableSymbol,
        statements: &[ProgramStatement],
        mut environment: Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        output: &mut SemanticDomain,
    ) -> Environment {
        for statement in statements {
            if !environment.reachable {
                break;
            }
            match statement {
                ProgramStatement::Let {
                    pattern,
                    value,
                    provenance,
                } => {
                    if let Some(value) = value {
                        let expected = pattern_binding(pattern)
                            .and_then(|name| self.local_types.get(&(symbol.id(), name)).copied());
                        let domain = self.evaluate_expression(
                            symbol,
                            value,
                            expected,
                            &environment,
                            outputs,
                            state,
                            provenance,
                        );
                        bind_pattern(pattern, &domain, &mut environment);
                    }
                }
                ProgramStatement::Assign {
                    target,
                    value,
                    provenance,
                } => {
                    let expected = self
                        .local_types
                        .get(&(symbol.id(), target.as_str()))
                        .copied();
                    let domain = self.evaluate_expression(
                        symbol,
                        value,
                        expected,
                        &environment,
                        outputs,
                        state,
                        provenance,
                    );
                    if is_simple_binding(target) {
                        environment.values.insert(target.clone(), domain);
                    }
                }
                ProgramStatement::Expression { value, provenance } => {
                    let _ = self.evaluate_expression(
                        symbol,
                        value,
                        None,
                        &environment,
                        outputs,
                        state,
                        provenance,
                    );
                }
                ProgramStatement::Return { value, provenance } => {
                    let domain = value.as_ref().map_or_else(
                        || self.static_domain(symbol.return_type().type_id()),
                        |value| {
                            self.evaluate_expression(
                                symbol,
                                value,
                                Some(symbol.return_type().type_id()),
                                &environment,
                                outputs,
                                state,
                                provenance,
                            )
                        },
                    );
                    *output = output.join(&domain);
                    environment.reachable = false;
                }
                ProgramStatement::If {
                    condition,
                    then_branch,
                    else_branch,
                    provenance: _,
                } => {
                    let (then_environment, else_environment) =
                        Self::refine_condition(condition, &environment);
                    let then_result = self.interpret_statements(
                        symbol,
                        then_branch,
                        then_environment,
                        outputs,
                        state,
                        output,
                    );
                    let else_result = self.interpret_statements(
                        symbol,
                        else_branch,
                        else_environment,
                        outputs,
                        state,
                        output,
                    );
                    environment = then_result.join(&else_result);
                }
                ProgramStatement::Match {
                    value,
                    arms,
                    provenance,
                } => {
                    let source_domain = self.evaluate_expression(
                        symbol,
                        value,
                        None,
                        &environment,
                        outputs,
                        state,
                        provenance,
                    );
                    let binding = expression_binding(value);
                    let mut joined: Option<Environment> = None;
                    for arm in arms {
                        let mut arm_environment = environment.clone();
                        let matched = domain_for_pattern(arm.pattern(), &source_domain);
                        if matched.is_bottom() {
                            arm_environment.reachable = false;
                        }
                        if let Some(binding) = binding {
                            arm_environment
                                .values
                                .insert(binding.into(), matched.clone());
                        }
                        bind_pattern(arm.pattern(), &matched, &mut arm_environment);
                        if let Some(guard) = arm.guard() {
                            arm_environment = Self::refine_condition(guard, &arm_environment).0;
                        }
                        let result = self.interpret_statements(
                            symbol,
                            arm.body(),
                            arm_environment,
                            outputs,
                            state,
                            output,
                        );
                        joined = Some(joined.map_or(result.clone(), |value| value.join(&result)));
                    }
                    environment = joined.unwrap_or_else(Environment::unreachable);
                }
                ProgramStatement::WhileLet {
                    pattern,
                    value,
                    body,
                    provenance,
                } => {
                    let mut loop_environment = environment.clone();
                    for iteration in 0..WIDEN_AFTER_ITERATION {
                        let source_domain = self.evaluate_expression(
                            symbol,
                            value,
                            None,
                            &loop_environment,
                            outputs,
                            state,
                            provenance,
                        );
                        let matched = domain_for_pattern(pattern, &source_domain);
                        let mut entered = loop_environment.clone();
                        bind_pattern(pattern, &matched, &mut entered);
                        if matched.is_bottom() {
                            entered.reachable = false;
                        }
                        let next = self
                            .interpret_statements(symbol, body, entered, outputs, state, output);
                        let joined = if iteration + 1 == WIDEN_AFTER_ITERATION {
                            loop_environment.widen(&next)
                        } else {
                            loop_environment.join(&next)
                        };
                        if joined == loop_environment {
                            break;
                        }
                        loop_environment = joined;
                    }
                    environment = environment.join(&loop_environment);
                }
            }
        }
        environment
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    fn evaluate_expression(
        &self,
        symbol: &ExecutableSymbol,
        expression: &ProgramExpression,
        expected_type: Option<&str>,
        environment: &Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        let fallback_type = expected_type.unwrap_or("type:unknown");
        match expression {
            ProgramExpression::Binding { name } => environment
                .values
                .get(name)
                .cloned()
                .unwrap_or_else(|| self.static_domain(fallback_type)),
            ProgramExpression::Boolean { value } => {
                SemanticDomain::boolean(fallback_type, [*value])
            }
            ProgramExpression::Integer { value } => parse_integer(value).map_or_else(
                || self.static_domain(fallback_type),
                |value| {
                    SemanticDomain::integer(
                        fallback_type,
                        [IntegerInterval::new(value, value).expect("equal bounds are valid")],
                        [],
                    )
                },
            ),
            ProgramExpression::Unit => self.static_domain(fallback_type),
            ProgramExpression::Variant { name } => {
                if last_path_segment(name) == "None"
                    && let Some(SemanticType::Option { value }) =
                        self.types.get(fallback_type).map(|value| value.semantic())
                {
                    return SemanticDomain::Option {
                        type_id: fallback_type.into(),
                        none: true,
                        some: Box::new(SemanticDomain::bottom(nested_type_id(value))),
                    };
                }
                SemanticDomain::Enum {
                    type_id: fallback_type.into(),
                    variants: [(last_path_segment(name).into(), None)]
                        .into_iter()
                        .collect(),
                }
            }
            ProgramExpression::Tuple { elements } => {
                let static_elements = self.types.get(fallback_type).and_then(|value| {
                    if let SemanticType::Tuple { elements } = value.semantic() {
                        Some(elements)
                    } else {
                        None
                    }
                });
                SemanticDomain::Tuple {
                    type_id: fallback_type.into(),
                    elements: elements
                        .iter()
                        .enumerate()
                        .map(|(index, element)| {
                            let element_type = static_elements
                                .and_then(|elements| elements.get(index))
                                .map(nested_type_id);
                            self.evaluate_expression(
                                symbol,
                                element,
                                element_type.as_deref(),
                                environment,
                                outputs,
                                state,
                                provenance,
                            )
                        })
                        .collect(),
                }
            }
            ProgramExpression::Construction {
                constructor,
                arguments,
            } => self.evaluate_construction(
                symbol,
                constructor,
                arguments,
                fallback_type,
                environment,
                outputs,
                state,
                provenance,
            ),
            ProgramExpression::PatternTest { .. } => {
                SemanticDomain::boolean(fallback_type, [false, true])
            }
            ProgramExpression::Call {
                reference,
                arguments,
            } => self.evaluate_call(
                symbol,
                reference,
                arguments,
                fallback_type,
                environment,
                outputs,
                state,
                provenance,
            ),
            ProgramExpression::MethodCall {
                receiver,
                method,
                arguments,
            } => self.evaluate_method_call(
                symbol,
                receiver,
                method,
                arguments,
                fallback_type,
                environment,
                outputs,
                state,
                provenance,
            ),
            ProgramExpression::Binary {
                operator,
                left,
                right,
            } => self.evaluate_binary(
                symbol,
                operator,
                left,
                right,
                fallback_type,
                environment,
                outputs,
                state,
                provenance,
            ),
            ProgramExpression::Unary { operator, value } if operator == "!" => {
                let value = self.evaluate_expression(
                    symbol,
                    value,
                    expected_type,
                    environment,
                    outputs,
                    state,
                    provenance,
                );
                if let SemanticDomain::Boolean { type_id, values } = value {
                    SemanticDomain::boolean(type_id, values.into_iter().map(|value| !value))
                } else {
                    self.static_domain(fallback_type)
                }
            }
            ProgramExpression::Try { value } => {
                let value = self.evaluate_expression(
                    symbol,
                    value,
                    None,
                    environment,
                    outputs,
                    state,
                    provenance,
                );
                match value {
                    SemanticDomain::Result { ok, .. } => *ok,
                    _ => self.static_domain(fallback_type),
                }
            }
            ProgramExpression::Reference { value, .. } => {
                let _ = self.evaluate_expression(
                    symbol,
                    value,
                    None,
                    environment,
                    outputs,
                    state,
                    provenance,
                );
                self.static_domain(fallback_type)
            }
            ProgramExpression::Exceptional { operation } => {
                if operation == "unreachable" {
                    let possible = SemanticDomain::Top {
                        type_id: "type:control_reachability".into(),
                    };
                    let required = SemanticDomain::bottom("type:control_reachability");
                    state.add_check(
                        DomainCheckKind::ImpossibleStateAssertion,
                        symbol.id(),
                        symbol.id(),
                        possible,
                        required,
                        AnalysisCoverageState::Partial,
                        SemanticProvenance::from_program(
                            provenance,
                            symbol.id(),
                            "reachable_impossible_state_assertion",
                            vec![symbol.id().into()],
                        ),
                        vec![symbol.id().into(), "unreachable!".into()],
                    );
                } else {
                    state
                        .exceptional
                        .entry(symbol.id().into())
                        .or_default()
                        .push("reachable_panic".into());
                }
                SemanticDomain::bottom(fallback_type)
            }
            ProgramExpression::Unsupported { .. } | ProgramExpression::Unary { .. } => {
                self.static_domain(fallback_type)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_construction(
        &self,
        symbol: &ExecutableSymbol,
        constructor: &str,
        arguments: &[ProgramExpression],
        expected_type: &str,
        environment: &Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        match last_path_segment(constructor) {
            "Some" => {
                let payload_type = self.types.get(expected_type).and_then(|value| {
                    if let SemanticType::Option { value } = value.semantic() {
                        Some(nested_type_id(value))
                    } else {
                        None
                    }
                });
                let payload = arguments.first().map_or_else(
                    || SemanticDomain::Top {
                        type_id: payload_type
                            .clone()
                            .unwrap_or_else(|| "type:unknown".into()),
                    },
                    |value| {
                        self.evaluate_expression(
                            symbol,
                            value,
                            payload_type.as_deref(),
                            environment,
                            outputs,
                            state,
                            provenance,
                        )
                    },
                );
                SemanticDomain::Option {
                    type_id: expected_type.into(),
                    none: false,
                    some: Box::new(payload),
                }
            }
            "Ok" | "Err" => {
                let types = self.types.get(expected_type).and_then(|value| {
                    if let SemanticType::Result { success, error } = value.semantic() {
                        Some((nested_type_id(success), nested_type_id(error)))
                    } else {
                        None
                    }
                });
                let ok_type = types
                    .as_ref()
                    .map_or("type:unknown", |value| value.0.as_str());
                let err_type = types
                    .as_ref()
                    .map_or("type:unknown", |value| value.1.as_str());
                let payload_type = if last_path_segment(constructor) == "Ok" {
                    ok_type
                } else {
                    err_type
                };
                let payload = arguments.first().map_or_else(
                    || self.static_domain(payload_type),
                    |value| {
                        self.evaluate_expression(
                            symbol,
                            value,
                            Some(payload_type),
                            environment,
                            outputs,
                            state,
                            provenance,
                        )
                    },
                );
                SemanticDomain::Result {
                    type_id: expected_type.into(),
                    ok: Box::new(if last_path_segment(constructor) == "Ok" {
                        payload.clone()
                    } else {
                        SemanticDomain::bottom(ok_type)
                    }),
                    err: Box::new(if last_path_segment(constructor) == "Err" {
                        payload
                    } else {
                        SemanticDomain::bottom(err_type)
                    }),
                }
            }
            variant => SemanticDomain::Enum {
                type_id: expected_type.into(),
                variants: [(variant.into(), None)].into_iter().collect(),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_call(
        &self,
        caller: &ExecutableSymbol,
        reference: &str,
        arguments: &[ProgramExpression],
        expected_type: &str,
        environment: &Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        let resolved = self.psm.calls().iter().find(|call| {
            call.caller() == caller.id()
                && call.state() == CallResolutionState::ResolvedStatic
                && call
                    .evidence()
                    .iter()
                    .any(|evidence| evidence.reference() == reference)
        });
        let Some(callee_id) = resolved.and_then(ProgramCall::callee) else {
            for argument in arguments {
                let _ = self.evaluate_expression(
                    caller,
                    argument,
                    None,
                    environment,
                    outputs,
                    state,
                    provenance,
                );
            }
            return self.static_domain(expected_type);
        };
        let Some(target_symbol) = self.symbols.get(callee_id) else {
            return self.static_domain(expected_type);
        };
        for (argument, parameter) in arguments.iter().zip(target_symbol.parameters()) {
            let possible = self.evaluate_expression(
                caller,
                argument,
                Some(parameter.parameter_type().type_id()),
                environment,
                outputs,
                state,
                provenance,
            );
            let Some(requirement) = self.contracts.get(target_symbol.id()).and_then(|contract| {
                contract
                    .requires()
                    .iter()
                    .find(|requirement| requirement.parameter() == parameter.name())
            }) else {
                continue;
            };
            let Some(required) = self
                .types
                .get(parameter.parameter_type().type_id())
                .and_then(|type_fact| {
                    function_contract::resolve_domain(requirement.domain(), type_fact).ok()
                })
            else {
                continue;
            };
            state.add_check(
                DomainCheckKind::CallPrecondition,
                caller.id(),
                target_symbol.id(),
                possible,
                required,
                AnalysisCoverageState::Proven,
                SemanticProvenance::from_program(
                    provenance,
                    caller.id(),
                    "argument_to_parameter_precondition",
                    vec![
                        caller.id().into(),
                        target_symbol.id().into(),
                        parameter.name().into(),
                    ],
                ),
                vec![
                    caller.id().into(),
                    format!("argument:{reference}"),
                    format!("{}:{}", target_symbol.id(), parameter.name()),
                ],
            );
        }
        outputs
            .get(target_symbol.id())
            .cloned()
            .unwrap_or_else(|| self.static_domain(target_symbol.return_type().type_id()))
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_method_call(
        &self,
        symbol: &ExecutableSymbol,
        receiver: &ProgramExpression,
        method: &str,
        arguments: &[ProgramExpression],
        expected_type: &str,
        environment: &Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        let receiver_domain = self.evaluate_expression(
            symbol,
            receiver,
            None,
            environment,
            outputs,
            state,
            provenance,
        );
        let receiver_coverage = expression_domain_coverage(symbol, receiver);
        for argument in arguments {
            let _ = self.evaluate_expression(
                symbol,
                argument,
                None,
                environment,
                outputs,
                state,
                provenance,
            );
        }
        match method {
            "is_some" => match receiver_domain {
                SemanticDomain::Option { none, some, .. } => SemanticDomain::boolean(
                    expected_type,
                    [(!some.is_bottom()).then_some(true), none.then_some(false)]
                        .into_iter()
                        .flatten(),
                ),
                _ => SemanticDomain::boolean(expected_type, [false, true]),
            },
            "is_none" => match receiver_domain {
                SemanticDomain::Option { none, some, .. } => SemanticDomain::boolean(
                    expected_type,
                    [(none).then_some(true), (!some.is_bottom()).then_some(false)]
                        .into_iter()
                        .flatten(),
                ),
                _ => SemanticDomain::boolean(expected_type, [false, true]),
            },
            "is_ok" => match receiver_domain {
                SemanticDomain::Result { ok, err, .. } => SemanticDomain::boolean(
                    expected_type,
                    [
                        (!ok.is_bottom()).then_some(true),
                        (!err.is_bottom()).then_some(false),
                    ]
                    .into_iter()
                    .flatten(),
                ),
                _ => SemanticDomain::boolean(expected_type, [false, true]),
            },
            "is_err" => match receiver_domain {
                SemanticDomain::Result { ok, err, .. } => SemanticDomain::boolean(
                    expected_type,
                    [
                        (!err.is_bottom()).then_some(true),
                        (!ok.is_bottom()).then_some(false),
                    ]
                    .into_iter()
                    .flatten(),
                ),
                _ => SemanticDomain::boolean(expected_type, [false, true]),
            },
            "unwrap" | "expect" => self.evaluate_unwrap(
                symbol,
                method,
                receiver_domain,
                expected_type,
                receiver_coverage,
                state,
                provenance,
            ),
            _ => self.static_domain(expected_type),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_unwrap(
        &self,
        symbol: &ExecutableSymbol,
        method: &str,
        receiver: SemanticDomain,
        expected_type: &str,
        coverage: AnalysisCoverageState,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        let (possible, required, output) = match receiver.clone() {
            SemanticDomain::Option { type_id, some, .. } => (
                receiver,
                SemanticDomain::Option {
                    type_id,
                    none: false,
                    some: Box::new(self.static_domain(some.type_id())),
                },
                *some,
            ),
            SemanticDomain::Result {
                type_id, ok, err, ..
            } => (
                receiver,
                SemanticDomain::Result {
                    type_id,
                    ok: Box::new(self.static_domain(ok.type_id())),
                    err: Box::new(SemanticDomain::bottom(err.type_id())),
                },
                *ok,
            ),
            _ => return self.static_domain(expected_type),
        };
        state.add_check(
            DomainCheckKind::PartialOperation,
            symbol.id(),
            format!("rust::{method}"),
            possible,
            required,
            coverage,
            SemanticProvenance::from_program(
                provenance,
                symbol.id(),
                "builtin_partial_operation",
                vec![symbol.id().into(), format!("rust::{method}")],
            ),
            vec![symbol.id().into(), format!("rust::{method}")],
        );
        output
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_binary(
        &self,
        symbol: &ExecutableSymbol,
        operator: &str,
        left: &ProgramExpression,
        right: &ProgramExpression,
        expected_type: &str,
        environment: &Environment,
        outputs: &BTreeMap<String, SemanticDomain>,
        state: &mut AnalysisState,
        provenance: &ProgramProvenance,
    ) -> SemanticDomain {
        let left_domain = self.evaluate_expression(
            symbol,
            left,
            expected_type.into(),
            environment,
            outputs,
            state,
            provenance,
        );
        let right_domain = self.evaluate_expression(
            symbol,
            right,
            Some(left_domain.type_id()),
            environment,
            outputs,
            state,
            provenance,
        );
        match operator {
            "==" | "!=" | "<" | "<=" | ">" | ">=" => {
                SemanticDomain::boolean(expected_type, [false, true])
            }
            "/" | "%" => {
                if let SemanticDomain::Integer {
                    type_id,
                    intervals,
                    excluded,
                } = &right_domain
                {
                    let nonzero = SemanticDomain::integer(
                        type_id,
                        intervals.iter().copied(),
                        excluded.iter().copied().chain([0]),
                    );
                    state.add_check(
                        DomainCheckKind::PartialOperation,
                        symbol.id(),
                        format!("rust::integer_{operator}"),
                        right_domain,
                        nonzero,
                        expression_domain_coverage(symbol, right),
                        SemanticProvenance::from_program(
                            provenance,
                            symbol.id(),
                            "integer_nonzero_denominator",
                            vec![symbol.id().into(), operator.into()],
                        ),
                        vec![symbol.id().into(), format!("denominator:{operator}")],
                    );
                }
                left_domain
            }
            "+" | "-" | "*" => integer_arithmetic(operator, &left_domain, &right_domain)
                .unwrap_or_else(|| self.static_domain(expected_type)),
            _ => self.static_domain(expected_type),
        }
    }

    fn refine_condition(
        condition: &ProgramExpression,
        environment: &Environment,
    ) -> (Environment, Environment) {
        let mut then_environment = environment.clone();
        let mut else_environment = environment.clone();
        match condition {
            ProgramExpression::Binding { name } => {
                refine_boolean_binding(name, true, &mut then_environment);
                refine_boolean_binding(name, false, &mut else_environment);
            }
            ProgramExpression::Unary { operator, value } if operator == "!" => {
                let (false_branch, true_branch) = Self::refine_condition(value, environment);
                return (true_branch, false_branch);
            }
            ProgramExpression::MethodCall {
                receiver,
                method,
                arguments,
            } if arguments.is_empty() => {
                if let Some(binding) = expression_binding(receiver) {
                    refine_wrapper_binding(binding, method, true, &mut then_environment);
                    refine_wrapper_binding(binding, method, false, &mut else_environment);
                }
            }
            ProgramExpression::PatternTest { pattern, value } => {
                if let Some(binding) = expression_binding(value)
                    && let Some(domain) = environment.values.get(binding)
                {
                    let matched = domain_for_pattern(pattern, domain);
                    let remaining = domain
                        .difference(&matched)
                        .unwrap_or_else(|| domain.clone());
                    then_environment.values.insert(binding.into(), matched);
                    else_environment.values.insert(binding.into(), remaining);
                }
            }
            ProgramExpression::Binary {
                operator,
                left,
                right,
            } => refine_comparison(
                operator,
                left,
                right,
                &mut then_environment,
                &mut else_environment,
            ),
            _ => {}
        }
        then_environment.normalize_reachability();
        else_environment.normalize_reachability();
        (then_environment, else_environment)
    }
}

fn expression_domain_coverage(
    symbol: &ExecutableSymbol,
    expression: &ProgramExpression,
) -> AnalysisCoverageState {
    match expression {
        ProgramExpression::Binding { name }
            if symbol
                .parameters()
                .iter()
                .any(|parameter| parameter.name() == name) =>
        {
            AnalysisCoverageState::Proven
        }
        ProgramExpression::Boolean { .. }
        | ProgramExpression::Integer { .. }
        | ProgramExpression::Unit
        | ProgramExpression::Variant { .. }
        | ProgramExpression::Tuple { .. }
        | ProgramExpression::Construction { .. } => AnalysisCoverageState::Proven,
        ProgramExpression::Call { .. }
        | ProgramExpression::MethodCall { .. }
        | ProgramExpression::Binding { .. }
        | ProgramExpression::PatternTest { .. }
        | ProgramExpression::Binary { .. }
        | ProgramExpression::Unary { .. }
        | ProgramExpression::Try { .. }
        | ProgramExpression::Reference { .. }
        | ProgramExpression::Exceptional { .. }
        | ProgramExpression::Unsupported { .. } => AnalysisCoverageState::Unknown,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AnalysisState {
    checks: Vec<DomainCheck>,
    violations: Vec<SemanticViolation>,
    exceptional: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct ViolationIdentity<'a> {
    kind: DomainCheckKind,
    producer_symbol: &'a str,
    consumer_symbol: &'a str,
    producer_domain: &'a SemanticDomain,
    required_domain: &'a SemanticDomain,
    counter_domain: &'a Option<SemanticDomain>,
    flow: &'a [String],
    provenance: &'a SemanticProvenance,
}

impl AnalysisState {
    #[allow(clippy::too_many_arguments)]
    fn add_check(
        &mut self,
        kind: DomainCheckKind,
        producer_symbol: impl Into<String>,
        consumer_symbol: impl Into<String>,
        possible_domain: SemanticDomain,
        required_domain: SemanticDomain,
        requested_state: AnalysisCoverageState,
        provenance: SemanticProvenance,
        flow: Vec<String>,
    ) {
        let producer_symbol = producer_symbol.into();
        let consumer_symbol = consumer_symbol.into();
        let state = if possible_domain.is_subset_of(&required_domain) {
            AnalysisCoverageState::Proven
        } else {
            requested_state
        };
        let id = fact_id(
            "domain_check",
            &(
                kind,
                &producer_symbol,
                &consumer_symbol,
                &possible_domain,
                &required_domain,
                &provenance,
            ),
        );
        self.checks.push(DomainCheck {
            id,
            kind,
            producer_symbol: producer_symbol.clone(),
            consumer_symbol: consumer_symbol.clone(),
            possible_domain: possible_domain.clone(),
            required_domain: required_domain.clone(),
            state,
            provenance: provenance.clone(),
        });
        if possible_domain.is_subset_of(&required_domain)
            || matches!(
                requested_state,
                AnalysisCoverageState::Unknown | AnalysisCoverageState::Unsupported
            )
        {
            return;
        }
        let counter_domain = possible_domain.difference(&required_domain);
        let message = format!(
            "possible domain from `{producer_symbol}` is not a subset of the domain required by `{consumer_symbol}`"
        );
        let fingerprint = fact_id(
            "semantic_violation",
            &ViolationIdentity {
                kind,
                producer_symbol: &producer_symbol,
                consumer_symbol: &consumer_symbol,
                producer_domain: &possible_domain,
                required_domain: &required_domain,
                counter_domain: &counter_domain,
                flow: &flow,
                provenance: &provenance,
            },
        );
        self.violations.push(SemanticViolation {
            fingerprint,
            kind,
            producer_symbol,
            consumer_symbol,
            producer_domain: possible_domain,
            required_domain,
            counter_domain,
            flow,
            message,
            provenance,
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Environment {
    values: BTreeMap<String, SemanticDomain>,
    reachable: bool,
}

impl Environment {
    fn unreachable() -> Self {
        Self {
            values: BTreeMap::new(),
            reachable: false,
        }
    }

    fn join(&self, other: &Self) -> Self {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }
        let names = self
            .values
            .keys()
            .chain(other.values.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            values: names
                .into_iter()
                .filter_map(
                    |name| match (self.values.get(&name), other.values.get(&name)) {
                        (Some(left), Some(right)) => Some((name, left.join(right))),
                        (Some(value), None) | (None, Some(value)) => Some((name, value.clone())),
                        (None, None) => None,
                    },
                )
                .collect(),
            reachable: true,
        }
    }

    fn widen(&self, other: &Self) -> Self {
        let mut joined = self.join(other);
        for (name, value) in &mut joined.values {
            if let (Some(previous), Some(next)) = (self.values.get(name), other.values.get(name)) {
                *value = previous.widen(next);
            }
        }
        joined
    }

    fn normalize_reachability(&mut self) {
        if self.values.values().any(SemanticDomain::is_bottom) {
            self.reachable = false;
        }
    }
}

fn refine_boolean_binding(name: &str, value: bool, environment: &mut Environment) {
    let Some(current) = environment.values.get(name) else {
        return;
    };
    let required = SemanticDomain::boolean(current.type_id(), [value]);
    environment
        .values
        .insert(name.into(), current.intersection(&required));
}

fn refine_wrapper_binding(name: &str, predicate: &str, truth: bool, environment: &mut Environment) {
    let Some(current) = environment.values.get(name).cloned() else {
        return;
    };
    let refined = match current {
        SemanticDomain::Option {
            type_id,
            none,
            some,
        } => match (predicate, truth) {
            ("is_some", true) | ("is_none", false) => SemanticDomain::Option {
                type_id,
                none: false,
                some,
            },
            ("is_some", false) | ("is_none", true) => SemanticDomain::Option {
                type_id,
                none,
                some: Box::new(SemanticDomain::bottom(some.type_id())),
            },
            _ => return,
        },
        SemanticDomain::Result { type_id, ok, err } => match (predicate, truth) {
            ("is_ok", true) | ("is_err", false) => SemanticDomain::Result {
                type_id,
                ok,
                err: Box::new(SemanticDomain::bottom(err.type_id())),
            },
            ("is_ok", false) | ("is_err", true) => SemanticDomain::Result {
                type_id,
                ok: Box::new(SemanticDomain::bottom(ok.type_id())),
                err,
            },
            _ => return,
        },
        _ => return,
    };
    environment.values.insert(name.into(), refined);
}

fn refine_comparison(
    operator: &str,
    left: &ProgramExpression,
    right: &ProgramExpression,
    then_environment: &mut Environment,
    else_environment: &mut Environment,
) {
    let (Some(binding), ProgramExpression::Integer { value }) = (expression_binding(left), right)
    else {
        return;
    };
    let Some(value) = parse_integer(value) else {
        return;
    };
    let Some(current) = then_environment.values.get(binding).cloned() else {
        return;
    };
    let type_id = current.type_id().to_owned();
    let (then_interval, else_interval, then_excluded, else_excluded) = match operator {
        "==" => (
            (value, value),
            (i128::MIN, i128::MAX),
            Vec::new(),
            vec![value],
        ),
        "!=" => (
            (i128::MIN, i128::MAX),
            (value, value),
            vec![value],
            Vec::new(),
        ),
        "<" => (
            (i128::MIN, value.saturating_sub(1)),
            (value, i128::MAX),
            Vec::new(),
            Vec::new(),
        ),
        "<=" => (
            (i128::MIN, value),
            (value.saturating_add(1), i128::MAX),
            Vec::new(),
            Vec::new(),
        ),
        ">" => (
            (value.saturating_add(1), i128::MAX),
            (i128::MIN, value),
            Vec::new(),
            Vec::new(),
        ),
        ">=" => (
            (value, i128::MAX),
            (i128::MIN, value.saturating_sub(1)),
            Vec::new(),
            Vec::new(),
        ),
        _ => return,
    };
    let then_required = IntegerInterval::new(then_interval.0, then_interval.1).map_or_else(
        || SemanticDomain::bottom(&type_id),
        |interval| SemanticDomain::integer(&type_id, [interval], then_excluded),
    );
    let else_required = IntegerInterval::new(else_interval.0, else_interval.1).map_or_else(
        || SemanticDomain::bottom(&type_id),
        |interval| SemanticDomain::integer(&type_id, [interval], else_excluded),
    );
    then_environment
        .values
        .insert(binding.into(), current.intersection(&then_required));
    else_environment
        .values
        .insert(binding.into(), current.intersection(&else_required));
}

fn bind_pattern(pattern: &ProgramPattern, domain: &SemanticDomain, environment: &mut Environment) {
    match pattern {
        ProgramPattern::Binding { name } => {
            environment.values.insert(name.clone(), domain.clone());
        }
        ProgramPattern::Variant { fields, .. } => {
            let payload = match domain {
                SemanticDomain::Option { some, .. } => Some(some.as_ref()),
                SemanticDomain::Result { ok, err, .. } if !ok.is_bottom() => Some(ok.as_ref()),
                SemanticDomain::Result { err, .. } => Some(err.as_ref()),
                _ => None,
            };
            if let (Some(field), Some(payload)) = (fields.first(), payload) {
                bind_pattern(field, payload, environment);
            }
        }
        ProgramPattern::Tuple { elements } => {
            if let SemanticDomain::Tuple {
                elements: values, ..
            } = domain
            {
                for (pattern, value) in elements.iter().zip(values) {
                    bind_pattern(pattern, value, environment);
                }
            }
        }
        ProgramPattern::Wildcard | ProgramPattern::Unsupported { .. } => {}
    }
}

fn domain_for_pattern(pattern: &ProgramPattern, source: &SemanticDomain) -> SemanticDomain {
    match pattern {
        ProgramPattern::Wildcard
        | ProgramPattern::Binding { .. }
        | ProgramPattern::Unsupported { .. } => source.clone(),
        ProgramPattern::Variant { name, .. } => match source {
            SemanticDomain::Option {
                type_id,
                none,
                some,
            } => match last_path_segment(name) {
                "None" => SemanticDomain::Option {
                    type_id: type_id.clone(),
                    none: *none,
                    some: Box::new(SemanticDomain::bottom(some.type_id())),
                },
                "Some" => SemanticDomain::Option {
                    type_id: type_id.clone(),
                    none: false,
                    some: some.clone(),
                },
                _ => SemanticDomain::bottom(type_id),
            },
            SemanticDomain::Result { type_id, ok, err } => match last_path_segment(name) {
                "Ok" => SemanticDomain::Result {
                    type_id: type_id.clone(),
                    ok: ok.clone(),
                    err: Box::new(SemanticDomain::bottom(err.type_id())),
                },
                "Err" => SemanticDomain::Result {
                    type_id: type_id.clone(),
                    ok: Box::new(SemanticDomain::bottom(ok.type_id())),
                    err: err.clone(),
                },
                _ => SemanticDomain::bottom(type_id),
            },
            SemanticDomain::Enum { type_id, variants } => {
                let variant = last_path_segment(name);
                SemanticDomain::Enum {
                    type_id: type_id.clone(),
                    variants: variants
                        .get(variant)
                        .map(|payload| [(variant.into(), payload.clone())].into_iter().collect())
                        .unwrap_or_default(),
                }
            }
            SemanticDomain::Top { type_id } | SemanticDomain::Opaque { type_id, top: true } => {
                SemanticDomain::Enum {
                    type_id: type_id.clone(),
                    variants: [(last_path_segment(name).into(), None)]
                        .into_iter()
                        .collect(),
                }
            }
            _ => SemanticDomain::bottom(source.type_id()),
        },
        ProgramPattern::Tuple { elements } => match source {
            SemanticDomain::Tuple {
                type_id,
                elements: values,
            } if elements.len() == values.len() => SemanticDomain::Tuple {
                type_id: type_id.clone(),
                elements: elements
                    .iter()
                    .zip(values)
                    .map(|(pattern, value)| domain_for_pattern(pattern, value))
                    .collect(),
            },
            _ => SemanticDomain::bottom(source.type_id()),
        },
    }
}

fn integer_arithmetic(
    operator: &str,
    left: &SemanticDomain,
    right: &SemanticDomain,
) -> Option<SemanticDomain> {
    let (
        SemanticDomain::Integer {
            type_id,
            intervals: left,
            ..
        },
        SemanticDomain::Integer {
            intervals: right, ..
        },
    ) = (left, right)
    else {
        return None;
    };
    let mut intervals = Vec::new();
    for left in left {
        for right in right {
            let (min, max) = match operator {
                "+" => (
                    left.lower().saturating_add(right.lower()),
                    left.upper().saturating_add(right.upper()),
                ),
                "-" => (
                    left.lower().saturating_sub(right.upper()),
                    left.upper().saturating_sub(right.lower()),
                ),
                "*" => {
                    let values = [
                        left.lower().saturating_mul(right.lower()),
                        left.lower().saturating_mul(right.upper()),
                        left.upper().saturating_mul(right.lower()),
                        left.upper().saturating_mul(right.upper()),
                    ];
                    (*values.iter().min()?, *values.iter().max()?)
                }
                _ => return None,
            };
            intervals.push(IntegerInterval::new(min, max)?);
        }
    }
    Some(SemanticDomain::integer(type_id, intervals, []))
}

fn aggregate_coverage(
    summaries: &[FunctionSemanticSummary],
    function_contracts: usize,
    fixed_point_iterations: usize,
    recursive_components: usize,
    interprocedural_transfers: usize,
    state: &AnalysisState,
) -> SemanticAnalysisCoverage {
    let properties = summaries.iter().flat_map(|summary| {
        [
            summary.coverage.precondition_compatibility,
            summary.coverage.postcondition,
            summary.coverage.partial_operations,
            summary.coverage.heap_alias_effects,
            summary.coverage.concurrency,
        ]
    });
    let mut proven = 0;
    let mut partial = 0;
    let mut unknown = 0;
    let mut unsupported = 0;
    for property in properties {
        match property {
            AnalysisCoverageState::Proven => proven += 1,
            AnalysisCoverageState::Partial => partial += 1,
            AnalysisCoverageState::Unknown => unknown += 1,
            AnalysisCoverageState::Unsupported => unsupported += 1,
        }
    }
    SemanticAnalysisCoverage {
        functions_analyzed: summaries.len(),
        function_contracts,
        function_summaries: summaries.len(),
        interprocedural_transfers,
        fixed_point_iterations,
        recursive_components,
        precondition_checks: state
            .checks
            .iter()
            .filter(|check| check.kind == DomainCheckKind::CallPrecondition)
            .count(),
        postcondition_proofs: state
            .checks
            .iter()
            .filter(|check| {
                check.kind == DomainCheckKind::FunctionPostcondition
                    && check.state == AnalysisCoverageState::Proven
            })
            .count(),
        partial_operation_checks: state
            .checks
            .iter()
            .filter(|check| {
                matches!(
                    check.kind,
                    DomainCheckKind::PartialOperation | DomainCheckKind::ImpossibleStateAssertion
                )
            })
            .count(),
        proven_properties: proven,
        partial_properties: partial,
        unknown_properties: unknown,
        unsupported_properties: unsupported,
        violations: state.violations.len(),
    }
}

fn coverage_for_checks<'a>(
    checks: impl Iterator<Item = &'a DomainCheck>,
    has_violation: bool,
    has_unsupported: bool,
) -> AnalysisCoverageState {
    let count = checks.count();
    if has_violation {
        AnalysisCoverageState::Partial
    } else if count > 0 && !has_unsupported {
        AnalysisCoverageState::Proven
    } else if count > 0 {
        AnalysisCoverageState::Partial
    } else if has_unsupported {
        AnalysisCoverageState::Unsupported
    } else {
        AnalysisCoverageState::Unknown
    }
}

fn finding_from_violation(
    violation: &SemanticViolation,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let definition = RuleFindingDefinition::new(
        PROGRAM_DOMAIN_RULE_ID,
        3,
        FindingCategory::Source,
        "Narrow the producer domain through supported control flow, strengthen the caller contract, make the consumer total, or correct an invalid Function Contract.",
    )?;
    let location = FindingLocation::at_path(&violation.provenance.path)?
        .with_span(SourceSpan::new(
            violation.provenance.line,
            violation.provenance.column,
            violation.provenance.line,
            violation.provenance.column,
        )?)
        .with_symbol(&violation.producer_symbol)?;
    let occurrence = FindingOccurrence::new(
        Vec::new(),
        location,
        format!(
            "{}; abstract counter-domain: {}",
            violation.message,
            violation.counter_domain.as_ref().map_or_else(
                || "not representable by Semantic Value Domains v1".into(),
                |domain| serde_json::to_string(domain)
                    .unwrap_or_else(|_| "unserializable counter-domain".into())
            )
        ),
    )?;
    CanonicalFinding::failure(
        definition,
        occurrence,
        EvaluatorProvenance::new(SEMANTIC_ANALYZER_ID, SEMANTIC_ANALYSIS_VERSION)?,
        standard_edition,
        None,
    )
}

fn symbol_provenance(
    symbol: &ExecutableSymbol,
    derivation: &str,
    mut inputs: Vec<String>,
) -> SemanticProvenance {
    inputs.sort();
    inputs.dedup();
    SemanticProvenance {
        path: symbol.source_path().into(),
        line: 1,
        column: 1,
        symbol: symbol.id().into(),
        derivation: derivation.into(),
        inputs,
    }
}

fn fact_id(prefix: &str, value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("semantic identity material is serializable");
    format!("{prefix}:sha256:{:x}", Sha256::digest(bytes))
}

fn expression_binding(expression: &ProgramExpression) -> Option<&str> {
    match expression {
        ProgramExpression::Binding { name } => Some(name),
        _ => None,
    }
}

fn pattern_binding(pattern: &ProgramPattern) -> Option<&str> {
    match pattern {
        ProgramPattern::Binding { name } => Some(name),
        _ => None,
    }
}

fn is_simple_binding(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn last_path_segment(value: &str) -> &str {
    value.rsplit("::").next().unwrap_or(value).trim()
}

fn parse_integer(value: &str) -> Option<i128> {
    let digits = value
        .trim()
        .trim_end_matches(|character: char| character.is_ascii_alphabetic())
        .replace('_', "");
    digits.parse().ok()
}

fn nested_type_id(semantic: &SemanticType) -> String {
    let bytes = serde_json::to_vec(semantic).expect("semantic type identity is serializable");
    format!("type:sha256:{:x}", Sha256::digest(bytes))
}

/// Explains why semantic analysis could not construct a canonical result.
#[derive(Debug)]
pub enum SemanticAnalysisError {
    /// Canonical serialization failed.
    Serialization(serde_json::Error),
    /// A normalized finding could not be constructed.
    Finding(FindingError),
}

impl Display for SemanticAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(formatter, "semantic serialization failed: {error}")
            }
            Self::Finding(error) => write!(formatter, "semantic finding failed: {error}"),
        }
    }
}

impl Error for SemanticAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
        }
    }
}

impl From<FindingError> for SemanticAnalysisError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}
