//! Conservative typestate and transitive effect analysis over canonical PSM facts.

#[path = "state_contract.rs"]
mod state_contract;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::program_semantics::{
    CallResolutionState, ExecutableSymbol, ProgramBody, ProgramCall, ProgramExpression,
    ProgramMutation, ProgramPlace, ProgramSemanticModel, ProgramStatement, ProgramType,
};
use crate::semantic_analysis::{
    DomainSpecification, FunctionContract, FunctionEffect, ResolvedFunctionContracts,
    SemanticAnalysisEvaluation, SemanticDomain, resolve_domain,
};

pub use state_contract::{
    ResolvedState, ResolvedStateContracts, ResolvedStatePredicate, ResolvedStateType,
    STATE_CONTRACT_SCHEMA, STATE_CONTRACT_SCHEMA_VERSION, StateContractError, StateContractSource,
    canonicalize_state_contract_json, load_state_contracts,
};

/// Canonical State & Effect Analysis schema identity.
pub const STATE_EFFECT_ANALYSIS_SCHEMA: &str = "urn:fortress:schema:v1:state-effect-analysis";
/// Canonical State & Effect Analysis schema version.
pub const STATE_EFFECT_ANALYSIS_SCHEMA_VERSION: u16 = 1;
/// Semantic version of the state/effect analyzer.
pub const STATE_EFFECT_ANALYSIS_VERSION: &str = "1.0.0";
/// Stable analyzer identity.
pub const STATE_EFFECT_ANALYZER_ID: &str = "fortress-state-effect-analysis";
/// Normative typestate rule identity.
pub const PROGRAM_STATE_RULE_ID: &str = "PROGRAM-STATE-001";
/// Normative effect-policy rule identity.
pub const PROGRAM_EFFECT_RULE_ID: &str = "PROGRAM-EFFECT-001";

const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_heap_graph_analysis",
    "concurrency_interleavings",
    "database_transaction_state",
    "external_failure_contracts",
    "general_alias_analysis",
    "global_static_state_proof",
    "interior_mutability_theorem_proving",
    "lock_deadlock_analysis",
    "symbolic_execution",
    "unsafe_alias_proof",
];

/// Independent epistemic coverage for one state/effect property.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateEffectCoverage {
    /// The supported facts prove the property.
    Proven,
    /// Some supported facts are known but opaque behavior remains.
    Partial,
    /// Required state/effect identity is unavailable.
    Unknown,
    /// The semantic class is outside v1.
    Unsupported,
}

/// Conservative classification of one modeled nominal state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TypestateClassification {
    /// Exactly one declared state contains every possible field value.
    Exact {
        /// Stable identity of the only possible state.
        state: String,
    },
    /// More than one declared state remains possible.
    Possible {
        /// Sorted stable identities of all possible states.
        states: Vec<String>,
    },
    /// Known concrete domains match no declared state.
    Unclassified,
    /// Missing/invalidated field identity prevents classification.
    Unknown,
}

/// One exact source or transitive cause for an effect.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EffectEvidence {
    effect: FunctionEffect,
    source_symbol: String,
    path: String,
    line: u32,
    column: u32,
    call_chain: Vec<String>,
}

/// One function's compositional state/effect summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateEffectSummary {
    symbol: String,
    stateful: bool,
    input_receiver_state: Option<TypestateClassification>,
    output_receiver_state: Option<TypestateClassification>,
    field_reads: Vec<String>,
    field_writes: Vec<String>,
    direct_effects: Vec<FunctionEffect>,
    transitive_effects: Vec<FunctionEffect>,
    effect_evidence: Vec<EffectEvidence>,
    state_preconditions: StateEffectCoverage,
    state_postconditions: StateEffectCoverage,
    effects: StateEffectCoverage,
    uncertainty: Vec<String>,
}

impl StateEffectSummary {
    /// Returns the governed executable symbol.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns direct observed effects.
    #[must_use]
    pub fn direct_effects(&self) -> &[FunctionEffect] {
        &self.direct_effects
    }

    /// Returns the transitive effect closure.
    #[must_use]
    pub fn transitive_effects(&self) -> &[FunctionEffect] {
        &self.transitive_effects
    }

    /// Returns inferred receiver output state.
    #[must_use]
    pub const fn output_receiver_state(&self) -> Option<&TypestateClassification> {
        self.output_receiver_state.as_ref()
    }

    /// Returns the admitted receiver state classification.
    #[must_use]
    pub const fn input_receiver_state(&self) -> Option<&TypestateClassification> {
        self.input_receiver_state.as_ref()
    }

    /// Returns the state-postcondition coverage for the transition.
    #[must_use]
    pub const fn state_postcondition_coverage(&self) -> StateEffectCoverage {
        self.state_postconditions
    }

    /// Returns exact direct and transitive effect evidence.
    #[must_use]
    pub fn effect_evidence(&self) -> &[EffectEvidence] {
        &self.effect_evidence
    }
}

impl EffectEvidence {
    /// Returns the effect supported by this evidence.
    #[must_use]
    pub const fn effect(&self) -> FunctionEffect {
        self.effect
    }

    /// Returns the executable where the effect originates.
    #[must_use]
    pub fn source_symbol(&self) -> &str {
        &self.source_symbol
    }

    /// Returns canonical repository-relative provenance.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Supported state/effect contradiction category.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateEffectViolationKind {
    /// Call receiver may not satisfy a callee state precondition.
    StatePrecondition,
    /// Function implementation may not satisfy a state postcondition.
    StatePostcondition,
    /// Supported direct or transitive effect is outside policy.
    ForbiddenEffect,
}

/// One exact supported contradiction.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StateEffectViolation {
    id: String,
    rule_id: String,
    kind: StateEffectViolationKind,
    symbol: String,
    related_symbol: Option<String>,
    message: String,
    counter_states: Vec<String>,
    forbidden_effect: Option<FunctionEffect>,
    evidence: Vec<String>,
    path: String,
    line: u32,
    column: u32,
}

/// Aggregate state/effect counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StateEffectCoverageSummary {
    functions: usize,
    stateful_functions: usize,
    modeled_types: usize,
    modeled_states: usize,
    exact_states: usize,
    possible_states: usize,
    unclassified_states: usize,
    unknown_states: usize,
    state_precondition_checks: usize,
    state_postcondition_checks: usize,
    effect_policy_checks: usize,
    alias_escape_uncertainties: usize,
    effect_fixed_point_iterations: usize,
    violations: usize,
}

impl StateEffectCoverageSummary {
    /// Returns supported contradiction count.
    #[must_use]
    pub const fn violations(self) -> usize {
        self.violations
    }

    /// Returns analyzed function count.
    #[must_use]
    pub const fn functions(self) -> usize {
        self.functions
    }
}

/// Canonical State & Effect Analysis v1 derived Info.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateEffectAnalysisModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: String,
    psm_digest: String,
    semantic_analysis_digest: String,
    state_contract_digest: String,
    function_contract_digest: String,
    summaries: Vec<StateEffectSummary>,
    violations: Vec<StateEffectViolation>,
    direct_effect_counts: BTreeMap<String, usize>,
    transitive_effect_counts: BTreeMap<String, usize>,
    coverage: StateEffectCoverageSummary,
    unsupported_semantics: Vec<String>,
}

impl StateEffectAnalysisModel {
    /// Returns canonical summaries.
    #[must_use]
    pub fn summaries(&self) -> &[StateEffectSummary] {
        &self.summaries
    }

    /// Returns supported contradictions.
    #[must_use]
    pub fn violations(&self) -> &[StateEffectViolation] {
        &self.violations
    }

    /// Returns aggregate coverage.
    #[must_use]
    pub const fn coverage(&self) -> StateEffectCoverageSummary {
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
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        Ok(json)
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

/// Rule-facing state/effect evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateEffectAnalysisEvaluation {
    model: StateEffectAnalysisModel,
    state_findings: Vec<CanonicalFinding>,
    effect_findings: Vec<CanonicalFinding>,
}

impl StateEffectAnalysisEvaluation {
    /// Returns the canonical derived model.
    #[must_use]
    pub const fn model(&self) -> &StateEffectAnalysisModel {
        &self.model
    }

    /// Returns PROGRAM-STATE-001 findings.
    #[must_use]
    pub fn state_findings(&self) -> &[CanonicalFinding] {
        &self.state_findings
    }

    /// Returns PROGRAM-EFFECT-001 findings.
    #[must_use]
    pub fn effect_findings(&self) -> &[CanonicalFinding] {
        &self.effect_findings
    }
}

#[derive(Clone)]
struct EffectWork {
    direct: BTreeSet<FunctionEffect>,
    transitive: BTreeSet<FunctionEffect>,
    evidence: BTreeMap<FunctionEffect, BTreeSet<EffectEvidence>>,
    uncertain: BTreeSet<String>,
}

/// Derives conservative state transitions and transitive effects.
///
/// # Errors
///
/// Returns an error only for canonical serialization/finding construction.
#[allow(clippy::too_many_lines)]
pub fn analyze_state_effects(
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisEvaluation,
    state_contracts: &ResolvedStateContracts,
    function_contracts: &ResolvedFunctionContracts,
    standard_edition: &str,
) -> Result<StateEffectAnalysisEvaluation, StateEffectAnalysisError> {
    let symbols = psm
        .symbols()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let types = psm
        .types()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let owner_states = owner_state_types(psm, state_contracts);
    validate_function_state_references(function_contracts, state_contracts)?;
    let mut effect_work = direct_effects(psm, &symbols);
    let effect_iterations = close_effects(psm.calls(), &mut effect_work);
    let mut violations =
        state_call_violations(psm, function_contracts, &owner_states, &symbols, &types);
    let mut summaries = Vec::new();
    for symbol in psm.symbols() {
        let contract = function_contracts.get(symbol.id());
        let state_type = owner_states.get(symbol.id()).copied();
        let input = state_type.map(|state_type| initial_classification(contract, state_type));
        let output = state_type.map(|state_type| {
            infer_output_state(
                psm,
                symbol,
                contract,
                state_type,
                function_contracts,
                &types,
            )
        });
        if let (Some(contract), Some(output)) = (contract, output.as_ref()) {
            violations.extend(postcondition_violations(symbol, contract, output));
        }
        let work = effect_work
            .get(symbol.id())
            .cloned()
            .unwrap_or_else(empty_effect_work);
        if let Some(contract) = contract
            && let Some(policy) = contract.effects()
        {
            violations.extend(effect_policy_violations(symbol, policy.allowed(), &work));
        }
        let field_reads: Vec<String> = psm
            .state_reads()
            .iter()
            .filter(|item| item.symbol() == symbol.id())
            .filter_map(|item| item.place().field_name().map(str::to_owned))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let field_writes: Vec<String> = psm
            .mutations()
            .iter()
            .filter(|item| item.symbol() == symbol.id())
            .filter_map(|item| item.target().field_name().map(str::to_owned))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let stateful = state_type.is_some() || !field_reads.is_empty() || !field_writes.is_empty();
        let state_postconditions =
            if contract.is_some_and(|value| !value.state_ensures().is_empty()) {
                if violations.iter().any(|item| {
                    item.symbol == symbol.id()
                        && item.kind == StateEffectViolationKind::StatePostcondition
                }) {
                    StateEffectCoverage::Partial
                } else if output
                    .as_ref()
                    .is_some_and(|value| matches!(value, TypestateClassification::Exact { .. }))
                {
                    StateEffectCoverage::Proven
                } else {
                    StateEffectCoverage::Partial
                }
            } else if state_type.is_some() {
                StateEffectCoverage::Unknown
            } else {
                StateEffectCoverage::Unsupported
            };
        let state_preconditions =
            if contract.is_some_and(|value| !value.state_requires().is_empty()) {
                StateEffectCoverage::Proven
            } else if state_type.is_some() {
                StateEffectCoverage::Unknown
            } else {
                StateEffectCoverage::Unsupported
            };
        let effects = if contract.and_then(FunctionContract::effects).is_some()
            && work.uncertain.is_empty()
        {
            StateEffectCoverage::Proven
        } else if !work.direct.is_empty() || !work.transitive.is_empty() {
            StateEffectCoverage::Partial
        } else if work.uncertain.is_empty() {
            StateEffectCoverage::Unknown
        } else {
            StateEffectCoverage::Unsupported
        };
        summaries.push(StateEffectSummary {
            symbol: symbol.id().into(),
            stateful,
            input_receiver_state: input,
            output_receiver_state: output,
            field_reads,
            field_writes,
            direct_effects: work.direct.iter().copied().collect(),
            transitive_effects: work.transitive.iter().copied().collect(),
            effect_evidence: work.evidence.values().flatten().cloned().collect(),
            state_preconditions,
            state_postconditions,
            effects,
            uncertainty: work.uncertain.into_iter().collect(),
        });
    }
    summaries.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    violations.sort();
    violations.dedup();
    let state_findings = violations
        .iter()
        .filter(|item| item.rule_id == PROGRAM_STATE_RULE_ID)
        .map(|item| finding(item, standard_edition))
        .collect::<Result<Vec<_>, _>>()?;
    let effect_findings = violations
        .iter()
        .filter(|item| item.rule_id == PROGRAM_EFFECT_RULE_ID)
        .map(|item| finding(item, standard_edition))
        .collect::<Result<Vec<_>, _>>()?;
    let direct_effect_counts = effect_counts(
        summaries
            .iter()
            .flat_map(|item| item.direct_effects.iter().copied()),
    );
    let transitive_effect_counts = effect_counts(
        summaries
            .iter()
            .flat_map(|item| item.transitive_effects.iter().copied()),
    );
    let coverage = coverage(&summaries, state_contracts, &violations, effect_iterations);
    let model = StateEffectAnalysisModel {
        schema: STATE_EFFECT_ANALYSIS_SCHEMA.into(),
        schema_version: STATE_EFFECT_ANALYSIS_SCHEMA_VERSION,
        semantic_version: STATE_EFFECT_ANALYSIS_VERSION.into(),
        project_id: psm.project_id().into(),
        psm_digest: psm.digest()?,
        semantic_analysis_digest: semantic.model().digest()?,
        state_contract_digest: state_contracts.digest().into(),
        function_contract_digest: function_contracts.digest().into(),
        summaries,
        violations,
        direct_effect_counts,
        transitive_effect_counts,
        coverage,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
    };
    Ok(StateEffectAnalysisEvaluation {
        model,
        state_findings,
        effect_findings,
    })
}

fn empty_effect_work() -> EffectWork {
    EffectWork {
        direct: BTreeSet::new(),
        transitive: BTreeSet::new(),
        evidence: BTreeMap::new(),
        uncertain: BTreeSet::new(),
    }
}

#[allow(clippy::too_many_lines)]
fn direct_effects(
    psm: &ProgramSemanticModel,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
) -> BTreeMap<String, EffectWork> {
    let mut result = symbols
        .keys()
        .map(|id| ((*id).into(), empty_effect_work()))
        .collect::<BTreeMap<_, _>>();
    for read in psm.state_reads() {
        let effect = if read.place().is_receiver() {
            FunctionEffect::ReceiverStateRead
        } else {
            FunctionEffect::OwnedStateRead
        };
        add_effect(
            &mut result,
            read.symbol(),
            effect,
            read.provenance().path(),
            read.provenance().location().line(),
            read.provenance().location().column(),
        );
    }
    for mutation in psm.mutations() {
        if mutation.target().field_name().is_none() {
            continue;
        }
        let effect = if mutation.target().is_receiver() {
            FunctionEffect::ReceiverStateWrite
        } else {
            FunctionEffect::OwnedStateWrite
        };
        add_effect(
            &mut result,
            mutation.symbol(),
            effect,
            mutation.provenance().path(),
            mutation.provenance().location().line(),
            mutation.provenance().location().column(),
        );
        if matches!(
            mutation.target(),
            ProgramPlace::Dereference { .. } | ProgramPlace::Unsupported { .. }
        ) {
            result
                .entry(mutation.symbol().into())
                .or_insert_with(empty_effect_work)
                .uncertain
                .insert("alias_or_unsupported_mutation".into());
        }
    }
    for symbol in symbols
        .values()
        .filter(|symbol| symbol.qualifiers().is_unsafe())
    {
        add_effect(
            &mut result,
            symbol.id(),
            FunctionEffect::UnsafeExecution,
            symbol.source_path(),
            1,
            1,
        );
        result
            .entry(symbol.id().into())
            .or_insert_with(empty_effect_work)
            .uncertain
            .insert("unsafe_alias_semantics".into());
    }
    for call in psm.calls() {
        match call.state() {
            CallResolutionState::External => {
                for evidence in call.evidence() {
                    add_effect(
                        &mut result,
                        call.caller(),
                        FunctionEffect::ExternalInteraction,
                        evidence.provenance().path(),
                        evidence.provenance().location().line(),
                        evidence.provenance().location().column(),
                    );
                    result
                        .entry(call.caller().into())
                        .or_insert_with(empty_effect_work)
                        .uncertain
                        .insert("opaque_external_effects".into());
                }
            }
            CallResolutionState::DynamicDispatch
            | CallResolutionState::Unresolved
            | CallResolutionState::Unsupported
            | CallResolutionState::Invalid => {
                result
                    .entry(call.caller().into())
                    .or_insert_with(empty_effect_work)
                    .uncertain
                    .insert(format!("opaque_call:{:?}", call.state()));
                if call
                    .evidence()
                    .iter()
                    .any(|evidence| evidence.receiver().is_some_and(ProgramPlace::is_receiver))
                {
                    result
                        .entry(call.caller().into())
                        .or_insert_with(empty_effect_work)
                        .uncertain
                        .insert("receiver_state_invalidated_by_opaque_call".into());
                }
            }
            CallResolutionState::ResolvedStatic => {}
        }
    }
    for body in psm.bodies() {
        for provenance in exceptional_sites(body) {
            add_effect(
                &mut result,
                body.symbol(),
                FunctionEffect::MayPanic,
                provenance.0,
                provenance.1,
                provenance.2,
            );
        }
    }
    for work in result.values_mut() {
        work.transitive = work.direct.clone();
    }
    result
}

fn add_effect(
    result: &mut BTreeMap<String, EffectWork>,
    symbol: &str,
    effect: FunctionEffect,
    path: &str,
    line: u32,
    column: u32,
) {
    let work = result
        .entry(symbol.into())
        .or_insert_with(empty_effect_work);
    work.direct.insert(effect);
    work.evidence
        .entry(effect)
        .or_default()
        .insert(EffectEvidence {
            effect,
            source_symbol: symbol.into(),
            path: path.into(),
            line,
            column,
            call_chain: vec![symbol.into()],
        });
}

fn close_effects(calls: &[ProgramCall], work: &mut BTreeMap<String, EffectWork>) -> usize {
    let edges = calls
        .iter()
        .filter(|call| call.state() == CallResolutionState::ResolvedStatic)
        .filter_map(|call| {
            call.callee()
                .map(|callee| (call.caller().to_owned(), callee.to_owned()))
        })
        .collect::<BTreeSet<_>>();
    let mut iterations = 0;
    loop {
        iterations += 1;
        let snapshot = work.clone();
        let mut changed = false;
        for (caller, callee) in &edges {
            let Some(provider_summary) = snapshot.get(callee) else {
                continue;
            };
            let consumer_summary = work.entry(caller.clone()).or_insert_with(empty_effect_work);
            for effect in &provider_summary.transitive {
                if consumer_summary.transitive.insert(*effect) {
                    changed = true;
                    if let Some(item) = provider_summary
                        .evidence
                        .get(effect)
                        .and_then(BTreeSet::first)
                        && !item.call_chain.iter().any(|symbol| symbol == caller)
                    {
                        let mut derived = item.clone();
                        derived.call_chain.insert(0, caller.clone());
                        consumer_summary
                            .evidence
                            .entry(*effect)
                            .or_default()
                            .insert(derived);
                    }
                }
            }
            if !provider_summary.uncertain.is_empty() {
                changed |= consumer_summary
                    .uncertain
                    .insert("transitive_opaque_effect".into());
            }
        }
        if !changed || iterations > work.len().saturating_add(1) {
            return iterations;
        }
    }
}

fn owner_state_types<'a>(
    psm: &'a ProgramSemanticModel,
    contracts: &'a ResolvedStateContracts,
) -> BTreeMap<&'a str, &'a ResolvedStateType> {
    let mut result = BTreeMap::new();
    for symbol in psm.symbols() {
        let Some(owner) = symbol.owner_type() else {
            continue;
        };
        let simple = last_segment(owner);
        if let Some(nominal) = psm.nominal_types().iter().find(|item| {
            item.fortress_module() == symbol.fortress_module()
                && last_segment(item.qualified_name()) == simple
        }) && let Some(state_type) = contracts.get_type(nominal.id())
        {
            result.insert(symbol.id(), state_type);
        }
    }
    result
}

fn initial_classification(
    contract: Option<&FunctionContract>,
    state_type: &ResolvedStateType,
) -> TypestateClassification {
    let required = contract
        .into_iter()
        .flat_map(FunctionContract::state_requires)
        .filter(|item| item.target() == "self")
        .map(|item| item.state().to_owned())
        .collect::<Vec<_>>();
    if required.len() == 1 {
        TypestateClassification::Exact {
            state: required[0].clone(),
        }
    } else if required.len() > 1 {
        TypestateClassification::Possible { states: required }
    } else if state_type.states().len() == 1 {
        TypestateClassification::Exact {
            state: state_type.states()[0].id().into(),
        }
    } else {
        TypestateClassification::Possible {
            states: state_type
                .states()
                .iter()
                .map(|state| state.id().into())
                .collect(),
        }
    }
}

fn infer_output_state(
    psm: &ProgramSemanticModel,
    symbol: &ExecutableSymbol,
    contract: Option<&FunctionContract>,
    state_type: &ResolvedStateType,
    function_contracts: &ResolvedFunctionContracts,
    types: &BTreeMap<&str, &ProgramType>,
) -> TypestateClassification {
    infer_receiver_state(
        psm,
        symbol.id(),
        contract,
        state_type,
        function_contracts,
        types,
        None,
    )
}

fn infer_receiver_state(
    psm: &ProgramSemanticModel,
    symbol_id: &str,
    contract: Option<&FunctionContract>,
    state_type: &ResolvedStateType,
    function_contracts: &ResolvedFunctionContracts,
    types: &BTreeMap<&str, &ProgramType>,
    before: Option<(u32, u32)>,
) -> TypestateClassification {
    let mut possible = state_ids(&initial_classification(contract, state_type));
    let mut unknown = false;
    let mut events = Vec::new();
    for mutation in psm
        .mutations()
        .iter()
        .filter(|item| item.symbol() == symbol_id && item.target().is_receiver())
    {
        events.push((
            mutation.provenance().location().line(),
            mutation.provenance().location().column(),
            StateEvent::Mutation(mutation),
        ));
    }
    for call in psm.calls().iter().filter(|call| call.caller() == symbol_id) {
        for evidence in call
            .evidence()
            .iter()
            .filter(|item| item.receiver().is_some_and(ProgramPlace::is_receiver))
        {
            events.push((
                evidence.provenance().location().line(),
                evidence.provenance().location().column(),
                StateEvent::Call(call),
            ));
        }
    }
    events.sort_by_key(|event| (event.0, event.1));
    let mut field_overrides = BTreeMap::<String, SemanticDomain>::new();
    for (line, column, event) in events {
        if before.is_some_and(|limit| (line, column) >= limit) {
            break;
        }
        match event {
            StateEvent::Mutation(mutation) => {
                let Some(field) = mutation.target().field_name() else {
                    unknown = true;
                    continue;
                };
                let Some(type_id) = mutation.target().static_type() else {
                    unknown = true;
                    continue;
                };
                let Some(type_fact) = types.get(type_id) else {
                    unknown = true;
                    continue;
                };
                if let Some(domain) = expression_domain(mutation.value(), type_fact) {
                    field_overrides.insert(field.into(), domain);
                } else {
                    unknown = true;
                }
            }
            StateEvent::Call(call) => {
                if call.state() != CallResolutionState::ResolvedStatic {
                    unknown = true;
                    continue;
                }
                let Some(callee) = call.callee() else {
                    unknown = true;
                    continue;
                };
                let Some(callee_contract) = function_contracts.get(callee) else {
                    continue;
                };
                let ensured = callee_contract
                    .state_ensures()
                    .iter()
                    .filter(|item| item.target() == "self")
                    .map(|item| item.state().into())
                    .collect::<Vec<String>>();
                if !ensured.is_empty() {
                    possible = ensured;
                    field_overrides.clear();
                }
            }
        }
    }
    if !field_overrides.is_empty() {
        let classification = classify_fields(state_type, &field_overrides);
        if !matches!(classification, TypestateClassification::Unknown) {
            return classification;
        }
    }
    if unknown {
        TypestateClassification::Unknown
    } else if possible.len() == 1 {
        TypestateClassification::Exact {
            state: possible[0].clone(),
        }
    } else if possible.is_empty() {
        TypestateClassification::Unclassified
    } else {
        possible.sort();
        possible.dedup();
        TypestateClassification::Possible { states: possible }
    }
}

enum StateEvent<'a> {
    Mutation(&'a ProgramMutation),
    Call(&'a ProgramCall),
}

fn state_call_violations(
    psm: &ProgramSemanticModel,
    function_contracts: &ResolvedFunctionContracts,
    owner_states: &BTreeMap<&str, &ResolvedStateType>,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
    types: &BTreeMap<&str, &ProgramType>,
) -> Vec<StateEffectViolation> {
    let mut result = Vec::new();
    for call in psm
        .calls()
        .iter()
        .filter(|call| call.state() == CallResolutionState::ResolvedStatic)
    {
        let Some(required_symbol) = call.callee() else {
            continue;
        };
        let Some(required_contract) = function_contracts.get(required_symbol) else {
            continue;
        };
        let required = required_contract
            .state_requires()
            .iter()
            .filter(|item| item.target() == "self")
            .map(|item| item.state().to_owned())
            .collect::<BTreeSet<_>>();
        if required.is_empty() {
            continue;
        }
        let Some(state_type) = owner_states.get(call.caller()).copied() else {
            continue;
        };
        for evidence in call
            .evidence()
            .iter()
            .filter(|item| item.receiver().is_some_and(ProgramPlace::is_receiver))
        {
            let Some(invoking_symbol) = symbols.get(call.caller()).copied() else {
                continue;
            };
            let invoking_contract = function_contracts.get(call.caller());
            let possible = infer_receiver_state(
                psm,
                invoking_symbol.id(),
                invoking_contract,
                state_type,
                function_contracts,
                types,
                Some((
                    evidence.provenance().location().line(),
                    evidence.provenance().location().column(),
                )),
            );
            let counter = state_ids(&possible)
                .into_iter()
                .filter(|state| !required.contains(state))
                .collect::<Vec<_>>();
            if counter.is_empty() {
                continue;
            }
            result.push(violation(
                PROGRAM_STATE_RULE_ID,
                StateEffectViolationKind::StatePrecondition,
                call.caller(),
                Some(required_symbol),
                format!("receiver state may violate `{required_symbol}` precondition"),
                counter.clone(),
                None,
                vec![format!(
                    "required={}",
                    required.iter().cloned().collect::<Vec<_>>().join(",")
                )],
                evidence.provenance().path(),
                evidence.provenance().location().line(),
                evidence.provenance().location().column(),
            ));
        }
    }
    result
}

fn validate_function_state_references(
    function_contracts: &ResolvedFunctionContracts,
    state_contracts: &ResolvedStateContracts,
) -> Result<(), StateEffectAnalysisError> {
    for contract in function_contracts.contracts() {
        for obligation in contract
            .state_requires()
            .iter()
            .chain(contract.state_ensures())
        {
            if state_contracts.get_state(obligation.state()).is_none() {
                return Err(StateEffectAnalysisError::InvalidFunctionState {
                    symbol: contract.symbol().into(),
                    target: obligation.target().into(),
                    state: obligation.state().into(),
                });
            }
        }
    }
    Ok(())
}

fn postcondition_violations(
    symbol: &ExecutableSymbol,
    contract: &FunctionContract,
    output: &TypestateClassification,
) -> Vec<StateEffectViolation> {
    let actual = state_ids(output);
    contract
        .state_ensures()
        .iter()
        .filter(|item| matches!(item.target(), "self" | "return"))
        .filter(|item| {
            matches!(output, TypestateClassification::Exact { state } if state != item.state())
                || matches!(output, TypestateClassification::Possible { states } if states.iter().any(|state| state != item.state()))
                || matches!(output, TypestateClassification::Unclassified)
        })
        .map(|item| {
            violation(
                PROGRAM_STATE_RULE_ID,
                StateEffectViolationKind::StatePostcondition,
                symbol.id(),
                None,
                format!(
                    "implementation does not prove state postcondition `{}` for `{}`",
                    item.state(),
                    item.target()
                ),
                actual.clone(),
                None,
                vec![item.state().into()],
                symbol.source_path(),
                1,
                1,
            )
        })
        .collect()
}

fn effect_policy_violations(
    symbol: &ExecutableSymbol,
    allowed: &[FunctionEffect],
    work: &EffectWork,
) -> Vec<StateEffectViolation> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    work.transitive
        .iter()
        .filter(|effect| !allowed.contains(effect))
        .map(|effect| {
            let evidence = work
                .evidence
                .get(effect)
                .into_iter()
                .flatten()
                .map(|item| item.call_chain.join(" -> "))
                .collect::<Vec<_>>();
            let first = work.evidence.get(effect).and_then(|items| items.first());
            violation(
                PROGRAM_EFFECT_RULE_ID,
                StateEffectViolationKind::ForbiddenEffect,
                symbol.id(),
                None,
                format!(
                    "supported direct/transitive effect `{}` is outside the authored policy",
                    effect_name(*effect)
                ),
                Vec::new(),
                Some(*effect),
                evidence,
                first.map_or(symbol.source_path(), |item| item.path.as_str()),
                first.map_or(1, |item| item.line),
                first.map_or(1, |item| item.column),
            )
        })
        .collect()
}

fn classify_fields(
    state_type: &ResolvedStateType,
    fields: &BTreeMap<String, SemanticDomain>,
) -> TypestateClassification {
    let mut possible = Vec::new();
    let mut exact = Vec::new();
    let mut missing = false;
    for state in state_type.states() {
        let mut compatible = true;
        let mut contained = true;
        for predicate in state.predicates() {
            let Some(actual) = fields.get(predicate.field()) else {
                missing = true;
                contained = false;
                continue;
            };
            if actual.intersection(predicate.domain()).is_bottom() {
                compatible = false;
                break;
            }
            contained &= actual.is_subset_of(predicate.domain());
        }
        if compatible {
            possible.push(state.id().to_owned());
            if contained {
                exact.push(state.id().to_owned());
            }
        }
    }
    if exact.len() == 1 && possible.len() == 1 {
        TypestateClassification::Exact {
            state: exact.remove(0),
        }
    } else if !possible.is_empty() {
        TypestateClassification::Possible { states: possible }
    } else if missing {
        TypestateClassification::Unknown
    } else {
        TypestateClassification::Unclassified
    }
}

fn expression_domain(
    expression: &ProgramExpression,
    type_fact: &ProgramType,
) -> Option<SemanticDomain> {
    let specification = match expression {
        ProgramExpression::Boolean { value } => DomainSpecification::Boolean {
            include: vec![*value],
        },
        ProgramExpression::Integer { value } => {
            let value = value.parse::<i64>().ok()?;
            DomainSpecification::IntegerInterval {
                min: value,
                max: value,
                exclude: Vec::new(),
            }
        }
        ProgramExpression::Variant { name } if last_segment(name) == "None" => {
            DomainSpecification::OptionStates {
                include: vec!["none".into()],
                some: None,
            }
        }
        ProgramExpression::Construction { constructor, .. }
            if last_segment(constructor) == "Some" =>
        {
            DomainSpecification::OptionStates {
                include: vec!["some".into()],
                some: None,
            }
        }
        ProgramExpression::Construction { constructor, .. }
            if last_segment(constructor) == "Ok" =>
        {
            DomainSpecification::ResultStates {
                include: vec!["ok".into()],
                ok: None,
                err: None,
            }
        }
        ProgramExpression::Construction { constructor, .. }
            if last_segment(constructor) == "Err" =>
        {
            DomainSpecification::ResultStates {
                include: vec!["err".into()],
                ok: None,
                err: None,
            }
        }
        ProgramExpression::Variant { name } => DomainSpecification::EnumVariants {
            include: vec![last_segment(name).into()],
        },
        _ => return None,
    };
    resolve_domain(&specification, type_fact).ok()
}

fn state_ids(classification: &TypestateClassification) -> Vec<String> {
    match classification {
        TypestateClassification::Exact { state } => vec![state.clone()],
        TypestateClassification::Possible { states } => states.clone(),
        TypestateClassification::Unclassified | TypestateClassification::Unknown => Vec::new(),
    }
}

fn exceptional_sites(body: &ProgramBody) -> Vec<(&str, u32, u32)> {
    let mut result = Vec::new();
    collect_exceptional(body.statements(), &mut result);
    result
}

fn collect_exceptional<'a>(
    statements: &'a [ProgramStatement],
    result: &mut Vec<(&'a str, u32, u32)>,
) {
    for statement in statements {
        match statement {
            ProgramStatement::Expression {
                value: ProgramExpression::Exceptional { operation },
                provenance,
            } if operation == "panic" => result.push((
                provenance.path(),
                provenance.location().line(),
                provenance.location().column(),
            )),
            ProgramStatement::If {
                then_branch,
                else_branch,
                ..
            } => {
                collect_exceptional(then_branch, result);
                collect_exceptional(else_branch, result);
            }
            ProgramStatement::Match { arms, .. } => {
                for arm in arms {
                    collect_exceptional(arm.body(), result);
                }
            }
            ProgramStatement::WhileLet { body, .. } => collect_exceptional(body, result),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn violation(
    rule_id: &str,
    kind: StateEffectViolationKind,
    symbol: &str,
    related: Option<&str>,
    message: String,
    counter_states: Vec<String>,
    forbidden_effect: Option<FunctionEffect>,
    evidence: Vec<String>,
    path: &str,
    line: u32,
    column: u32,
) -> StateEffectViolation {
    #[derive(Serialize)]
    struct Identity<'a> {
        rule_id: &'a str,
        kind: StateEffectViolationKind,
        symbol: &'a str,
        related: Option<&'a str>,
        message: &'a str,
        path: &'a str,
        line: u32,
        column: u32,
    }
    let material = Identity {
        rule_id,
        kind,
        symbol,
        related,
        message: &message,
        path,
        line,
        column,
    };
    StateEffectViolation {
        id: format!(
            "state_effect_violation:sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&material).expect("violation identity serializes"))
        ),
        rule_id: rule_id.into(),
        kind,
        symbol: symbol.into(),
        related_symbol: related.map(str::to_owned),
        message,
        counter_states,
        forbidden_effect,
        evidence,
        path: path.into(),
        line,
        column,
    }
}

fn finding(
    violation: &StateEffectViolation,
    edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let remediation = if violation.rule_id == PROGRAM_STATE_RULE_ID {
        "Narrow the admitted receiver state, correct the supported transition, or align the State/Function Contract with truthful lifecycle intent."
    } else {
        "Remove the direct/transitive effect or explicitly authorize it in the owning Function Contract when that policy is truthful."
    };
    let definition =
        RuleFindingDefinition::new(&violation.rule_id, 3, FindingCategory::Source, remediation)?;
    let location = FindingLocation::at_path(&violation.path)?
        .with_span(SourceSpan::new(
            violation.line.max(1),
            violation.column.max(1),
            violation.line.max(1),
            violation.column.max(1),
        )?)
        .with_symbol(&violation.symbol)?;
    let occurrence = FindingOccurrence::new(Vec::new(), location, &violation.message)?;
    CanonicalFinding::failure(
        definition,
        occurrence,
        EvaluatorProvenance::new(STATE_EFFECT_ANALYZER_ID, STATE_EFFECT_ANALYSIS_VERSION)?,
        edition,
        None,
    )
}

fn coverage(
    summaries: &[StateEffectSummary],
    contracts: &ResolvedStateContracts,
    violations: &[StateEffectViolation],
    iterations: usize,
) -> StateEffectCoverageSummary {
    let outputs = summaries
        .iter()
        .filter_map(|item| item.output_receiver_state.as_ref());
    let mut exact = 0;
    let mut possible = 0;
    let mut unclassified = 0;
    let mut unknown = 0;
    for output in outputs {
        match output {
            TypestateClassification::Exact { .. } => exact += 1,
            TypestateClassification::Possible { .. } => possible += 1,
            TypestateClassification::Unclassified => unclassified += 1,
            TypestateClassification::Unknown => unknown += 1,
        }
    }
    StateEffectCoverageSummary {
        functions: summaries.len(),
        stateful_functions: summaries.iter().filter(|item| item.stateful).count(),
        modeled_types: contracts.types().count(),
        modeled_states: contracts.types().map(|item| item.states().len()).sum(),
        exact_states: exact,
        possible_states: possible,
        unclassified_states: unclassified,
        unknown_states: unknown,
        state_precondition_checks: violations
            .iter()
            .filter(|item| item.kind == StateEffectViolationKind::StatePrecondition)
            .count(),
        state_postcondition_checks: summaries
            .iter()
            .filter(|item| {
                !matches!(
                    item.state_postconditions,
                    StateEffectCoverage::Unsupported | StateEffectCoverage::Unknown
                )
            })
            .count(),
        effect_policy_checks: summaries
            .iter()
            .filter(|item| item.effects == StateEffectCoverage::Proven)
            .count(),
        alias_escape_uncertainties: summaries
            .iter()
            .map(|item| {
                item.uncertainty
                    .iter()
                    .filter(|value| {
                        value.contains("alias") || value.contains("receiver_state_invalidated")
                    })
                    .count()
            })
            .sum(),
        effect_fixed_point_iterations: iterations,
        violations: violations.len(),
    }
}

fn effect_counts(effects: impl Iterator<Item = FunctionEffect>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for effect in effects {
        *counts.entry(effect_name(effect).into()).or_insert(0) += 1;
    }
    counts
}

fn effect_name(effect: FunctionEffect) -> &'static str {
    match effect {
        FunctionEffect::ReceiverStateRead => "receiver_state_read",
        FunctionEffect::ReceiverStateWrite => "receiver_state_write",
        FunctionEffect::OwnedStateRead => "owned_state_read",
        FunctionEffect::OwnedStateWrite => "owned_state_write",
        FunctionEffect::ExternalInteraction => "external_interaction",
        FunctionEffect::MayPanic => "may_panic",
        FunctionEffect::UnsafeExecution => "unsafe_execution",
    }
}

fn last_segment(value: &str) -> &str {
    value.rsplit("::").next().unwrap_or(value)
}

/// Explains state/effect model construction failure.
#[derive(Debug)]
pub enum StateEffectAnalysisError {
    /// Canonical JSON serialization failed.
    Serialization(serde_json::Error),
    /// Normalized finding construction failed.
    Finding(FindingError),
    /// A Function Contract references a state absent from the distributed State Contracts.
    InvalidFunctionState {
        /// Executable symbol carrying the invalid obligation.
        symbol: String,
        /// Authored state target.
        target: String,
        /// Unknown state identity.
        state: String,
    },
}

impl Display for StateEffectAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(formatter, "state/effect serialization failed: {error}")
            }
            Self::Finding(error) => write!(formatter, "state/effect finding failed: {error}"),
            Self::InvalidFunctionState {
                symbol,
                target,
                state,
            } => write!(
                formatter,
                "Function Contract `{symbol}` references unknown state `{state}` for `{target}`",
            ),
        }
    }
}

impl Error for StateEffectAnalysisError {}
impl From<serde_json::Error> for StateEffectAnalysisError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}
impl From<FindingError> for StateEffectAnalysisError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}
