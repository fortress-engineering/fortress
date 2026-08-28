//! Coverage-aware reconciliation of Intended BFG checkpoints with implementation semantics.

#[path = "realization_contract.rs"]
mod realization_contract;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::behavioral_semantics::{
    BehavioralModelingState, IntendedBehavioralFlowGraph, IntendedFeatureFlow,
};
use crate::contract_coherency::ContractCoherencyGraph;
use crate::environmental_semantics::{EnvironmentalAnalysisModel, HandlingStatus};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::information_flow::InformationFlowAnalysisModel;
use crate::program_semantics::{
    CallResolutionState, ProgramExpression, ProgramMatchArm, ProgramSemanticModel, ProgramStatement,
};
use crate::semantic_analysis::{SemanticAnalysisModel, SemanticDomain};
use crate::state_effect_analysis::{
    StateEffectAnalysisModel, StateEffectCoverage, TypestateClassification,
};

pub use realization_contract::{
    BEHAVIOR_REALIZATION_CONTRACT_SCHEMA, BEHAVIOR_REALIZATION_CONTRACT_SCHEMA_VERSION,
    BehaviorAnchor, BehaviorRealizationContractError, BehaviorRealizationContractSource,
    ResolvedBehaviorRealizationContracts, ResolvedCheckpointRealization,
    canonicalize_behavior_realization_contract_json, load_behavior_realization_contracts,
};

/// Canonical Realized BFG v1 schema identity.
pub const REALIZED_BFG_SCHEMA: &str = "urn:fortress:schema:v1:realized-behavioral-flow-graph";
/// Canonical Realized BFG schema version.
pub const REALIZED_BFG_SCHEMA_VERSION: u16 = 1;
/// Behavioral Realization semantic analyzer version.
pub const BEHAVIORAL_REALIZATION_VERSION: &str = "1.0.0";
/// Stable analyzer identity.
pub const BEHAVIORAL_REALIZATION_ANALYZER_ID: &str = "fortress-behavioral-realization";
/// Opted-in realization coherency rule identity.
pub const BEHAVIOR_REALIZATION_RULE_ID: &str = "BEHAVIOR-REALIZATION-001";
/// Intended-dominator bypass rule identity.
pub const BEHAVIOR_BYPASS_RULE_ID: &str = "BEHAVIOR-BYPASS-001";

const REALIZATION_REMEDIATION: &str = "Correct the realization contract or implementation so every opted-in checkpoint and intended transition has exact supported realization and no undeclared semantic transition or terminal remains.";
const BYPASS_REMEDIATION: &str = "Correct the implementation so every supported route to the reached checkpoint passes its Intended BFG dominator, or correct the authored behavior if the intended mandatory passage is wrong.";
const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_symbolic_execution",
    "automatic_checkpoint_inference",
    "capability_to_symbol_realization",
    "complete_compiler_hir_semantics",
    "dynamic_runtime_trace_realization",
    "natural_language_anchor_matching",
    "path_probability_analysis",
    "verified_behavioral_evidence",
];

/// Epistemic coverage for implementation-event and bypass conclusions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealizationCoverage {
    /// Exact supported semantics establish the conclusion.
    Proven,
    /// Exact facts coexist with relevant opaque semantics.
    Partial,
    /// Insufficient semantic facts prevent a conclusion.
    Unknown,
    /// The semantic class is outside v1.
    Unsupported,
}

/// Supported event reachability conclusion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventReachability {
    /// At least one supported path exists.
    ProvenReachable,
    /// Supported graph semantics prove no path exists.
    ProvenUnreachable,
    /// Opaque semantics prevent a conclusion.
    Unknown,
    /// The requested semantic class is outside v1.
    Unsupported,
}

/// One checkpoint's implementation realization state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckpointRealizationState {
    /// At least one exact anchor is reachable under supported semantics.
    Realized,
    /// Some alternatives are exact while others remain uncertain.
    PartiallyRealized,
    /// Every anchor is proven unreachable.
    Unreachable,
    /// Coverage prevents a sound conclusion.
    Unknown,
    /// Supported semantics contradict intended placement.
    Contradicted,
}

/// Aggregate Feature behavioral realization state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeatureRealizationState {
    /// The Feature has no Intended BFG.
    Unmodeled,
    /// Intended behavior exists but no realization contract opts in.
    ModeledUnrealized,
    /// Opted-in realization remains incomplete under current coverage.
    RealizationPartial,
    /// All supported reconciliation facts agree with intended behavior.
    RealizedCoherent,
    /// Supported semantics contradict intended behavior.
    RealizedContradicted,
}

/// Intended/realized transition reconciliation state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeReconciliationState {
    /// Authored transition has a supported implementation-semantic path.
    IntendedAndRealized,
    /// Intent exists but current semantics cannot prove a path.
    IntendedUnproven,
    /// Supported next-checkpoint behavior is absent from intent.
    RealizedUndeclared,
    /// Supported semantics prove the authored transition impossible.
    IntendedProvenImpossible,
}

/// Source semantic authority for one implementation event.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAuthority {
    /// Canonical PSM executable/control semantics.
    ProgramSemanticModel,
    /// Canonical State and Effect Analysis.
    StateEffectAnalysis,
    /// Canonical Information Flow Analysis.
    InformationFlowAnalysis,
    /// Canonical Environmental Analysis.
    EnvironmentalAnalysis,
}

/// One language-neutral semantic implementation event.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ImplementationEvent {
    id: String,
    kind: String,
    responsible_symbol: Option<String>,
    module: String,
    authority: EventAuthority,
    provenance: Vec<String>,
    coverage: RealizationCoverage,
}

impl ImplementationEvent {
    /// Returns the content-addressed event identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the semantic event kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// Returns the responsible executable when applicable.
    #[must_use]
    pub fn responsible_symbol(&self) -> Option<&str> {
        self.responsible_symbol.as_deref()
    }
    /// Returns the Fortress Module lane.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }
}

/// One supported implementation-event transition.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ImplementationEventEdge {
    source: String,
    target: String,
    coverage: RealizationCoverage,
    derivation: String,
}

/// Canonical implementation event graph derived without reparsing source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImplementationEventModel {
    semantic_version: String,
    events: Vec<ImplementationEvent>,
    edges: Vec<ImplementationEventEdge>,
    unsupported_semantics: Vec<String>,
}

impl ImplementationEventModel {
    /// Returns canonical semantic events.
    #[must_use]
    pub fn events(&self) -> &[ImplementationEvent] {
        &self.events
    }
    /// Returns canonical event edges.
    #[must_use]
    pub fn edges(&self) -> &[ImplementationEventEdge] {
        &self.edges
    }
}

/// One checkpoint projected onto its alternative implementation events.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RealizedCheckpoint {
    checkpoint: String,
    state: CheckpointRealizationState,
    anchor_events: Vec<String>,
    anchor_kinds: Vec<String>,
    coverage: RealizationCoverage,
    provenance: Vec<String>,
}

/// One next-semantic-checkpoint transition and supporting path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RealizedTransition {
    source: String,
    target: String,
    state: EdgeReconciliationState,
    implementation_path: Vec<String>,
    coverage: RealizationCoverage,
}

impl RealizedTransition {
    /// Returns the source checkpoint.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Returns the target checkpoint.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Returns the reconciliation state.
    #[must_use]
    pub const fn state(&self) -> EdgeReconciliationState {
        self.state
    }
}

/// One proven route bypassing an Intended BFG dominator.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BehavioralBypass {
    feature: String,
    required_dominator: String,
    reached_checkpoint: String,
    implementation_path: Vec<String>,
    anchor_provenance: Vec<String>,
    coverage: RealizationCoverage,
}

/// One deterministic later verification obligation; it is not evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BehavioralVerificationObligation {
    id: String,
    feature: String,
    proposition: String,
    checkpoints: Vec<String>,
    evidence_status: String,
}

/// Per-Feature realized behavior projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RealizedFeatureFlow {
    feature: String,
    state: FeatureRealizationState,
    checkpoints: Vec<RealizedCheckpoint>,
    transitions: Vec<RealizedTransition>,
    bypasses: Vec<BehavioralBypass>,
    bypass_freedom: RealizationCoverage,
    terminal_reconciliations: usize,
    decision_reconciliations: usize,
}

impl RealizedFeatureFlow {
    /// Returns the Feature identity.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }
    /// Returns the aggregate realization state.
    #[must_use]
    pub const fn state(&self) -> FeatureRealizationState {
        self.state
    }
    /// Returns reconciled transitions.
    #[must_use]
    pub fn transitions(&self) -> &[RealizedTransition] {
        &self.transitions
    }
    /// Returns proven bypasses.
    #[must_use]
    pub fn bypasses(&self) -> &[BehavioralBypass] {
        &self.bypasses
    }
}

/// Aggregate Realized BFG counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RealizedBfgSummary {
    opted_in_features: usize,
    modeled_unrealized_features: usize,
    checkpoints: usize,
    anchors: usize,
    realized_checkpoints: usize,
    partial_checkpoints: usize,
    unreachable_checkpoints: usize,
    unknown_checkpoints: usize,
    contradicted_checkpoints: usize,
    intended_and_realized_edges: usize,
    intended_unproven_edges: usize,
    realized_undeclared_edges: usize,
    intended_proven_impossible_edges: usize,
    dominator_checks: usize,
    proven_bypasses: usize,
    terminal_reconciliations: usize,
    decision_reconciliations: usize,
    verification_obligations: usize,
}

impl RealizedBfgSummary {
    /// Returns opted-in Feature count.
    #[must_use]
    pub const fn opted_in_features(self) -> usize {
        self.opted_in_features
    }
    /// Returns proven realization-rule contradiction count.
    #[must_use]
    pub const fn realization_violations(self) -> usize {
        self.realized_undeclared_edges + self.intended_proven_impossible_edges
    }
    /// Returns proven bypass count.
    #[must_use]
    pub const fn proven_bypasses(self) -> usize {
        self.proven_bypasses
    }
}

/// Canonical Realized BFG v1 derived information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RealizedBehavioralFlowGraph {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: String,
    view: String,
    intended_bfg_digest: String,
    psm_digest: String,
    semantic_analysis_digest: String,
    state_effect_digest: String,
    information_flow_digest: String,
    environmental_analysis_digest: String,
    realization_contract_digest: String,
    summary: RealizedBfgSummary,
    feature_states: Vec<(String, FeatureRealizationState)>,
    implementation_events: ImplementationEventModel,
    flows: Vec<RealizedFeatureFlow>,
    verification_obligations: Vec<BehavioralVerificationObligation>,
    unsupported_semantics: Vec<String>,
}

impl RealizedBehavioralFlowGraph {
    /// Returns aggregate realization counts.
    #[must_use]
    pub const fn summary(&self) -> RealizedBfgSummary {
        self.summary
    }
    /// Returns per-Feature realization projections.
    #[must_use]
    pub fn flows(&self) -> &[RealizedFeatureFlow] {
        &self.flows
    }
    /// Returns deterministic verification obligations without claiming evidence.
    #[must_use]
    pub fn verification_obligations(&self) -> &[BehavioralVerificationObligation] {
        &self.verification_obligations
    }
    /// Returns explicit semantic limits.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[String] {
        &self.unsupported_semantics
    }
    /// Serializes deterministic two-space JSON with one trailing LF.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if canonical serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }
    /// Computes SHA-256 over canonical bytes without embedding the digest.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if canonical serialization fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_json()?.as_bytes())
        ))
    }
}

/// Rule-facing realized-behavior evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehavioralRealizationEvaluation {
    graph: RealizedBehavioralFlowGraph,
    realization_findings: Vec<CanonicalFinding>,
    bypass_findings: Vec<CanonicalFinding>,
}

impl BehavioralRealizationEvaluation {
    /// Returns the canonical Realized BFG.
    #[must_use]
    pub const fn graph(&self) -> &RealizedBehavioralFlowGraph {
        &self.graph
    }
    /// Returns BEHAVIOR-REALIZATION-001 findings.
    #[must_use]
    pub fn realization_findings(&self) -> &[CanonicalFinding] {
        &self.realization_findings
    }
    /// Returns BEHAVIOR-BYPASS-001 findings.
    #[must_use]
    pub fn bypass_findings(&self) -> &[CanonicalFinding] {
        &self.bypass_findings
    }
}

/// Behavioral Realization construction failure.
#[derive(Debug)]
pub enum BehavioralRealizationError {
    /// Canonical model serialization failed.
    Serialization(serde_json::Error),
    /// Canonical finding normalization failed.
    Finding(FindingError),
}

impl Display for BehavioralRealizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(formatter, "realized BFG serialization failed: {error}")
            }
            Self::Finding(error) => {
                write!(formatter, "behavioral realization finding failed: {error}")
            }
        }
    }
}

impl Error for BehavioralRealizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug)]
struct CallSite {
    caller: String,
    callee: Option<String>,
    state: CallResolutionState,
    reference: String,
    path: String,
    line: u32,
    column: u32,
    sequence: usize,
}

#[derive(Default)]
struct EventBuilder {
    events: BTreeMap<String, ImplementationEvent>,
    edges: BTreeSet<ImplementationEventEdge>,
    call_sites: BTreeMap<String, Vec<CallSite>>,
    call_cursors: BTreeMap<String, usize>,
    sequence: usize,
}

impl EventBuilder {
    #[allow(clippy::too_many_arguments)]
    fn add_event(
        &mut self,
        kind: &str,
        key: &str,
        symbol: Option<&str>,
        module: &str,
        authority: EventAuthority,
        provenance: Vec<String>,
        coverage: RealizationCoverage,
    ) -> String {
        let id = event_id(kind, key);
        self.events
            .entry(id.clone())
            .or_insert(ImplementationEvent {
                id: id.clone(),
                kind: kind.into(),
                responsible_symbol: symbol.map(str::to_owned),
                module: module.into(),
                authority,
                provenance,
                coverage,
            });
        id
    }

    fn add_edge(
        &mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        coverage: RealizationCoverage,
        derivation: impl Into<String>,
    ) {
        self.edges.insert(ImplementationEventEdge {
            source: source.into(),
            target: target.into(),
            coverage,
            derivation: derivation.into(),
        });
    }

    fn consume_call(&mut self, caller: &str, reference: &str) -> Option<CallSite> {
        let sites = self.call_sites.get(caller)?;
        let cursor = self.call_cursors.entry(caller.into()).or_default();
        let index = sites
            .iter()
            .enumerate()
            .skip(*cursor)
            .find(|(_, site)| {
                site.reference == reference
                    || site.reference.ends_with(&format!("::{reference}"))
                    || reference.ends_with(&site.reference)
            })
            .map(|(index, _)| index)
            .or_else(|| (*cursor < sites.len()).then_some(*cursor))?;
        *cursor = index + 1;
        Some(sites[index].clone())
    }
}

/// Derives one canonical implementation-event graph from existing semantic models.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn derive_implementation_events(
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisModel,
    state_effect: &StateEffectAnalysisModel,
    information_flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
) -> ImplementationEventModel {
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut builder = EventBuilder::default();
    for symbol in psm.symbols() {
        let provenance = vec![format!(
            "{}:{}:{}",
            symbol.provenance().path(),
            symbol.provenance().location().line(),
            symbol.provenance().location().column()
        )];
        builder.add_event(
            "symbol_entry",
            symbol.id(),
            Some(symbol.id()),
            symbol.fortress_module(),
            EventAuthority::ProgramSemanticModel,
            provenance.clone(),
            RealizationCoverage::Proven,
        );
        builder.add_event(
            "symbol_return",
            symbol.id(),
            Some(symbol.id()),
            symbol.fortress_module(),
            EventAuthority::ProgramSemanticModel,
            provenance,
            RealizationCoverage::Proven,
        );
    }
    for summary in semantic.summaries() {
        if let SemanticDomain::Boolean { values, .. } = summary.inferred_output_domain() {
            for value in values {
                let event = builder.add_event(
                    "symbol_return_boolean",
                    &format!("{}:{value}", summary.symbol()),
                    Some(summary.symbol()),
                    symbols
                        .get(summary.symbol())
                        .map_or("", |symbol| symbol.fortress_module()),
                    EventAuthority::ProgramSemanticModel,
                    symbols
                        .get(summary.symbol())
                        .map_or_else(Vec::new, |symbol| vec![symbol.source_path().into()]),
                    RealizationCoverage::Proven,
                );
                builder.add_edge(
                    event_id("symbol_return", summary.symbol()),
                    event,
                    RealizationCoverage::Proven,
                    "boolean_return_domain",
                );
            }
        }
    }
    for call in psm.calls() {
        for evidence in call.evidence() {
            let location = evidence.provenance().location();
            let sequence = builder.sequence;
            builder.sequence += 1;
            builder
                .call_sites
                .entry(call.caller().into())
                .or_default()
                .push(CallSite {
                    caller: call.caller().into(),
                    callee: call.callee().map(str::to_owned),
                    state: call.state(),
                    reference: evidence.reference().into(),
                    path: evidence.provenance().path().into(),
                    line: location.line(),
                    column: location.column(),
                    sequence,
                });
        }
    }
    for sites in builder.call_sites.values_mut() {
        sites.sort_by(|left, right| {
            (left.path.as_str(), left.line, left.column, left.sequence).cmp(&(
                right.path.as_str(),
                right.line,
                right.column,
                right.sequence,
            ))
        });
    }
    let fallback_sites = builder.call_sites.clone();
    for (caller, sites) in fallback_sites {
        let resolved = sites
            .iter()
            .filter_map(|site| site.callee.as_deref())
            .collect::<Vec<_>>();
        if let Some(first) = resolved.first() {
            builder.add_edge(
                event_id("symbol_entry", &caller),
                event_id("symbol_entry", first),
                RealizationCoverage::Partial,
                "lexical_call_order_fallback",
            );
        }
        for pair in resolved.windows(2) {
            builder.add_edge(
                event_id("symbol_return", pair[0]),
                event_id("symbol_entry", pair[1]),
                RealizationCoverage::Partial,
                "lexical_call_order_fallback",
            );
        }
        if let Some(last) = resolved.last() {
            builder.add_edge(
                event_id("symbol_return", last),
                event_id("symbol_return", &caller),
                RealizationCoverage::Partial,
                "lexical_call_order_fallback",
            );
        }
    }
    for body in psm.bodies() {
        let Some(symbol) = symbols.get(body.symbol()) else {
            continue;
        };
        let entry = event_id("symbol_entry", body.symbol());
        let returned = event_id("symbol_return", body.symbol());
        let exits = lower_block(
            &mut builder,
            body.symbol(),
            symbol.fortress_module(),
            body.statements(),
            vec![entry],
            &symbols,
        );
        for exit in exits {
            builder.add_edge(
                exit,
                returned.clone(),
                RealizationCoverage::Proven,
                "normal_return",
            );
        }
    }
    for symbol in psm.symbols() {
        if !psm.bodies().iter().any(|body| body.symbol() == symbol.id()) {
            builder.add_edge(
                event_id("symbol_entry", symbol.id()),
                event_id("symbol_return", symbol.id()),
                RealizationCoverage::Partial,
                "opaque_declaration_return",
            );
        }
    }
    derive_state_effect_events(&mut builder, &symbols, state_effect);
    derive_information_events(&mut builder, &symbols, information_flow);
    derive_environment_events(&mut builder, &symbols, environmental);
    ImplementationEventModel {
        semantic_version: BEHAVIORAL_REALIZATION_VERSION.into(),
        events: builder.events.into_values().collect(),
        edges: builder.edges.into_iter().collect(),
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
    }
}

#[allow(clippy::too_many_lines)]
fn lower_block(
    builder: &mut EventBuilder,
    caller: &str,
    module: &str,
    statements: &[ProgramStatement],
    mut inputs: Vec<String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
) -> Vec<String> {
    for statement in statements {
        inputs = match statement {
            ProgramStatement::Let { value, .. } => value.as_ref().map_or(inputs.clone(), |value| {
                lower_expression(builder, caller, module, value, inputs.clone(), symbols)
            }),
            ProgramStatement::Assign { value, .. } | ProgramStatement::Expression { value, .. } => {
                lower_expression(builder, caller, module, value, inputs, symbols)
            }
            ProgramStatement::Return { value, .. } => {
                let exits = if let Some(value) = value {
                    lower_expression(builder, caller, module, value, inputs, symbols)
                } else {
                    inputs
                };
                let returned = event_id("symbol_return", caller);
                for exit in exits {
                    builder.add_edge(
                        exit,
                        returned.clone(),
                        RealizationCoverage::Proven,
                        "explicit_return",
                    );
                }
                Vec::new()
            }
            ProgramStatement::If {
                condition,
                then_branch,
                else_branch,
                provenance,
            } => {
                let condition_exits =
                    lower_expression(builder, caller, module, condition, inputs, symbols);
                let branch = builder.add_event(
                    "control_decision",
                    &format!(
                        "{caller}:{}:{}:{}",
                        provenance.path(),
                        provenance.location().line(),
                        provenance.location().column()
                    ),
                    Some(caller),
                    module,
                    EventAuthority::ProgramSemanticModel,
                    vec![provenance.path().into()],
                    RealizationCoverage::Proven,
                );
                for exit in condition_exits {
                    builder.add_edge(
                        exit,
                        branch.clone(),
                        RealizationCoverage::Proven,
                        "if_condition",
                    );
                }
                let mut outputs = lower_block(
                    builder,
                    caller,
                    module,
                    then_branch,
                    vec![branch.clone()],
                    symbols,
                );
                outputs.extend(lower_block(
                    builder,
                    caller,
                    module,
                    else_branch,
                    vec![branch],
                    symbols,
                ));
                outputs.sort();
                outputs.dedup();
                outputs
            }
            ProgramStatement::Match {
                value,
                arms,
                provenance,
            } => {
                let value_exits = lower_expression(builder, caller, module, value, inputs, symbols);
                lower_match(
                    builder,
                    caller,
                    module,
                    arms,
                    provenance.path(),
                    provenance.location().line(),
                    value_exits,
                    symbols,
                )
            }
            ProgramStatement::WhileLet {
                value,
                body,
                provenance,
                ..
            } => {
                let loop_head = builder.add_event(
                    "control_loop",
                    &format!(
                        "{caller}:{}:{}:{}",
                        provenance.path(),
                        provenance.location().line(),
                        provenance.location().column()
                    ),
                    Some(caller),
                    module,
                    EventAuthority::ProgramSemanticModel,
                    vec![provenance.path().into()],
                    RealizationCoverage::Proven,
                );
                for input in inputs {
                    builder.add_edge(
                        input,
                        loop_head.clone(),
                        RealizationCoverage::Proven,
                        "loop_entry",
                    );
                }
                let condition = lower_expression(
                    builder,
                    caller,
                    module,
                    value,
                    vec![loop_head.clone()],
                    symbols,
                );
                let body_exits =
                    lower_block(builder, caller, module, body, condition.clone(), symbols);
                for exit in body_exits {
                    builder.add_edge(
                        exit,
                        loop_head.clone(),
                        RealizationCoverage::Proven,
                        "loop_back_edge",
                    );
                }
                condition
            }
        };
    }
    inputs
}

#[allow(clippy::too_many_arguments)]
fn lower_match(
    builder: &mut EventBuilder,
    caller: &str,
    module: &str,
    arms: &[ProgramMatchArm],
    path: &str,
    line: u32,
    inputs: Vec<String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
) -> Vec<String> {
    let decision = builder.add_event(
        "control_decision",
        &format!("{caller}:{path}:{line}:match"),
        Some(caller),
        module,
        EventAuthority::ProgramSemanticModel,
        vec![path.into()],
        RealizationCoverage::Proven,
    );
    for input in inputs {
        builder.add_edge(
            input,
            decision.clone(),
            RealizationCoverage::Proven,
            "match_scrutinee",
        );
    }
    let mut outputs = Vec::new();
    for arm in arms {
        let arm_inputs = arm.guard().map_or(vec![decision.clone()], |guard| {
            lower_expression(
                builder,
                caller,
                module,
                guard,
                vec![decision.clone()],
                symbols,
            )
        });
        outputs.extend(lower_block(
            builder,
            caller,
            module,
            arm.body(),
            arm_inputs,
            symbols,
        ));
    }
    outputs.sort();
    outputs.dedup();
    outputs
}

fn lower_expression(
    builder: &mut EventBuilder,
    caller: &str,
    module: &str,
    expression: &ProgramExpression,
    inputs: Vec<String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
) -> Vec<String> {
    match expression {
        ProgramExpression::Call {
            reference,
            arguments,
        } => {
            let mut exits = inputs;
            for argument in arguments {
                exits = lower_expression(builder, caller, module, argument, exits, symbols);
            }
            lower_call(builder, caller, module, reference, exits, symbols)
        }
        ProgramExpression::MethodCall {
            receiver,
            method,
            arguments,
        } => {
            let mut exits = lower_expression(builder, caller, module, receiver, inputs, symbols);
            for argument in arguments {
                exits = lower_expression(builder, caller, module, argument, exits, symbols);
            }
            lower_call(builder, caller, module, method, exits, symbols)
        }
        ProgramExpression::Tuple { elements } => {
            lower_expressions(builder, caller, module, elements, inputs, symbols)
        }
        ProgramExpression::Field { base, .. }
        | ProgramExpression::PatternTest { value: base, .. }
        | ProgramExpression::Unary { value: base, .. }
        | ProgramExpression::Try { value: base }
        | ProgramExpression::Reference { value: base, .. } => {
            lower_expression(builder, caller, module, base, inputs, symbols)
        }
        ProgramExpression::Construction { arguments, .. } => {
            lower_expressions(builder, caller, module, arguments, inputs, symbols)
        }
        ProgramExpression::Binary { left, right, .. } => {
            let exits = lower_expression(builder, caller, module, left, inputs, symbols);
            lower_expression(builder, caller, module, right, exits, symbols)
        }
        ProgramExpression::Binding { .. }
        | ProgramExpression::Boolean { .. }
        | ProgramExpression::Integer { .. }
        | ProgramExpression::Unit
        | ProgramExpression::Variant { .. }
        | ProgramExpression::Exceptional { .. }
        | ProgramExpression::Unsupported { .. } => inputs,
    }
}

fn lower_expressions(
    builder: &mut EventBuilder,
    caller: &str,
    module: &str,
    expressions: &[ProgramExpression],
    mut inputs: Vec<String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
) -> Vec<String> {
    for expression in expressions {
        inputs = lower_expression(builder, caller, module, expression, inputs, symbols);
    }
    inputs
}

fn lower_call(
    builder: &mut EventBuilder,
    caller: &str,
    module: &str,
    reference: &str,
    inputs: Vec<String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
) -> Vec<String> {
    let Some(call) = builder.consume_call(caller, reference) else {
        return inputs;
    };
    let key = format!(
        "{}:{}:{}:{}:{}",
        call.caller, call.path, call.line, call.column, call.sequence
    );
    let before = builder.add_event(
        "call_site",
        &format!("{key}:before"),
        Some(caller),
        module,
        EventAuthority::ProgramSemanticModel,
        vec![format!("{}:{}:{}", call.path, call.line, call.column)],
        if call.state == CallResolutionState::ResolvedStatic {
            RealizationCoverage::Proven
        } else {
            RealizationCoverage::Partial
        },
    );
    let after = builder.add_event(
        "call_return",
        &format!("{key}:after"),
        Some(caller),
        module,
        EventAuthority::ProgramSemanticModel,
        vec![format!("{}:{}:{}", call.path, call.line, call.column)],
        if call.state == CallResolutionState::ResolvedStatic {
            RealizationCoverage::Proven
        } else {
            RealizationCoverage::Partial
        },
    );
    for input in inputs {
        builder.add_edge(
            input,
            before.clone(),
            RealizationCoverage::Proven,
            "expression_order",
        );
    }
    if let Some(callee) = call
        .callee
        .filter(|value| symbols.contains_key(value.as_str()))
    {
        builder.add_edge(
            before,
            event_id("symbol_entry", &callee),
            RealizationCoverage::Proven,
            "resolved_static_call",
        );
        builder.add_edge(
            event_id("symbol_return", &callee),
            after.clone(),
            RealizationCoverage::Partial,
            "context_insensitive_static_return",
        );
    } else {
        builder.add_edge(
            before,
            after.clone(),
            RealizationCoverage::Partial,
            "opaque_call_continuation",
        );
    }
    vec![after]
}

fn derive_state_effect_events(
    builder: &mut EventBuilder,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
    model: &StateEffectAnalysisModel,
) {
    for summary in model.summaries() {
        let Some(symbol) = symbols.get(summary.symbol()) else {
            continue;
        };
        if let (Some(from), Some(to)) = (
            summary.input_receiver_state(),
            summary.output_receiver_state(),
        ) {
            let key = format!("{}:{from:?}:{to:?}", summary.symbol());
            let event = builder.add_event(
                "state_transition",
                &key,
                Some(summary.symbol()),
                symbol.fortress_module(),
                EventAuthority::StateEffectAnalysis,
                vec![symbol.source_path().into()],
                match summary.state_postcondition_coverage() {
                    StateEffectCoverage::Proven => RealizationCoverage::Proven,
                    StateEffectCoverage::Partial => RealizationCoverage::Partial,
                    StateEffectCoverage::Unknown => RealizationCoverage::Unknown,
                    StateEffectCoverage::Unsupported => RealizationCoverage::Unsupported,
                },
            );
            builder.add_edge(
                event_id("symbol_entry", summary.symbol()),
                event.clone(),
                RealizationCoverage::Proven,
                "state_summary_input",
            );
            builder.add_edge(
                event,
                event_id("symbol_return", summary.symbol()),
                RealizationCoverage::Proven,
                "state_summary_output",
            );
        }
        for effect in summary.direct_effects() {
            let event = builder.add_event(
                "effect",
                &format!("{}:{effect:?}", summary.symbol()),
                Some(summary.symbol()),
                symbol.fortress_module(),
                EventAuthority::StateEffectAnalysis,
                vec![symbol.source_path().into()],
                RealizationCoverage::Proven,
            );
            builder.add_edge(
                event_id("symbol_entry", summary.symbol()),
                event.clone(),
                RealizationCoverage::Proven,
                "direct_effect",
            );
            builder.add_edge(
                event,
                event_id("symbol_return", summary.symbol()),
                RealizationCoverage::Proven,
                "effect_completion",
            );
        }
    }
}

fn derive_information_events(
    builder: &mut EventBuilder,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
    model: &InformationFlowAnalysisModel,
) {
    for diagnostic in model.trusted_transition_diagnostics() {
        let Some(symbol) = symbols.get(diagnostic.symbol()) else {
            continue;
        };
        let key = format!(
            "{}:{:?}:{}:{}:{}",
            diagnostic.symbol(),
            diagnostic.kind(),
            diagnostic.facet(),
            diagnostic.from(),
            diagnostic.to()
        );
        let event = builder.add_event(
            "information_transition",
            &key,
            Some(diagnostic.symbol()),
            symbol.fortress_module(),
            EventAuthority::InformationFlowAnalysis,
            vec![diagnostic.contract_provenance().into()],
            RealizationCoverage::Proven,
        );
        builder.add_edge(
            event_id("symbol_entry", diagnostic.symbol()),
            event.clone(),
            RealizationCoverage::Proven,
            "trusted_transition",
        );
        builder.add_edge(
            event,
            event_id("symbol_return", diagnostic.symbol()),
            RealizationCoverage::Proven,
            "trusted_transition_completion",
        );
    }
}

fn derive_environment_events(
    builder: &mut EventBuilder,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
    model: &EnvironmentalAnalysisModel,
) {
    for operation in model.operations() {
        let Some(symbol) = symbols.get(operation.boundary()) else {
            continue;
        };
        for outcome in operation.outcomes() {
            let coverage = match outcome.handling() {
                HandlingStatus::Handled => RealizationCoverage::Proven,
                HandlingStatus::PartiallyHandled => RealizationCoverage::Partial,
                HandlingStatus::Unknown | HandlingStatus::Unhandled => RealizationCoverage::Unknown,
                HandlingStatus::Unsupported => RealizationCoverage::Unsupported,
            };
            let event = builder.add_event(
                "environment_outcome",
                &format!("{}:{}", operation.operation(), outcome.id()),
                Some(operation.boundary()),
                symbol.fortress_module(),
                EventAuthority::EnvironmentalAnalysis,
                vec![outcome.provenance().into()],
                coverage,
            );
            builder.add_edge(
                event_id("symbol_entry", operation.boundary()),
                event.clone(),
                RealizationCoverage::Proven,
                "admissible_environment_outcome",
            );
            let target = outcome.continuation().map_or_else(
                || event_id("symbol_return", operation.boundary()),
                |continuation| event_id("symbol_entry", continuation),
            );
            builder.add_edge(event, target, coverage, "environment_outcome_continuation");
        }
    }
}

/// Compiles one Realized BFG from already-compiled semantic authorities.
///
/// # Errors
///
/// Returns an error only when canonical upstream digests cannot serialize.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn compile_realized_bfg(
    _ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisModel,
    state_effect: &StateEffectAnalysisModel,
    information_flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
    contracts: &ResolvedBehaviorRealizationContracts,
) -> Result<RealizedBehavioralFlowGraph, BehavioralRealizationError> {
    let event_model =
        derive_implementation_events(psm, semantic, state_effect, information_flow, environmental);
    let graph = EventGraph::new(&event_model);
    let summaries = semantic
        .summaries()
        .iter()
        .map(|summary| (summary.symbol(), summary.inferred_output_domain()))
        .collect::<BTreeMap<_, _>>();
    let by_checkpoint = contracts
        .checkpoints()
        .iter()
        .map(|checkpoint| (checkpoint.checkpoint(), checkpoint))
        .collect::<BTreeMap<_, _>>();
    let mut feature_states = Vec::new();
    let mut flows = Vec::new();
    let mut obligations = Vec::new();
    for state in intended.feature_states() {
        if state.state() == BehavioralModelingState::Unmodeled {
            feature_states.push((state.feature().into(), FeatureRealizationState::Unmodeled));
        } else if !contracts
            .features()
            .iter()
            .any(|feature| feature == state.feature())
        {
            feature_states.push((
                state.feature().into(),
                FeatureRealizationState::ModeledUnrealized,
            ));
        }
    }
    for intended_flow in intended.flows() {
        if !contracts
            .features()
            .iter()
            .any(|feature| feature == intended_flow.feature())
        {
            continue;
        }
        let (flow, mut feature_obligations) = realize_feature(
            intended_flow,
            &by_checkpoint,
            &event_model,
            &graph,
            &summaries,
        );
        feature_states.push((intended_flow.feature().into(), flow.state));
        obligations.append(&mut feature_obligations);
        flows.push(flow);
    }
    feature_states.sort();
    flows.sort_by(|left, right| left.feature.cmp(&right.feature));
    obligations.sort();
    obligations.dedup();
    let summary = summarize(
        intended,
        contracts,
        &feature_states,
        &flows,
        obligations.len(),
    );
    Ok(RealizedBehavioralFlowGraph {
        schema: REALIZED_BFG_SCHEMA.into(),
        schema_version: REALIZED_BFG_SCHEMA_VERSION,
        semantic_version: BEHAVIORAL_REALIZATION_VERSION.into(),
        project_id: psm.project_id().into(),
        view: "realized".into(),
        intended_bfg_digest: intended
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        psm_digest: psm
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        semantic_analysis_digest: semantic
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        state_effect_digest: state_effect
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        information_flow_digest: information_flow
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        environmental_analysis_digest: environmental
            .digest()
            .map_err(BehavioralRealizationError::Serialization)?,
        realization_contract_digest: contracts.digest().into(),
        summary,
        feature_states,
        implementation_events: event_model,
        flows,
        verification_obligations: obligations,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
    })
}

#[derive(Clone)]
struct EventGraph {
    adjacency: BTreeMap<String, Vec<(String, RealizationCoverage)>>,
}

impl EventGraph {
    fn new(model: &ImplementationEventModel) -> Self {
        let mut adjacency = BTreeMap::<String, Vec<(String, RealizationCoverage)>>::new();
        for event in model.events() {
            adjacency.entry(event.id().into()).or_default();
        }
        for edge in model.edges() {
            adjacency
                .entry(edge.source.clone())
                .or_default()
                .push((edge.target.clone(), edge.coverage));
        }
        for targets in adjacency.values_mut() {
            targets.sort();
            targets.dedup();
        }
        Self { adjacency }
    }

    fn path(
        &self,
        sources: &[String],
        targets: &BTreeSet<String>,
        forbidden: &BTreeSet<String>,
    ) -> Option<(Vec<String>, RealizationCoverage)> {
        let mut queue = VecDeque::new();
        let mut previous = BTreeMap::<String, (String, RealizationCoverage)>::new();
        let mut coverage = BTreeMap::<String, RealizationCoverage>::new();
        for source in sources {
            if !forbidden.contains(source) {
                queue.push_back(source.clone());
                coverage.insert(source.clone(), RealizationCoverage::Proven);
            }
        }
        while let Some(current) = queue.pop_front() {
            if targets.contains(&current) {
                let mut path = vec![current.clone()];
                let mut cursor = current.clone();
                while let Some((parent, _)) = previous.get(&cursor) {
                    path.push(parent.clone());
                    cursor = parent.clone();
                }
                path.reverse();
                return Some((
                    path,
                    coverage
                        .get(&current)
                        .copied()
                        .unwrap_or(RealizationCoverage::Unknown),
                ));
            }
            for (next, edge_coverage) in self.adjacency.get(&current).into_iter().flatten() {
                if forbidden.contains(next) || coverage.contains_key(next) {
                    continue;
                }
                let combined = combine_coverage(
                    coverage
                        .get(&current)
                        .copied()
                        .unwrap_or(RealizationCoverage::Unknown),
                    *edge_coverage,
                );
                coverage.insert(next.clone(), combined);
                previous.insert(next.clone(), (current.clone(), *edge_coverage));
                queue.push_back(next.clone());
            }
        }
        None
    }
}

#[allow(clippy::too_many_lines)]
fn realize_feature(
    intended: &IntendedFeatureFlow,
    contracts: &BTreeMap<&str, &ResolvedCheckpointRealization>,
    event_model: &ImplementationEventModel,
    graph: &EventGraph,
    summaries: &BTreeMap<&str, &SemanticDomain>,
) -> (RealizedFeatureFlow, Vec<BehavioralVerificationObligation>) {
    let event_ids = event_model
        .events()
        .iter()
        .map(ImplementationEvent::id)
        .collect::<BTreeSet<_>>();
    let mut checkpoint_events = BTreeMap::<String, Vec<String>>::new();
    let mut checkpoints = Vec::new();
    for node in intended.nodes() {
        let contract = contracts
            .get(node.checkpoint())
            .expect("validated opted-in Feature has every checkpoint");
        let mut anchors = Vec::new();
        let mut kinds = Vec::new();
        let mut exact = 0usize;
        let mut uncertain = 0usize;
        for anchor in contract.anchors() {
            kinds.push(anchor.kind().into());
            if let Some(id) = resolve_anchor_event(anchor, summaries) {
                if event_ids.contains(id.as_str()) {
                    anchors.push(id);
                    exact += 1;
                } else {
                    uncertain += 1;
                }
            } else {
                uncertain += 1;
            }
        }
        anchors.sort();
        anchors.dedup();
        kinds.sort();
        kinds.dedup();
        let (state, coverage) = if exact > 0 && uncertain == 0 {
            (
                CheckpointRealizationState::Realized,
                RealizationCoverage::Proven,
            )
        } else if exact > 0 {
            (
                CheckpointRealizationState::PartiallyRealized,
                RealizationCoverage::Partial,
            )
        } else {
            (
                CheckpointRealizationState::Unknown,
                RealizationCoverage::Unknown,
            )
        };
        checkpoint_events.insert(node.checkpoint().into(), anchors.clone());
        checkpoints.push(RealizedCheckpoint {
            checkpoint: node.checkpoint().into(),
            state,
            anchor_events: anchors,
            anchor_kinds: kinds,
            coverage,
            provenance: vec![
                contract.source_path().into(),
                contract.pointer().into(),
                node.provenance().path().into(),
                node.provenance().pointer().into(),
            ],
        });
    }
    checkpoints.sort();
    let intended_edges = intended
        .edges()
        .iter()
        .map(|edge| (edge.source(), edge.target()))
        .collect::<BTreeSet<_>>();
    let mut realized_pairs =
        BTreeMap::<(String, String), (Vec<String>, RealizationCoverage)>::new();
    for (source, sources) in &checkpoint_events {
        let forbidden = checkpoint_events
            .iter()
            .filter(|(checkpoint, _)| *checkpoint != source)
            .flat_map(|(_, values)| values.iter().cloned())
            .collect::<BTreeSet<_>>();
        for (target, target_events) in &checkpoint_events {
            if target == source {
                continue;
            }
            let targets = target_events.iter().cloned().collect::<BTreeSet<_>>();
            let allowed_forbidden = forbidden
                .difference(&targets)
                .cloned()
                .collect::<BTreeSet<_>>();
            if let Some(path) = graph.path(sources, &targets, &allowed_forbidden) {
                realized_pairs.insert((source.clone(), target.clone()), path);
            }
        }
    }
    let mut transitions = Vec::new();
    for edge in intended.edges() {
        let key = (edge.source().to_owned(), edge.target().to_owned());
        if let Some((path, coverage)) = realized_pairs.get(&key) {
            transitions.push(RealizedTransition {
                source: key.0,
                target: key.1,
                state: EdgeReconciliationState::IntendedAndRealized,
                implementation_path: path.clone(),
                coverage: *coverage,
            });
        } else {
            transitions.push(RealizedTransition {
                source: key.0,
                target: key.1,
                state: EdgeReconciliationState::IntendedUnproven,
                implementation_path: Vec::new(),
                coverage: RealizationCoverage::Unknown,
            });
        }
    }
    for ((source, target), (path, coverage)) in &realized_pairs {
        if !intended_edges.contains(&(source.as_str(), target.as_str()))
            && *coverage == RealizationCoverage::Proven
        {
            transitions.push(RealizedTransition {
                source: source.clone(),
                target: target.clone(),
                state: EdgeReconciliationState::RealizedUndeclared,
                implementation_path: path.clone(),
                coverage: *coverage,
            });
        }
    }
    transitions.sort();
    transitions.dedup();
    let (bypasses, dominator_checks, bypass_freedom) =
        derive_bypasses(intended, &checkpoint_events, graph, contracts);
    let contradicted = transitions.iter().any(|transition| {
        matches!(
            transition.state,
            EdgeReconciliationState::RealizedUndeclared
                | EdgeReconciliationState::IntendedProvenImpossible
        )
    }) || !bypasses.is_empty();
    let partial = checkpoints
        .iter()
        .any(|checkpoint| checkpoint.state != CheckpointRealizationState::Realized)
        || transitions
            .iter()
            .any(|transition| transition.state == EdgeReconciliationState::IntendedUnproven);
    let state = if contradicted {
        FeatureRealizationState::RealizedContradicted
    } else if partial {
        FeatureRealizationState::RealizationPartial
    } else {
        FeatureRealizationState::RealizedCoherent
    };
    let terminal_reconciliations = intended
        .terminal_checkpoints()
        .iter()
        .filter(|terminal| {
            checkpoints.iter().any(|checkpoint| {
                checkpoint.checkpoint == **terminal
                    && checkpoint.state == CheckpointRealizationState::Realized
            })
        })
        .count();
    let decision_reconciliations = intended
        .decision_branches()
        .iter()
        .filter(|branch| {
            transitions.iter().any(|transition| {
                transition.source == branch.decision()
                    && transition.target == branch.target()
                    && transition.state == EdgeReconciliationState::IntendedAndRealized
            })
        })
        .count();
    let mut obligations = intended
        .edges()
        .iter()
        .map(|edge| {
            verification_obligation(
                intended.feature(),
                "checkpoint_transition",
                vec![edge.source().into(), edge.target().into()],
            )
        })
        .collect::<Vec<_>>();
    for domination in intended.immediate_dominators() {
        if let Some(dominator) = domination.immediate() {
            obligations.push(verification_obligation(
                intended.feature(),
                "dominator_precedes_checkpoint",
                vec![dominator.into(), domination.checkpoint().into()],
            ));
        }
    }
    let _ = dominator_checks;
    (
        RealizedFeatureFlow {
            feature: intended.feature().into(),
            state,
            checkpoints,
            transitions,
            bypasses,
            bypass_freedom,
            terminal_reconciliations,
            decision_reconciliations,
        },
        obligations,
    )
}

fn resolve_anchor_event(
    anchor: &BehaviorAnchor,
    summaries: &BTreeMap<&str, &SemanticDomain>,
) -> Option<String> {
    match anchor {
        BehaviorAnchor::SymbolEntry { symbol } => Some(event_id("symbol_entry", symbol)),
        BehaviorAnchor::SymbolReturn { symbol, boolean } => {
            if let Some(expected) = boolean {
                let SemanticDomain::Boolean { values, .. } = summaries.get(symbol.as_str())? else {
                    return None;
                };
                values
                    .contains(expected)
                    .then(|| event_id("symbol_return_boolean", &format!("{symbol}:{expected}")))
            } else {
                Some(event_id("symbol_return", symbol))
            }
        }
        BehaviorAnchor::StateTransition {
            symbol,
            from_states,
            to_states,
            ..
        } => Some(event_id(
            "state_transition",
            &format!(
                "{}:{:?}:{:?}",
                symbol,
                classification_from_states(from_states),
                classification_from_states(to_states)
            ),
        )),
        BehaviorAnchor::Effect { effect, symbol } => {
            Some(event_id("effect", &format!("{symbol}:{effect:?}")))
        }
        BehaviorAnchor::InformationTransition {
            transition,
            symbol,
            facet,
            from,
            to,
        } => Some(event_id(
            "information_transition",
            &format!("{symbol}:{transition:?}:{facet}:{from}:{to}"),
        )),
        BehaviorAnchor::EnvironmentOutcome { operation, outcome } => Some(event_id(
            "environment_outcome",
            &format!("{operation}:{outcome}"),
        )),
    }
}

fn classification_from_states(states: &[String]) -> TypestateClassification {
    if let [state] = states {
        TypestateClassification::Exact {
            state: state.clone(),
        }
    } else {
        TypestateClassification::Possible {
            states: states.to_vec(),
        }
    }
}

fn derive_bypasses(
    intended: &IntendedFeatureFlow,
    checkpoint_events: &BTreeMap<String, Vec<String>>,
    graph: &EventGraph,
    contracts: &BTreeMap<&str, &ResolvedCheckpointRealization>,
) -> (Vec<BehavioralBypass>, usize, RealizationCoverage) {
    let Some(trigger) = intended.trigger_checkpoint() else {
        return (Vec::new(), 0, RealizationCoverage::Unsupported);
    };
    let Some(trigger_events) = checkpoint_events.get(trigger) else {
        return (Vec::new(), 0, RealizationCoverage::Unknown);
    };
    let immediate = intended
        .immediate_dominators()
        .iter()
        .map(|value| (value.checkpoint(), value.immediate()))
        .collect::<BTreeMap<_, _>>();
    let mut bypasses = Vec::new();
    let mut checks = 0;
    for reached in intended
        .nodes()
        .iter()
        .map(crate::behavioral_semantics::BfgNode::checkpoint)
    {
        let mut cursor = immediate.get(reached).copied().flatten();
        while let Some(dominator) = cursor {
            if dominator == trigger {
                cursor = immediate.get(dominator).copied().flatten();
                continue;
            }
            checks += 1;
            let targets = checkpoint_events
                .get(reached)
                .into_iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            let forbidden = checkpoint_events
                .get(dominator)
                .into_iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            if let Some((path, coverage)) = graph.path(trigger_events, &targets, &forbidden)
                && coverage == RealizationCoverage::Proven
            {
                let contract = contracts
                    .get(reached)
                    .expect("validated opted-in Feature has checkpoint");
                bypasses.push(BehavioralBypass {
                    feature: intended.feature().into(),
                    required_dominator: dominator.into(),
                    reached_checkpoint: reached.into(),
                    implementation_path: path,
                    anchor_provenance: vec![
                        contract.source_path().into(),
                        contract.pointer().into(),
                    ],
                    coverage,
                });
            }
            cursor = immediate.get(dominator).copied().flatten();
        }
    }
    bypasses.sort();
    bypasses.dedup();
    let coverage = if bypasses.is_empty() {
        RealizationCoverage::Partial
    } else {
        RealizationCoverage::Proven
    };
    (bypasses, checks, coverage)
}

fn verification_obligation(
    feature: &str,
    proposition: &str,
    checkpoints: Vec<String>,
) -> BehavioralVerificationObligation {
    let material = format!("{feature}:{proposition}:{}", checkpoints.join(":"));
    BehavioralVerificationObligation {
        id: format!(
            "OBL-BEHAVIOR-{}",
            &format!("{:X}", Sha256::digest(material.as_bytes()))[..16]
        ),
        feature: feature.into(),
        proposition: proposition.into(),
        checkpoints,
        evidence_status: "NOT_ESTABLISHED".into(),
    }
}

fn summarize(
    intended: &IntendedBehavioralFlowGraph,
    contracts: &ResolvedBehaviorRealizationContracts,
    feature_states: &[(String, FeatureRealizationState)],
    flows: &[RealizedFeatureFlow],
    obligations: usize,
) -> RealizedBfgSummary {
    let checkpoints = flows
        .iter()
        .flat_map(|flow| &flow.checkpoints)
        .collect::<Vec<_>>();
    let transitions = flows
        .iter()
        .flat_map(|flow| &flow.transitions)
        .collect::<Vec<_>>();
    RealizedBfgSummary {
        opted_in_features: contracts.features().len(),
        modeled_unrealized_features: feature_states
            .iter()
            .filter(|(_, state)| *state == FeatureRealizationState::ModeledUnrealized)
            .count(),
        checkpoints: checkpoints.len(),
        anchors: contracts
            .checkpoints()
            .iter()
            .map(|checkpoint| checkpoint.anchors().len())
            .sum(),
        realized_checkpoints: checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.state == CheckpointRealizationState::Realized)
            .count(),
        partial_checkpoints: checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.state == CheckpointRealizationState::PartiallyRealized)
            .count(),
        unreachable_checkpoints: checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.state == CheckpointRealizationState::Unreachable)
            .count(),
        unknown_checkpoints: checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.state == CheckpointRealizationState::Unknown)
            .count(),
        contradicted_checkpoints: checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.state == CheckpointRealizationState::Contradicted)
            .count(),
        intended_and_realized_edges: transitions
            .iter()
            .filter(|edge| edge.state == EdgeReconciliationState::IntendedAndRealized)
            .count(),
        intended_unproven_edges: transitions
            .iter()
            .filter(|edge| edge.state == EdgeReconciliationState::IntendedUnproven)
            .count(),
        realized_undeclared_edges: transitions
            .iter()
            .filter(|edge| edge.state == EdgeReconciliationState::RealizedUndeclared)
            .count(),
        intended_proven_impossible_edges: transitions
            .iter()
            .filter(|edge| edge.state == EdgeReconciliationState::IntendedProvenImpossible)
            .count(),
        dominator_checks: intended
            .flows()
            .iter()
            .filter(|flow| {
                contracts
                    .features()
                    .iter()
                    .any(|item| item == flow.feature())
            })
            .map(|flow| {
                flow.immediate_dominators()
                    .iter()
                    .filter(|item| item.immediate().is_some())
                    .count()
            })
            .sum(),
        proven_bypasses: flows.iter().map(|flow| flow.bypasses.len()).sum(),
        terminal_reconciliations: flows.iter().map(|flow| flow.terminal_reconciliations).sum(),
        decision_reconciliations: flows.iter().map(|flow| flow.decision_reconciliations).sum(),
        verification_obligations: obligations,
    }
}

/// Compiles and normalizes both behavioral realization rule families.
///
/// # Errors
///
/// Returns an error when model serialization or finding normalization fails.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_behavioral_realization(
    ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisModel,
    state_effect: &StateEffectAnalysisModel,
    information_flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
    contracts: &ResolvedBehaviorRealizationContracts,
    standard_edition: &str,
) -> Result<BehavioralRealizationEvaluation, BehavioralRealizationError> {
    let graph = compile_realized_bfg(
        ccg,
        intended,
        psm,
        semantic,
        state_effect,
        information_flow,
        environmental,
        contracts,
    )?;
    let evaluator = EvaluatorProvenance::new(
        "fortress-core/behavioral-realization",
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(BehavioralRealizationError::Finding)?;
    let realization_definition = RuleFindingDefinition::new(
        BEHAVIOR_REALIZATION_RULE_ID,
        1,
        FindingCategory::Behavior,
        REALIZATION_REMEDIATION,
    )
    .map_err(BehavioralRealizationError::Finding)?;
    let bypass_definition = RuleFindingDefinition::new(
        BEHAVIOR_BYPASS_RULE_ID,
        1,
        FindingCategory::Behavior,
        BYPASS_REMEDIATION,
    )
    .map_err(BehavioralRealizationError::Finding)?;
    let mut realization_findings = Vec::new();
    let mut bypass_findings = Vec::new();
    for flow in graph.flows() {
        for transition in flow.transitions().iter().filter(|transition| {
            matches!(
                transition.state(),
                EdgeReconciliationState::RealizedUndeclared
                    | EdgeReconciliationState::IntendedProvenImpossible
            )
        }) {
            realization_findings.push(
                CanonicalFinding::failure(
                    realization_definition.clone(),
                    FindingOccurrence::new(
                        vec![flow.feature().into()],
                        FindingLocation::none(),
                        format!(
                            "{:?}: Feature {} transition {} -> {}; implementation path: {}",
                            transition.state(),
                            flow.feature(),
                            transition.source(),
                            transition.target(),
                            transition.implementation_path.join(" -> ")
                        ),
                    )
                    .map_err(BehavioralRealizationError::Finding)?,
                    evaluator.clone(),
                    standard_edition,
                    None,
                )
                .map_err(BehavioralRealizationError::Finding)?,
            );
        }
        for bypass in flow.bypasses() {
            bypass_findings.push(
                CanonicalFinding::failure(
                    bypass_definition.clone(),
                    FindingOccurrence::new(
                        vec![flow.feature().into()],
                        FindingLocation::none(),
                        format!(
                            "Feature {} reaches {} while bypassing required dominator {}; implementation path: {}",
                            flow.feature(),
                            bypass.reached_checkpoint,
                            bypass.required_dominator,
                            bypass.implementation_path.join(" -> ")
                        ),
                    )
                    .map_err(BehavioralRealizationError::Finding)?,
                    evaluator.clone(),
                    standard_edition,
                    None,
                )
                .map_err(BehavioralRealizationError::Finding)?,
            );
        }
    }
    realization_findings.sort();
    bypass_findings.sort();
    Ok(BehavioralRealizationEvaluation {
        graph,
        realization_findings,
        bypass_findings,
    })
}

fn event_id(kind: &str, key: &str) -> String {
    format!(
        "event:{kind}:sha256:{:x}",
        Sha256::digest(format!("{kind}:{key}").as_bytes())
    )
}

const fn combine_coverage(
    left: RealizationCoverage,
    right: RealizationCoverage,
) -> RealizationCoverage {
    match (left, right) {
        (RealizationCoverage::Unsupported, _) | (_, RealizationCoverage::Unsupported) => {
            RealizationCoverage::Unsupported
        }
        (RealizationCoverage::Unknown, _) | (_, RealizationCoverage::Unknown) => {
            RealizationCoverage::Unknown
        }
        (RealizationCoverage::Partial, _) | (_, RealizationCoverage::Partial) => {
            RealizationCoverage::Partial
        }
        (RealizationCoverage::Proven, RealizationCoverage::Proven) => RealizationCoverage::Proven,
    }
}
