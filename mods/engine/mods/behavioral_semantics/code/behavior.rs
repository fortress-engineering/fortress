//! Deterministic compilation of Contract v2 behavior into intended BFG v1.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract_coherency::{BehaviorCheckpoint, CheckpointKind, ContractCoherencyGraph};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Canonical Intended BFG schema identity.
pub const BFG_SCHEMA: &str = "urn:fortress:schema:v1:behavioral-flow-graph";
/// Canonical Intended BFG schema version.
pub const BFG_SCHEMA_VERSION: u16 = 1;
/// Semantic compiler version bound into the derived artifact.
pub const BFG_SEMANTIC_VERSION: &str = "1.0.0";
/// Stable rule identity for modeled Feature-flow coherency.
pub const BEHAVIOR_FLOW_RULE_ID: &str = "BEHAVIOR-FLOW-001";

const REMEDIATION: &str = "Correct the authored Contract v2 checkpoints so each modeled Feature has one trigger, terminal-reaching branches, no dead flow region, and coherent distributed ownership.";

/// Semantic proof classes deliberately outside Intended BFG v1 authority.
pub const BFG_UNSUPPORTED_SEMANTICS: &[&str] = &[
    "concurrency_liveness_proof",
    "effect_system_proof",
    "environment_api_nondeterminism",
    "failure_crash_semantics",
    "formal_state_variable_invariants",
    "function_call_realization",
    "implementation_behavior_realization",
    "natural_language_requirement_satisfiability",
    "pre_postcondition_proof",
    "runtime_frequency_probability",
    "security_information_flow_proof",
    "value_data_flow_realization",
];

/// Per-Feature behavioral modeling state without treating absence as success.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BehavioralModelingState {
    /// No checkpoint has been authored for the Feature.
    Unmodeled,
    /// Authored checkpoints satisfy all BFG v1 structural flow semantics.
    ModeledCoherent,
    /// Authored checkpoints contradict one or more BFG v1 semantics.
    ModeledIncoherent,
}

/// Exact contract source location supporting a behavioral fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BfgProvenance {
    path: String,
    pointer: String,
}

impl BfgProvenance {
    fn new(path: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            pointer: pointer.into(),
        }
    }

    /// Returns the repository-relative contract path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the canonical JSON pointer.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}

/// Deterministic graph-level contradiction found while compiling one Feature.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BehavioralViolation {
    code: String,
    feature: String,
    checkpoint: Option<String>,
    message: String,
    input_facts: Vec<String>,
    provenance: Vec<BfgProvenance>,
}

impl BehavioralViolation {
    /// Returns the stable BFG violation code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the affected Feature.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns the affected checkpoint when the contradiction is node-local.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&str> {
        self.checkpoint.as_deref()
    }

    /// Returns the deterministic explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns exact source and derived inputs.
    #[must_use]
    pub fn input_facts(&self) -> &[String] {
        &self.input_facts
    }

    /// Returns complete source provenance for the contradiction.
    #[must_use]
    pub fn provenance(&self) -> &[BfgProvenance] {
        &self.provenance
    }
}

/// Summary counts for the complete intended behavioral model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BfgSummary {
    total_features: usize,
    modeled_features: usize,
    unmodeled_features: usize,
    coherent_features: usize,
    incoherent_features: usize,
    checkpoints: usize,
    edges: usize,
    decisions: usize,
    terminals: usize,
    participant_modules: usize,
    boundary_crossings: usize,
    loops: usize,
}

impl BfgSummary {
    /// Returns all CCG Feature identities.
    #[must_use]
    pub const fn total_features(self) -> usize {
        self.total_features
    }
    /// Returns Features containing authored checkpoints.
    #[must_use]
    pub const fn modeled_features(self) -> usize {
        self.modeled_features
    }
    /// Returns Features with no authored checkpoints.
    #[must_use]
    pub const fn unmodeled_features(self) -> usize {
        self.unmodeled_features
    }
    /// Returns modeled Features without implemented graph contradictions.
    #[must_use]
    pub const fn coherent_features(self) -> usize {
        self.coherent_features
    }
    /// Returns modeled Features with implemented graph contradictions.
    #[must_use]
    pub const fn incoherent_features(self) -> usize {
        self.incoherent_features
    }
    /// Returns modeled checkpoints.
    #[must_use]
    pub const fn checkpoints(self) -> usize {
        self.checkpoints
    }
    /// Returns authored transition edges.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }
    /// Returns decision checkpoints.
    #[must_use]
    pub const fn decisions(self) -> usize {
        self.decisions
    }
    /// Returns terminal checkpoints.
    #[must_use]
    pub const fn terminals(self) -> usize {
        self.terminals
    }
    /// Returns distinct Modules participating in modeled flows.
    #[must_use]
    pub const fn participant_modules(self) -> usize {
        self.participant_modules
    }
    /// Returns transitions crossing Module boundaries.
    #[must_use]
    pub const fn boundary_crossings(self) -> usize {
        self.boundary_crossings
    }
    /// Returns cyclic strongly connected components.
    #[must_use]
    pub const fn loops(self) -> usize {
        self.loops
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct BfgStandard {
    id: String,
    edition: String,
}

/// Modeling state projected for every Feature, including unmodeled Features.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FeatureModelingState {
    feature: String,
    owner: String,
    state: BehavioralModelingState,
}

impl FeatureModelingState {
    /// Returns the Feature identity.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }
    /// Returns the Feature-owning Module.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Returns the explicit modeling state.
    #[must_use]
    pub const fn state(&self) -> BehavioralModelingState {
        self.state
    }
}

/// One semantic checkpoint node in an intended Feature flow.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BfgNode {
    checkpoint: String,
    module: String,
    kind: CheckpointKind,
    terminal_outcome: Option<String>,
    provenance: BfgProvenance,
}

impl BfgNode {
    /// Returns the checkpoint identity.
    #[must_use]
    pub fn checkpoint(&self) -> &str {
        &self.checkpoint
    }
    /// Returns the declaring Module lane.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }
    /// Returns trigger, action, decision, or terminal kind.
    #[must_use]
    pub const fn kind(&self) -> CheckpointKind {
        self.kind
    }
    /// Returns terminal outcome when applicable.
    #[must_use]
    pub fn terminal_outcome(&self) -> Option<&str> {
        self.terminal_outcome.as_deref()
    }
    /// Returns contract provenance.
    #[must_use]
    pub const fn provenance(&self) -> &BfgProvenance {
        &self.provenance
    }
}

/// One intended transition edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BfgEdge {
    source: String,
    target: String,
    decision_outcome: Option<String>,
    crosses_module_boundary: bool,
    provenance: BfgProvenance,
}

impl BfgEdge {
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
    /// Returns a decision branch outcome when present.
    #[must_use]
    pub fn decision_outcome(&self) -> Option<&str> {
        self.decision_outcome.as_deref()
    }
    /// Returns whether the transition changes declaring Module lane.
    #[must_use]
    pub const fn crosses_module_boundary(&self) -> bool {
        self.crosses_module_boundary
    }
    /// Returns transition source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &BfgProvenance {
        &self.provenance
    }
}

/// One decision branch and its terminal viability.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DecisionBranch {
    decision: String,
    outcome: String,
    target: String,
    can_reach_terminal: bool,
    derivation: String,
}

/// One strongly connected component and loop interpretation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StronglyConnectedComponent {
    id: String,
    checkpoints: Vec<String>,
    is_loop: bool,
    can_reach_terminal: bool,
    derivation: String,
}

/// Compact immediate-dominator or post-dominator relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ImmediateDomination {
    checkpoint: String,
    immediate: Option<String>,
    derivation: String,
}

impl ImmediateDomination {
    /// Returns the dominated checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> &str {
        &self.checkpoint
    }
    /// Returns its immediate dominator, or none at the root/synthetic exit boundary.
    #[must_use]
    pub fn immediate(&self) -> Option<&str> {
        self.immediate.as_deref()
    }
}

/// Explainable derived BFG fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BfgDerivation {
    id: String,
    kind: String,
    fact: String,
    input_facts: Vec<String>,
    explanation_path: Vec<String>,
    provenance: Vec<BfgProvenance>,
}

/// One independently compiled intended Feature flow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IntendedFeatureFlow {
    feature: String,
    owner: String,
    state: BehavioralModelingState,
    participating_modules: Vec<String>,
    trigger_checkpoint: Option<String>,
    terminal_checkpoints: Vec<String>,
    nodes: Vec<BfgNode>,
    edges: Vec<BfgEdge>,
    module_boundary_crossings: Vec<BfgEdge>,
    decision_branches: Vec<DecisionBranch>,
    strongly_connected_components: Vec<StronglyConnectedComponent>,
    immediate_dominators: Vec<ImmediateDomination>,
    immediate_post_dominators: Vec<ImmediateDomination>,
    derivations: Vec<BfgDerivation>,
    provenance: Vec<BfgProvenance>,
}

impl IntendedFeatureFlow {
    /// Returns the modeled Feature.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }
    /// Returns the Feature owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Returns coherent or incoherent modeled state.
    #[must_use]
    pub const fn state(&self) -> BehavioralModelingState {
        self.state
    }
    /// Returns participating Module lanes.
    #[must_use]
    pub fn participating_modules(&self) -> &[String] {
        &self.participating_modules
    }
    /// Returns the unique trigger when coherent enough to identify one.
    #[must_use]
    pub fn trigger_checkpoint(&self) -> Option<&str> {
        self.trigger_checkpoint.as_deref()
    }
    /// Returns all terminal checkpoints.
    #[must_use]
    pub fn terminal_checkpoints(&self) -> &[String] {
        &self.terminal_checkpoints
    }
    /// Returns canonical nodes.
    #[must_use]
    pub fn nodes(&self) -> &[BfgNode] {
        &self.nodes
    }
    /// Returns canonical edges.
    #[must_use]
    pub fn edges(&self) -> &[BfgEdge] {
        &self.edges
    }
    /// Returns cross-Module edges.
    #[must_use]
    pub fn module_boundary_crossings(&self) -> &[BfgEdge] {
        &self.module_boundary_crossings
    }
    /// Returns decision branches.
    #[must_use]
    pub fn decision_branches(&self) -> &[DecisionBranch] {
        &self.decision_branches
    }
    /// Returns canonical SCC facts.
    #[must_use]
    pub fn strongly_connected_components(&self) -> &[StronglyConnectedComponent] {
        &self.strongly_connected_components
    }
    /// Returns compact immediate dominators.
    #[must_use]
    pub fn immediate_dominators(&self) -> &[ImmediateDomination] {
        &self.immediate_dominators
    }
    /// Returns compact immediate post-dominators using a synthetic common exit.
    #[must_use]
    pub fn immediate_post_dominators(&self) -> &[ImmediateDomination] {
        &self.immediate_post_dominators
    }
}

/// Canonical deterministic Intended BFG v1 for one CCG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IntendedBehavioralFlowGraph {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    semantic_version: &'static str,
    project_id: String,
    standard: BfgStandard,
    source_ccg_digest: String,
    view: &'static str,
    summary: BfgSummary,
    feature_states: Vec<FeatureModelingState>,
    flows: Vec<IntendedFeatureFlow>,
    violations: Vec<BehavioralViolation>,
    unsupported_semantics: Vec<&'static str>,
}

impl IntendedBehavioralFlowGraph {
    /// Returns aggregate Feature and graph counts.
    #[must_use]
    pub const fn summary(&self) -> BfgSummary {
        self.summary
    }
    /// Returns all Feature modeling states.
    #[must_use]
    pub fn feature_states(&self) -> &[FeatureModelingState] {
        &self.feature_states
    }
    /// Returns modeled Feature flows only.
    #[must_use]
    pub fn flows(&self) -> &[IntendedFeatureFlow] {
        &self.flows
    }
    /// Returns implemented graph-level contradictions.
    #[must_use]
    pub fn violations(&self) -> &[BehavioralViolation] {
        &self.violations
    }
    /// Returns explicit semantic limits.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[&str] {
        &self.unsupported_semantics
    }

    /// Serializes canonical two-space JSON with LF termination.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error when the typed model cannot serialize.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut json| {
            json.push('\n');
            json
        })
    }

    /// Computes SHA-256 over canonical bytes without embedding it.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error when canonical bytes cannot serialize.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        self.to_canonical_json()
            .map(|json| format!("sha256:{:x}", Sha256::digest(json.as_bytes())))
    }
}

/// Intended BFG plus normalized BEHAVIOR-FLOW-001 findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehavioralSemanticsEvaluation {
    graph: IntendedBehavioralFlowGraph,
    findings: Vec<CanonicalFinding>,
}

impl BehavioralSemanticsEvaluation {
    /// Returns the compiled Intended BFG.
    #[must_use]
    pub const fn graph(&self) -> &IntendedBehavioralFlowGraph {
        &self.graph
    }
    /// Returns normalized modeled-flow contradictions.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Failure while serializing or normalizing intended behavior.
#[derive(Debug)]
pub enum BehavioralSemanticsError {
    /// Canonical CCG or BFG serialization failed.
    Serialization(serde_json::Error),
    /// Canonical finding normalization failed.
    Finding(FindingError),
    /// Root ecosystem selection required by the BFG was absent.
    MissingRootEcosystem,
}

impl Display for BehavioralSemanticsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(formatter, "behavior serialization failed: {error}")
            }
            Self::Finding(error) => write!(formatter, "behavior finding failed: {error}"),
            Self::MissingRootEcosystem => formatter.write_str("CCG root ecosystem is absent"),
        }
    }
}

impl Error for BehavioralSemanticsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::MissingRootEcosystem => None,
        }
    }
}

/// Compiles the CCG-preserved declarations into one deterministic Intended BFG.
///
/// # Errors
///
/// Returns [`BehavioralSemanticsError`] if root interpretation or CCG digest
/// serialization is unavailable.
pub fn compile_intended_bfg(
    ccg: &ContractCoherencyGraph,
) -> Result<IntendedBehavioralFlowGraph, BehavioralSemanticsError> {
    let root = ccg
        .root()
        .ok_or(BehavioralSemanticsError::MissingRootEcosystem)?;
    let ecosystem = root
        .contract()
        .ecosystem()
        .ok_or(BehavioralSemanticsError::MissingRootEcosystem)?;
    let declarations = behavior_declarations(ccg);
    let mut by_feature = BTreeMap::<String, Vec<Declaration>>::new();
    for declaration in declarations {
        by_feature
            .entry(declaration.checkpoint.feature().into())
            .or_default()
            .push(declaration);
    }
    let mut feature_states = Vec::new();
    let mut flows = Vec::new();
    let mut violations = Vec::new();
    for (feature, ownership) in ccg.features() {
        if let Some(feature_declarations) = by_feature.remove(feature) {
            let (flow, mut feature_violations) =
                compile_feature_flow(feature, ownership.owner(), &feature_declarations);
            feature_states.push(FeatureModelingState {
                feature: feature.clone(),
                owner: ownership.owner().into(),
                state: flow.state,
            });
            flows.push(flow);
            violations.append(&mut feature_violations);
        } else {
            feature_states.push(FeatureModelingState {
                feature: feature.clone(),
                owner: ownership.owner().into(),
                state: BehavioralModelingState::Unmodeled,
            });
        }
    }
    feature_states.sort();
    flows.sort_by(|left, right| left.feature.cmp(&right.feature));
    violations.sort();
    violations.dedup();
    let summary = summarize(&feature_states, &flows);
    Ok(IntendedBehavioralFlowGraph {
        schema: BFG_SCHEMA,
        schema_version: BFG_SCHEMA_VERSION,
        semantic_version: BFG_SEMANTIC_VERSION,
        project_id: root.contract().id().into(),
        standard: BfgStandard {
            id: ecosystem.standard().id().into(),
            edition: ecosystem.standard().edition().into(),
        },
        source_ccg_digest: ccg
            .digest()
            .map_err(BehavioralSemanticsError::Serialization)?,
        view: "intended",
        summary,
        feature_states,
        flows,
        violations,
        unsupported_semantics: BFG_UNSUPPORTED_SEMANTICS.to_vec(),
    })
}

fn summarize(feature_states: &[FeatureModelingState], flows: &[IntendedFeatureFlow]) -> BfgSummary {
    BfgSummary {
        total_features: feature_states.len(),
        modeled_features: flows.len(),
        unmodeled_features: feature_states
            .iter()
            .filter(|state| state.state == BehavioralModelingState::Unmodeled)
            .count(),
        coherent_features: flows
            .iter()
            .filter(|flow| flow.state == BehavioralModelingState::ModeledCoherent)
            .count(),
        incoherent_features: flows
            .iter()
            .filter(|flow| flow.state == BehavioralModelingState::ModeledIncoherent)
            .count(),
        checkpoints: flows.iter().map(|flow| flow.nodes.len()).sum(),
        edges: flows.iter().map(|flow| flow.edges.len()).sum(),
        decisions: flows
            .iter()
            .flat_map(|flow| &flow.nodes)
            .filter(|node| node.kind == CheckpointKind::Decision)
            .count(),
        terminals: flows
            .iter()
            .map(|flow| flow.terminal_checkpoints.len())
            .sum(),
        participant_modules: flows
            .iter()
            .flat_map(|flow| flow.participating_modules.iter().cloned())
            .collect::<BTreeSet<_>>()
            .len(),
        boundary_crossings: flows
            .iter()
            .map(|flow| flow.module_boundary_crossings.len())
            .sum(),
        loops: flows
            .iter()
            .flat_map(|flow| &flow.strongly_connected_components)
            .filter(|component| component.is_loop)
            .count(),
    }
}

/// Compiles intended behavior and projects contradictions into the governing rule.
///
/// # Errors
///
/// Returns [`BehavioralSemanticsError`] for serialization or finding failure.
pub fn evaluate_behavioral_semantics(
    ccg: &ContractCoherencyGraph,
    standard_edition: &str,
) -> Result<BehavioralSemanticsEvaluation, BehavioralSemanticsError> {
    let graph = compile_intended_bfg(ccg)?;
    let definition = RuleFindingDefinition::new(
        BEHAVIOR_FLOW_RULE_ID,
        1,
        FindingCategory::Behavior,
        REMEDIATION,
    )
    .map_err(BehavioralSemanticsError::Finding)?;
    let evaluator = EvaluatorProvenance::new(
        "fortress-core/behavioral-semantics",
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(BehavioralSemanticsError::Finding)?;
    let mut findings = Vec::new();
    for violation in graph.violations() {
        let location = violation
            .provenance()
            .first()
            .map_or_else(
                || Ok(FindingLocation::none()),
                |source| FindingLocation::at_path(source.path()),
            )
            .map_err(BehavioralSemanticsError::Finding)?;
        findings.push(
            CanonicalFinding::failure(
                definition.clone(),
                FindingOccurrence::new(
                    vec![violation.feature().into()],
                    location,
                    format!("{}: {}", violation.code(), violation.message()),
                )
                .map_err(BehavioralSemanticsError::Finding)?,
                evaluator.clone(),
                standard_edition,
                None,
            )
            .map_err(BehavioralSemanticsError::Finding)?,
        );
    }
    findings.sort();
    Ok(BehavioralSemanticsEvaluation { graph, findings })
}

#[derive(Clone)]
struct Declaration {
    checkpoint: BehaviorCheckpoint,
    module: String,
    contract_path: String,
    index: usize,
}

fn behavior_declarations(ccg: &ContractCoherencyGraph) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    for (module_id, module) in ccg.modules() {
        for (index, checkpoint) in module.contract().behavior().iter().enumerate() {
            declarations.push(Declaration {
                checkpoint: checkpoint.clone(),
                module: module_id.clone(),
                contract_path: module.contract_path().into(),
                index,
            });
        }
    }
    declarations.sort_by(|left, right| left.checkpoint.id().cmp(right.checkpoint.id()));
    declarations
}

fn compile_feature_flow(
    feature: &str,
    owner: &str,
    declarations: &[Declaration],
) -> (IntendedFeatureFlow, Vec<BehavioralViolation>) {
    let (nodes, edges) = build_nodes_and_edges(declarations);
    let node_ids: BTreeSet<String> = nodes.iter().map(|node| node.checkpoint.clone()).collect();
    let adjacency = adjacency(&node_ids, &edges);
    let predecessors = reverse_adjacency(&node_ids, &edges);
    let triggers: Vec<String> = nodes
        .iter()
        .filter(|node| node.kind == CheckpointKind::Trigger)
        .map(|node| node.checkpoint.clone())
        .collect();
    let terminals: Vec<String> = nodes
        .iter()
        .filter(|node| node.kind == CheckpointKind::Terminal)
        .map(|node| node.checkpoint.clone())
        .collect();
    let trigger = (triggers.len() == 1).then(|| triggers[0].clone());
    let reachable = trigger
        .as_deref()
        .map_or_else(BTreeSet::new, |start| traverse(start, &adjacency));
    let can_reach_terminal = reverse_reachable(&terminals, &predecessors);
    let components = strongly_connected_components(&node_ids, &adjacency, &can_reach_terminal);
    let mut violations = FlowValidation {
        feature,
        nodes: &nodes,
        edges: &edges,
        triggers: &triggers,
        terminals: &terminals,
        reachable: &reachable,
        can_reach_terminal: &can_reach_terminal,
        components: &components,
    }
    .validate();
    violations.sort();
    violations.dedup();
    let state = if violations.is_empty() {
        BehavioralModelingState::ModeledCoherent
    } else {
        BehavioralModelingState::ModeledIncoherent
    };
    let participating_modules: Vec<String> = nodes
        .iter()
        .map(|node| node.module.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let module_boundary_crossings: Vec<BfgEdge> = edges
        .iter()
        .filter(|edge| edge.crosses_module_boundary)
        .cloned()
        .collect();
    let decision_branches = decision_branches(&nodes, &edges, &can_reach_terminal);
    let provenance: Vec<BfgProvenance> = nodes
        .iter()
        .map(|node| node.provenance.clone())
        .chain(edges.iter().map(|edge| edge.provenance.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let immediate_dominators = trigger.as_deref().map_or_else(Vec::new, |start| {
        immediate_dominators(start, &node_ids, &predecessors, &reachable, "dominator")
    });
    let immediate_post_dominators =
        immediate_post_dominators(&node_ids, &adjacency, &terminals, &can_reach_terminal);
    let derivations = derivations(
        feature,
        &participating_modules,
        &module_boundary_crossings,
        &components,
        &immediate_dominators,
        &immediate_post_dominators,
        &provenance,
    );
    (
        IntendedFeatureFlow {
            feature: feature.into(),
            owner: owner.into(),
            state,
            participating_modules,
            trigger_checkpoint: trigger,
            terminal_checkpoints: terminals,
            nodes,
            edges,
            module_boundary_crossings,
            decision_branches,
            strongly_connected_components: components,
            immediate_dominators,
            immediate_post_dominators,
            derivations,
            provenance,
        },
        violations,
    )
}

fn build_nodes_and_edges(declarations: &[Declaration]) -> (Vec<BfgNode>, Vec<BfgEdge>) {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let by_id: BTreeMap<String, &Declaration> = declarations
        .iter()
        .map(|declaration| (declaration.checkpoint.id().into(), declaration))
        .collect();
    for declaration in declarations {
        let pointer = format!("/behavior/{}", declaration.index);
        nodes.push(BfgNode {
            checkpoint: declaration.checkpoint.id().into(),
            module: declaration.module.clone(),
            kind: declaration.checkpoint.kind(),
            terminal_outcome: declaration.checkpoint.outcome().map(str::to_owned),
            provenance: BfgProvenance::new(&declaration.contract_path, &pointer),
        });
        for (transition_index, transition) in
            declaration.checkpoint.transitions().iter().enumerate()
        {
            let target_module = &by_id[transition.target()].module;
            edges.push(BfgEdge {
                source: declaration.checkpoint.id().into(),
                target: transition.target().into(),
                decision_outcome: transition.outcome().map(str::to_owned),
                crosses_module_boundary: declaration.module != *target_module,
                provenance: BfgProvenance::new(
                    &declaration.contract_path,
                    format!("{pointer}/transitions/{transition_index}"),
                ),
            });
        }
    }
    nodes.sort();
    edges.sort();
    (nodes, edges)
}

fn adjacency(nodes: &BTreeSet<String>, edges: &[BfgEdge]) -> BTreeMap<String, BTreeSet<String>> {
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = nodes
        .iter()
        .map(|node| (node.clone(), BTreeSet::new()))
        .collect();
    for edge in edges {
        adjacency
            .entry(edge.source.clone())
            .or_default()
            .insert(edge.target.clone());
    }
    adjacency
}

fn reverse_adjacency(
    nodes: &BTreeSet<String>,
    edges: &[BfgEdge],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut reversed: BTreeMap<String, BTreeSet<String>> = nodes
        .iter()
        .map(|node| (node.clone(), BTreeSet::new()))
        .collect();
    for edge in edges {
        reversed
            .entry(edge.target.clone())
            .or_default()
            .insert(edge.source.clone());
    }
    reversed
}

fn traverse(start: &str, adjacency: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([start.to_owned()]);
    while let Some(node) = queue.pop_front() {
        if visited.insert(node.clone()) {
            queue.extend(adjacency.get(&node).into_iter().flatten().cloned());
        }
    }
    visited
}

fn reverse_reachable(
    terminals: &[String],
    predecessors: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reached = BTreeSet::new();
    let mut queue: VecDeque<String> = terminals.iter().cloned().collect();
    while let Some(node) = queue.pop_front() {
        if reached.insert(node.clone()) {
            queue.extend(predecessors.get(&node).into_iter().flatten().cloned());
        }
    }
    reached
}

struct FlowValidation<'a> {
    feature: &'a str,
    nodes: &'a [BfgNode],
    edges: &'a [BfgEdge],
    triggers: &'a [String],
    terminals: &'a [String],
    reachable: &'a BTreeSet<String>,
    can_reach_terminal: &'a BTreeSet<String>,
    components: &'a [StronglyConnectedComponent],
}

impl FlowValidation<'_> {
    fn validate(&self) -> Vec<BehavioralViolation> {
        let mut violations = self.cardinality_violations();
        violations.extend(self.reachability_violations());
        violations.extend(self.branch_violations());
        violations.extend(self.component_violations());
        violations
    }

    fn provenance(&self) -> Vec<BfgProvenance> {
        self.nodes
            .iter()
            .map(|node| node.provenance.clone())
            .collect()
    }

    fn cardinality_violations(&self) -> Vec<BehavioralViolation> {
        let mut violations = Vec::new();
        if self.triggers.len() != 1 {
            violations.push(violation(
                "BFG-TRIGGER-COUNT",
                self.feature,
                None,
                format!(
                    "modeled Feature `{}` must have exactly one trigger, found {}",
                    self.feature,
                    self.triggers.len()
                ),
                self.triggers
                    .iter()
                    .map(|trigger| format!("checkpoint:{trigger}"))
                    .collect(),
                self.provenance(),
            ));
        }
        if self.terminals.is_empty() {
            violations.push(violation(
                "BFG-TERMINAL-MISSING",
                self.feature,
                None,
                format!(
                    "modeled Feature `{}` has no terminal checkpoint",
                    self.feature
                ),
                Vec::new(),
                self.provenance(),
            ));
        }
        violations
    }

    fn reachability_violations(&self) -> Vec<BehavioralViolation> {
        let mut violations = Vec::new();
        if self.triggers.len() == 1 {
            for node in self.nodes {
                if self.reachable.contains(node.checkpoint()) {
                    continue;
                }
                violations.push(violation(
                    "BFG-UNREACHABLE-CHECKPOINT",
                    self.feature,
                    Some(node.checkpoint()),
                    format!(
                        "checkpoint `{}` is unreachable from trigger `{}`",
                        node.checkpoint(),
                        self.triggers[0]
                    ),
                    vec![
                        format!("trigger:{}", self.triggers[0]),
                        format!("checkpoint:{}", node.checkpoint()),
                    ],
                    vec![node.provenance.clone()],
                ));
            }
        }
        for node in self
            .nodes
            .iter()
            .filter(|node| node.kind != CheckpointKind::Terminal)
        {
            if self.can_reach_terminal.contains(node.checkpoint()) {
                continue;
            }
            violations.push(violation(
                "BFG-NO-TERMINAL-PATH",
                self.feature,
                Some(node.checkpoint()),
                format!(
                    "nonterminal checkpoint `{}` cannot reach any terminal",
                    node.checkpoint()
                ),
                vec![format!("checkpoint:{}", node.checkpoint())],
                vec![node.provenance.clone()],
            ));
        }
        violations
    }

    fn branch_violations(&self) -> Vec<BehavioralViolation> {
        let mut violations = Vec::new();
        for node in self
            .nodes
            .iter()
            .filter(|node| node.kind == CheckpointKind::Decision)
        {
            for edge in self
                .edges
                .iter()
                .filter(|edge| edge.source == node.checkpoint)
            {
                if self.can_reach_terminal.contains(edge.target()) {
                    continue;
                }
                violations.push(violation(
                    "BFG-NONVIABLE-BRANCH",
                    self.feature,
                    Some(node.checkpoint()),
                    format!(
                        "decision `{}` outcome `{}` targets `{}` without a terminal path",
                        node.checkpoint(),
                        edge.decision_outcome.as_deref().unwrap_or("unlabeled"),
                        edge.target()
                    ),
                    vec![format!("edge:{}:{}", edge.source(), edge.target())],
                    vec![node.provenance.clone(), edge.provenance.clone()],
                ));
            }
        }
        violations
    }

    fn component_violations(&self) -> Vec<BehavioralViolation> {
        let by_id: BTreeMap<&str, &BfgNode> = self
            .nodes
            .iter()
            .map(|node| (node.checkpoint.as_str(), node))
            .collect();
        self.components
            .iter()
            .filter(|component| component.is_loop && !component.can_reach_terminal)
            .map(|component| {
                let provenance = component
                    .checkpoints
                    .iter()
                    .filter_map(|checkpoint| by_id.get(checkpoint.as_str()))
                    .map(|node| node.provenance.clone())
                    .collect();
                violation(
                    "BFG-CLOSED-SCC",
                    self.feature,
                    component.checkpoints.first().map(String::as_str),
                    format!(
                        "closed loop `{}` has no route to a terminal",
                        component.checkpoints.join(" -> ")
                    ),
                    component
                        .checkpoints
                        .iter()
                        .map(|checkpoint| format!("checkpoint:{checkpoint}"))
                        .collect(),
                    provenance,
                )
            })
            .collect()
    }
}

fn violation(
    code: &str,
    feature: &str,
    checkpoint: Option<&str>,
    message: String,
    input_facts: Vec<String>,
    mut provenance: Vec<BfgProvenance>,
) -> BehavioralViolation {
    provenance.sort();
    provenance.dedup();
    BehavioralViolation {
        code: code.into(),
        feature: feature.into(),
        checkpoint: checkpoint.map(str::to_owned),
        message,
        input_facts,
        provenance,
    }
}

fn decision_branches(
    nodes: &[BfgNode],
    edges: &[BfgEdge],
    can_reach_terminal: &BTreeSet<String>,
) -> Vec<DecisionBranch> {
    let decisions: BTreeSet<&str> = nodes
        .iter()
        .filter(|node| node.kind == CheckpointKind::Decision)
        .map(|node| node.checkpoint.as_str())
        .collect();
    edges
        .iter()
        .filter(|edge| decisions.contains(edge.source.as_str()))
        .map(|edge| DecisionBranch {
            decision: edge.source.clone(),
            outcome: edge.decision_outcome.clone().unwrap_or_default(),
            target: edge.target.clone(),
            can_reach_terminal: can_reach_terminal.contains(&edge.target),
            derivation: format!("branch_viability:{}:{}", edge.source, edge.target),
        })
        .collect()
}

fn strongly_connected_components(
    nodes: &BTreeSet<String>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    can_reach_terminal: &BTreeSet<String>,
) -> Vec<StronglyConnectedComponent> {
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for node in nodes {
        finish_order(node, adjacency, &mut visited, &mut order);
    }
    let reversed = adjacency.iter().fold(
        nodes
            .iter()
            .map(|node| (node.clone(), BTreeSet::new()))
            .collect::<BTreeMap<_, _>>(),
        |mut result, (source, targets)| {
            for target in targets {
                result
                    .entry(target.clone())
                    .or_default()
                    .insert(source.clone());
            }
            result
        },
    );
    visited.clear();
    let mut components = Vec::new();
    while let Some(node) = order.pop() {
        if visited.contains(&node) {
            continue;
        }
        let mut values = Vec::new();
        collect_component(&node, &reversed, &mut visited, &mut values);
        values.sort();
        let self_loop = values.len() == 1
            && adjacency
                .get(&values[0])
                .is_some_and(|targets| targets.contains(&values[0]));
        let is_loop = values.len() > 1 || self_loop;
        components.push(StronglyConnectedComponent {
            id: format!("scc:{}", values.join("+")),
            can_reach_terminal: values
                .iter()
                .any(|value| can_reach_terminal.contains(value)),
            derivation: format!("strongly_connected_component:{}", values.join(":")),
            checkpoints: values,
            is_loop,
        });
    }
    components.sort();
    components
}

fn finish_order(
    node: &str,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if !visited.insert(node.into()) {
        return;
    }
    for target in adjacency.get(node).into_iter().flatten() {
        finish_order(target, adjacency, visited, order);
    }
    order.push(node.into());
}

fn collect_component(
    node: &str,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
    values: &mut Vec<String>,
) {
    if !visited.insert(node.into()) {
        return;
    }
    values.push(node.into());
    for target in adjacency.get(node).into_iter().flatten() {
        collect_component(target, adjacency, visited, values);
    }
}

fn immediate_dominators(
    start: &str,
    nodes: &BTreeSet<String>,
    predecessors: &BTreeMap<String, BTreeSet<String>>,
    included: &BTreeSet<String>,
    kind: &str,
) -> Vec<ImmediateDomination> {
    let universe: BTreeSet<String> = nodes.intersection(included).cloned().collect();
    let mut dominators: BTreeMap<String, BTreeSet<String>> = universe
        .iter()
        .map(|node| {
            if node == start {
                (node.clone(), BTreeSet::from([node.clone()]))
            } else {
                (node.clone(), universe.clone())
            }
        })
        .collect();
    loop {
        let previous = dominators.clone();
        for node in universe.iter().filter(|node| node.as_str() != start) {
            let incoming: Vec<&BTreeSet<String>> = predecessors
                .get(node)
                .into_iter()
                .flatten()
                .filter_map(|predecessor| previous.get(predecessor))
                .collect();
            let mut next = incoming
                .first()
                .map_or_else(BTreeSet::new, |values| (*values).clone());
            for values in incoming.iter().skip(1) {
                next = next.intersection(values).cloned().collect();
            }
            next.insert(node.clone());
            dominators.insert(node.clone(), next);
        }
        if dominators == previous {
            break;
        }
    }
    universe
        .iter()
        .map(|node| {
            let immediate = if node == start {
                None
            } else {
                dominators[node]
                    .iter()
                    .filter(|candidate| *candidate != node)
                    .max_by_key(|candidate| dominators.get(*candidate).map_or(0, BTreeSet::len))
                    .cloned()
            };
            ImmediateDomination {
                checkpoint: node.clone(),
                derivation: format!("{kind}:{node}:{}", immediate.as_deref().unwrap_or("root")),
                immediate,
            }
        })
        .collect()
}

fn immediate_post_dominators(
    nodes: &BTreeSet<String>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    terminals: &[String],
    included: &BTreeSet<String>,
) -> Vec<ImmediateDomination> {
    const EXIT: &str = "__BFG_COMMON_EXIT__";
    if terminals.is_empty() {
        return Vec::new();
    }
    let mut extended_nodes: BTreeSet<String> = nodes.intersection(included).cloned().collect();
    extended_nodes.insert(EXIT.into());
    let mut reversed_successors: BTreeMap<String, BTreeSet<String>> = extended_nodes
        .iter()
        .map(|node| (node.clone(), BTreeSet::new()))
        .collect();
    for (source, targets) in adjacency {
        for target in targets {
            if included.contains(source) && included.contains(target) {
                reversed_successors
                    .entry(source.clone())
                    .or_default()
                    .insert(target.clone());
            }
        }
    }
    for terminal in terminals {
        reversed_successors
            .entry(terminal.clone())
            .or_default()
            .insert(EXIT.into());
    }
    let post = immediate_dominators(
        EXIT,
        &extended_nodes,
        &reversed_successors,
        &extended_nodes,
        "post_dominator",
    );
    post.into_iter()
        .filter(|value| value.checkpoint != EXIT)
        .map(|mut value| {
            if value.immediate.as_deref() == Some(EXIT) {
                value.immediate = None;
            }
            value
        })
        .collect()
}

fn derivations(
    feature: &str,
    modules: &[String],
    crossings: &[BfgEdge],
    components: &[StronglyConnectedComponent],
    dominators: &[ImmediateDomination],
    post_dominators: &[ImmediateDomination],
    provenance: &[BfgProvenance],
) -> Vec<BfgDerivation> {
    let mut values = Vec::new();
    for module in modules {
        values.push(BfgDerivation {
            id: format!("participant:{feature}:{module}"),
            kind: "participant_module".into(),
            fact: format!("Feature `{feature}` includes Module `{module}`"),
            input_facts: vec![format!("checkpoint_owner:{module}")],
            explanation_path: vec![feature.into(), module.clone()],
            provenance: provenance.to_vec(),
        });
    }
    for edge in crossings {
        values.push(BfgDerivation {
            id: format!("boundary:{}:{}", edge.source, edge.target),
            kind: "boundary_crossing".into(),
            fact: format!(
                "{} -> {} crosses Module ownership",
                edge.source, edge.target
            ),
            input_facts: vec![format!("edge:{}:{}", edge.source, edge.target)],
            explanation_path: vec![edge.source.clone(), edge.target.clone()],
            provenance: vec![edge.provenance.clone()],
        });
    }
    for component in components {
        values.push(BfgDerivation {
            id: component.derivation.clone(),
            kind: "strongly_connected_component".into(),
            fact: format!("SCC contains {}", component.checkpoints.join(", ")),
            input_facts: component
                .checkpoints
                .iter()
                .map(|id| format!("checkpoint:{id}"))
                .collect(),
            explanation_path: component.checkpoints.clone(),
            provenance: provenance.to_vec(),
        });
    }
    for domination in dominators {
        values.push(domination_derivation(
            feature,
            "dominator",
            domination,
            provenance,
        ));
    }
    for domination in post_dominators {
        values.push(domination_derivation(
            feature,
            "post_dominator",
            domination,
            provenance,
        ));
    }
    values.sort();
    values.dedup();
    values
}

fn domination_derivation(
    feature: &str,
    kind: &str,
    value: &ImmediateDomination,
    provenance: &[BfgProvenance],
) -> BfgDerivation {
    BfgDerivation {
        id: value.derivation.clone(),
        kind: kind.into(),
        fact: format!(
            "{} immediate {} is {}",
            value.checkpoint,
            kind,
            value.immediate.as_deref().unwrap_or("none")
        ),
        input_facts: vec![format!("feature_graph:{feature}")],
        explanation_path: value
            .immediate
            .iter()
            .cloned()
            .chain(std::iter::once(value.checkpoint.clone()))
            .collect(),
        provenance: provenance.to_vec(),
    }
}
