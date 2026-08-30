//! Deterministic interprocedural information-flow analysis over canonical PSM facts.

pub(crate) const PROGRAM_INFOFLOW_RULE_SOURCE: &str =
    include_str!("../data/program_infoflow_rule.json");

#[path = "policy.rs"]
mod policy;

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
    ExecutableSymbol, ProgramBody, ProgramExpression, ProgramPattern, ProgramProvenance,
    ProgramSemanticModel, ProgramStatement, ValueEndpoint,
};
use crate::semantic_analysis::{
    FunctionContract, FunctionInformationFlow, InformationFlowTarget, InformationFlowTransformKind,
    ResolvedFunctionContracts, SemanticAnalysisEvaluation,
};
use crate::state_effect_analysis::StateEffectAnalysisEvaluation;

pub use policy::{
    FacetDirection, INFORMATION_FLOW_POLICY_SCHEMA, INFORMATION_FLOW_POLICY_SCHEMA_VERSION,
    InformationFacet, InformationFlowPolicy, InformationFlowPolicyError,
    InformationFlowPolicySource, canonicalize_information_flow_policy_json,
    load_information_flow_policy,
};

/// Canonical Information Flow Analysis schema identity.
pub const INFORMATION_FLOW_ANALYSIS_SCHEMA: &str =
    "urn:fortress:schema:v1:information-flow-analysis";
/// Canonical Information Flow Analysis schema version.
pub const INFORMATION_FLOW_ANALYSIS_SCHEMA_VERSION: u16 = 1;
/// Semantic version of the information-flow analyzer.
pub const INFORMATION_FLOW_ANALYSIS_VERSION: &str = "1.0.0";
/// Stable analyzer identity.
pub const INFORMATION_FLOW_ANALYZER_ID: &str = "fortress-information-flow";
/// Normative information-flow rule identity.
pub const PROGRAM_INFOFLOW_RULE_ID: &str = "PROGRAM-INFOFLOW-001";

const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_heap_alias_information_flow",
    "capability_to_symbol_realization",
    "complete_implicit_control_information_flow",
    "concurrency_interleaving_information_flow",
    "covert_and_timing_channels",
    "cryptographic_secrecy_proof",
    "database_row_level_information_flow",
    "external_api_information_flow_without_contract",
];

/// Authority explaining why one label is attached to a value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowAuthority {
    /// A Function Contract introduced an authoritative source classification.
    ContractSource,
    /// Existing PSM data movement mechanically propagated a label.
    ProvenPropagation,
    /// An explicit contract endorsement increased integrity/trust.
    TrustedEndorsement,
    /// An explicit contract declassification reduced confidentiality restriction.
    TrustedDeclassification,
    /// Exact flow classification is unavailable.
    Unknown,
}

/// Independent epistemic state of one information-flow dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InformationFlowCoverage {
    /// Supported semantics completely establish the represented facts.
    Proven,
    /// Some represented facts are established while opaque flow remains.
    Partial,
    /// No exact classification is available.
    Unknown,
    /// The semantic class is outside v1.
    Unsupported,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct FlowNode {
    symbol: String,
    role: String,
    name: String,
}

impl FlowNode {
    fn new(symbol: impl Into<String>, role: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            role: role.into(),
            name: name.into(),
        }
    }

    fn from_endpoint(endpoint: &ValueEndpoint) -> Self {
        Self::new(endpoint.symbol(), endpoint.role(), endpoint.name())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowEdge {
    producer: FlowNode,
    consumer: FlowNode,
    kind: String,
    path: String,
    line: u32,
    column: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct LabelFact {
    facet: String,
    level: String,
    authority: FlowAuthority,
    origin: String,
    chain: Vec<String>,
}

/// One exact trusted security boundary declared by a Function Contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TrustedTransitionDiagnostic {
    kind: InformationFlowTransformKind,
    symbol: String,
    facet: String,
    from: String,
    to: String,
    input: String,
    output: String,
    contract_provenance: String,
    fingerprint: String,
}

impl TrustedTransitionDiagnostic {
    /// Returns endorsement or declassification.
    #[must_use]
    pub const fn kind(&self) -> InformationFlowTransformKind {
        self.kind
    }

    /// Returns the executable symbol containing the trusted transition.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the project-defined information facet.
    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    /// Returns the declared source level.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Returns the declared target level.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Returns exact Function Contract provenance.
    #[must_use]
    pub fn contract_provenance(&self) -> &str {
        &self.contract_provenance
    }
}

/// One supported source-to-sink information-flow contradiction.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct InformationFlowViolation {
    id: String,
    symbol: String,
    facet: String,
    sink_target: String,
    required: String,
    contradicting_levels: Vec<String>,
    source_chain: Vec<String>,
    message: String,
    path: String,
    line: u32,
    column: u32,
}

/// One function's compositional information-flow summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InformationFlowSummary {
    symbol: String,
    sources: Vec<String>,
    sinks: Vec<String>,
    return_labels: Vec<LabelFact>,
    field_flows: Vec<String>,
    trusted_transitions: Vec<String>,
    uncertainty: Vec<String>,
    explicit_value_propagation: InformationFlowCoverage,
    field_propagation: InformationFlowCoverage,
    interprocedural_propagation: InformationFlowCoverage,
    sink_verification: InformationFlowCoverage,
}

impl InformationFlowSummary {
    /// Returns the governed executable symbol.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }
}

/// Deterministic aggregate information-flow counts and coverage states.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct InformationFlowCoverageSummary {
    functions: usize,
    classified_sources: usize,
    declared_sinks: usize,
    sink_checks: usize,
    sink_violations: usize,
    interprocedural_flow_facts: usize,
    field_flow_facts: usize,
    endorsements: usize,
    declassifications: usize,
    unknown_sinks: usize,
    fixed_point_iterations: usize,
    explicit_value_propagation: InformationFlowCoverage,
    field_propagation: InformationFlowCoverage,
    interprocedural_propagation: InformationFlowCoverage,
    sink_verification: InformationFlowCoverage,
    source_classification: InformationFlowCoverage,
    trusted_transition_coverage: InformationFlowCoverage,
    implicit_control_flow: InformationFlowCoverage,
    external_flow: InformationFlowCoverage,
}

impl InformationFlowCoverageSummary {
    /// Returns the supported violation count.
    #[must_use]
    pub const fn violations(self) -> usize {
        self.sink_violations
    }
}

/// Canonical deterministic Information Flow Analysis v1 derived Info.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InformationFlowAnalysisModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: Option<String>,
    psm_digest: String,
    semantic_analysis_digest: String,
    state_effect_digest: String,
    information_flow_policy_digest: String,
    function_contract_digest: String,
    facets: Vec<InformationFacet>,
    summaries: Vec<InformationFlowSummary>,
    violations: Vec<InformationFlowViolation>,
    trusted_transition_diagnostics: Vec<TrustedTransitionDiagnostic>,
    coverage: InformationFlowCoverageSummary,
    unsupported_semantics: Vec<String>,
}

impl InformationFlowAnalysisModel {
    /// Returns supported contradictions.
    #[must_use]
    pub fn violations(&self) -> &[InformationFlowViolation] {
        &self.violations
    }

    /// Returns all explicit trusted security boundaries.
    #[must_use]
    pub fn trusted_transition_diagnostics(&self) -> &[TrustedTransitionDiagnostic] {
        &self.trusted_transition_diagnostics
    }

    /// Returns aggregate coverage.
    #[must_use]
    pub const fn coverage(&self) -> InformationFlowCoverageSummary {
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

/// Rule-facing information-flow evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationFlowEvaluation {
    model: InformationFlowAnalysisModel,
    findings: Vec<CanonicalFinding>,
}

impl InformationFlowEvaluation {
    /// Returns the canonical derived model.
    #[must_use]
    pub const fn model(&self) -> &InformationFlowAnalysisModel {
        &self.model
    }

    /// Returns PROGRAM-INFOFLOW-001 findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Propagates project-defined classifications over canonical PSM flow facts.
///
/// # Errors
///
/// Returns a typed error for invalid policy references, invalid trusted
/// transitions, canonical serialization, or finding construction.
#[allow(clippy::too_many_lines)]
pub fn analyze_information_flow(
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisEvaluation,
    state_effect: &StateEffectAnalysisEvaluation,
    policy: &InformationFlowPolicy,
    contracts: &ResolvedFunctionContracts,
    standard_edition: &str,
) -> Result<InformationFlowEvaluation, InformationFlowAnalysisError> {
    validate_contract_policy(policy, contracts)?;
    let (mut edges, field_edge_count) = flow_edges(psm);
    edges.sort();
    edges.dedup();
    let mut facts: BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>> = BTreeMap::new();
    let mut barriers = BTreeSet::new();
    let mut diagnostics = Vec::new();
    let mut classified_sources = 0;
    for contract in contracts.contracts() {
        let Some(flow) = contract.information_flow() else {
            continue;
        };
        for source in flow.sources() {
            classified_sources += 1;
            let node = target_node(contract.symbol(), source.target());
            insert_fact(
                &mut facts,
                node,
                LabelFact {
                    facet: source.facet().into(),
                    level: source.level().into(),
                    authority: FlowAuthority::ContractSource,
                    origin: format!("{}:{}", contract.symbol(), source.target().identity()),
                    chain: vec![format!("contract_source:{}", contract.symbol())],
                },
            );
        }
        for ensure in flow.ensures() {
            let node = target_node(contract.symbol(), ensure.target());
            insert_fact(
                &mut facts,
                node,
                LabelFact {
                    facet: ensure.facet().into(),
                    level: ensure.level().into(),
                    authority: FlowAuthority::ContractSource,
                    origin: format!("{}:{}", contract.symbol(), ensure.target().identity()),
                    chain: vec![format!("contract_ensure:{}", contract.symbol())],
                },
            );
        }
        for transform in flow.transforms() {
            barriers.insert((
                target_node(contract.symbol(), transform.output()),
                transform.facet().to_owned(),
            ));
            diagnostics.push(trusted_transition_diagnostic(contract, transform));
        }
    }
    diagnostics.sort();
    diagnostics.dedup();

    let mut iterations = 0;
    let limit = psm.symbols().len().saturating_mul(4).max(16);
    loop {
        iterations += 1;
        let mut changed = propagate_edges(&edges, &barriers, &mut facts);
        changed |= apply_trusted_transitions(contracts, &mut facts);
        if !changed || iterations >= limit {
            break;
        }
    }

    let (mut violations, sink_checks, unknown_sinks, declared_sinks) =
        check_sinks(psm, policy, contracts, &facts);
    violations.sort();
    violations.dedup();
    let findings = violations
        .iter()
        .map(|violation| finding(violation, standard_edition))
        .collect::<Result<Vec<_>, _>>()?;
    let summaries = summaries(psm, contracts, &facts, &violations, field_edge_count);
    let interprocedural_flow_facts = edges
        .iter()
        .filter(|edge| edge.producer.symbol != edge.consumer.symbol)
        .filter(|edge| facts.contains_key(&edge.producer))
        .count();
    let endorsements = diagnostics
        .iter()
        .filter(|item| item.kind == InformationFlowTransformKind::Endorsement)
        .count();
    let declassifications = diagnostics.len() - endorsements;
    let coverage = InformationFlowCoverageSummary {
        functions: psm.symbols().len(),
        classified_sources,
        declared_sinks,
        sink_checks,
        sink_violations: violations.len(),
        interprocedural_flow_facts,
        field_flow_facts: field_edge_count,
        endorsements,
        declassifications,
        unknown_sinks,
        fixed_point_iterations: iterations,
        explicit_value_propagation: InformationFlowCoverage::Proven,
        field_propagation: if psm.mutations().is_empty() {
            InformationFlowCoverage::Unknown
        } else {
            InformationFlowCoverage::Partial
        },
        interprocedural_propagation: if psm.calls().iter().any(|call| call.callee().is_none()) {
            InformationFlowCoverage::Partial
        } else {
            InformationFlowCoverage::Proven
        },
        sink_verification: if declared_sinks == 0 {
            InformationFlowCoverage::Unknown
        } else if unknown_sinks == 0 {
            InformationFlowCoverage::Proven
        } else {
            InformationFlowCoverage::Partial
        },
        source_classification: if classified_sources == 0 {
            InformationFlowCoverage::Unknown
        } else if policy.is_authored() {
            InformationFlowCoverage::Proven
        } else {
            InformationFlowCoverage::Unknown
        },
        trusted_transition_coverage: if diagnostics.is_empty() {
            InformationFlowCoverage::Unknown
        } else {
            InformationFlowCoverage::Proven
        },
        implicit_control_flow: InformationFlowCoverage::Unsupported,
        external_flow: InformationFlowCoverage::Unknown,
    };
    let model = InformationFlowAnalysisModel {
        schema: INFORMATION_FLOW_ANALYSIS_SCHEMA.into(),
        schema_version: INFORMATION_FLOW_ANALYSIS_SCHEMA_VERSION,
        semantic_version: INFORMATION_FLOW_ANALYSIS_VERSION.into(),
        project_id: psm.project_id().map(str::to_owned),
        psm_digest: psm.digest()?,
        semantic_analysis_digest: semantic.model().digest()?,
        state_effect_digest: state_effect.model().digest()?,
        information_flow_policy_digest: policy.digest().into(),
        function_contract_digest: contracts.digest().into(),
        facets: policy.facets().cloned().collect(),
        summaries,
        violations,
        trusted_transition_diagnostics: diagnostics,
        coverage,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
    };
    Ok(InformationFlowEvaluation { model, findings })
}

fn validate_contract_policy(
    policy: &InformationFlowPolicy,
    contracts: &ResolvedFunctionContracts,
) -> Result<(), InformationFlowAnalysisError> {
    for contract in contracts.contracts() {
        let Some(flow) = contract.information_flow() else {
            continue;
        };
        for (facet, level) in flow
            .sources()
            .iter()
            .map(|item| (item.facet(), item.level()))
            .chain(
                flow.ensures()
                    .iter()
                    .map(|item| (item.facet(), item.level())),
            )
        {
            resolve_level(policy, contract.symbol(), facet, level)?;
        }
        for requirement in flow.requires() {
            if let Some(level) = requirement.minimum() {
                resolve_level(policy, contract.symbol(), requirement.facet(), level)?;
            }
            if let Some(level) = requirement.maximum() {
                resolve_level(policy, contract.symbol(), requirement.facet(), level)?;
            }
        }
        for transform in flow.transforms() {
            let facet = policy.facet(transform.facet()).ok_or_else(|| {
                InformationFlowAnalysisError::UnknownFacet {
                    symbol: contract.symbol().into(),
                    facet: transform.facet().into(),
                }
            })?;
            let from = resolve_level(
                policy,
                contract.symbol(),
                transform.facet(),
                transform.from(),
            )?;
            let to = resolve_level(policy, contract.symbol(), transform.facet(), transform.to())?;
            let valid = match transform.kind() {
                InformationFlowTransformKind::Endorsement => {
                    facet.direction() == FacetDirection::HigherIsStronger && to > from
                }
                InformationFlowTransformKind::Declassification => {
                    facet.direction() == FacetDirection::HigherIsMoreRestricted && to < from
                }
            };
            if !valid {
                return Err(InformationFlowAnalysisError::InvalidTrustedTransition {
                    symbol: contract.symbol().into(),
                    facet: transform.facet().into(),
                    from: transform.from().into(),
                    to: transform.to().into(),
                });
            }
        }
    }
    Ok(())
}

fn resolve_level(
    policy: &InformationFlowPolicy,
    symbol: &str,
    facet_id: &str,
    level: &str,
) -> Result<usize, InformationFlowAnalysisError> {
    let facet =
        policy
            .facet(facet_id)
            .ok_or_else(|| InformationFlowAnalysisError::UnknownFacet {
                symbol: symbol.into(),
                facet: facet_id.into(),
            })?;
    facet
        .index_of(level)
        .ok_or_else(|| InformationFlowAnalysisError::UnknownLevel {
            symbol: symbol.into(),
            facet: facet_id.into(),
            level: level.into(),
        })
}

fn target_node(symbol: &str, target: &InformationFlowTarget) -> FlowNode {
    match target {
        InformationFlowTarget::Parameter { name } => FlowNode::new(symbol, "parameter", name),
        InformationFlowTarget::Receiver => FlowNode::new(symbol, "parameter", "self"),
        InformationFlowTarget::Return => FlowNode::new(symbol, "return", "return"),
    }
}

fn insert_fact(
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    node: FlowNode,
    fact: LabelFact,
) -> bool {
    let existing = facts
        .entry(node)
        .or_default()
        .entry(fact.facet.clone())
        .or_default();
    if existing
        .iter()
        .any(|candidate| candidate.level == fact.level && candidate.origin == fact.origin)
    {
        return false;
    }
    existing.insert(fact)
}

fn flow_edges(psm: &ProgramSemanticModel) -> (Vec<FlowEdge>, usize) {
    let mut edges = psm
        .value_transfers()
        .iter()
        .map(|transfer| FlowEdge {
            producer: FlowNode::from_endpoint(transfer.producer()),
            consumer: FlowNode::from_endpoint(transfer.consumer()),
            kind: format!("psm:{:?}", transfer.kind()).to_lowercase(),
            path: transfer.provenance().path().into(),
            line: transfer.provenance().location().line(),
            column: transfer.provenance().location().column(),
        })
        .collect::<Vec<_>>();
    let mut nodes = BTreeSet::new();
    for edge in &edges {
        nodes.insert(edge.producer.clone());
        nodes.insert(edge.consumer.clone());
    }
    add_parameter_identity_edges(psm, &mut edges);
    add_binding_identity_edges(&nodes, &mut edges);
    for body in psm.bodies() {
        body_edges(body, body.statements(), &mut edges);
    }
    let field_edges = add_field_edges(psm, &mut edges);
    (edges, field_edges)
}

fn add_parameter_identity_edges(psm: &ProgramSemanticModel, edges: &mut Vec<FlowEdge>) {
    for symbol in psm.symbols() {
        for parameter in symbol.parameters() {
            let named = FlowNode::new(symbol.id(), "parameter", parameter.name());
            let positional = FlowNode::new(
                symbol.id(),
                "parameter",
                format!("parameter:{}", parameter.position()),
            );
            edges.push(FlowEdge {
                producer: named.clone(),
                consumer: positional.clone(),
                kind: "psm:parameter_identity".into(),
                path: parameter.provenance().path().into(),
                line: parameter.provenance().location().line(),
                column: parameter.provenance().location().column(),
            });
            edges.push(FlowEdge {
                producer: positional,
                consumer: named,
                kind: "psm:parameter_identity".into(),
                path: parameter.provenance().path().into(),
                line: parameter.provenance().location().line(),
                column: parameter.provenance().location().column(),
            });
        }
    }
}

fn add_binding_identity_edges(nodes: &BTreeSet<FlowNode>, edges: &mut Vec<FlowEdge>) {
    let bindings = nodes
        .iter()
        .filter(|node| matches!(node.role.as_str(), "binding" | "parameter"))
        .cloned()
        .collect::<Vec<_>>();
    for binding in bindings {
        for candidate in nodes.iter().filter(|candidate| {
            candidate.symbol == binding.symbol
                && candidate.name == binding.name
                && matches!(candidate.role.as_str(), "argument" | "expression" | "place")
        }) {
            edges.push(FlowEdge {
                producer: binding.clone(),
                consumer: candidate.clone(),
                kind: "psm:binding_identity".into(),
                path: "<derived-psm-binding-identity>".into(),
                line: 1,
                column: 1,
            });
            edges.push(FlowEdge {
                producer: candidate.clone(),
                consumer: binding.clone(),
                kind: "psm:binding_identity".into(),
                path: "<derived-psm-binding-identity>".into(),
                line: 1,
                column: 1,
            });
        }
    }
}

fn add_field_edges(psm: &ProgramSemanticModel, edges: &mut Vec<FlowEdge>) -> usize {
    let mut field_edges = 0;
    for mutation in psm.mutations() {
        if let (Some(owner), Some(field)) = (
            mutation.target().nominal_owner(),
            mutation.target().field_name(),
        ) {
            let target = FlowNode::new(owner, "field", field);
            for producer in expression_sources(mutation.symbol(), mutation.value()) {
                edges.push(edge_from_provenance(
                    producer,
                    target.clone(),
                    "psm:field_write",
                    mutation.provenance(),
                ));
                field_edges += 1;
            }
        }
    }
    for read in psm.state_reads() {
        if let (Some(owner), Some(field)) =
            (read.place().nominal_owner(), read.place().field_name())
        {
            let producer = FlowNode::new(owner, "field", field);
            let consumer = FlowNode::new(read.symbol(), "field_read", format!("?.{field}"));
            edges.push(edge_from_provenance(
                producer,
                consumer,
                "psm:field_read",
                read.provenance(),
            ));
            field_edges += 1;
        }
    }
    field_edges
}

fn body_edges(body: &ProgramBody, statements: &[ProgramStatement], edges: &mut Vec<FlowEdge>) {
    for statement in statements {
        match statement {
            ProgramStatement::Let {
                pattern,
                value: Some(value),
                provenance,
            } => {
                let targets = pattern_bindings(pattern)
                    .into_iter()
                    .map(|name| FlowNode::new(body.symbol(), "binding", name))
                    .collect::<Vec<_>>();
                add_expression_edges(
                    body.symbol(),
                    value,
                    &targets,
                    "psm:construction",
                    provenance,
                    edges,
                );
            }
            ProgramStatement::Assign {
                target,
                value,
                provenance,
            } => add_expression_edges(
                body.symbol(),
                value,
                &[FlowNode::new(body.symbol(), "place", target)],
                "psm:assignment",
                provenance,
                edges,
            ),
            ProgramStatement::Return {
                value: Some(value),
                provenance,
            } => add_expression_edges(
                body.symbol(),
                value,
                &[FlowNode::new(body.symbol(), "return", "return")],
                "psm:return",
                provenance,
                edges,
            ),
            ProgramStatement::Expression { .. }
            | ProgramStatement::Let { value: None, .. }
            | ProgramStatement::Return { value: None, .. } => {}
            ProgramStatement::If {
                then_branch,
                else_branch,
                ..
            } => {
                body_edges(body, then_branch, edges);
                body_edges(body, else_branch, edges);
            }
            ProgramStatement::Match { arms, .. } => {
                for arm in arms {
                    body_edges(body, arm.body(), edges);
                }
            }
            ProgramStatement::WhileLet { body: nested, .. } => body_edges(body, nested, edges),
        }
    }
}

fn add_expression_edges(
    symbol: &str,
    expression: &ProgramExpression,
    targets: &[FlowNode],
    kind: &str,
    provenance: &ProgramProvenance,
    edges: &mut Vec<FlowEdge>,
) {
    for source in expression_sources(symbol, expression) {
        for target in targets {
            edges.push(edge_from_provenance(
                source.clone(),
                target.clone(),
                kind,
                provenance,
            ));
        }
    }
}

fn edge_from_provenance(
    producer: FlowNode,
    consumer: FlowNode,
    kind: &str,
    provenance: &ProgramProvenance,
) -> FlowEdge {
    FlowEdge {
        producer,
        consumer,
        kind: kind.into(),
        path: provenance.path().into(),
        line: provenance.location().line(),
        column: provenance.location().column(),
    }
}

fn pattern_bindings(pattern: &ProgramPattern) -> Vec<String> {
    let mut result = Vec::new();
    match pattern {
        ProgramPattern::Binding { name } => result.push(name.clone()),
        ProgramPattern::Variant { fields, .. } => {
            for field in fields {
                result.extend(pattern_bindings(field));
            }
        }
        ProgramPattern::Tuple { elements } => {
            for element in elements {
                result.extend(pattern_bindings(element));
            }
        }
        ProgramPattern::Wildcard | ProgramPattern::Unsupported { .. } => {}
    }
    result.sort();
    result.dedup();
    result
}

fn expression_sources(symbol: &str, expression: &ProgramExpression) -> Vec<FlowNode> {
    let mut result = BTreeSet::new();
    collect_expression_sources(symbol, expression, &mut result);
    result.into_iter().collect()
}

fn collect_expression_sources(
    symbol: &str,
    expression: &ProgramExpression,
    result: &mut BTreeSet<FlowNode>,
) {
    match expression {
        ProgramExpression::Binding { name } => {
            result.insert(FlowNode::new(symbol, "binding", name));
        }
        ProgramExpression::Field { base, field } => {
            collect_expression_sources(symbol, base, result);
            result.insert(FlowNode::new(symbol, "field_read", format!("?.{field}")));
        }
        ProgramExpression::Tuple { elements }
        | ProgramExpression::Construction {
            arguments: elements,
            ..
        } => {
            for element in elements {
                collect_expression_sources(symbol, element, result);
            }
        }
        ProgramExpression::Call { arguments, .. } => {
            for argument in arguments {
                collect_expression_sources(symbol, argument, result);
            }
        }
        ProgramExpression::MethodCall {
            receiver,
            arguments,
            ..
        } => {
            collect_expression_sources(symbol, receiver, result);
            for argument in arguments {
                collect_expression_sources(symbol, argument, result);
            }
        }
        ProgramExpression::PatternTest { value, .. }
        | ProgramExpression::Unary { value, .. }
        | ProgramExpression::Try { value }
        | ProgramExpression::Reference { value, .. } => {
            collect_expression_sources(symbol, value, result);
        }
        ProgramExpression::Binary { left, right, .. } => {
            collect_expression_sources(symbol, left, result);
            collect_expression_sources(symbol, right, result);
        }
        ProgramExpression::Boolean { .. }
        | ProgramExpression::Integer { .. }
        | ProgramExpression::Unit
        | ProgramExpression::Variant { .. }
        | ProgramExpression::Exceptional { .. }
        | ProgramExpression::Unsupported { .. } => {}
    }
}

fn propagate_edges(
    edges: &[FlowEdge],
    barriers: &BTreeSet<(FlowNode, String)>,
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
) -> bool {
    let snapshot = facts.clone();
    let mut changed = false;
    for edge in edges {
        let Some(by_facet) = snapshot.get(&edge.producer) else {
            continue;
        };
        for (facet, source_facts) in by_facet {
            if barriers.contains(&(edge.consumer.clone(), facet.clone())) {
                continue;
            }
            for source in source_facts {
                let mut propagated = source.clone();
                propagated.authority = FlowAuthority::ProvenPropagation;
                propagated.chain.push(format!(
                    "{}:{}:{}:{}",
                    edge.kind, edge.path, edge.line, edge.column
                ));
                changed |= insert_fact(facts, edge.consumer.clone(), propagated);
            }
        }
    }
    changed
}

fn apply_trusted_transitions(
    contracts: &ResolvedFunctionContracts,
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
) -> bool {
    let snapshot = facts.clone();
    let mut changed = false;
    for contract in contracts.contracts() {
        let Some(flow) = contract.information_flow() else {
            continue;
        };
        for transform in flow.transforms() {
            let input = target_node(contract.symbol(), transform.input());
            let output = target_node(contract.symbol(), transform.output());
            let matching = snapshot
                .get(&input)
                .and_then(|by_facet| by_facet.get(transform.facet()))
                .into_iter()
                .flatten()
                .filter(|fact| fact.level == transform.from())
                .cloned()
                .collect::<Vec<_>>();
            for source in matching {
                let authority = match transform.kind() {
                    InformationFlowTransformKind::Endorsement => FlowAuthority::TrustedEndorsement,
                    InformationFlowTransformKind::Declassification => {
                        FlowAuthority::TrustedDeclassification
                    }
                };
                let mut chain = source.chain;
                chain.push(format!(
                    "trusted_{:?}:{}:{}->{}",
                    transform.kind(),
                    contract.symbol(),
                    transform.from(),
                    transform.to()
                ));
                changed |= insert_fact(
                    facts,
                    output.clone(),
                    LabelFact {
                        facet: transform.facet().into(),
                        level: transform.to().into(),
                        authority,
                        origin: source.origin,
                        chain,
                    },
                );
            }
        }
    }
    changed
}

fn check_sinks(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    contracts: &ResolvedFunctionContracts,
    facts: &BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
) -> (Vec<InformationFlowViolation>, usize, usize, usize) {
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();
    let mut checks = 0;
    let mut unknown = 0;
    let mut declared = 0;
    for contract in contracts.contracts() {
        let Some(flow) = contract.information_flow() else {
            continue;
        };
        for requirement in flow.requires() {
            declared += 1;
            let node = target_node(contract.symbol(), requirement.target());
            let Some(label_facts) = facts
                .get(&node)
                .and_then(|by_facet| by_facet.get(requirement.facet()))
            else {
                unknown += 1;
                continue;
            };
            checks += 1;
            let facet = policy
                .facet(requirement.facet())
                .expect("contract policy was validated");
            let minimum = requirement
                .minimum()
                .and_then(|level| facet.index_of(level));
            let maximum = requirement
                .maximum()
                .and_then(|level| facet.index_of(level));
            let contradicting = label_facts
                .iter()
                .filter(|fact| {
                    let index = facet
                        .index_of(&fact.level)
                        .expect("label level was validated");
                    minimum.is_some_and(|bound| index < bound)
                        || maximum.is_some_and(|bound| index > bound)
                })
                .cloned()
                .collect::<Vec<_>>();
            if contradicting.is_empty() {
                continue;
            }
            let provenance = symbols
                .get(contract.symbol())
                .map(|symbol| symbol.provenance())
                .expect("contract symbol exists");
            let required = requirement.minimum().map_or_else(
                || format!("<= {}", requirement.maximum().unwrap_or("?")),
                |value| format!(">= {value}"),
            );
            violations.push(information_flow_violation(
                contract.symbol(),
                requirement.facet(),
                &requirement.target().identity(),
                &required,
                &contradicting,
                provenance,
            ));
        }
    }
    (violations, checks, unknown, declared)
}

#[derive(Serialize)]
struct InformationFlowViolationIdentity<'a> {
    symbol: &'a str,
    facet: &'a str,
    target: &'a str,
    required: &'a str,
    levels: &'a [String],
}

fn information_flow_violation(
    symbol: &str,
    facet: &str,
    target: &str,
    required: &str,
    contradicting: &[LabelFact],
    provenance: &ProgramProvenance,
) -> InformationFlowViolation {
    let levels = contradicting
        .iter()
        .map(|fact| fact.level.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let chain = contradicting
        .iter()
        .flat_map(|fact| fact.chain.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let message = format!(
        "information flow into `{symbol}` `{target}` carries `{facet}` levels [{}] but requires {required}",
        levels.join(", ")
    );
    let id = format!(
        "information_flow_violation:sha256:{:x}",
        Sha256::digest(
            serde_json::to_vec(&InformationFlowViolationIdentity {
                symbol,
                facet,
                target,
                required,
                levels: &levels,
            })
            .expect("violation identity serializes")
        )
    );
    InformationFlowViolation {
        id,
        symbol: symbol.into(),
        facet: facet.into(),
        sink_target: target.into(),
        required: required.into(),
        contradicting_levels: levels,
        source_chain: chain,
        message,
        path: provenance.path().into(),
        line: provenance.location().line(),
        column: provenance.location().column(),
    }
}

fn summaries(
    psm: &ProgramSemanticModel,
    contracts: &ResolvedFunctionContracts,
    facts: &BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    violations: &[InformationFlowViolation],
    field_edge_count: usize,
) -> Vec<InformationFlowSummary> {
    let mut result = psm
        .symbols()
        .iter()
        .map(|symbol| {
            let flow = contracts
                .get(symbol.id())
                .and_then(FunctionContract::information_flow);
            let return_labels = facts
                .get(&FlowNode::new(symbol.id(), "return", "return"))
                .into_iter()
                .flat_map(BTreeMap::values)
                .flatten()
                .cloned()
                .collect();
            let sources = flow
                .into_iter()
                .flat_map(FunctionInformationFlow::sources)
                .map(|source| {
                    format!(
                        "{}:{}={}",
                        source.target().identity(),
                        source.facet(),
                        source.level()
                    )
                })
                .collect();
            let sinks = flow
                .into_iter()
                .flat_map(FunctionInformationFlow::requires)
                .map(|requirement| {
                    format!(
                        "{}:{}",
                        requirement.target().identity(),
                        requirement.facet()
                    )
                })
                .collect::<Vec<_>>();
            let trusted_transitions = flow
                .into_iter()
                .flat_map(FunctionInformationFlow::transforms)
                .map(|transform| {
                    format!(
                        "{:?}:{}:{}->{}",
                        transform.kind(),
                        transform.facet(),
                        transform.from(),
                        transform.to()
                    )
                })
                .collect();
            let has_unknown_calls = symbol_has_unknown_calls(psm, symbol);
            let sink_verification = if violations.iter().any(|item| item.symbol == symbol.id()) {
                InformationFlowCoverage::Partial
            } else if sinks.is_empty() {
                InformationFlowCoverage::Unknown
            } else {
                InformationFlowCoverage::Proven
            };
            InformationFlowSummary {
                symbol: symbol.id().into(),
                sources,
                sinks,
                return_labels,
                field_flows: symbol_field_flows(psm, symbol, field_edge_count),
                trusted_transitions,
                uncertainty: if has_unknown_calls {
                    vec!["opaque_or_unresolved_call_flow".into()]
                } else {
                    Vec::new()
                },
                explicit_value_propagation: InformationFlowCoverage::Proven,
                field_propagation: if psm
                    .state_reads()
                    .iter()
                    .any(|read| read.symbol() == symbol.id())
                {
                    InformationFlowCoverage::Partial
                } else {
                    InformationFlowCoverage::Unknown
                },
                interprocedural_propagation: if has_unknown_calls {
                    InformationFlowCoverage::Partial
                } else {
                    InformationFlowCoverage::Proven
                },
                sink_verification,
            }
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    result
}

fn symbol_has_unknown_calls(psm: &ProgramSemanticModel, symbol: &ExecutableSymbol) -> bool {
    psm.calls()
        .iter()
        .any(|call| call.caller() == symbol.id() && call.callee().is_none())
}

fn symbol_field_flows(
    psm: &ProgramSemanticModel,
    symbol: &ExecutableSymbol,
    field_edge_count: usize,
) -> Vec<String> {
    if field_edge_count == 0 {
        return Vec::new();
    }
    psm.state_reads()
        .iter()
        .filter(|read| read.symbol() == symbol.id())
        .filter_map(|read| read.place().field_name().map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn trusted_transition_diagnostic(
    contract: &FunctionContract,
    transform: &crate::semantic_analysis::InformationFlowTransform,
) -> TrustedTransitionDiagnostic {
    #[derive(Serialize)]
    struct Identity<'a> {
        kind: InformationFlowTransformKind,
        symbol: &'a str,
        facet: &'a str,
        from: &'a str,
        to: &'a str,
    }
    let identity = Identity {
        kind: transform.kind(),
        symbol: contract.symbol(),
        facet: transform.facet(),
        from: transform.from(),
        to: transform.to(),
    };
    TrustedTransitionDiagnostic {
        kind: transform.kind(),
        symbol: contract.symbol().into(),
        facet: transform.facet().into(),
        from: transform.from().into(),
        to: transform.to().into(),
        input: transform.input().identity(),
        output: transform.output().identity(),
        contract_provenance: format!("function_contract:{}", contract.symbol()),
        fingerprint: format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&identity).expect("diagnostic identity serializes"))
        ),
    }
}

fn finding(
    violation: &InformationFlowViolation,
    edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let definition = RuleFindingDefinition::new(
        PROGRAM_INFOFLOW_RULE_ID,
        3,
        FindingCategory::Security,
        "Preserve the incoming classification, satisfy the sink constraint, or declare and review an explicit truthful endorsement/declassification boundary.",
    )?;
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
        EvaluatorProvenance::new(
            INFORMATION_FLOW_ANALYZER_ID,
            INFORMATION_FLOW_ANALYSIS_VERSION,
        )?,
        edition,
        None,
    )
}

/// Explains why information-flow analysis could not be constructed.
#[derive(Debug)]
pub enum InformationFlowAnalysisError {
    /// One Function Contract references an unknown project facet.
    UnknownFacet {
        /// Contracted symbol.
        symbol: String,
        /// Unknown facet.
        facet: String,
    },
    /// One Function Contract references an unknown project level.
    UnknownLevel {
        /// Contracted symbol.
        symbol: String,
        /// Facet identity.
        facet: String,
        /// Unknown level.
        level: String,
    },
    /// A trusted transition does not move in the direction authorized by its kind.
    InvalidTrustedTransition {
        /// Contracted symbol.
        symbol: String,
        /// Facet identity.
        facet: String,
        /// Input level.
        from: String,
        /// Output level.
        to: String,
    },
    /// Canonical JSON serialization failed.
    Serialization(serde_json::Error),
    /// Normalized finding construction failed.
    Finding(FindingError),
}

impl Display for InformationFlowAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFacet { symbol, facet } => {
                write!(
                    formatter,
                    "Function Contract `{symbol}` references unknown facet `{facet}`"
                )
            }
            Self::UnknownLevel {
                symbol,
                facet,
                level,
            } => write!(
                formatter,
                "Function Contract `{symbol}` references unknown `{facet}` level `{level}`"
            ),
            Self::InvalidTrustedTransition {
                symbol,
                facet,
                from,
                to,
            } => write!(
                formatter,
                "Function Contract `{symbol}` declares invalid trusted transition `{facet}` `{from}` -> `{to}`"
            ),
            Self::Serialization(error) => {
                write!(formatter, "information-flow serialization failed: {error}")
            }
            Self::Finding(error) => write!(formatter, "information-flow finding failed: {error}"),
        }
    }
}

impl Error for InformationFlowAnalysisError {}
impl From<serde_json::Error> for InformationFlowAnalysisError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}
impl From<FindingError> for InformationFlowAnalysisError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}
