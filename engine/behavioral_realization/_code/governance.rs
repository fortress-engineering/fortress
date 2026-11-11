//! Bounded checkpoint claims over the existing owner-produced event graph.
//! Intent, static realization, execution and authorization remain independent.
use super::{
    BEHAVIOR_BYPASS_RULE_ID, BEHAVIOR_REALIZATION_RULE_ID, BOUNDED_BEHAVIOR_CONTRACT_SCHEMA,
    BYPASS_REMEDIATION, BehaviorAnchor, BehavioralModelingState, BehavioralRealizationError,
    BehavioralRealizationEvaluation, CanonicalFinding, ContractCoherencyGraph,
    EnvironmentalAnalysisModel, EvaluatorProvenance, FindingCategory, FindingLocation,
    FindingOccurrence, ImplementationEventModel, InformationFlowAnalysisModel,
    IntendedBehavioralFlowGraph, ProgramSemanticModel, REALIZATION_REMEDIATION,
    RealizationCoverage, ResolvedBehaviorRealizationContracts, RuleFindingDefinition,
    SemanticAnalysisModel, SemanticDomain, StateEffectAnalysisModel,
    canonicalize_behavior_realization_contract_json, derive_event_model,
    evaluate_behavioral_realization, event_id, resolve_anchor_event,
};
use crate::finding::{
    Defeater, DefeaterKind, DefeaterRetirementCondition, DefeaterScope, DefeaterScopeKind,
    DefeaterStrength,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
/// Explicit bounded behavior profile; selection is supplied by profile composition.
pub const BEHAVIOR_PROFILE_ID: &str = "GOV-FORTRESS-BOUNDED-BEHAVIOR";
/// Public checkpoint claim wire identity.
pub const BEHAVIOR_CLAIM_SCHEMA: &str = "urn:fortress:schema:v1:behavior-claim";
/// Exact project/Module applicability, independent of source observations.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorSelection {
    /// Select all authored, bound Features in this project.
    pub project: bool,
    /// Otherwise select Features owned by these canonical Modules.
    pub modules: BTreeSet<String>,
}
/// Immutable owner conclusions; consumers serialize and assess, never re-evaluate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedBehaviorEvaluation {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    context_ref: String,
    claims: Vec<Value>,
    findings: Vec<CanonicalFinding>,
}
impl BoundedBehaviorEvaluation {
    /// Returns canonical claim projections with their original uncertainty.
    #[must_use]
    pub fn claims(&self) -> &[Value] {
        &self.claims
    }
    /// Returns supported normalized findings, independently of enforcement.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct State {
    node: String,
    stack: Vec<(String, String)>,
    seen: BTreeSet<String>,
    last: Option<String>,
    supported: bool,
}
struct Visit {
    state: State,
    previous: Option<usize>,
}
const MAX_STATES: usize = 20_000;
const MAX_STEPS: usize = 1_000_000;
const MAX_FRAMES: usize = 16;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
fn trace(arena: &[Visit], mut at: usize) -> Vec<String> {
    let mut out = vec![];
    loop {
        out.push(arena[at].state.node.clone());
        if let Some(p) = arena[at].previous {
            at = p;
        } else {
            break;
        }
    }
    out.reverse();
    out
}
fn key(value: &Value) -> String {
    let bytes = crate::wire::canonicalize_public_json(&value.to_string())
        .expect("owner JSON is canonicalizable");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Evaluates the named optional checkpoint scope without source parsing or execution.
/// All model inputs must belong to one exact analysis context. Missing evidence is
/// uncertainty. A supported violation witness survives an unrelated unknown route.
///
/// # Errors
/// Refuses invalid input bindings, serialization and canonical finding failures.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn compile_bounded_behavior(
    ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisModel,
    effects: &StateEffectAnalysisModel,
    flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
    contracts: &ResolvedBehaviorRealizationContracts,
    selection: &BehaviorSelection,
) -> Result<BoundedBehaviorEvaluation, BehavioralRealizationError> {
    let context = psm.program_context().digest();
    let psm_digest = psm
        .digest()
        .map_err(BehavioralRealizationError::Serialization)?;
    if [
        semantic.psm_digest(),
        effects.psm_digest(),
        flow.psm_digest(),
        environmental.psm_digest(),
    ]
    .iter()
    .any(|d| *d != psm_digest)
    {
        return Err(BehavioralRealizationError::InvalidBinding(
            "upstream PSM identities differ".into(),
        ));
    }
    let ccg_digest = ccg
        .digest()
        .map_err(BehavioralRealizationError::Serialization)?;
    let semantic_digest = semantic
        .digest()
        .map_err(BehavioralRealizationError::Serialization)?;
    let effects_digest = effects
        .digest()
        .map_err(BehavioralRealizationError::Serialization)?;
    let flow_digest = flow
        .digest()
        .map_err(BehavioralRealizationError::Serialization)?;
    if effects.semantic_analysis_digest() != semantic_digest
        || flow.semantic_analysis_digest() != semantic_digest
        || environmental.semantic_analysis_digest() != semantic_digest
        || flow.state_effect_digest() != effects_digest
        || environmental.state_effect_digest() != effects_digest
        || environmental.information_flow_digest() != flow_digest
        || intended.source_ccg_digest() != ccg_digest
        || !contracts.matches_admission(&ccg_digest, psm)
        || selection
            .modules
            .iter()
            .any(|m| !ccg.modules().contains_key(m))
    {
        return Err(BehavioralRealizationError::InvalidBinding(
            "inconsistent semantic, intent, contract or selected-scope inputs".into(),
        ));
    }
    let graph_within_limits = event_input_within_limits(psm);
    let inputs = json!({"intended_bfg":intended.digest().map_err(BehavioralRealizationError::Serialization)?,"psm":psm_digest,"semantic":semantic.digest().map_err(BehavioralRealizationError::Serialization)?,"state_effect":effects.digest().map_err(BehavioralRealizationError::Serialization)?,"information_flow":flow.digest().map_err(BehavioralRealizationError::Serialization)?,"environmental":environmental.digest().map_err(BehavioralRealizationError::Serialization)?,"realization_contracts":contracts.digest()});
    let selected_any = intended
        .flows()
        .iter()
        .any(|f| selection.project || selection.modules.contains(f.owner()));
    let (events, frames) = if selected_any && graph_within_limits {
        derive_event_model(psm, semantic, effects, flow, environmental, true)
    } else {
        (
            ImplementationEventModel {
                semantic_version: "1.0.0".into(),
                events: vec![],
                edges: vec![],
                unsupported_semantics: vec![],
            },
            BTreeMap::new(),
        )
    };
    let by_event = events
        .events
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = BTreeMap::<&str, Vec<(&str, RealizationCoverage)>>::new();
    for edge in &events.edges {
        if edge.derivation != "context_insensitive_static_return" {
            adjacency
                .entry(&edge.source)
                .or_default()
                .push((&edge.target, edge.coverage));
        }
    }
    let domains = semantic
        .summaries()
        .iter()
        .map(|s| (s.symbol(), s.inferred_output_domain()))
        .collect::<BTreeMap<_, _>>();
    let mut total_steps = 0usize;
    let mut result_bytes = 0usize;
    let mut claims = vec![];
    let mut findings = vec![];
    for intended_flow in intended.flows() {
        let feature = intended_flow.feature();
        let module = intended_flow.owner();
        let selected = selection.project || selection.modules.contains(module);
        let id = format!(
            "behavior_claim:v1:{}",
            key(&json!({"module":module,"feature":feature,"scope":"BOUNDED_CHECKPOINT_ORDER"}))
        );
        let instance = format!(
            "behavior_instance:v1:{}",
            key(&json!({"id":id,"context":context,"source":psm.source_identity(),"inputs":inputs}))
        );
        let mut reasons = BTreeSet::<String>::new();
        if selected
            && (!graph_within_limits
                || events
                    .unsupported_semantics
                    .iter()
                    .any(|s| s == "BOUNDED_EVENT_GRAPH_RESOURCE_LIMIT"))
        {
            reasons.insert("SOURCE_GRAPH_RESOURCE_LIMIT".into());
        }
        let mut mapping = BTreeMap::<String, Vec<String>>::new();
        let mut unsupported_anchors = BTreeSet::new();
        let feature_contracts = contracts
            .checkpoints()
            .iter()
            .filter(|c| c.feature() == feature)
            .collect::<Vec<_>>();
        for checkpoint in &feature_contracts {
            if checkpoint.anchors().len() != 1 {
                reasons.insert("ALTERNATIVE_ANCHOR_EXCLUSIVITY_UNPROVEN".into());
            }
            for anchor in checkpoint.anchors() {
                if anchor.symbol().is_some_and(|id| {
                    psm.symbols()
                        .iter()
                        .find(|s| s.id() == id)
                        .is_some_and(|s| s.qualifiers().is_async())
                }) {
                    unsupported_anchors.insert(checkpoint.checkpoint().to_owned());
                }

                if !matches!(
                    anchor,
                    BehaviorAnchor::SymbolEntry { .. } | BehaviorAnchor::SymbolReturn { .. }
                ) {
                    unsupported_anchors.insert(checkpoint.checkpoint().to_owned());
                }
                if let BehaviorAnchor::SymbolReturn {
                    symbol,
                    boolean: Some(value),
                } = anchor
                    && (semantic.coverage().function_contracts() > 0
                        || !matches!(domains.get(symbol.as_str()),Some(SemanticDomain::Boolean{values,..}) if values.len()==1&&values.contains(value)))
                {
                    unsupported_anchors.insert(checkpoint.checkpoint().to_owned());
                }
                if let Some(event) = resolve_anchor_event(anchor, &domains) {
                    mapping
                        .entry(event)
                        .or_default()
                        .push(checkpoint.checkpoint().into());
                } else {
                    unsupported_anchors.insert(checkpoint.checkpoint().into());
                }
            }
        }
        for names in mapping.values_mut() {
            names.sort();
            names.dedup();
            if names.len() > 1 {
                reasons.insert("AMBIGUOUS_SHARED_ANCHOR".into());
            }
        }
        mapping.retain(|_, names| {
            names.retain(|c| !unsupported_anchors.contains(c));
            !names.is_empty()
        });
        let trigger = intended_flow.trigger_checkpoint().unwrap_or("");
        let trigger_contract = feature_contracts.iter().find(|c| c.checkpoint() == trigger);
        let roots = trigger_contract
            .into_iter()
            .flat_map(|c| c.anchors())
            .filter_map(|a| match a {
                BehaviorAnchor::SymbolEntry { symbol } => Some(symbol.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if selected && roots.len() != 1 {
            reasons.insert("UNIQUE_SYMBOL_ENTRY_TRIGGER_REQUIRED".into());
        }
        if selected && !contracts.features().iter().any(|f| f == feature) {
            reasons.insert("MISSING_REALIZATION_CONTRACT".into());
        }
        if selected && intended_flow.state() != BehavioralModelingState::ModeledCoherent {
            reasons.insert("INCOHERENT_INTENDED_FLOW".into());
        }
        if selected && !unsupported_anchors.is_empty() {
            reasons.insert("ANCHOR_EVIDENCE_NOT_SUFFICIENT".into());
        }
        let intent_bytes = intended_flow
            .nodes()
            .iter()
            .fold(0usize, |n, v| n.saturating_add(v.checkpoint().len() + 96))
            .saturating_mul(intended_flow.nodes().len())
            .saturating_mul(2)
            .saturating_add(intended_flow.edges().iter().fold(0usize, |n, e| {
                n.saturating_add(2 * (e.source().len() + e.target().len() + 192))
            }));
        let scope_admitted = selected
            && reasons
                .iter()
                .all(|r| r == "ANCHOR_EVIDENCE_NOT_SUFFICIENT")
            && !unsupported_anchors.contains(trigger);
        let intent_admitted = scope_admitted && intent_bytes <= 8 * 1024 * 1024;
        if selected && intent_bytes > 8 * 1024 * 1024 {
            reasons.insert("INTENDED_GRAPH_RESOURCE_LIMIT".into());
        }
        let mut required = BTreeMap::<String, BTreeSet<String>>::new();
        let dominators = intended_flow
            .immediate_dominators()
            .iter()
            .map(|d| (d.checkpoint(), d.immediate()))
            .collect::<BTreeMap<_, _>>();
        for node in intended_flow.nodes().iter().filter(|_| intent_admitted) {
            let mut cursor = dominators.get(node.checkpoint()).copied().flatten();
            let set = required.entry(node.checkpoint().to_owned()).or_default();
            while let Some(d) = cursor {
                if !set.insert(d.to_owned()) {
                    break;
                }
                cursor = dominators.get(d).copied().flatten();
            }
        }
        let intended_edges = intended_flow
            .edges()
            .iter()
            .filter(|_| intent_admitted)
            .map(|e| (e.source().to_owned(), e.target().to_owned()))
            .collect::<BTreeSet<_>>();
        let terminals = intended_flow
            .terminal_checkpoints()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        let mut reached = BTreeSet::new();
        let mut counterexample = vec![];
        let mut violation: Option<String> = None;
        let mut violation_scope = Value::Null;
        let mut arena = Vec::<Visit>::new();
        let mut queue = VecDeque::new();
        let mut visited = BTreeSet::new();
        let mut bytes = 0usize;
        let mut steps = 0usize;
        let mut completed_paths = 0usize;
        let mut unknown = selected && !unsupported_anchors.is_empty();
        if intent_admitted {
            let root = roots.iter().next().ok_or_else(|| {
                BehavioralRealizationError::InvalidBinding("unique entry absent".into())
            })?;
            let start = State {
                node: event_id("symbol_entry", root),
                stack: vec![],
                seen: BTreeSet::new(),
                last: None,
                supported: true,
            };
            visited.insert(start.clone());
            arena.push(Visit {
                state: start,
                previous: None,
            });
            queue.push_back(0);
            while let Some(at) = queue.pop_front() {
                steps += 1;
                total_steps = total_steps.saturating_add(1);
                if steps > MAX_STEPS || total_steps > MAX_STEPS {
                    reasons.insert("RESOURCE_LIMIT".into());
                    unknown = true;
                    break;
                }
                let mut state = arena[at].state.clone();
                let Some(event) = by_event.get(state.node.as_str()) else {
                    unknown = true;
                    continue;
                };
                state.supported &= event.coverage == RealizationCoverage::Proven;
                if event.kind == "opaque_path" {
                    for reason in &event.provenance {
                        reasons.insert(format!("COVERAGE_GAP:{reason}"));
                    }
                }
                if event.kind == "call_site" && event.coverage != RealizationCoverage::Proven {
                    reasons.insert("UNKNOWN_CALL_RESOLUTION".into());
                }
                if matches!(event.kind.as_str(), "symbol_entry" | "symbol_return")
                    && event.coverage != RealizationCoverage::Proven
                {
                    reasons.insert("CONFIGURATION_PROVENANCE_UNCERTAIN".into());
                }

                let mut checkpoints = mapping.get(&state.node).cloned().unwrap_or_default();
                if event.kind == "symbol_return"
                    && let Some(symbol) = event.responsible_symbol()
                    && let Some(SemanticDomain::Boolean { values, .. }) = domains.get(symbol)
                    && values.len() == 1
                {
                    let boolean =
                        event_id("symbol_return_boolean", &format!("{symbol}:{}", values[0]));
                    checkpoints.extend(mapping.get(&boolean).into_iter().flatten().cloned());
                }
                checkpoints.sort();
                checkpoints.dedup();
                if checkpoints.len() > 1 {
                    unknown = true;
                    reasons.insert("AMBIGUOUS_SHARED_ANCHOR".into());
                }
                for checkpoint in checkpoints {
                    reached.insert(checkpoint.clone());
                    if required.get(&checkpoint).is_some_and(|ds| {
                        ds.difference(&state.seen)
                            .any(|d| !unsupported_anchors.contains(d))
                    }) && checkpoint != trigger
                    {
                        if state.supported {
                            violation = Some("REQUIRED_DOMINATOR_BYPASSED".into());
                            violation_scope = json!({"reached":checkpoint,"missing_dominators":required.get(&checkpoint).into_iter().flatten().filter(|d|!state.seen.contains(*d)&&!unsupported_anchors.contains(*d)).collect::<Vec<_>>()});
                            counterexample = trace(&arena, at);
                            break;
                        }
                        unknown = true;
                    }
                    if let Some(last) = &state.last {
                        if unsupported_anchors.is_empty()
                            && !intended_edges.contains(&(last.clone(), checkpoint.clone()))
                        {
                            if state.supported {
                                violation = Some("UNDECLARED_CHECKPOINT_TRANSITION".into());
                                violation_scope = json!({"source":last,"target":checkpoint});
                                counterexample = trace(&arena, at);
                                break;
                            }
                            unknown = true;
                        }
                        observed.insert((last.clone(), checkpoint.clone()));
                    }
                    state.seen.insert(checkpoint.clone());
                    state.last = Some(checkpoint);
                }
                if violation.is_some() {
                    break;
                }
                let is_return = event.kind == "symbol_return";
                let mut next = vec![];
                if is_return {
                    if let Some((callee, after)) = state.stack.pop() {
                        if event.responsible_symbol() != Some(callee.as_str()) {
                            unknown = true;
                            continue;
                        }
                        next.push((after, RealizationCoverage::Proven));
                    } else {
                        completed_paths += 1;
                        if !state.last.as_ref().is_some_and(|c| terminals.contains(c)) {
                            if state.supported && unsupported_anchors.is_disjoint(&terminals) {
                                violation = Some("UNDECLARED_TERMINAL".into());
                                violation_scope = json!({"last_checkpoint":state.last});
                                counterexample = trace(&arena, at);
                                break;
                            }
                            unknown = true;
                        }
                        if !state.supported {
                            unknown = true;
                        }
                        continue;
                    }
                } else if let Some((callee, after)) = frames.get(&state.node) {
                    if state.stack.len() >= MAX_FRAMES
                        || state.stack.iter().any(|(s, _)| s == callee)
                        || roots.contains(callee)
                    {
                        unknown = true;
                        reasons.insert("RECURSION_OR_CONTEXT_LIMIT".into());
                        continue;
                    }
                    state.stack.push((callee.clone(), after.clone()));
                    next.push((
                        event_id("symbol_entry", callee),
                        RealizationCoverage::Proven,
                    ));
                } else {
                    next.extend(
                        adjacency
                            .get(state.node.as_str())
                            .into_iter()
                            .flatten()
                            .map(|(n, c)| (n.to_string(), *c)),
                    );
                }
                if next.is_empty() {
                    unknown = true;
                    reasons.insert("INCOMPLETE_CONTROL_PATH".into());
                }
                for (node, coverage) in next {
                    let mut successor = state.clone();
                    successor.node = node;
                    successor.supported &= coverage == RealizationCoverage::Proven;
                    if !successor.supported {
                        unknown = true;
                    }
                    let charge = 512
                        + successor.node.len()
                        + successor
                            .stack
                            .iter()
                            .map(|(s, a)| s.len() + a.len() + 64)
                            .sum::<usize>()
                        + successor.seen.iter().map(|s| s.len() + 48).sum::<usize>();
                    if !visited.contains(&successor) {
                        bytes = bytes.saturating_add(charge.saturating_mul(2));
                        if visited.len() >= MAX_STATES || bytes > MAX_STATE_BYTES {
                            unknown = true;
                            reasons.insert("RESOURCE_LIMIT".into());
                            queue.clear();
                            break;
                        }
                        visited.insert(successor.clone());
                        let index = arena.len();
                        arena.push(Visit {
                            state: successor,
                            previous: Some(at),
                        });
                        queue.push_back(index);
                    }
                }
            }
            if unknown {
                reasons.insert("INCOMPLETE_PATH_COVERAGE".into());
            }
            if !unknown && violation.is_none() {
                if completed_paths == 0 {
                    reasons.insert("NO_SUPPORTED_TERMINAL_PATH".into());
                } else if intended_flow
                    .nodes()
                    .iter()
                    .any(|n| !reached.contains(n.checkpoint()))
                {
                    violation = Some("REQUIRED_CHECKPOINT_UNREACHABLE".into());
                    violation_scope = json!({"unreachable_checkpoints":intended_flow.nodes().iter().filter(|n|!reached.contains(n.checkpoint())).map(crate::behavioral_semantics::BfgNode::checkpoint).collect::<Vec<_>>()});
                } else if !intended_edges.is_subset(&observed) {
                    violation = Some("REQUIRED_TRANSITION_UNREACHABLE".into());
                    violation_scope = json!({"unreachable_transitions":intended_edges.difference(&observed).collect::<Vec<_>>()});
                }
            }
        }
        if counterexample.len() > 4096 {
            counterexample.clear();
            violation = None;
            violation_scope = Value::Null;
            reasons.insert("COUNTEREXAMPLE_RESOURCE_LIMIT".into());
        }
        let verdict = if !selected {
            "NOT_APPLICABLE"
        } else if violation.is_some() {
            "SUPPORTED_VIOLATION"
        } else if reasons.is_empty() {
            "NO_SUPPORTED_VIOLATION"
        } else {
            "NOT_EVALUABLE"
        };
        if !selected {
            reasons.insert("BEHAVIOR_PROFILE_NOT_SELECTED_FOR_SCOPE".into());
        }
        if let Some(code) = &violation {
            reasons.insert(code.clone());
        }
        let mut claim_findings = vec![];
        if let Some(code) = &violation {
            let mut finding=CanonicalFinding::failure(RuleFindingDefinition::new(if code=="REQUIRED_DOMINATOR_BYPASSED"{BEHAVIOR_BYPASS_RULE_ID}else{BEHAVIOR_REALIZATION_RULE_ID},1,FindingCategory::Behavior,if code=="REQUIRED_DOMINATOR_BYPASSED"{BYPASS_REMEDIATION}else{REALIZATION_REMEDIATION}).map_err(BehavioralRealizationError::Finding)?,FindingOccurrence::new(vec![feature.into()],FindingLocation::none(),format!("Feature {feature}: {code}; supported static checkpoint scope, not authorization or runtime execution proof")).map_err(BehavioralRealizationError::Finding)?.with_discriminator(format!("bounded-checkpoint:{code}:{}",key(&violation_scope))).map_err(BehavioralRealizationError::Finding)?,EvaluatorProvenance::new("fortress-core/bounded-behavior","1.0.0").map_err(BehavioralRealizationError::Finding)?,ccg.standard_edition()).map_err(BehavioralRealizationError::Finding)?;
            let advisory = roots
                .iter()
                .chain(counterexample.iter().filter_map(|node| {
                    by_event
                        .get(node.as_str())
                        .and_then(|e| e.responsible_symbol.as_ref())
                }))
                .any(|id| {
                    psm.symbols()
                        .iter()
                        .find(|s| s.id() == id)
                        .is_some_and(|s| {
                            s.execution_provenance()
                                != crate::program_semantics::ExecutionProvenance::ProductionCapable
                        })
                });
            if advisory {
                finding = finding
                    .with_advisory_enforcement("NON_PRODUCTION_OR_UNKNOWN_BEHAVIOR_PROVENANCE")
                    .map_err(BehavioralRealizationError::Finding)?;
            }
            claim_findings.push(finding.finding_id().to_owned());
            findings.push(finding);
        }
        let mut defeaters = vec![];
        if verdict == "NOT_EVALUABLE" || unknown {
            for reason in reasons
                .iter()
                .filter(|r| violation.as_deref() != Some(r.as_str()))
            {
                let d = Defeater::new(
                    DefeaterKind::PartialSemanticCoverage,
                    if verdict == "NOT_EVALUABLE" {
                        DefeaterStrength::Defeating
                    } else {
                        DefeaterStrength::Limiting
                    },
                    "fortress-bounded-behavior",
                    "1.0.0",
                    DefeaterScope::new(DefeaterScopeKind::SemanticClaim, &id)
                        .map_err(|e| BehavioralRealizationError::InvalidBinding(e.to_string()))?,
                    reason,
                    BTreeMap::new(),
                    vec![
                        psm_digest.clone(),
                        intended
                            .digest()
                            .map_err(BehavioralRealizationError::Serialization)?,
                    ],
                    DefeaterRetirementCondition::AnalyserSupportEstablished,
                )
                .map_err(|e| BehavioralRealizationError::InvalidBinding(e.to_string()))?;
                defeaters.push(
                    serde_json::to_value(d).map_err(BehavioralRealizationError::Serialization)?,
                );
            }
        }
        defeaters.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let path=counterexample.iter().map(|node|{let e=by_event.get(node.as_str());let symbol=e.and_then(|e|e.responsible_symbol());let name=symbol.and_then(|s|psm.symbols().iter().find(|p|p.id()==s)).map(crate::program_semantics::ExecutableSymbol::qualified_name);json!({"event_ref":node,"kind":e.map(|e|e.kind()),"symbol_ref":symbol,"qualified_name":name})}).collect::<Vec<_>>();
        let (flow_claims, flow_assumptions) = flow.operation_provenance_for_module(module);
        claims.push(json!({"$schema":BEHAVIOR_CLAIM_SCHEMA,"schema_version":1,"id":id,"instance_ref":instance,"module_id":module,"feature":feature,"context_ref":context,"source_ref":psm.source_identity(),"inputs":inputs,"profile":BEHAVIOR_PROFILE_ID,"verdict":verdict,"proposition":"Bounded static checkpoint ordering, required transitions and terminal containment","rule_id":BEHAVIOR_REALIZATION_RULE_ID,"reason_codes":reasons,"assumptions":[],"coverage":{"complete":selected&&verdict!="NOT_EVALUABLE"&&violation.is_none(),"states":arena.len(),"steps":steps,"completed_paths":completed_paths,"reached_checkpoints":reached,"unsupported_anchors":unsupported_anchors,"max_states":MAX_STATES,"max_steps":MAX_STEPS,"max_frames":MAX_FRAMES,"state_bytes_limit":MAX_STATE_BYTES},"counterexample":path,"violation_scope":violation_scope,"flow_provenance":{"analysis_ref":inputs["information_flow"],"claim_refs":flow_claims,"assumptions":flow_assumptions,"interpretation":"CONDITIONAL_UPSTREAM_ONLY"},"findings":claim_findings,"defeaters":defeaters.iter().filter_map(|d|d["id"].as_str()).collect::<Vec<_>>(),"defeater_records":defeaters,"execution_evidence":"NOT_SUPPLIED","authorization":"NOT_ESTABLISHED","limitations":["Static source control paths only; no execution or authorization-implementation proof.","Unknown guards, loops, recursion, aliases, concurrency and unsupported language semantics prevent negative claims.","State/effect summaries, declared FLOW transformations and environmental outcomes require independently sufficient path evidence; declarations alone do not establish checkpoint execution.","Natural-language decision conditions are not interpreted."]}));
        result_bytes =
            result_bytes.saturating_add(claims.last().map_or(0, |c| c.to_string().len()));
        if result_bytes > 32 * 1024 * 1024 {
            return Err(BehavioralRealizationError::InvalidBinding(
                "BEHAVIOR_OUTPUT_RESOURCE_LIMIT".into(),
            ));
        }
    }
    for state in intended
        .feature_states()
        .iter()
        .filter(|s| s.state() == BehavioralModelingState::Unmodeled)
    {
        let feature = state.feature();
        let module = state.owner();
        let selected = selection.project || selection.modules.contains(module);
        let id = format!(
            "behavior_claim:v1:{}",
            key(&json!({"module":module,"feature":feature,"scope":"BOUNDED_CHECKPOINT_ORDER"}))
        );
        let instance = format!(
            "behavior_instance:v1:{}",
            key(&json!({"id":id,"context":context,"source":psm.source_identity(),"inputs":inputs}))
        );
        let records = if selected {
            vec![
                serde_json::to_value(
                    Defeater::new(
                        DefeaterKind::PartialSemanticCoverage,
                        DefeaterStrength::Defeating,
                        "fortress-bounded-behavior",
                        "1.0.0",
                        DefeaterScope::new(DefeaterScopeKind::SemanticClaim, &id).map_err(|e| {
                            BehavioralRealizationError::InvalidBinding(e.to_string())
                        })?,
                        "UNMODELED_FEATURE",
                        BTreeMap::new(),
                        vec![psm_digest.clone()],
                        DefeaterRetirementCondition::AnalyserSupportEstablished,
                    )
                    .map_err(|e| BehavioralRealizationError::InvalidBinding(e.to_string()))?,
                )
                .map_err(BehavioralRealizationError::Serialization)?,
            ]
        } else {
            vec![]
        };
        let (flow_claims, flow_assumptions) = flow.operation_provenance_for_module(module);
        claims.push(json!({"$schema":BEHAVIOR_CLAIM_SCHEMA,"schema_version":1,"id":id,"instance_ref":instance,"module_id":module,"feature":feature,"context_ref":context,"source_ref":psm.source_identity(),"inputs":inputs,"profile":BEHAVIOR_PROFILE_ID,"verdict":if selected{"NOT_EVALUABLE"}else{"NOT_APPLICABLE"},"proposition":"Bounded static checkpoint ordering, required transitions and terminal containment","rule_id":BEHAVIOR_REALIZATION_RULE_ID,"reason_codes":[if selected{"UNMODELED_FEATURE"}else{"BEHAVIOR_PROFILE_NOT_SELECTED_FOR_SCOPE"}],"assumptions":[],"coverage":{"complete":false,"states":0,"steps":0,"completed_paths":0,"reached_checkpoints":[],"unsupported_anchors":[],"max_states":MAX_STATES,"max_steps":MAX_STEPS,"max_frames":MAX_FRAMES,"state_bytes_limit":MAX_STATE_BYTES},"counterexample":[],"violation_scope":null,"flow_provenance":{"analysis_ref":inputs["information_flow"],"claim_refs":flow_claims,"assumptions":flow_assumptions,"interpretation":"CONDITIONAL_UPSTREAM_ONLY"},"findings":[],"defeaters":records.iter().map(|d|d["id"].clone()).collect::<Vec<_>>(),"defeater_records":records,"execution_evidence":"NOT_SUPPLIED","authorization":"NOT_ESTABLISHED","limitations":["Unmodeled intent cannot establish checkpoint execution or bypass absence."]}));
        result_bytes =
            result_bytes.saturating_add(claims.last().map_or(0, |c| c.to_string().len()));
        if result_bytes > 32 * 1024 * 1024 {
            return Err(BehavioralRealizationError::InvalidBinding(
                "BEHAVIOR_OUTPUT_RESOURCE_LIMIT".into(),
            ));
        }
    }
    claims.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    findings.sort();
    Ok(BoundedBehaviorEvaluation {
        schema: "urn:fortress:schema:v1:bounded-behavior-analysis".into(),
        schema_version: 1,
        semantic_version: "1.0.0".into(),
        context_ref: context,
        claims,
        findings,
    })
}

/// Evaluates legacy observations and, only when selected, bounded checkpoint claims.
/// # Errors
/// Rejects malformed or mismatched immutable inputs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_behavioral_realization_with_selection(
    ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    semantic: &SemanticAnalysisModel,
    effects: &StateEffectAnalysisModel,
    flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
    contracts: &ResolvedBehaviorRealizationContracts,
    edition: &str,
    selection: &BehaviorSelection,
) -> Result<BehavioralRealizationEvaluation, BehavioralRealizationError> {
    let mut evaluation = evaluate_behavioral_realization(
        ccg,
        intended,
        psm,
        semantic,
        effects,
        flow,
        environmental,
        contracts,
        edition,
    )?;
    if selection.project || !selection.modules.is_empty() {
        let bounded = compile_bounded_behavior(
            ccg,
            intended,
            psm,
            semantic,
            effects,
            flow,
            environmental,
            contracts,
            selection,
        )?;
        for finding in bounded.findings() {
            if finding.rule_id() == BEHAVIOR_BYPASS_RULE_ID {
                evaluation.bypass_findings.push(finding.clone());
            } else {
                evaluation.realization_findings.push(finding.clone());
            }
        }
        evaluation.bypass_findings.sort();
        evaluation.bypass_findings.dedup();
        evaluation.realization_findings.sort();
        evaluation.realization_findings.dedup();
        evaluation.graph.schema = "urn:fortress:schema:v2:realized-behavioral-flow-graph".into();
        evaluation.graph.schema_version = 2;
        evaluation.graph.semantic_version = "2.0.0".into();
        evaluation.graph.bounded_analysis = Some(bounded);
    }
    Ok(evaluation)
}

/// Validates a serialized owner conclusion without interpreting source or intent.
/// # Errors
/// Rejects substituted identities, inconsistent truth, missing evidence and versions.
pub fn validate_behavior_claim_projection(
    value: &Value,
    context: &str,
) -> Result<(), BehavioralRealizationError> {
    validate_claim_descriptor(value)?;
    let fail =
        || BehavioralRealizationError::InvalidBinding("INVALID_BEHAVIOR_CLAIM_PROJECTION".into());
    if value["$schema"] != BEHAVIOR_CLAIM_SCHEMA
        || value["schema_version"].as_u64() != Some(1)
        || value["context_ref"] != context
        || value["profile"] != BEHAVIOR_PROFILE_ID
        || value["rule_id"] != BEHAVIOR_REALIZATION_RULE_ID
        || value["execution_evidence"] != "NOT_SUPPLIED"
        || value["authorization"] != "NOT_ESTABLISHED"
    {
        return Err(fail());
    }
    let expected = format!(
        "behavior_claim:v1:{}",
        key(
            &json!({"module":value["module_id"],"feature":value["feature"],"scope":"BOUNDED_CHECKPOINT_ORDER"})
        )
    );
    let instance = format!(
        "behavior_instance:v1:{}",
        key(
            &json!({"id":expected,"context":context,"source":value["source_ref"],"inputs":value["inputs"]})
        )
    );
    if value["id"] != expected || value["instance_ref"] != instance {
        return Err(fail());
    }
    for field in ["module_id", "feature", "source_ref"] {
        if value[field].as_str().is_none_or(str::is_empty) {
            return Err(fail());
        }
    }
    for field in ["findings", "defeaters", "reason_codes", "assumptions"] {
        let items = value[field].as_array().ok_or_else(fail)?;
        if items.iter().any(|v| v.as_str().is_none_or(str::is_empty))
            || items.windows(2).any(|v| v[0].as_str() >= v[1].as_str())
        {
            return Err(fail());
        }
    }
    let records = value["defeater_records"].as_array().ok_or_else(fail)?;
    let ids = records.iter().map(|v| v["id"].clone()).collect::<Vec<_>>();
    if value["defeaters"] != json!(ids) {
        return Err(fail());
    }
    let nonempty = |f: &str| value[f].as_array().is_some_and(|v| !v.is_empty());
    match value["verdict"].as_str() {
        Some("NO_SUPPORTED_VIOLATION")
            if value["coverage"]["complete"] == true
                && value["coverage"]["states"].as_u64().is_some_and(|n| n > 0)
                && value["coverage"]["completed_paths"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
                && !nonempty("defeaters")
                && !nonempty("findings")
                && !nonempty("reason_codes") =>
        {
            Ok(())
        }
        Some("SUPPORTED_VIOLATION") if nonempty("findings") && nonempty("reason_codes") => Ok(()),
        Some("NOT_EVALUABLE")
            if nonempty("defeaters")
                && nonempty("reason_codes")
                && value["coverage"]["complete"] == false =>
        {
            Ok(())
        }
        Some("NOT_APPLICABLE")
            if !nonempty("findings") && value["coverage"]["complete"] == false =>
        {
            Ok(())
        }
        _ => Err(fail()),
    }
}

/// Readable, unapplied entry/return checkpoint bindings for one authored Feature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAuthorParameters {
    /// Existing authored Feature identity; validated when the proposal is admitted.
    pub feature: String,
    /// Checkpoint identity to unique qualified symbol name or canonical identity.
    pub checkpoints: BTreeMap<String, String>,
    /// Checkpoints bound to return instead of entry.
    #[serde(default, deserialize_with = "unique_returns")]
    pub returns: BTreeSet<String>,
}
fn unique_returns<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(deserializer)?;
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value) {
            return Err(serde::de::Error::custom("duplicate return checkpoint"));
        }
    }
    Ok(result)
}
impl BehaviorAuthorParameters {
    /// Validates bounded proposal shape before any explicit source preparation.
    /// # Errors
    /// Rejects empty identities, excessive selectors and unknown return bindings.
    pub fn validate_shape(&self) -> Result<(), BehavioralRealizationError> {
        let identity = |v: &str| {
            !v.is_empty()
                && v.len() <= 1024
                && v.bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-')
        };
        if !identity(&self.feature)
            || self.checkpoints.is_empty()
            || self.checkpoints.len() > 4096
            || self
                .checkpoints
                .iter()
                .any(|(c, s)| !identity(c) || s.is_empty() || s.len() > 1024)
            || !self
                .returns
                .iter()
                .all(|c| self.checkpoints.contains_key(c))
        {
            return Err(BehavioralRealizationError::InvalidBinding(
                "invalid or excessive readable checkpoint proposal".into(),
            ));
        }
        Ok(())
    }
}
/// Returns the public exact-context authoring schema.
#[must_use]
pub fn behavior_realization_contract_schema() -> &'static str {
    include_str!("../_data/realization_contract_schema_v3.json")
}
/// Previews readable bindings using an already loaded PSM; never writes authority.
/// # Errors
/// Rejects ambiguous names, malformed identities and bounded-input violations.
pub fn preview_behavior_contract(
    psm: &ProgramSemanticModel,
    parameters: &BehaviorAuthorParameters,
) -> Result<Value, BehavioralRealizationError> {
    parameters.validate_shape()?;
    let fail = |detail: &str| BehavioralRealizationError::InvalidBinding(detail.into());
    if parameters.feature.is_empty()
        || parameters.feature.len() > 1024
        || parameters.checkpoints.is_empty()
        || parameters.checkpoints.len() > 4096
        || !parameters
            .returns
            .iter()
            .all(|c| parameters.checkpoints.contains_key(c))
    {
        return Err(fail("invalid or excessive checkpoint proposal"));
    }
    let references = psm.symbol_reference_index();
    let mut checkpoints = vec![];
    let mut resolutions = vec![];
    for (checkpoint, reference) in &parameters.checkpoints {
        if checkpoint.is_empty() || checkpoint.len() > 1024 || reference.len() > 1024 {
            return Err(fail("checkpoint selector exceeds bounded vocabulary"));
        }
        let resolved = references
            .resolve_readable(reference)
            .map_err(|e| fail(&e.to_string()))?
            .ok_or_else(|| fail("unknown checkpoint selector"))?;
        checkpoints.push(json!({"checkpoint":checkpoint,"anchors":[{"kind":if parameters.returns.contains(checkpoint){"symbol_return"}else{"symbol_entry"},"symbol":reference}]}));
        resolutions.push(json!({"checkpoint":checkpoint,"authored_selector":reference,"symbol_ref":resolved.symbol().id(),"qualified_name":resolved.symbol().qualified_name()}));
    }
    let document = json!({"$schema":BOUNDED_BEHAVIOR_CONTRACT_SCHEMA,"schema_version":3,"context_ref":psm.program_context().digest(),"features":[{"feature":parameters.feature,"checkpoints":checkpoints}]});
    let canonical = canonicalize_behavior_realization_contract_json(&document.to_string())
        .map_err(|e| fail(&e.to_string()))?;
    Ok(
        json!({"disposition":"PROPOSED","accepted_authority":false,"context_ref":psm.program_context().digest(),"document":serde_json::from_str::<Value>(&canonical).map_err(BehavioralRealizationError::Serialization)?,"canonical_preview":canonical,"resolutions":resolutions,"verification_binding_schema":"urn:fortress:schema:v1:verification-bindings","limitations":["Intent membership, Module ownership and complete checkpoint coverage require authoritative contract admission.","Entry or return observation is not proof that authorization or a declared transformation is implemented correctly.","Requirement-to-test bindings and actual execution evidence remain separately admitted EVIDENCE inputs."]}),
    )
}

fn validate_claim_descriptor(value: &Value) -> Result<(), BehavioralRealizationError> {
    let fail =
        || BehavioralRealizationError::InvalidBinding("MALFORMED_BEHAVIOR_CLAIM_DESCRIPTOR".into());
    let fields="$schema schema_version id instance_ref module_id feature context_ref source_ref inputs profile verdict proposition rule_id reason_codes assumptions coverage counterexample violation_scope flow_provenance findings defeaters defeater_records execution_evidence authorization limitations".split_whitespace().collect::<Vec<_>>();
    let object = value.as_object().ok_or_else(fail)?;
    if object.len() != fields.len() || fields.iter().any(|f| !object.contains_key(*f)) {
        return Err(fail());
    }
    let digest = |v: &Value| {
        v.as_str().is_some_and(|s| {
            s.strip_prefix("sha256:").is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    };
    if !digest(&value["context_ref"]) || !digest(&value["source_ref"]) {
        return Err(fail());
    }
    let inputs = value["inputs"].as_object().ok_or_else(fail)?;
    let required = [
        "intended_bfg",
        "psm",
        "semantic",
        "state_effect",
        "information_flow",
        "environmental",
        "realization_contracts",
    ];
    if inputs.len() != required.len() || required.iter().any(|f| !digest(&value["inputs"][f])) {
        return Err(fail());
    }
    validate_claim_coverage(&value["coverage"])?;
    let path = value["counterexample"].as_array().ok_or_else(fail)?;
    if path.len() > 4096
        || path
            .iter()
            .any(|v| v["event_ref"].as_str().is_none_or(str::is_empty))
    {
        return Err(fail());
    }
    let flow = value["flow_provenance"].as_object().ok_or_else(fail)?;
    if flow.len() != 4
        || flow.get("analysis_ref") != inputs.get("information_flow")
        || flow.get("interpretation").and_then(Value::as_str) != Some("CONDITIONAL_UPSTREAM_ONLY")
    {
        return Err(fail());
    }
    for field in ["claim_refs", "assumptions"] {
        let items = value["flow_provenance"][field]
            .as_array()
            .ok_or_else(fail)?;
        if items.iter().any(|i| i.as_str().is_none_or(str::is_empty))
            || items.windows(2).any(|p| p[0].as_str() >= p[1].as_str())
        {
            return Err(fail());
        }
    }
    if value["verdict"] == "SUPPORTED_VIOLATION" {
        if !value["violation_scope"].is_object() {
            return Err(fail());
        }
    } else if !value["violation_scope"].is_null() || !path.is_empty() {
        return Err(fail());
    }
    Ok(())
}

fn validate_claim_coverage(value: &Value) -> Result<(), BehavioralRealizationError> {
    let fail = || BehavioralRealizationError::InvalidBinding("MALFORMED_BEHAVIOR_COVERAGE".into());
    let coverage = value.as_object().ok_or_else(fail)?;
    let required = [
        "complete",
        "states",
        "steps",
        "completed_paths",
        "reached_checkpoints",
        "unsupported_anchors",
        "max_states",
        "max_steps",
        "max_frames",
        "state_bytes_limit",
    ];
    if coverage.len() != required.len()
        || required.iter().any(|f| !coverage.contains_key(*f))
        || coverage["complete"].as_bool().is_none()
    {
        return Err(fail());
    }
    for (field, maximum) in [
        ("states", MAX_STATES),
        ("steps", MAX_STEPS + 1),
        ("completed_paths", MAX_STATES),
    ] {
        if coverage[field].as_u64().is_none_or(|n| n > maximum as u64) {
            return Err(fail());
        }
    }
    for (field, expected) in [
        ("max_states", MAX_STATES),
        ("max_steps", MAX_STEPS),
        ("max_frames", MAX_FRAMES),
        ("state_bytes_limit", MAX_STATE_BYTES),
    ] {
        if coverage[field].as_u64() != Some(expected as u64) {
            return Err(fail());
        }
    }
    for field in ["reached_checkpoints", "unsupported_anchors"] {
        let items = coverage[field].as_array().ok_or_else(fail)?;
        if items.iter().any(|i| i.as_str().is_none_or(str::is_empty))
            || items.windows(2).any(|p| p[0].as_str() >= p[1].as_str())
        {
            return Err(fail());
        }
    }
    Ok(())
}

fn event_input_within_limits(psm: &ProgramSemanticModel) -> bool {
    if psm.symbols().len() > 10_000 || psm.calls().len() > 10_000 {
        return false;
    }
    let mut bytes = psm.symbols().len().saturating_mul(2048);
    for call in psm.calls() {
        for evidence in call.evidence() {
            bytes = bytes.saturating_add(
                2 * (1024
                    + call.caller().len()
                    + call.callee().map_or(0, str::len)
                    + evidence.reference().len()
                    + evidence.provenance().path().len()),
            );
            if bytes > 48 * 1024 * 1024 {
                return false;
            }
        }
    }
    true
}
