//! Operation declarations lower to the existing finite-facet propagation algebra.
use super::{
    FacetDirection, FlowAuthority, FlowNode, INFORMATION_FLOW_ANALYSIS_VERSION,
    INFORMATION_FLOW_ANALYZER_ID, INFORMATION_FLOW_POLICY_SCHEMA,
    INFORMATION_FLOW_POLICY_SCHEMA_VERSION, InformationFacet, InformationFlowAnalysisError,
    InformationFlowPolicy, InformationFlowPolicySource, InformationFlowTransformKind,
    InformationFlowViolation, LabelFact, ProgramProvenance, ProgramSemanticModel,
    UNSUPPORTED_SEMANTICS, canonicalize_information_flow_policy_json, finding, flow_edges,
    information_flow_violation, insert_fact, load_information_flow_policy,
};
use crate::finding::{
    Defeater, DefeaterKind, DefeaterRetirementCondition, DefeaterScope, DefeaterScopeKind,
    DefeaterStrength,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Explicitly selected bounded declared-boundary profile identity.
pub const FLOW_PROFILE_ID: &str = "GOV-FORTRESS-DECLARED-FLOW";

/// Portable per-sink claim schema, independent of internal Rust types.
pub const FLOW_CLAIM_SCHEMA: &str = "urn:fortress:schema:v1:information-flow-claim";

/// Resolved profile scope supplied by the existing profile-composition owner.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSelection {
    /// Select all declared sinks in the governed project.
    pub project: bool,
    /// Otherwise select only sinks owned by these canonical Module identities.
    pub modules: BTreeSet<String>,
}

impl FlowSelection {
    pub(super) fn applicable(&self, psm: &ProgramSemanticModel, binding: &BoundOperation) -> bool {
        self.project
            || psm.symbols().iter().any(|symbol| {
                self.modules.contains(symbol.fortress_module())
                    && (symbol.id() == binding.node_symbol
                        || psm.calls().iter().any(|call| {
                            call.caller() == symbol.id()
                                && call
                                    .evidence()
                                    .iter()
                                    .any(|site| site.operation_site_id() == binding.node_symbol)
                        }))
            })
    }
}

/// Readable source/sink authoring proposal; slots use bounded return/parameter defaults.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowAuthorParameters {
    /// Exact qualified local name, canonical symbol ID or external operation ID.
    pub source: String,
    /// Exact qualified local name, canonical symbol ID or external operation ID.
    pub sink: String,
    /// Existing finite facet identity.
    pub facet: String,
    /// Explicit source classification; no default environmental secrecy.
    pub level: String,
    /// Maximum confidentiality or minimum integrity accepted at the sink.
    pub bound: String,
    /// Zero-based sink parameter position, excluding a method receiver.
    #[serde(default)]
    pub parameter: u16,
}

/// Previews a canonical root policy using an already-loaded immutable PSM.
/// No evaluation, file write, trusted authority acceptance or repair occurs.
///
/// # Errors
/// Rejects stale, unsupported, ambiguous or contradictory declarations.
pub fn preview_operation_policy(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    parameters: &FlowAuthorParameters,
) -> Result<serde_json::Value, InformationFlowAnalysisError> {
    let mut sources = policy.sources.clone();
    let mut sinks = policy.sinks.clone();
    let selector = |reference: &str| OperationSelector {
        reference: reference.into(),
        context_digest: psm.program_context().digest(),
    };
    sources.push(OperationSource {
        operation_selector: selector(&parameters.source),
        output_slot: Slot::Return,
        facet: parameters.facet.clone(),
        level: parameters.level.clone(),
    });
    sinks.push(OperationSink {
        operation_selector: selector(&parameters.sink),
        input_slot: Slot::Parameter {
            position: parameters.parameter,
        },
        facet: parameters.facet.clone(),
        bound: parameters.bound.clone(),
    });
    sources.sort();
    sources.dedup();
    sinks.sort();
    sinks.dedup();
    let document = serde_json::json!({"$schema":INFORMATION_FLOW_POLICY_SCHEMA,"schema_version":INFORMATION_FLOW_POLICY_SCHEMA_VERSION,"facets":policy.facets().collect::<Vec<_>>(),"sources":sources,"sinks":sinks,"transforms":policy.transforms});
    let preview = canonicalize_information_flow_policy_json("proposal", &document.to_string())
        .map_err(|e| InformationFlowAnalysisError::OperationBinding(e.to_string()))?;
    let proposed = load_information_flow_policy(vec![InformationFlowPolicySource::new(
        "__fortress/governance/information_flow_policy.json",
        &preview,
    )])
    .map_err(|e| InformationFlowAnalysisError::OperationBinding(e.to_string()))?;
    seed(
        psm,
        &proposed,
        &mut BTreeMap::new(),
        &mut BTreeSet::new(),
        false,
    )?;
    let profile_reference =
        crate::profile::installed_profile_reference(FLOW_PROFILE_ID, "1.0.0")
            .map_err(|e| InformationFlowAnalysisError::OperationBinding(e.to_string()))?;
    Ok(
        serde_json::json!({"classification":"PROPOSED","acceptance":"UNAPPROVED","profile":FLOW_PROFILE_ID,"profile_reference":profile_reference,"context_ref":psm.program_context().digest(),"psm_digest":psm.digest()?,"source_identity":psm.source_identity(),"preimage_digest":policy.digest(),"schema_ref":INFORMATION_FLOW_POLICY_SCHEMA,"canonical_policy_preview":preview,"limitations":["Root policy proposal only; distributed Function Contracts retain their own authority.","Classification and transformation declarations do not prove implementation or test execution.","Explicit-data flow only; unsupported aliases, implicit flows, callbacks, concurrency and incomplete contexts remain uncertain."]}),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationSelector {
    reference: String,
    context_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Slot {
    Return,
    Parameter { position: u16 },
    Field { owner: String, field: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationSource {
    operation_selector: OperationSelector,
    output_slot: Slot,
    facet: String,
    level: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationSink {
    operation_selector: OperationSelector,
    input_slot: Slot,
    facet: String,
    bound: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransferSlots {
    input: Slot,
    output: Slot,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClassificationRule {
    kind: InformationFlowTransformKind,
    facet: String,
    from: String,
    to: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustBasis {
    authority_ref: String,
    rationale: String,
    state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationTransform {
    operation_selector: OperationSelector,
    input_to_output: TransferSlots,
    classification_rule: ClassificationRule,
    trust_basis: TrustBasis,
}

fn ordered<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn source_name(names: &BTreeMap<String, String>, origin: &str) -> String {
    if let Some((id, name)) = names.range(..=origin.to_owned()).next_back()
        && (origin == id
            || origin
                .strip_prefix(id)
                .is_some_and(|suffix| suffix.starts_with(':')))
    {
        return name.clone();
    }
    format!("UNAVAILABLE:{origin}")
}

pub(super) fn validate_declarations(
    facets: &[InformationFacet],
    sources: &[OperationSource],
    sinks: &[OperationSink],
    transforms: &[OperationTransform],
) -> Result<(), String> {
    if sources.len() + sinks.len() + transforms.len() > 4096
        || !ordered(sources)
        || !ordered(sinks)
        || !ordered(transforms)
    {
        return Err(
            "operation declarations must be sorted, unique and bounded to 4096 entries".into(),
        );
    }
    let selectors = sources
        .iter()
        .map(|v| &v.operation_selector)
        .chain(sinks.iter().map(|v| &v.operation_selector))
        .chain(transforms.iter().map(|v| &v.operation_selector));
    for selector in selectors {
        if selector.reference.is_empty()
            || selector.reference.len() > 1024
            || selector.reference.chars().any(char::is_control)
            || !(selector.context_digest.starts_with("sha256:")
                && selector.context_digest.len() == 71
                && selector.context_digest[7..]
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase()))
        {
            return Err("invalid exact operation/context selector".into());
        }
    }
    let level = |id: &str, name: &str| {
        if id.len() > 1024 || name.len() > 1024 {
            return Err("operation facet/level exceeds public string bound".to_owned());
        }
        facets
            .iter()
            .find(|v| v.id() == id)
            .and_then(|v| v.index_of(name))
            .ok_or_else(|| "unknown operation facet/level".to_owned())
    };
    let mut unique = BTreeSet::new();
    for source in sources {
        level(&source.facet, &source.level)?;
        if !unique.insert((
            &source.operation_selector,
            &source.output_slot,
            &source.facet,
        )) {
            return Err("conflicting source classifications".into());
        }
    }
    unique.clear();
    for sink in sinks {
        level(&sink.facet, &sink.bound)?;
        if !unique.insert((&sink.operation_selector, &sink.input_slot, &sink.facet)) {
            return Err("conflicting sink bounds".into());
        }
    }
    unique.clear();
    for transform in transforms {
        let rule = &transform.classification_rule;
        let from = level(&rule.facet, &rule.from)?;
        let to = level(&rule.facet, &rule.to)?;
        let facet = facets
            .iter()
            .find(|v| v.id() == rule.facet)
            .expect("validated facet");
        if !unique.insert((
            &transform.operation_selector,
            &transform.input_to_output.output,
            &rule.facet,
        )) || !matches!(
            (rule.kind, facet.direction()),
            (
                InformationFlowTransformKind::Endorsement,
                FacetDirection::HigherIsStronger
            ) | (
                InformationFlowTransformKind::Declassification,
                FacetDirection::HigherIsMoreRestricted
            )
        ) || !facet.is_trusted_transition(from, to)
            || transform.trust_basis.state != "DECLARED_ASSUMPTION"
            || transform.trust_basis.authority_ref.trim().is_empty()
            || transform.trust_basis.rationale.trim().is_empty()
            || transform.trust_basis.authority_ref.len() > 1024
            || transform.trust_basis.rationale.len() > 4096
        {
            return Err(
                "invalid, conflicting or self-authenticating transformation authority".into(),
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct OperationClaim {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    operation: String,
    operation_name: String,
    module_id: String,
    slot: Slot,
    facet: String,
    bound: String,
    verdict: String,
    source_refs: Vec<String>,
    source_names: Vec<String>,
    evidence_refs: Vec<String>,
    defeaters: Vec<String>,
    assumptions: Vec<String>,
    reason_codes: Vec<String>,
    defeater_records: Vec<crate::finding::Defeater>,
    findings: Vec<String>,
    coverage: ClaimCoverage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimCoverage {
    scope: String,
    source_ref: String,
    context_ref: String,
    policy_ref: String,
    governed_source_files: usize,
    parsed_source_files: usize,
    dependency_symbols: Vec<String>,
    blocking_eligibility: String,
    unsupported: Vec<String>,
}

impl OperationClaim {
    pub(super) fn is_unevaluable(&self) -> bool {
        self.verdict == "NOT_EVALUABLE"
    }
    pub(super) fn is_applicable(&self) -> bool {
        self.verdict != "NOT_APPLICABLE"
    }
}

/// Validates public claim structure and reported input/evaluability bindings.
/// It checks recorded meaning without re-evaluating data propagation or trust.
///
/// # Errors
/// Rejects unsupported versions, malformed scope, inconsistent evidence or favorable unknowns.
pub fn validate_operation_claim_projection(
    value: &serde_json::Value,
    context_ref: &str,
) -> Result<(), InformationFlowAnalysisError> {
    let fail =
        || InformationFlowAnalysisError::OperationBinding("INVALID_FLOW_CLAIM_PROJECTION".into());
    if value["$schema"] != FLOW_CLAIM_SCHEMA || value["schema_version"].as_u64() != Some(1) {
        return binding_error("UNSUPPORTED_FLOW_CLAIM_VERSION");
    }
    validate_claim_descriptor(value)?;
    for key in [
        "source_refs",
        "source_names",
        "evidence_refs",
        "defeaters",
        "assumptions",
        "reason_codes",
        "findings",
    ] {
        let values = value[key].as_array().ok_or_else(fail)?;
        if values.iter().any(|v| v.as_str().is_none_or(str::is_empty))
            || values.windows(2).any(|p| p[0].as_str() >= p[1].as_str())
        {
            return Err(fail());
        }
    }
    let (governed, parsed) = validate_claim_coverage(value, context_ref)?;
    let records = value["defeater_records"].as_array().ok_or_else(fail)?;
    let mut ids = records
        .iter()
        .map(|v| v["id"].as_str().ok_or_else(fail))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    let cited = value["defeaters"]
        .as_array()
        .ok_or_else(fail)?
        .iter()
        .map(|v| v.as_str().ok_or_else(fail))
        .collect::<Result<Vec<_>, _>>()?;
    if ids != cited {
        return Err(fail());
    }
    let nonempty = |key: &str| value[key].as_array().is_some_and(|v| !v.is_empty());
    match value["verdict"].as_str() {
        Some("NO_SUPPORTED_VIOLATION")
            if governed == 0
                || parsed != governed
                || nonempty("assumptions")
                || nonempty("defeaters")
                || nonempty("reason_codes")
                || nonempty("findings")
                || !nonempty("source_refs")
                || !nonempty("evidence_refs") =>
        {
            Err(fail())
        }
        Some("SUPPORTED_VIOLATION")
            if !nonempty("findings") || !nonempty("source_refs") || !nonempty("evidence_refs") =>
        {
            Err(fail())
        }
        Some("NOT_EVALUABLE") if !nonempty("defeaters") || !nonempty("reason_codes") => Err(fail()),
        Some(
            "NO_SUPPORTED_VIOLATION" | "SUPPORTED_VIOLATION" | "NOT_EVALUABLE" | "NOT_APPLICABLE",
        ) => Ok(()),
        _ => Err(fail()),
    }
}

fn validate_claim_descriptor(
    value: &serde_json::Value,
) -> Result<(), InformationFlowAnalysisError> {
    let fail =
        || InformationFlowAnalysisError::OperationBinding("INVALID_FLOW_CLAIM_DESCRIPTOR".into());
    let object = value.as_object().ok_or_else(fail)?;
    let fields = [
        "$schema",
        "schema_version",
        "id",
        "operation",
        "operation_name",
        "module_id",
        "slot",
        "facet",
        "bound",
        "verdict",
        "source_refs",
        "source_names",
        "evidence_refs",
        "defeaters",
        "assumptions",
        "reason_codes",
        "defeater_records",
        "findings",
        "coverage",
    ];
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(fail());
    }
    for key in [
        "id",
        "operation",
        "operation_name",
        "module_id",
        "facet",
        "bound",
    ] {
        if value[key].as_str().is_none_or(str::is_empty) {
            return Err(fail());
        }
    }
    let id = value["id"].as_str().ok_or_else(fail)?;
    let suffix = id.strip_prefix("flow_claim:v1:sha256:").ok_or_else(fail)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail());
    }
    let _: Slot = serde_json::from_value(value["slot"].clone()).map_err(|_| fail())?;
    Ok(())
}

pub(super) struct BoundOperation {
    node_symbol: String,
    operation: String,
    name: String,
    provenance: ProgramProvenance,
}

pub(super) struct FactBudget {
    steps: usize,
    count: usize,
    bytes: usize,
}

pub(super) fn qualities(psm: &ProgramSemanticModel) -> BTreeMap<String, (bool, bool, bool)> {
    let mut opaque = BTreeSet::new();
    opaque.extend(psm.mutations().iter().map(|v| v.symbol().to_owned()));
    opaque.extend(
        psm.operation_inventory()
            .iter()
            .filter(|v| v.coverage_barrier())
            .map(|v| v.enclosing_symbol().to_owned()),
    );
    for body in psm.bodies() {
        if body.statements().iter().any(|v| {
            matches!(
                v,
                crate::program_semantics::ProgramStatement::If { .. }
                    | crate::program_semantics::ProgramStatement::Match { .. }
                    | crate::program_semantics::ProgramStatement::WhileLet { .. }
            )
        }) {
            opaque.insert(body.symbol().to_owned());
        }
    }
    let mut result = psm
        .symbols()
        .iter()
        .map(|symbol| {
            (
                symbol.id().to_owned(),
                (
                    !opaque.contains(symbol.id()),
                    symbol.execution_provenance()
                        == crate::program_semantics::ExecutionProvenance::ProductionCapable,
                    true,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for call in psm.calls() {
        let (supported, production, _) = result.get(call.caller()).copied().unwrap_or_default();
        for site in call.evidence() {
            result.insert(
                site.operation_site_id().into(),
                (supported, production, false),
            );
        }
    }
    result
}

pub(super) fn qualify_seeds(
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    qualities: &BTreeMap<String, (bool, bool, bool)>,
) {
    for (node, facets) in facts {
        let (body_supported, production, local) =
            qualities.get(&node.symbol).copied().unwrap_or_default();
        let supported = body_supported || (local && node.role == "parameter");
        for labels in facets.values_mut() {
            *labels = labels
                .iter()
                .cloned()
                .map(|mut fact| {
                    fact.supported_witness &= supported;
                    fact.production_witness &= supported && production;
                    fact
                })
                .collect();
        }
    }
}

impl FactBudget {
    pub(super) fn new(
        facts: &BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    ) -> Result<Self, InformationFlowAnalysisError> {
        let mut result = Self {
            count: 0,
            bytes: 0,
            steps: 0,
        };
        for fact in facts.values().flat_map(BTreeMap::values).flatten() {
            result.charge(fact)?;
        }
        Ok(result)
    }

    fn charge(&mut self, fact: &LabelFact) -> Result<(), InformationFlowAnalysisError> {
        self.count = self.count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(
            fact.origin.len()
                + fact.facet.len()
                + fact.level.len()
                + fact.chain.iter().map(String::len).sum::<usize>(),
        );
        if self.count > 100_000 || self.bytes > 64 * 1024 * 1024 || fact.chain.len() > 8192 {
            return binding_error("FLOW_FACT_RESOURCE_LIMIT");
        }
        Ok(())
    }

    pub(super) fn insert(
        &mut self,
        facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
        node: FlowNode,
        fact: LabelFact,
    ) -> Result<bool, InformationFlowAnalysisError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > 8_000_000 {
            return binding_error("FLOW_WORK_RESOURCE_LIMIT");
        }
        if let Some(previous) =
            facts
                .get(&node)
                .and_then(|v| v.get(&fact.facet))
                .and_then(|values| {
                    values
                        .iter()
                        .find(|v| v.origin == fact.origin && v.level == fact.level)
                })
        {
            if (previous.production_witness || !fact.production_witness)
                && (previous.supported_witness || !fact.supported_witness)
            {
                return Ok(false);
            }
            self.count -= 1;
            self.bytes -= previous.origin.len()
                + previous.facet.len()
                + previous.level.len()
                + previous.chain.iter().map(String::len).sum::<usize>();
        }
        self.charge(&fact)?;
        Ok(insert_fact(facts, node, fact))
    }
}

fn bind(
    psm: &ProgramSemanticModel,
    selector: &OperationSelector,
) -> Result<Vec<BoundOperation>, InformationFlowAnalysisError> {
    if selector.context_digest != psm.program_context().digest() {
        return binding_error("STALE_OPERATION_CONTEXT");
    }
    let symbols = psm
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.id() == selector.reference || symbol.qualified_name() == selector.reference
        })
        .collect::<Vec<_>>();
    if symbols.len() > 1 {
        return binding_error("AMBIGUOUS_OPERATION");
    }
    if let [symbol] = symbols.as_slice() {
        return Ok(vec![BoundOperation {
            node_symbol: symbol.id().into(),
            operation: symbol.id().into(),
            name: symbol.qualified_name().into(),
            provenance: symbol.provenance().clone(),
        }]);
    }
    let external = psm
        .calls()
        .iter()
        .filter(|call| call.external_target() == Some(selector.reference.as_str()))
        .flat_map(crate::program_semantics::ProgramCall::evidence)
        .map(|site| BoundOperation {
            node_symbol: site.operation_site_id().into(),
            operation: selector.reference.clone(),
            name: selector.reference.clone(),
            provenance: site.provenance().clone(),
        })
        .take(8193)
        .collect::<Vec<_>>();
    if external.len() > 8192 {
        return binding_error("OPERATION_BINDING_RESOURCE_LIMIT");
    }
    if external.is_empty() {
        return binding_error("UNKNOWN_OR_UNSUPPORTED_OPERATION");
    }
    Ok(external)
}

fn binding_error<T>(message: &str) -> Result<T, InformationFlowAnalysisError> {
    Err(InformationFlowAnalysisError::OperationBinding(
        message.into(),
    ))
}

fn node(
    psm: &ProgramSemanticModel,
    binding: &BoundOperation,
    slot: &Slot,
) -> Result<FlowNode, InformationFlowAnalysisError> {
    match slot {
        Slot::Return => Ok(FlowNode::new(&binding.node_symbol, "return", "return")),
        Slot::Parameter { position } => {
            if let Some(symbol) = psm.symbols().iter().find(|v| v.id() == binding.node_symbol) {
                let Some(parameter) = symbol
                    .parameters()
                    .iter()
                    .find(|v| v.position() == usize::from(*position))
                else {
                    return binding_error("INVALID_PARAMETER_SLOT");
                };
                Ok(FlowNode::new(
                    &binding.node_symbol,
                    "parameter",
                    parameter.name(),
                ))
            } else {
                let value = FlowNode::new(
                    &binding.node_symbol,
                    "parameter",
                    format!("parameter:{position}"),
                );
                if !psm
                    .value_transfers()
                    .iter()
                    .any(|t| FlowNode::from_endpoint(t.consumer()) == value)
                {
                    return binding_error("UNAVAILABLE_EXTERNAL_PARAMETER_SLOT");
                }
                Ok(value)
            }
        }
        Slot::Field { owner, field } => {
            if owner.len() > 1024 || field.len() > 1024 {
                return binding_error("FIELD_SLOT_STRING_RESOURCE_LIMIT");
            }
            let candidates = psm
                .nominal_types()
                .iter()
                .filter(|v| v.id() == owner || v.qualified_name() == owner)
                .collect::<Vec<_>>();
            let [nominal] = candidates.as_slice() else {
                return binding_error("AMBIGUOUS_OR_UNKNOWN_FIELD_OWNER");
            };
            if !nominal.fields().iter().any(|v| v.name() == field) {
                return binding_error("UNKNOWN_FIELD_SLOT");
            }
            if !psm.mutations().iter().any(|v| {
                v.symbol() == binding.node_symbol
                    && v.target().nominal_owner() == Some(nominal.id())
                    && v.target().field_name() == Some(field.as_str())
            }) && !psm.state_reads().iter().any(|v| {
                v.symbol() == binding.node_symbol
                    && v.place().nominal_owner() == Some(nominal.id())
                    && v.place().field_name() == Some(field.as_str())
            }) {
                return binding_error("FIELD_OUTSIDE_OPERATION_SCOPE");
            }
            Ok(FlowNode::new(nominal.id(), "field", field))
        }
    }
}

pub(super) fn seed(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    barriers: &mut BTreeSet<(FlowNode, String)>,
    selected: bool,
) -> Result<(), InformationFlowAnalysisError> {
    let mut admitted = 0usize;
    let mut unique = BTreeSet::new();
    let mut budget = selected.then(|| FactBudget::new(facts)).transpose()?;
    for source in &policy.sources {
        for binding in bind(psm, &source.operation_selector)? {
            admitted += 1;
            if admitted > 8192 {
                return binding_error("OPERATION_BINDING_RESOURCE_LIMIT");
            }
            let node = node(psm, &binding, &source.output_slot)?;
            if !unique.insert((
                binding.node_symbol.clone(),
                node.clone(),
                source.facet.clone(),
            )) {
                return binding_error("DUPLICATE_OR_CONFLICTING_RESOLVED_SOURCE");
            }
            if let Some(budget) = &mut budget {
                budget.insert(
                    facts,
                    node,
                    LabelFact {
                        supported_witness: true,
                        production_witness: true,
                        facet: source.facet.clone(),
                        level: source.level.clone(),
                        authority: FlowAuthority::ContractSource,
                        origin: binding.node_symbol.clone(),
                        chain: vec![format!(
                            "declared_operation_source:{}:{}",
                            policy.digest(),
                            binding.node_symbol
                        )],
                    },
                )?;
            }
        }
    }
    unique.clear();
    for sink in &policy.sinks {
        for binding in bind(psm, &sink.operation_selector)? {
            admitted += 1;
            if admitted > 8192 {
                return binding_error("OPERATION_BINDING_RESOURCE_LIMIT");
            }
            let target = node(psm, &binding, &sink.input_slot)?;
            if !unique.insert((binding.node_symbol, target, sink.facet.clone())) {
                return binding_error("DUPLICATE_OR_CONFLICTING_RESOLVED_SINK");
            }
        }
    }
    unique.clear();
    for transform in &policy.transforms {
        for binding in bind(psm, &transform.operation_selector)? {
            admitted += 1;
            if admitted > 8192 {
                return binding_error("OPERATION_BINDING_RESOURCE_LIMIT");
            }
            node(psm, &binding, &transform.input_to_output.input)?;
            let output = node(psm, &binding, &transform.input_to_output.output)?;
            if !unique.insert((
                binding.node_symbol,
                output.clone(),
                transform.classification_rule.facet.clone(),
            )) {
                return binding_error("DUPLICATE_OR_CONFLICTING_RESOLVED_TRANSFORM");
            }
            if selected {
                barriers.insert((output, transform.classification_rule.facet.clone()));
            }
        }
    }
    Ok(())
}

pub(super) fn transform(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    facts: &mut BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    budget: &mut FactBudget,
) -> Result<bool, InformationFlowAnalysisError> {
    let mut changed = false;
    for transform in &policy.transforms {
        let rule = &transform.classification_rule;
        for binding in bind(psm, &transform.operation_selector)? {
            let input = node(psm, &binding, &transform.input_to_output.input)?;
            let output = node(psm, &binding, &transform.input_to_output.output)?;
            let values = facts
                .get(&input)
                .and_then(|v| v.get(&rule.facet))
                .cloned()
                .unwrap_or_default();
            for mut fact in values {
                // Nonmatching classifications survive; a partial transform cannot erase them.
                if fact.level == rule.from {
                    fact.level.clone_from(&rule.to);
                }
                fact.authority = FlowAuthority::Unknown;
                fact.supported_witness = false;
                fact.production_witness = false;
                fact.chain.push(format!(
                    "DECLARED_ASSUMPTION:{}:{}",
                    policy.digest(),
                    transform.trust_basis.authority_ref
                ));
                changed |= budget.insert(facts, output.clone(), fact)?;
            }
        }
    }
    Ok(changed)
}

#[allow(clippy::too_many_lines)]
pub(super) fn claims(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    facts: &BTreeMap<FlowNode, BTreeMap<String, BTreeSet<LabelFact>>>,
    selection: &FlowSelection,
    converged: bool,
    edition: &str,
) -> Result<(Vec<OperationClaim>, Vec<InformationFlowViolation>), InformationFlowAnalysisError> {
    if policy.sinks.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut claims = Vec::new();
    let mut claim_bytes = 0usize;
    let mut violations = Vec::new();
    let mut names = psm
        .symbols()
        .iter()
        .map(|v| (v.id().to_owned(), v.qualified_name().to_owned()))
        .collect::<BTreeMap<_, _>>();
    for call in psm.calls() {
        if let Some(operation) = call.external_target() {
            for site in call.evidence() {
                names.insert(site.operation_site_id().into(), operation.into());
            }
        }
    }
    let (edges, _) = flow_edges(psm, false);
    let mut reverse = BTreeMap::<FlowNode, Vec<FlowNode>>::new();
    for edge in edges {
        reverse
            .entry(edge.consumer)
            .or_default()
            .push(edge.producer);
    }
    for sink in &policy.sinks {
        for binding in bind(psm, &sink.operation_selector)? {
            let selected = selection.applicable(psm, &binding);
            let target = node(psm, &binding, &sink.input_slot)?;
            let mut dependencies = BTreeSet::from([target.clone()]);
            let mut pending = vec![target.clone()];
            while let Some(node) = pending.pop() {
                for predecessor in reverse.get(&node).into_iter().flatten() {
                    if dependencies.insert(predecessor.clone()) {
                        pending.push(predecessor.clone());
                    }
                }
                if dependencies.len() > 262_144 {
                    return binding_error("FLOW_DEPENDENCY_RESOURCE_LIMIT");
                }
            }
            let scopes = dependencies
                .iter()
                .map(|v| v.symbol.as_str())
                .collect::<BTreeSet<_>>();
            // A sink's input restriction ends at arrival. Its downstream logging
            // implementation does not change the classification of that input.
            let mut analysis_scopes = scopes.clone();
            if matches!(sink.input_slot, Slot::Parameter { .. }) {
                analysis_scopes.remove(binding.node_symbol.as_str());
            }
            let value_semantics_incomplete = psm
                .mutations()
                .iter()
                .any(|v| analysis_scopes.contains(v.symbol()))
                || psm
                    .bodies()
                    .iter()
                    .filter(|body| analysis_scopes.contains(body.symbol()))
                    .any(|body| {
                        body.statements().iter().any(|statement| {
                            matches!(
                                statement,
                                crate::program_semantics::ProgramStatement::If { .. }
                                    | crate::program_semantics::ProgramStatement::Match { .. }
                                    | crate::program_semantics::ProgramStatement::WhileLet { .. }
                            )
                        })
                    })
                || psm.operation_inventory().iter().any(|v| {
                    analysis_scopes.contains(v.enclosing_symbol()) && v.coverage_barrier()
                });
            let labels = facts
                .get(&target)
                .and_then(|v| v.get(&sink.facet))
                .cloned()
                .unwrap_or_default();
            let facet = policy.facet(&sink.facet).expect("validated facet");
            let bound = facet.index_of(&sink.bound).expect("validated level");
            let contradicting = labels
                .iter()
                .filter(|v| {
                    let index = facet
                        .index_of(&v.level)
                        .expect("validated propagated level");
                    v.supported_witness
                        && !v.chain.iter().any(|v| {
                            v.starts_with("DECLARED_ASSUMPTION:")
                                || v.starts_with("opaque_shared_call_context:")
                                || v.starts_with("psm:field_")
                        })
                        && match facet.direction() {
                            FacetDirection::HigherIsStronger => index < bound,
                            FacetDirection::HigherIsMoreRestricted => index > bound,
                        }
                })
                .cloned()
                .collect::<Vec<_>>();
            let uncertain_configuration = psm.symbols().iter().any(|v| {
                scopes.contains(v.id())
                    && v.execution_provenance()
                        == crate::program_semantics::ExecutionProvenance::Unknown
            });
            let mut defeaters = scoped_defeaters(psm, policy, &labels, &analysis_scopes, converged);
            if labels.iter().any(|v| !v.supported_witness) {
                defeaters.insert("UNQUALIFIED_VALUE_TRANSFER".into());
            }
            if uncertain_configuration {
                defeaters.insert("CONFIGURATION_PROVENANCE_UNCERTAIN".into());
            }
            if value_semantics_incomplete {
                defeaters.insert("PATH_OR_REASSIGNMENT_SEMANTICS_UNSUPPORTED".into());
            }
            for transfer in psm.value_transfers().iter().filter(|v| {
                v.kind() == crate::program_semantics::ValueTransferKind::ArgumentToParameter
                    && FlowNode::from_endpoint(v.consumer()) == target
            }) {
                if facts
                    .get(&FlowNode::from_endpoint(transfer.producer()))
                    .and_then(|v| v.get(&sink.facet))
                    .is_none_or(BTreeSet::is_empty)
                {
                    defeaters.insert("UNCLASSIFIED_DEPENDENCY_INPUT".into());
                }
            }
            let assumptions = labels
                .iter()
                .flat_map(|v| &v.chain)
                .filter(|v| v.starts_with("DECLARED_ASSUMPTION:"))
                .cloned()
                .collect::<BTreeSet<_>>();
            if !assumptions.is_empty() {
                defeaters.insert("TRANSFORMATION_IMPLEMENTATION_NOT_PROVEN".to_owned());
            }
            let verdict = if !selected {
                "NOT_APPLICABLE"
            } else if !contradicting.is_empty() {
                "SUPPORTED_VIOLATION"
            } else if !defeaters.is_empty() {
                "NOT_EVALUABLE"
            } else {
                "NO_SUPPORTED_VIOLATION"
            };
            let id = format!(
                "flow_claim:v1:sha256:{:x}",
                Sha256::digest(
                    serde_json_canonicalizer::to_vec(&(
                        policy.digest(),
                        &binding.node_symbol,
                        &sink.input_slot,
                        &sink.facet,
                        &sink.bound
                    ))
                    .map_err(|e| InformationFlowAnalysisError::OperationBinding(e.to_string()))?
                )
            );
            let mut findings = Vec::new();
            if verdict == "SUPPORTED_VIOLATION" {
                let mut violation = information_flow_violation(
                    &binding.node_symbol,
                    &sink.facet,
                    &format!("{:?}", sink.input_slot),
                    &sink.bound,
                    &contradicting,
                    &binding.provenance,
                );
                violation.advisory = !contradicting.iter().any(|v| v.production_witness);
                findings.push(finding(&violation, edition)?.finding_id().into());
                violations.push(violation);
            }
            if !selected {
                defeaters.clear();
            }
            let records = canonical_defeaters(&defeaters, verdict, &id, policy, psm)?;
            let reason_codes = if selected {
                defeaters.into_iter().collect()
            } else {
                vec!["FLOW_PROFILE_NOT_SELECTED_FOR_SCOPE".into()]
            };
            let mut defeaters = records
                .iter()
                .map(|v| v.id().to_owned())
                .collect::<Vec<_>>();
            defeaters.sort();
            let claim = OperationClaim {
                schema: FLOW_CLAIM_SCHEMA.into(),
                schema_version: 1,
                id,
                operation: binding.operation,
                operation_name: binding.name,
                module_id: psm
                    .symbols()
                    .iter()
                    .find(|symbol| {
                        symbol.id() == binding.node_symbol
                            || psm.calls().iter().any(|call| {
                                call.caller() == symbol.id()
                                    && call
                                        .evidence()
                                        .iter()
                                        .any(|site| site.operation_site_id() == binding.node_symbol)
                            })
                    })
                    .map_or("UNKNOWN", |symbol| symbol.fortress_module())
                    .into(),
                slot: sink.input_slot.clone(),
                facet: sink.facet.clone(),
                bound: sink.bound.clone(),
                verdict: verdict.into(),
                source_refs: labels
                    .iter()
                    .map(|v| v.origin.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                evidence_refs: labels
                    .iter()
                    .flat_map(|v| v.chain.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                source_names: labels
                    .iter()
                    .map(|fact| source_name(&names, &fact.origin))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                defeaters,
                assumptions: assumptions.into_iter().collect(),
                reason_codes,
                defeater_records: records,
                findings,
                coverage: ClaimCoverage {
                    scope: "EXPLICIT_VALUE_TRANSFERS".into(),
                    source_ref: psm.source_identity().into(),
                    context_ref: psm.program_context().digest(),
                    policy_ref: policy.digest().into(),
                    governed_source_files: psm.file_coverage().len(),
                    parsed_source_files: psm.file_coverage().iter().filter(|v| v.parsed()).count(),
                    dependency_symbols: scopes.into_iter().map(str::to_owned).collect(),
                    blocking_eligibility: if contradicting.iter().any(|v| v.production_witness) {
                        "BLOCK_SUPPORTED"
                    } else if !contradicting.is_empty() {
                        "ADVISORY_ONLY"
                    } else if verdict == "NOT_EVALUABLE" {
                        "NOT_EVALUABLE"
                    } else {
                        "NOT_APPLICABLE"
                    }
                    .into(),
                    unsupported: UNSUPPORTED_SEMANTICS.iter().map(|v| (*v).into()).collect(),
                },
            };
            claim_bytes = claim_bytes.saturating_add(
                serde_json::to_vec(&claim)
                    .map_err(|e| InformationFlowAnalysisError::OperationBinding(e.to_string()))?
                    .len(),
            );
            if claim_bytes > 64 * 1024 * 1024 {
                return binding_error("FLOW_CLAIM_RESOURCE_LIMIT");
            }
            claims.push(claim);
        }
    }
    claims.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((claims, violations))
}

fn canonical_defeaters(
    reasons: &BTreeSet<String>,
    verdict: &str,
    id: &str,
    policy: &InformationFlowPolicy,
    psm: &ProgramSemanticModel,
) -> Result<Vec<Defeater>, InformationFlowAnalysisError> {
    let make_error = |e: crate::finding::DefeaterError| {
        InformationFlowAnalysisError::OperationBinding(e.to_string())
    };
    let scope = DefeaterScope::new(DefeaterScopeKind::SemanticClaim, id).map_err(make_error)?;
    let records = reasons
        .iter()
        .map(|reason| {
            Defeater::new(
                if reason == "INCOMPLETE_SOURCE_COVERAGE" {
                    DefeaterKind::PartialSemanticCoverage
                } else {
                    DefeaterKind::AnalyserLimit
                },
                if verdict == "SUPPORTED_VIOLATION" {
                    DefeaterStrength::Limiting
                } else {
                    DefeaterStrength::Defeating
                },
                INFORMATION_FLOW_ANALYZER_ID,
                INFORMATION_FLOW_ANALYSIS_VERSION,
                scope.clone(),
                reason,
                BTreeMap::new(),
                vec![policy.digest().into(), psm.program_context().digest()],
                DefeaterRetirementCondition::CurrentAuthorityReevaluated,
            )
            .map_err(make_error)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(records)
}

fn scoped_defeaters(
    psm: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    labels: &BTreeSet<LabelFact>,
    scopes: &BTreeSet<&str>,
    converged: bool,
) -> BTreeSet<String> {
    let mut defeaters = BTreeSet::new();
    if labels.is_empty() {
        defeaters.insert("UNCLASSIFIED_SINK_INPUT".to_owned());
    }
    if !converged {
        defeaters.insert("PROPAGATION_RESOURCE_LIMIT".to_owned());
    }
    let uncertain_configuration = psm.symbols().iter().any(|v| {
        scopes.contains(v.id())
            && v.execution_provenance() == crate::program_semantics::ExecutionProvenance::Unknown
    });
    if uncertain_configuration {
        defeaters.insert("CONFIGURATION_PROVENANCE_UNCERTAIN".to_owned());
    }
    if labels
        .iter()
        .flat_map(|v| &v.chain)
        .any(|v| v.starts_with("opaque_shared_call_context:"))
    {
        defeaters.insert("INTERPROCEDURAL_CONTEXT_AMBIGUITY".to_owned());
    }
    if labels
        .iter()
        .flat_map(|v| &v.chain)
        .any(|v| v.starts_with("psm:field_"))
    {
        defeaters.insert("INSTANCE_ALIAS_PRECISION_UNAVAILABLE".to_owned());
    }
    // Only narrow explicit-data flow is covered. Whole-program security is never asserted.
    if psm.calls().iter().any(|v| {
        scopes.contains(v.caller())
            && v.callee().is_none()
            && !policy
                .sources
                .iter()
                .any(|s| Some(s.operation_selector.reference.as_str()) == v.external_target())
            && !policy
                .sinks
                .iter()
                .any(|s| Some(s.operation_selector.reference.as_str()) == v.external_target())
            && !policy
                .transforms
                .iter()
                .any(|s| Some(s.operation_selector.reference.as_str()) == v.external_target())
    }) {
        defeaters.insert("UNRESOLVED_EXTERNAL_ALIAS_CALLBACK_OR_DISPATCH".to_owned());
    }
    if psm
        .operation_inventory()
        .iter()
        .any(|v| scopes.contains(v.enclosing_symbol()) && v.coverage_barrier())
    {
        defeaters.insert("INCOMPLETE_OPERATION_COVERAGE".to_owned());
    }
    if psm.file_coverage().iter().any(|v| !v.parsed()) {
        defeaters.insert("INCOMPLETE_SOURCE_COVERAGE".to_owned());
    }
    if psm.mutations().iter().any(|v| {
        scopes.contains(v.symbol())
            && matches!(
                v.mutation_kind(),
                crate::program_semantics::MutationKind::MutableFieldUpdate
            )
    }) {
        defeaters.insert("INSTANCE_ALIAS_PRECISION_UNAVAILABLE".to_owned());
    }

    defeaters
}

fn validate_claim_coverage(
    value: &serde_json::Value,
    context_ref: &str,
) -> Result<(u64, u64), InformationFlowAnalysisError> {
    let fail =
        || InformationFlowAnalysisError::OperationBinding("INVALID_FLOW_CLAIM_COVERAGE".into());
    let typed: ClaimCoverage =
        serde_json::from_value(value["coverage"].clone()).map_err(|_| fail())?;
    if !matches!(
        typed.blocking_eligibility.as_str(),
        "BLOCK_SUPPORTED" | "ADVISORY_ONLY" | "NOT_EVALUABLE" | "NOT_APPLICABLE"
    ) || [&typed.dependency_symbols, &typed.unsupported]
        .iter()
        .any(|values| {
            values.iter().any(String::is_empty)
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
        })
    {
        return Err(fail());
    }
    let coverage = &value["coverage"];
    if coverage["scope"] != "EXPLICIT_VALUE_TRANSFERS" || coverage["context_ref"] != context_ref {
        return Err(fail());
    }
    for key in ["source_ref", "context_ref", "policy_ref"] {
        let digest = coverage[key].as_str().ok_or_else(fail)?;
        if digest.len() != 71
            || !digest.starts_with("sha256:")
            || !digest[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(fail());
        }
    }
    let governed = coverage["governed_source_files"]
        .as_u64()
        .ok_or_else(fail)?;
    let parsed = coverage["parsed_source_files"].as_u64().ok_or_else(fail)?;
    if governed > crate::wire::MAX_EXACT_PUBLIC_INTEGER || parsed > governed {
        return Err(fail());
    }
    Ok((governed, parsed))
}

pub(super) fn module_provenance(
    claims: &[OperationClaim],
    module: &str,
) -> (Vec<String>, Vec<String>) {
    let selected = claims
        .iter()
        .filter(|c| c.module_id == module)
        .collect::<Vec<_>>();
    (
        selected
            .iter()
            .map(|c| c.id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        selected
            .iter()
            .flat_map(|c| c.assumptions.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    )
}
