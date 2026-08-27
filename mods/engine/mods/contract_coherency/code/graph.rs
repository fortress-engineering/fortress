//! Deterministic semantic facts, derivations, and serialization for CCG v1.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    CcgViolation, ConstraintScope, ContractCoherencyGraph, GuaranteeSubjectKind,
    ModuleRelationshipType, ResolvedConstraint,
};

/// Canonical serialized Contract Coherency Graph schema identity.
pub const CCG_SCHEMA: &str = "urn:fortress:schema:v1:contract-coherency-graph";

/// Canonical serialized Contract Coherency Graph schema version.
pub const CCG_SCHEMA_VERSION: u16 = 1;

/// Semantic classes intentionally outside CCG v1 proof authority.
pub const CCG_UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_natural_language_requirement_contradiction",
    "general_behavioral_satisfiability",
    "source_code_dependency_realization",
    "lowest_semantic_ownership_from_runtime_consumers",
    "security_information_flow_proof",
    "arbitrary_theorem_proving",
];

/// Supported analyzer classification carried into CCG verification facts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CcgTestClassification {
    /// Product behavior evidence that requires one exact requirement mapping.
    Behavioral,
    /// Rule-conformance evidence that requires one exact requirement mapping.
    Conformance,
    /// Implementation-only evidence that does not satisfy Feature coverage.
    Infrastructure,
}

/// One supported observed test-source fact supplied to CCG compilation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CcgObservedTestFact {
    id: String,
    path: String,
    symbol: String,
    classification: CcgTestClassification,
    declared_requirement: Option<String>,
}

impl CcgObservedTestFact {
    /// Creates one deterministic source-analysis fact.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        path: impl Into<String>,
        symbol: impl Into<String>,
        classification: CcgTestClassification,
        declared_requirement: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
            symbol: symbol.into(),
            classification,
            declared_requirement,
        }
    }

    /// Returns the stable test identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the observed source symbol.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the semantic test classification.
    #[must_use]
    pub const fn classification(&self) -> CcgTestClassification {
        self.classification
    }

    /// Returns the exact source-declared requirement identity, when present.
    #[must_use]
    pub fn declared_requirement(&self) -> Option<&str> {
        self.declared_requirement.as_deref()
    }
}

/// Supported logical status of one compiled CCG.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CcgCoherencyStatus {
    /// No contradiction exists within implemented semantics.
    Coherent,
    /// At least one implemented semantic contradiction exists.
    Incoherent,
}

/// Deterministic summary counts for one compiled CCG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CcgSummary {
    modules: usize,
    capabilities: usize,
    features: usize,
    requirements: usize,
    guarantees: usize,
    explicit_constraints: usize,
    effective_constraints: usize,
    relationships: usize,
    testing_boundaries: usize,
    derivations: usize,
}

impl CcgSummary {
    /// Returns the Module count.
    #[must_use]
    pub const fn modules(self) -> usize {
        self.modules
    }
    /// Returns the provided capability count.
    #[must_use]
    pub const fn capabilities(self) -> usize {
        self.capabilities
    }
    /// Returns the Feature count.
    #[must_use]
    pub const fn features(self) -> usize {
        self.features
    }
    /// Returns the requirement count.
    #[must_use]
    pub const fn requirements(self) -> usize {
        self.requirements
    }
    /// Returns the guarantee count.
    #[must_use]
    pub const fn guarantees(self) -> usize {
        self.guarantees
    }
    /// Returns the explicit constraint count.
    #[must_use]
    pub const fn explicit_constraints(self) -> usize {
        self.explicit_constraints
    }
    /// Returns the effective constraint count after inheritance and implication.
    #[must_use]
    pub const fn effective_constraints(self) -> usize {
        self.effective_constraints
    }
    /// Returns direct and derived relationship fact count.
    #[must_use]
    pub const fn relationships(self) -> usize {
        self.relationships
    }
    /// Returns canonical Testing boundary count.
    #[must_use]
    pub const fn testing_boundaries(self) -> usize {
        self.testing_boundaries
    }
    /// Returns derived fact explanation count.
    #[must_use]
    pub const fn derivations(self) -> usize {
        self.derivations
    }
}

impl ContractCoherencyGraph {
    /// Serializes CCG v1 as deterministic UTF-8-compatible pretty JSON with LF termination.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if the typed semantic graph cannot be serialized.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.document()).map(|mut json| {
            json.push('\n');
            json
        })
    }

    /// Computes the SHA-256 identity of canonical graph bytes without embedding it.
    ///
    /// # Errors
    ///
    /// Returns a JSON error if canonical graph serialization fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        self.to_canonical_json()
            .map(|json| format!("sha256:{:x}", Sha256::digest(json.as_bytes())))
    }

    /// Returns logical status within the semantics implemented by CCG v1.
    #[must_use]
    pub fn coherency_status(&self) -> CcgCoherencyStatus {
        if self.coherency_findings.is_empty() {
            CcgCoherencyStatus::Coherent
        } else {
            CcgCoherencyStatus::Incoherent
        }
    }

    /// Returns semantic contradiction findings produced during compilation.
    #[must_use]
    pub fn coherency_findings(&self) -> &[CcgViolation] {
        &self.coherency_findings
    }

    /// Returns explicit semantic classes CCG v1 does not prove.
    #[must_use]
    pub const fn unsupported_semantics(&self) -> &'static [&'static str] {
        CCG_UNSUPPORTED_SEMANTICS
    }

    /// Returns deterministic semantic-domain counts.
    #[must_use]
    pub fn summary(&self) -> CcgSummary {
        let document = self.document();
        CcgSummary {
            modules: document.modules.len(),
            capabilities: document.capabilities.len(),
            features: document.features.len(),
            requirements: document.requirements.len(),
            guarantees: document.guarantees.len(),
            explicit_constraints: document.constraints.explicit.len(),
            effective_constraints: document.constraints.effective.len(),
            relationships: document.relationships.capability_requirements.len()
                + document.relationships.typed.len()
                + document.relationships.dependency_reachability.len()
                + document.relationships.reachable_capabilities.len(),
            testing_boundaries: document.verification.testing_boundaries.len(),
            derivations: document.derivations.len(),
        }
    }

    /// Returns canonical directed dependency cycles derived from capability requirements.
    #[must_use]
    pub fn dependency_cycles(&self) -> Vec<Vec<String>> {
        dependency_cycles(&self.direct_requirements)
    }

    /// Returns the canonical shortest declared dependency path between Modules.
    ///
    /// Direct paths have two identities. A longer path proves reachability but
    /// does not authorize a direct source dependency.
    #[must_use]
    pub fn canonical_dependency_path(&self, source: &str, target: &str) -> Option<Vec<String>> {
        dependency_paths(&self.direct_requirements).remove(&(source.to_owned(), target.to_owned()))
    }

    pub(super) fn analyze_coherency(&self) -> Vec<CcgViolation> {
        let mut findings = Vec::new();
        for cycle in self.dependency_cycles() {
            let module_id = cycle.first().map_or("", String::as_str);
            let path = self
                .modules
                .get(module_id)
                .map_or("contract.json", |module| module.contract_path());
            let mut violation = semantic_violation(
                "CCG-DEPENDENCY-CYCLE",
                path,
                "/requires",
                format!(
                    "capability dependency closure contains a directed cycle: {}",
                    cycle.join(" -> ")
                ),
            );
            violation.input_facts = cycle
                .windows(2)
                .map(|edge| format!("dependency:{}:{}", edge[0], edge[1]))
                .collect();
            violation.provenance_closure = cycle
                .windows(2)
                .filter_map(|edge| {
                    self.direct_requirements.iter().find(|requirement| {
                        requirement.consumer() == edge[0] && requirement.provider() == edge[1]
                    })
                })
                .map(|requirement| provenance(requirement.provenance()))
                .collect();
            findings.push(violation);
        }
        let effective = effective_constraint_facts(self);
        let conflicts = conflict_pairs(self);
        let mut by_module = BTreeMap::<&str, BTreeSet<&str>>::new();
        for fact in &effective {
            by_module
                .entry(&fact.module)
                .or_default()
                .insert(&fact.rule);
        }
        for (module_id, rules) in by_module {
            for (first, second) in &conflicts {
                if rules.contains(first.as_str()) && rules.contains(second.as_str()) {
                    let path = self
                        .modules
                        .get(module_id)
                        .map_or("contract.json", |module| module.contract_path());
                    let mut violation = semantic_violation(
                        "CCG-CONSTRAINT-CONFLICT",
                        path,
                        "/constraints",
                        format!(
                            "Module `{module_id}` has conflicting effective rules `{first}` and `{second}`"
                        ),
                    );
                    violation.input_facts = vec![
                        format!("effective_constraint:{module_id}:{first}"),
                        format!("effective_constraint:{module_id}:{second}"),
                    ];
                    violation.provenance_closure = effective
                        .iter()
                        .filter(|fact| {
                            fact.module == module_id
                                && (fact.rule == *first || fact.rule == *second)
                        })
                        .flat_map(|fact| {
                            fact.origins.iter().map(|origin| origin.provenance.clone())
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    findings.push(violation);
                }
            }
        }
        findings.extend(verification_violations(self));
        findings.sort();
        findings.dedup();
        findings
    }

    fn document(&self) -> CcgDocument {
        let mut derivations = Vec::new();
        let provenance = source_provenance(self);
        let modules = module_facts(self, &mut derivations);
        let dependency_paths = dependency_paths(&self.direct_requirements);
        let capabilities = capability_facts(self, &dependency_paths, &mut derivations);
        let features = feature_facts(self);
        let requirements = requirement_facts(self);
        let verification = verification_facts(self, &mut derivations);
        let guarantees = guarantee_facts(self, &verification, &mut derivations);
        let constraints = CcgConstraints {
            explicit: explicit_constraint_facts(self),
            effective: effective_constraint_facts(self),
        };
        let relationships = relationship_facts(self, &dependency_paths, &mut derivations);
        let behavior_declarations = behavior_facts(self);
        derivations.sort();
        derivations.dedup();
        CcgDocument {
            schema: CCG_SCHEMA,
            schema_version: CCG_SCHEMA_VERSION,
            identity: identity_fact(self),
            standard: standard_fact(self),
            modules,
            capabilities,
            features,
            requirements,
            guarantees,
            constraints,
            relationships,
            verification,
            behavior_declarations,
            derivations,
            provenance,
            coherency: CcgCoherency {
                status: self.coherency_status(),
                findings: self
                    .coherency_findings
                    .iter()
                    .map(CcgSerializedFinding::from)
                    .collect(),
                unsupported_semantics: CCG_UNSUPPORTED_SEMANTICS.to_vec(),
            },
        }
    }
}

#[derive(Serialize)]
struct CcgDocument {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    identity: CcgIdentity,
    standard: CcgStandard,
    modules: Vec<CcgModule>,
    capabilities: Vec<CcgCapability>,
    features: Vec<CcgFeature>,
    requirements: Vec<CcgRequirement>,
    guarantees: Vec<CcgGuarantee>,
    constraints: CcgConstraints,
    relationships: CcgRelationships,
    verification: CcgVerification,
    behavior_declarations: Vec<CcgBehavior>,
    derivations: Vec<CcgDerivation>,
    provenance: Vec<CcgSourceProvenance>,
    coherency: CcgCoherency,
}

#[derive(Serialize)]
struct CcgIdentity {
    project_id: String,
    repository_grammar: u16,
}
#[derive(Serialize)]
struct CcgStandard {
    id: String,
    edition: String,
    status: String,
    bundle_digest: String,
    rules: Vec<CcgRuleLogic>,
}
#[derive(Serialize)]
struct CcgRuleLogic {
    id: String,
    source_digest: String,
    implies: Vec<String>,
    conflicts_with: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgModule {
    id: String,
    display_name: String,
    path: String,
    parent: Option<String>,
    children: Vec<String>,
    contract_source: String,
    contract_digest: String,
    provenance: CcgSourceProvenance,
    containment_derivation: String,
}
#[derive(Serialize)]
struct CcgCapability {
    id: String,
    provider: String,
    version: String,
    visibility: String,
    direct_consumers: Vec<String>,
    direct_requirements: Vec<String>,
    transitively_reachable_by: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgFeature {
    id: String,
    owner: String,
    version: String,
    requirements: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgRequirement {
    id: String,
    owner: String,
    feature: String,
    statement: String,
    declared_tests: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgGuarantee {
    id: String,
    owner: String,
    subject_kind: String,
    subject_id: String,
    backing_requirements: Vec<String>,
    support_topology: Vec<CcgGuaranteeSupport>,
    complete_declared_verification_obligations: bool,
    provenance: CcgSourceProvenance,
}
#[derive(Clone, Serialize)]
struct CcgGuaranteeSupport {
    requirement: String,
    feature: String,
    testing_module: Option<String>,
    declared_tests: Vec<String>,
    derivation: String,
}
#[derive(Serialize)]
struct CcgConstraints {
    explicit: Vec<CcgExplicitConstraint>,
    effective: Vec<CcgEffectiveConstraint>,
}
#[derive(Serialize)]
struct CcgExplicitConstraint {
    module: String,
    rule: String,
    scope: String,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgEffectiveConstraint {
    module: String,
    rule: String,
    origins: Vec<CcgConstraintOrigin>,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CcgConstraintOrigin {
    kind: String,
    declared_by: String,
    declared_rule: String,
    rule_path: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgRelationships {
    capability_requirements: Vec<CcgCapabilityRequirement>,
    typed: Vec<CcgTypedRelationship>,
    inverse_consumers: Vec<CcgInverseConsumer>,
    dependency_reachability: Vec<CcgDependencyReachability>,
    reachable_capabilities: Vec<CcgReachableCapability>,
}
#[derive(Serialize)]
struct CcgCapabilityRequirement {
    consumer: String,
    provider: String,
    capability: String,
    version_requirement: String,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgTypedRelationship {
    source: String,
    relationship_type: String,
    target: String,
    subjects: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgInverseConsumer {
    provider: String,
    consumer: String,
    capability: String,
    derivation: String,
}
#[derive(Serialize)]
struct CcgDependencyReachability {
    source: String,
    target: String,
    direct: bool,
    path: Vec<String>,
    derivation: String,
}
#[derive(Serialize)]
struct CcgReachableCapability {
    source: String,
    capability: String,
    provider: String,
    path: Vec<String>,
    reexported: bool,
    derivation: String,
}
#[derive(Serialize)]
struct CcgVerification {
    observed_test_source_resolution_supported: bool,
    testing_boundaries: Vec<CcgTestingBoundary>,
    requirement_support: Vec<CcgRequirementSupport>,
    observed_tests: Vec<CcgObservedTest>,
}
#[derive(Clone, Serialize)]
struct CcgTestingBoundary {
    parent: String,
    testing_module: String,
    verified_features: Vec<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Clone, Serialize)]
struct CcgRequirementSupport {
    requirement: String,
    owner: String,
    feature: String,
    testing_module: Option<String>,
    declared_tests: Vec<String>,
    observed_tests: Vec<String>,
    complete_declared_support: bool,
    derivation: String,
}
#[derive(Serialize)]
struct CcgObservedTest {
    id: String,
    testing_module: Option<String>,
    path: String,
    symbol: String,
    classification: CcgTestClassification,
    declared_requirement: Option<String>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgBehavior {
    id: String,
    owner: String,
    feature: String,
    kind: String,
    outcome: Option<String>,
    transitions: Vec<CcgTransition>,
    provenance: CcgSourceProvenance,
}
#[derive(Serialize)]
struct CcgTransition {
    outcome: Option<String>,
    target: String,
}
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CcgDerivation {
    id: String,
    kind: String,
    fact: String,
    input_facts: Vec<String>,
    explanation_path: Vec<String>,
    provenance_closure: Vec<CcgSourceProvenance>,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
/// Canonical repository-relative origin of one source or derived CCG fact.
pub struct CcgSourceProvenance {
    path: String,
    pointer: String,
}

impl CcgSourceProvenance {
    pub(super) fn new(path: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            pointer: pointer.into(),
        }
    }

    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the JSON pointer or semantic source location.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}
#[derive(Serialize)]
struct CcgCoherency {
    status: CcgCoherencyStatus,
    findings: Vec<CcgSerializedFinding>,
    unsupported_semantics: Vec<&'static str>,
}
#[derive(Serialize)]
struct CcgSerializedFinding {
    code: String,
    path: String,
    pointer: String,
    message: String,
    input_facts: Vec<String>,
    provenance_closure: Vec<CcgSourceProvenance>,
}

impl From<&CcgViolation> for CcgSerializedFinding {
    fn from(value: &CcgViolation) -> Self {
        Self {
            code: value.code().into(),
            path: value.path().into(),
            pointer: value.pointer().into(),
            message: value.message().into(),
            input_facts: value.input_facts().to_vec(),
            provenance_closure: value.provenance_closure().to_vec(),
        }
    }
}

fn identity_fact(graph: &ContractCoherencyGraph) -> CcgIdentity {
    let root = graph
        .root()
        .expect("compiled CCG must contain its root Module");
    let ecosystem = root
        .contract()
        .ecosystem()
        .expect("compiled CCG root must contain ecosystem selection");
    CcgIdentity {
        project_id: root.contract().id().into(),
        repository_grammar: ecosystem.repository_grammar(),
    }
}

fn standard_fact(graph: &ContractCoherencyGraph) -> CcgStandard {
    let rules = graph
        .standard
        .rule_ids
        .iter()
        .map(|id| {
            let indexed = graph.standard.rules.get(id);
            CcgRuleLogic {
                id: id.clone(),
                source_digest: indexed.map_or_else(
                    || graph.standard.digest.clone(),
                    |rule| rule.source_digest.clone(),
                ),
                implies: indexed.map_or_else(Vec::new, |rule| rule.implies.clone()),
                conflicts_with: indexed.map_or_else(Vec::new, |rule| rule.conflicts_with.clone()),
                provenance: CcgSourceProvenance {
                    path: indexed
                        .map_or("synthetic-standard", |rule| &rule.source_path)
                        .into(),
                    pointer: "/logic".into(),
                },
            }
        })
        .collect();
    CcgStandard {
        id: graph.standard.id.clone(),
        edition: graph.standard.edition.clone(),
        status: graph.standard.status.clone(),
        bundle_digest: graph.standard.digest.clone(),
        rules,
    }
}

fn module_facts(
    graph: &ContractCoherencyGraph,
    derivations: &mut Vec<CcgDerivation>,
) -> Vec<CcgModule> {
    let mut children = BTreeMap::<&str, Vec<String>>::new();
    for (child, parent) in &graph.containment {
        if let Some(parent) = parent {
            children.entry(parent).or_default().push(child.clone());
        }
    }
    graph
        .modules
        .iter()
        .map(|(id, module)| {
            let derivation = format!("containment:{id}");
            derivations.push(CcgDerivation {
                id: derivation.clone(),
                kind: "physical_containment".into(),
                fact: format!("module_parent:{id}"),
                input_facts: vec![format!("contract:{id}")],
                explanation_path: module.parent_id().map_or_else(
                    || vec![id.clone()],
                    |parent| vec![parent.into(), id.clone()],
                ),
                provenance_closure: vec![source(module.contract_path(), "/id")],
            });
            CcgModule {
                id: id.clone(),
                display_name: module.contract().display_name().into(),
                path: if module.path().is_empty() {
                    ".".into()
                } else {
                    module.path().into()
                },
                parent: module.parent_id().map(str::to_owned),
                children: children.remove(id.as_str()).unwrap_or_default(),
                contract_source: module.contract_path().into(),
                contract_digest: module.digest().into(),
                provenance: source(module.contract_path(), "/"),
                containment_derivation: derivation,
            }
        })
        .collect()
}

fn capability_facts(
    graph: &ContractCoherencyGraph,
    paths: &BTreeMap<(String, String), Vec<String>>,
    derivations: &mut Vec<CcgDerivation>,
) -> Vec<CcgCapability> {
    graph
        .capabilities
        .iter()
        .map(|(id, capability)| {
            let direct_requirements: Vec<&super::ResolvedCapabilityRequirement> = graph
                .direct_requirements
                .iter()
                .filter(|requirement| requirement.capability() == id)
                .collect();
            let direct_consumers: BTreeSet<String> = direct_requirements
                .iter()
                .map(|requirement| requirement.consumer().into())
                .collect();
            for requirement in &direct_requirements {
                derivations.push(CcgDerivation {
                    id: format!(
                        "inverse_consumer:{}:{}:{}",
                        capability.provider(),
                        requirement.consumer(),
                        id
                    ),
                    kind: "inverse_consumer".into(),
                    fact: format!(
                        "consumer:{}:{}:{}",
                        capability.provider(),
                        requirement.consumer(),
                        id
                    ),
                    input_facts: vec![format!("requires:{}:{}", requirement.consumer(), id)],
                    explanation_path: vec![
                        requirement.consumer().into(),
                        capability.provider().into(),
                    ],
                    provenance_closure: vec![provenance(requirement.provenance())],
                });
            }
            let transitively_reachable_by = paths
                .iter()
                .filter(|((source_id, target_id), path)| {
                    target_id == capability.provider() && source_id != target_id && path.len() > 2
                })
                .map(|((source_id, _), _)| source_id.clone())
                .collect();
            CcgCapability {
                id: id.clone(),
                provider: capability.provider().into(),
                version: capability.version().into(),
                visibility: match capability.visibility() {
                    super::CapabilityVisibility::Project => "project",
                    super::CapabilityVisibility::Public => "public",
                }
                .into(),
                direct_consumers: direct_consumers.into_iter().collect(),
                direct_requirements: direct_requirements
                    .iter()
                    .map(|requirement| format!("requires:{}:{}", requirement.consumer(), id))
                    .collect(),
                transitively_reachable_by,
                provenance: provenance(capability.provenance()),
            }
        })
        .collect()
}

fn feature_facts(graph: &ContractCoherencyGraph) -> Vec<CcgFeature> {
    graph
        .features
        .iter()
        .map(|(id, ownership)| {
            let module = &graph.modules[ownership.owner()];
            let feature = module
                .contract()
                .features()
                .iter()
                .find(|feature| feature.id() == id)
                .expect("indexed Feature must remain in its source contract");
            CcgFeature {
                id: id.clone(),
                owner: ownership.owner().into(),
                version: feature.version().into(),
                requirements: feature
                    .requirements()
                    .iter()
                    .map(|requirement| requirement.id().into())
                    .collect(),
                provenance: provenance(ownership.provenance()),
            }
        })
        .collect()
}

fn requirement_facts(graph: &ContractCoherencyGraph) -> Vec<CcgRequirement> {
    graph
        .requirements
        .iter()
        .map(|(id, requirement)| CcgRequirement {
            id: id.clone(),
            owner: requirement.owner().into(),
            feature: requirement.feature().into(),
            statement: requirement.statement().into(),
            declared_tests: requirement.tests().to_vec(),
            provenance: provenance(requirement.provenance()),
        })
        .collect()
}

fn explicit_constraint_facts(graph: &ContractCoherencyGraph) -> Vec<CcgExplicitConstraint> {
    let mut facts = Vec::new();
    for (id, module) in &graph.modules {
        for (index, constraint) in module.contract().constraints().iter().enumerate() {
            facts.push(CcgExplicitConstraint {
                module: id.clone(),
                rule: constraint.rule().into(),
                scope: constraint_scope(constraint.scope()).into(),
                provenance: source(module.contract_path(), &format!("/constraints/{index}")),
            });
        }
    }
    facts
}

fn effective_constraint_facts(graph: &ContractCoherencyGraph) -> Vec<CcgEffectiveConstraint> {
    let implication_paths = implication_paths(graph);
    let mut facts = BTreeMap::<(String, String), BTreeSet<CcgConstraintOrigin>>::new();
    for (module, constraints) in &graph.effective_constraints {
        for constraint in constraints {
            add_constraint_origin(
                &mut facts,
                module,
                constraint.rule(),
                constraint,
                vec![constraint.rule().into()],
            );
            for ((source_rule, implied_rule), rule_path) in &implication_paths {
                if source_rule == constraint.rule() && implied_rule != source_rule {
                    add_constraint_origin(
                        &mut facts,
                        module,
                        implied_rule,
                        constraint,
                        rule_path.clone(),
                    );
                }
            }
        }
    }
    facts
        .into_iter()
        .map(|((module, rule), origins)| CcgEffectiveConstraint {
            module,
            rule,
            origins: origins.into_iter().collect(),
        })
        .collect()
}

fn add_constraint_origin(
    facts: &mut BTreeMap<(String, String), BTreeSet<CcgConstraintOrigin>>,
    module: &str,
    effective_rule: &str,
    constraint: &ResolvedConstraint,
    rule_path: Vec<String>,
) {
    let kind = if rule_path.len() > 1 {
        "implied"
    } else if constraint.inherited() {
        "inherited"
    } else {
        "explicit"
    };
    facts
        .entry((module.into(), effective_rule.into()))
        .or_default()
        .insert(CcgConstraintOrigin {
            kind: kind.into(),
            declared_by: constraint.declared_by().into(),
            declared_rule: constraint.rule().into(),
            rule_path,
            provenance: provenance(constraint.provenance()),
        });
}

fn relationship_facts(
    graph: &ContractCoherencyGraph,
    paths: &BTreeMap<(String, String), Vec<String>>,
    derivations: &mut Vec<CcgDerivation>,
) -> CcgRelationships {
    let capability_requirements = graph
        .direct_requirements
        .iter()
        .map(|requirement| CcgCapabilityRequirement {
            consumer: requirement.consumer().into(),
            provider: requirement.provider().into(),
            capability: requirement.capability().into(),
            version_requirement: requirement.version_requirement().into(),
            provenance: provenance(requirement.provenance()),
        })
        .collect();
    let typed = graph
        .relationships
        .iter()
        .map(|relationship| CcgTypedRelationship {
            source: relationship.source().into(),
            relationship_type: relationship.kind().as_str().into(),
            target: relationship.target().into(),
            subjects: relationship.subjects().to_vec(),
            provenance: provenance(relationship.provenance()),
        })
        .collect();
    let inverse_consumers = graph
        .direct_requirements
        .iter()
        .map(|requirement| CcgInverseConsumer {
            provider: requirement.provider().into(),
            consumer: requirement.consumer().into(),
            capability: requirement.capability().into(),
            derivation: format!(
                "inverse_consumer:{}:{}:{}",
                requirement.provider(),
                requirement.consumer(),
                requirement.capability()
            ),
        })
        .collect();
    let (dependency_reachability, reachable_capabilities) =
        reachability_facts(graph, paths, derivations);
    CcgRelationships {
        capability_requirements,
        typed,
        inverse_consumers,
        dependency_reachability,
        reachable_capabilities,
    }
}

fn reachability_facts(
    graph: &ContractCoherencyGraph,
    paths: &BTreeMap<(String, String), Vec<String>>,
    derivations: &mut Vec<CcgDerivation>,
) -> (Vec<CcgDependencyReachability>, Vec<CcgReachableCapability>) {
    let mut dependencies = Vec::new();
    let mut capabilities = Vec::new();
    for ((source_id, target_id), path) in paths {
        if source_id == target_id {
            continue;
        }
        let dependency_derivation = format!("dependency_reachability:{source_id}:{target_id}");
        let input_facts = path
            .windows(2)
            .map(|edge| format!("dependency:{}:{}", edge[0], edge[1]))
            .collect();
        let provenance_closure = path
            .windows(2)
            .filter_map(|edge| {
                graph.direct_requirements.iter().find(|requirement| {
                    requirement.consumer() == edge[0] && requirement.provider() == edge[1]
                })
            })
            .map(|requirement| provenance(requirement.provenance()))
            .collect();
        derivations.push(CcgDerivation {
            id: dependency_derivation.clone(),
            kind: if path.len() == 2 {
                "direct_dependency"
            } else {
                "transitive_dependency"
            }
            .into(),
            fact: format!("dependency_reachability:{source_id}:{target_id}"),
            input_facts,
            explanation_path: path.clone(),
            provenance_closure,
        });
        dependencies.push(CcgDependencyReachability {
            source: source_id.clone(),
            target: target_id.clone(),
            direct: path.len() == 2,
            path: path.clone(),
            derivation: dependency_derivation,
        });
        for (capability_id, capability) in &graph.capabilities {
            if capability.provider() != target_id {
                continue;
            }
            let derivation =
                format!("capability_reachability:{source_id}:{target_id}:{capability_id}");
            derivations.push(CcgDerivation {
                id: derivation.clone(),
                kind: "capability_reachability".into(),
                fact: format!("reachable_capability:{source_id}:{capability_id}"),
                input_facts: vec![
                    format!("dependency_reachability:{source_id}:{target_id}"),
                    format!("provides:{target_id}:{capability_id}"),
                ],
                explanation_path: path.clone(),
                provenance_closure: vec![provenance(capability.provenance())],
            });
            capabilities.push(CcgReachableCapability {
                source: source_id.clone(),
                capability: capability_id.clone(),
                provider: target_id.clone(),
                path: path.clone(),
                reexported: capability.provider() == source_id,
                derivation,
            });
        }
    }
    (dependencies, capabilities)
}

fn verification_facts(
    graph: &ContractCoherencyGraph,
    derivations: &mut Vec<CcgDerivation>,
) -> CcgVerification {
    let testing_boundaries = testing_boundary_facts(graph, derivations);
    let requirement_support = requirement_support_facts(graph, &testing_boundaries, derivations);
    let observed_tests = graph
        .observed_tests
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|test| CcgObservedTest {
            id: test.id().into(),
            testing_module: testing_module_for_source(graph, test.path()),
            path: test.path().into(),
            symbol: test.symbol().into(),
            classification: test.classification(),
            declared_requirement: test.declared_requirement().map(str::to_owned),
            provenance: source(test.path(), &format!("symbol:{}", test.symbol())),
        })
        .collect();
    CcgVerification {
        observed_test_source_resolution_supported: graph.observed_tests.is_some(),
        testing_boundaries,
        requirement_support,
        observed_tests,
    }
}

fn testing_boundary_facts(
    graph: &ContractCoherencyGraph,
    derivations: &mut Vec<CcgDerivation>,
) -> Vec<CcgTestingBoundary> {
    let mut testing_boundaries = Vec::new();
    let path_to_id: BTreeMap<&str, &str> = graph
        .modules
        .iter()
        .map(|(id, module)| (module.path(), id.as_str()))
        .collect();
    for (id, module) in &graph.modules {
        if module.contract().features().is_empty() {
            continue;
        }
        let testing_path = direct_testing_path(module.path());
        if let Some(testing_id) = path_to_id.get(testing_path.as_str()) {
            let testing = &graph.modules[*testing_id];
            let relationship = testing
                .contract()
                .relationships()
                .iter()
                .find(|relationship| {
                    relationship.kind() == ModuleRelationshipType::Verifies
                        && relationship.target() == id
                });
            let source_provenance = relationship.map_or_else(
                || source(testing.contract_path(), "/relationships"),
                |_| source(testing.contract_path(), "/relationships/0"),
            );
            let derivation = format!("verification_boundary:{id}:{testing_id}");
            derivations.push(CcgDerivation {
                id: derivation,
                kind: "verification_boundary".into(),
                fact: format!("testing_boundary:{id}"),
                input_facts: vec![
                    format!("containment:{testing_id}"),
                    format!("verifies:{testing_id}:{id}"),
                ],
                explanation_path: vec![id.clone(), (*testing_id).into()],
                provenance_closure: vec![source_provenance.clone()],
            });
            testing_boundaries.push(CcgTestingBoundary {
                parent: id.clone(),
                testing_module: (*testing_id).into(),
                verified_features: relationship
                    .map_or_else(Vec::new, |value| value.subjects().to_vec()),
                provenance: source_provenance,
            });
        }
    }
    testing_boundaries
}

fn requirement_support_facts(
    graph: &ContractCoherencyGraph,
    testing_boundaries: &[CcgTestingBoundary],
    derivations: &mut Vec<CcgDerivation>,
) -> Vec<CcgRequirementSupport> {
    let boundary_by_parent: BTreeMap<&str, &str> = testing_boundaries
        .iter()
        .map(|boundary| (boundary.parent.as_str(), boundary.testing_module.as_str()))
        .collect();
    let observed = graph.observed_tests.as_deref().unwrap_or_default();
    let observed_ids: BTreeSet<&str> = observed.iter().map(CcgObservedTestFact::id).collect();
    let mut requirement_support = Vec::new();
    for (id, requirement) in &graph.requirements {
        let testing_module = boundary_by_parent
            .get(requirement.owner())
            .copied()
            .map(str::to_owned);
        let observed_tests = requirement
            .tests()
            .iter()
            .filter(|test| observed_ids.contains(test.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let complete = testing_module.is_some()
            && !requirement.tests().is_empty()
            && (graph.observed_tests.is_none()
                || observed_tests.len() == requirement.tests().len());
        let derivation = format!("verification_support:{id}");
        derivations.push(CcgDerivation {
            id: derivation.clone(),
            kind: "verification_support".into(),
            fact: format!("requirement_support:{id}"),
            input_facts: std::iter::once(format!("requirement:{id}"))
                .chain(
                    testing_module
                        .iter()
                        .map(|module| format!("testing_boundary:{}:{module}", requirement.owner())),
                )
                .chain(
                    requirement
                        .tests()
                        .iter()
                        .map(|test| format!("declared_test:{id}:{test}")),
                )
                .collect(),
            explanation_path: vec![
                requirement.feature().into(),
                id.clone(),
                testing_module
                    .clone()
                    .unwrap_or_else(|| "unresolved".into()),
            ],
            provenance_closure: vec![provenance(requirement.provenance())],
        });
        requirement_support.push(CcgRequirementSupport {
            requirement: id.clone(),
            owner: requirement.owner().into(),
            feature: requirement.feature().into(),
            testing_module,
            declared_tests: requirement.tests().to_vec(),
            observed_tests,
            complete_declared_support: complete,
            derivation,
        });
    }
    requirement_support
}

fn guarantee_facts(
    graph: &ContractCoherencyGraph,
    verification: &CcgVerification,
    derivations: &mut Vec<CcgDerivation>,
) -> Vec<CcgGuarantee> {
    let support_by_requirement: BTreeMap<&str, &CcgRequirementSupport> = verification
        .requirement_support
        .iter()
        .map(|support| (support.requirement.as_str(), support))
        .collect();
    let mut facts = Vec::new();
    for (id, ownership) in &graph.guarantees {
        let module = &graph.modules[ownership.owner()];
        let guarantee = module
            .contract()
            .guarantees()
            .iter()
            .find(|guarantee| guarantee.id() == id)
            .expect("indexed guarantee must remain in its source contract");
        let support_topology: Vec<CcgGuaranteeSupport> = guarantee
            .requirements()
            .iter()
            .map(|requirement_id| {
                let requirement = &graph.requirements[requirement_id];
                let support = support_by_requirement.get(requirement_id.as_str());
                let derivation = format!("guarantee_support:{id}:{requirement_id}");
                derivations.push(CcgDerivation {
                    id: derivation.clone(),
                    kind: "guarantee_support".into(),
                    fact: format!("guarantee_requirement_support:{id}:{requirement_id}"),
                    input_facts: vec![
                        format!("guarantee:{id}"),
                        format!("requirement_support:{requirement_id}"),
                    ],
                    explanation_path: vec![
                        id.clone(),
                        requirement_id.clone(),
                        requirement.feature().into(),
                        support
                            .and_then(|value| value.testing_module.clone())
                            .unwrap_or_else(|| "unresolved".into()),
                    ],
                    provenance_closure: vec![
                        provenance(ownership.provenance()),
                        provenance(requirement.provenance()),
                    ],
                });
                CcgGuaranteeSupport {
                    requirement: requirement_id.clone(),
                    feature: requirement.feature().into(),
                    testing_module: support.and_then(|value| value.testing_module.clone()),
                    declared_tests: requirement.tests().to_vec(),
                    derivation,
                }
            })
            .collect();
        facts.push(CcgGuarantee {
            id: id.clone(),
            owner: ownership.owner().into(),
            subject_kind: guarantee_subject_kind(guarantee.subject().kind()).into(),
            subject_id: guarantee.subject().id().into(),
            backing_requirements: guarantee.requirements().to_vec(),
            complete_declared_verification_obligations: support_topology.iter().all(|support| {
                support.testing_module.is_some() && !support.declared_tests.is_empty()
            }),
            support_topology,
            provenance: provenance(ownership.provenance()),
        });
    }
    facts
}

fn behavior_facts(graph: &ContractCoherencyGraph) -> Vec<CcgBehavior> {
    let mut facts = Vec::new();
    for (owner, module) in &graph.modules {
        for (index, checkpoint) in module.contract().behavior().iter().enumerate() {
            facts.push(CcgBehavior {
                id: checkpoint.id().into(),
                owner: owner.clone(),
                feature: checkpoint.feature().into(),
                kind: match checkpoint.kind() {
                    super::CheckpointKind::Trigger => "trigger",
                    super::CheckpointKind::Action => "action",
                    super::CheckpointKind::Decision => "decision",
                    super::CheckpointKind::Terminal => "terminal",
                }
                .into(),
                outcome: checkpoint.outcome().map(str::to_owned),
                transitions: checkpoint
                    .transitions()
                    .iter()
                    .map(|transition| CcgTransition {
                        outcome: transition.outcome().map(str::to_owned),
                        target: transition.target().into(),
                    })
                    .collect(),
                provenance: source(module.contract_path(), &format!("/behavior/{index}")),
            });
        }
    }
    facts
}

fn source_provenance(graph: &ContractCoherencyGraph) -> Vec<CcgSourceProvenance> {
    let mut sources = BTreeSet::new();
    for module in graph.modules.values() {
        sources.insert(source(module.contract_path(), "/"));
    }
    for rule in graph.standard.rules.values() {
        sources.insert(source(&rule.source_path, "/logic"));
    }
    if let Some(tests) = &graph.observed_tests {
        for test in tests {
            sources.insert(source(test.path(), &format!("symbol:{}", test.symbol())));
        }
    }
    sources.into_iter().collect()
}

fn dependency_paths(
    requirements: &[super::ResolvedCapabilityRequirement],
) -> BTreeMap<(String, String), Vec<String>> {
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    let mut modules = BTreeSet::new();
    for requirement in requirements {
        adjacency
            .entry(requirement.consumer().into())
            .or_default()
            .insert(requirement.provider().into());
        modules.insert(requirement.consumer().to_owned());
        modules.insert(requirement.provider().to_owned());
    }
    let mut paths = BTreeMap::new();
    for source_id in modules {
        let mut queue = VecDeque::<Vec<String>>::new();
        if let Some(neighbors) = adjacency.get(&source_id) {
            queue.extend(
                neighbors
                    .iter()
                    .map(|target| vec![source_id.clone(), target.clone()]),
            );
        }
        while let Some(path) = queue.pop_front() {
            let target = path
                .last()
                .expect("dependency path cannot be empty")
                .clone();
            let key = (source_id.clone(), target.clone());
            let improves = paths
                .get(&key)
                .is_none_or(|existing: &Vec<String>| canonical_path_is_better(&path, existing));
            if !improves {
                continue;
            }
            paths.insert(key, path.clone());
            if target == source_id {
                continue;
            }
            if let Some(neighbors) = adjacency.get(&target) {
                for neighbor in neighbors {
                    if neighbor == &source_id || !path.contains(neighbor) {
                        let mut next = path.clone();
                        next.push(neighbor.clone());
                        queue.push_back(next);
                    }
                }
            }
        }
    }
    paths
}

fn canonical_path_is_better(candidate: &[String], existing: &[String]) -> bool {
    candidate.len() < existing.len() || (candidate.len() == existing.len() && candidate < existing)
}

fn dependency_cycles(requirements: &[super::ResolvedCapabilityRequirement]) -> Vec<Vec<String>> {
    let paths = dependency_paths(requirements);
    let mut cycles = BTreeSet::new();
    for ((source_id, target_id), path) in paths {
        if source_id != target_id || path.len() < 2 {
            continue;
        }
        let body = &path[..path.len() - 1];
        let Some((offset, _)) = body.iter().enumerate().min_by_key(|(_, id)| *id) else {
            continue;
        };
        let mut canonical = body[offset..].to_vec();
        canonical.extend_from_slice(&body[..offset]);
        canonical.push(canonical[0].clone());
        cycles.insert(canonical);
    }
    cycles.into_iter().collect()
}

fn implication_paths(graph: &ContractCoherencyGraph) -> BTreeMap<(String, String), Vec<String>> {
    let adjacency: BTreeMap<String, BTreeSet<String>> = graph
        .standard
        .rules
        .iter()
        .map(|(id, logic)| (id.clone(), logic.implies.iter().cloned().collect()))
        .collect();
    let mut paths = BTreeMap::new();
    for source_id in &graph.standard.rule_ids {
        paths.insert(
            (source_id.clone(), source_id.clone()),
            vec![source_id.clone()],
        );
        let mut queue = VecDeque::from([vec![source_id.clone()]]);
        while let Some(path) = queue.pop_front() {
            let current = path.last().expect("implication path cannot be empty");
            if let Some(targets) = adjacency.get(current) {
                for target in targets {
                    let mut next = path.clone();
                    next.push(target.clone());
                    let key = (source_id.clone(), target.clone());
                    let improves = paths.get(&key).is_none_or(|existing: &Vec<String>| {
                        canonical_path_is_better(&next, existing)
                    });
                    if improves {
                        paths.insert(key, next.clone());
                        if !path.contains(target) {
                            queue.push_back(next);
                        }
                    }
                }
            }
        }
    }
    paths
}

fn conflict_pairs(graph: &ContractCoherencyGraph) -> BTreeSet<(String, String)> {
    graph
        .standard
        .rules
        .iter()
        .flat_map(|(id, logic)| {
            logic.conflicts_with.iter().map(move |target| {
                if id < target {
                    (id.clone(), target.clone())
                } else {
                    (target.clone(), id.clone())
                }
            })
        })
        .collect()
}

// Keeping the recursive Testing structure and observed evidence checks in one
// ordered pass prevents separate evaluators from becoming competing topology.
#[allow(clippy::too_many_lines)]
fn verification_violations(graph: &ContractCoherencyGraph) -> Vec<CcgViolation> {
    let mut findings = Vec::new();
    let path_to_id: BTreeMap<&str, &str> = graph
        .modules
        .iter()
        .map(|(id, module)| (module.path(), id.as_str()))
        .collect();
    for (id, module) in &graph.modules {
        let testing_path = direct_testing_path(module.path());
        let testing_id = path_to_id.get(testing_path.as_str()).copied();
        if !module.contract().features().is_empty() && testing_id.is_none() {
            findings.push(semantic_violation(
                "CCG-TESTING-MISSING",
                module.contract_path(),
                "/features",
                format!("Feature-owning Module `{id}` has no direct `mods/testing` child"),
            ));
        }
        if module.contract().features().is_empty() && testing_id.is_some() {
            findings.push(semantic_violation(
                "CCG-TESTING-UNEXPECTED",
                module.contract_path(),
                "/features",
                format!("Featureless Module `{id}` has a direct canonical Testing child"),
            ));
        }
        if is_testing_module(module.path()) {
            let parent = module.parent_id().unwrap_or_default();
            let expected: Vec<&str> = graph
                .modules
                .get(parent)
                .map(|parent| {
                    parent
                        .contract()
                        .features()
                        .iter()
                        .map(super::ContractFeature::id)
                        .collect()
                })
                .unwrap_or_default();
            let relationships = module.contract().relationships();
            let exact = relationships.len() == 1
                && relationships[0].kind() == ModuleRelationshipType::Verifies
                && relationships[0].target() == parent
                && relationships[0]
                    .subjects()
                    .iter()
                    .map(String::as_str)
                    .eq(expected.iter().copied());
            if !exact {
                findings.push(semantic_violation(
                    "CCG-TESTING-SUBJECT-MISMATCH", module.contract_path(), "/relationships",
                    format!("Testing Module `{id}` must declare exactly one `verifies` relationship to its parent with exact local Feature subjects [{}]", expected.join(", "))));
            }
            if !module.contract().provides().is_empty()
                || !module.contract().guarantees().is_empty()
                || !module.contract().features().is_empty()
                || !module.contract().behavior().is_empty()
            {
                findings.push(semantic_violation(
                    "CCG-TESTING-ROLE",
                    module.contract_path(),
                    "/",
                    format!("canonical Testing Module `{id}` must keep `provides`, `guarantees`, `features`, and `behavior` empty"),
                ));
            }
        }
        if module.path() == "mods/tests"
            || module.path().ends_with("/mods/tests")
            || module.path().ends_with("/mods/unit_tests")
            || module.path().ends_with("/mods/integration_tests")
            || module.path().ends_with("/mods/e2e_tests")
        {
            findings.push(semantic_violation(
                "CCG-TESTING-TAXONOMY",
                module.contract_path(),
                "/",
                format!("Module `{id}` uses a prohibited parallel testing taxonomy"),
            ));
        }
    }
    if let Some(tests) = &graph.observed_tests {
        let mut declared_by_test =
            BTreeMap::<&str, Vec<(&str, &super::ResolvedRequirement)>>::new();
        for (requirement_id, requirement) in &graph.requirements {
            for test in requirement.tests() {
                declared_by_test
                    .entry(test)
                    .or_default()
                    .push((requirement_id, requirement));
            }
        }
        for (test, declarations) in &declared_by_test {
            if declarations.len() > 1 {
                let (requirement_id, requirement) = declarations[0];
                findings.push(semantic_violation(
                    "CCG-TRACE-TEST-MULTIPLE-REQUIREMENTS",
                    requirement.provenance().contract_path(),
                    requirement.provenance().pointer(),
                    format!(
                        "declared test `{test}` is assigned to multiple requirements including `{requirement_id}`"
                    ),
                ));
            }
        }
        let mut observed = BTreeMap::<&str, Vec<&CcgObservedTestFact>>::new();
        for test in tests {
            observed.entry(test.id()).or_default().push(test);
        }
        for (id, facts) in observed {
            if facts.len() > 1 {
                findings.push(semantic_violation(
                    "CCG-TEST-DUPLICATE",
                    facts[0].path(),
                    &format!("symbol:{}", facts[0].symbol()),
                    format!("test ID `{id}` is observed more than once"),
                ));
            }
        }
        for test in tests {
            if test.classification() == CcgTestClassification::Infrastructure {
                if declared_by_test.contains_key(test.id()) {
                    findings.push(semantic_violation(
                        "CCG-TRACE-INFRASTRUCTURE-EVIDENCE",
                        test.path(),
                        &format!("symbol:{}", test.symbol()),
                        format!(
                            "infrastructure tests cannot satisfy Feature coverage; `{}` is declared as evidence",
                            test.id()
                        ),
                    ));
                }
                continue;
            }
            let Some(requirement_id) = test.declared_requirement() else {
                findings.push(semantic_violation(
                    "CCG-TEST-REQUIREMENT-MISSING",
                    test.path(),
                    &format!("symbol:{}", test.symbol()),
                    format!(
                        "test `{}` has no explicit `Fortress requirement:` marker",
                        test.id()
                    ),
                ));
                continue;
            };
            let Some(requirement) = graph.requirements.get(requirement_id) else {
                findings.push(semantic_violation(
                    "CCG-TEST-REQUIREMENT-UNKNOWN",
                    test.path(),
                    &format!("symbol:{}", test.symbol()),
                    format!(
                        "test `{}` declares unknown requirement `{requirement_id}`",
                        test.id()
                    ),
                ));
                continue;
            };
            if !requirement.tests().iter().any(|id| id == test.id()) {
                findings.push(semantic_violation(
                    "CCG-TRACE-TEST-REQUIREMENT-MISMATCH",
                    test.path(),
                    &format!("symbol:{}", test.symbol()),
                    format!(
                        "requirement `{requirement_id}` does not reference the test `{}`",
                        test.id()
                    ),
                ));
            }
            let testing_owner = testing_module_for_source(graph, test.path());
            let expected_testing = graph
                .modules
                .get(requirement.owner())
                .map(|owner| direct_testing_path(owner.path()))
                .and_then(|path| path_to_id.get(path.as_str()).copied())
                .map(str::to_owned);
            if testing_owner != expected_testing {
                findings.push(semantic_violation(
                    "CCG-TEST-BOUNDARY",
                    test.path(),
                    &format!("symbol:{}", test.symbol()),
                    format!(
                        "test `{}` is not directly beneath the Testing Module for requirement owner `{}`",
                        test.id(),
                        requirement.owner()
                    ),
                ));
            }
        }
    }
    findings
}

fn direct_testing_path(parent: &str) -> String {
    if parent.is_empty() {
        "mods/testing".into()
    } else {
        format!("{parent}/mods/testing")
    }
}
fn is_testing_module(path: &str) -> bool {
    path == "mods/testing" || path.ends_with("/mods/testing")
}
fn testing_module_for_source(graph: &ContractCoherencyGraph, path: &str) -> Option<String> {
    graph
        .modules
        .iter()
        .filter(|(_, module)| is_testing_module(module.path()))
        .find(|(_, module)| {
            path.strip_prefix(&format!("{}/code/", module.path()))
                .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
        })
        .map(|(id, _)| id.clone())
}
fn semantic_violation(code: &str, path: &str, pointer: &str, message: String) -> CcgViolation {
    CcgViolation {
        code: code.into(),
        path: path.into(),
        pointer: pointer.into(),
        message,
        input_facts: vec![format!("source:{path}:{pointer}")],
        provenance_closure: vec![source(path, pointer)],
    }
}
fn source(path: &str, pointer: &str) -> CcgSourceProvenance {
    CcgSourceProvenance::new(path, pointer)
}
fn provenance(value: &super::ContractProvenance) -> CcgSourceProvenance {
    source(value.contract_path(), value.pointer())
}
fn constraint_scope(scope: ConstraintScope) -> &'static str {
    match scope {
        ConstraintScope::SelfOnly => "self",
        ConstraintScope::Subtree => "subtree",
    }
}
fn guarantee_subject_kind(kind: GuaranteeSubjectKind) -> &'static str {
    match kind {
        GuaranteeSubjectKind::Module => "module",
        GuaranteeSubjectKind::Capability => "capability",
        GuaranteeSubjectKind::Feature => "feature",
    }
}
