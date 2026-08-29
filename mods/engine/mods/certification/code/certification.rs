//! Content-addressed evidence, snapshot certification, and Verified BFG semantics.
//!
//! Certification consumes conclusions from the semantic stack. It never
//! re-evaluates their underlying meaning. The types in this module deliberately
//! distinguish authored authority, observed implementation, static proof,
//! executed verification, and trusted assertions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Evidence Graph schema version.
pub const EVIDENCE_GRAPH_SCHEMA_VERSION: u16 = 1;
/// Certification Profile schema version.
pub const CERTIFICATION_PROFILE_SCHEMA_VERSION: u16 = 1;
/// Certification result schema version.
pub const CERTIFICATION_SCHEMA_VERSION: u16 = 1;
/// Verified Behavioral Flow Graph schema version.
pub const VERIFIED_BFG_SCHEMA_VERSION: u16 = 1;
/// Certification semantic implementation version.
pub const CERTIFICATION_SEMANTIC_VERSION: &str = "1.0.0";
/// Canonical full-snapshot profile identity.
pub const FULL_SNAPSHOT_PROFILE_ID: &str = "CERT-FULL-SNAPSHOT-V1";
/// Semantic artifact kinds mandatory for full-snapshot certification.
pub const MANDATORY_SEMANTIC_ARTIFACTS: [&str; 9] = [
    "ccg",
    "environmental_analysis",
    "information_flow",
    "intended_bfg",
    "psm",
    "realized_bfg",
    "reference_resolution",
    "semantic_analysis",
    "state_effect",
];

/// Generated semantic projections excluded from certification source identity.
///
/// This is the one canonical exclusion registry. Authored data, source,
/// contracts, documentation, and lockfiles are intentionally absent.
pub const GENERATED_CERTIFICATION_PROJECTIONS: &[&str] = &[
    "info/behavioral_flow_graph.json",
    "info/certification.json",
    "info/component_resolution_index.json",
    "info/contract_coherency_graph.json",
    "info/environmental_analysis.json",
    "info/evidence_graph.json",
    "info/information_flow_analysis.json",
    "info/program_semantic_model.json",
    "info/quality_certificate.json",
    "info/realized_behavioral_flow_graph.json",
    "info/semantic_analysis.json",
    "info/state_effect_analysis.json",
    "info/verified_behavioral_flow_graph.json",
];

/// Closed evidence-authority vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClass {
    /// Authored or canonically derived semantic authority.
    Authority,
    /// Snapshot-bound implementation observation.
    Observation,
    /// Deterministic proof produced by a semantic evaluator.
    StaticProof,
    /// Actual eligible test-suite execution evidence.
    ExecutedTest,
    /// Actual execution evidence for a bound generated scenario.
    ExecutedScenario,
    /// Explicitly trusted assertion, never relabeled as proof.
    TrustedAssertion,
    /// Deterministic aggregation over other evidence.
    Aggregate,
}

/// Result vocabulary carried by evidence nodes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceResult {
    /// The evidenced proposition holds.
    Pass,
    /// Current evidence proves the proposition false.
    Fail,
    /// The producing analyzer cannot establish the proposition.
    Unsupported,
    /// The evidence or authority is invalid.
    Invalid,
    /// The evidence is an observed fact without a truth verdict.
    Observed,
    /// The evidence is an explicitly trusted assertion.
    Asserted,
}

/// Immutable content-addressed evidence node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceNode {
    id: String,
    kind: String,
    subject: String,
    result: EvidenceResult,
    inputs: Vec<String>,
    producer: String,
    producer_semantic_version: String,
    evidence_class: EvidenceClass,
    payload: Value,
}

#[derive(Serialize)]
struct EvidenceNodeBody<'a> {
    kind: &'a str,
    subject: &'a str,
    result: EvidenceResult,
    inputs: &'a [String],
    producer: &'a str,
    producer_semantic_version: &'a str,
    evidence_class: EvidenceClass,
    payload: &'a Value,
}

impl EvidenceNode {
    /// Creates a canonical node and derives its immutable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationError`] for empty identities or non-canonical
    /// input ordering.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: impl Into<String>,
        subject: impl Into<String>,
        result: EvidenceResult,
        mut inputs: Vec<String>,
        producer: impl Into<String>,
        producer_semantic_version: impl Into<String>,
        evidence_class: EvidenceClass,
        payload: Value,
    ) -> Result<Self, CertificationError> {
        let kind = kind.into();
        let subject = subject.into();
        let producer = producer.into();
        let producer_semantic_version = producer_semantic_version.into();
        if kind.is_empty()
            || subject.is_empty()
            || producer.is_empty()
            || producer_semantic_version.is_empty()
        {
            return Err(CertificationError::EmptyNodeField);
        }
        inputs.sort();
        inputs.dedup();
        let id = digest_json(&EvidenceNodeBody {
            kind: &kind,
            subject: &subject,
            result,
            inputs: &inputs,
            producer: &producer,
            producer_semantic_version: &producer_semantic_version,
            evidence_class,
            payload: &payload,
        })?;
        Ok(Self {
            id,
            kind,
            subject,
            result,
            inputs,
            producer,
            producer_semantic_version,
            evidence_class,
            payload,
        })
    }

    /// Returns the content-addressed node identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the evidence kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// Returns the semantic subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Returns the node result.
    #[must_use]
    pub const fn result(&self) -> EvidenceResult {
        self.result
    }
    /// Returns the immutable dependency references.
    #[must_use]
    pub fn inputs(&self) -> &[String] {
        &self.inputs
    }
    /// Returns the evidence authority class.
    #[must_use]
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    fn recompute_id(&self) -> Result<String, CertificationError> {
        digest_json(&EvidenceNodeBody {
            kind: &self.kind,
            subject: &self.subject,
            result: self.result,
            inputs: &self.inputs,
            producer: &self.producer,
            producer_semantic_version: &self.producer_semantic_version,
            evidence_class: self.evidence_class,
            payload: &self.payload,
        })
    }
}

/// Deterministic content-addressed Evidence DAG.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceGraph {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    subject: String,
    standard: StandardIdentity,
    profile: ProfileIdentity,
    nodes: Vec<EvidenceNode>,
    root_obligations: Vec<String>,
    coverage: EvidenceCoverage,
    provenance: Vec<String>,
}

impl EvidenceGraph {
    /// Creates, sorts, and validates a graph.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationError`] when any DAG invariant fails.
    pub fn new(
        subject: impl Into<String>,
        standard: StandardIdentity,
        profile: ProfileIdentity,
        mut nodes: Vec<EvidenceNode>,
        mut root_obligations: Vec<String>,
        provenance: Vec<String>,
    ) -> Result<Self, CertificationError> {
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        root_obligations.sort();
        root_obligations.dedup();
        let coverage = EvidenceCoverage::from_nodes(&nodes);
        let graph = Self {
            schema: "urn:fortress:schema:v1:evidence-graph".into(),
            schema_version: EVIDENCE_GRAPH_SCHEMA_VERSION,
            subject: subject.into(),
            standard,
            profile,
            nodes,
            root_obligations,
            coverage,
            provenance,
        };
        graph.validate()?;
        Ok(graph)
    }

    /// Validates content identities, references, ordering, and acyclicity.
    ///
    /// # Errors
    ///
    /// Returns a normalized structural or cryptographic validation error.
    pub fn validate(&self) -> Result<(), CertificationError> {
        if self.schema_version != EVIDENCE_GRAPH_SCHEMA_VERSION {
            return Err(CertificationError::InvalidSchemaVersion(
                self.schema_version,
            ));
        }
        let mut previous: Option<&str> = None;
        let mut by_id = BTreeMap::new();
        let mut semantic_nodes = BTreeMap::new();
        for node in &self.nodes {
            if previous.is_some_and(|value| value > node.id()) {
                return Err(CertificationError::NonCanonicalNodeOrdering);
            }
            previous = Some(node.id());
            if node.inputs.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(CertificationError::NonCanonicalInputOrdering(
                    node.id.clone(),
                ));
            }
            if by_id.insert(node.id.as_str(), node).is_some() {
                return Err(CertificationError::DuplicateNode(node.id.clone()));
            }
            let semantic_key = (node.kind.as_str(), node.subject.as_str());
            if let Some(previous_id) = semantic_nodes.insert(semantic_key, node.id.as_str())
                && previous_id != node.id()
            {
                return Err(CertificationError::ConflictingSemanticNode {
                    kind: node.kind.clone(),
                    subject: node.subject.clone(),
                });
            }
        }
        for node in &self.nodes {
            for input in &node.inputs {
                if !by_id.contains_key(input.as_str()) {
                    return Err(CertificationError::MissingInput {
                        node: node.id.clone(),
                        input: input.clone(),
                    });
                }
            }
        }
        for root in &self.root_obligations {
            if !by_id.contains_key(root.as_str()) {
                return Err(CertificationError::MissingRoot(root.clone()));
            }
        }
        validate_acyclic(&self.nodes)?;
        for node in &self.nodes {
            if node.recompute_id()? != node.id {
                return Err(CertificationError::NodeDigestMismatch(node.id.clone()));
            }
        }
        Ok(())
    }

    /// Returns nodes in content-address order.
    #[must_use]
    pub fn nodes(&self) -> &[EvidenceNode] {
        &self.nodes
    }
    /// Returns root obligation references.
    #[must_use]
    pub fn root_obligations(&self) -> &[String] {
        &self.root_obligations
    }
    /// Returns the exact source subject digest.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Returns counts by evidence class.
    #[must_use]
    pub const fn coverage(&self) -> &EvidenceCoverage {
        &self.coverage
    }

    /// Derives every node transitively affected by changed node identities.
    #[must_use]
    pub fn affected(&self, changed: &BTreeSet<String>) -> BTreeSet<String> {
        let mut reverse: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for node in &self.nodes {
            for input in &node.inputs {
                reverse.entry(input).or_default().push(node.id());
            }
        }
        let mut affected = changed.clone();
        let mut queue: VecDeque<String> = changed.iter().cloned().collect();
        while let Some(current) = queue.pop_front() {
            if let Some(dependents) = reverse.get(current.as_str()) {
                for dependent in dependents {
                    if affected.insert((*dependent).to_owned()) {
                        queue.push_back((*dependent).to_owned());
                    }
                }
            }
        }
        affected
    }

    /// Serializes canonical pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        canonical_pretty(self)
    }
}

/// Standard identity bound into evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StandardIdentity {
    /// Stable Standard identity.
    pub id: String,
    /// Exact Standard edition.
    pub edition: String,
}

/// Certification profile identity bound into evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileIdentity {
    /// Stable profile identity.
    pub id: String,
    /// Exact profile schema/semantic version.
    pub version: u16,
}

/// Evidence counts by authority class.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCoverage {
    /// Authority nodes.
    pub authority: usize,
    /// Observation nodes.
    pub observation: usize,
    /// Static proof nodes.
    pub static_proof: usize,
    /// Executed test nodes.
    pub executed_test: usize,
    /// Executed scenario nodes.
    pub executed_scenario: usize,
    /// Trusted assertion nodes.
    pub trusted_assertion: usize,
    /// Aggregate nodes.
    pub aggregate: usize,
}

impl EvidenceCoverage {
    fn from_nodes(nodes: &[EvidenceNode]) -> Self {
        let mut value = Self::default();
        for node in nodes {
            match node.evidence_class {
                EvidenceClass::Authority => value.authority += 1,
                EvidenceClass::Observation => value.observation += 1,
                EvidenceClass::StaticProof => value.static_proof += 1,
                EvidenceClass::ExecutedTest => value.executed_test += 1,
                EvidenceClass::ExecutedScenario => value.executed_scenario += 1,
                EvidenceClass::TrustedAssertion => value.trusted_assertion += 1,
                EvidenceClass::Aggregate => value.aggregate += 1,
            }
        }
        value
    }
}

/// Exact certification aggregate status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificationStatus {
    /// Every mandatory obligation has sufficient current evidence.
    Pass,
    /// Required evidence is absent or unsupported.
    Missing,
    /// Evidence is valid but bound to previous inputs.
    Stale,
    /// Current valid evidence proves a mandatory obligation false.
    Fail,
    /// Profile or evidence structure is invalid.
    Invalid,
}

impl CertificationStatus {
    /// Combines statuses using `INVALID > FAIL > STALE > MISSING > PASS`.
    #[must_use]
    pub fn aggregate(values: impl IntoIterator<Item = Self>) -> Self {
        values.into_iter().max().unwrap_or(Self::Pass)
    }
}

/// Canonical obligation kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificationObligationKind {
    /// Applicable Standard rule.
    StandardRule,
    /// Feature Requirement verification chain.
    FeatureRequirement,
    /// Behavioral realization coherence.
    BehavioralRealization,
    /// Behavioral verification obligation.
    BehavioralVerification,
    /// Environmental scenario obligation.
    EnvironmentalVerification,
    /// Semantic artifact freshness.
    ArtifactFreshness,
}

/// One deterministic certification obligation and its supporting evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationObligation {
    /// Obligation kind.
    pub kind: CertificationObligationKind,
    /// Stable semantic subject.
    pub subject: String,
    /// Accepted evidence classes.
    pub required_evidence_classes: Vec<EvidenceClass>,
    /// Content-addressed supporting evidence references.
    pub evidence_refs: Vec<String>,
    /// Derived status.
    pub status: CertificationStatus,
    /// Deterministic explanation.
    pub reason: String,
}

/// Canonical certification result whose digest is the root evidence node ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationResult {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    profile: ProfileIdentity,
    subject: String,
    status: CertificationStatus,
    certification_digest: String,
    evidence_graph_digest: String,
    obligations: Vec<CertificationObligation>,
    summary: CertificationSummary,
    trusted_assertion_dependencies: Vec<String>,
}

impl CertificationResult {
    /// Returns aggregate certification state.
    #[must_use]
    pub const fn status(&self) -> CertificationStatus {
        self.status
    }
    /// Returns the content-addressed root digest.
    #[must_use]
    pub fn certification_digest(&self) -> &str {
        &self.certification_digest
    }
    /// Returns all root obligations.
    #[must_use]
    pub fn obligations(&self) -> &[CertificationObligation] {
        &self.obligations
    }
    /// Returns summary counts.
    #[must_use]
    pub const fn summary(&self) -> &CertificationSummary {
        &self.summary
    }
    /// Serializes canonical pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        canonical_pretty(self)
    }
}

/// Certification obligation counts.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationSummary {
    /// Total obligations.
    pub obligations: usize,
    /// Passing obligations.
    pub pass: usize,
    /// Failed obligations.
    pub fail: usize,
    /// Missing obligations.
    pub missing: usize,
    /// Stale obligations.
    pub stale: usize,
    /// Invalid obligations.
    pub invalid: usize,
    /// Trusted assertions in the dependency closure.
    pub trusted_assertions: usize,
}

/// Canonical certification profile.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationProfile {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Stable profile identity.
    pub id: String,
    /// Whether all applicable rules must be supported and pass.
    pub require_all_applicable_rules: bool,
    /// Whether all declared Requirement tests must execute.
    pub require_all_requirement_tests: bool,
    /// Whether opted-in behavioral realization must be coherent.
    pub require_behavioral_realization: bool,
    /// Whether generated verification obligations must execute.
    pub require_generated_verification: bool,
    /// Whether every mandatory semantic artifact must be current.
    pub require_current_artifacts: bool,
}

impl CertificationProfile {
    /// Returns the canonical full-snapshot profile.
    #[must_use]
    pub fn full_snapshot() -> Self {
        Self {
            schema: "urn:fortress:schema:v1:certification-profile".into(),
            schema_version: CERTIFICATION_PROFILE_SCHEMA_VERSION,
            id: FULL_SNAPSHOT_PROFILE_ID.into(),
            require_all_applicable_rules: true,
            require_all_requirement_tests: true,
            require_behavioral_realization: true,
            require_generated_verification: true,
            require_current_artifacts: true,
        }
    }

    /// Validates profile identity and v1 mandatory semantics.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationError`] for a malformed or weakened full profile.
    pub fn validate(&self) -> Result<(), CertificationError> {
        if self.schema_version != CERTIFICATION_PROFILE_SCHEMA_VERSION || self.id.is_empty() {
            return Err(CertificationError::InvalidProfile);
        }
        if self.id == FULL_SNAPSHOT_PROFILE_ID
            && !(self.require_all_applicable_rules
                && self.require_all_requirement_tests
                && self.require_behavioral_realization
                && self.require_generated_verification
                && self.require_current_artifacts)
        {
            return Err(CertificationError::WeakenedFullProfile);
        }
        Ok(())
    }
}

/// Exact normalized Rust suite execution supplied by the execution boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RustSuiteExecution {
    /// Stable executor identity.
    pub executor: String,
    /// Executor semantic version.
    pub executor_version: String,
    /// Exact toolchain identity.
    pub toolchain: String,
    /// Exact certification source digest before and after execution.
    pub certification_source_digest: String,
    /// Digest of the eligible test inventory.
    pub test_inventory_digest: String,
    /// Whether the canonical unfiltered workspace/all-target/all-feature command ran.
    pub canonical_unfiltered: bool,
    /// Process result.
    pub passed: bool,
    /// Sorted eligible Test IDs proven included by the canonical suite.
    pub eligible_test_ids: Vec<String>,
    /// Sorted ignored Test IDs, which never satisfy execution evidence.
    pub ignored_test_ids: Vec<String>,
}

/// Snapshot-bound source and Rust test inventory prepared before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationSourceIdentity {
    /// Recursion-free exact repository source digest.
    pub digest: String,
    /// Sorted enabled Rust Test IDs.
    pub eligible_test_ids: Vec<String>,
    /// Sorted ignored Rust Test IDs.
    pub ignored_test_ids: Vec<String>,
    /// Digest of the enabled/ignored inventory.
    pub test_inventory_digest: String,
}

impl RustSuiteExecution {
    /// Validates canonical suite semantics and deterministic inventory ordering.
    ///
    /// # Errors
    ///
    /// Returns [`CertificationError`] for ambiguous or contradictory execution evidence.
    pub fn validate(&self) -> Result<(), CertificationError> {
        if self.executor.is_empty() || self.executor_version.is_empty() || self.toolchain.is_empty()
        {
            return Err(CertificationError::InvalidSuiteExecution);
        }
        if !is_strictly_sorted(&self.eligible_test_ids)
            || !is_strictly_sorted(&self.ignored_test_ids)
        {
            return Err(CertificationError::NonCanonicalTestInventory);
        }
        if self
            .eligible_test_ids
            .iter()
            .any(|id| self.ignored_test_ids.binary_search(id).is_ok())
        {
            return Err(CertificationError::ContradictoryTestEligibility);
        }
        if self.test_inventory_digest
            != test_inventory_digest(&self.eligible_test_ids, &self.ignored_test_ids)
        {
            return Err(CertificationError::TestInventoryDigestMismatch);
        }
        Ok(())
    }
}

/// One applicable rule result supplied by the canonical rule engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleEvidenceInput {
    /// Rule identity.
    pub rule_id: String,
    /// PASS, FAIL, UNSUPPORTED, or INVALID result.
    pub result: EvidenceResult,
    /// Whether the proof binds the current certification subject.
    pub current: bool,
    /// Normalized finding fingerprints.
    pub finding_fingerprints: Vec<String>,
    /// Exact semantic input evidence refs.
    pub input_refs: Vec<String>,
}

/// One canonical semantic artifact reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactEvidenceInput {
    /// Artifact semantic kind.
    pub kind: String,
    /// Canonical artifact digest.
    pub digest: String,
    /// Artifact schema identity/version.
    pub schema: String,
    /// Whether it was regenerated from current inputs.
    pub current: bool,
    /// Upstream evidence refs.
    pub input_refs: Vec<String>,
    /// Whether this artifact is observation rather than proof/authority.
    pub evidence_class: EvidenceClass,
    /// Explicit unsupported coverage labels.
    pub unsupported: Vec<String>,
}

/// One Feature Requirement and all its declared tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequirementEvidenceInput {
    /// Owning Feature identity.
    pub feature_id: String,
    /// Requirement identity.
    pub requirement_id: String,
    /// Declared required Test IDs.
    pub test_ids: Vec<String>,
}

/// Generated verification obligation category.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GeneratedVerificationKind {
    /// Behavioral checkpoint/edge/dominator obligation.
    Behavioral,
    /// Environmental fault/outcome scenario.
    Environmental,
}

/// One current generated verification obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedVerificationInput {
    /// Stable obligation identity.
    pub id: String,
    /// Owning Testing Module.
    pub testing_module: String,
    /// Behavioral or environmental provenance.
    pub kind: GeneratedVerificationKind,
    /// Related checkpoint/edge/scenario subjects.
    pub targets: Vec<String>,
}

/// Distributed mapping from one generated obligation to owned Test IDs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationBinding {
    /// Binding-owning Testing Module.
    pub testing_module: String,
    /// Current generated obligation identity.
    pub obligation: String,
    /// Sorted Test IDs owned by the Testing Module.
    pub tests: Vec<String>,
}

/// Opted-in behavioral realization aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehavioralRealizationEvidenceInput {
    /// Feature identity.
    pub feature: String,
    /// Whether current static semantics prove coherent realization.
    pub coherent: bool,
    /// Exact static proof artifact ref.
    pub evidence_ref: String,
}

/// Explicit trusted assertion dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAssertionInput {
    /// Stable assertion subject.
    pub subject: String,
    /// Authority kind such as endorsement, declassification, or atomicity.
    pub kind: String,
    /// Exact contract provenance.
    pub provenance: String,
}

/// Complete already-derived evidence inputs consumed by Certification.
#[derive(Clone, Debug)]
pub struct CertificationInput {
    /// Project identity.
    pub project_id: String,
    /// Exact certification source digest.
    pub source_digest: String,
    /// Standard identity/edition.
    pub standard: StandardIdentity,
    /// Certification profile.
    pub profile: CertificationProfile,
    /// Current semantic artifacts.
    pub artifacts: Vec<ArtifactEvidenceInput>,
    /// Complete sorted applicable Standard rule identities.
    pub applicable_rules: Vec<String>,
    /// Applicable Standard rule evaluations.
    pub rules: Vec<RuleEvidenceInput>,
    /// Feature Requirements.
    pub requirements: Vec<RequirementEvidenceInput>,
    /// Current Rust execution result.
    pub suite_execution: RustSuiteExecution,
    /// Opted-in realization results.
    pub behavioral_realizations: Vec<BehavioralRealizationEvidenceInput>,
    /// Generated verification obligations.
    pub generated_verification: Vec<GeneratedVerificationInput>,
    /// Distributed verification bindings.
    pub verification_bindings: Vec<VerificationBinding>,
    /// Trusted assertion dependencies.
    pub trusted_assertions: Vec<TrustedAssertionInput>,
    /// Intended/realized Feature projection used only for Verified BFG.
    pub behavioral_projection: Vec<BehavioralProjectionInput>,
}

/// Minimal meaningful Feature projection consumed by Verified BFG generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehavioralProjectionInput {
    /// Feature identity.
    pub feature: String,
    /// Checkpoint identities.
    pub checkpoints: Vec<String>,
    /// Intended edges `(source, target)`.
    pub intended_edges: Vec<(String, String)>,
    /// Realized checkpoint identities.
    pub realized_checkpoints: Vec<String>,
    /// Realized edges `(source, target)`.
    pub realized_edges: Vec<(String, String)>,
    /// Whether realization is contradicted.
    pub contradicted: bool,
}

/// Complete deterministic certification products.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationProducts {
    /// Content-addressed evidence graph.
    pub evidence_graph: EvidenceGraph,
    /// Profile result.
    pub certification: CertificationResult,
    /// Evidence-aware behavioral projection.
    pub verified_bfg: VerifiedBehavioralFlowGraph,
}

/// Compiles the Evidence DAG, certification aggregate, and Verified BFG.
///
/// # Errors
///
/// Returns [`CertificationError`] for invalid profile, suite evidence, node
/// graph, duplicate inputs, or conflicting bindings.
#[allow(clippy::too_many_lines)]
pub fn compile_certification(
    input: &CertificationInput,
) -> Result<CertificationProducts, CertificationError> {
    input.profile.validate()?;
    input.suite_execution.validate()?;
    if !input.applicable_rules.is_empty() && !is_strictly_sorted(&input.applicable_rules) {
        return Err(CertificationError::NonCanonicalApplicableRules);
    }
    let suite_current = input.suite_execution.certification_source_digest == input.source_digest;

    let profile_identity = ProfileIdentity {
        id: input.profile.id.clone(),
        version: CERTIFICATION_PROFILE_SCHEMA_VERSION,
    };
    let mut nodes = Vec::new();
    let source = EvidenceNode::new(
        "certification_source_snapshot",
        &input.project_id,
        EvidenceResult::Observed,
        Vec::new(),
        "fortress-certification-source",
        CERTIFICATION_SEMANTIC_VERSION,
        EvidenceClass::Observation,
        json!({"certification_source_digest": input.source_digest}),
    )?;
    let source_ref = source.id.clone();
    nodes.push(source);
    let standard = EvidenceNode::new(
        "standard",
        &input.standard.id,
        EvidenceResult::Pass,
        vec![source_ref.clone()],
        "fortress-standard-registry",
        CERTIFICATION_SEMANTIC_VERSION,
        EvidenceClass::Authority,
        json!({"edition": input.standard.edition}),
    )?;
    let standard_ref = standard.id.clone();
    nodes.push(standard);
    let profile = EvidenceNode::new(
        "certification_profile",
        &input.profile.id,
        EvidenceResult::Pass,
        vec![standard_ref.clone()],
        "fortress-certification",
        CERTIFICATION_SEMANTIC_VERSION,
        EvidenceClass::Authority,
        serde_json::to_value(&input.profile)?,
    )?;
    let profile_ref = profile.id.clone();
    nodes.push(profile);

    let mut artifact_refs = BTreeMap::new();
    let mut obligations = Vec::new();
    for artifact in sorted_artifacts(&input.artifacts)? {
        let mut refs = artifact
            .input_refs
            .iter()
            .filter_map(|kind| artifact_refs.get(kind).cloned())
            .collect::<Vec<_>>();
        refs.push(source_ref.clone());
        let node = EvidenceNode::new(
            format!("semantic_artifact:{}", artifact.kind),
            &artifact.kind,
            if artifact.current {
                EvidenceResult::Pass
            } else {
                EvidenceResult::Observed
            },
            refs,
            "fortress-semantic-artifact",
            CERTIFICATION_SEMANTIC_VERSION,
            artifact.evidence_class,
            json!({
                "artifact_digest": artifact.digest,
                "schema": artifact.schema,
                "current": artifact.current,
                "unsupported": artifact.unsupported,
            }),
        )?;
        artifact_refs.insert(artifact.kind.clone(), node.id.clone());
        nodes.push(node);
        obligations.push(CertificationObligation {
            kind: CertificationObligationKind::ArtifactFreshness,
            subject: artifact.kind.clone(),
            required_evidence_classes: vec![artifact.evidence_class],
            evidence_refs: vec![artifact_refs[&artifact.kind].clone()],
            status: if artifact.current {
                CertificationStatus::Pass
            } else {
                CertificationStatus::Stale
            },
            reason: if artifact.current {
                "artifact was regenerated from the current certification source".into()
            } else {
                "artifact is cryptographically valid but references prior semantic inputs".into()
            },
        });
    }
    if input.profile.require_current_artifacts {
        for kind in MANDATORY_SEMANTIC_ARTIFACTS {
            if !artifact_refs.contains_key(kind) {
                obligations.push(CertificationObligation {
                    kind: CertificationObligationKind::ArtifactFreshness,
                    subject: kind.into(),
                    required_evidence_classes: vec![EvidenceClass::StaticProof],
                    evidence_refs: Vec::new(),
                    status: CertificationStatus::Missing,
                    reason: "mandatory semantic artifact evidence is absent".into(),
                });
            }
        }
    }

    let suite = EvidenceNode::new(
        "rust_workspace_suite_execution",
        &input.project_id,
        if input.suite_execution.passed {
            EvidenceResult::Pass
        } else {
            EvidenceResult::Fail
        },
        vec![source_ref.clone()],
        &input.suite_execution.executor,
        &input.suite_execution.executor_version,
        EvidenceClass::ExecutedTest,
        json!({
            "command": [
                "cargo",
                "+1.97.1",
                "--config",
                "data/cargo_config.toml",
                "test",
                "--manifest-path",
                "data/Cargo.toml",
                "--workspace",
                "--all-targets",
                "--all-features"
            ],
            "toolchain": input.suite_execution.toolchain,
            "certification_source_digest": input.suite_execution.certification_source_digest,
            "test_inventory_digest": input.suite_execution.test_inventory_digest,
            "canonical_unfiltered": input.suite_execution.canonical_unfiltered,
            "eligible_test_ids": input.suite_execution.eligible_test_ids,
            "ignored_test_ids": input.suite_execution.ignored_test_ids,
        }),
    )?;
    let suite_ref = suite.id.clone();
    nodes.push(suite);
    let suite_sufficient =
        input.suite_execution.passed && input.suite_execution.canonical_unfiltered;
    let eligible: BTreeSet<&str> = input
        .suite_execution
        .eligible_test_ids
        .iter()
        .map(String::as_str)
        .collect();
    let ignored: BTreeSet<&str> = input
        .suite_execution
        .ignored_test_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut test_refs = BTreeMap::new();
    if suite_sufficient {
        for test_id in &input.suite_execution.eligible_test_ids {
            let node = EvidenceNode::new(
                "rust_test_execution",
                test_id,
                EvidenceResult::Pass,
                vec![suite_ref.clone()],
                &input.suite_execution.executor,
                &input.suite_execution.executor_version,
                EvidenceClass::ExecutedTest,
                json!({"derivation": "eligible member of successful canonical unfiltered suite"}),
            )?;
            test_refs.insert(test_id.clone(), node.id.clone());
            nodes.push(node);
        }
    }

    let expected_rules = input
        .applicable_rules
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let supplied_rules = input
        .rules
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(unexpected) = supplied_rules.difference(&expected_rules).next() {
        return Err(CertificationError::UnexpectedRuleEvidence(
            (*unexpected).into(),
        ));
    }
    for rule in sorted_rules(&input.rules)? {
        let mut refs = artifact_refs.values().cloned().collect::<Vec<_>>();
        refs.push(standard_ref.clone());
        let node = EvidenceNode::new(
            "standard_rule_evaluation",
            &rule.rule_id,
            rule.result,
            refs,
            "fortress-snapshot-rule-engine",
            CERTIFICATION_SEMANTIC_VERSION,
            EvidenceClass::StaticProof,
            json!({
                "standard_edition": input.standard.edition,
                "finding_fingerprints": rule.finding_fingerprints,
                "current": rule.current,
            }),
        )?;
        let status = match (rule.current, rule.result) {
            (_, EvidenceResult::Invalid) => CertificationStatus::Invalid,
            (false, _) => CertificationStatus::Stale,
            (true, EvidenceResult::Pass) => CertificationStatus::Pass,
            (true, EvidenceResult::Fail) => CertificationStatus::Fail,
            (true, EvidenceResult::Unsupported) => CertificationStatus::Missing,
            (true, EvidenceResult::Observed | EvidenceResult::Asserted) => {
                CertificationStatus::Invalid
            }
        };
        obligations.push(CertificationObligation {
            kind: CertificationObligationKind::StandardRule,
            subject: rule.rule_id.clone(),
            required_evidence_classes: vec![EvidenceClass::StaticProof],
            evidence_refs: vec![node.id.clone()],
            status,
            reason: match status {
                CertificationStatus::Pass => "applicable rule has current PASS proof".into(),
                CertificationStatus::Fail => {
                    "current rule evidence contains one or more findings".into()
                }
                CertificationStatus::Missing => {
                    "mandatory applicable rule remains unsupported".into()
                }
                CertificationStatus::Invalid => "rule evidence is invalid".into(),
                CertificationStatus::Stale => "rule evidence is stale".into(),
            },
        });
        nodes.push(node);
    }
    for missing_rule in expected_rules.difference(&supplied_rules) {
        obligations.push(CertificationObligation {
            kind: CertificationObligationKind::StandardRule,
            subject: (*missing_rule).into(),
            required_evidence_classes: vec![EvidenceClass::StaticProof],
            evidence_refs: Vec::new(),
            status: CertificationStatus::Missing,
            reason: "applicable Standard rule has no current evaluation evidence".into(),
        });
    }

    for requirement in sorted_requirements(&input.requirements)? {
        let mut refs = Vec::new();
        let mut missing = Vec::new();
        let mut ignored_tests = Vec::new();
        for test in &requirement.test_ids {
            if ignored.contains(test.as_str()) {
                ignored_tests.push(test.clone());
            } else if eligible.contains(test.as_str()) {
                if let Some(reference) = test_refs.get(test) {
                    refs.push(reference.clone());
                } else {
                    missing.push(test.clone());
                }
            } else {
                missing.push(test.clone());
            }
        }
        let status = if !suite_current {
            CertificationStatus::Stale
        } else if !input.suite_execution.passed {
            CertificationStatus::Fail
        } else if !input.suite_execution.canonical_unfiltered
            || !missing.is_empty()
            || !ignored_tests.is_empty()
        {
            CertificationStatus::Missing
        } else {
            CertificationStatus::Pass
        };
        obligations.push(CertificationObligation {
            kind: CertificationObligationKind::FeatureRequirement,
            subject: requirement.requirement_id.clone(),
            required_evidence_classes: vec![EvidenceClass::ExecutedTest],
            evidence_refs: refs,
            status,
            reason: match status {
                CertificationStatus::Pass => "every declared required test is eligible and covered by the successful canonical suite".into(),
                CertificationStatus::Fail => "the canonical required test suite failed".into(),
                _ => format!("missing tests: {}; ignored tests: {}", missing.join(","), ignored_tests.join(",")),
            },
        });
    }

    for realization in sorted_realizations(&input.behavioral_realizations)? {
        obligations.push(CertificationObligation {
            kind: CertificationObligationKind::BehavioralRealization,
            subject: realization.feature.clone(),
            required_evidence_classes: vec![EvidenceClass::StaticProof],
            evidence_refs: artifact_refs
                .get("realized_bfg")
                .cloned()
                .into_iter()
                .collect(),
            status: if realization.coherent {
                CertificationStatus::Pass
            } else {
                CertificationStatus::Fail
            },
            reason: if realization.coherent {
                "opted-in Feature has coherent current behavioral realization".into()
            } else {
                "current semantic proof contradicts opted-in behavioral realization".into()
            },
        });
    }

    let bindings = validate_bindings(&input.generated_verification, &input.verification_bindings)?;
    for generated in sorted_generated(&input.generated_verification)? {
        let binding = bindings.get(generated.id.as_str());
        let mut refs = Vec::new();
        let mut missing = Vec::new();
        if let Some(binding) = binding {
            for test in &binding.tests {
                if let Some(reference) = test_refs.get(test) {
                    refs.push(reference.clone());
                } else {
                    missing.push(test.clone());
                }
            }
        }
        let status =
            if !suite_current && binding.is_some() && missing.is_empty() && !refs.is_empty() {
                CertificationStatus::Stale
            } else if !input.suite_execution.passed {
                CertificationStatus::Fail
            } else if binding.is_none() || !missing.is_empty() || refs.is_empty() {
                CertificationStatus::Missing
            } else {
                CertificationStatus::Pass
            };
        let evidence_refs = if matches!(
            status,
            CertificationStatus::Pass | CertificationStatus::Stale
        ) {
            let scenario = EvidenceNode::new(
                match generated.kind {
                    GeneratedVerificationKind::Behavioral => "behavioral_verification_execution",
                    GeneratedVerificationKind::Environmental => "environmental_scenario_execution",
                },
                &generated.id,
                if status == CertificationStatus::Pass {
                    EvidenceResult::Pass
                } else {
                    EvidenceResult::Observed
                },
                refs,
                "fortress-certification",
                CERTIFICATION_SEMANTIC_VERSION,
                EvidenceClass::ExecutedScenario,
                json!({"testing_module": generated.testing_module, "targets": generated.targets}),
            )?;
            let reference = scenario.id.clone();
            nodes.push(scenario);
            vec![reference]
        } else {
            refs
        };
        obligations.push(CertificationObligation {
            kind: match generated.kind {
                GeneratedVerificationKind::Behavioral => {
                    CertificationObligationKind::BehavioralVerification
                }
                GeneratedVerificationKind::Environmental => {
                    CertificationObligationKind::EnvironmentalVerification
                }
            },
            subject: generated.id.clone(),
            required_evidence_classes: vec![EvidenceClass::ExecutedScenario],
            evidence_refs,
            status,
            reason: match status {
                CertificationStatus::Pass => {
                    "distributed verification binding is covered by current executed tests".into()
                }
                CertificationStatus::Fail => {
                    "the canonical suite supporting the generated scenario failed".into()
                }
                CertificationStatus::Stale => {
                    "bound execution evidence refers to a prior certification subject".into()
                }
                _ if binding.is_none() => "no distributed verification binding exists".into(),
                _ => format!(
                    "bound tests lack current execution evidence: {}",
                    missing.join(",")
                ),
            },
        });
    }

    let mut trusted_refs = Vec::new();
    let mut trusted_subjects = Vec::new();
    for assertion in sorted_assertions(&input.trusted_assertions)? {
        let node = EvidenceNode::new(
            &assertion.kind,
            &assertion.subject,
            EvidenceResult::Asserted,
            vec![source_ref.clone()],
            "fortress-distributed-authority",
            CERTIFICATION_SEMANTIC_VERSION,
            EvidenceClass::TrustedAssertion,
            json!({"provenance": assertion.provenance}),
        )?;
        trusted_refs.push(node.id.clone());
        trusted_subjects.push(assertion.subject.clone());
        nodes.push(node);
    }

    obligations.sort_by(|left, right| {
        (left.kind, left.subject.as_str()).cmp(&(right.kind, right.subject.as_str()))
    });
    let mut root_obligations = Vec::new();
    for obligation in &obligations {
        let mut inputs = obligation.evidence_refs.clone();
        inputs.push(profile_ref.clone());
        let node = EvidenceNode::new(
            format!("certification_obligation:{:?}", obligation.kind).to_ascii_lowercase(),
            &obligation.subject,
            match obligation.status {
                CertificationStatus::Pass => EvidenceResult::Pass,
                CertificationStatus::Fail => EvidenceResult::Fail,
                CertificationStatus::Invalid => EvidenceResult::Invalid,
                CertificationStatus::Missing | CertificationStatus::Stale => {
                    EvidenceResult::Unsupported
                }
            },
            inputs,
            "fortress-certification",
            CERTIFICATION_SEMANTIC_VERSION,
            EvidenceClass::Aggregate,
            serde_json::to_value(obligation)?,
        )?;
        root_obligations.push(node.id.clone());
        nodes.push(node);
    }
    let aggregate_status =
        CertificationStatus::aggregate(obligations.iter().map(|value| value.status));
    let mut root_inputs = root_obligations.clone();
    root_inputs.extend(trusted_refs.iter().cloned());
    let root = EvidenceNode::new(
        "certification_root",
        &input.project_id,
        match aggregate_status {
            CertificationStatus::Pass => EvidenceResult::Pass,
            CertificationStatus::Fail => EvidenceResult::Fail,
            CertificationStatus::Invalid => EvidenceResult::Invalid,
            CertificationStatus::Missing | CertificationStatus::Stale => {
                EvidenceResult::Unsupported
            }
        },
        root_inputs,
        "fortress-certification",
        CERTIFICATION_SEMANTIC_VERSION,
        EvidenceClass::Aggregate,
        json!({
            "certification_source_digest": input.source_digest,
            "profile": input.profile.id,
            "standard": {"id": input.standard.id, "edition": input.standard.edition},
            "semantic_artifacts": artifact_refs,
            "test_execution_digest": suite_ref,
            "trusted_assertion_dependencies": trusted_refs,
        }),
    )?;
    let certification_digest = root.id.clone();
    nodes.push(root);
    root_obligations.push(certification_digest.clone());
    let graph = EvidenceGraph::new(
        &input.source_digest,
        input.standard.clone(),
        profile_identity.clone(),
        nodes,
        root_obligations,
        vec![
            "Certification consumes upstream semantic conclusions without redefining them.".into(),
        ],
    )?;
    let graph_digest = digest_bytes(graph.to_json_pretty()?.as_bytes());
    let summary = summarize_obligations(&obligations, trusted_subjects.len());
    let certification = CertificationResult {
        schema: "urn:fortress:schema:v1:certification-result".into(),
        schema_version: CERTIFICATION_SCHEMA_VERSION,
        profile: profile_identity,
        subject: input.source_digest.clone(),
        status: aggregate_status,
        certification_digest,
        evidence_graph_digest: graph_digest,
        obligations: obligations.clone(),
        summary,
        trusted_assertion_dependencies: trusted_subjects,
    };
    let mut verified_bfg = build_verified_bfg(input, &obligations, &test_refs);
    verified_bfg
        .certification_digest
        .clone_from(&certification.certification_digest);
    Ok(CertificationProducts {
        evidence_graph: graph,
        certification,
        verified_bfg,
    })
}

/// Evidence-aware behavioral verification state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifiedBehavioralState {
    /// Intended behavior has no supported realization.
    Unrealized,
    /// Static semantic realization exists without bound execution evidence.
    RealizedStatic,
    /// Static proof verifies the meaningful element.
    VerifiedStatic,
    /// Bound executed evidence exists without a complete static proof.
    VerifiedExecuted,
    /// Both evidence classes support the element.
    VerifiedStaticAndExecuted,
    /// Required evidence is absent.
    MissingEvidence,
    /// Existing evidence references prior inputs.
    StaleEvidence,
    /// Current proof contradicts intent.
    Contradicted,
}

impl VerifiedBehavioralState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unrealized => "UNREALIZED",
            Self::RealizedStatic => "REALIZED_STATIC",
            Self::VerifiedStatic => "VERIFIED_STATIC",
            Self::VerifiedExecuted => "VERIFIED_EXECUTED",
            Self::VerifiedStaticAndExecuted => "VERIFIED_STATIC_AND_EXECUTED",
            Self::MissingEvidence => "MISSING_EVIDENCE",
            Self::StaleEvidence => "STALE_EVIDENCE",
            Self::Contradicted => "CONTRADICTED",
        }
    }
}

/// One verified meaningful checkpoint or edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedBehavioralElement {
    /// Checkpoint identity or `source->target` edge identity.
    pub id: String,
    /// Authored Intended BFG presence.
    pub intended: bool,
    /// Supported Realized BFG presence.
    pub realized: bool,
    /// Evidence-aware state.
    pub verification: VerifiedBehavioralState,
    /// Static and executed evidence remain individually identifiable.
    pub evidence_refs: Vec<String>,
}

/// Per-Feature Verified BFG projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedFeatureFlow {
    /// Feature identity.
    pub feature: String,
    /// Feature Requirement evidence refs, not falsely attributed to edges.
    pub feature_requirement_evidence: Vec<String>,
    /// Meaningful checkpoint states.
    pub checkpoints: Vec<VerifiedBehavioralElement>,
    /// Meaningful edge states.
    pub edges: Vec<VerifiedBehavioralElement>,
}

/// Canonical Verified BFG v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedBehavioralFlowGraph {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    project_id: String,
    certification_source_digest: String,
    certification_digest: String,
    view: String,
    features: Vec<VerifiedFeatureFlow>,
    summary: BTreeMap<String, usize>,
    provenance: Vec<String>,
}

impl VerifiedBehavioralFlowGraph {
    /// Returns per-Feature intended/realized/verified projections.
    #[must_use]
    pub fn features(&self) -> &[VerifiedFeatureFlow] {
        &self.features
    }
    /// Returns state counts.
    #[must_use]
    pub const fn summary(&self) -> &BTreeMap<String, usize> {
        &self.summary
    }
    /// Serializes canonical pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        canonical_pretty(self)
    }
}

#[allow(clippy::too_many_lines)]
fn build_verified_bfg(
    input: &CertificationInput,
    obligations: &[CertificationObligation],
    test_refs: &BTreeMap<String, String>,
) -> VerifiedBehavioralFlowGraph {
    let mut features = Vec::new();
    let generated_by_target = input.generated_verification.iter().fold(
        BTreeMap::<&str, Vec<&GeneratedVerificationInput>>::new(),
        |mut index, obligation| {
            for target in &obligation.targets {
                index.entry(target).or_default().push(obligation);
            }
            index
        },
    );
    let bindings: BTreeMap<&str, &VerificationBinding> = input
        .verification_bindings
        .iter()
        .map(|binding| (binding.obligation.as_str(), binding))
        .collect();
    let stale_verification = obligations
        .iter()
        .filter(|obligation| {
            matches!(
                obligation.kind,
                CertificationObligationKind::BehavioralVerification
                    | CertificationObligationKind::EnvironmentalVerification
            ) && obligation.status == CertificationStatus::Stale
        })
        .map(|obligation| obligation.subject.as_str())
        .collect::<BTreeSet<_>>();
    let opted_features = input
        .behavioral_realizations
        .iter()
        .map(|realization| realization.feature.as_str())
        .collect::<BTreeSet<_>>();
    for projection in &input.behavioral_projection {
        let opted_in = opted_features.contains(projection.feature.as_str());
        let realized_checkpoints: BTreeSet<&str> = projection
            .realized_checkpoints
            .iter()
            .map(String::as_str)
            .collect();
        let realized_edges: BTreeSet<String> = projection
            .realized_edges
            .iter()
            .map(|(a, b)| format!("{a}->{b}"))
            .collect();
        let mut checkpoints = projection
            .checkpoints
            .iter()
            .map(|id| {
                verified_element(
                    id,
                    true,
                    realized_checkpoints.contains(id.as_str()),
                    projection.contradicted,
                    generated_by_target.get(id.as_str()),
                    &bindings,
                    test_refs,
                    &stale_verification,
                    opted_in,
                )
            })
            .collect::<Vec<_>>();
        let mut edges = projection
            .intended_edges
            .iter()
            .map(|(source, target)| {
                let id = format!("{source}->{target}");
                verified_element(
                    &id,
                    true,
                    realized_edges.contains(&id),
                    projection.contradicted,
                    generated_by_target.get(id.as_str()),
                    &bindings,
                    test_refs,
                    &stale_verification,
                    opted_in,
                )
            })
            .collect::<Vec<_>>();
        checkpoints.sort_by(|left, right| left.id.cmp(&right.id));
        edges.sort_by(|left, right| left.id.cmp(&right.id));
        let feature_requirements = input
            .requirements
            .iter()
            .filter(|requirement| requirement.feature_id == projection.feature)
            .map(|requirement| requirement.requirement_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut feature_requirement_evidence = obligations
            .iter()
            .filter(|obligation| {
                obligation.kind == CertificationObligationKind::FeatureRequirement
                    && feature_requirements.contains(obligation.subject.as_str())
            })
            .flat_map(|obligation| obligation.evidence_refs.iter().cloned())
            .collect::<Vec<_>>();
        feature_requirement_evidence.sort();
        feature_requirement_evidence.dedup();
        features.push(VerifiedFeatureFlow {
            feature: projection.feature.clone(),
            feature_requirement_evidence,
            checkpoints,
            edges,
        });
    }
    features.sort_by(|left, right| left.feature.cmp(&right.feature));
    let mut summary = BTreeMap::new();
    for element in features
        .iter()
        .flat_map(|feature| feature.checkpoints.iter().chain(feature.edges.iter()))
    {
        *summary
            .entry(element.verification.as_str().into())
            .or_insert(0) += 1;
    }
    VerifiedBehavioralFlowGraph {
        schema: "urn:fortress:schema:v1:verified-behavioral-flow-graph".into(),
        schema_version: VERIFIED_BFG_SCHEMA_VERSION,
        project_id: input.project_id.clone(),
        certification_source_digest: input.source_digest.clone(),
        certification_digest: String::new(),
        view: "verified".into(),
        features,
        summary,
        provenance: vec![
            "Intended, realized, and verification dimensions remain separate.".into(),
            "Feature Requirement tests are not attributed to exact edges without a verification binding.".into(),
        ],
    }
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn verified_element(
    id: &str,
    intended: bool,
    realized: bool,
    contradicted: bool,
    generated: Option<&Vec<&GeneratedVerificationInput>>,
    bindings: &BTreeMap<&str, &VerificationBinding>,
    test_refs: &BTreeMap<String, String>,
    stale_verification: &BTreeSet<&str>,
    opted_in: bool,
) -> VerifiedBehavioralElement {
    let mut refs = Vec::new();
    let mut executed = false;
    let mut stale = false;
    if let Some(generated) = generated {
        for obligation in generated {
            stale |= stale_verification.contains(obligation.id.as_str());
            if let Some(binding) = bindings.get(obligation.id.as_str()) {
                for test in &binding.tests {
                    if let Some(reference) = test_refs.get(test) {
                        refs.push(reference.clone());
                        executed = true;
                    }
                }
            }
        }
    }
    refs.sort();
    refs.dedup();
    let verification = if contradicted {
        VerifiedBehavioralState::Contradicted
    } else if stale {
        VerifiedBehavioralState::StaleEvidence
    } else if realized && executed {
        VerifiedBehavioralState::VerifiedStaticAndExecuted
    } else if realized {
        VerifiedBehavioralState::RealizedStatic
    } else if executed {
        VerifiedBehavioralState::VerifiedExecuted
    } else if intended && opted_in {
        VerifiedBehavioralState::MissingEvidence
    } else {
        VerifiedBehavioralState::Unrealized
    };
    VerifiedBehavioralElement {
        id: id.into(),
        intended,
        realized,
        verification,
        evidence_refs: refs,
    }
}

/// Computes the canonical certification-source digest from observed bytes.
///
/// Paths must be canonical repository-relative spellings. Generated projections
/// registered by [`GENERATED_CERTIFICATION_PROJECTIONS`] do not contribute.
#[must_use]
pub fn certification_source_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let excluded: BTreeSet<&str> = GENERATED_CERTIFICATION_PROJECTIONS
        .iter()
        .copied()
        .collect();
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        if excluded.contains(path.as_str()) {
            continue;
        }
        hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Computes a deterministic test-inventory digest.
#[must_use]
pub fn test_inventory_digest(eligible: &[String], ignored: &[String]) -> String {
    digest_bytes(
        serde_json::to_vec(&json!({"eligible": eligible, "ignored": ignored}))
            .unwrap_or_default()
            .as_slice(),
    )
}

fn validate_acyclic(nodes: &[EvidenceNode]) -> Result<(), CertificationError> {
    let by_id: BTreeMap<&str, &EvidenceNode> = nodes.iter().map(|node| (node.id(), node)).collect();
    let mut temporary = BTreeSet::new();
    let mut permanent = BTreeSet::new();
    for id in by_id.keys().copied() {
        visit_evidence_node(id, &by_id, &mut temporary, &mut permanent)?;
    }
    Ok(())
}

fn visit_evidence_node<'a>(
    id: &'a str,
    by_id: &BTreeMap<&'a str, &'a EvidenceNode>,
    temporary: &mut BTreeSet<&'a str>,
    permanent: &mut BTreeSet<&'a str>,
) -> Result<(), CertificationError> {
    if permanent.contains(id) {
        return Ok(());
    }
    if !temporary.insert(id) {
        return Err(CertificationError::Cycle(id.into()));
    }
    if let Some(node) = by_id.get(id) {
        for input in &node.inputs {
            visit_evidence_node(input, by_id, temporary, permanent)?;
        }
    }
    temporary.remove(id);
    permanent.insert(id);
    Ok(())
}

fn validate_bindings<'a>(
    obligations: &'a [GeneratedVerificationInput],
    bindings: &'a [VerificationBinding],
) -> Result<BTreeMap<&'a str, &'a VerificationBinding>, CertificationError> {
    let by_obligation: BTreeMap<&str, &GeneratedVerificationInput> = obligations
        .iter()
        .map(|value| (value.id.as_str(), value))
        .collect();
    let mut result = BTreeMap::new();
    for binding in bindings {
        let Some(obligation) = by_obligation.get(binding.obligation.as_str()) else {
            return Err(CertificationError::UnknownVerificationObligation(
                binding.obligation.clone(),
            ));
        };
        if binding.testing_module != obligation.testing_module {
            return Err(CertificationError::ForeignVerificationBinding {
                obligation: binding.obligation.clone(),
                expected: obligation.testing_module.clone(),
                actual: binding.testing_module.clone(),
            });
        }
        if binding.tests.is_empty() || !is_strictly_sorted(&binding.tests) {
            return Err(CertificationError::InvalidVerificationBinding(
                binding.obligation.clone(),
            ));
        }
        if result
            .insert(binding.obligation.as_str(), binding)
            .is_some()
        {
            return Err(CertificationError::DuplicateVerificationBinding(
                binding.obligation.clone(),
            ));
        }
    }
    Ok(result)
}

fn sorted_artifacts(
    values: &[ArtifactEvidenceInput],
) -> Result<Vec<&ArtifactEvidenceInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.kind.as_str(),
        CertificationError::DuplicateArtifact,
    )
}
fn sorted_rules(
    values: &[RuleEvidenceInput],
) -> Result<Vec<&RuleEvidenceInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.rule_id.as_str(),
        CertificationError::DuplicateRuleEvidence,
    )
}
fn sorted_requirements(
    values: &[RequirementEvidenceInput],
) -> Result<Vec<&RequirementEvidenceInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.requirement_id.as_str(),
        CertificationError::DuplicateRequirement,
    )
}
fn sorted_realizations(
    values: &[BehavioralRealizationEvidenceInput],
) -> Result<Vec<&BehavioralRealizationEvidenceInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.feature.as_str(),
        CertificationError::DuplicateBehavioralRealization,
    )
}
fn sorted_generated(
    values: &[GeneratedVerificationInput],
) -> Result<Vec<&GeneratedVerificationInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.id.as_str(),
        CertificationError::DuplicateGeneratedVerification,
    )
}
fn sorted_assertions(
    values: &[TrustedAssertionInput],
) -> Result<Vec<&TrustedAssertionInput>, CertificationError> {
    sorted_unique(
        values,
        |value| value.subject.as_str(),
        CertificationError::DuplicateTrustedAssertion,
    )
}

fn sorted_unique<T, F, E>(values: &[T], key: F, error: E) -> Result<Vec<&T>, CertificationError>
where
    F: Fn(&T) -> &str,
    E: Fn(String) -> CertificationError,
{
    let mut sorted: Vec<&T> = values.iter().collect();
    sorted.sort_by(|left, right| key(left).cmp(key(right)));
    if let Some(pair) = sorted.windows(2).find(|pair| key(pair[0]) == key(pair[1])) {
        return Err(error(key(pair[0]).into()));
    }
    Ok(sorted)
}

fn summarize_obligations(
    obligations: &[CertificationObligation],
    trusted: usize,
) -> CertificationSummary {
    let mut value = CertificationSummary {
        obligations: obligations.len(),
        trusted_assertions: trusted,
        ..CertificationSummary::default()
    };
    for obligation in obligations {
        match obligation.status {
            CertificationStatus::Pass => value.pass += 1,
            CertificationStatus::Fail => value.fail += 1,
            CertificationStatus::Missing => value.missing += 1,
            CertificationStatus::Stale => value.stale += 1,
            CertificationStatus::Invalid => value.invalid += 1,
        }
    }
    value
}

fn is_strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest_json(value: &impl Serialize) -> Result<String, CertificationError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn canonical_pretty(value: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value).map(|mut rendered| {
        rendered.push('\n');
        rendered
    })
}

/// Certification construction or validation error.
#[derive(Debug)]
pub enum CertificationError {
    /// JSON serialization failed.
    Json(serde_json::Error),
    /// A required node field was empty.
    EmptyNodeField,
    /// Graph schema version is unsupported.
    InvalidSchemaVersion(u16),
    /// Node array is not ordered by content identity.
    NonCanonicalNodeOrdering,
    /// Input references are not strictly sorted.
    NonCanonicalInputOrdering(String),
    /// A node digest does not match its canonical body.
    NodeDigestMismatch(String),
    /// Duplicate content identity appears.
    DuplicateNode(String),
    /// Two different nodes claim one semantic kind/subject identity.
    ConflictingSemanticNode {
        /// Evidence kind.
        kind: String,
        /// Semantic subject.
        subject: String,
    },
    /// An input reference is missing.
    MissingInput {
        /// Referencing node identity.
        node: String,
        /// Missing input identity.
        input: String,
    },
    /// A root obligation reference is missing.
    MissingRoot(String),
    /// Graph contains a dependency cycle.
    Cycle(String),
    /// Certification profile is malformed.
    InvalidProfile,
    /// Canonical full profile was weakened.
    WeakenedFullProfile,
    /// Suite execution semantics are malformed.
    InvalidSuiteExecution,
    /// Test inventory is not canonical.
    NonCanonicalTestInventory,
    /// Test appears as both enabled and ignored.
    ContradictoryTestEligibility,
    /// Test inventory digest does not bind its normalized eligibility lists.
    TestInventoryDigestMismatch,
    /// Suite evidence binds a different source subject.
    SuiteSubjectMismatch,
    /// Duplicate artifact evidence.
    DuplicateArtifact(String),
    /// Duplicate rule evidence.
    DuplicateRuleEvidence(String),
    /// Applicable rule inventory is not strictly sorted.
    NonCanonicalApplicableRules,
    /// Rule evidence claims a rule outside the applicable inventory.
    UnexpectedRuleEvidence(String),
    /// Duplicate Requirement evidence.
    DuplicateRequirement(String),
    /// Duplicate behavioral realization evidence.
    DuplicateBehavioralRealization(String),
    /// Duplicate generated obligation.
    DuplicateGeneratedVerification(String),
    /// Duplicate trusted assertion.
    DuplicateTrustedAssertion(String),
    /// Binding references an absent current obligation.
    UnknownVerificationObligation(String),
    /// Binding is owned by the wrong Testing Module.
    ForeignVerificationBinding {
        /// Bound obligation identity.
        obligation: String,
        /// Required canonical Testing Module.
        expected: String,
        /// Actual binding-owning Module.
        actual: String,
    },
    /// Binding has no tests or noncanonical tests.
    InvalidVerificationBinding(String),
    /// More than one binding targets an obligation.
    DuplicateVerificationBinding(String),
}

impl Display for CertificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "certification JSON failed: {error}"),
            Self::EmptyNodeField => formatter.write_str(
                "evidence node identity, subject, producer, and version must be nonempty",
            ),
            Self::InvalidSchemaVersion(value) => write!(
                formatter,
                "unsupported Evidence Graph schema version {value}"
            ),
            Self::NonCanonicalNodeOrdering => {
                formatter.write_str("evidence nodes are not strictly ordered by content identity")
            }
            Self::NonCanonicalInputOrdering(node) => write!(
                formatter,
                "evidence node `{node}` inputs are not strictly ordered"
            ),
            Self::NodeDigestMismatch(node) => write!(
                formatter,
                "evidence node `{node}` digest does not match canonical content"
            ),
            Self::DuplicateNode(node) => write!(formatter, "duplicate evidence node `{node}`"),
            Self::ConflictingSemanticNode { kind, subject } => write!(
                formatter,
                "conflicting evidence nodes claim semantic identity `{kind}:{subject}`"
            ),
            Self::MissingInput { node, input } => write!(
                formatter,
                "evidence node `{node}` references missing input `{input}`"
            ),
            Self::MissingRoot(root) => write!(formatter, "root obligation `{root}` does not exist"),
            Self::Cycle(node) => write!(formatter, "evidence dependency cycle contains `{node}`"),
            Self::InvalidProfile => {
                formatter.write_str("certification profile identity or version is invalid")
            }
            Self::WeakenedFullProfile => formatter
                .write_str("CERT-FULL-SNAPSHOT-V1 cannot weaken any mandatory obligation class"),
            Self::InvalidSuiteExecution => formatter.write_str(
                "Rust suite execution evidence is missing executor, version, or toolchain identity",
            ),
            Self::NonCanonicalTestInventory => formatter
                .write_str("Rust suite eligible/ignored inventories must be strictly sorted"),
            Self::ContradictoryTestEligibility => {
                formatter.write_str("a Rust Test ID cannot be both eligible and ignored")
            }
            Self::TestInventoryDigestMismatch => formatter
                .write_str("Rust test inventory digest does not match normalized eligibility"),
            Self::SuiteSubjectMismatch => formatter.write_str(
                "Rust suite execution evidence refers to a different certification source digest",
            ),
            Self::DuplicateArtifact(value) => {
                write!(formatter, "duplicate artifact evidence `{value}`")
            }
            Self::DuplicateRuleEvidence(value) => {
                write!(formatter, "duplicate rule evidence `{value}`")
            }
            Self::NonCanonicalApplicableRules => {
                formatter.write_str("applicable Standard rule identities must be strictly sorted")
            }
            Self::UnexpectedRuleEvidence(value) => {
                write!(formatter, "rule evidence `{value}` is not applicable")
            }
            Self::DuplicateRequirement(value) => {
                write!(formatter, "duplicate Requirement evidence `{value}`")
            }
            Self::DuplicateBehavioralRealization(value) => write!(
                formatter,
                "duplicate behavioral realization evidence `{value}`"
            ),
            Self::DuplicateGeneratedVerification(value) => write!(
                formatter,
                "duplicate generated verification obligation `{value}`"
            ),
            Self::DuplicateTrustedAssertion(value) => {
                write!(formatter, "duplicate trusted assertion `{value}`")
            }
            Self::UnknownVerificationObligation(value) => write!(
                formatter,
                "verification binding references absent obligation `{value}`"
            ),
            Self::ForeignVerificationBinding {
                obligation,
                expected,
                actual,
            } => write!(
                formatter,
                "verification binding `{obligation}` belongs to `{actual}`, expected `{expected}`"
            ),
            Self::InvalidVerificationBinding(value) => write!(
                formatter,
                "verification binding `{value}` must contain strictly sorted Test IDs"
            ),
            Self::DuplicateVerificationBinding(value) => {
                write!(formatter, "duplicate verification binding `{value}`")
            }
        }
    }
}

impl Error for CertificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for CertificationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
