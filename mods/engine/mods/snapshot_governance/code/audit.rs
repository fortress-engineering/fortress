//! End-to-end provider-independent Snapshot Governance repository audit.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::architecture::ArchitectureManifest;
use crate::architecture_diagnostics::{
    ArchitectureDiagnostic, ArchitectureDiagnosticError, derive_architecture_diagnostics,
};
use crate::architecture_realization::{ArchitectureRealization, reconcile_implementation};
use crate::behavioral_realization::{
    BehaviorRealizationContractError, BehaviorRealizationContractSource,
    BehavioralRealizationError, BehavioralRealizationEvaluation, RealizedBehavioralFlowGraph,
    evaluate_behavioral_realization, load_behavior_realization_contracts,
};
use crate::behavioral_semantics::{
    BehavioralSemanticsError, IntendedBehavioralFlowGraph, evaluate_behavioral_semantics,
};
use crate::certification::{
    ArtifactEvidenceInput, BehavioralProjectionInput, BehavioralRealizationEvidenceInput,
    CertificationError, CertificationInput, CertificationProducts, CertificationProfile,
    CertificationSourceIdentity, EvidenceClass, EvidenceResult, GeneratedVerificationInput,
    GeneratedVerificationKind, RequirementEvidenceInput, RuleEvidenceInput, RustSuiteExecution,
    StandardIdentity, VerificationBinding, certification_source_digest, compile_certification,
    test_inventory_digest,
};
use crate::contract::evaluate_contract_coherency;
use crate::contract_coherency::{
    CcgCompilation, CcgObservedTestFact, ContractCoherencyGraph, ContractStandardIndex,
    compile_contract_coherency_graph,
};
use crate::documentation::{
    DocumentationEvaluationError, code_file_responsibilities, evaluate_repository_documentation,
};
use crate::environmental_semantics::{
    EnvironmentContractError, EnvironmentContractSource, EnvironmentalAnalysisError,
    EnvironmentalAnalysisEvaluation, analyze_environmental_semantics, load_environment_contracts,
};
use crate::evaluation::{
    CompleteEvaluationInputs, EvaluationError, ProgramEvaluationInputs, RepositoryEvaluationInputs,
    RuleExecution, SnapshotRuleEngine,
};
use crate::filing::{FilingSystemProfiles, analyze_project_filing_system};
use crate::finding::{CanonicalFinding, FindingError};
use crate::implementation_observation::{
    ImplementationObservationError, ImplementationObservationInput, ModuleTerritory,
    ObservedImplementation, SnapshotBoundFile, observe_rust_implementation,
};
use crate::information_flow::{
    InformationFlowAnalysisError, InformationFlowEvaluation, InformationFlowPolicyError,
    InformationFlowPolicySource, analyze_information_flow, load_information_flow_policy,
};
use crate::observation::{ObservationError, ObservationPolicy, RepositoryObservation};
use crate::program_semantics::{
    ProgramSemanticError, ProgramSemanticInput, ProgramSemanticModel,
    compile_program_semantic_model,
};
use crate::project::{ProjectConfiguration, ProjectConfigurationLoadError};
use crate::reference_resolution::{
    ReferenceResolutionError, ReferenceResolutionEvaluation, evaluate_reference_resolution,
};
use crate::rust_test_analyzer::{
    RustAnalyzerError, RustTestEligibility, analyze_observed_rust_tests,
};
use crate::semantic_analysis::{
    FunctionContractError, FunctionContractSource, ResolvedFunctionContracts,
    SemanticAnalysisError, SemanticAnalysisEvaluation, analyze_program_domains,
    load_function_contracts,
};
use crate::snapshot::{
    RepositorySnapshot, SnapshotDocuments, SnapshotError, build_repository_snapshot,
    observe_repository_stably,
};
use crate::source_architecture::{
    LanguageAssignment, SourceArchitectureEvaluation, SourceArchitectureInput, SourceArtifactModel,
    SourceProfileRegistry, SourceVerificationRelationship, evaluate_source_architecture,
    observations_from_psm,
};
use crate::standard::{StandardBundle, StandardLoadError};
use crate::state_effect_analysis::{
    StateContractError, StateContractSource, StateEffectAnalysisError,
    StateEffectAnalysisEvaluation, analyze_state_effects, load_state_contracts,
};

/// Current stable machine-readable snapshot audit schema family.
pub const AUDIT_RESULT_SCHEMA_VERSION: u16 = 2;

/// Deterministic repository audit result; this is not certification evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditResult {
    schema_version: u16,
    project_id: String,
    standard: AuditStandard,
    snapshot_fingerprint: String,
    repository_content_fingerprint: String,
    outcome: AuditOutcome,
    summary: AuditSummary,
    rules: Vec<RuleExecution>,
    findings: Vec<CanonicalFinding>,
    diagnostics: Vec<ArchitectureDiagnostic>,
    unsupported_analysis: Vec<String>,
}

impl AuditResult {
    /// Returns whether all actually evaluated mandatory rules had no findings.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome == AuditOutcome::Pass
    }

    /// Returns the exact stabilized snapshot fingerprint.
    #[must_use]
    pub fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    /// Returns deterministic audit summary counts.
    #[must_use]
    pub const fn summary(&self) -> &AuditSummary {
        &self.summary
    }

    /// Returns canonical findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns evidence-backed architecture interpretations that do not affect outcome.
    #[must_use]
    pub fn diagnostics(&self) -> &[ArchitectureDiagnostic] {
        &self.diagnostics
    }

    /// Returns architecture conclusions deliberately unsupported by diagnostics v1.
    #[must_use]
    pub fn unsupported_analysis(&self) -> &[String] {
        &self.unsupported_analysis
    }

    /// Returns deterministic execution records for every applicable standard rule.
    #[must_use]
    pub fn rules(&self) -> &[RuleExecution] {
        &self.rules
    }

    /// Serializes stable pretty JSON with deterministic collection ordering.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the version-two contract cannot be represented.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Renders concise deterministic terminal output.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut output = format!(
            "Fortress Snapshot Audit\nStandard: {}\nSnapshot: {}\n\nRules evaluated: {}\nPASS: {}\nFAIL: {}\nUnsupported: {}\n\nFindings:\n",
            self.standard.edition,
            self.snapshot_fingerprint,
            self.summary.rules_evaluated,
            self.summary.passed,
            self.summary.failed,
            self.summary.unsupported
        );
        if self.findings.is_empty() {
            output.push_str("None\n");
        } else {
            for finding in &self.findings {
                let location = finding.location().path().unwrap_or("repository");
                output.push_str("- [");
                output.push_str(finding.rule_id());
                output.push_str("] ");
                output.push_str(location);
                output.push_str(": ");
                output.push_str(finding.message());
                output.push('\n');
            }
        }
        output.push_str("\nArchitecture diagnostics:\n");
        if self.diagnostics.is_empty() {
            output.push_str("None\n");
        } else {
            for diagnostic in &self.diagnostics {
                output.push_str("- [");
                output.push_str(diagnostic.kind().as_str());
                output.push_str("] ");
                output.push_str(diagnostic.primary_module());
                output.push_str(": ");
                output.push_str(diagnostic.summary());
                output.push('\n');
            }
        }
        output.push_str("\nUnsupported analysis:\n");
        if self.unsupported_analysis.is_empty() {
            output.push_str("None\n");
        } else {
            for unsupported in &self.unsupported_analysis {
                output.push_str("- ");
                output.push_str(unsupported);
                output.push('\n');
            }
        }
        output
    }
}

/// Standard identity reported by an audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AuditStandard {
    edition: String,
    status: String,
}

/// Overall evaluated-rule outcome, excluding explicitly unsupported rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AuditOutcome {
    Pass,
    Fail,
}

/// Stable audit rule counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuditSummary {
    rules_evaluated: usize,
    passed: usize,
    failed: usize,
    unsupported: usize,
}

impl AuditSummary {
    /// Returns actually evaluated rule count.
    #[must_use]
    pub const fn rules_evaluated(&self) -> usize {
        self.rules_evaluated
    }

    /// Returns evaluated pass count.
    #[must_use]
    pub const fn passed(&self) -> usize {
        self.passed
    }

    /// Returns evaluated failure count.
    #[must_use]
    pub const fn failed(&self) -> usize {
        self.failed
    }

    /// Returns applicable unsupported rule count.
    #[must_use]
    pub const fn unsupported(&self) -> usize {
        self.unsupported
    }
}

/// Audits one repository root using only its declared model and stabilized facts.
///
/// # Errors
///
/// Returns [`AuditError`] for invalid/missing declarations, unstable or
/// inconsistent snapshot inputs, analyzer failure, or rule-evaluation failure.
pub fn audit_repository(root: impl AsRef<Path>) -> Result<AuditResult, AuditError> {
    audit_repository_with_models(root.as_ref(), true).map(|(audit, _, _)| audit)
}

/// Compiles the canonical CCG for a stabilized repository input set.
///
/// The same orchestration path used by [`audit_repository`] supplies standard,
/// contract, containment, and observed Rust verification facts. Independent
/// implementation observation is deliberately omitted because source
/// realization is evidence compared with the CCG, never a CCG input. Other
/// audit rules are evaluated as a consistency guard, but their result is not
/// embedded in the graph.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed or unstable repository state.
pub fn compile_repository_ccg(
    root: impl AsRef<Path>,
) -> Result<ContractCoherencyGraph, AuditError> {
    audit_repository_with_models(root.as_ref(), false).map(|(_, ccg, _)| ccg)
}

/// Compiles the canonical Intended BFG for one stabilized repository.
///
/// The graph is derived from the same immutable CCG and standard interpretation
/// used by [`audit_repository`]; observed implementation facts never enter it.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed, unstable, or incoherent repository state.
pub fn compile_repository_bfg(
    root: impl AsRef<Path>,
) -> Result<IntendedBehavioralFlowGraph, AuditError> {
    audit_repository_with_models(root.as_ref(), false).map(|(_, _, bfg)| bfg)
}

/// Compiles the canonical CCG-bound component reference resolution projection.
///
/// The projection maps stable identities to current repository locations and
/// evaluates only understood Markdown, Cargo, and Rust physical reference forms.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed, unstable, or unresolvable repository state.
pub fn compile_repository_reference_resolution(
    root: impl AsRef<Path>,
) -> Result<ReferenceResolutionEvaluation, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    evaluate_reference_resolution(
        ccg,
        &prepared.observed_files,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::ReferenceResolution)
}

/// Compiles the canonical snapshot-bound Rust Program Semantic Model.
///
/// Program facts remain independent of the CCG and Intended BFG. The CCG is
/// consulted only for physical Module ownership and Testing classification,
/// while Implementation Observation supplies the broader dependency projection
/// used for analyzer-coherency validation.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed or unstable repository state, source
/// analysis failure, or disagreement between supported source analyzers.
pub fn compile_repository_psm(root: impl AsRef<Path>) -> Result<ProgramSemanticModel, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    let observation_input =
        implementation_input(&prepared.snapshot, ccg, &prepared.observed_files)?;
    let observed = observe_rust_implementation(&observation_input)
        .map_err(AuditError::ImplementationObservation)?;
    compile_psm_from_observed(&prepared, ccg, observation_input, &observed)
}

/// Compiles the canonical language-neutral Source Artifact Model v1.
///
/// The compiler reuses Project Filing membership, Snapshot Governance's
/// canonical `code_docs.md` projection, and stable PSM references. It does not
/// parse Rust or Markdown and leaves Rust archetype status explicitly
/// `PROFILE_NOT_REGISTERED` until the Rust File Content Profile exists.
///
/// # Errors
///
/// Returns [`AuditError`] for invalid or unstable repository authority,
/// semantic-substrate failure, responsibility projection failure, or finding
/// normalization failure.
pub fn compile_repository_source_artifact_model(
    root: impl AsRef<Path>,
) -> Result<SourceArtifactModel, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    let observation_input =
        implementation_input(&prepared.snapshot, ccg, &prepared.observed_files)?;
    let observed = observe_rust_implementation(&observation_input)
        .map_err(AuditError::ImplementationObservation)?;
    let psm = compile_psm_from_observed(&prepared, ccg, observation_input, &observed)?;
    compile_source_architecture_from(&prepared, ccg, Some(&psm)).map(|value| value.model().clone())
}

fn compile_source_architecture_from(
    prepared: &PreparedAudit,
    ccg: &ContractCoherencyGraph,
    psm: Option<&ProgramSemanticModel>,
) -> Result<SourceArchitectureEvaluation, AuditError> {
    let observed_paths = prepared.observed_files.keys().cloned().collect::<Vec<_>>();
    let filing = analyze_project_filing_system(&observed_paths, &FilingSystemProfiles::standard());
    let responsibilities = code_file_responsibilities(&prepared.observed_files, ccg)
        .map_err(|error| AuditError::ContractState(error.into()))?;
    let observations = psm.map_or_else(Vec::new, observations_from_psm);
    let languages = [
        LanguageAssignment::new("rs", "rust", "fortress-core/program-semantics-v3"),
        LanguageAssignment::new(
            "py",
            "python",
            "fortress-core/source-extension-observation-v1",
        ),
    ];
    let verification_relationships = prepared
        .rust_tests
        .iter()
        .filter_map(|test| {
            let requirement_id = test.declared_requirement()?;
            let requirement = ccg.requirements().get(requirement_id)?;
            Some(SourceVerificationRelationship::new(
                test.path(),
                requirement.feature(),
                requirement_id,
                test.id(),
            ))
        })
        .collect::<Vec<_>>();
    let available_adapters = ["fortress-core/program-semantics-v3".to_owned()]
        .into_iter()
        .collect();
    let psm_json = psm
        .map(ProgramSemanticModel::to_canonical_json)
        .transpose()
        .map_err(|error| AuditError::ContractState(error.to_string().into()))?;
    let psm_digest = psm_json
        .as_deref()
        .map(|value| format!("sha256:{:x}", Sha256::digest(value.as_bytes())));
    // Source Architecture is a derived projection. Bind it to the canonical
    // certification source rather than Snapshot Governance's raw observation
    // fingerprint so generated semantic projections cannot influence their
    // own input identity.
    let source_identity = certification_source_digest(&prepared.observed_files);
    evaluate_source_architecture(&SourceArchitectureInput {
        project_id: prepared.snapshot.project_id(),
        source_identity: &source_identity,
        filing: &filing,
        ccg,
        files: &prepared.observed_files,
        responsibilities: &responsibilities,
        profiles: &SourceProfileRegistry::standard(),
        languages: &languages,
        observations: &observations,
        generated_sources: &[],
        verification_relationships: &verification_relationships,
        available_adapters: &available_adapters,
        psm_digest: psm_digest.as_deref(),
        standard_edition: prepared.standard.bundle.edition(),
    })
    .map_err(AuditError::SourceArchitecture)
}

fn compile_psm_from_observed(
    prepared: &PreparedAudit,
    ccg: &ContractCoherencyGraph,
    observation_input: ImplementationObservationInput,
    observed: &ObservedImplementation,
) -> Result<ProgramSemanticModel, AuditError> {
    let testing_modules = ccg
        .modules()
        .iter()
        .filter(|(_, module)| {
            module.path() == "mods/testing" || module.path().ends_with("/mods/testing")
        })
        .map(|(id, _)| id.clone());
    let observed_dependencies = observed.module_dependencies().iter().map(|dependency| {
        (
            dependency.source_module().to_owned(),
            dependency.target_module().to_owned(),
        )
    });
    compile_program_semantic_model(&ProgramSemanticInput::new(
        prepared.snapshot.project_id(),
        observation_input,
        testing_modules,
        observed_dependencies,
    ))
    .map_err(AuditError::ProgramSemantics)
}

/// Compiles distributed Function Contracts and the snapshot-bound PSM into
/// canonical Semantic Analysis v1 derived information.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed repository authority, unstable source,
/// invalid Function Contracts, PSM failure, or semantic result construction.
pub fn compile_repository_semantic_analysis(
    root: impl AsRef<Path>,
) -> Result<SemanticAnalysisEvaluation, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    compile_analysis_models(&prepared, ccg).map(|models| models.semantic)
}

/// Compiles the repository's canonical State and Effect Analysis v1 result.
///
/// # Errors
///
/// Returns [`AuditError`] for any invalid stabilized input, PSM, Function
/// Contract, State Contract, Semantic Analysis, or State/Effect result.
pub fn compile_repository_state_effect_analysis(
    root: impl AsRef<Path>,
) -> Result<StateEffectAnalysisEvaluation, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    compile_analysis_models(&prepared, ccg).map(|models| models.state_effect)
}

/// Compiles the repository's canonical Information Flow Analysis v1 result.
///
/// # Errors
///
/// Returns [`AuditError`] for any invalid stabilized input, semantic substrate,
/// information-flow policy, Function Contract flow declaration, or result.
pub fn compile_repository_information_flow_analysis(
    root: impl AsRef<Path>,
) -> Result<InformationFlowEvaluation, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    compile_analysis_models(&prepared, ccg).map(|models| models.information_flow)
}

/// Compiles the repository's canonical Environmental Analysis v1 result.
///
/// # Errors
///
/// Returns [`AuditError`] for invalid stabilized inputs, semantic substrate,
/// distributed Environment Contracts, or environmental result construction.
pub fn compile_repository_environmental_analysis(
    root: impl AsRef<Path>,
) -> Result<EnvironmentalAnalysisEvaluation, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    compile_analysis_models(&prepared, ccg).map(|models| models.environmental)
}

/// Compiles the repository's canonical Realized BFG v1.
///
/// # Errors
///
/// Returns an audit error for invalid stabilized input, any failed semantic
/// substrate, invalid distributed realization authority, or serialization.
pub fn compile_repository_realized_bfg(
    root: impl AsRef<Path>,
) -> Result<RealizedBehavioralFlowGraph, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    let behavioral_semantics =
        evaluate_behavioral_semantics(ccg, prepared.standard.bundle.edition())
            .map_err(AuditError::BehavioralSemantics)?;
    let models = compile_analysis_models(&prepared, ccg)?;
    let sources = behavior_realization_contract_sources(ccg, &prepared.observed_files)?;
    let contracts = load_behavior_realization_contracts(
        ccg,
        behavioral_semantics.graph(),
        &models.psm,
        models.state_effect.model(),
        models.information_flow.model(),
        models.environmental.model(),
        sources,
    )
    .map_err(AuditError::BehaviorRealizationContracts)?;
    evaluate_behavioral_realization(
        ccg,
        behavioral_semantics.graph(),
        &models.psm,
        models.semantic.model(),
        models.state_effect.model(),
        models.information_flow.model(),
        models.environmental.model(),
        &contracts,
        prepared.standard.bundle.edition(),
    )
    .map(|evaluation| evaluation.graph().clone())
    .map_err(AuditError::BehavioralRealization)
}

/// Prepares the recursion-free certification subject and exact Rust test inventory.
///
/// This operation does not execute tests and therefore is not execution evidence.
/// It is intended to bracket the canonical local suite so callers can reject a
/// source mutation between preparation and evidence construction.
///
/// # Errors
///
/// Returns an audit error for unstable repository bytes or invalid test metadata.
pub fn prepare_repository_certification_source(
    root: impl AsRef<Path>,
) -> Result<CertificationSourceIdentity, AuditError> {
    let prepared = prepare_audit(root.as_ref())?;
    let digest = certification_source_digest(&prepared.observed_files);
    let mut eligible_test_ids = prepared
        .rust_tests
        .iter()
        .filter(|test| test.eligibility() == RustTestEligibility::Enabled)
        .map(|test| test.id().to_owned())
        .collect::<Vec<_>>();
    let mut ignored_test_ids = prepared
        .rust_tests
        .iter()
        .filter(|test| test.eligibility() == RustTestEligibility::Ignored)
        .map(|test| test.id().to_owned())
        .collect::<Vec<_>>();
    eligible_test_ids.sort();
    eligible_test_ids.dedup();
    ignored_test_ids.sort();
    ignored_test_ids.dedup();
    Ok(CertificationSourceIdentity {
        test_inventory_digest: test_inventory_digest(&eligible_test_ids, &ignored_test_ids),
        digest,
        eligible_test_ids,
        ignored_test_ids,
    })
}

/// Compiles all semantic models once and constructs current certification products.
///
/// The supplied Rust suite execution must have been obtained by the external
/// execution boundary using the exact source identity returned by
/// [`prepare_repository_certification_source`]. Certification itself remains a
/// provider-independent consumer and never launches a shell.
///
/// # Errors
///
/// Returns an audit error for invalid/stale repository semantics, invalid
/// distributed bindings, or Evidence DAG construction failure.
pub fn compile_repository_certification(
    root: impl AsRef<Path>,
    suite_execution: RustSuiteExecution,
) -> Result<CertificationProducts, AuditError> {
    let stack = compile_certification_semantic_stack(root.as_ref())?;
    let source_digest = certification_source_digest(&stack.observed_files);
    let artifacts = certification_artifacts(&stack)?;
    let rules = stack
        .evaluation
        .rules()
        .iter()
        .map(|execution| {
            let result = match execution.state() {
                crate::evaluation::RuleExecutionState::Passed => EvidenceResult::Pass,
                crate::evaluation::RuleExecutionState::Failed => EvidenceResult::Fail,
                crate::evaluation::RuleExecutionState::Unsupported => EvidenceResult::Unsupported,
            };
            let mut finding_fingerprints = stack
                .evaluation
                .findings()
                .iter()
                .filter(|finding| finding.rule_id() == execution.rule_id())
                .map(|finding| finding.finding_fingerprint().to_owned())
                .collect::<Vec<_>>();
            finding_fingerprints.sort();
            RuleEvidenceInput {
                rule_id: execution.rule_id().to_owned(),
                result,
                current: true,
                finding_fingerprints,
                input_refs: Vec::new(),
            }
        })
        .collect();
    let requirements = stack
        .ccg
        .requirements()
        .iter()
        .map(|(id, requirement)| RequirementEvidenceInput {
            feature_id: requirement.feature().to_owned(),
            requirement_id: id.clone(),
            test_ids: requirement.tests().to_vec(),
        })
        .collect();
    let (generated_verification, behavioral_projection, behavioral_realizations) =
        certification_behavior_inputs(&stack)?;
    let verification_bindings =
        certification_verification_bindings(&stack.ccg, &stack.observed_files, &stack.rust_tests)?;
    let trusted_assertions = certification_trusted_assertions(&stack)?;
    let profile: CertificationProfile = serde_json::from_slice(
        stack
            .observed_files
            .get("mods/engine/mods/standard_registry/data/cert_full_snapshot_v1.json")
            .ok_or_else(|| {
                AuditError::ContractState("missing CERT-FULL-SNAPSHOT-V1 authority".into())
            })?,
    )
    .map_err(CertificationError::Json)
    .map_err(AuditError::Certification)?;
    let mut applicable_rules = stack
        .standard
        .rules()
        .iter()
        .map(|rule| rule.id().to_owned())
        .collect::<Vec<_>>();
    applicable_rules.sort();
    compile_certification(&CertificationInput {
        project_id: stack.snapshot.project_id().to_owned(),
        source_digest,
        standard: StandardIdentity {
            id: stack.standard.id().to_owned(),
            edition: stack.standard.edition().to_owned(),
        },
        profile,
        artifacts,
        applicable_rules,
        rules,
        requirements,
        suite_execution,
        behavioral_realizations,
        generated_verification,
        verification_bindings,
        trusted_assertions,
        behavioral_projection,
    })
    .map_err(AuditError::Certification)
}

struct CertificationSemanticStack {
    observed_files: BTreeMap<String, Vec<u8>>,
    rust_tests: Vec<crate::rust_test_analyzer::RustTestFact>,
    standard: StandardBundle,
    snapshot: RepositorySnapshot,
    ccg: ContractCoherencyGraph,
    intended_bfg: IntendedBehavioralFlowGraph,
    models: AnalysisModels,
    realized: BehavioralRealizationEvaluation,
    reference_resolution: ReferenceResolutionEvaluation,
    source_architecture: SourceArchitectureEvaluation,
    evaluation: crate::evaluation::SnapshotEvaluation,
}

fn compile_certification_semantic_stack(
    root: &Path,
) -> Result<CertificationSemanticStack, AuditError> {
    let prepared = prepare_audit(root)?;
    let initial_ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    let observation_input =
        implementation_input(&prepared.snapshot, initial_ccg, &prepared.observed_files)?;
    let observed = observe_rust_implementation(&observation_input)
        .map_err(AuditError::ImplementationObservation)?;
    let architecture_realization =
        reconcile_implementation(initial_ccg, &observed, prepared.standard.bundle.edition())
            .map_err(EvaluationError::Finding)
            .map_err(AuditError::Evaluation)?;
    let models = compile_analysis_models_from_observed(
        &prepared,
        initial_ccg,
        observation_input,
        &observed,
    )?;
    let documentation = evaluate_repository_documentation(
        root,
        &prepared.snapshot,
        initial_ccg,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::Documentation)?;
    let contract_coherency = evaluate_contract_coherency(
        prepared.ccg_compilation.clone(),
        &documentation,
        prepared.standard.bundle.edition(),
    )
    .map_err(EvaluationError::Finding)
    .map_err(AuditError::Evaluation)?;
    let ccg = contract_coherency
        .graph()
        .ok_or_else(|| AuditError::ContractState("CCG compilation did not produce a graph".into()))?
        .clone();
    let behavioral_semantics =
        evaluate_behavioral_semantics(&ccg, prepared.standard.bundle.edition())
            .map_err(AuditError::BehavioralSemantics)?;
    let realized = compile_certification_realization(
        &ccg,
        behavioral_semantics.graph(),
        &models.psm,
        &models,
        &prepared.observed_files,
        prepared.standard.bundle.edition(),
    )?;
    let reference_resolution = evaluate_reference_resolution(
        &ccg,
        &prepared.observed_files,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::ReferenceResolution)?;
    let source_architecture = compile_source_architecture_from(&prepared, &ccg, Some(&models.psm))?;
    let evaluation_inputs = CompleteEvaluationInputs::new(
        &prepared.rust_tests,
        RepositoryEvaluationInputs::new(
            &documentation,
            &contract_coherency,
            &architecture_realization,
            &behavioral_semantics,
            Some(&realized),
            &reference_resolution,
            &source_architecture,
        ),
        ProgramEvaluationInputs::new(
            Some(&models.semantic),
            Some(&models.state_effect),
            Some(&models.information_flow),
            Some(&models.environmental),
        ),
    );
    let evaluation = evaluate_certification_rules(
        &prepared.standard.bundle,
        &prepared.snapshot,
        &ccg,
        evaluation_inputs,
    )?;
    Ok(CertificationSemanticStack {
        observed_files: prepared.observed_files,
        rust_tests: prepared.rust_tests,
        standard: prepared.standard.bundle,
        snapshot: prepared.snapshot,
        ccg,
        intended_bfg: behavioral_semantics.graph().clone(),
        models,
        realized,
        reference_resolution,
        source_architecture,
        evaluation,
    })
}

fn compile_certification_realization(
    ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    models: &AnalysisModels,
    observed_files: &BTreeMap<String, Vec<u8>>,
    edition: &str,
) -> Result<BehavioralRealizationEvaluation, AuditError> {
    let sources = behavior_realization_contract_sources(ccg, observed_files)?;
    let contracts = load_behavior_realization_contracts(
        ccg,
        intended,
        psm,
        models.state_effect.model(),
        models.information_flow.model(),
        models.environmental.model(),
        sources,
    )
    .map_err(AuditError::BehaviorRealizationContracts)?;
    evaluate_behavioral_realization(
        ccg,
        intended,
        psm,
        models.semantic.model(),
        models.state_effect.model(),
        models.information_flow.model(),
        models.environmental.model(),
        &contracts,
        edition,
    )
    .map_err(AuditError::BehavioralRealization)
}

fn evaluate_certification_rules(
    standard: &StandardBundle,
    snapshot: &RepositorySnapshot,
    ccg: &ContractCoherencyGraph,
    inputs: CompleteEvaluationInputs<'_>,
) -> Result<crate::evaluation::SnapshotEvaluation, AuditError> {
    evaluate_snapshot_rules(standard, snapshot, ccg, inputs)
}

#[allow(clippy::too_many_lines)]
fn certification_artifacts(
    stack: &CertificationSemanticStack,
) -> Result<Vec<ArtifactEvidenceInput>, AuditError> {
    let entries = [
        (
            "ccg",
            "urn:fortress:schema:v1:contract-coherency-graph",
            "info/contract_coherency_graph.json",
            stack
                .ccg
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::Authority,
            Vec::new(),
            stack
                .ccg
                .unsupported_semantics()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        ),
        (
            "intended_bfg",
            "urn:fortress:schema:v1:behavioral-flow-graph",
            "info/behavioral_flow_graph.json",
            stack
                .intended_bfg
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::Authority,
            vec!["ccg".to_owned()],
            stack
                .intended_bfg
                .unsupported_semantics()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        ),
        (
            "psm",
            "urn:fortress:schema:v3:program-semantic-model",
            "info/program_semantic_model.json",
            stack
                .models
                .psm
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::Observation,
            vec!["ccg".to_owned()],
            Vec::new(),
        ),
        (
            "semantic_analysis",
            "urn:fortress:schema:v1:semantic-analysis",
            "info/semantic_analysis.json",
            stack
                .models
                .semantic
                .model()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec!["psm".to_owned()],
            stack
                .models
                .semantic
                .model()
                .unsupported_semantics()
                .to_vec(),
        ),
        (
            "state_effect",
            "urn:fortress:schema:v1:state-effect-analysis",
            "info/state_effect_analysis.json",
            stack
                .models
                .state_effect
                .model()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec!["psm".to_owned(), "semantic_analysis".to_owned()],
            stack
                .models
                .state_effect
                .model()
                .unsupported_semantics()
                .to_vec(),
        ),
        (
            "information_flow",
            "urn:fortress:schema:v1:information-flow-analysis",
            "info/information_flow_analysis.json",
            stack
                .models
                .information_flow
                .model()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec![
                "psm".to_owned(),
                "semantic_analysis".to_owned(),
                "state_effect".to_owned(),
            ],
            stack
                .models
                .information_flow
                .model()
                .unsupported_semantics()
                .to_vec(),
        ),
        (
            "environmental_analysis",
            "urn:fortress:schema:v1:environmental-analysis",
            "info/environmental_analysis.json",
            stack
                .models
                .environmental
                .model()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec![
                "psm".to_owned(),
                "semantic_analysis".to_owned(),
                "state_effect".to_owned(),
                "information_flow".to_owned(),
            ],
            stack
                .models
                .environmental
                .model()
                .unsupported_semantics()
                .to_vec(),
        ),
        (
            "realized_bfg",
            "urn:fortress:schema:v1:realized-behavioral-flow-graph",
            "info/realized_behavioral_flow_graph.json",
            stack
                .realized
                .graph()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec![
                "intended_bfg".to_owned(),
                "psm".to_owned(),
                "semantic_analysis".to_owned(),
                "state_effect".to_owned(),
                "information_flow".to_owned(),
                "environmental_analysis".to_owned(),
            ],
            stack.realized.graph().unsupported_semantics().to_vec(),
        ),
        (
            "reference_resolution",
            "urn:fortress:schema:v1:component-resolution-index",
            "info/component_resolution_index.json",
            stack
                .reference_resolution
                .index()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec!["ccg".to_owned()],
            Vec::new(),
        ),
        (
            "source_artifact_model",
            "urn:fortress:schema:v1:source-artifact-model",
            "info/source_artifact_model.json",
            stack
                .source_architecture
                .model()
                .to_canonical_json()
                .map_err(CertificationError::Json)?,
            EvidenceClass::StaticProof,
            vec!["ccg".to_owned(), "psm".to_owned()],
            stack
                .source_architecture
                .model()
                .unsupported_semantics()
                .to_vec(),
        ),
    ];
    entries
        .into_iter()
        .map(
            |(kind, schema, _logical_path, canonical, evidence_class, input_refs, unsupported)| {
                Ok(ArtifactEvidenceInput {
                    kind: kind.into(),
                    digest: format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())),
                    schema: schema.into(),
                    current: true,
                    input_refs,
                    evidence_class,
                    unsupported,
                })
            },
        )
        .collect()
}

type CertificationBehaviorInputs = (
    Vec<GeneratedVerificationInput>,
    Vec<BehavioralProjectionInput>,
    Vec<BehavioralRealizationEvidenceInput>,
);

#[allow(clippy::too_many_lines)]
fn certification_behavior_inputs(
    stack: &CertificationSemanticStack,
) -> Result<CertificationBehaviorInputs, AuditError> {
    let realized_value = serde_json::to_value(stack.realized.graph())
        .map_err(CertificationError::Json)
        .map_err(AuditError::Certification)?;
    let mut generated = Vec::new();
    for obligation in realized_value["verification_obligations"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let id = required_string(obligation, "id")?;
        let feature = required_string(obligation, "feature")?;
        let owner = stack
            .ccg
            .features()
            .get(&feature)
            .ok_or_else(|| {
                AuditError::ContractState(
                    format!("unknown verification Feature `{feature}`").into(),
                )
            })?
            .owner();
        let testing_module = testing_module_for_owner(&stack.ccg, owner)?;
        let checkpoints = string_array(&obligation["checkpoints"])?;
        let mut targets = checkpoints.clone();
        if checkpoints.len() == 2 {
            targets.push(format!("{}->{}", checkpoints[0], checkpoints[1]));
        }
        targets.sort();
        targets.dedup();
        generated.push(GeneratedVerificationInput {
            id,
            testing_module,
            kind: GeneratedVerificationKind::Behavioral,
            targets,
        });
    }
    let environmental_value = serde_json::to_value(stack.models.environmental.model())
        .map_err(CertificationError::Json)
        .map_err(AuditError::Certification)?;
    for obligation in environmental_value["failure_test_obligations"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let id = required_string(obligation, "id")?;
        let provenance = required_string(obligation, "contract_provenance")?;
        let path = provenance.split('#').next().unwrap_or(&provenance);
        let owner = owner_for_path(&stack.ccg, path)?;
        generated.push(GeneratedVerificationInput {
            id: id.clone(),
            testing_module: testing_module_for_owner(&stack.ccg, &owner)?,
            kind: GeneratedVerificationKind::Environmental,
            targets: vec![id],
        });
    }
    generated.sort_by(|left, right| left.id.cmp(&right.id));

    let realized_flows: BTreeMap<String, &Value> = realized_value["flows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|flow| {
            flow["feature"]
                .as_str()
                .map(|feature| (feature.to_owned(), flow))
        })
        .collect();
    let mut projection = Vec::new();
    let mut realizations = Vec::new();
    for intended in stack.intended_bfg.flows() {
        let realized = realized_flows.get(intended.feature()).copied();
        let realized_checkpoints = realized
            .and_then(|flow| flow["checkpoints"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|checkpoint| checkpoint["checkpoint"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        let realized_edges = realized
            .and_then(|flow| flow["transitions"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|edge| {
                Some((
                    edge["source"].as_str()?.to_owned(),
                    edge["target"].as_str()?.to_owned(),
                ))
            })
            .collect::<Vec<_>>();
        let contradicted = realized
            .and_then(|flow| flow["state"].as_str())
            .is_some_and(|state| state == "REALIZED_CONTRADICTED");
        if let Some(flow) = realized {
            realizations.push(BehavioralRealizationEvidenceInput {
                feature: intended.feature().to_owned(),
                coherent: flow["state"] == "REALIZED_COHERENT",
                evidence_ref: String::new(),
            });
        }
        projection.push(BehavioralProjectionInput {
            feature: intended.feature().to_owned(),
            checkpoints: intended
                .nodes()
                .iter()
                .map(|node| node.checkpoint().to_owned())
                .collect(),
            intended_edges: intended
                .edges()
                .iter()
                .map(|edge| (edge.source().to_owned(), edge.target().to_owned()))
                .collect(),
            realized_checkpoints,
            realized_edges,
            contradicted,
        });
    }
    Ok((generated, projection, realizations))
}

#[derive(Deserialize)]
struct VerificationBindingDocument {
    bindings: Vec<VerificationBindingRecord>,
}

#[derive(Deserialize)]
struct VerificationBindingRecord {
    obligation: String,
    tests: Vec<String>,
}

fn certification_verification_bindings(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    rust_tests: &[crate::rust_test_analyzer::RustTestFact],
) -> Result<Vec<VerificationBinding>, AuditError> {
    let mut bindings = Vec::new();
    for (path, bytes) in files.iter().filter(|(path, _)| {
        path.as_str() == "data/verification_bindings.json"
            || path.ends_with("/data/verification_bindings.json")
    }) {
        let testing_module = owner_for_path(ccg, path)?;
        let testing_path = ccg
            .modules()
            .get(&testing_module)
            .map(super::contract_coherency::ResolvedModule::path)
            .ok_or_else(|| {
                AuditError::ContractState(
                    format!("unknown binding owner `{testing_module}`").into(),
                )
            })?;
        if testing_path != "mods/testing" && !testing_path.ends_with("/mods/testing") {
            return Err(AuditError::ContractState(
                format!("verification binding `{path}` is not owned by a canonical Testing Module")
                    .into(),
            ));
        }
        let document: VerificationBindingDocument = serde_json::from_slice(bytes)
            .map_err(CertificationError::Json)
            .map_err(AuditError::Certification)?;
        for record in document.bindings {
            for test in &record.tests {
                let fact = rust_tests
                    .iter()
                    .find(|fact| fact.id() == test)
                    .ok_or_else(|| {
                        AuditError::ContractState(
                            format!(
                                "verification binding `{}` references unknown Test `{test}`",
                                record.obligation
                            )
                            .into(),
                        )
                    })?;
                let test_owner = owner_for_path(ccg, fact.path())?;
                if test_owner != testing_module {
                    return Err(AuditError::ContractState(
                        format!("verification binding `{}` Test `{test}` belongs to `{test_owner}`, not `{testing_module}`", record.obligation).into(),
                    ));
                }
            }
            bindings.push(VerificationBinding {
                testing_module: testing_module.clone(),
                obligation: record.obligation,
                tests: record.tests,
            });
        }
    }
    bindings.sort_by(|left, right| left.obligation.cmp(&right.obligation));
    Ok(bindings)
}

fn certification_trusted_assertions(
    stack: &CertificationSemanticStack,
) -> Result<Vec<crate::certification::TrustedAssertionInput>, AuditError> {
    let information = serde_json::to_value(stack.models.information_flow.model())
        .map_err(CertificationError::Json)
        .map_err(AuditError::Certification)?;
    let mut assertions = information["trusted_transition_diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(
            |(index, value)| crate::certification::TrustedAssertionInput {
                subject: value["symbol"]
                    .as_str()
                    .map_or_else(|| format!("trusted-transition-{index}"), str::to_owned),
                kind: value["kind"]
                    .as_str()
                    .unwrap_or("trusted_information_transition")
                    .to_owned(),
                provenance: value["provenance"]
                    .as_str()
                    .unwrap_or("distributed Function Contract")
                    .to_owned(),
            },
        )
        .collect::<Vec<_>>();
    let environmental = serde_json::to_value(stack.models.environmental.model())
        .map_err(CertificationError::Json)
        .map_err(AuditError::Certification)?;
    for operation in environmental["operations"].as_array().into_iter().flatten() {
        if operation["atomicity"] == "ATOMIC" {
            assertions.push(crate::certification::TrustedAssertionInput {
                subject: required_string(operation, "id")?,
                kind: "external_atomicity".into(),
                provenance: operation["contract_provenance"]
                    .as_str()
                    .unwrap_or("distributed Environment Contract")
                    .into(),
            });
        }
    }
    assertions.sort_by(|left, right| left.subject.cmp(&right.subject));
    Ok(assertions)
}

fn owner_for_path(ccg: &ContractCoherencyGraph, path: &str) -> Result<String, AuditError> {
    ccg.module_paths()
        .iter()
        .filter(|(_, module_path)| {
            module_path.is_empty() || path.starts_with(&format!("{module_path}/"))
        })
        .max_by_key(|(_, module_path)| module_path.len())
        .map(|(id, _)| id.clone())
        .ok_or_else(|| AuditError::ContractState(format!("no Module owns `{path}`").into()))
}

fn testing_module_for_owner(
    ccg: &ContractCoherencyGraph,
    owner: &str,
) -> Result<String, AuditError> {
    let owner_path = ccg
        .module_paths()
        .get(owner)
        .ok_or_else(|| AuditError::ContractState(format!("unknown Module `{owner}`").into()))?;
    let expected = if owner_path.is_empty() {
        "mods/testing".to_owned()
    } else {
        format!("{owner_path}/mods/testing")
    };
    ccg.module_paths()
        .iter()
        .find(|(_, path)| **path == expected)
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            AuditError::ContractState(
                format!(
                    "Module `{owner}` has no canonical Testing child for certification binding"
                )
                .into(),
            )
        })
}

fn required_string(value: &Value, field: &str) -> Result<String, AuditError> {
    value[field].as_str().map(str::to_owned).ok_or_else(|| {
        AuditError::ContractState(
            format!("certification semantic input lacks string `{field}`").into(),
        )
    })
}

fn string_array(value: &Value) -> Result<Vec<String>, AuditError> {
    value
        .as_array()
        .ok_or_else(|| {
            AuditError::ContractState("certification semantic input expected a string array".into())
        })?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                AuditError::ContractState(
                    "certification semantic input contains a non-string array member".into(),
                )
            })
        })
        .collect()
}

struct AnalysisModels {
    psm: ProgramSemanticModel,
    semantic: SemanticAnalysisEvaluation,
    state_effect: StateEffectAnalysisEvaluation,
    information_flow: InformationFlowEvaluation,
    environmental: EnvironmentalAnalysisEvaluation,
}

fn compile_analysis_models(
    prepared: &PreparedAudit,
    ccg: &ContractCoherencyGraph,
) -> Result<AnalysisModels, AuditError> {
    let observation_input =
        implementation_input(&prepared.snapshot, ccg, &prepared.observed_files)?;
    let observed = observe_rust_implementation(&observation_input)
        .map_err(AuditError::ImplementationObservation)?;
    compile_analysis_models_from_observed(prepared, ccg, observation_input, &observed)
}

fn compile_analysis_models_from_observed(
    prepared: &PreparedAudit,
    ccg: &ContractCoherencyGraph,
    observation_input: ImplementationObservationInput,
    observed: &ObservedImplementation,
) -> Result<AnalysisModels, AuditError> {
    let psm = compile_psm_from_observed(prepared, ccg, observation_input, observed)?;
    let sources = function_contract_sources(ccg, &prepared.observed_files)?;
    let contracts: ResolvedFunctionContracts =
        load_function_contracts(&psm, sources).map_err(AuditError::FunctionContracts)?;
    let semantic = analyze_program_domains(&psm, &contracts, prepared.standard.bundle.edition())
        .map_err(AuditError::SemanticAnalysis)?;
    let state_sources = state_contract_sources(ccg, &prepared.observed_files)?;
    let state_contracts =
        load_state_contracts(&psm, state_sources).map_err(AuditError::StateContracts)?;
    let state_effect = analyze_state_effects(
        &psm,
        &semantic,
        &state_contracts,
        &contracts,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::StateEffectAnalysis)?;
    let policy =
        load_information_flow_policy(information_flow_policy_sources(&prepared.observed_files)?)
            .map_err(AuditError::InformationFlowPolicy)?;
    let information_flow = analyze_information_flow(
        &psm,
        &semantic,
        &state_effect,
        &policy,
        &contracts,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::InformationFlowAnalysis)?;
    let environment_sources = environment_contract_sources(ccg, &prepared.observed_files)?;
    let environment_contracts =
        load_environment_contracts(&psm, &state_contracts, &policy, environment_sources)
            .map_err(AuditError::EnvironmentContracts)?;
    let environmental = analyze_environmental_semantics(
        &psm,
        &semantic,
        &state_effect,
        &information_flow,
        &environment_contracts,
        &contracts,
        prepared.standard.bundle.edition(),
    )
    .map_err(AuditError::EnvironmentalAnalysis)?;
    Ok(AnalysisModels {
        psm,
        semantic,
        state_effect,
        information_flow,
        environmental,
    })
}

fn behavior_realization_contract_sources(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<BehaviorRealizationContractSource>, AuditError> {
    files
        .iter()
        .filter(|(path, _)| {
            path.as_str() == "data/behavior_realization_contracts.json"
                || path.ends_with("/data/behavior_realization_contracts.json")
        })
        .map(|(path, bytes)| {
            let owner = ccg
                .module_paths()
                .iter()
                .filter(|(_, module_path)| {
                    module_path.is_empty() || path.starts_with(&format!("{module_path}/"))
                })
                .max_by_key(|(_, module_path)| module_path.len())
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    AuditError::ContractState(format!("no Module owns '{path}'").into())
                })?;
            let source =
                std::str::from_utf8(bytes).map_err(|_| AuditError::NonUtf8(path.clone().into()))?;
            Ok(BehaviorRealizationContractSource::new(owner, path, source))
        })
        .collect()
}

fn environment_contract_sources(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<EnvironmentContractSource>, AuditError> {
    files
        .iter()
        .filter(|(path, _)| {
            path.as_str() == "data/environment_contracts.json"
                || path.ends_with("/data/environment_contracts.json")
        })
        .map(|(path, bytes)| {
            let owner = ccg
                .module_paths()
                .iter()
                .filter(|(_, module_path)| {
                    module_path.is_empty() || path.starts_with(&format!("{module_path}/"))
                })
                .max_by_key(|(_, module_path)| module_path.len())
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    AuditError::ContractState(format!("no Module owns `{path}`").into())
                })?;
            let source =
                std::str::from_utf8(bytes).map_err(|_| AuditError::NonUtf8(path.clone().into()))?;
            Ok(EnvironmentContractSource::new(owner, path, source))
        })
        .collect()
}

fn information_flow_policy_sources(
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<InformationFlowPolicySource>, AuditError> {
    files
        .iter()
        .filter(|(path, _)| path.as_str() == "data/information_flow_policy.json")
        .map(|(path, bytes)| {
            let source =
                std::str::from_utf8(bytes).map_err(|_| AuditError::NonUtf8(path.clone().into()))?;
            Ok(InformationFlowPolicySource::new(path, source))
        })
        .collect()
}

fn function_contract_sources(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<FunctionContractSource>, AuditError> {
    files
        .iter()
        .filter(|(path, _)| {
            path.as_str() == "data/function_contracts.json"
                || path.ends_with("/data/function_contracts.json")
        })
        .map(|(path, bytes)| {
            let owner = ccg
                .module_paths()
                .iter()
                .filter(|(_, module_path)| {
                    module_path.is_empty() || path.starts_with(&format!("{module_path}/"))
                })
                .max_by_key(|(_, module_path)| module_path.len())
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    AuditError::ContractState(format!("no Module owns `{path}`").into())
                })?;
            let source =
                std::str::from_utf8(bytes).map_err(|_| AuditError::NonUtf8(path.clone().into()))?;
            Ok(FunctionContractSource::new(owner, path, source))
        })
        .collect()
}

fn state_contract_sources(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<StateContractSource>, AuditError> {
    files
        .iter()
        .filter(|(path, _)| {
            path.as_str() == "data/state_contracts.json"
                || path.ends_with("/data/state_contracts.json")
        })
        .map(|(path, bytes)| {
            let owner = ccg
                .module_paths()
                .iter()
                .filter(|(_, module_path)| {
                    module_path.is_empty() || path.starts_with(&format!("{module_path}/"))
                })
                .max_by_key(|(_, module_path)| module_path.len())
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    AuditError::ContractState(format!("no Module owns `{path}`").into())
                })?;
            let source =
                std::str::from_utf8(bytes).map_err(|_| AuditError::NonUtf8(path.clone().into()))?;
            Ok(StateContractSource::new(owner, path, source))
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn audit_repository_with_models(
    root: &Path,
    include_implementation_observation: bool,
) -> Result<
    (
        AuditResult,
        ContractCoherencyGraph,
        IntendedBehavioralFlowGraph,
    ),
    AuditError,
> {
    let prepared = prepare_audit(root)?;
    let standard = &prepared.standard.bundle;
    let ccg = prepared
        .ccg_compilation
        .graph()
        .ok_or_else(|| AuditError::ContractState("prepared audit did not contain a CCG".into()))?;
    let (observed_implementation, architecture_realization) = reconcile_repository_implementation(
        &prepared.snapshot,
        ccg,
        &prepared.observed_files,
        standard.edition(),
        include_implementation_observation,
    )?;
    let analysis_models = if include_implementation_observation {
        let observation_input =
            implementation_input(&prepared.snapshot, ccg, &prepared.observed_files)?;
        Some(compile_analysis_models_from_observed(
            &prepared,
            ccg,
            observation_input,
            &observed_implementation,
        )?)
    } else {
        None
    };
    let documentation =
        evaluate_repository_documentation(root, &prepared.snapshot, ccg, standard.edition())
            .map_err(AuditError::Documentation)?;
    let contract_coherency = evaluate_contract_coherency(
        prepared.ccg_compilation.clone(),
        &documentation,
        standard.edition(),
    )
    .map_err(EvaluationError::Finding)
    .map_err(AuditError::Evaluation)?;
    let ccg = contract_coherency.graph().ok_or_else(|| {
        AuditError::ContractState("CCG compilation did not produce a graph".into())
    })?;
    let behavioral_semantics = evaluate_behavioral_semantics(ccg, standard.edition())
        .map_err(AuditError::BehavioralSemantics)?;
    let reference_resolution =
        evaluate_reference_resolution(ccg, &prepared.observed_files, standard.edition())
            .map_err(AuditError::ReferenceResolution)?;
    let source_architecture = compile_source_architecture_from(
        &prepared,
        ccg,
        analysis_models.as_ref().map(|models| &models.psm),
    )?;
    let behavioral_realization: Option<BehavioralRealizationEvaluation> =
        if let Some(models) = &analysis_models {
            let sources = behavior_realization_contract_sources(ccg, &prepared.observed_files)?;
            let contracts = load_behavior_realization_contracts(
                ccg,
                behavioral_semantics.graph(),
                &models.psm,
                models.state_effect.model(),
                models.information_flow.model(),
                models.environmental.model(),
                sources,
            )
            .map_err(AuditError::BehaviorRealizationContracts)?;
            Some(
                evaluate_behavioral_realization(
                    ccg,
                    behavioral_semantics.graph(),
                    &models.psm,
                    models.semantic.model(),
                    models.state_effect.model(),
                    models.information_flow.model(),
                    models.environmental.model(),
                    &contracts,
                    standard.edition(),
                )
                .map_err(AuditError::BehavioralRealization)?,
            )
        } else {
            None
        };
    let architecture_diagnostics =
        derive_architecture_diagnostics(ccg, &observed_implementation, &architecture_realization)
            .map_err(AuditError::ArchitectureDiagnostics)?;
    let analyses = analysis_models.as_ref();
    let evaluation_inputs = CompleteEvaluationInputs::new(
        &prepared.rust_tests,
        RepositoryEvaluationInputs::new(
            &documentation,
            &contract_coherency,
            &architecture_realization,
            &behavioral_semantics,
            behavioral_realization.as_ref(),
            &reference_resolution,
            &source_architecture,
        ),
        ProgramEvaluationInputs::new(
            analyses.map(|models| &models.semantic),
            analyses.map(|models| &models.state_effect),
            analyses.map(|models| &models.information_flow),
            analyses.map(|models| &models.environmental),
        ),
    );
    let evaluation = evaluate_snapshot_rules(standard, &prepared.snapshot, ccg, evaluation_inputs)?;
    let mut unsupported_analysis = architecture_diagnostics.unsupported_analysis().to_vec();
    unsupported_analysis.extend(
        behavioral_semantics
            .graph()
            .unsupported_semantics()
            .iter()
            .map(|value| format!("intended_bfg:{value}")),
    );
    if let Some(models) = &analysis_models {
        unsupported_analysis.extend(
            models
                .semantic
                .model()
                .unsupported_semantics()
                .iter()
                .map(|value| format!("semantic_analysis:{value}")),
        );
        unsupported_analysis.extend(
            models
                .state_effect
                .model()
                .unsupported_semantics()
                .iter()
                .map(|value| format!("state_effect_analysis:{value}")),
        );
        unsupported_analysis.extend(
            models
                .information_flow
                .model()
                .unsupported_semantics()
                .iter()
                .map(|value| format!("information_flow_analysis:{value}")),
        );
        unsupported_analysis.extend(
            models
                .environmental
                .model()
                .unsupported_semantics()
                .iter()
                .map(|value| format!("environmental_analysis:{value}")),
        );
    }
    if let Some(realization) = &behavioral_realization {
        unsupported_analysis.extend(
            realization
                .graph()
                .unsupported_semantics()
                .iter()
                .map(|value| format!("behavioral_realization:{value}")),
        );
    }
    unsupported_analysis.extend(
        source_architecture
            .model()
            .unsupported_semantics()
            .iter()
            .map(|value| format!("source_architecture:{value}")),
    );
    unsupported_analysis.sort();
    unsupported_analysis.dedup();
    Ok((
        result_from_evaluation(
            &prepared.snapshot,
            &evaluation,
            &architecture_diagnostics,
            unsupported_analysis,
        ),
        ccg.clone(),
        behavioral_semantics.graph().clone(),
    ))
}

struct PreparedAudit {
    observed_files: BTreeMap<String, Vec<u8>>,
    standard: LoadedStandard,
    rust_tests: Vec<crate::rust_test_analyzer::RustTestFact>,
    ccg_compilation: CcgCompilation,
    snapshot: RepositorySnapshot,
}

fn prepare_audit(root: &Path) -> Result<PreparedAudit, AuditError> {
    let project_document = read_document(root, "data/project.json")?;
    let project = ProjectConfiguration::from_json_str(project_document.source()?)
        .map_err(AuditError::Project)?;
    let policy = ObservationPolicy::new(project.observation_exclusions().iter().cloned())
        .map_err(AuditError::ObservationPolicy)?;
    let observation = observe_repository_stably(root, &policy).map_err(AuditError::Snapshot)?;
    let observed_files = read_observed_files(root, &observation)?;
    let standard = load_standard(root, &observed_files)?;
    let rust_tests = analyze_observed_rust_tests(
        observed_files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    )
    .map_err(AuditError::RustAnalyzer)?;
    let observed_test_facts: Vec<CcgObservedTestFact> =
        rust_tests.iter().map(CcgObservedTestFact::from).collect();
    let ccg_compilation = compile_contract_coherency_graph(
        &observed_files,
        &ContractStandardIndex::from_bundle(&standard.bundle),
        Some(&observed_test_facts),
    );
    let ccg = ccg_compilation.graph().ok_or_else(|| {
        AuditError::ContractState(
            ccg_compilation
                .violations()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
                .into(),
        )
    })?;
    let contract_documents = contract_documents(&observed_files);
    let documents = SnapshotDocuments::new(
        &standard.manifest.path,
        &standard.manifest.bytes,
        standard
            .rules
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
        &project_document.bytes,
        contract_documents
            .iter()
            .map(|document| (document.path.as_str(), document.bytes.as_slice())),
    );
    let snapshot = build_repository_snapshot(root, &policy, ccg, &standard.bundle, &documents)
        .map_err(AuditError::Snapshot)?;
    verify_loaded_inputs(
        &snapshot,
        std::iter::once(&project_document)
            .chain(std::iter::once(&standard.manifest))
            .chain(standard.rules.iter())
            .chain(contract_documents.iter()),
    )?;
    verify_observed_files(&snapshot, &observed_files)?;
    Ok(PreparedAudit {
        observed_files,
        standard,
        rust_tests,
        ccg_compilation,
        snapshot,
    })
}

fn contract_documents(files: &BTreeMap<String, Vec<u8>>) -> Vec<LoadedDocument> {
    files
        .iter()
        .filter(|(path, _)| path.as_str() == "contract.json" || path.ends_with("/contract.json"))
        .map(|(path, bytes)| LoadedDocument {
            path: path.clone(),
            bytes: bytes.clone(),
        })
        .collect()
}

fn evaluate_snapshot_rules(
    standard: &StandardBundle,
    snapshot: &RepositorySnapshot,
    ccg: &ContractCoherencyGraph,
    inputs: CompleteEvaluationInputs<'_>,
) -> Result<crate::evaluation::SnapshotEvaluation, AuditError> {
    let paths: Vec<String> = snapshot
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let architecture = ArchitectureManifest::from_ccg(ccg, &paths);
    SnapshotRuleEngine::builtin()
        .evaluate_complete(standard, snapshot, &architecture, inputs)
        .map_err(AuditError::Evaluation)
}

fn implementation_input(
    snapshot: &RepositorySnapshot,
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<ImplementationObservationInput, AuditError> {
    let by_path: BTreeMap<&str, &crate::observation::ObservedFile> = snapshot
        .files()
        .iter()
        .map(|file| (file.path(), file))
        .collect();
    let snapshot_files = files
        .iter()
        .map(|(path, bytes)| {
            let identity = by_path
                .get(path.as_str())
                .ok_or_else(|| AuditError::InputMismatch(path.clone().into()))?;
            Ok(SnapshotBoundFile::new(
                path,
                identity.size(),
                identity.sha256(),
                bytes.clone(),
            ))
        })
        .collect::<Result<Vec<_>, AuditError>>()?;
    let modules = ccg
        .modules()
        .iter()
        .map(|(id, module)| ModuleTerritory::new(id, module.path()))
        .collect();
    Ok(ImplementationObservationInput::new(
        snapshot.snapshot_fingerprint(),
        snapshot_files,
        modules,
    ))
}

fn reconcile_repository_implementation(
    snapshot: &RepositorySnapshot,
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    standard_edition: &str,
    include_observation: bool,
) -> Result<(ObservedImplementation, ArchitectureRealization), AuditError> {
    let observed = if include_observation {
        let input = implementation_input(snapshot, ccg, files)?;
        observe_rust_implementation(&input).map_err(AuditError::ImplementationObservation)?
    } else {
        crate::implementation_observation::ObservedImplementation::from_facts(
            snapshot.snapshot_fingerprint(),
            "fortress-ccg-intent-only",
            env!("CARGO_PKG_VERSION"),
            Vec::new(),
            Vec::new(),
        )
    };
    let realization = reconcile_implementation(ccg, &observed, standard_edition)
        .map_err(EvaluationError::Finding)
        .map_err(AuditError::Evaluation)?;
    Ok((observed, realization))
}

fn result_from_evaluation(
    snapshot: &RepositorySnapshot,
    evaluation: &crate::evaluation::SnapshotEvaluation,
    architecture_diagnostics: &crate::architecture_diagnostics::ArchitectureDiagnostics,
    unsupported_analysis: Vec<String>,
) -> AuditResult {
    let summary = AuditSummary {
        rules_evaluated: evaluation.evaluated_count(),
        passed: evaluation.passed_count(),
        failed: evaluation.failed_count(),
        unsupported: evaluation.unsupported_count(),
    };
    AuditResult {
        schema_version: AUDIT_RESULT_SCHEMA_VERSION,
        project_id: snapshot.project_id().into(),
        standard: AuditStandard {
            edition: snapshot.standard_edition().into(),
            status: snapshot.standard_status().into(),
        },
        snapshot_fingerprint: snapshot.snapshot_fingerprint().into(),
        repository_content_fingerprint: snapshot.repository_content_fingerprint().into(),
        outcome: if summary.failed == 0 {
            AuditOutcome::Pass
        } else {
            AuditOutcome::Fail
        },
        summary,
        rules: evaluation.rules().to_vec(),
        findings: evaluation.findings().to_vec(),
        diagnostics: architecture_diagnostics.diagnostics().to_vec(),
        unsupported_analysis,
    }
}

#[derive(Deserialize)]
struct StandardManifestIndex {
    rules: Vec<String>,
}

struct LoadedDocument {
    path: String,
    bytes: Vec<u8>,
}

struct LoadedStandard {
    manifest: LoadedDocument,
    rules: Vec<LoadedDocument>,
    bundle: StandardBundle,
}

impl LoadedDocument {
    fn source(&self) -> Result<&str, AuditError> {
        std::str::from_utf8(&self.bytes).map_err(|_| AuditError::NonUtf8(self.path.clone().into()))
    }
}

fn read_document(root: &Path, path: &str) -> Result<LoadedDocument, AuditError> {
    let absolute = root.join(path);
    let bytes = fs::read(&absolute).map_err(|source| AuditError::Io {
        path: absolute,
        source,
    })?;
    Ok(LoadedDocument {
        path: path.into(),
        bytes,
    })
}

fn read_observed_files(
    root: &Path,
    observation: &RepositoryObservation,
) -> Result<BTreeMap<String, Vec<u8>>, AuditError> {
    observation
        .files()
        .iter()
        .map(|file| {
            let document = read_document(root, file.path())?;
            Ok((document.path, document.bytes))
        })
        .collect()
}

fn load_standard(
    root: &Path,
    observed_files: &BTreeMap<String, Vec<u8>>,
) -> Result<LoadedStandard, AuditError> {
    let manifest_path = find_standard_manifest(observed_files)?;
    let manifest = read_document(root, &manifest_path)?;
    let index: StandardManifestIndex =
        serde_json::from_str(manifest.source()?).map_err(AuditError::StandardManifestIndex)?;
    let rules: Vec<LoadedDocument> = index
        .rules
        .iter()
        .map(|relative| read_document(root, relative))
        .collect::<Result<_, _>>()?;
    let sources: Vec<(&str, &str)> = rules
        .iter()
        .zip(&index.rules)
        .map(|(document, relative)| Ok((relative.as_str(), document.source()?)))
        .collect::<Result<_, AuditError>>()?;
    let bundle = StandardBundle::from_json_documents(manifest.source()?, &sources)
        .map_err(AuditError::Standard)?;
    Ok(LoadedStandard {
        manifest,
        rules,
        bundle,
    })
}

fn verify_observed_files(
    snapshot: &RepositorySnapshot,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), AuditError> {
    if snapshot.files().len() != files.len() {
        return Err(AuditError::InputMismatch(
            "stabilized repository inventory".into(),
        ));
    }
    for (path, bytes) in files {
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        let size = u64::try_from(bytes.len())
            .map_err(|_| AuditError::InputMismatch(path.clone().into()))?;
        if !snapshot
            .files()
            .iter()
            .any(|file| file.path() == path && file.size() == size && file.sha256() == digest)
        {
            return Err(AuditError::InputMismatch(path.clone().into()));
        }
    }
    Ok(())
}

fn find_standard_manifest(files: &BTreeMap<String, Vec<u8>>) -> Result<String, AuditError> {
    let candidates: Vec<String> = files
        .keys()
        .filter(|path| {
            path.as_str() == "standard_manifest.json" || path.ends_with("/standard_manifest.json")
        })
        .cloned()
        .collect();
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(AuditError::StandardManifestDiscovery(
            "no standard_manifest.json exists in the stabilized repository".into(),
        )),
        _ => Err(AuditError::StandardManifestDiscovery(
            format!(
                "multiple standard_manifest.json candidates exist: {}",
                candidates.join(", ")
            )
            .into(),
        )),
    }
}

fn verify_loaded_inputs<'a>(
    snapshot: &RepositorySnapshot,
    documents: impl IntoIterator<Item = &'a LoadedDocument>,
) -> Result<(), AuditError> {
    for document in documents {
        let digest = format!("sha256:{:x}", Sha256::digest(&document.bytes));
        let size = u64::try_from(document.bytes.len())
            .map_err(|_| AuditError::InputMismatch(document.path.clone().into()))?;
        let matches = snapshot.files().iter().any(|file| {
            file.path() == document.path && file.size() == size && file.sha256() == digest
        });
        if !matches {
            return Err(AuditError::InputMismatch(document.path.clone().into()));
        }
    }
    Ok(())
}

/// Explains why repository audit construction could not complete.
#[derive(Debug)]
pub enum AuditError {
    /// A required document could not be read.
    Io {
        /// Filesystem path used for the read.
        path: PathBuf,
        /// Underlying read failure.
        source: std::io::Error,
    },
    /// A required JSON document was not UTF-8.
    NonUtf8(Box<str>),
    /// Operational project configuration was invalid.
    Project(ProjectConfigurationLoadError),
    /// The applicable standard manifest could not be discovered unambiguously.
    StandardManifestDiscovery(Box<str>),
    /// Standard manifest rule index was invalid JSON.
    StandardManifestIndex(serde_json::Error),
    /// Exact standard bundle was invalid.
    Standard(StandardLoadError),
    /// Contracts could not form the minimum resolved state needed for snapshot identity.
    ContractState(Box<str>),
    /// Observation exclusions were invalid.
    ObservationPolicy(ObservationError),
    /// Stabilized snapshot construction failed.
    Snapshot(SnapshotError),
    /// Loaded input bytes did not match the stabilized inventory.
    InputMismatch(Box<str>),
    /// Snapshot-bound Rust analysis failed.
    RustAnalyzer(RustAnalyzerError),
    /// Snapshot-bound implementation observation failed.
    ImplementationObservation(ImplementationObservationError),
    /// Snapshot-bound Program Semantic Model compilation failed.
    ProgramSemantics(ProgramSemanticError),
    /// Distributed Function Contract authority was invalid.
    FunctionContracts(FunctionContractError),
    /// Semantic Analysis result construction failed.
    SemanticAnalysis(SemanticAnalysisError),
    /// Distributed State Contract authority was invalid.
    StateContracts(StateContractError),
    /// State and Effect Analysis result construction failed.
    StateEffectAnalysis(StateEffectAnalysisError),
    /// Project information-flow policy authority was invalid.
    InformationFlowPolicy(InformationFlowPolicyError),
    /// Information Flow Analysis result construction failed.
    InformationFlowAnalysis(InformationFlowAnalysisError),
    /// Distributed Environment Contract authority was invalid.
    EnvironmentContracts(EnvironmentContractError),
    /// Environmental Analysis result construction failed.
    EnvironmentalAnalysis(EnvironmentalAnalysisError),
    /// Distributed Behavior Realization Contract authority was invalid.
    BehaviorRealizationContracts(BehaviorRealizationContractError),
    /// Realized BFG construction or finding normalization failed.
    BehavioralRealization(BehavioralRealizationError),
    /// Architecture diagnostic derivation failed.
    ArchitectureDiagnostics(ArchitectureDiagnosticError),
    /// Intended behavioral semantics could not compile or normalize.
    BehavioralSemantics(BehavioralSemanticsError),
    /// Snapshot-bound documentation and contract evaluation failed.
    Documentation(DocumentationEvaluationError),
    /// CCG-backed reference resolution failed.
    ReferenceResolution(ReferenceResolutionError),
    /// Source Artifact Model evaluation could not normalize a finding.
    SourceArchitecture(FindingError),
    /// Rule evaluation failed.
    Evaluation(EvaluationError),
    /// Certification evidence or profile construction failed.
    Certification(CertificationError),
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::NonUtf8(path) => write!(formatter, "audit input `{path}` is not UTF-8"),
            Self::Project(error) => write!(formatter, "invalid project state: {error}"),
            Self::StandardManifestDiscovery(error) => {
                write!(formatter, "standard manifest discovery failed: {error}")
            }
            Self::StandardManifestIndex(error) => {
                write!(formatter, "invalid standard manifest rule index: {error}")
            }
            Self::Standard(error) => write!(formatter, "invalid standard bundle: {error}"),
            Self::ContractState(error) => write!(formatter, "invalid contract state: {error}"),
            Self::ObservationPolicy(error) => {
                write!(formatter, "invalid observation policy: {error}")
            }
            Self::Snapshot(error) => write!(formatter, "snapshot construction failed: {error}"),
            Self::InputMismatch(path) => write!(
                formatter,
                "loaded input `{path}` does not match the stabilized snapshot"
            ),
            Self::RustAnalyzer(error) => write!(formatter, "Rust test analysis failed: {error}"),
            Self::ImplementationObservation(error) => {
                write!(formatter, "implementation observation failed: {error}")
            }
            Self::ProgramSemantics(error) => {
                write!(formatter, "program semantics failed: {error}")
            }
            Self::FunctionContracts(error) => {
                write!(formatter, "function contracts failed: {error}")
            }
            Self::SemanticAnalysis(error) => {
                write!(formatter, "semantic analysis failed: {error}")
            }
            Self::StateContracts(error) => {
                write!(formatter, "state contracts failed: {error}")
            }
            Self::StateEffectAnalysis(error) => {
                write!(formatter, "state and effect analysis failed: {error}")
            }
            Self::InformationFlowPolicy(error) => {
                write!(formatter, "information-flow policy failed: {error}")
            }
            Self::InformationFlowAnalysis(error) => {
                write!(formatter, "information-flow analysis failed: {error}")
            }
            Self::EnvironmentContracts(error) => {
                write!(formatter, "environment contracts failed: {error}")
            }
            Self::EnvironmentalAnalysis(error) => {
                write!(formatter, "environmental analysis failed: {error}")
            }
            Self::BehaviorRealizationContracts(error) => {
                write!(formatter, "behavior realization contracts failed: {error}")
            }
            Self::BehavioralRealization(error) => {
                write!(formatter, "behavioral realization failed: {error}")
            }
            Self::ArchitectureDiagnostics(error) => {
                write!(
                    formatter,
                    "architecture diagnostic derivation failed: {error}"
                )
            }
            Self::BehavioralSemantics(error) => {
                write!(formatter, "behavioral semantics failed: {error}")
            }
            Self::Documentation(error) => {
                write!(formatter, "documentation evaluation failed: {error}")
            }
            Self::ReferenceResolution(error) => {
                write!(formatter, "reference resolution failed: {error}")
            }
            Self::SourceArchitecture(error) => {
                write!(formatter, "source architecture failed: {error}")
            }
            Self::Evaluation(error) => {
                write!(formatter, "snapshot rule evaluation failed: {error}")
            }
            Self::Certification(error) => {
                write!(formatter, "snapshot certification failed: {error}")
            }
        }
    }
}

impl Error for AuditError {}

impl From<CertificationError> for AuditError {
    fn from(value: CertificationError) -> Self {
        Self::Certification(value)
    }
}
