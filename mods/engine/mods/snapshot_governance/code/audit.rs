//! End-to-end provider-independent Snapshot Governance repository audit.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::architecture::ArchitectureManifest;
use crate::architecture_diagnostics::{
    ArchitectureDiagnostic, ArchitectureDiagnosticError, derive_architecture_diagnostics,
};
use crate::architecture_realization::{ArchitectureRealization, reconcile_implementation};
use crate::behavioral_semantics::{
    BehavioralSemanticsError, IntendedBehavioralFlowGraph, evaluate_behavioral_semantics,
};
use crate::contract::evaluate_contract_coherency;
use crate::contract_coherency::{
    CcgCompilation, CcgObservedTestFact, ContractCoherencyGraph, ContractStandardIndex,
    compile_contract_coherency_graph,
};
use crate::documentation::{DocumentationEvaluationError, evaluate_repository_documentation};
use crate::evaluation::{
    CompleteEvaluationInputs, EvaluationError, ProgramEvaluationInputs, RuleExecution,
    SnapshotRuleEngine,
};
use crate::finding::CanonicalFinding;
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
use crate::rust_test_analyzer::{RustAnalyzerError, analyze_observed_rust_tests};
use crate::semantic_analysis::{
    FunctionContractError, FunctionContractSource, ResolvedFunctionContracts,
    SemanticAnalysisError, SemanticAnalysisEvaluation, analyze_program_domains,
    load_function_contracts,
};
use crate::snapshot::{
    RepositorySnapshot, SnapshotDocuments, SnapshotError, build_repository_snapshot,
    observe_repository_stably,
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

struct AnalysisModels {
    semantic: SemanticAnalysisEvaluation,
    state_effect: StateEffectAnalysisEvaluation,
    information_flow: InformationFlowEvaluation,
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
    Ok(AnalysisModels {
        semantic,
        state_effect,
        information_flow,
    })
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
    let contract_coherency =
        evaluate_contract_coherency(prepared.ccg_compilation, &documentation, standard.edition())
            .map_err(EvaluationError::Finding)
            .map_err(AuditError::Evaluation)?;
    let ccg = contract_coherency.graph().ok_or_else(|| {
        AuditError::ContractState("CCG compilation did not produce a graph".into())
    })?;
    let behavioral_semantics = evaluate_behavioral_semantics(ccg, standard.edition())
        .map_err(AuditError::BehavioralSemantics)?;
    let architecture_diagnostics =
        derive_architecture_diagnostics(ccg, &observed_implementation, &architecture_realization)
            .map_err(AuditError::ArchitectureDiagnostics)?;
    let analyses = analysis_models.as_ref();
    let evaluation_inputs = CompleteEvaluationInputs::new(
        &prepared.rust_tests,
        &documentation,
        &contract_coherency,
        &architecture_realization,
        &behavioral_semantics,
        ProgramEvaluationInputs::new(
            analyses.map(|models| &models.semantic),
            analyses.map(|models| &models.state_effect),
            analyses.map(|models| &models.information_flow),
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
    }
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
    /// Architecture diagnostic derivation failed.
    ArchitectureDiagnostics(ArchitectureDiagnosticError),
    /// Intended behavioral semantics could not compile or normalize.
    BehavioralSemantics(BehavioralSemanticsError),
    /// Snapshot-bound documentation and contract evaluation failed.
    Documentation(DocumentationEvaluationError),
    /// Rule evaluation failed.
    Evaluation(EvaluationError),
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
            Self::Evaluation(error) => {
                write!(formatter, "snapshot rule evaluation failed: {error}")
            }
        }
    }
}

impl Error for AuditError {}
