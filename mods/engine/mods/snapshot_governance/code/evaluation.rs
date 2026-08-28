//! Truthful evaluation of implemented Snapshot Governance rules.
//!
//! The engine walks the exact loaded standard bundle, invokes only registered
//! native evaluators, normalizes violations, and reports unsupported rules
//! explicitly. Absence of an evaluator never becomes a pass.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use crate::architecture::{ARCH_DEPENDENCY_RULE_ID, ArchitectureManifest};
use crate::architecture_realization::{ARCH_REALIZATION_RULE_ID, ArchitectureRealization};
use crate::behavioral_realization::{
    BEHAVIOR_BYPASS_RULE_ID, BEHAVIOR_REALIZATION_RULE_ID, BehavioralRealizationEvaluation,
};
use crate::behavioral_semantics::{BEHAVIOR_FLOW_RULE_ID, BehavioralSemanticsEvaluation};
use crate::contract::{CONTRACT_COHERENCY_RULE_ID, ContractCoherencyEvaluation};
use crate::documentation::{DocumentationConformanceReport, REPO_DOCS_RULE_ID};
use crate::environmental_semantics::{
    EnvironmentalAnalysisEvaluation, PROGRAM_ENVIRONMENT_RULE_ID, PROGRAM_RECOVERY_RULE_ID,
    PROGRAM_RETRY_RULE_ID,
};
use crate::finding::{CanonicalFinding, FindingError};
use crate::information_flow::{InformationFlowEvaluation, PROGRAM_INFOFLOW_RULE_ID};
use crate::ownership::{ARCH_OWNERSHIP_RULE_ID, evaluate_file_ownership};
use crate::placement::{REPO_MODULE_RULE_ID, evaluate_module_grammar};
use crate::rust_test_analyzer::RustTestFact;
use crate::semantic_analysis::{PROGRAM_DOMAIN_RULE_ID, SemanticAnalysisEvaluation};
use crate::snapshot::RepositorySnapshot;
use crate::standard::StandardBundle;
use crate::state_effect_analysis::{
    PROGRAM_EFFECT_RULE_ID, PROGRAM_STATE_RULE_ID, StateEffectAnalysisEvaluation,
};
use crate::testing_boundary::{TEST_BOUNDARY_RULE_ID, evaluate_testing_boundaries};
use crate::traceability::{TEST_TRACEABILITY_RULE_ID, evaluate_ccg_test_traceability};

/// Truthful execution result for one applicable standard rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleExecutionState {
    /// A registered evaluator ran and produced no violation.
    Passed,
    /// A registered evaluator ran and produced one or more violations.
    Failed,
    /// No Snapshot Governance evaluator is implemented for this rule.
    Unsupported,
}

/// Deterministic execution record for one standard rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuleExecution {
    rule_id: String,
    state: RuleExecutionState,
    applicable: bool,
    findings: usize,
    detail: String,
}

impl RuleExecution {
    /// Returns the stable rule identity.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the truthful evaluator state.
    #[must_use]
    pub const fn state(&self) -> RuleExecutionState {
        self.state
    }

    /// Returns whether the current engine treated the rule as applicable.
    #[must_use]
    pub const fn applicable(&self) -> bool {
        self.applicable
    }

    /// Returns the number of normalized findings produced.
    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.findings
    }

    /// Returns the truthful evaluator detail, including explicit unsupported semantics.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Deterministic aggregate of rule executions and normalized findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotEvaluation {
    standard_edition: String,
    snapshot_fingerprint: String,
    rules: Vec<RuleExecution>,
    findings: Vec<CanonicalFinding>,
}

impl SnapshotEvaluation {
    /// Returns the exact evaluated standard edition.
    #[must_use]
    pub fn standard_edition(&self) -> &str {
        &self.standard_edition
    }

    /// Returns the exact evaluated snapshot identity.
    #[must_use]
    pub fn snapshot_fingerprint(&self) -> &str {
        &self.snapshot_fingerprint
    }

    /// Returns execution records sorted by stable rule identity.
    #[must_use]
    pub fn rules(&self) -> &[RuleExecution] {
        &self.rules
    }

    /// Returns canonical findings in global deterministic order.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns the number of actually evaluated rules.
    #[must_use]
    pub fn evaluated_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|execution| {
                execution.applicable
                    && matches!(
                        execution.state,
                        RuleExecutionState::Passed | RuleExecutionState::Failed
                    )
            })
            .count()
    }

    /// Returns the number of evaluated rules without violations.
    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|execution| {
                execution.applicable && execution.state == RuleExecutionState::Passed
            })
            .count()
    }

    /// Returns the number of evaluated rules with violations.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|execution| {
                execution.applicable && execution.state == RuleExecutionState::Failed
            })
            .count()
    }

    /// Returns the number of applicable rules lacking an evaluator.
    #[must_use]
    pub fn unsupported_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|execution| execution.state == RuleExecutionState::Unsupported)
            .count()
    }
}

/// Registry and dispatcher for implemented provider-independent snapshot rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct SnapshotRuleEngine;

/// Complete snapshot-bound evidence supplied to all implemented rule families.
#[derive(Clone, Copy, Debug)]
pub struct CompleteEvaluationInputs<'a> {
    rust_tests: &'a [RustTestFact],
    documentation: &'a DocumentationConformanceReport,
    contract_coherency: &'a ContractCoherencyEvaluation,
    architecture_realization: &'a ArchitectureRealization,
    behavioral_semantics: &'a BehavioralSemanticsEvaluation,
    behavioral_realization: Option<&'a BehavioralRealizationEvaluation>,
    semantic_analysis: Option<&'a SemanticAnalysisEvaluation>,
    state_effect_analysis: Option<&'a StateEffectAnalysisEvaluation>,
    information_flow_analysis: Option<&'a InformationFlowEvaluation>,
    environmental_analysis: Option<&'a EnvironmentalAnalysisEvaluation>,
}

/// Program-analysis evidence grouped as one semantic layer for rule evaluation.
#[derive(Clone, Copy, Debug)]
pub struct ProgramEvaluationInputs<'a> {
    semantic: Option<&'a SemanticAnalysisEvaluation>,
    state_effect: Option<&'a StateEffectAnalysisEvaluation>,
    information_flow: Option<&'a InformationFlowEvaluation>,
    environmental: Option<&'a EnvironmentalAnalysisEvaluation>,
}

impl<'a> ProgramEvaluationInputs<'a> {
    /// Groups the progressively derived program-analysis models.
    #[must_use]
    pub const fn new(
        semantic_analysis: Option<&'a SemanticAnalysisEvaluation>,
        state_effect_analysis: Option<&'a StateEffectAnalysisEvaluation>,
        information_flow_analysis: Option<&'a InformationFlowEvaluation>,
        environmental_analysis: Option<&'a EnvironmentalAnalysisEvaluation>,
    ) -> Self {
        Self {
            semantic: semantic_analysis,
            state_effect: state_effect_analysis,
            information_flow: information_flow_analysis,
            environmental: environmental_analysis,
        }
    }
}

impl<'a> CompleteEvaluationInputs<'a> {
    /// Groups the current complete evaluator inputs without creating another authority.
    #[must_use]
    pub const fn new(
        rust_tests: &'a [RustTestFact],
        documentation: &'a DocumentationConformanceReport,
        contract_coherency: &'a ContractCoherencyEvaluation,
        architecture_realization: &'a ArchitectureRealization,
        behavioral_semantics: &'a BehavioralSemanticsEvaluation,
        behavioral_realization: Option<&'a BehavioralRealizationEvaluation>,
        program_analysis: ProgramEvaluationInputs<'a>,
    ) -> Self {
        Self {
            rust_tests,
            documentation,
            contract_coherency,
            architecture_realization,
            behavioral_semantics,
            behavioral_realization,
            semantic_analysis: program_analysis.semantic,
            state_effect_analysis: program_analysis.state_effect,
            information_flow_analysis: program_analysis.information_flow,
            environmental_analysis: program_analysis.environmental,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct EvaluationInputs<'a> {
    rust_tests: Option<&'a [RustTestFact]>,
    documentation: Option<&'a DocumentationConformanceReport>,
    contract_coherency: Option<&'a ContractCoherencyEvaluation>,
    architecture_realization: Option<&'a ArchitectureRealization>,
    behavioral_semantics: Option<&'a BehavioralSemanticsEvaluation>,
    behavioral_realization: Option<&'a BehavioralRealizationEvaluation>,
    semantic_analysis: Option<&'a SemanticAnalysisEvaluation>,
    state_effect_analysis: Option<&'a StateEffectAnalysisEvaluation>,
    information_flow_analysis: Option<&'a InformationFlowEvaluation>,
    environmental_analysis: Option<&'a EnvironmentalAnalysisEvaluation>,
}

impl<'a> From<CompleteEvaluationInputs<'a>> for EvaluationInputs<'a> {
    fn from(inputs: CompleteEvaluationInputs<'a>) -> Self {
        Self {
            rust_tests: Some(inputs.rust_tests),
            documentation: Some(inputs.documentation),
            contract_coherency: Some(inputs.contract_coherency),
            architecture_realization: Some(inputs.architecture_realization),
            behavioral_semantics: Some(inputs.behavioral_semantics),
            behavioral_realization: inputs.behavioral_realization,
            semantic_analysis: inputs.semantic_analysis,
            state_effect_analysis: inputs.state_effect_analysis,
            information_flow_analysis: inputs.information_flow_analysis,
            environmental_analysis: inputs.environmental_analysis,
        }
    }
}

impl SnapshotRuleEngine {
    /// Returns the built-in Snapshot Governance evaluator registry.
    #[must_use]
    pub const fn builtin() -> Self {
        Self
    }

    /// Evaluates every rule in the exact loaded standard bundle truthfully.
    ///
    /// Rules currently use their governed universal applicability. A rule with
    /// no registered Snapshot Governance evaluator is `UNSUPPORTED`, never
    /// `PASSED`. Execution records and findings are sorted deterministically.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError`] when the snapshot and standard editions
    /// disagree or a native evaluator cannot normalize its finding.
    pub fn evaluate(
        &self,
        standard: &StandardBundle,
        snapshot: &RepositorySnapshot,
        architecture: &ArchitectureManifest,
    ) -> Result<SnapshotEvaluation, EvaluationError> {
        Self::evaluate_internal(
            standard,
            snapshot,
            architecture,
            EvaluationInputs::default(),
        )
    }

    /// Evaluates the bundle with all currently supported snapshot-bound inputs.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError`] under the same conditions as [`Self::evaluate`].
    pub fn evaluate_complete(
        &self,
        standard: &StandardBundle,
        snapshot: &RepositorySnapshot,
        architecture: &ArchitectureManifest,
        inputs: CompleteEvaluationInputs<'_>,
    ) -> Result<SnapshotEvaluation, EvaluationError> {
        Self::evaluate_internal(standard, snapshot, architecture, inputs.into())
    }

    fn evaluate_internal(
        standard: &StandardBundle,
        snapshot: &RepositorySnapshot,
        architecture: &ArchitectureManifest,
        inputs: EvaluationInputs<'_>,
    ) -> Result<SnapshotEvaluation, EvaluationError> {
        validate_standard_edition(standard, snapshot)?;

        let mut rules = Vec::with_capacity(standard.rules().len());
        let mut findings = Vec::new();
        for rule in standard.rules() {
            let (execution, mut rule_findings) = evaluate_rule(
                rule.id(),
                standard.edition(),
                snapshot,
                architecture,
                inputs,
            )?;
            rules.push(execution);
            findings.append(&mut rule_findings);
        }
        rules.sort_unstable_by(|left, right| left.rule_id.cmp(&right.rule_id));
        findings.sort();

        Ok(SnapshotEvaluation {
            standard_edition: standard.edition().into(),
            snapshot_fingerprint: snapshot.snapshot_fingerprint().into(),
            rules,
            findings,
        })
    }
}

fn evaluate_rule(
    rule_id: &str,
    edition: &str,
    snapshot: &RepositorySnapshot,
    architecture: &ArchitectureManifest,
    inputs: EvaluationInputs<'_>,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    match rule_id {
        ARCH_DEPENDENCY_RULE_ID => dependency_execution(rule_id, architecture, edition),
        ARCH_REALIZATION_RULE_ID => Ok(inputs.architecture_realization.map_or_else(
            || unsupported_execution(rule_id, "Architecture realization requires one snapshot-bound observed implementation and one compiled CCG reconciliation."),
            |result| realization_execution(rule_id, result),
        )),
        BEHAVIOR_FLOW_RULE_ID => Ok(inputs.behavioral_semantics.map_or_else(
            || unsupported_execution(rule_id, "Behavioral-flow evaluation requires one Intended BFG compiled from the audit CCG."),
            |result| behavior_execution(rule_id, result),
        )),
        BEHAVIOR_REALIZATION_RULE_ID | BEHAVIOR_BYPASS_RULE_ID => {
            Ok(inputs.behavioral_realization.map_or_else(
                || unsupported_execution(rule_id, "Behavioral realization requires one Intended BFG, the canonical program/value/state/information/environment semantic stack, and validated distributed realization authority."),
                |result| behavioral_realization_execution(rule_id, result),
            ))
        }
        PROGRAM_DOMAIN_RULE_ID => Ok(inputs.semantic_analysis.map_or_else(
            || unsupported_execution(rule_id, "Program-domain evaluation requires one snapshot-bound PSM and its distributed Function Contract v3 set."),
            |result| semantic_execution(rule_id, result),
        )),
        PROGRAM_STATE_RULE_ID => Ok(inputs.state_effect_analysis.map_or_else(
            || unsupported_execution(rule_id, "Program-state evaluation requires one snapshot-bound PSM, Semantic Analysis result, State Contract set, and Function Contract v3 set."),
            |result| state_effect_execution(rule_id, result, true),
        )),
        PROGRAM_EFFECT_RULE_ID => Ok(inputs.state_effect_analysis.map_or_else(
            || unsupported_execution(rule_id, "Program-effect evaluation requires one snapshot-bound PSM and State/Effect Analysis result."),
            |result| state_effect_execution(rule_id, result, false),
        )),
        PROGRAM_INFOFLOW_RULE_ID => Ok(inputs.information_flow_analysis.map_or_else(
            || unsupported_execution(rule_id, "Program information-flow evaluation requires one snapshot-bound PSM, Semantic Analysis result, State/Effect result, policy, and Function Contract v3 set."),
            |result| information_flow_execution(rule_id, result),
        )),
        PROGRAM_ENVIRONMENT_RULE_ID | PROGRAM_RETRY_RULE_ID | PROGRAM_RECOVERY_RULE_ID => {
            Ok(inputs.environmental_analysis.map_or_else(
                || unsupported_execution(rule_id, "Environmental evaluation requires one snapshot-bound PSM and the canonical value, state/effect, information-flow, Function Contract, and Environment Contract models."),
                |result| environmental_execution(rule_id, result),
            ))
        }
        ARCH_OWNERSHIP_RULE_ID => ownership_execution(rule_id, architecture, snapshot, edition),
        REPO_MODULE_RULE_ID => placement_execution(rule_id, snapshot, edition),
        REPO_DOCS_RULE_ID => Ok(inputs.documentation.map_or_else(
            || unsupported_execution(rule_id, "Documentation evaluation requires snapshot-bound repository bytes and canonical Module contracts."),
            |report| documentation_execution(rule_id, report),
        )),
        CONTRACT_COHERENCY_RULE_ID => Ok(inputs.contract_coherency.map_or_else(
            || unsupported_execution(rule_id, "Contract coherency requires canonical Module Contract v2 repository bytes, observed test evidence, and parsed README relationship projections."),
            |result| contract_execution(rule_id, result),
        )),
        TEST_TRACEABILITY_RULE_ID => traceability_from_inputs(rule_id, edition, inputs),
        TEST_BOUNDARY_RULE_ID => testing_boundary_from_inputs(rule_id, edition, inputs),
        _ => Ok(unsupported_execution(
            rule_id,
            "No Snapshot Governance evaluator is registered for this rule.",
        )),
    }
}

fn traceability_from_inputs(
    rule_id: &str,
    edition: &str,
    inputs: EvaluationInputs<'_>,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let (Some(rust_tests), Some(contract_coherency)) =
        (inputs.rust_tests, inputs.contract_coherency)
    else {
        return Ok(unsupported_execution(
            rule_id,
            "Traceability evaluation requires a compiled CCG and snapshot-bound Rust test facts.",
        ));
    };
    contract_coherency.graph().map_or_else(
        || {
            Ok(unsupported_execution(
                rule_id,
                "Traceability evaluation requires a compiled CCG verification topology.",
            ))
        },
        |ccg| traceability_execution(rule_id, ccg, rust_tests, edition),
    )
}

fn testing_boundary_from_inputs(
    rule_id: &str,
    edition: &str,
    inputs: EvaluationInputs<'_>,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let (Some(rust_tests), Some(contract_coherency)) =
        (inputs.rust_tests, inputs.contract_coherency)
    else {
        return Ok(unsupported_execution(
            rule_id,
            "Testing-boundary evaluation requires resolved Module contracts and snapshot-bound Rust test facts.",
        ));
    };
    contract_coherency.graph().map_or_else(
        || {
            Ok(unsupported_execution(
                rule_id,
                "Testing-boundary evaluation requires a successfully resolved Module Contract v2 ecosystem.",
            ))
        },
        |ccg| testing_boundary_execution(rule_id, ccg, rust_tests, edition),
    )
}

fn behavior_execution(
    rule_id: &str,
    result: &BehavioralSemanticsEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = result.findings().to_vec();
    let summary = result.graph().summary();
    let applicable = summary.modeled_features() > 0;
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable,
            findings: findings.len(),
            detail: format!(
                "Intended BFG v1 compiled {} modeled Feature(s): {} coherent, {} incoherent, with {} unmodeled Feature(s) preserved as {} and {} finding(s).",
                summary.modeled_features(),
                summary.coherent_features(),
                summary.incoherent_features(),
                summary.unmodeled_features(),
                "UNMODELED",
                findings.len(),
            ),
        },
        findings,
    )
}

fn behavioral_realization_execution(
    rule_id: &str,
    result: &BehavioralRealizationEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = if rule_id == BEHAVIOR_BYPASS_RULE_ID {
        result.bypass_findings().to_vec()
    } else {
        result.realization_findings().to_vec()
    };
    let summary = result.graph().summary();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: summary.opted_in_features() > 0,
            findings: findings.len(),
            detail: format!(
                "Realized BFG v1 reconciled {} opted-in Feature(s), with {} realization contradiction(s), {} proven dominator bypass(es), and {} finding(s) for this rule; incomplete semantic coverage remains explicit.",
                summary.opted_in_features(),
                summary.realization_violations(),
                summary.proven_bypasses(),
                findings.len(),
            ),
        },
        findings,
    )
}

fn semantic_execution(
    rule_id: &str,
    result: &SemanticAnalysisEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = result.findings().to_vec();
    let coverage = result.model().coverage();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: format!(
                "Semantic Analysis v1 evaluated {} function summary(ies), {} distributed Function Contract(s), and produced {} supported program-domain contradiction(s); unsupported semantics remain explicit.",
                coverage.functions_analyzed(),
                coverage.function_contracts(),
                coverage.violations(),
            ),
        },
        findings,
    )
}

fn state_effect_execution(
    rule_id: &str,
    result: &StateEffectAnalysisEvaluation,
    state_rule: bool,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = if state_rule {
        result.state_findings().to_vec()
    } else {
        result.effect_findings().to_vec()
    };
    let coverage = result.model().coverage();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: format!(
                "State and Effect Analysis v1 evaluated {} function summary(ies) and produced {} supported contradiction(s) for this rule; unknown and unclassified semantics remain explicit.",
                coverage.functions(),
                findings.len(),
            ),
        },
        findings,
    )
}

fn information_flow_execution(
    rule_id: &str,
    result: &InformationFlowEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = result.findings().to_vec();
    let coverage = result.model().coverage();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: format!(
                "Information Flow Analysis v1 evaluated project-defined ordered facets and produced {} supported information-flow contradiction(s); unknown and unsupported flow remains explicit.",
                coverage.violations(),
            ),
        },
        findings,
    )
}

fn environmental_execution(
    rule_id: &str,
    result: &EnvironmentalAnalysisEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = match rule_id {
        PROGRAM_ENVIRONMENT_RULE_ID => result.environment_findings().to_vec(),
        PROGRAM_RETRY_RULE_ID => result.retry_findings().to_vec(),
        PROGRAM_RECOVERY_RULE_ID => result.recovery_findings().to_vec(),
        _ => Vec::new(),
    };
    let coverage = result.model().coverage();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: coverage.operations() > 0,
            findings: findings.len(),
            detail: format!(
                "Environmental Analysis v1 evaluated {} modeled external operation(s) and produced {} supported contradiction(s) for this rule; unknown and unsupported environment behavior remains explicit.",
                coverage.operations(),
                findings.len(),
            ),
        },
        findings,
    )
}

fn validate_standard_edition(
    standard: &StandardBundle,
    snapshot: &RepositorySnapshot,
) -> Result<(), EvaluationError> {
    if standard.edition() == snapshot.standard_edition() {
        return Ok(());
    }
    Err(EvaluationError::StandardEditionMismatch {
        bundle: standard.edition().into(),
        snapshot: snapshot.standard_edition().into(),
    })
}

fn realization_execution(
    rule_id: &str,
    result: &ArchitectureRealization,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = result.findings().to_vec();
    let summary = result.summary();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: format!(
                "Rust realization reconciliation produced {} declared-and-observed, {} observed-undeclared, {} transitive-bypass, {} declared-unobserved, {} external, {} unresolved, {} unsupported, and {} invalid conclusion(s); capability realization remains unsupported.",
                summary.declared_and_observed(),
                summary.observed_undeclared(),
                summary.observed_transitive_bypass(),
                summary.declared_unobserved(),
                summary.external(),
                summary.unresolved(),
                summary.unsupported(),
                summary.invalid(),
            ),
        },
        findings,
    )
}

fn testing_boundary_execution(
    rule_id: &str,
    contracts: &crate::contract_coherency::ContractCoherencyGraph,
    rust_tests: &[RustTestFact],
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let result = evaluate_testing_boundaries(contracts, rust_tests, standard_edition)
        .map_err(EvaluationError::Finding)?;
    let findings = result.findings().to_vec();
    Ok((
        completed_execution(
            rule_id,
            findings.len(),
            "recursive testing-boundary violation(s)",
        ),
        findings,
    ))
}

fn dependency_execution(
    rule_id: &str,
    architecture: &ArchitectureManifest,
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let finding = architecture
        .evaluate_acyclic_dependencies(standard_edition)
        .map_err(EvaluationError::Finding)?;
    let findings: Vec<CanonicalFinding> = finding.into_iter().collect();
    Ok((
        completed_execution(
            rule_id,
            findings.len(),
            "declared dependency-cycle violation(s)",
        ),
        findings,
    ))
}

fn ownership_execution(
    rule_id: &str,
    architecture: &ArchitectureManifest,
    snapshot: &RepositorySnapshot,
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let paths: Vec<String> = snapshot
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let result = evaluate_file_ownership(architecture, &paths, standard_edition)
        .map_err(EvaluationError::Finding)?;
    Ok((
        completed_execution(
            rule_id,
            result.findings().len(),
            "declared file ownership violation(s)",
        ),
        result.findings().to_vec(),
    ))
}

fn traceability_execution(
    rule_id: &str,
    ccg: &crate::contract_coherency::ContractCoherencyGraph,
    rust_tests: &[RustTestFact],
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let result = evaluate_ccg_test_traceability(ccg, rust_tests, standard_edition)
        .map_err(EvaluationError::Finding)?;
    Ok((
        completed_execution(
            rule_id,
            result.findings().len(),
            "requirement/test traceability violation(s)",
        ),
        result.findings().to_vec(),
    ))
}

fn contract_execution(
    rule_id: &str,
    result: &ContractCoherencyEvaluation,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = result.findings().to_vec();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() && result.is_coherent() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: format!(
                "CCG compilation ran with test-reference support {}, graph coherent {}, and produced {} CONTRACT-COHERENCY-001 finding(s); unsupported semantic classes: {}.",
                result.test_reference_resolution_supported(),
                result.is_coherent(),
                findings.len(),
                result.unsupported_semantics().join(", ")
            ),
        },
        findings,
    )
}

fn placement_execution(
    rule_id: &str,
    snapshot: &RepositorySnapshot,
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let paths: Vec<String> = snapshot
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let findings =
        evaluate_module_grammar(&paths, standard_edition).map_err(EvaluationError::Finding)?;
    Ok((
        completed_execution(
            rule_id,
            findings.len(),
            "recursive repository grammar violation(s)",
        ),
        findings,
    ))
}

fn documentation_execution(
    rule_id: &str,
    report: &DocumentationConformanceReport,
) -> (RuleExecution, Vec<CanonicalFinding>) {
    let findings = report.findings().to_vec();
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: if findings.is_empty() {
                RuleExecutionState::Passed
            } else {
                RuleExecutionState::Failed
            },
            applicable: true,
            findings: findings.len(),
            detail: report.execution_detail(),
        },
        findings,
    )
}

fn completed_execution(rule_id: &str, findings: usize, subject: &str) -> RuleExecution {
    RuleExecution {
        rule_id: rule_id.into(),
        state: if findings == 0 {
            RuleExecutionState::Passed
        } else {
            RuleExecutionState::Failed
        },
        applicable: true,
        findings,
        detail: format!("Evaluator ran and produced {findings} {subject}."),
    }
}

fn unsupported_execution(rule_id: &str, detail: &str) -> (RuleExecution, Vec<CanonicalFinding>) {
    (
        RuleExecution {
            rule_id: rule_id.into(),
            state: RuleExecutionState::Unsupported,
            applicable: true,
            findings: 0,
            detail: detail.into(),
        },
        Vec::new(),
    )
}

/// Explains why a snapshot rule evaluation could not complete.
#[derive(Debug)]
pub enum EvaluationError {
    /// The loaded bundle and snapshot identify different standard editions.
    StandardEditionMismatch {
        /// Loaded bundle edition.
        bundle: String,
        /// Snapshot-declared edition.
        snapshot: String,
    },
    /// A native evaluator could not construct canonical finding evidence.
    Finding(FindingError),
}

impl Display for EvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardEditionMismatch { bundle, snapshot } => write!(
                formatter,
                "standard edition mismatch: bundle `{bundle}`, snapshot `{snapshot}`"
            ),
            Self::Finding(error) => write!(formatter, "rule finding normalization failed: {error}"),
        }
    }
}

impl Error for EvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::StandardEditionMismatch { .. } => None,
        }
    }
}
