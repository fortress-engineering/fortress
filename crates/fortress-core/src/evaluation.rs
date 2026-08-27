//! Truthful evaluation of implemented Snapshot Governance rules.
//!
//! The engine walks the exact loaded standard bundle, invokes only registered
//! native evaluators, normalizes violations, and reports unsupported rules
//! explicitly. Absence of an evaluator never becomes a pass.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use crate::architecture::{ARCH_DEPENDENCY_RULE_ID, ArchitectureManifest};
use crate::feature::FeatureContract;
use crate::finding::{CanonicalFinding, FindingError};
use crate::ownership::{ARCH_OWNERSHIP_RULE_ID, evaluate_file_ownership};
use crate::rust_test_analyzer::RustTestFact;
use crate::snapshot::RepositorySnapshot;
use crate::standard::StandardBundle;
use crate::traceability::{TEST_TRACEABILITY_RULE_ID, evaluate_test_traceability};

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
                matches!(
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
            .filter(|execution| execution.state == RuleExecutionState::Passed)
            .count()
    }

    /// Returns the number of evaluated rules with violations.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|execution| execution.state == RuleExecutionState::Failed)
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
        Self::evaluate_internal(standard, snapshot, architecture, None)
    }

    /// Evaluates the bundle with complete declared feature and Rust test facts.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError`] under the same conditions as [`Self::evaluate`].
    pub fn evaluate_with_traceability(
        &self,
        standard: &StandardBundle,
        snapshot: &RepositorySnapshot,
        architecture: &ArchitectureManifest,
        feature_contracts: &[FeatureContract],
        rust_tests: &[RustTestFact],
    ) -> Result<SnapshotEvaluation, EvaluationError> {
        Self::evaluate_internal(
            standard,
            snapshot,
            architecture,
            Some((feature_contracts, rust_tests)),
        )
    }

    fn evaluate_internal(
        standard: &StandardBundle,
        snapshot: &RepositorySnapshot,
        architecture: &ArchitectureManifest,
        traceability_inputs: Option<(&[FeatureContract], &[RustTestFact])>,
    ) -> Result<SnapshotEvaluation, EvaluationError> {
        if standard.edition() != snapshot.standard_edition() {
            return Err(EvaluationError::StandardEditionMismatch {
                bundle: standard.edition().into(),
                snapshot: snapshot.standard_edition().into(),
            });
        }

        let mut rules = Vec::with_capacity(standard.rules().len());
        let mut findings = Vec::new();
        for rule in standard.rules() {
            let (execution, mut rule_findings) = if rule.id() == ARCH_DEPENDENCY_RULE_ID {
                dependency_execution(rule.id(), architecture, standard.edition())?
            } else if rule.id() == ARCH_OWNERSHIP_RULE_ID {
                ownership_execution(rule.id(), architecture, snapshot, standard.edition())?
            } else if rule.id() == TEST_TRACEABILITY_RULE_ID {
                if let Some((contracts, rust_tests)) = traceability_inputs {
                    traceability_execution(rule.id(), contracts, rust_tests, standard.edition())?
                } else {
                    unsupported_execution(
                        rule.id(),
                        "Traceability evaluation requires declared feature contracts and snapshot-bound Rust test facts.",
                    )
                }
            } else {
                unsupported_execution(
                    rule.id(),
                    "No Snapshot Governance evaluator is registered for this rule.",
                )
            };
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
    contracts: &[FeatureContract],
    rust_tests: &[RustTestFact],
    standard_edition: &str,
) -> Result<(RuleExecution, Vec<CanonicalFinding>), EvaluationError> {
    let result = evaluate_test_traceability(contracts, rust_tests, standard_edition)
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
