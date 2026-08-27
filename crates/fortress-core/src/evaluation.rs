//! Truthful evaluation of implemented Snapshot Governance rules.
//!
//! The engine walks the exact loaded standard bundle, invokes only registered
//! native evaluators, normalizes violations, and reports unsupported rules
//! explicitly. Absence of an evaluator never becomes a pass.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use crate::architecture::{ARCH_DEPENDENCY_RULE_ID, ArchitectureManifest};
use crate::finding::{CanonicalFinding, FindingError};
use crate::snapshot::RepositorySnapshot;
use crate::standard::StandardBundle;

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
        if standard.edition() != snapshot.standard_edition() {
            return Err(EvaluationError::StandardEditionMismatch {
                bundle: standard.edition().into(),
                snapshot: snapshot.standard_edition().into(),
            });
        }

        let mut rules = Vec::with_capacity(standard.rules().len());
        let mut findings = Vec::new();
        for rule in standard.rules() {
            if rule.id() == ARCH_DEPENDENCY_RULE_ID {
                let finding = architecture
                    .evaluate_acyclic_dependencies(standard.edition())
                    .map_err(EvaluationError::Finding)?;
                if let Some(finding) = finding {
                    findings.push(finding);
                    rules.push(RuleExecution {
                        rule_id: rule.id().into(),
                        state: RuleExecutionState::Failed,
                        applicable: true,
                        findings: 1,
                        detail:
                            "Evaluator ran and produced one declared dependency-cycle violation."
                                .into(),
                    });
                } else {
                    rules.push(RuleExecution {
                        rule_id: rule.id().into(),
                        state: RuleExecutionState::Passed,
                        applicable: true,
                        findings: 0,
                        detail:
                            "Evaluator ran and produced no declared dependency-cycle violation."
                                .into(),
                    });
                }
            } else {
                rules.push(RuleExecution {
                    rule_id: rule.id().into(),
                    state: RuleExecutionState::Unsupported,
                    applicable: true,
                    findings: 0,
                    detail: "No Snapshot Governance evaluator is registered for this rule.".into(),
                });
            }
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
