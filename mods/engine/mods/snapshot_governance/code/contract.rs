//! Snapshot rule evidence for Module Contract v2 ecosystem coherency.
//!
//! The evaluator reports every implemented local and repository-wide contract
//! gate. It deliberately does not claim general rule satisfiability,
//! capability-effect closure, or completion of the future Contract Coherency
//! Graph.

use crate::documentation::DocumentationConformanceReport;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::module_contract::{ContractResolution, ResolvedContractSet};

/// Stable identity of implemented Module Contract v2 coherency.
pub const CONTRACT_COHERENCY_RULE_ID: &str = "CONTRACT-COHERENCY-001";

const REMEDIATION: &str = "Canonicalize every Module Contract v2 document, resolve identities, capabilities, relationships, inherited constraints, guarantees, Features, requirements, tests, and behavioral checkpoints, then synchronize README outbound relationships to the resolved contract projection.";

/// Deterministic implemented coherency result with its resolved model on success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCoherencyEvaluation {
    resolution: ContractResolution,
    findings: Vec<CanonicalFinding>,
}

impl ContractCoherencyEvaluation {
    /// Returns the resolved ecosystem only when all contract checks passed.
    #[must_use]
    pub fn resolved(&self) -> Option<&ResolvedContractSet> {
        self.resolution.resolved()
    }

    /// Returns deterministic normalized findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns whether observed test evidence resolution was implemented for this run.
    #[must_use]
    pub const fn test_reference_resolution_supported(&self) -> bool {
        self.resolution.test_reference_resolution_supported()
    }
}

/// Normalizes contract resolution and README synchronization into rule evidence.
///
/// # Errors
///
/// Returns [`FindingError`] only if canonical finding construction fails.
pub fn evaluate_contract_coherency(
    resolution: ContractResolution,
    documentation: &DocumentationConformanceReport,
    standard_edition: &str,
) -> Result<ContractCoherencyEvaluation, FindingError> {
    let definition = RuleFindingDefinition::new(
        CONTRACT_COHERENCY_RULE_ID,
        1,
        FindingCategory::Architecture,
        REMEDIATION,
    )?;
    let evaluator = EvaluatorProvenance::new("fortress-core/contract", env!("CARGO_PKG_VERSION"))?;
    let mut findings = Vec::new();
    for violation in resolution.violations() {
        findings.push(CanonicalFinding::failure(
            definition.clone(),
            FindingOccurrence::new(
                Vec::new(),
                FindingLocation::at_path(violation.path())?,
                format!("{}: {}", violation.pointer(), violation.message()),
            )?,
            evaluator.clone(),
            standard_edition,
            None,
        )?);
    }
    if !resolution.test_reference_resolution_supported() {
        findings.push(CanonicalFinding::failure(
            definition.clone(),
            FindingOccurrence::new(
                Vec::new(),
                FindingLocation::none(),
                "Observed test evidence was not supplied; contract test-reference resolution is unsupported for this evaluation.",
            )?,
            evaluator.clone(),
            standard_edition,
            None,
        )?);
    }
    if documentation.summary().relationship_violations() > 0 {
        findings.push(CanonicalFinding::failure(
            definition,
            FindingOccurrence::new(
                Vec::new(),
                FindingLocation::at_path("README.md")?,
                format!(
                    "Canonical README relationship projections contain {} contract synchronization violation(s).",
                    documentation.summary().relationship_violations()
                ),
            )?,
            evaluator,
            standard_edition,
            None,
        )?);
    }
    findings.sort();
    Ok(ContractCoherencyEvaluation {
        resolution,
        findings,
    })
}
