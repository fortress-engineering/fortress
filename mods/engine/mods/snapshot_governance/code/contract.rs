//! Snapshot rule evidence for Module Contract v2 ecosystem coherency.
//!
//! The evaluator projects CCG compilation and supported semantic coherency into
//! the governing snapshot rule. Unsupported proof classes remain explicit.

pub(crate) const CONTRACT_RULE_SOURCE: &str = include_str!("../data/contract_rule.json");

use crate::contract_coherency::{CcgCoherencyStatus, CcgCompilation, ContractCoherencyGraph};
use crate::documentation::DocumentationConformanceReport;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of implemented Module Contract v2 coherency.
pub const CONTRACT_COHERENCY_RULE_ID: &str = "CONTRACT-COHERENCY-001";

const REMEDIATION: &str = "Restore canonical Contract v2 sources, correct the CCG provenance or supported logical contradiction, and synchronize README outbound relationships to the contract-derived projection.";

/// Deterministic snapshot-rule projection of CCG compilation and coherency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCoherencyEvaluation {
    resolution: CcgCompilation,
    findings: Vec<CanonicalFinding>,
}

impl ContractCoherencyEvaluation {
    /// Returns the canonical compiled CCG when structural compilation succeeded.
    #[must_use]
    pub fn graph(&self) -> Option<&ContractCoherencyGraph> {
        self.resolution.graph()
    }

    /// Returns deterministic normalized findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns whether the compiled graph is coherent within supported semantics.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        self.graph()
            .is_some_and(|graph| graph.coherency_status() == CcgCoherencyStatus::Coherent)
    }

    /// Returns semantic classes CCG v1 explicitly does not prove.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[&str] {
        self.graph()
            .map_or(&[], ContractCoherencyGraph::unsupported_semantics)
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
    resolution: CcgCompilation,
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
    for violation in resolution.violations().iter().filter(|violation| {
        !violation.code().starts_with("CCG-TESTING-")
            && !violation.code().starts_with("CCG-TEST-")
            && !violation.code().starts_with("CCG-TRACE-")
    }) {
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
