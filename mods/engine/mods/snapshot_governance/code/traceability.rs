//! Requirement-to-test reconciliation projected from the canonical CCG.

pub(crate) const TRACEABILITY_RULE_SOURCE: &str = include_str!("../data/traceability_rule.json");

use std::collections::BTreeSet;

use crate::contract_coherency::ContractCoherencyGraph;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::rust_test_analyzer::{RustTestClassification, RustTestFact, RustTestObservation};

/// Stable identity of mandatory requirement/test traceability.
pub const TEST_TRACEABILITY_RULE_ID: &str = "TEST-TRACEABILITY-001";

const REMEDIATION: &str = "Give each active mandatory requirement unique canonical test evidence, place that evidence in the owning Module's direct Testing child, add one exact source requirement marker to every behavioral or conformance test, and classify truly unmapped implementation-only tests as infrastructure.";

/// Deterministic traceability coverage and findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceabilityEvaluation {
    active_requirements: usize,
    referenced_tests: usize,
    observed_behavior_tests: usize,
    findings: Vec<CanonicalFinding>,
}

impl TraceabilityEvaluation {
    /// Returns the number of active mandatory requirement declarations.
    #[must_use]
    pub const fn active_requirement_count(&self) -> usize {
        self.active_requirements
    }

    /// Returns the number of distinct canonical tests referenced by requirements.
    #[must_use]
    pub const fn referenced_test_count(&self) -> usize {
        self.referenced_tests
    }

    /// Returns the number of observed behavioral or conformance tests.
    #[must_use]
    pub const fn observed_behavior_test_count(&self) -> usize {
        self.observed_behavior_tests
    }

    /// Returns canonical findings in global deterministic order.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Projects CCG requirement/test identity contradictions into `TEST-TRACEABILITY-001`.
///
/// CCG compilation is the sole authority for requirement/test identity,
/// verification ownership, and parent-local Testing topology. This evaluator
/// only maps the CCG's normalized contradictions into the rule's canonical
/// finding vocabulary.
///
/// # Errors
///
/// Returns [`FindingError`] only if canonical finding construction fails.
pub fn evaluate_ccg_test_traceability(
    ccg: &ContractCoherencyGraph,
    tests: &[RustTestFact],
    standard_edition: &str,
) -> Result<TraceabilityEvaluation, FindingError> {
    let definition = RuleFindingDefinition::new(
        TEST_TRACEABILITY_RULE_ID,
        1,
        FindingCategory::Testing,
        REMEDIATION,
    )?;
    let evaluator =
        EvaluatorProvenance::new("fortress-core/traceability", env!("CARGO_PKG_VERSION"))?;
    let mut findings = Vec::new();
    for violation in ccg.coherency_findings().iter().filter(|violation| {
        violation.code().starts_with("CCG-TRACE-")
            || matches!(
                violation.code(),
                "CCG-TEST-DUPLICATE"
                    | "CCG-TEST-REQUIREMENT-MISSING"
                    | "CCG-TEST-REQUIREMENT-UNKNOWN"
            )
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
        )?);
    }
    findings.sort();
    Ok(TraceabilityEvaluation {
        active_requirements: ccg.requirements().len(),
        referenced_tests: ccg
            .requirements()
            .values()
            .flat_map(crate::contract_coherency::ResolvedRequirement::tests)
            .collect::<BTreeSet<_>>()
            .len(),
        observed_behavior_tests: tests
            .iter()
            .filter(|test| test.classification() != RustTestClassification::Infrastructure)
            .count(),
        findings,
    })
}

/// Produces traceability findings for observed Rust tests lacking stable governance identity.
///
/// # Errors
///
/// Returns an error only if canonical finding construction fails.
pub fn missing_test_identity_findings(
    observations: &[RustTestObservation],
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let definition = RuleFindingDefinition::new(
        TEST_TRACEABILITY_RULE_ID,
        1,
        FindingCategory::Testing,
        REMEDIATION,
    )?;
    let evaluator =
        EvaluatorProvenance::new("fortress-core/traceability", env!("CARGO_PKG_VERSION"))?;
    let mut findings = observations
        .iter()
        .filter(|test| !test.is_governed())
        .map(|test| {
            let location = FindingLocation::at_path(test.path())?.with_symbol(test.symbol())?;
            let occurrence = FindingOccurrence::new(
                Vec::new(),
                location,
                format!(
                    "observed Rust test `{}` has no valid stable Fortress test identity",
                    test.symbol()
                ),
            )?
            .with_discriminator(format!(
                "MISSING_TEST_ID:{}#{}",
                test.path(),
                test.symbol()
            ))?;
            CanonicalFinding::failure(
                definition.clone(),
                occurrence,
                evaluator.clone(),
                standard_edition,
            )
        })
        .collect::<Result<Vec<_>, FindingError>>()?;
    findings.sort();
    Ok(findings)
}
