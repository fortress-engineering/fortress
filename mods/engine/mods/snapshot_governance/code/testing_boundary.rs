//! Snapshot-rule projection of CCG parent-local verification topology.

pub(crate) const TEST_BOUNDARY_RULE_SOURCE: &str = include_str!("../data/test_boundary_rule.json");

use crate::contract_coherency::ContractCoherencyGraph;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::rust_test_analyzer::RustTestFact;

/// Stable identity of recursive parent-local Feature verification boundaries.
pub const TEST_BOUNDARY_RULE_ID: &str = "TEST-BOUNDARY-001";

const REMEDIATION: &str = "Give every Feature-owning Module exactly one direct mods/testing child, make that Testing contract verify exactly its immediate parent's local Features, keep canonical Testing Modules featureless, and place every Rust test directly beneath a canonical Testing Module's code directory.";

/// Deterministic recursive testing-boundary result projected from the CCG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestingBoundaryEvaluation {
    feature_owning_modules: usize,
    testing_modules: usize,
    observed_tests: usize,
    findings: Vec<CanonicalFinding>,
}

impl TestingBoundaryEvaluation {
    /// Returns the number of Modules that directly own one or more Features.
    #[must_use]
    pub const fn feature_owning_module_count(&self) -> usize {
        self.feature_owning_modules
    }

    /// Returns the number of canonical direct Testing Modules.
    #[must_use]
    pub const fn testing_module_count(&self) -> usize {
        self.testing_modules
    }

    /// Returns the number of observed Rust tests inspected for placement.
    #[must_use]
    pub const fn observed_test_count(&self) -> usize {
        self.observed_tests
    }

    /// Returns normalized findings in deterministic global order.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Projects CCG verification-boundary contradictions into `TEST-BOUNDARY-001`.
///
/// CCG compilation owns topology derivation. This evaluator does not rediscover
/// containment, relationships, Feature subjects, or test ownership.
///
/// # Errors
///
/// Returns [`FindingError`] only if canonical finding construction fails.
pub fn evaluate_testing_boundaries(
    ccg: &ContractCoherencyGraph,
    rust_tests: &[RustTestFact],
    standard_edition: &str,
) -> Result<TestingBoundaryEvaluation, FindingError> {
    let definition = RuleFindingDefinition::new(
        TEST_BOUNDARY_RULE_ID,
        1,
        FindingCategory::Testing,
        REMEDIATION,
    )?;
    let evaluator =
        EvaluatorProvenance::new("fortress-core/testing-boundary", env!("CARGO_PKG_VERSION"))?;
    let mut findings = Vec::new();
    for violation in ccg.coherency_findings().iter().filter(|violation| {
        violation.code().starts_with("CCG-TESTING-") || violation.code() == "CCG-TEST-BOUNDARY"
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
    Ok(TestingBoundaryEvaluation {
        feature_owning_modules: ccg
            .modules()
            .values()
            .filter(|module| !module.contract().features().is_empty())
            .count(),
        testing_modules: ccg
            .modules()
            .values()
            .filter(|module| {
                module.path() == "mods/testing" || module.path().ends_with("/mods/testing")
            })
            .count(),
        observed_tests: rust_tests.len(),
        findings,
    })
}
