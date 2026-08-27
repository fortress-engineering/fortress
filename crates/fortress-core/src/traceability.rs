//! Requirement-to-test reconciliation for stabilized Snapshot Governance.

use std::collections::{BTreeMap, BTreeSet};

use crate::feature::{FeatureContract, FeatureStatus, RequirementDeclaration};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::identity::StableId;
use crate::rust_test_analyzer::{RustTestClassification, RustTestFact};

/// Stable identity of mandatory requirement/test traceability.
pub const TEST_TRACEABILITY_RULE_ID: &str = "TEST-TRACEABILITY-001";

const REMEDIATION: &str = "Give each active mandatory requirement unique canonical test evidence, ensure every referenced test exists exactly once in the supported evidence inventory, and map every behavioral or conformance test to one valid active requirement; classify implementation-only tests explicitly.";

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

struct RequirementRef<'a> {
    contract_path: &'a str,
    feature_id: &'a str,
    requirement: &'a RequirementDeclaration,
}

/// Evaluates active requirement and Rust test evidence traceability.
///
/// Planned, deprecated, and retired feature requirements are preserved but are
/// not mandatory in this snapshot rule. Behavioral and conformance test facts
/// require exactly one active requirement relation. Explicitly classified
/// infrastructure tests may remain unmapped.
///
/// # Errors
///
/// Returns [`FindingError`] only if deterministic finding construction fails.
pub fn evaluate_test_traceability(
    contracts: &[FeatureContract],
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
    let requirements = active_requirements(contracts);
    let mut findings = Vec::new();
    let (requirement_ids, references) = evaluate_requirements(
        &requirements,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    evaluate_observed_tests(
        tests,
        &requirement_ids,
        &references,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    evaluate_stale_references(
        tests,
        &references,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    findings.sort();

    Ok(TraceabilityEvaluation {
        active_requirements: requirements.len(),
        referenced_tests: references.len(),
        observed_behavior_tests: tests
            .iter()
            .filter(|test| test.classification() != RustTestClassification::Infrastructure)
            .count(),
        findings,
    })
}

fn active_requirements(contracts: &[FeatureContract]) -> Vec<RequirementRef<'_>> {
    contracts
        .iter()
        .flat_map(|contract| {
            contract
                .features()
                .iter()
                .filter(|feature| feature.status() == FeatureStatus::Active)
                .flat_map(|feature| {
                    feature
                        .requirements()
                        .iter()
                        .map(|requirement| RequirementRef {
                            contract_path: contract.source_path(),
                            feature_id: feature.id(),
                            requirement,
                        })
                })
        })
        .collect()
}

type RequirementIds<'a> = BTreeMap<&'a str, Vec<&'a RequirementRef<'a>>>;
type TestReferences<'a> = BTreeMap<&'a str, Vec<&'a RequirementRef<'a>>>;

#[allow(clippy::too_many_arguments)]
fn evaluate_requirements<'a>(
    requirements: &'a [RequirementRef<'a>],
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(RequirementIds<'a>, TestReferences<'a>), FindingError> {
    let mut requirement_ids: RequirementIds<'a> = BTreeMap::new();
    let mut references: TestReferences<'a> = BTreeMap::new();
    for reference in requirements {
        let requirement = reference.requirement;
        if canonical_entity(requirement.id()) {
            requirement_ids
                .entry(requirement.id())
                .or_default()
                .push(reference);
        } else {
            findings.push(contract_finding(
                definition,
                evaluator,
                reference,
                valid_entities([reference.feature_id]),
                format!(
                    "Active requirement ID `{}` is not canonical.",
                    requirement.id()
                ),
                standard_edition,
            )?);
        }
        if requirement.statement().is_empty() || requirement.tests().is_empty() {
            findings.push(contract_finding(
                definition,
                evaluator,
                reference,
                valid_entities([requirement.id()]),
                format!(
                    "Active mandatory requirement `{}` declares no required test evidence.",
                    requirement.id()
                ),
                standard_edition,
            )?);
        }
        let mut local = BTreeSet::new();
        for test_id in requirement.tests() {
            if canonical_test_id(test_id) {
                references.entry(test_id).or_default().push(reference);
                if !local.insert(test_id) {
                    findings.push(contract_finding(
                        definition,
                        evaluator,
                        reference,
                        valid_entities([requirement.id(), test_id]),
                        format!(
                            "Requirement `{}` repeats test evidence `{test_id}`.",
                            requirement.id()
                        ),
                        standard_edition,
                    )?);
                }
            } else {
                findings.push(contract_finding(
                    definition,
                    evaluator,
                    reference,
                    valid_entities([requirement.id()]),
                    format!(
                        "Requirement `{}` references non-canonical test ID `{test_id}`.",
                        requirement.id()
                    ),
                    standard_edition,
                )?);
            }
        }
    }
    for (id, declarations) in &requirement_ids {
        if declarations.len() > 1 {
            findings.push(contract_finding(
                definition,
                evaluator,
                declarations[0],
                valid_entities([*id]),
                format!("Active requirement ID `{id}` is declared more than once."),
                standard_edition,
            )?);
        }
    }
    for (id, mappings) in &references {
        if mappings.len() > 1 {
            let requirements: Vec<&str> = mappings
                .iter()
                .map(|mapping| mapping.requirement.id())
                .collect();
            findings.push(contract_finding(
                definition,
                evaluator,
                mappings[0],
                valid_entities(std::iter::once(*id).chain(requirements.iter().copied())),
                format!(
                    "Test evidence `{id}` is mapped more than once: {}.",
                    requirements.join(", ")
                ),
                standard_edition,
            )?);
        }
    }
    Ok((requirement_ids, references))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_observed_tests(
    tests: &[RustTestFact],
    requirement_ids: &RequirementIds<'_>,
    references: &TestReferences<'_>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    let mut observed: BTreeMap<&str, Vec<&RustTestFact>> = BTreeMap::new();
    for test in tests {
        observed.entry(test.id()).or_default().push(test);
        if test.classification() != RustTestClassification::Infrastructure
            && !references.contains_key(test.id())
        {
            findings.push(test_finding(
                definition,
                evaluator,
                test,
                valid_entities([test.id()]),
                format!(
                    "Observed {} Rust test `{}` is not mapped to an active requirement.",
                    test.classification().as_str(),
                    test.id()
                ),
                standard_edition,
            )?);
        }
        if let Some(declared) = test.declared_requirement() {
            if !requirement_ids.contains_key(declared) {
                findings.push(test_finding(
                    definition,
                    evaluator,
                    test,
                    valid_entities([test.id(), declared]),
                    format!(
                        "Rust test `{}` declares nonexistent active requirement `{declared}`.",
                        test.id()
                    ),
                    standard_edition,
                )?);
            } else if !references.get(test.id()).is_some_and(|mappings| {
                mappings
                    .iter()
                    .any(|mapping| mapping.requirement.id() == declared)
            }) {
                findings.push(test_finding(
                    definition,
                    evaluator,
                    test,
                    valid_entities([test.id(), declared]),
                    format!(
                        "Rust test `{}` declares requirement `{declared}` but that requirement does not reference the test.",
                        test.id()
                    ),
                    standard_edition,
                )?);
            }
        }
    }
    for (id, facts) in observed {
        if facts.len() > 1 {
            findings.push(test_finding(
                definition,
                evaluator,
                facts[0],
                valid_entities([id]),
                format!("Rust test ID `{id}` is observed more than once."),
                standard_edition,
            )?);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_stale_references(
    tests: &[RustTestFact],
    references: &TestReferences<'_>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    let observed: BTreeSet<&str> = tests.iter().map(RustTestFact::id).collect();
    for (test_id, mappings) in references {
        if !observed.contains(test_id) {
            findings.push(contract_finding(
                definition,
                evaluator,
                mappings[0],
                valid_entities([mappings[0].requirement.id(), *test_id]),
                format!(
                    "Requirement `{}` references test `{test_id}` absent from the supported Rust evidence inventory.",
                    mappings[0].requirement.id()
                ),
                standard_edition,
            )?);
        }
    }
    Ok(())
}

fn contract_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    reference: &RequirementRef<'_>,
    entities: Vec<String>,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    make_finding(
        definition,
        evaluator,
        entities,
        FindingLocation::at_path(reference.contract_path)?,
        message,
        standard_edition,
    )
}

fn test_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    test: &RustTestFact,
    entities: Vec<String>,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    make_finding(
        definition,
        evaluator,
        entities,
        FindingLocation::at_path(test.path())?.with_symbol(test.symbol())?,
        message,
        standard_edition,
    )
}

fn make_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    entities: Vec<String>,
    location: FindingLocation,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(entities, location, message)?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}

fn valid_entities<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values
        .into_iter()
        .filter(|value| canonical_entity(value))
        .map(str::to_owned)
        .collect()
}

fn canonical_entity(value: &str) -> bool {
    StableId::parse(value).is_ok()
}

fn canonical_test_id(value: &str) -> bool {
    value.starts_with("T-") && canonical_entity(value)
}
