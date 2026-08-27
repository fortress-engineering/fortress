//! Recursive parent-local Feature verification boundary evaluation.

use std::collections::{BTreeMap, BTreeSet};

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::module_contract::{
    ContractFeature, ModuleRelationshipType, ResolvedContractSet, ResolvedModule,
};
use crate::rust_test_analyzer::RustTestFact;

/// Stable identity of recursive parent-local Feature verification boundaries.
pub const TEST_BOUNDARY_RULE_ID: &str = "TEST-BOUNDARY-001";

const REMEDIATION: &str = "Give every Feature-owning Module exactly one direct mods/testing child, make that Testing contract verify exactly its immediate parent's local Features, keep canonical Testing Modules featureless, and place every Rust test directly beneath a canonical Testing Module's code directory.";

/// Deterministic recursive testing-boundary result.
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

/// Evaluates recursive Testing Module structure and parent-local Feature claims.
///
/// Requirement identity and requirement-owner/test-owner reconciliation remain
/// owned by `TEST-TRACEABILITY-001`; this evaluator owns the surrounding
/// structural obligation and therefore does not duplicate those findings.
///
/// # Errors
///
/// Returns [`FindingError`] only if canonical finding construction fails.
pub fn evaluate_testing_boundaries(
    contracts: &ResolvedContractSet,
    tests: &[RustTestFact],
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
    let by_path: BTreeMap<&str, &ResolvedModule> = contracts
        .modules()
        .values()
        .map(|module| (module.path(), module))
        .collect();
    let mut findings = Vec::new();
    let feature_owning_modules = evaluate_module_obligations(
        contracts,
        &by_path,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    let testing_modules = evaluate_testing_modules(
        contracts,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;

    for test in tests {
        if testing_owner_for_path(test.path(), &by_path).is_none() {
            findings.push(test_finding(
                &definition,
                &evaluator,
                test,
                format!(
                    "Rust test `{}` is outside the direct `code/` directory of a canonical Testing Module.",
                    test.id()
                ),
                standard_edition,
            )?);
        }
    }

    findings.sort();
    Ok(TestingBoundaryEvaluation {
        feature_owning_modules,
        testing_modules,
        observed_tests: tests.len(),
        findings,
    })
}

fn evaluate_module_obligations(
    contracts: &ResolvedContractSet,
    by_path: &BTreeMap<&str, &ResolvedModule>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<usize, FindingError> {
    let mut feature_owning_modules = 0;
    for module in contracts.modules().values() {
        let local_features: BTreeSet<&str> = module
            .contract()
            .features()
            .iter()
            .map(ContractFeature::id)
            .collect();
        if !local_features.is_empty() {
            feature_owning_modules += 1;
        }
        for feature in module.contract().features() {
            if feature.requirements().is_empty() {
                findings.push(module_finding(
                    definition,
                    evaluator,
                    module,
                    [feature.id()],
                    format!(
                        "Feature `{}` owns no requirements and therefore cannot define a verifiable Module boundary.",
                        feature.id()
                    ),
                    standard_edition,
                )?);
            }
        }

        let testing_path = direct_child_path(module.path(), "testing");
        let testing = by_path.get(testing_path.as_str()).copied();
        match (local_features.is_empty(), testing) {
            (false, None) => findings.push(module_finding(
                definition,
                evaluator,
                module,
                local_features.iter().copied(),
                format!(
                    "Feature-owning Module `{}` has no direct `mods/testing` child.",
                    module.contract().id()
                ),
                standard_edition,
            )?),
            (true, Some(testing)) => findings.push(module_finding(
                definition,
                evaluator,
                testing,
                [module.contract().id(), testing.contract().id()],
                format!(
                    "Featureless Module `{}` has a canonical Testing child without a current parent-local Feature obligation.",
                    module.contract().id()
                ),
                standard_edition,
            )?),
            _ => {}
        }
    }
    Ok(feature_owning_modules)
}

fn evaluate_testing_modules(
    contracts: &ResolvedContractSet,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<usize, FindingError> {
    let mut testing_modules = 0;
    for module in contracts.modules().values() {
        if is_testing_module(module.path()) {
            testing_modules += 1;
            validate_testing_contract(
                module,
                contracts,
                definition,
                evaluator,
                standard_edition,
                findings,
            )?;
        }
        if is_parallel_testing_taxonomy(module.path()) {
            findings.push(module_finding(
                definition,
                evaluator,
                module,
                [module.contract().id()],
                format!(
                    "Module `{}` uses reserved parallel testing taxonomy `{}`; verification scope must be represented only by a direct `mods/testing` Module.",
                    module.contract().id(),
                    module.path()
                ),
                standard_edition,
            )?);
        }
    }
    Ok(testing_modules)
}

fn validate_testing_contract(
    testing: &ResolvedModule,
    contracts: &ResolvedContractSet,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    let Some(parent_id) = testing.parent_id() else {
        findings.push(module_finding(
            definition,
            evaluator,
            testing,
            [testing.contract().id()],
            "Canonical Testing Module has no immediate physical parent Module.".into(),
            standard_edition,
        )?);
        return Ok(());
    };
    let parent = contracts
        .modules()
        .get(parent_id)
        .expect("resolved containment parent must exist");
    let expected_subjects: Vec<&str> = parent
        .contract()
        .features()
        .iter()
        .map(ContractFeature::id)
        .collect();
    let relationships = testing.contract().relationships();
    let valid_relationship = relationships.len() == 1
        && relationships[0].kind() == ModuleRelationshipType::Verifies
        && relationships[0].target() == parent_id
        && relationships[0]
            .subjects()
            .iter()
            .map(String::as_str)
            .eq(expected_subjects.iter().copied());
    if !valid_relationship {
        findings.push(module_finding(
            definition,
            evaluator,
            testing,
            std::iter::once(testing.contract().id())
                .chain(std::iter::once(parent_id))
                .chain(expected_subjects.iter().copied()),
            format!(
                "Testing Module `{}` must declare exactly one `verifies` relationship to immediate parent `{parent_id}` with exact local Feature subjects [{}].",
                testing.contract().id(),
                expected_subjects.join(", ")
            ),
            standard_edition,
        )?);
    }
    let contract = testing.contract();
    if !contract.provides().is_empty()
        || !contract.guarantees().is_empty()
        || !contract.features().is_empty()
        || !contract.behavior().is_empty()
    {
        findings.push(module_finding(
            definition,
            evaluator,
            testing,
            [testing.contract().id()],
            format!(
                "Canonical Testing Module `{}` must keep `provides`, `guarantees`, `features`, and `behavior` empty.",
                testing.contract().id()
            ),
            standard_edition,
        )?);
    }
    Ok(())
}

fn direct_child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        format!("mods/{child}")
    } else {
        format!("{parent}/mods/{child}")
    }
}

fn is_testing_module(path: &str) -> bool {
    path == "mods/testing" || path.ends_with("/mods/testing")
}

fn is_parallel_testing_taxonomy(path: &str) -> bool {
    ["tests", "unit_tests", "integration_tests", "e2e_tests"]
        .iter()
        .any(|name| path == format!("mods/{name}") || path.ends_with(&format!("/mods/{name}")))
}

fn testing_owner_for_path<'a>(
    test_path: &str,
    by_path: &BTreeMap<&'a str, &'a ResolvedModule>,
) -> Option<&'a ResolvedModule> {
    by_path.values().copied().find(|module| {
        if !is_testing_module(module.path()) {
            return false;
        }
        let prefix = format!("{}/code/", module.path());
        test_path
            .strip_prefix(&prefix)
            .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
    })
}

fn module_finding<'a>(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    module: &ResolvedModule,
    entities: impl IntoIterator<Item = &'a str>,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(
            entities.into_iter().map(str::to_owned).collect(),
            FindingLocation::at_path(module.contract_path())?,
            message,
        )?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}

fn test_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    test: &RustTestFact,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(
            vec![test.id().to_owned()],
            FindingLocation::at_path(test.path())?.with_symbol(test.symbol())?,
            message,
        )?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}
