//! Conformance evidence for recursive parent-local Feature verification boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::module_contract::{ContractStandardIndex, resolve_contracts};
use fortress_core::rust_test_analyzer::{RustTestClassification, RustTestFact};
use fortress_core::testing_boundary::evaluate_testing_boundaries;
use fortress_core::traceability::{evaluate_test_traceability, requirements_from_resolved};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize)]
struct Fixture {
    modules: Vec<ModuleSpec>,
    tests: Vec<TestSpec>,
}

#[derive(Clone, Deserialize)]
struct ModuleSpec {
    path: String,
    id: String,
    display_name: String,
    #[serde(default)]
    provides: Vec<ProvidedSpec>,
    #[serde(default)]
    requires: Vec<RequiredSpec>,
    #[serde(default)]
    features: Vec<FeatureSpec>,
    verifies: Option<VerificationSpec>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ProvidedSpec {
    id: String,
    version: String,
    visibility: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct RequiredSpec {
    provider: String,
    capability: String,
    version: String,
}

#[derive(Clone, Deserialize)]
struct FeatureSpec {
    id: String,
    requirement: String,
    test: String,
}

#[derive(Clone, Deserialize)]
struct VerificationSpec {
    target: String,
    subjects: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct TestSpec {
    id: String,
    path: String,
    requirement: Option<String>,
    classification: RustTestClassification,
}

#[derive(Deserialize)]
struct CaseFixture {
    base: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    operation: Operation,
    expected: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Operation {
    RemoveModule {
        path: String,
    },
    RenameModule {
        from: String,
        to: String,
    },
    SetVerifies {
        path: String,
        target: String,
        subjects: Vec<String>,
    },
    AddTestingFeature {
        path: String,
        feature: String,
        requirement: String,
        test: String,
    },
    MoveTest {
        id: String,
        path: String,
    },
    ClearRequirement {
        id: String,
    },
    SetRequirement {
        id: String,
        requirement: String,
    },
    SetClassification {
        id: String,
        classification: RustTestClassification,
    },
    DuplicateTest {
        id: String,
        path: String,
    },
    AddModule {
        path: String,
        id: String,
        target: Option<String>,
        subjects: Vec<String>,
    },
}

#[derive(Serialize)]
struct ContractWire<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    id: &'a str,
    display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<EcosystemWire>,
    provides: &'a [ProvidedSpec],
    requires: &'a [RequiredSpec],
    relationships: Vec<RelationshipWire<'a>>,
    constraints: Vec<serde_json::Value>,
    guarantees: Vec<serde_json::Value>,
    features: Vec<FeatureWire<'a>>,
    behavior: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct EcosystemWire {
    repository_grammar: u16,
    standard: StandardWire,
}

#[derive(Serialize)]
struct StandardWire {
    id: &'static str,
    edition: &'static str,
}

#[derive(Serialize)]
struct RelationshipWire<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    target: &'a str,
    subjects: &'a [String],
}

#[derive(Serialize)]
struct FeatureWire<'a> {
    id: &'a str,
    version: &'static str,
    requirements: Vec<RequirementWire<'a>>,
}

#[derive(Serialize)]
struct RequirementWire<'a> {
    id: &'a str,
    statement: String,
    tests: [&'a str; 1],
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/snapshot_governance/mods/testing/data")
}

fn read<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = fixture_root().join(name);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn contract_source(module: &ModuleSpec) -> String {
    let relationships = module
        .verifies
        .as_ref()
        .map_or_else(Vec::new, |verification| {
            vec![RelationshipWire {
                kind: "verifies",
                target: &verification.target,
                subjects: &verification.subjects,
            }]
        });
    let features = module
        .features
        .iter()
        .map(|feature| FeatureWire {
            id: &feature.id,
            version: "0.1.0",
            requirements: vec![RequirementWire {
                id: &feature.requirement,
                statement: format!("{} remains verified at its owning boundary.", feature.id),
                tests: [&feature.test],
            }],
        })
        .collect();
    let contract = ContractWire {
        schema: "urn:fortress:schema:v2:module-contract",
        schema_version: 2,
        id: &module.id,
        display_name: &module.display_name,
        ecosystem: module.path.is_empty().then_some(EcosystemWire {
            repository_grammar: 1,
            standard: StandardWire {
                id: "STD-FORTRESS-ENGINEERING",
                edition: "1.0.0-draft.1",
            },
        }),
        provides: &module.provides,
        requires: &module.requires,
        relationships,
        constraints: Vec::new(),
        guarantees: Vec::new(),
        features,
        behavior: Vec::new(),
    };
    let mut source = serde_json::to_string_pretty(&contract).expect("fixture contract serializes");
    source.push('\n');
    source
}

fn evaluate(fixture: &Fixture) -> Vec<String> {
    let files: BTreeMap<String, Vec<u8>> = fixture
        .modules
        .iter()
        .map(|module| {
            let path = if module.path.is_empty() {
                "contract.json".to_owned()
            } else {
                format!("{}/contract.json", module.path)
            };
            (path, contract_source(module).into_bytes())
        })
        .collect();
    let observed_ids: BTreeSet<String> = fixture.tests.iter().map(|test| test.id.clone()).collect();
    let resolution = resolve_contracts(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "CONTRACT-COHERENCY-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        Some(&observed_ids),
    );
    let Some(resolved) = resolution.resolved() else {
        return resolution
            .violations()
            .iter()
            .map(ToString::to_string)
            .collect();
    };
    let tests: Vec<RustTestFact> = fixture
        .tests
        .iter()
        .map(|test| {
            RustTestFact::new(
                &test.id,
                &test.path,
                test.id.trim_start_matches("T-").to_ascii_lowercase(),
                test.classification,
                test.requirement.clone(),
            )
            .expect("fixture test fact validates")
        })
        .collect();
    let boundary = evaluate_testing_boundaries(resolved, &tests, "1.0.0-draft.1")
        .expect("boundary evaluation completes");
    let requirements = requirements_from_resolved(resolved);
    let traceability = evaluate_test_traceability(&requirements, &tests, "1.0.0-draft.1")
        .expect("traceability evaluation completes");
    boundary
        .findings()
        .iter()
        .chain(traceability.findings())
        .map(|finding| finding.message().to_owned())
        .collect()
}

fn apply_operation(fixture: &mut Fixture, operation: &Operation) {
    match operation {
        Operation::RemoveModule { path } => fixture.modules.retain(|module| module.path != *path),
        Operation::RenameModule { from, to } => {
            module_mut(fixture, from).path.clone_from(to);
        }
        Operation::SetVerifies {
            path,
            target,
            subjects,
        } => {
            module_mut(fixture, path).verifies = Some(VerificationSpec {
                target: target.clone(),
                subjects: subjects.clone(),
            });
        }
        Operation::AddTestingFeature {
            path,
            feature,
            requirement,
            test,
        } => {
            module_mut(fixture, path).features.push(FeatureSpec {
                id: feature.clone(),
                requirement: requirement.clone(),
                test: test.clone(),
            });
            fixture.tests.push(TestSpec {
                id: test.clone(),
                path: format!("{path}/code/owned.rs"),
                requirement: Some(requirement.clone()),
                classification: RustTestClassification::Behavioral,
            });
        }
        Operation::MoveTest { id, path } => test_mut(fixture, id).path.clone_from(path),
        Operation::ClearRequirement { id } => test_mut(fixture, id).requirement = None,
        Operation::SetRequirement { id, requirement } => {
            test_mut(fixture, id).requirement = Some(requirement.clone());
        }
        Operation::SetClassification { id, classification } => {
            test_mut(fixture, id).classification = *classification;
        }
        Operation::DuplicateTest { id, path } => {
            let mut duplicate = test_mut(fixture, id).clone();
            duplicate.path.clone_from(path);
            fixture.tests.push(duplicate);
        }
        Operation::AddModule {
            path,
            id,
            target,
            subjects,
        } => fixture.modules.push(ModuleSpec {
            path: path.clone(),
            id: id.clone(),
            display_name: id.replace('-', " "),
            provides: Vec::new(),
            requires: Vec::new(),
            features: Vec::new(),
            verifies: target.as_ref().map(|target| VerificationSpec {
                target: target.clone(),
                subjects: subjects.clone(),
            }),
        }),
    }
}

fn module_mut<'a>(fixture: &'a mut Fixture, path: &str) -> &'a mut ModuleSpec {
    fixture
        .modules
        .iter_mut()
        .find(|module| module.path == path)
        .unwrap_or_else(|| panic!("fixture Module `{path}` exists"))
}

fn test_mut<'a>(fixture: &'a mut Fixture, id: &str) -> &'a mut TestSpec {
    fixture
        .tests
        .iter_mut()
        .find(|test| test.id == id)
        .unwrap_or_else(|| panic!("fixture test `{id}` exists"))
}

/// `T-TEST-BOUNDARY-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R12
#[test]
fn simple_recursive_utility_has_exact_parent_local_testing() {
    let fixture: Fixture = read("testing_simple.json");
    let findings = evaluate(&fixture);
    assert!(findings.is_empty(), "findings: {findings:#?}");
}

/// `T-TEST-BOUNDARY-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R12
#[test]
fn complex_recursive_ecosystem_separates_atomic_composite_and_root_evidence() {
    let fixture: Fixture = read("testing_complex.json");
    let findings = evaluate(&fixture);
    assert!(findings.is_empty(), "findings: {findings:#?}");
    assert!(
        fixture
            .modules
            .iter()
            .any(|module| module.path == "mods/operations" && module.features.is_empty())
    );
    assert!(fixture.tests.iter().any(|test| {
        test.classification == RustTestClassification::Conformance
            && test.path.contains("service/mods/testing/code/")
    }));
}

/// `T-TEST-BOUNDARY-001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R12
#[test]
fn invalid_recursive_boundaries_fail_at_their_exact_authority() {
    let cases: CaseFixture = read("testing_cases.json");
    let base: Fixture = read(&cases.base);
    assert_eq!(cases.cases.len(), 17);
    for case in cases.cases {
        let mut fixture = base.clone();
        apply_operation(&mut fixture, &case.operation);
        let messages = evaluate(&fixture);
        assert!(
            messages
                .iter()
                .any(|message| message.contains(&case.expected)),
            "case `{}` expected `{}` in {messages:#?}",
            case.name,
            case.expected
        );
    }
}
