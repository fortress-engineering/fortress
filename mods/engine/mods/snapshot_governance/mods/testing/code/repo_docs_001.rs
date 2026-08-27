//! Specification-authored conformance for `REPO-DOCS-001`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::documentation::evaluate_documentation_files;
use fortress_core::module_contract::ModuleContract;
use serde::Deserialize;
use serde_json::json;

const EDITION: &str = "1.0.0-draft.1";

fn data_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../mods/snapshot_governance/mods/testing/data/{name}"
    ))
}

fn fixture<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = data_path(name);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn bytes(value: impl Into<String>) -> Vec<u8> {
    value.into().into_bytes()
}

fn contract(id: &str, display_name: &str, relationships: &serde_json::Value) -> Vec<u8> {
    let capability = format!(
        "CAP-{}",
        id.split('-')
            .skip(1)
            .take_while(|segment| !segment.bytes().all(|byte| byte.is_ascii_digit()))
            .collect::<Vec<_>>()
            .join("-")
    );
    let groups = relationships
        .as_array()
        .expect("relationship fixture is array");
    let requires = groups
        .iter()
        .filter(|group| {
            group["types"]
                .as_array()
                .is_some_and(|types| types.iter().any(|kind| kind == "depends_on"))
        })
        .map(|group| {
            let target = group["target"].as_str().expect("target is string");
            let target_capability = format!(
                "CAP-{}",
                target
                    .split('-')
                    .skip(1)
                    .take_while(|segment| !segment.bytes().all(|byte| byte.is_ascii_digit()))
                    .collect::<Vec<_>>()
                    .join("-")
            );
            json!({
                "provider": target,
                "capability": target_capability,
                "version": "^0.1.0"
            })
        })
        .collect::<Vec<_>>();
    let verifies = groups
        .iter()
        .filter(|group| {
            group["types"]
                .as_array()
                .is_some_and(|types| types.iter().any(|kind| kind == "verifies"))
        })
        .map(|group| {
            json!({
                "type": "verifies",
                "target": group["target"],
                "subjects": []
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": display_name,
        "provides": [{"id": capability, "version": "0.1.0", "visibility": "project"}],
        "requires": requires,
        "relationships": verifies,
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    });
    let contract: ModuleContract =
        serde_json::from_value(value).expect("fixture contract deserializes");
    contract
        .to_canonical_json()
        .expect("fixture contract serializes")
        .into_bytes()
}

fn readme(name: &str, relationships: &str) -> Vec<u8> {
    bytes(format!(
        "# {name}\n\n## Purpose\n\nProvide a durable governed responsibility to its parent system.\n\n## Responsibility\n\nFulfill the boundary represented by this Module independently of implementation choices.\n\n## Scope\n\n### Includes\n\nThe directly governed behavior and elements needed for this responsibility.\n\n### Excludes\n\nAdjacent responsibilities owned by explicitly separate Modules.\n\n## Relationships\n\n{relationships}\n\n## Guarantees\n\nPreserve deterministic, inspectable behavior and fail explicitly when its contract cannot be fulfilled.\n"
    ))
}

fn code_docs(files: &[&str]) -> Vec<u8> {
    let entries = files
        .iter()
        .map(|file| {
            format!(
                "### [`{file}`](../code/{file})\n\nContributes the directly owned executable behavior represented by this Code element.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bytes(format!(
        "# Code\n\n## Role\n\nRealize the Module responsibility through directly owned executable logic.\n\n## Execution\n\nThe Code is invoked through its public boundary, processes validated inputs deterministically, and returns after producing its result.\n\n## State\n\nExecution is stateless except for process-local values required by one invocation.\n\n## Failure Semantics\n\nFailures are returned explicitly to the caller without converting incomplete work into success.\n\n## Files\n\n{entries}"
    ))
}

fn data_docs(files: &[&str]) -> Vec<u8> {
    let entries = files
        .iter()
        .map(|file| {
            format!(
                "### [`{file}`](../data/{file})\n\nSupplies an authored input whose meaning is governed by this Module.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bytes(format!(
        "# Data\n\n## Role\n\nProvide persisted computational inputs directly owned by the Module.\n\n## Origin\n\nThese inputs are project-authored under the Module contract.\n\n## Semantics\n\nEach file supplies validated declarative meaning consumed by the Module.\n\n## Validity\n\nData is consumable only when its structure, identity, and references satisfy the applicable schema.\n\n## Lifecycle\n\nMaintainers update the Data when its governed meaning changes and review it with its consumers.\n\n## Files\n\n{entries}"
    ))
}

fn info_docs(files: &[&str]) -> Vec<u8> {
    let entries = files
        .iter()
        .map(|file| {
            format!(
                "### [`{file}`](../info/{file})\n\nPersists the deterministic output produced by the Module computation.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bytes(format!(
        "# Info\n\n## Role\n\nPersist computational output that must survive the producing invocation.\n\n## Production\n\nThe Module produces each output from validated governed inputs.\n\n## Semantics\n\nThe output records the exact result of its identified computation and supports only the conclusions declared by that producer.\n\n## Lifecycle\n\nOutputs are replaced by deterministic regeneration and retained only while their provenance remains valid.\n\n## Files\n\n{entries}"
    ))
}

fn mods_docs(children: &[(&str, &str)]) -> Vec<u8> {
    let entries = children
        .iter()
        .map(|(directory, display)| {
            format!(
                "### [{display}](../mods/{directory}/README.md)\n\nOwns one independently governed contribution to the parent responsibility.\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bytes(format!(
        "# Modules\n\n## Composition\n\nThe parent separates durable child responsibilities so each boundary can be governed independently.\n\n## Modules\n\n{entries}\n## Coordination\n\nThe immediate children combine their distinct outputs through the parent boundary without duplicating their contract graph.\n"
    ))
}

fn atomic() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "README.md".into(),
            readme(
                "Atomic",
                "This Module declares no outbound architectural relationships.",
            ),
        ),
        (
            "contract.json".into(),
            contract("AF-ATOMIC-0001", "Atomic", &json!([])),
        ),
        ("code/main.rs".into(), bytes("pub fn run() {}\n")),
        ("docs/code_docs.md".into(), code_docs(&["main.rs"])),
    ])
}

fn add_child(files: &mut BTreeMap<String, Vec<u8>>, directory: &str, id: &str, display: &str) {
    files.insert(
        format!("mods/{directory}/README.md"),
        readme(
            display,
            "This Module declares no outbound architectural relationships.",
        ),
    );
    files.insert(
        format!("mods/{directory}/contract.json"),
        contract(id, display, &json!([])),
    );
    files.insert(
        format!("mods/{directory}/code/lib.rs"),
        bytes("pub fn child() {}\n"),
    );
    files.insert(
        format!("mods/{directory}/docs/code_docs.md"),
        code_docs(&["lib.rs"]),
    );
}

fn composite() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::from([
        (
            "README.md".into(),
            readme(
                "Composite",
                "This Module declares no outbound architectural relationships.",
            ),
        ),
        (
            "contract.json".into(),
            contract("AF-COMPOSITE-0001", "Composite", &json!([])),
        ),
        ("docs/mods_docs.md".into(), mods_docs(&[("child", "Child")])),
    ]);
    add_child(&mut files, "child", "AF-CHILD-0001", "Child");
    files
}

fn all_elements() -> BTreeMap<String, Vec<u8>> {
    let mut files = composite();
    files.insert("code/main.rs".into(), bytes("pub fn run() {}\n"));
    files.insert("data/input.json".into(), bytes("{}\n"));
    files.insert("info/result.json".into(), bytes("{}\n"));
    files.insert("docs/code_docs.md".into(), code_docs(&["main.rs"]));
    files.insert("docs/data_docs.md".into(), data_docs(&["input.json"]));
    files.insert("docs/info_docs.md".into(), info_docs(&["result.json"]));
    files
}

fn relational(types: &[&str]) -> BTreeMap<String, Vec<u8>> {
    let serialized_types = types.iter().map(|kind| json!(kind)).collect::<Vec<_>>();
    let types_text = types
        .iter()
        .map(|kind| format!("`{kind}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut files = BTreeMap::from([
        (
            "README.md".into(),
            readme(
                "Consumer",
                &format!(
                    "### [Provider](mods/provider/README.md)\n\n**Types:** {types_text}\n\nProvides governed behavior required by the consumer boundary."
                ),
            ),
        ),
        (
            "contract.json".into(),
            contract(
                "AF-CONSUMER-0001",
                "Consumer",
                &json!([{ "target": "AF-PROVIDER-0001", "types": serialized_types }]),
            ),
        ),
        ("code/main.rs".into(), bytes("pub fn run() {}\n")),
        ("docs/code_docs.md".into(), code_docs(&["main.rs"])),
        (
            "docs/mods_docs.md".into(),
            mods_docs(&[("provider", "Provider")]),
        ),
    ]);
    add_child(&mut files, "provider", "AF-PROVIDER-0001", "Provider");
    files
}

fn replace(files: &mut BTreeMap<String, Vec<u8>>, path: &str, old: &str, new: &str) {
    let source = String::from_utf8(files[path].clone()).expect("fixture Markdown is UTF-8");
    assert!(
        source.contains(old),
        "fixture replacement source missing: {old}"
    );
    files.insert(path.into(), bytes(source.replacen(old, new, 1)));
}

#[derive(Deserialize)]
struct ValidFixture {
    cases: Vec<String>,
}

#[derive(Deserialize)]
struct InvalidFixture {
    cases: Vec<InvalidCase>,
}

#[derive(Deserialize)]
struct InvalidCase {
    name: String,
    expected: String,
}

#[derive(Deserialize)]
struct BoundaryFixture {
    case: String,
}

/// `T-REPO-DOCS-001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R10
#[test]
fn valid_documentation_fixtures_pass() {
    let fixture: ValidFixture = fixture("documentation_valid.json");
    for name in fixture.cases {
        let files = match name.as_str() {
            "minimal_atomic_module" => atomic(),
            "pure_composite_module" => composite(),
            "module_with_all_element_types" => all_elements(),
            _ => panic!("unknown valid fixture case: {name}"),
        };
        let report = evaluate_documentation_files(&files, EDITION)
            .expect("documentation evaluation completes");
        assert!(report.is_success(), "{name}: {:#?}", report.findings());
    }
}

#[allow(clippy::too_many_lines)]
fn invalid_case(name: &str) -> BTreeMap<String, Vec<u8>> {
    let mut files = match name {
        "missing_data_entry" | "missing_info_entry" => all_elements(),
        "missing_child_module"
        | "phantom_child_module"
        | "grandchild_cataloged_by_parent"
        | "broken_child_readme_link" => composite(),
        "contract_relationship_missing_readme"
        | "readme_relationship_absent_contract"
        | "mismatched_relationship_type"
        | "stale_renamed_module_relationship"
        | "duplicate_relationship_target"
        | "dependency_cycle" => relational(&["depends_on"]),
        _ => atomic(),
    };
    match name {
        "missing_readme" => {
            files.remove("README.md");
        }
        "missing_contract" => {
            files.remove("contract.json");
        }
        "missing_companion_docs" => {
            files.remove("docs/code_docs.md");
        }
        "orphan_companion_docs" => {
            files.insert("docs/data_docs.md".into(), data_docs(&["input.json"]));
        }
        "extra_file_under_docs" => {
            files.insert("docs/notes.md".into(), bytes("# Notes\n"));
        }
        "subdirectory_under_docs" => {
            files.insert("docs/archive/note.md".into(), bytes("# Note\n"));
        }
        "wrong_h1" => replace(&mut files, "README.md", "# Atomic", "# Wrong"),
        "missing_h2" => replace(
            &mut files,
            "README.md",
            "\n## Guarantees\n\nPreserve deterministic, inspectable behavior and fail explicitly when its contract cannot be fulfilled.\n",
            "\n",
        ),
        "reordered_h2" => {
            let source = readme(
                "Atomic",
                "This Module declares no outbound architectural relationships.",
            );
            let source = String::from_utf8(source).expect("fixture readme is UTF-8");
            let purpose =
                "## Purpose\n\nProvide a durable governed responsibility to its parent system.";
            let responsibility = "## Responsibility\n\nFulfill the boundary represented by this Module independently of implementation choices.";
            files.insert(
                "README.md".into(),
                bytes(
                    source
                        .replace(purpose, "ORDER_MARKER")
                        .replace(responsibility, purpose)
                        .replace("ORDER_MARKER", responsibility),
                ),
            );
        }
        "extra_h2" => {
            let source = String::from_utf8(files["README.md"].clone()).expect("UTF-8");
            files.insert(
                "README.md".into(),
                bytes(format!(
                    "{source}\n## Notes\n\nAdditional taxonomy is forbidden.\n"
                )),
            );
        }
        "illegal_h3" => replace(
            &mut files,
            "README.md",
            "## Purpose\n\n",
            "## Purpose\n\n### Detail\n\nArchitectural detail.\n\n",
        ),
        "h4_heading" => {
            let source = String::from_utf8(files["docs/code_docs.md"].clone()).expect("UTF-8");
            files.insert(
                "docs/code_docs.md".into(),
                bytes(format!("{source}\n#### Detail\n\nForbidden depth.\n")),
            );
        }
        "empty_required_section" => replace(
            &mut files,
            "README.md",
            "## Purpose\n\nProvide a durable governed responsibility to its parent system.\n\n## Responsibility",
            "## Purpose\n\n## Responsibility",
        ),
        "placeholder_content" => replace(
            &mut files,
            "README.md",
            "Provide a durable governed responsibility to its parent system.",
            "TBD.",
        ),
        "missing_code_entry" => replace(
            &mut files,
            "docs/code_docs.md",
            "### [`main.rs`](../code/main.rs)\n\nContributes the directly owned executable behavior represented by this Code element.\n",
            "",
        ),
        "phantom_code_entry" => {
            let source = String::from_utf8(files["docs/code_docs.md"].clone()).expect("UTF-8");
            files.insert(
                "docs/code_docs.md".into(),
                bytes(format!("{source}\n### [`ghost.rs`](../code/ghost.rs)\n\nClaims a nonexistent Code contribution.\n")),
            );
        }
        "missing_data_entry" => replace(
            &mut files,
            "docs/data_docs.md",
            "### [`input.json`](../data/input.json)\n\nSupplies an authored input whose meaning is governed by this Module.\n",
            "",
        ),
        "missing_info_entry" => replace(
            &mut files,
            "docs/info_docs.md",
            "### [`result.json`](../info/result.json)\n\nPersists the deterministic output produced by the Module computation.\n",
            "",
        ),
        "missing_child_module" => replace(
            &mut files,
            "docs/mods_docs.md",
            "### [Child](../mods/child/README.md)\n\nOwns one independently governed contribution to the parent responsibility.\n\n",
            "",
        ),
        "phantom_child_module" => replace(
            &mut files,
            "docs/mods_docs.md",
            "## Coordination",
            "### [Ghost](../mods/ghost/README.md)\n\nClaims a nonexistent child contribution.\n\n## Coordination",
        ),
        "grandchild_cataloged_by_parent" => {
            files.insert(
                "mods/child/docs/mods_docs.md".into(),
                mods_docs(&[("grandchild", "Grandchild")]),
            );
            files.insert(
                "mods/child/mods/grandchild/README.md".into(),
                readme(
                    "Grandchild",
                    "This Module declares no outbound architectural relationships.",
                ),
            );
            files.insert(
                "mods/child/mods/grandchild/contract.json".into(),
                contract("AF-GRANDCHILD-0001", "Grandchild", &json!([])),
            );
            files.insert(
                "mods/child/mods/grandchild/code/lib.rs".into(),
                bytes("pub fn grandchild() {}\n"),
            );
            files.insert(
                "mods/child/mods/grandchild/docs/code_docs.md".into(),
                code_docs(&["lib.rs"]),
            );
            replace(
                &mut files,
                "docs/mods_docs.md",
                "## Coordination",
                "### [Grandchild](../mods/child/mods/grandchild/README.md)\n\nCatalogs a grandchild at the wrong parent.\n\n## Coordination",
            );
        }
        "broken_child_readme_link" => replace(
            &mut files,
            "docs/mods_docs.md",
            "../mods/child/README.md",
            "../mods/renamed/README.md",
        ),
        "contract_relationship_missing_readme" => replace(
            &mut files,
            "README.md",
            "### [Provider](mods/provider/README.md)\n\n**Types:** `depends_on`\n\nProvides governed behavior required by the consumer boundary.",
            "This Module has no human relationship projection.",
        ),
        "readme_relationship_absent_contract" => {
            files.insert(
                "contract.json".into(),
                contract("AF-CONSUMER-0001", "Consumer", &json!([])),
            );
        }
        "mismatched_relationship_type" => replace(
            &mut files,
            "README.md",
            "**Types:** `depends_on`",
            "**Types:** `verifies`",
        ),
        "stale_renamed_module_relationship" => replace(
            &mut files,
            "contract.json",
            "AF-PROVIDER-0001",
            "AF-RENAMED-0001",
        ),
        "self_relationship" => {
            files.insert(
                "contract.json".into(),
                contract(
                    "AF-ATOMIC-0001",
                    "Atomic",
                    &json!([{ "target": "AF-ATOMIC-0001", "types": ["depends_on"] }]),
                ),
            );
        }
        "duplicate_relationship_target" => {
            files.insert(
                "contract.json".into(),
                contract(
                    "AF-CONSUMER-0001",
                    "Consumer",
                    &json!([
                        { "target": "AF-PROVIDER-0001", "types": ["verifies"] },
                        { "target": "AF-PROVIDER-0001", "types": ["verifies"] }
                    ]),
                ),
            );
        }
        "dependency_cycle" => {
            files.insert(
                "mods/provider/contract.json".into(),
                contract(
                    "AF-PROVIDER-0001",
                    "Provider",
                    &json!([{ "target": "AF-CONSUMER-0001", "types": ["depends_on"] }]),
                ),
            );
            replace(
                &mut files,
                "mods/provider/README.md",
                "This Module declares no outbound architectural relationships.",
                "### [Consumer](../../README.md)\n\n**Types:** `depends_on`\n\nRequires the consumer and creates a prohibited dependency cycle.",
            );
        }
        _ => panic!("unknown invalid fixture case: {name}"),
    }
    files
}

/// `T-REPO-DOCS-001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R10
#[test]
fn invalid_documentation_fixtures_fail_with_specific_findings() {
    let fixture: InvalidFixture = fixture("documentation_invalid.json");
    for case in fixture.cases {
        let files = invalid_case(&case.name);
        let report = evaluate_documentation_files(&files, EDITION)
            .expect("documentation evaluation completes");
        assert!(!report.is_success(), "{} unexpectedly passed", case.name);
        assert!(
            report
                .findings()
                .iter()
                .any(|finding| finding.message().contains(&case.expected)),
            "{} did not contain `{}`: {:#?}",
            case.name,
            case.expected,
            report.findings()
        );
    }
}

/// `T-REPO-DOCS-001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R10
#[test]
fn boundary_fixture_groups_multiple_relationship_types_by_target() {
    let fixture: BoundaryFixture = fixture("documentation_boundary.json");
    assert_eq!(fixture.case, "valid_multi_relationship_target");
    let files = relational(&["depends_on", "verifies"]);
    let report =
        evaluate_documentation_files(&files, EDITION).expect("documentation evaluation completes");
    assert!(report.is_success(), "{:#?}", report.findings());
}
