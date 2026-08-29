//! Parent-local conformance for relocation-transparent reference resolution.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fortress_core::audit::compile_repository_ccg;
use fortress_core::contract_coherency::{
    ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::reference_resolution::{
    ComponentResolution, ComponentResolutionIndex, ReferenceClass, ReferenceFact,
    ResolutionBoundary, ResolutionBoundaryClass, evaluate_reference_resolution,
    project_readme_relationships, relative_navigation,
};
use serde_json::{Value, json};

fn canonical(value: &Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value.clone())
        .expect("fixture contract shape")
        .to_canonical_json()
        .expect("fixture serializes")
        .into_bytes()
}

fn contract(id: &str, name: &str, provides: &Value, requires: &Value) -> Value {
    json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": name,
        "provides": provides,
        "requires": requires,
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    })
}

fn fixture_files() -> BTreeMap<String, Vec<u8>> {
    let root = json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": "PF-REFERENCE-FIXTURE",
        "display_name": "Fixture",
        "ecosystem": {
            "repository_grammar": 1,
            "standard": {"id": "STD-FIXTURE", "edition": "1.0.0-draft.1"}
        },
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    });
    let provider = contract(
        "AF-PROVIDER-0001",
        "Provider",
        &json!([{"id": "CAP-PROVIDER", "version": "0.1.0", "visibility": "project"}]),
        &json!([]),
    );
    let consumer = contract(
        "AF-CONSUMER-0001",
        "Consumer",
        &json!([]),
        &json!([{"provider": "AF-PROVIDER-0001", "capability": "CAP-PROVIDER", "version": "^0.1.0"}]),
    );
    BTreeMap::from([
        ("contract.json".into(), canonical(&root)),
        ("mods/consumer/contract.json".into(), canonical(&consumer)),
        ("mods/provider/contract.json".into(), canonical(&provider)),
    ])
}

fn fixture_ccg(
    files: &BTreeMap<String, Vec<u8>>,
) -> fortress_core::contract_coherency::ContractCoherencyGraph {
    let compilation = compile_contract_coherency_graph(
        files,
        &ContractStandardIndex::new("STD-FIXTURE", "1.0.0-draft.1", ["REPO-REFERENCE-001"]),
        None,
    );
    assert!(compilation.is_success(), "{:?}", compilation.violations());
    compilation.graph().expect("fixture CCG compiles").clone()
}

fn synthetic_index(modules: usize, references: usize) -> ComponentResolutionIndex {
    let mut components = vec![ComponentResolution::new("PF-LARGE", "", None)];
    for index in 0..modules {
        let parent = if index < 10 {
            "PF-LARGE".to_owned()
        } else {
            format!("AF-MODULE-{:04}", index % 10)
        };
        let path = if index < 10 {
            format!("mods/m{index:04}")
        } else {
            format!("mods/m{:04}/mods/m{index:04}", index % 10)
        };
        components.push(ComponentResolution::new(
            format!("AF-MODULE-{index:04}"),
            path,
            Some(parent),
        ));
    }
    let semantic = (0..references)
        .map(|index| {
            ReferenceFact::new(
                ReferenceClass::Semantic,
                format!("AF-MODULE-{:04}", index % modules),
                Some(format!("AF-MODULE-{:04}", (index + 1) % modules)),
                format!("CAP-{index:06}"),
                None,
                format!("contract-{index:06}"),
            )
        })
        .collect();
    ComponentResolutionIndex::synthetic(
        "PF-LARGE",
        format!("sha256:{}", "0".repeat(64)),
        components,
        semantic,
        Vec::new(),
    )
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R01-001`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R01
#[test]
fn stable_identity_resolves_to_portable_current_location() {
    let mut files = fixture_files();
    files.insert("mods/consumer/README.md".into(), b"# Consumer\n".to_vec());
    files.insert("mods/provider/README.md".into(), b"# Provider\n".to_vec());
    let ccg = fixture_ccg(&files);
    let evaluation =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("resolution succeeds");
    let provider = evaluation
        .index()
        .resolve_module("AF-PROVIDER-0001")
        .expect("stable ID resolves");
    assert_eq!(provider.module_path(), "mods/provider");
    assert_eq!(provider.readme_path(), "mods/provider/README.md");
    assert!(!provider.module_path().contains('\\'));
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R01-002`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R01
#[test]
fn resolution_projection_is_ccg_bound_and_deterministic() {
    let files = fixture_files();
    let ccg = fixture_ccg(&files);
    let first =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("first resolution");
    let second =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("second resolution");
    assert_eq!(first.index(), second.index());
    assert_eq!(
        first.index().to_canonical_json().expect("JSON"),
        second.index().to_canonical_json().expect("JSON")
    );
    assert_eq!(
        first.index().source_ccg_digest(),
        ccg.digest().expect("digest")
    );
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R01-003`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R01
#[test]
fn one_module_project_needs_no_authored_resolution_configuration() {
    let index = ComponentResolutionIndex::synthetic(
        "PF-ONE",
        format!("sha256:{}", "1".repeat(64)),
        vec![ComponentResolution::new("PF-ONE", "", None)],
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(index.summary().modules(), 1);
    assert_eq!(index.summary().semantic_references(), 0);
    assert_eq!(index.summary().authored_resolution_boundaries(), 0);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R02-001`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn local_semantic_external_and_projection_classes_remain_distinct() {
    let references = [
        ReferenceFact::new(
            ReferenceClass::Local,
            "AF-A-0001",
            Some("AF-A-0001".into()),
            "local",
            Some("docs/code_docs.md".into()),
            "a",
        ),
        ReferenceFact::new(
            ReferenceClass::Semantic,
            "AF-A-0001",
            Some("AF-B-0001".into()),
            "CAP-B",
            None,
            "b",
        ),
        ReferenceFact::new(
            ReferenceClass::PhysicalProjection,
            "AF-A-0001",
            Some("AF-B-0001".into()),
            "AF-B-0001",
            Some("../b/README.md".into()),
            "c",
        ),
        ReferenceFact::new(
            ReferenceClass::External,
            "AF-A-0001",
            None,
            "fortress-core",
            None,
            "d",
        ),
    ];
    assert_eq!(references[0].class(), ReferenceClass::Local);
    assert_eq!(references[1].authority(), "CAP-B");
    assert_eq!(references[2].class(), ReferenceClass::PhysicalProjection);
    assert_eq!(references[3].class(), ReferenceClass::External);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R02-002`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn machine_absolute_and_direct_cross_module_rust_paths_fail_exactly() {
    let mut files = fixture_files();
    files.insert(
        "mods/consumer/README.md".into(),
        b"# Consumer\n\n## Relationships\n\n### [Provider](C:\\repo\\mods\\provider\\README.md)\n"
            .to_vec(),
    );
    files.insert(
        "mods/consumer/code/direct.rs".into(),
        b"include_str!(\"../../provider/data/value.txt\");\n".to_vec(),
    );
    files.insert("mods/provider/data/value.txt".into(), b"value\n".to_vec());
    let ccg = fixture_ccg(&files);
    let result =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("violations normalize");
    let messages = result
        .findings()
        .iter()
        .map(fortress_core::finding::CanonicalFinding::message)
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .any(|message| message.contains("machine-local absolute"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("directly traverses a cross-Module"))
    );
}

/// `T-REPO-REFERENCE-001-R01-001`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn rule_rejects_machine_absolute_persistent_navigation() {
    let mut files = fixture_files();
    files.insert(
        "mods/consumer/README.md".into(),
        b"# Consumer\n\n## Relationships\n\n### [Provider](C:\\repo\\provider\\README.md)\n"
            .to_vec(),
    );
    let ccg = fixture_ccg(&files);
    let result =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("finding normalizes");
    assert_eq!(result.findings().len(), 1);
    assert!(
        result.findings()[0]
            .message()
            .contains("machine-local absolute")
    );
}

/// `T-REPO-REFERENCE-001-R01-002`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn rule_rejects_stale_semantic_markdown_projection() {
    let mut files = fixture_files();
    files.insert(
        "mods/consumer/README.md".into(),
        b"# Consumer\n\n## Relationships\n\n### [Provider](../../mods/provider/README.md)\n"
            .to_vec(),
    );
    files.insert("mods/provider/README.md".into(), b"# Provider\n".to_vec());
    let ccg = fixture_ccg(&files);
    let result =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("finding normalizes");
    assert_eq!(result.findings().len(), 1);
    assert!(result.findings()[0].message().contains("is stale"));
}

/// `T-REPO-REFERENCE-001-R01-003`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn rule_allows_same_module_relative_path_and_rejects_cross_module_traversal() {
    let mut files = fixture_files();
    files.insert(
        "mods/consumer/code/use_data.rs".into(),
        b"const LOCAL: &str = include_str!(\"../data/local.txt\");\nconst FOREIGN: &str = include_str!(\"../../provider/data/value.txt\");\n".to_vec(),
    );
    files.insert("mods/consumer/data/local.txt".into(), b"local\n".to_vec());
    files.insert("mods/provider/data/value.txt".into(), b"foreign\n".to_vec());
    let ccg = fixture_ccg(&files);
    let result =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("finding normalizes");
    assert_eq!(result.findings().len(), 1);
    assert!(result.index().references().iter().any(|reference| {
        reference.class() == ReferenceClass::Local
            && reference.projection() == Some("../data/local.txt")
    }));
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R02-003`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R02
#[test]
fn unknown_and_duplicate_stable_id_remain_ccg_failures() {
    let mut unknown = fixture_files();
    let source = String::from_utf8(unknown["mods/consumer/contract.json"].clone()).expect("UTF-8");
    unknown.insert(
        "mods/consumer/contract.json".into(),
        source
            .replace("AF-PROVIDER-0001", "AF-UNKNOWN-0001")
            .into_bytes(),
    );
    let standard =
        ContractStandardIndex::new("STD-FIXTURE", "1.0.0-draft.1", ["REPO-REFERENCE-001"]);
    assert!(!compile_contract_coherency_graph(&unknown, &standard, None).is_success());
    let mut duplicate = fixture_files();
    duplicate.insert(
        "mods/duplicate/contract.json".into(),
        duplicate["mods/provider/contract.json"].clone(),
    );
    assert!(!compile_contract_coherency_graph(&duplicate, &standard, None).is_success());
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R03-001`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R03
#[test]
fn markdown_projection_regenerates_from_semantic_identity_idempotently() {
    let files = fixture_files();
    let ccg = fixture_ccg(&files);
    let stale = "# Consumer\n\n## Relationships\n\n### [Provider](old/location.md)\n\n**Types:** `depends_on`\n\nReason.\n\n## Guarantees\n\nStable.\n";
    let projected =
        project_readme_relationships(&ccg, "AF-CONSUMER-0001", stale).expect("projection succeeds");
    assert!(projected.contains("### [Provider](../provider/README.md)"));
    assert_eq!(
        project_readme_relationships(&ccg, "AF-CONSUMER-0001", &projected)
            .expect("second projection"),
        projected
    );
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R03-002`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R03
#[test]
fn cargo_and_rust_crate_roots_are_explicit_resolution_boundaries() {
    let boundaries = [
        ResolutionBoundary::new(
            ResolutionBoundaryClass::AuthoredResolutionBoundary,
            "cargo",
            "data/Cargo.toml",
            "workspace.members[0]",
            "PF-X",
            Some("AF-A-0001".into()),
            "mods/a/data",
        ),
        ResolutionBoundary::new(
            ResolutionBoundaryClass::AuthoredResolutionBoundary,
            "rust-module",
            "mods/a/code/lib.rs",
            "../mods/b/code/b.rs",
            "AF-A-0001",
            Some("AF-B-0001".into()),
            "mods/a/mods/b/code/b.rs",
        ),
    ];
    assert!(boundaries.iter().all(|boundary| boundary.class() == ResolutionBoundaryClass::AuthoredResolutionBoundary));
    assert!(
        boundaries
            .iter()
            .all(|boundary| !boundary.resolved_target().contains(".."))
    );
    let stable_import = ReferenceFact::new(
        ReferenceClass::External,
        "AF-CLI-0001",
        Some("AF-CORE-0001".into()),
        "fortress-core",
        None,
        "use fortress_core::audit",
    );
    assert_eq!(stable_import.authority(), "fortress-core");
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R03-003`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R03
#[test]
fn relative_navigation_is_portable_case_exact_and_location_sensitive() {
    assert_eq!(
        relative_navigation("mods/a/README.md", "mods/b/README.md"),
        "../b/README.md"
    );
    assert_eq!(
        relative_navigation("mods/a/mods/x/README.md", "mods/a/README.md"),
        "../../README.md"
    );
    assert_eq!(
        relative_navigation("README.md", "mods/a/README.md"),
        "mods/a/README.md"
    );
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R03-004`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R03
#[test]
fn rust_native_package_identity_survives_module_relocation() {
    let mut files = fixture_files();
    files.insert(
        "mods/consumer/data/Cargo.toml".into(),
        b"[package]\nname = \"consumer-crate\"\nversion = \"0.1.0\"\n\n[dependencies]\nprovider-crate = { path = \"../../provider/data\" }\n"
            .to_vec(),
    );
    files.insert(
        "mods/provider/data/Cargo.toml".into(),
        b"[package]\nname = \"provider-crate\"\nversion = \"0.1.0\"\n".to_vec(),
    );
    files.insert(
        "mods/consumer/code/lib.rs".into(),
        b"use provider_crate::Facade;\n".to_vec(),
    );
    let ccg = fixture_ccg(&files);
    let evaluation =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("resolution");
    assert!(evaluation.index().references().iter().any(|reference| {
        reference.class() == ReferenceClass::External
            && reference.authority() == "provider-crate"
            && reference.target_module() == Some("AF-PROVIDER-0001")
    }));
    let preview = evaluation
        .index()
        .preview_move_to_path("AF-PROVIDER-0001", "mods/platform/mods/provider")
        .expect("move preview");
    assert_eq!(preview.required_semantic_reference_edits(), 0);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R04-001`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R04
#[test]
fn subtree_move_preserves_child_ids_and_all_semantic_references() {
    let modules = vec![
        ComponentResolution::new("PF-X", "", None),
        ComponentResolution::new("AF-A-0001", "mods/a", Some("PF-X".into())),
        ComponentResolution::new("AF-B-0001", "mods/a/mods/b", Some("AF-A-0001".into())),
        ComponentResolution::new(
            "AF-C-0001",
            "mods/a/mods/b/mods/c",
            Some("AF-B-0001".into()),
        ),
        ComponentResolution::new("AF-X-0001", "mods/x", Some("PF-X".into())),
    ];
    let references = vec![ReferenceFact::new(
        ReferenceClass::Semantic,
        "AF-C-0001",
        Some("AF-A-0001".into()),
        "CAP-A",
        None,
        "contract",
    )];
    let index = ComponentResolutionIndex::synthetic(
        "PF-X",
        format!("sha256:{}", "2".repeat(64)),
        modules,
        references,
        Vec::new(),
    );
    let preview = index
        .preview_move("AF-B-0001", "AF-X-0001")
        .expect("subtree move");
    assert_eq!(preview.moved_modules(), &["AF-B-0001", "AF-C-0001"]);
    assert_eq!(preview.required_semantic_reference_edits(), 0);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R04-002`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R04
#[test]
fn upward_and_downward_moves_only_affect_physical_boundaries() {
    let modules = vec![
        ComponentResolution::new("PF-X", "", None),
        ComponentResolution::new("AF-PAYMENTS-0001", "mods/payments", Some("PF-X".into())),
        ComponentResolution::new(
            "AF-CURRENCY-0001",
            "mods/payments/mods/currency",
            Some("AF-PAYMENTS-0001".into()),
        ),
        ComponentResolution::new("AF-COMPILER-0001", "mods/compiler", Some("PF-X".into())),
        ComponentResolution::new("AF-PARSER-0001", "mods/parser", Some("PF-X".into())),
    ];
    let boundaries = vec![ResolutionBoundary::new(
        ResolutionBoundaryClass::AuthoredResolutionBoundary,
        "cargo",
        "data/Cargo.toml",
        "workspace.members[0]",
        "PF-X",
        Some("AF-CURRENCY-0001".into()),
        "mods/payments/mods/currency/data",
    )];
    let index = ComponentResolutionIndex::synthetic(
        "PF-X",
        format!("sha256:{}", "3".repeat(64)),
        modules,
        Vec::new(),
        boundaries,
    );
    let upward = index
        .preview_move_to_path("AF-CURRENCY-0001", "mods/currency")
        .expect("upward move");
    let downward = index
        .preview_move("AF-PARSER-0001", "AF-COMPILER-0001")
        .expect("downward move");
    assert_eq!(upward.required_semantic_reference_edits(), 0);
    assert_eq!(upward.authored_resolution_boundaries_affected().len(), 1);
    assert_eq!(downward.required_semantic_reference_edits(), 0);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R04-003`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R04
#[test]
fn hundreds_of_modules_and_thousands_of_references_have_bounded_churn() {
    let index = synthetic_index(500, 5_000);
    let preview = index
        .preview_move("AF-MODULE-0001", "AF-MODULE-0002")
        .expect("large move");
    assert_eq!(preview.required_semantic_reference_edits(), 0);
    assert!(preview.moved_modules().len() <= 51);
    assert!(preview.unrelated_modules_unaffected() >= 450);
    assert_eq!(index.summary().semantic_references(), 5_000);
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R04-005`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R04
#[test]
fn genuine_semantic_dependency_change_remains_visible_beside_a_move() {
    let modules = vec![
        ComponentResolution::new("PF-X", "", None),
        ComponentResolution::new("AF-A-0001", "mods/a", Some("PF-X".into())),
        ComponentResolution::new("AF-B-0001", "mods/b", Some("PF-X".into())),
    ];
    let before = ComponentResolutionIndex::synthetic(
        "PF-X",
        format!("sha256:{}", "4".repeat(64)),
        modules.clone(),
        vec![ReferenceFact::new(
            ReferenceClass::Semantic,
            "AF-A-0001",
            Some("AF-B-0001".into()),
            "CAP-B-V1",
            None,
            "before",
        )],
        Vec::new(),
    );
    let after = ComponentResolutionIndex::synthetic(
        "PF-X",
        format!("sha256:{}", "5".repeat(64)),
        modules,
        vec![ReferenceFact::new(
            ReferenceClass::Semantic,
            "AF-A-0001",
            Some("AF-B-0001".into()),
            "CAP-B-V2",
            None,
            "after",
        )],
        Vec::new(),
    );
    let move_preview = before
        .preview_move_to_path("AF-B-0001", "mods/platform/mods/b")
        .expect("pure move");
    let semantic_delta = before.semantic_reference_delta(&after);
    assert_eq!(move_preview.required_semantic_reference_edits(), 0);
    assert_eq!(semantic_delta.added().len(), 1);
    assert_eq!(semantic_delta.removed().len(), 1);
    assert!(!semantic_delta.is_empty());
}

/// `T-AF-REFERENCE-RESOLUTION-0001-R04-004`
/// Fortress requirement: AF-REFERENCE-RESOLUTION-0001-R04
#[test]
fn live_fortress_reference_audit_is_clean_and_repeatable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root");
    let ccg = compile_repository_ccg(&root).expect("live CCG");
    let mut files = BTreeMap::new();
    collect_sources(&root, &root, &mut files);
    let first =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("live resolution");
    let second =
        evaluate_reference_resolution(&ccg, &files, "1.0.0-draft.1").expect("repeat resolution");
    assert!(first.findings().is_empty(), "{:?}", first.findings());
    assert_eq!(first.index(), second.index());
}

fn collect_sources(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("directory readable") {
        let entry = entry.expect("entry readable");
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != ".git" && name != "target" {
                collect_sources(root, &path, files);
            }
        } else if path.extension().is_some_and(|extension| {
            matches!(extension.to_str(), Some("rs" | "md" | "json" | "toml"))
        }) {
            let relative = path
                .strip_prefix(root)
                .expect("within root")
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative, fs::read(path).expect("file readable"));
        }
    }
}
