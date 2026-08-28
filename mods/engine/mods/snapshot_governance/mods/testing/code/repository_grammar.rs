//! Parent-local self-application evidence for recursive Module grammar and documentation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::documentation::evaluate_documentation_files;
use fortress_core::observation::{ObservationPolicy, observe_repository};
use fortress_core::placement::evaluate_module_grammar;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R10-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R10
#[test]
fn fortress_documentation_is_complete_synchronized_and_deterministic() {
    let root = repository_root();
    let policy = ObservationPolicy::new([".git"]).expect("self exclusion validates");
    let observation = observe_repository(&root, &policy).expect("repository observes");
    let files: BTreeMap<String, Vec<u8>> = observation
        .files()
        .iter()
        .map(|file| {
            let bytes = fs::read(root.join(file.path()))
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.path()));
            (file.path().to_owned(), bytes)
        })
        .collect();
    let first = evaluate_documentation_files(&files, "1.0.0-draft.1")
        .expect("documentation evaluation completes");
    let second = evaluate_documentation_files(&files, "1.0.0-draft.1")
        .expect("documentation evaluation repeats");
    assert!(
        first.is_success(),
        "documentation findings: {:#?}",
        first.findings()
    );
    assert_eq!(first, second);
    assert_eq!(first.summary().modules_inspected(), 36);
    assert_eq!(first.summary().markdown_files_inspected(), 115);
    assert_eq!(
        first.summary().code_bijection().0,
        first.summary().code_bijection().1
    );
    assert_eq!(
        first.summary().data_bijection().0,
        first.summary().data_bijection().1
    );
    assert_eq!(
        first.summary().info_bijection().0,
        first.summary().info_bijection().1
    );
    assert_eq!(
        first.summary().module_bijection().0,
        first.summary().module_bijection().1
    );
    assert_eq!(
        first.summary().relationship_bijection().0,
        first.summary().relationship_bijection().1
    );
    assert_eq!(first.summary().broken_or_stale_links(), 0);
    assert_eq!(first.summary().structural_markdown_violations(), 0);
    assert_eq!(first.summary().unexpected_docs_files(), 0);
    assert_eq!(first.summary().missing_canonical_docs(), 0);
    println!(
        "{}",
        first
            .to_json_pretty()
            .expect("documentation report serializes")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R09-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn fortress_physical_tree_satisfies_recursive_module_grammar() {
    let root = repository_root();
    let policy = ObservationPolicy::new([".git"]).expect("self exclusion validates");
    let observation = observe_repository(&root, &policy).expect("repository observes");
    let paths: Vec<String> = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let findings = evaluate_module_grammar(&paths, "1.0.0-draft.1")
        .expect("recursive grammar evaluation completes");
    assert!(findings.is_empty(), "grammar findings: {findings:#?}");
}
