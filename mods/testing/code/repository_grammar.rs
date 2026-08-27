//! Direct whole-repository evidence for the canonical recursive Module grammar.

use std::path::{Path, PathBuf};

use fortress_core::observation::{ObservationPolicy, observe_repository};
use fortress_core::placement::evaluate_module_grammar;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R09-003`
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
