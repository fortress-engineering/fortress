//! Conformance evidence for snapshot-bound Rust implementation observation.

use std::collections::BTreeMap;

use fortress_core::implementation_observation::{
    ImplementationObservationError, ImplementationObservationInput, ModuleTerritory,
    ResolutionStatus, SnapshotBoundFile, TargetClassification, observe_rust_implementation,
};
use sha2::{Digest, Sha256};

fn snapshot_input(
    files: impl IntoIterator<Item = (&'static str, &'static str)>,
    modules: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> ImplementationObservationInput {
    ImplementationObservationInput::new(
        "sha256:fixture",
        files
            .into_iter()
            .map(|(path, source)| SnapshotBoundFile::from_bytes(path, source.as_bytes()))
            .collect(),
        modules
            .into_iter()
            .map(|(id, path)| ModuleTerritory::new(id, path))
            .collect(),
    )
}

fn basic_cross_package_input() -> ImplementationObservationInput {
    snapshot_input(
        [
            (
                "mods/provider/data/Cargo.toml",
                "[package]\nname = \"provider\"\nversion = \"0.1.0\"\n[lib]\npath = \"../code/lib.rs\"\n",
            ),
            (
                "mods/provider/code/lib.rs",
                "pub struct Value;\npub fn value() -> Value { Value }\n",
            ),
            (
                "mods/consumer/data/Cargo.toml",
                "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[lib]\npath = \"../code/lib.rs\"\n[dependencies]\nprovider = { path = \"../../provider/data\" }\n",
            ),
            (
                "mods/consumer/code/lib.rs",
                "use provider::Value;\npub fn consume(_: Value) {}\n",
            ),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-PROVIDER-0001", "mods/provider"),
            ("AF-CONSUMER-0001", "mods/consumer"),
        ],
    )
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R01-001`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R01
#[test]
fn repeated_snapshot_analysis_is_byte_fact_deterministic() {
    let input = basic_cross_package_input();
    let first = observe_rust_implementation(&input).expect("fixture observes");
    let second = observe_rust_implementation(&input).expect("fixture repeats");
    assert_eq!(first, second);
    assert_eq!(first.snapshot_fingerprint(), "sha256:fixture");
    assert_eq!(first.analyzer_version(), "1.0.0");
    assert_eq!(first.module_dependencies().len(), 1);
    let edge = &first.module_dependencies()[0];
    assert_eq!(edge.source_module(), "AF-CONSUMER-0001");
    assert_eq!(edge.target_module(), "AF-PROVIDER-0001");
    assert!(!edge.evidence().is_empty());
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R01-002`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R01
#[test]
fn snapshot_byte_mutation_is_rejected_before_parsing() {
    let original = b"pub fn stable() {}";
    let expected = format!("sha256:{:x}", Sha256::digest(original));
    let input = ImplementationObservationInput::new(
        "sha256:fixture",
        vec![SnapshotBoundFile::new(
            "code/lib.rs",
            u64::try_from(original.len()).expect("length fits"),
            expected,
            b"pub fn changed() {}".to_vec(),
        )],
        vec![ModuleTerritory::new("PF-FIXTURE", "")],
    );
    assert!(matches!(
        observe_rust_implementation(&input),
        Err(ImplementationObservationError::SnapshotIdentityMismatch(path))
            if path.as_ref() == "code/lib.rs"
    ));
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R02-001`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R02
#[test]
fn structural_rust_paths_resolve_same_crate_modules_and_external_targets() {
    let input = snapshot_input(
        [
            (
                "mods/engine/data/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\n[lib]\npath = \"../code/lib.rs\"\n[dependencies]\nserde = \"1\"\n",
            ),
            (
                "mods/engine/code/lib.rs",
                "#[path = \"../mods/alpha/code/alpha.rs\"]\npub mod alpha;\n#[path = \"../mods/beta/code/beta.rs\"]\npub mod beta;\n",
            ),
            (
                "mods/engine/mods/alpha/code/alpha.rs",
                "use crate::beta::Thing;\nuse super::beta::Thing as Other;\nuse serde::Serialize;\nuse crate::mystery::unknown;\n#[path = \"local.rs\"]\nmod local;\npub fn run(_: Thing, _: Other) {}\n",
            ),
            (
                "mods/engine/mods/alpha/code/local.rs",
                "use self::Local as Alias;\npub struct Local;\npub fn local(_: Alias) {}\n",
            ),
            ("mods/engine/mods/beta/code/beta.rs", "pub struct Thing;\n"),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-ENGINE-0001", "mods/engine"),
            ("AF-ALPHA-0001", "mods/engine/mods/alpha"),
            ("AF-BETA-0001", "mods/engine/mods/beta"),
        ],
    );
    let result = observe_rust_implementation(&input).expect("structural fixture observes");
    let edges: Vec<_> = result
        .module_dependencies()
        .iter()
        .map(|edge| (edge.source_module(), edge.target_module()))
        .collect();
    assert!(edges.contains(&("AF-ENGINE-0001", "AF-ALPHA-0001")));
    assert!(edges.contains(&("AF-ENGINE-0001", "AF-BETA-0001")));
    assert!(edges.contains(&("AF-ALPHA-0001", "AF-BETA-0001")));
    assert!(result.observations().iter().any(|observation| {
        observation.target_classification() == TargetClassification::ExternalDependency
            && observation.external_target() == Some("serde")
    }));
    assert!(result.observations().iter().any(|observation| {
        observation.resolution_status() == ResolutionStatus::Unresolved
            && observation.provenance().reference() == "crate::mystery::unknown"
    }));
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R02-002`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R02
#[test]
fn workspace_facades_testing_ownership_and_edge_evidence_are_preserved() {
    let input = snapshot_input(
        [
            (
                "mods/engine/data/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nautotests = false\n[lib]\npath = \"../code/lib.rs\"\n[[test]]\nname = \"engine_test\"\npath = \"../mods/testing/code/engine_test.rs\"\n",
            ),
            (
                "mods/engine/code/lib.rs",
                "#[path = \"../mods/child/code/child.rs\"]\npub mod child;\n",
            ),
            (
                "mods/engine/mods/child/code/child.rs",
                "pub struct Surface;\n",
            ),
            (
                "mods/engine/mods/testing/code/engine_test.rs",
                "use engine::child::Surface;\nfn proof(_: Surface) {}\n",
            ),
            (
                "mods/cli/data/Cargo.toml",
                "[package]\nname = \"cli\"\nversion = \"0.1.0\"\n[lib]\npath = \"../code/lib.rs\"\n[dependencies]\nengine = { path = \"../../engine/data\" }\n",
            ),
            (
                "mods/cli/code/lib.rs",
                "use engine::child::Surface;\nuse engine::child::Surface as Again;\npub fn run(_: Surface, _: Again) {}\n",
            ),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-ENGINE-0001", "mods/engine"),
            ("AF-CHILD-0001", "mods/engine/mods/child"),
            ("TEST-ENGINE-0001", "mods/engine/mods/testing"),
            ("TF-CLI-0001", "mods/cli"),
        ],
    );
    let result = observe_rust_implementation(&input).expect("facade fixture observes");
    let edges: BTreeMap<_, _> = result
        .module_dependencies()
        .iter()
        .map(|edge| {
            (
                (edge.source_module(), edge.target_module()),
                edge.evidence().len(),
            )
        })
        .collect();
    assert!(edges.contains_key(&("TEST-ENGINE-0001", "AF-ENGINE-0001")));
    assert!(!edges.contains_key(&("TEST-ENGINE-0001", "AF-CHILD-0001")));
    assert!(edges.contains_key(&("TF-CLI-0001", "AF-ENGINE-0001")));
    assert!(!edges.contains_key(&("TF-CLI-0001", "AF-CHILD-0001")));
    assert!(edges[&("TF-CLI-0001", "AF-ENGINE-0001")] >= 2);
}
