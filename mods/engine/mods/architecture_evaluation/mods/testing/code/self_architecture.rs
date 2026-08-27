//! Parent-local verification of Fortress's resolved self-architecture.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::architecture::ArchitectureManifest;
use fortress_core::module_contract::{ContractStandardIndex, resolve_contracts};
use fortress_core::observation::{ObservationPolicy, observe_repository};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-ARCHITECTURE-EVALUATION-0001-R02-001`
/// Fortress requirement: AF-ARCHITECTURE-EVALUATION-0001-R02
#[test]
fn declared_self_architecture_is_acyclic() {
    let root = repository_root();
    let policy = ObservationPolicy::new([".git"]).expect("policy validates");
    let observation = observe_repository(&root, &policy).expect("repository observes");
    let files = observation
        .files()
        .iter()
        .map(|file| {
            (
                file.path().to_owned(),
                fs::read(root.join(file.path())).expect("observed file reads"),
            )
        })
        .collect();
    let resolution = resolve_contracts(
        &files,
        &ContractStandardIndex::new(
            "STD-FORTRESS-ENGINEERING",
            "1.0.0-draft.1",
            [
                "ARCH-DEPENDENCY-001",
                "ARCH-OWNERSHIP-001",
                "CONTRACT-COHERENCY-001",
                "REPO-DOCS-001",
                "REPO-MODULE-001",
                "STD-ID-001",
                "TEST-BOUNDARY-001",
                "TEST-TRACEABILITY-001",
            ],
        ),
        None,
    );
    let paths = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect::<Vec<_>>();
    let resolved = resolution
        .resolved()
        .unwrap_or_else(|| panic!("self contracts resolve: {:#?}", resolution.violations()));
    let architecture = ArchitectureManifest::from_resolved_contracts(resolved, &paths);
    assert!(
        architecture
            .evaluate_acyclic_dependencies("1.0.0-draft.1")
            .expect("finding normalization must succeed")
            .is_none()
    );
}
