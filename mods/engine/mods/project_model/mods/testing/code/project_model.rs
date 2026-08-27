//! Positive, negative, and boundary implementation evidence for project loading.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::project::{ProjectLoadError, ProjectManifest, ProjectModelError};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mods/project_model/mods/testing/data")
}

fn load(relative_path: &str) -> Result<ProjectManifest, ProjectLoadError> {
    let path = fixture_root().join(relative_path);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    ProjectManifest::from_json_str(&source)
}

/// `T-AF-PROJECT-MODEL-0001-R02-001`
#[test]
fn valid_declared_project_loads() {
    let project = load("project_valid.json").expect("positive fixture must load");
    assert_eq!(project.id(), "PF-FORTRESS");
    assert_eq!(project.archetypes(), ["package.library", "package.cli"]);
}

/// `T-AF-PROJECT-MODEL-0001-R02-002`
#[test]
fn duplicate_language_is_rejected() {
    let error = load("project_invalid.json").expect_err("negative fixture must fail");
    assert!(matches!(
        error,
        ProjectLoadError::Model(ProjectModelError::DuplicateValue { .. })
    ));
}

/// `T-AF-PROJECT-MODEL-0001-R02-003`
#[test]
fn parent_traversal_path_is_rejected() {
    let error = load("path_boundary.json").expect_err("boundary fixture must fail");
    assert!(matches!(
        error,
        ProjectLoadError::Model(ProjectModelError::InvalidRelativePath { .. })
    ));
}
