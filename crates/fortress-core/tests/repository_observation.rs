//! Positive, negative, boundary, determinism, and self-application evidence for
//! universal repository file observation.

use std::path::{Path, PathBuf};

use fortress_core::observation::{
    KnowledgeState, ObservationPolicy, ObservedFile, observe_repository,
};

/// Returns the repository root used by integration fixtures.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Returns one repository-observation fixture root.
fn fixture(name: &str) -> PathBuf {
    repository_root()
        .join("tests/fixtures/repository-observation")
        .join(name)
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R01-001`
#[test]
fn observation_emits_sorted_relative_content_facts() {
    let policy = ObservationPolicy::new(["excluded"]).expect("fixture exclusion is valid");
    let observation = observe_repository(fixture("positive"), &policy)
        .expect("positive fixture observation must succeed");

    assert_eq!(observation.schema_version(), 1);
    assert_eq!(observation.knowledge_state(), KnowledgeState::Observed);
    assert_eq!(observation.files().len(), 2);
    assert_eq!(observation.files()[0].path(), "alpha.txt");
    assert_eq!(observation.files()[0].size(), 6);
    assert_eq!(observation.files()[1].path(), "nested/beta.txt");
    assert_eq!(observation.files()[1].size(), 5);
    assert!(
        observation
            .files()
            .iter()
            .all(|file| file.sha256().starts_with("sha256:") && file.sha256().len() == 71)
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R01-002`
#[test]
fn repeated_observation_and_json_are_deterministic() {
    let policy = ObservationPolicy::new(["excluded"]).expect("fixture exclusion is valid");
    let first =
        observe_repository(fixture("positive"), &policy).expect("first observation succeeds");
    let second =
        observe_repository(fixture("positive"), &policy).expect("second observation succeeds");

    assert_eq!(first, second);
    assert_eq!(
        first.to_json_pretty().expect("JSON serialization succeeds"),
        second
            .to_json_pretty()
            .expect("JSON serialization succeeds")
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R01-003`
#[test]
fn fully_excluded_boundary_produces_empty_observed_inventory() {
    let policy = ObservationPolicy::new(["ignored.txt"]).expect("fixture exclusion is valid");
    let observation = observe_repository(fixture("boundary-only-excluded"), &policy)
        .expect("fully excluded observation succeeds");
    assert!(observation.files().is_empty());
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-003`
#[test]
fn fortress_observes_itself_without_transient_roots() {
    let policy = ObservationPolicy::new([".git", ".fortress/state", "target"])
        .expect("self-observation exclusions are valid");
    let observation =
        observe_repository(repository_root(), &policy).expect("Fortress self-observation succeeds");
    let paths: Vec<&str> = observation.files().iter().map(ObservedFile::path).collect();

    assert!(paths.contains(&"Cargo.toml"));
    assert!(paths.contains(&".fortress/project.json"));
    assert!(paths.windows(2).all(|window| window[0] < window[1]));
    assert!(
        paths
            .iter()
            .all(|path| !path.starts_with(".git/") && !path.starts_with("target/"))
    );
}
