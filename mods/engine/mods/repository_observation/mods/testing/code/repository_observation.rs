//! Positive, negative, boundary, determinism, and self-application evidence for
//! universal repository file observation.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::observation::{
    KnowledgeState, ObservationPolicy, ObservedFile, observe_repository,
};
use serde::Deserialize;

/// Returns the repository root used by integration fixtures.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct ObservationFixture {
    root: PathBuf,
}

#[derive(Deserialize)]
struct ObservationCase {
    exclusions: Vec<String>,
    files: Vec<FixtureFile>,
}

#[derive(Deserialize)]
struct FixtureFile {
    path: String,
    content: String,
}

impl ObservationFixture {
    fn from_case(case: &ObservationCase) -> Self {
        let fixture = Self::empty();
        for file in &case.files {
            let path = fixture.root.join(&file.path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent creates");
            }
            fs::write(path, &file.content).expect("fixture file writes");
        }
        fixture
    }

    fn empty() -> Self {
        let identity = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-observation-{}-{identity}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture root creates");
        Self { root }
    }
}

fn load_case(name: &str) -> ObservationCase {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mods/repository_observation/mods/testing/data/observation_cases.json");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&source).expect("cases JSON loads");
    serde_json::from_value(document[name].clone()).expect("named observation case loads")
}

impl Drop for ObservationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R01-001`
#[test]
fn observation_emits_sorted_relative_content_facts() {
    let case = load_case("positive");
    let policy =
        ObservationPolicy::new(case.exclusions.clone()).expect("fixture exclusion is valid");
    let fixture = ObservationFixture::from_case(&case);
    let observation = observe_repository(&fixture.root, &policy)
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
    let case = load_case("positive");
    let policy =
        ObservationPolicy::new(case.exclusions.clone()).expect("fixture exclusion is valid");
    let fixture = ObservationFixture::from_case(&case);
    let first = observe_repository(&fixture.root, &policy).expect("first observation succeeds");
    let second = observe_repository(&fixture.root, &policy).expect("second observation succeeds");

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
    let case = load_case("boundary");
    let policy =
        ObservationPolicy::new(case.exclusions.clone()).expect("fixture exclusion is valid");
    let fixture = ObservationFixture::from_case(&case);
    let observation =
        observe_repository(&fixture.root, &policy).expect("fully excluded observation succeeds");
    assert!(observation.files().is_empty());
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-003`
#[test]
fn fortress_observes_itself_without_transient_roots() {
    let policy = ObservationPolicy::new([".git"]).expect("self-observation exclusions are valid");
    let observation =
        observe_repository(repository_root(), &policy).expect("Fortress self-observation succeeds");
    let paths: Vec<&str> = observation.files().iter().map(ObservedFile::path).collect();

    assert!(paths.contains(&"data/Cargo.toml"));
    assert!(paths.contains(&"data/project.json"));
    assert!(paths.windows(2).all(|window| window[0] < window[1]));
    assert!(
        paths
            .iter()
            .all(|path| !path.starts_with(".git/") && !path.starts_with("target/"))
    );
}
