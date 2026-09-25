//! Positive, negative, boundary, determinism, and self-application evidence for
//! universal repository file observation.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::observation::{
    CandidateChangeSet, ChangeOperation, KnowledgeState, ObservationError, ObservationPolicy,
    ObservedFile, SourceView, observe_repository, observe_source_manifest,
};
use serde::Deserialize;

/// Returns the repository root used by integration fixtures.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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
        .join("../repository_observation/testing/_data/observation_cases.json");
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
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R01
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
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R01
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
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R01
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
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R02
#[test]
fn fortress_observes_itself_without_transient_roots() {
    let policy =
        ObservationPolicy::new([".git", "target"]).expect("self-observation exclusions are valid");
    let observation =
        observe_repository(repository_root(), &policy).expect("Fortress self-observation succeeds");
    let paths: Vec<&str> = observation.files().iter().map(ObservedFile::path).collect();

    assert!(paths.contains(&"_data/Cargo.toml"));
    assert!(paths.contains(&"__fortress/.fsconfig"));
    assert!(paths.windows(2).all(|window| window[0] < window[1]));
    assert!(
        paths
            .iter()
            .all(|path| !path.starts_with(".git/") && !path.starts_with("target/"))
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-004`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R02
#[test]
fn active_control_configuration_remains_observed_when_git_ignored_and_untracked() {
    let fixture = ObservationFixture::empty();
    fs::create_dir_all(fixture.root.join("__fortress")).expect("control root creates");
    fs::write(fixture.root.join(".gitignore"), "__fortress/\n").expect("ignore file writes");
    fs::write(
        fixture.root.join("__fortress/.fsconfig"),
        r#"{"$schema":"urn:fortress:schema:v4:project-configuration","schema_version":4}"#,
    )
    .expect("untracked configuration writes");
    let policy = ObservationPolicy::new([".git"]).expect("policy");
    let observation = observe_repository(&fixture.root, &policy).expect("observation");
    assert!(
        observation
            .files()
            .iter()
            .any(|file| file.path() == "__fortress/.fsconfig")
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-001`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R02
#[test]
fn exclusion_policy_rejects_parent_traversal() {
    let result = ObservationPolicy::new(["../outside"]);
    assert!(matches!(
        result,
        Err(ObservationError::InvalidExcludedPrefix(_))
    ));
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-002`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R02
#[test]
fn exclusion_policy_is_sorted_and_deduplicated() {
    let policy = ObservationPolicy::new(["target", ".git", "target"])
        .expect("canonical exclusions are valid");
    assert_eq!(policy.excluded_prefixes(), [".git", "target"]);
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-001`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn source_manifest_reports_exclusions_and_nonregular_barriers() {
    let fixture = ObservationFixture::empty();
    fs::write(fixture.root.join("plain.rs"), "pub fn run() {}").unwrap();
    fs::create_dir(fixture.root.join(".git")).unwrap();
    fs::write(fixture.root.join(".git/config"), "private").unwrap();
    let manifest = observe_source_manifest(&fixture.root, &ObservationPolicy::default()).unwrap();
    assert_eq!(manifest.entries().len(), 1);
    assert_eq!(manifest.entries()[0].repository_relative_path(), "plain.rs");
    assert!(
        manifest
            .exclusions()
            .iter()
            .any(|item| item.selector() == ".git")
    );
    assert_eq!(
        manifest.entries_digest(),
        observe_source_manifest(&fixture.root, &ObservationPolicy::default())
            .unwrap()
            .entries_digest()
    );
    let policy = ObservationPolicy::new([".git"]).unwrap();
    let direct = observe_source_manifest(&fixture.root, &policy).unwrap();
    let observed = observe_repository(&fixture.root, &policy).unwrap();
    let reused =
        fortress_core::observation::SourceManifest::from_observation(&observed, &policy).unwrap();
    assert_eq!(direct, reused);
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-002`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn candidate_change_set_checks_exact_base_and_keeps_unsaved_view_separate() {
    let base = SourceView::from_bytes([("src/lib.rs", b"pub fn old() {}".to_vec())]).unwrap();
    let candidate = CandidateChangeSet::new(
        &base,
        "sha256:context",
        "sha256:authority",
        [ChangeOperation::Replace {
            path: "src/lib.rs".into(),
            base_bytes: b"pub fn old() {}".to_vec(),
            candidate_bytes: b"pub fn new() {}".to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(
        base.bytes("src/lib.rs"),
        Some(b"pub fn old() {}".as_slice())
    );
    assert_eq!(
        candidate.view().bytes("src/lib.rs"),
        Some(b"pub fn new() {}".as_slice())
    );
    assert_ne!(candidate.view().digest(), base.digest());
    let changed_context = CandidateChangeSet::new(
        &base,
        "sha256:other-context",
        "sha256:authority",
        [ChangeOperation::Replace {
            path: "src/lib.rs".into(),
            base_bytes: b"pub fn old() {}".to_vec(),
            candidate_bytes: b"pub fn new() {}".to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(candidate.view().digest(), changed_context.view().digest());
    assert_ne!(candidate.digest(), changed_context.digest());
    assert!(
        CandidateChangeSet::new(
            &base,
            "sha256:context",
            "sha256:authority",
            [ChangeOperation::Delete {
                path: "src/lib.rs".into(),
                base_bytes: b"wrong".to_vec()
            }]
        )
        .is_err()
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-003`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn symlink_escape_cycle_and_reparse_are_bounded() {
    let fixture = ObservationFixture::empty();
    let outside = ObservationFixture::empty();
    fs::write(outside.root.join("secret.rs"), "secret").unwrap();
    #[cfg(windows)]
    {
        let create_junction = |name: &str, target: &Path| {
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(fixture.root.join(name))
                .arg(target)
                .status()
                .expect("Windows junction fixture command starts");
            assert!(status.success(), "Windows junction fixture creates");
        };
        create_junction("escape_dir", &outside.root);
        create_junction("cycle_dir", &fixture.root);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.root.join("secret.rs"),
            fixture.root.join("escape.rs"),
        )
        .unwrap();
        std::os::unix::fs::symlink("cycle.rs", fixture.root.join("cycle.rs")).unwrap();
        std::os::unix::fs::symlink(&fixture.root, fixture.root.join("directory_link")).unwrap();
    }
    let manifest = observe_source_manifest(&fixture.root, &ObservationPolicy::default()).unwrap();
    #[cfg(windows)]
    assert_eq!(manifest.entries().len(), 2);
    #[cfg(unix)]
    assert_eq!(manifest.entries().len(), 3);
    assert!(
        manifest
            .entries()
            .iter()
            .all(|entry| entry.limitation_ref().is_some())
    );
    assert!(
        !manifest
            .entries()
            .iter()
            .any(|entry| entry.repository_relative_path().contains("secret"))
    );
    assert!(matches!(
        observe_repository(&fixture.root, &ObservationPolicy::default()),
        Err(ObservationError::UnsupportedEntry(_))
    ));
    #[cfg(windows)]
    {
        fs::remove_dir(fixture.root.join("escape_dir"))
            .expect("escape junction removes without target traversal");
        fs::remove_dir(fixture.root.join("cycle_dir"))
            .expect("cycle junction removes without traversal");
        assert!(outside.root.join("secret.rs").exists());
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-004`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn source_manifest_writer_matches_registered_schema() {
    let fixture = ObservationFixture::empty();
    fs::write(fixture.root.join("source.rs"), "pub fn run() {}").unwrap();
    let manifest = observe_source_manifest(&fixture.root, &ObservationPolicy::default()).unwrap();
    let instance: serde_json::Value = serde_json::from_str(&manifest.to_canonical_json()).unwrap();
    let schema_path = repository_root()
        .join("engine/repository_observation/_data/source_manifest_schema_v1.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    jsonschema::draft202012::validate(&schema, &instance).expect("source manifest v1 validates");
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-005`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn candidate_operations_are_ordered_and_conflict_checked() {
    let base = SourceView::from_bytes([("src/old.rs", b"old".to_vec())]).unwrap();
    let moved = CandidateChangeSet::new(
        &base,
        "sha256:context",
        "sha256:authority",
        [ChangeOperation::Move {
            source: "src/old.rs".into(),
            destination: "src/new.rs".into(),
            base_bytes: b"old".to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(moved.view().bytes("src/old.rs"), None);
    assert_eq!(moved.view().bytes("src/new.rs"), Some(b"old".as_slice()));
    assert!(
        CandidateChangeSet::new(
            &base,
            "sha256:context",
            "sha256:authority",
            [
                ChangeOperation::Delete {
                    path: "src/old.rs".into(),
                    base_bytes: b"old".to_vec()
                },
                ChangeOperation::Create {
                    path: "src/old.rs".into(),
                    candidate_bytes: b"new".to_vec()
                },
            ]
        )
        .is_err()
    );
    assert!(SourceView::from_bytes([("C:/outside", b"bad".to_vec())]).is_err());
    assert!(SourceView::from_bytes([(".git/config", b"bad".to_vec())]).is_err());
}
