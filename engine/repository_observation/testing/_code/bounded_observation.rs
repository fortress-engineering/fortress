//! Preallocation quotas over the unchanged universal observation facts.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::observation::{
    ObservationError, ObservationLimits, ObservationPolicy, observe_repository,
    observe_repository_bounded,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fortress-bounded-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("fixture");
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn limits() -> ObservationLimits {
    ObservationLimits {
        max_files: 16,
        max_entries: 64,
        max_source_bytes: 4096,
        max_path_bytes: 8192,
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R04-001`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R04
#[test]
fn successful_bounded_observation_preserves_exact_content_facts() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("src")).expect("source directory");
    fs::create_dir_all(fixture.0.join("hidden")).expect("excluded directory");
    fs::write(fixture.0.join("Cargo.toml"), b"abcd").expect("source");
    fs::write(fixture.0.join("src/lib.rs"), b"xyz").expect("source");
    fs::write(fixture.0.join("hidden/large"), vec![0; 8192]).expect("excluded bytes");
    let policy = ObservationPolicy::new(["hidden"]).expect("policy");
    let mut bounded = limits();
    bounded.max_source_bytes = 7;
    bounded.max_files = 2;
    let observed = observe_repository_bounded(&fixture.0, &policy, &bounded)
        .expect("exact byte/file boundary");
    let ordinary = observe_repository(&fixture.0, &policy).expect("ordinary producer");
    assert_eq!(observed, ordinary);
    assert_eq!(
        observed.to_json_pretty().unwrap(),
        ordinary.to_json_pretty().unwrap()
    );
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R04-002`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R04
#[test]
fn file_and_byte_quotas_refuse_a_partial_observation() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("a.rs"), b"abcd").expect("source");
    fs::write(fixture.0.join("b.rs"), b"xyz").expect("source");
    let policy = ObservationPolicy::default();
    let mut bounded = limits();
    bounded.max_source_bytes = 6;
    assert!(matches!(
        observe_repository_bounded(&fixture.0, &policy, &bounded),
        Err(ObservationError::ResourceLimit { .. })
    ));
    bounded.max_source_bytes = 7;
    bounded.max_files = 1;
    assert!(matches!(
        observe_repository_bounded(&fixture.0, &policy, &bounded),
        Err(ObservationError::ResourceLimit { .. })
    ));
    assert_eq!(fs::read(fixture.0.join("a.rs")).unwrap(), b"abcd");
    assert_eq!(fs::read(fixture.0.join("b.rs")).unwrap(), b"xyz");
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R04-003`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R04
#[test]
fn empty_directories_and_path_metadata_cannot_evade_admission() {
    let fixture = Fixture::new();
    for index in 0..12 {
        fs::create_dir_all(fixture.0.join(format!("empty-{index}"))).expect("empty directory");
    }
    let policy = ObservationPolicy::default();
    let mut bounded = limits();
    bounded.max_entries = 4;
    assert!(matches!(
        observe_repository_bounded(&fixture.0, &policy, &bounded),
        Err(ObservationError::ResourceLimit { .. })
    ));
    bounded.max_entries = 64;
    bounded.max_path_bytes = 1;
    assert!(matches!(
        observe_repository_bounded(&fixture.0, &policy, &bounded),
        Err(ObservationError::ResourceLimit { .. })
    ));
    bounded.max_path_bytes = 8192;
    assert_eq!(
        observe_repository_bounded(&fixture.0, &policy, &bounded)
            .unwrap()
            .files()
            .len(),
        0
    );
}
