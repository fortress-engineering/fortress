//! Immutable resident generations and coordinator lifecycle controls.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
};
use fortress_core::observation::ChangeOperation;
use fortress_core::runtime_storage::StoragePolicy;
use fortress_core::session::{
    Generation, Session, SessionErrorKind, SessionLimits, SessionOptions, SessionStage, SourceDelta,
};

#[path = "resident_comparison.rs"]
mod resident_comparison;

use resident_comparison::{ComparisonSnapshot, MAX_COMPARISON_SCRATCH_BYTES, checked_scratch_sum};

static NEXT: AtomicU64 = AtomicU64::new(0);
const COMPARISON_HISTORY: &str = r#"{"$schema":"urn:fortress:derived:v1:assessment-selection-index","schema_version":1,"selections":[]}"#;

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    storage: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "fortress-resident-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root = base.join("repository");
        let storage = base.join("storage");
        fs::create_dir_all(root.join("src")).expect("source");
        fs::create_dir_all(&storage).expect("storage");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"resident_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), Self::source(1)).expect("source");
        let proposal = discover_repository_bootstrap(
            &root,
            &BootstrapDiscoveryOptions::new(
                Some("PF-RESIDENT-FIXTURE".into()),
                Some("Resident Fixture".into()),
            ),
        )
        .expect("proposal");
        apply_repository_bootstrap(&root, &proposal, false).expect("fixture authority");
        Self {
            base,
            root,
            storage,
        }
    }

    fn source(value: u32) -> String {
        format!(
            "pub fn changed() -> u32 {{\n    {value}\n}}\npub fn stable() -> u32 {{\n    9\n}}\n"
        )
    }

    fn options() -> SessionOptions {
        SessionOptions {
            storage_policy: StoragePolicy {
                reserve_bytes: 0,
                retain_shared_compiler: false,
                ..StoragePolicy::default()
            },
            ..SessionOptions::default()
        }
    }

    fn open(&self) -> Session {
        Session::open(&self.root, &self.storage, Self::options()).expect("session")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn concurrent_readers_keep_their_exact_immutable_generation() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    let prior_artifacts = prior.canonical_artifacts().clone();
    let reader = std::thread::spawn({
        let prior = prior.clone();
        move || prior.canonical_artifacts().clone()
    });
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(2)).expect("mutation");
    let refreshed = session.refresh(&SourceDelta::default()).expect("refresh");
    assert_ne!(
        prior.input_revision(),
        refreshed.generation.input_revision()
    );
    assert_eq!(reader.join().expect("reader"), prior_artifacts);
    assert_eq!(prior.canonical_artifacts(), &prior_artifacts);
    assert_eq!(refreshed.generation.canonical_artifacts().len(), 11);
    for phase in ["session_dependency_index", "session_generation_assembly"] {
        assert_eq!(
            refreshed
                .work
                .phase_measurements
                .iter()
                .filter(|measurement| measurement.phase == phase)
                .count(),
            1
        );
    }
    session.close().expect("close");
    assert_eq!(prior.canonical_artifacts(), &prior_artifacts);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn missed_watcher_change_is_never_returned_as_current() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(3)).expect("mutation");
    assert_eq!(
        session.acquire_generation().expect_err("stale").kind(),
        SessionErrorKind::StaleBase
    );
    assert_eq!(
        session
            .refresh(&SourceDelta::for_base("sha256:wrong"))
            .expect_err("wrong base")
            .kind(),
        SessionErrorKind::StaleBase
    );
    let update = session
        .refresh(&SourceDelta::default())
        .expect("unannounced refresh");
    assert_ne!(update.generation.input_revision(), prior.input_revision());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn cancellation_and_cache_eviction_preserve_prior_subject() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    session.cancel();
    assert_eq!(
        session
            .refresh(&SourceDelta::default())
            .expect_err("cancelled")
            .kind(),
        SessionErrorKind::Cancelled
    );
    assert_eq!(
        session
            .acquire_generation()
            .expect("current")
            .input_revision(),
        prior.input_revision()
    );
    let artifacts = prior.canonical_artifacts().clone();
    session.evict_preparation().expect("evict preparation");
    let cold = session
        .refresh(&SourceDelta::default())
        .expect("evicted preparation");
    assert_eq!(cold.generation.canonical_artifacts(), &artifacts);
    assert_eq!(prior.canonical_artifacts(), &artifacts);
    let phases = cold
        .work
        .phase_measurements
        .iter()
        .map(|measurement| measurement.phase)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(phases.len(), cold.work.phase_measurements.len());
    for required in [
        "source_preparation",
        "audit_inputs",
        "implementation_observation",
        "program_semantics",
        "function_contracts",
        "semantic_domains",
        "state_effects",
        "information_flow",
        "environmental_semantics",
        "preparation_accounting",
        "governance_composition",
        "dependency_snapshot",
        "canonical_serialization",
    ] {
        assert!(
            phases.contains(required),
            "missing measured phase: {required}"
        );
    }
    let measured = session
        .refresh(&SourceDelta::default())
        .expect("measured refresh");
    assert_eq!(measured.generation.canonical_artifacts(), &artifacts);
    assert_eq!(measured.generation.context_digest(), prior.context_digest());
    assert_eq!(
        measured.generation.authority_digest(),
        prior.authority_digest()
    );
    assert_eq!(
        cold.work.preparation_bytes_before_eviction,
        cold.work
            .preparation_bytes_by_owner
            .iter()
            .copied()
            .fold(0, usize::saturating_add)
    );
    assert!(cold.work.preparation_units_before_eviction >= cold.work.prepared_units);
    let partial_limit = cold.work.preparation_bytes_by_owner[1]
        .checked_add(cold.work.preparation_bytes_by_owner[2])
        .expect("bounded fixture charges");
    assert!(cold.work.preparation_bytes_by_owner[0] > partial_limit);
    let cold_admission = cold.work.parser_admission_bytes_added;
    session.close().expect("close complete preparation");
    drop(measured);
    drop(cold);
    drop(prior);
    check_partial_owner_retention(&fixture, partial_limit, &artifacts);
    check_partial_program_demand_learning(&fixture, partial_limit, cold_admission);
}

fn check_partial_program_demand_learning(
    fixture: &Fixture,
    partial_limit: usize,
    cold_admission: usize,
) {
    let mut options = Fixture::options();
    options.limits.max_preparation_bytes = partial_limit;
    options.limits.max_parser_bytes = cold_admission * 2 + cold_admission / 2;
    let mut session = Session::open(&fixture.root, &fixture.storage, options)
        .expect("partial preparation demand session");
    let base = session.acquire_generation().expect("actual base");
    let mixed = session
        .evaluate_delta(
            "partial-demand",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: Fixture::source(1).into_bytes(),
                candidate_bytes: Fixture::source(2).into_bytes(),
            }],
        )
        .expect("unseen candidate completes with cold program and retained peers");
    assert!(!mixed.work.parser_epoch_rotated);
    assert_eq!(mixed.work.program.reused_bodies, 0);
    assert!(mixed.work.program.analyzed_bodies > 0);
    assert!(mixed.work.semantic.reused_domain_rounds > 0);
    assert!(mixed.work.state_effect.reused_direct_units > 0);
    assert!(mixed.work.prepared_units > 0);
    let view = mixed.generation.source_view().clone();
    let expected = mixed.generation.canonical_artifacts().clone();
    session.release_candidate("partial-demand");
    drop(mixed);
    drop(base);
    let cold = session
        .evaluate_view_cold(view)
        .expect("successful cold-program demand avoids a discarded attempt");
    assert_known_cold_rotation(&cold);
    assert_eq!(cold.generation.canonical_artifacts(), &expected);
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).expect("actual source preserved"),
        Fixture::source(1).as_bytes()
    );
    session.close().expect("join partial demand epoch");
}

fn check_partial_owner_retention(
    fixture: &Fixture,
    partial_limit: usize,
    artifacts: &std::collections::BTreeMap<String, String>,
) {
    let mut partial_options = Fixture::options();
    partial_options.limits.max_preparation_bytes = partial_limit;
    let mut partial = Session::open(&fixture.root, &fixture.storage, partial_options)
        .expect("partial owner preparation is admitted");
    let mixed = partial
        .refresh(&SourceDelta::default())
        .expect("mixed owner refresh");
    assert_eq!(mixed.generation.canonical_artifacts(), artifacts);
    assert_eq!(
        mixed.disposition,
        fortress_core::session::SessionDisposition::FullReevaluationRequired
    );
    assert_eq!(mixed.work.program.reused_bodies, 0);
    assert!(mixed.work.program.analyzed_bodies > 0);
    assert!(mixed.work.semantic.reused_domain_rounds > 0);
    assert!(mixed.work.state_effect.reused_direct_units > 0);
    assert!(mixed.work.prepared_units > 0);
    assert!(mixed.work.preparation_bytes_before_eviction > partial_limit);
    assert!(
        mixed
            .reasons
            .iter()
            .any(|reason| reason == "program_preparation_evicted_for_retention_limit")
    );
    assert!(
        mixed
            .reasons
            .iter()
            .any(|reason| reason == "incomplete_owner_preparation_requires_full_fallback")
    );
    let view_reference = partial
        .evaluate_view_cold(mixed.generation.source_view().clone())
        .expect("independent cold view with mixed cache");
    assert_eq!(view_reference.generation.canonical_artifacts(), artifacts);
    assert_eq!(view_reference.work.semantic.reused_domain_rounds, 0);
    assert_eq!(view_reference.work.state_effect.reused_direct_units, 0);
    partial.evict_preparation().expect("evict every owner");
    let empty = partial
        .refresh(&SourceDelta::default())
        .expect("fully evicted refresh");
    assert_eq!(empty.generation.canonical_artifacts(), artifacts);
    assert_eq!(empty.work.program.reused_bodies, 0);
    assert_eq!(empty.work.semantic.reused_domain_rounds, 0);
    assert_eq!(empty.work.state_effect.reused_direct_units, 0);
    partial.cancel();
    assert_eq!(
        partial
            .refresh(&SourceDelta::default())
            .expect_err("cancel mixed cache")
            .kind(),
        SessionErrorKind::Cancelled
    );
    assert_eq!(
        partial
            .acquire_generation()
            .expect("prior mixed head")
            .generation_id(),
        empty.generation.generation_id()
    );
    partial.close().expect("close partial preparation");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn candidate_buffers_are_isolated_and_do_not_publish() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let base = session.acquire_generation().expect("base");
    let bytes = fs::read(fixture.root.join("src/lib.rs")).expect("preimage");
    let left = session
        .evaluate_delta(
            "left",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: bytes.clone(),
                candidate_bytes: Fixture::source(4).into_bytes(),
            }],
        )
        .expect("left");
    let right = session
        .evaluate_delta(
            "right",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: bytes.clone(),
                candidate_bytes: Fixture::source(5).into_bytes(),
            }],
        )
        .expect("right");
    assert_ne!(
        left.generation.input_revision(),
        right.generation.input_revision()
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).expect("actual bytes"),
        bytes
    );
    assert_eq!(
        session
            .acquire_generation()
            .expect("actual current")
            .input_revision(),
        base.input_revision()
    );
    assert_eq!(
        session
            .evaluate_delta("left", base.input_revision(), Vec::new())
            .expect_err("duplicate buffer")
            .kind(),
        SessionErrorKind::InvalidInput
    );
    session.release_candidate("left");
    session.release_candidate("right");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn pinned_generation_limits_survive_close_and_reopen() {
    let fixture = Fixture::new();
    let mut options = Fixture::options();
    options.limits.max_generations = 1;
    let mut session =
        Session::open(&fixture.root, &fixture.storage, options.clone()).expect("session");
    let pin = session.acquire_generation().expect("pin");
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(6)).expect("mutation");
    assert_eq!(
        session
            .refresh(&SourceDelta::default())
            .expect_err("pinned limit")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    session.close().expect("close");
    assert_eq!(
        Session::open(&fixture.root, &fixture.storage, options.clone())
            .expect_err("pin outlives close")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    drop(pin);
    Session::open(&fixture.root, &fixture.storage, options)
        .expect("released pin permits reopen")
        .close()
        .expect("close");
    comparison_snapshots_release_only_completed_candidate_models();
}

fn comparison_snapshots_release_only_completed_candidate_models() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("__fortress/evidence")).expect("retained history");
    fs::write(
        fixture.root.join("__fortress/evidence/current.json"),
        COMPARISON_HISTORY,
    )
    .expect("retained selection availability");
    let mut options = Fixture::options();
    options.limits.max_generations = 2;
    let mut session = Session::open(&fixture.root, &fixture.storage, options).expect("session");
    let actual = session.acquire_generation().expect("actual head");
    let original = fs::read(fixture.root.join("src/lib.rs")).expect("actual source");
    let warm = session
        .evaluate_delta(
            "measured",
            actual.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: original.clone(),
                candidate_bytes: Fixture::source(7).into_bytes(),
            }],
        )
        .expect("warm candidate");
    let independent_reader = Arc::clone(&warm.generation);
    let pinned_usage = session.resource_usage().expect("warm charges");
    assert_eq!(pinned_usage.1, 2);
    let snapshot = bounded_comparison_snapshot(&session, &warm.generation);
    assert!(!snapshot.matches(&actual));
    assert_eq!(snapshot.artifact_digests().len(), 11);
    assert_eq!(
        snapshot.context()["execution_evidence_present"].as_bool(),
        Some(false)
    );
    assert_actual_head(&session, &actual, &fixture, &original);

    session.release_candidate("measured");
    assert_eq!(
        session
            .resource_usage()
            .expect("returned candidate remains pinned"),
        pinned_usage
    );
    drop(warm);
    assert_eq!(
        session.resource_usage().expect("reader charge"),
        pinned_usage
    );
    assert_eq!(
        session
            .evaluate_view_cold(snapshot.source_view().clone())
            .expect_err("independent reader still prevents a third generation")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    assert_eq!(
        session.resource_usage().expect("failed cold charges"),
        pinned_usage
    );
    assert_actual_head(&session, &actual, &fixture, &original);

    drop(independent_reader);
    let released_usage = session.resource_usage().expect("released candidate charge");
    assert_eq!(released_usage.1, 1);
    assert!(released_usage.0 < pinned_usage.0);
    cold_comparisons_preserve_actual_head(&mut session, &actual, &snapshot, &fixture, &original);
    drop(snapshot);
    drop(actual);
    session.close().expect("close");
    assert_eq!(
        session.resource_usage().expect("all charges released"),
        (0, 0)
    );
}

fn bounded_comparison_snapshot(session: &Session, generation: &Generation) -> ComparisonSnapshot {
    let usage = session.resource_usage().expect("charges before snapshot");
    assert!(checked_scratch_sum([usize::MAX, 1]).is_err());
    assert_eq!(checked_scratch_sum([1, 2, 3]).expect("checked sum"), 6);
    assert_eq!(
        session
            .resource_usage()
            .expect("overflow leaves charges unchanged"),
        usage
    );
    let required = ComparisonSnapshot::required_bytes(generation).expect("checked scratch charge");
    assert!(required > 0);
    assert!(required <= MAX_COMPARISON_SCRATCH_BYTES);
    assert!(ComparisonSnapshot::capture(generation, required - 1).is_err());
    assert_eq!(
        session.resource_usage().expect("refused scratch charges"),
        usage
    );
    let snapshot = ComparisonSnapshot::capture(generation, MAX_COMPARISON_SCRATCH_BYTES)
        .expect("bounded exact comparison snapshot");
    let accounting = snapshot.accounting();
    assert_eq!(
        accounting["snapshot_accounted_bytes"].as_u64(),
        Some(u64::try_from(required).expect("representable scratch charge"))
    );
    let source_capacity = checked_scratch_sum(
        generation
            .source_view()
            .iter()
            .flat_map(|(path, bytes)| [path.capacity(), bytes.capacity()]),
    )
    .expect("checked full source backing");
    assert!(
        accounting["retained_source_allocation_charge"]
            .as_u64()
            .expect("source backing charge")
            >= u64::try_from(source_capacity).expect("representable source charge")
    );
    assert!(snapshot.matches(generation));
    assert_eq!(snapshot.source_view(), generation.source_view());
    assert_eq!(
        session
            .resource_usage()
            .expect("diagnostic scratch is separate"),
        usage
    );
    snapshot
}

fn cold_comparisons_preserve_actual_head(
    session: &mut Session,
    actual: &Arc<Generation>,
    snapshot: &ComparisonSnapshot,
    fixture: &Fixture,
    original: &[u8],
) {
    let cold_view = session
        .evaluate_view_cold(snapshot.source_view().clone())
        .expect("supplied-view cold with only actual head retained");
    assert!(snapshot.matches(&cold_view.generation));
    assert_eq!(session.resource_usage().expect("head and cold view").1, 2);
    assert_actual_head(session, actual, fixture, original);
    drop(cold_view);
    assert_eq!(session.resource_usage().expect("cold view released").1, 1);

    session
        .evict_preparation()
        .expect("same-API cold preparation eviction");
    let cold_api = session
        .evaluate_delta(
            "reference",
            actual.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: original.to_vec(),
                candidate_bytes: snapshot
                    .source_view()
                    .bytes("src/lib.rs")
                    .expect("exact candidate source")
                    .to_vec(),
            }],
        )
        .expect("identical cold candidate API");
    assert!(snapshot.matches(&cold_api.generation));
    assert_eq!(
        session.resource_usage().expect("head and cold candidate").1,
        2
    );
    assert_actual_head(session, actual, fixture, original);
    session.release_candidate("reference");
    drop(cold_api);
    assert_eq!(
        session.resource_usage().expect("cold candidate released").1,
        1
    );
}

fn assert_actual_head(
    session: &Session,
    actual: &Arc<Generation>,
    fixture: &Fixture,
    original: &[u8],
) {
    let current = session
        .acquire_generation()
        .expect("actual head remains current");
    assert!(Arc::ptr_eq(&current, actual));
    assert_eq!(current.source_view(), actual.source_view());
    assert_eq!(
        current.observed_availability(),
        actual.observed_availability()
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).expect("unchanged physical source"),
        original
    );
    assert_eq!(
        fs::read(fixture.root.join("__fortress/evidence/current.json"))
            .expect("unchanged retained history"),
        COMPARISON_HISTORY.as_bytes()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn input_limits_reject_before_source_or_evidence_changes() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.root.join("src/lib.rs")).expect("source");
    let mut options = Fixture::options();
    options.limits = SessionLimits {
        max_source_bytes: 1,
        ..SessionLimits::default()
    };
    assert_eq!(
        Session::open(&fixture.root, &fixture.storage, options)
            .expect_err("source cap")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).expect("source"),
        before
    );
    fixture.open().close().expect("failed open releases lease");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-020`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn cancellation_during_preparation_never_replaces_the_prior_head() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    let control = session.control();
    session.set_progress_observer(move |stage| {
        if stage == SessionStage::ModelsPrepared {
            control.cancel();
        }
    });
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(7)).expect("mutation");
    assert_eq!(
        session
            .refresh(&SourceDelta::default())
            .expect_err("cancelled")
            .kind(),
        SessionErrorKind::Cancelled
    );
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(1)).expect("restore exact prior");
    assert_eq!(
        session
            .acquire_generation()
            .expect("prior remains current")
            .generation_id(),
        prior.generation_id()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-021`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn mutation_during_preparation_is_detected_before_publication() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    let path = fixture.root.join("src/lib.rs");
    session.set_progress_observer(move |stage| {
        if stage == SessionStage::ModelsPrepared {
            fs::write(&path, Fixture::source(8)).expect("concurrent writer");
        }
    });
    assert_eq!(
        session
            .refresh(&SourceDelta::default())
            .expect_err("changed during preparation")
            .kind(),
        SessionErrorKind::StaleBase
    );
    fs::write(fixture.root.join("src/lib.rs"), Fixture::source(1)).expect("restore exact prior");
    assert_eq!(
        session
            .acquire_generation()
            .expect("prior remains current")
            .generation_id(),
        prior.generation_id()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-022`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn history_changes_update_availability_without_changing_semantics() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    fs::create_dir_all(fixture.root.join("__fortress/evidence")).expect("history");
    fs::write(fixture.root.join("__fortress/evidence/current.json"), r#"{"$schema":"urn:fortress:derived:v1:assessment-selection-index","schema_version":1,"selections":[]}"#).expect("selection availability");
    let update = session
        .refresh(&SourceDelta::default())
        .expect("availability refresh");
    assert_eq!(update.generation.input_revision(), prior.input_revision());
    assert_eq!(
        update.generation.canonical_artifacts(),
        prior.canonical_artifacts()
    );
    assert_eq!(
        update.availability_changes,
        ["__fortress/evidence/current.json"]
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-023`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn removing_an_exclusion_requires_a_complete_candidate_inventory() {
    let fixture = Fixture::new();
    let config_path = fixture.root.join("__fortress/.fsconfig");
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).expect("configuration"))
            .expect("configuration JSON");
    config["observation_exclusions"]
        .as_array_mut()
        .expect("exclusions")
        .push("hidden".into());
    fs::write(
        &config_path,
        serde_json::to_vec(&config).expect("configuration bytes"),
    )
    .expect("configuration");
    fs::create_dir_all(fixture.root.join("hidden")).expect("hidden");
    fs::write(fixture.root.join("hidden/extra.rs"), "pub fn hidden() {}\n")
        .expect("unobserved source");
    let mut session = fixture.open();
    let base = session.acquire_generation().expect("base");
    let prior = fs::read(&config_path).expect("preimage");
    config["observation_exclusions"]
        .as_array_mut()
        .expect("exclusions")
        .retain(|value| value != "hidden");
    let replacement = serde_json::to_vec(&config).expect("configuration bytes");
    let error = session
        .evaluate_delta(
            "revealed",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: "__fortress/.fsconfig".into(),
                base_bytes: prior,
                candidate_bytes: replacement,
            }],
        )
        .expect_err("incomplete view");
    assert_eq!(error.kind(), SessionErrorKind::FullReevaluationRequired);
    assert_eq!(
        session
            .acquire_generation()
            .expect("unchanged actual base")
            .input_revision(),
        base.input_revision()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-024`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn parser_admission_rejects_oversized_requests_without_publishing() {
    let fixture = Fixture::new();
    let mut options = Fixture::options();
    options.limits.max_parser_bytes = 1;
    assert_eq!(
        Session::open(&fixture.root, &fixture.storage, options)
            .expect_err("parser input cap")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    let mut options = Fixture::options();
    options.limits.max_accounted_bytes = 64 * 1024 * 1024 * 1024;
    let mut session =
        Session::open(&fixture.root, &fixture.storage, options).expect("parser test session");
    let prior = session.acquire_generation().expect("prior");
    let before_failed_epoch = session
        .resource_usage()
        .expect("retained preparation charge")
        .0;
    let mut files = prior.source_view().files().clone();
    files.insert(
        "src/lib.rs".into(),
        format!("pub fn huge() {{}}\n{}", " ".repeat(65 * 1024 * 1024)).into_bytes(),
    );
    let view =
        fortress_core::observation::SourceView::from_bytes(files).expect("oversized parser view");
    assert_eq!(
        session
            .evaluate_view_cold(view)
            .expect_err("parser cap")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    assert_eq!(
        session
            .acquire_generation()
            .expect("prior still current")
            .generation_id(),
        prior.generation_id()
    );
    assert!(
        session
            .resource_usage()
            .expect("joined prior cache released")
            .0
            < before_failed_epoch
    );
    let after_failure = session
        .refresh(&SourceDelta::default())
        .expect("fresh parser epoch");
    assert_eq!(after_failure.work.program.reused_bodies, 0);
    assert_eq!(
        after_failure.generation.canonical_artifacts(),
        prior.canonical_artifacts()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-025`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn exhausted_parser_epochs_join_then_retry_with_cold_equal_bytes() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let base = session.acquire_generation().expect("base");
    let cold = session
        .evaluate_view_cold(base.source_view().clone())
        .expect("cold reference");
    let cold_bytes = cold.generation.canonical_artifacts().clone();
    let cold_admission = cold.work.parser_admission_bytes_added;
    assert!(cold_admission > 0);
    session.close().expect("close");
    drop(cold);
    drop(base);
    drop(session);
    let mut options = Fixture::options();
    options.limits.max_parser_bytes = cold_admission + cold_admission / 2;
    let mut session =
        Session::open(&fixture.root, &fixture.storage, options).expect("bounded epoch");
    let update = session
        .refresh(&SourceDelta::default())
        .expect("fresh epoch retry");
    assert!(update.work.parser_epoch_rotated);
    assert!(update.work.discarded_tokenizations > 0);
    assert!(update.work.tokenizations > update.work.retained_parser_tokenizations);
    assert_eq!(update.generation.canonical_artifacts(), &cold_bytes);
    assert!(
        update
            .reasons
            .iter()
            .any(|reason| reason == "resident_parser_epoch_rotated_to_cold_evaluation")
    );
    session.close().expect("close exhausted epoch");
    drop(update);
    drop(session);
    check_known_cold_parser_admission(&fixture, cold_admission, &cold_bytes);
}

fn check_known_cold_parser_admission(
    fixture: &Fixture,
    cold_admission: usize,
    cold_bytes: &std::collections::BTreeMap<String, String>,
) {
    let mut options = Fixture::options();
    options.limits.max_parser_bytes = cold_admission + cold_admission / 2;
    let mut session = Session::open(&fixture.root, &fixture.storage, options)
        .expect("known cold admission session");
    let view = session
        .acquire_generation()
        .expect("base")
        .source_view()
        .clone();
    for _ in 0..2 {
        let update = session
            .evaluate_view_cold(view.clone())
            .expect("preflighted fresh cold evaluation");
        assert_known_cold_rotation(&update);
        assert_eq!(update.generation.canonical_artifacts(), cold_bytes);
    }
    let mut files = view.files().clone();
    files.insert("src/lib.rs".into(), Fixture::source(2).into_bytes());
    let changed = fortress_core::observation::SourceView::from_bytes(files)
        .expect("previously unseen exact source");
    let update = session
        .evaluate_view_cold(changed.clone())
        .expect("unknown demand preserves exhaustion and cold retry");
    assert!(update.work.parser_epoch_rotated);
    assert!(update.work.discarded_tokenizations > 0);
    assert!(
        !update.reasons.iter().any(|reason| {
            reason == "resident_parser_epoch_rotated_before_known_cold_admission"
        })
    );
    let changed_bytes = update.generation.canonical_artifacts().clone();
    drop(update);
    let repeated = session
        .evaluate_view_cold(changed)
        .expect("new identity learned only after successful full cold execution");
    assert_known_cold_rotation(&repeated);
    assert_eq!(repeated.generation.canonical_artifacts(), &changed_bytes);
    session.close().expect("join known cold epoch");
}

fn assert_known_cold_rotation(update: &fortress_core::session::SessionUpdate) {
    assert!(update.work.parser_epoch_rotated);
    assert_eq!(update.work.discarded_tokenizations, 0);
    assert_eq!(update.work.discarded_parser_bytes, 0);
    assert_eq!(update.work.discarded_input_bytes, 0);
    assert!(update.work.tokenizations > 0);
    assert!(update.work.parser_admission_bytes_added > 0);
    assert_eq!(update.work.program.reused_bodies, 0);
    assert_eq!(update.work.semantic.reused_domain_rounds, 0);
    assert_eq!(update.work.state_effect.reused_direct_units, 0);
    assert!(
        update.reasons.iter().any(|reason| {
            reason == "resident_parser_epoch_rotated_before_known_cold_admission"
        })
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-026`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn parser_charge_survives_cache_eviction_and_ends_only_after_join() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let pin = session.acquire_generation().expect("pin");
    let bytes = pin.canonical_artifacts().clone();
    session.evict_preparation().expect("eviction");
    let after_eviction = session.resource_usage().expect("charge").0;
    let parser_permit = SessionLimits::default().max_parser_bytes * 64;
    assert!(after_eviction >= parser_permit);
    session.close().expect("join and close");
    let after_close = session.resource_usage().expect("historical pin").0;
    assert!(after_eviction - after_close >= parser_permit);
    assert_eq!(pin.canonical_artifacts(), &bytes);
    drop(pin);
    assert_eq!(session.resource_usage().expect("fully released"), (0, 0));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-027`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn cancelled_candidate_does_not_promote_its_preparation() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let base = session.acquire_generation().expect("base");
    let control = session.control();
    session.set_progress_observer(move |stage| {
        if stage == SessionStage::ModelsPrepared {
            control.cancel();
        }
    });
    let error = session
        .evaluate_delta(
            "cancelled",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: "src/lib.rs".into(),
                base_bytes: Fixture::source(1).into_bytes(),
                candidate_bytes: Fixture::source(12).into_bytes(),
            }],
        )
        .expect_err("cancelled candidate");
    assert_eq!(error.kind(), SessionErrorKind::Cancelled);
    session.set_progress_observer(|_| {});
    let current = session
        .refresh(&SourceDelta::default())
        .expect("actual preparation retained");
    assert!(current.work.program.reused_bodies > 0);
    assert_eq!(
        current.generation.canonical_artifacts(),
        base.canonical_artifacts()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-028`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn journal_failure_cannot_replace_the_immutable_head() {
    let fixture = Fixture::new();
    let mut session = fixture.open();
    let prior = session.acquire_generation().expect("prior");
    let registry = fixture.storage.join("rust/x");
    let folder = fs::read_dir(registry)
        .expect("registry")
        .next()
        .expect("root registry")
        .expect("folder")
        .path();
    let journal = fs::read_dir(folder)
        .expect("journals")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("journal");
    let saved = fs::read(&journal).expect("journal preimage");
    let sabotage = journal.clone();
    session.set_progress_observer(move |stage| {
        if stage == SessionStage::ModelsPrepared {
            fs::remove_file(&sabotage).expect("remove journal");
            fs::create_dir(&sabotage).expect("directory blocks replacement");
        }
    });
    let error = session
        .refresh(&SourceDelta::default())
        .expect_err("journal replacement failure");
    fs::remove_dir(&journal).expect("remove obstruction");
    fs::write(&journal, saved).expect("restore journal preimage");
    assert_eq!(error.kind(), SessionErrorKind::Storage);
    assert_eq!(
        session
            .acquire_generation()
            .expect("prior remains current")
            .generation_id(),
        prior.generation_id()
    );
    session.set_progress_observer(|_| {});
    session.close().expect("cleanup");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-029`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn empty_history_directories_cannot_evade_inventory_admission() {
    let fixture = Fixture::new();
    assert_eq!(
        fortress_core::session::observe_session_availability(&fixture.root, usize::MAX)
            .expect_err("path quota overflow is rejected before allocation")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
    let unknown = fixture.root.join(format!(
        "__fortress/evidence/generations/{}/unregistered",
        "e".repeat(64)
    ));
    fs::create_dir_all(unknown.join("nested")).expect("unregistered empty subtree");
    assert_eq!(
        fortress_core::session::observe_session_availability(&fixture.root, 64)
            .expect_err("unregistered directories cannot evade closed inventory roles")
            .kind(),
        SessionErrorKind::InvalidInput
    );
    fs::remove_dir_all(&unknown).expect("remove owned negative fixture subtree");
    for index in 0..100 {
        fs::create_dir_all(
            fixture
                .root
                .join(format!("__fortress/evidence/generations/{index:064x}")),
        )
        .expect("empty history directory");
    }
    let mut options = Fixture::options();
    options.limits.max_files = 64;
    assert_eq!(
        Session::open(&fixture.root, &fixture.storage, options)
            .expect_err("total history entry cap")
            .kind(),
        SessionErrorKind::ResourceLimit
    );
}
