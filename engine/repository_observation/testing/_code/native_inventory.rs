//! Exact physical Go and Python inventories independent of language semantics.

use std::fs;
use std::path::Path;

use fortress_core::observation::{
    ObservationError, ObservationLimits, ObservationPolicy, RepositoryObservation, SourceManifest,
    SourceView, observe_repository, observe_repository_bounded, observe_source_manifest,
};
use serde::Deserialize;

use super::{Fixture, limits};

const EXCLUDED_DIRECTORY: &str = "assets/excluded";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCases {
    provenance_sha256: String,
    inventories: Vec<NativeInventory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInventory {
    language: String,
    source_bytes: u64,
    files: Vec<NativeFile>,
    manifest_ref: String,
    scoped_manifest_ref: String,
    view_ref: String,
    drift: NativeDrift,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFile {
    path: String,
    bytes: u64,
    sha256: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeDrift {
    path: String,
    content: String,
    sha256: String,
    manifest_ref: String,
    view_ref: String,
}

fn native_inventories() -> Vec<NativeInventory> {
    let cases: NativeCases = serde_json::from_str(include_str!("../_data/native_cases.json"))
        .expect("frozen native observation fixtures parse");
    assert_eq!(
        cases.provenance_sha256,
        "sha256:bdee296951ef9011f6c9143a18cefd4059550773aab38bd908c4574d5a3c0da1"
    );
    cases.inventories
}

fn materialize(inventory: &NativeInventory) -> Fixture {
    let fixture = Fixture::new();
    for file in inventory.files.iter().rev() {
        let destination = fixture.0.join(&file.path);
        fs::create_dir_all(destination.parent().unwrap()).expect("owned fixture parent creates");
        fs::write(&destination, &file.content).expect("frozen source bytes write");
    }
    fixture
}

fn exact_limits(inventory: &NativeInventory) -> ObservationLimits {
    ObservationLimits {
        max_files: inventory.files.len(),
        max_source_bytes: inventory.source_bytes,
        ..limits()
    }
}

fn assert_file_facts(
    observed: &RepositoryObservation,
    expected: &NativeInventory,
    drift: Option<&NativeDrift>,
) {
    assert_eq!(
        observed.files().len(),
        expected.files.len(),
        "{} complete physical inventory",
        expected.language
    );
    for (actual, file) in observed.files().iter().zip(&expected.files) {
        let hash = drift
            .filter(|item| item.path == file.path)
            .map_or(file.sha256.as_str(), |item| item.sha256.as_str());
        assert_eq!(
            (actual.path(), actual.size(), actual.sha256()),
            (file.path.as_str(), file.bytes, hash),
            "{} exact relative path, size and hash",
            expected.language
        );
    }
}

fn source_view(root: &Path, inventory: &RepositoryObservation) -> SourceView {
    let files = inventory.files().iter().map(|file| {
        (
            file.path(),
            fs::read(root.join(file.path())).expect("snapshot fixture source remains readable"),
        )
    });
    SourceView::from_bytes(files).expect("observed paths form a canonical immutable view")
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R01-004`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R01
#[test]
fn native_repository_observation_matches_frozen_bytes_and_paths() {
    for inventory in native_inventories() {
        let fixture = materialize(&inventory);
        let replica = materialize(&inventory);
        let policy = ObservationPolicy::default();
        let bounded = observe_repository_bounded(&fixture.0, &policy, &exact_limits(&inventory))
            .expect("native inventory fits the exact independent byte and file count");
        assert_file_facts(&bounded, &inventory, None);
        let ordinary = observe_repository(&replica.0, &policy).expect("separate physical root");
        assert_eq!(bounded, ordinary);
        assert_eq!(
            bounded.to_json_pretty().unwrap(),
            ordinary.to_json_pretty().unwrap()
        );
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R02-005`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R02
#[test]
fn native_excluded_subtree_is_neutral_to_admitted_files() {
    for inventory in native_inventories() {
        let fixture = materialize(&inventory);
        let scoped = ObservationPolicy::new([EXCLUDED_DIRECTORY]).expect("explicit subtree scope");
        let initial = observe_source_manifest(&fixture.0, &scoped).unwrap();
        assert_eq!(initial.entries_digest(), inventory.scoped_manifest_ref);
        assert_ne!(initial.entries_digest(), inventory.manifest_ref);
        assert!(
            initial
                .exclusions()
                .iter()
                .any(|entry| entry.selector() == EXCLUDED_DIRECTORY)
        );

        let filename = Path::new(&inventory.drift.path)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("frozen native filename");
        let hidden = format!("{EXCLUDED_DIRECTORY}/{filename}");
        fs::create_dir(fixture.0.join(EXCLUDED_DIRECTORY)).unwrap();
        for content in ["initial excluded source", "changed excluded source bytes"] {
            fs::write(fixture.0.join(&hidden), content).unwrap();
            let observed =
                observe_repository_bounded(&fixture.0, &scoped, &exact_limits(&inventory))
                    .expect("excluded bytes do not consume the source quota");
            assert_file_facts(&observed, &inventory, None);
            assert_eq!(
                source_view(&fixture.0, &observed).digest(),
                inventory.view_ref
            );
            assert_eq!(
                observe_source_manifest(&fixture.0, &scoped).unwrap(),
                initial
            );
        }
        let complete = observe_repository(&fixture.0, &ObservationPolicy::default()).unwrap();
        assert_eq!(complete.files().len(), inventory.files.len() + 1);
        assert!(complete.files().iter().any(|file| file.path() == hidden));
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R03-006`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R03
#[test]
fn native_same_size_drift_and_restore_bind_exact_source_views() {
    for inventory in native_inventories() {
        let fixture = materialize(&inventory);
        let policy = ObservationPolicy::default();
        let original = observe_repository(&fixture.0, &policy).unwrap();
        assert_file_facts(&original, &inventory, None);
        let original_manifest = observe_source_manifest(&fixture.0, &policy).unwrap();
        assert_eq!(original_manifest.entries_digest(), inventory.manifest_ref);
        assert_eq!(
            original_manifest,
            SourceManifest::from_observation(&original, &policy).unwrap()
        );
        let retained = source_view(&fixture.0, &original);
        assert_eq!(retained.digest(), inventory.view_ref);

        let before = retained.bytes(&inventory.drift.path).unwrap();
        let after = inventory.drift.content.as_bytes();
        assert_eq!(before.len(), after.len());
        assert_ne!(before, after);
        let physical = fixture.0.join(&inventory.drift.path);
        fs::write(&physical, after).unwrap();
        let changed = observe_repository(&fixture.0, &policy).unwrap();
        assert_file_facts(&changed, &inventory, Some(&inventory.drift));
        let changed_manifest = observe_source_manifest(&fixture.0, &policy).unwrap();
        assert_eq!(
            changed_manifest.entries_digest(),
            inventory.drift.manifest_ref
        );
        let current = source_view(&fixture.0, &changed);
        assert_eq!(current.digest(), inventory.drift.view_ref);
        assert_eq!(current.bytes(&inventory.drift.path), Some(after));
        assert_ne!(retained, current);
        assert_ne!(original_manifest, changed_manifest);
        assert_eq!(retained.digest(), inventory.view_ref);

        fs::write(physical, before).unwrap();
        let restored = observe_repository(&fixture.0, &policy).unwrap();
        assert_eq!(restored, original);
        assert_eq!(
            observe_source_manifest(&fixture.0, &policy).unwrap(),
            original_manifest
        );
        assert_eq!(source_view(&fixture.0, &restored), retained);
    }
}

/// `T-AF-REPOSITORY-OBSERVATION-0001-R04-004`
/// Fortress requirement: AF-REPOSITORY-OBSERVATION-0001-R04
#[test]
fn native_inventory_one_byte_over_quota_refuses_the_whole_inventory() {
    for inventory in native_inventories() {
        let fixture = materialize(&inventory);
        let policy = ObservationPolicy::default();
        let mut bound = exact_limits(&inventory);
        bound.max_source_bytes -= 1;
        let refusal = observe_repository_bounded(&fixture.0, &policy, &bound);
        assert!(matches!(
            refusal,
            Err(ObservationError::ResourceLimit {
                resource: "source_bytes",
                maximum,
                observed,
            }) if maximum == bound.max_source_bytes && observed == inventory.source_bytes
        ));
        let complete = observe_repository_bounded(&fixture.0, &policy, &exact_limits(&inventory))
            .expect("the unchanged physical tree fits the correct quota");
        assert_file_facts(&complete, &inventory, None);
        assert_eq!(
            source_view(&fixture.0, &complete).digest(),
            inventory.view_ref
        );
    }
}
