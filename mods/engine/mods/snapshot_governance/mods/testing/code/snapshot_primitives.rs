//! Parent-local verification of snapshot, finding, placement, analyzer, and bundle primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingLocation, FindingOccurrence,
    RuleFindingDefinition,
};
use fortress_core::module_contract::{
    ContractStandardIndex, ResolvedContractSet, resolve_contracts,
};
use fortress_core::observation::ObservationPolicy;
use fortress_core::placement::is_lexical_name;
use fortress_core::rust_test_analyzer::{
    RustAnalyzerError, RustTestClassification, analyze_rust_source,
};
use fortress_core::snapshot::{
    SnapshotDocuments, SnapshotError, build_repository_snapshot, observe_repository_stably_with,
};
use fortress_core::standard::{StandardBundle, StandardLoadError};

static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(0);

struct TestRepository(PathBuf);

impl TestRepository {
    fn new(name: &str) -> Self {
        let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-snapshot-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test repository must be created");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent must be created");
        }
        fs::write(path, contents).expect("test file must be written");
    }
}

impl Drop for TestRepository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("test repository must be removed");
    }
}

fn standard() -> StandardBundle {
    let manifest = r#"{"$schema":"urn:fortress:schema:v1:standard-manifest","schema_version":1,"id":"STD-FORTRESS-ENGINEERING","title":"Test","edition":"1.0.0-draft.1","status":"draft","release_digest":null,"rules":["rule.json"]}"#;
    let rule = r#"{"$schema":"urn:fortress:schema:v1:rule","schema_version":1,"id":"STD-ID-001","title":"Identity","status":"draft","statement":"Identity is stable.","rationale":"Determinism.","failure_prevented":"Ambiguity.","applicability":"All identities.","category":"standard","integrity_tier":1,"evaluation":"Parse IDs.","required_capabilities":[],"finding":{"message":"Invalid.","location":"entity"},"remediation":"Correct it.","valid_example":"AF-CORE-0001","invalid_example":"bad","exception_policy":"None.","introduced":"1.0.0-draft.1","history":[]}"#;
    StandardBundle::from_json_documents(manifest, &[("rule.json", rule)])
        .expect("test standard validates")
}

fn contracts() -> ResolvedContractSet {
    let source = "{\n  \"$schema\": \"urn:fortress:schema:v2:module-contract\",\n  \"schema_version\": 2,\n  \"id\": \"PF-SNAPSHOT-TEST\",\n  \"display_name\": \"Snapshot Test\",\n  \"ecosystem\": {\n    \"repository_grammar\": 1,\n    \"standard\": {\n      \"id\": \"STD-FORTRESS-ENGINEERING\",\n      \"edition\": \"1.0.0-draft.1\"\n    }\n  },\n  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n  \"constraints\": [],\n  \"guarantees\": [],\n  \"features\": [],\n  \"behavior\": []\n}\n";
    let files = BTreeMap::from([("contract.json".into(), source.as_bytes().to_vec())]);
    resolve_contracts(
        &files,
        &ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", "1.0.0-draft.1", ["STD-ID-001"]),
        Some(&BTreeSet::new()),
    )
    .resolved()
    .expect("test contract resolves")
    .clone()
}

fn documents() -> SnapshotDocuments<'static> {
    SnapshotDocuments::new(
        "mods/engine/mods/standard_registry/data/standard_manifest.json",
        b"standard",
        [(
            "mods/engine/mods/standard_registry/data/std_id_rule.json",
            &b"rule"[..],
        )],
        b"project",
        [("contract.json", &b"contract"[..])],
    )
}

fn finding(rule_id: &str, path: &str, message: &str) -> CanonicalFinding {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(rule_id, 1, FindingCategory::Architecture, "Repair it.")
            .expect("definition must validate"),
        FindingOccurrence::new(
            vec!["AF-CORE-0001".into()],
            FindingLocation::at_path(path).expect("path must validate"),
            message,
        )
        .expect("occurrence must validate"),
        EvaluatorProvenance::new("fortress-core/test", "1").expect("provenance is valid"),
        "1.0.0-draft.1",
        None,
    )
    .expect("finding must normalize")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R01
#[test]
fn stable_repository_produces_a_snapshot() {
    let repository = TestRepository::new("stable");
    repository.write("source.txt", "stable");
    let snapshot = build_repository_snapshot(
        repository.path(),
        &ObservationPolicy::default(),
        &contracts(),
        &standard(),
        &documents(),
    )
    .expect("stable repository must produce a snapshot");
    assert_eq!(snapshot.files().len(), 1);
    assert!(snapshot.snapshot_fingerprint().starts_with("sha256:"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R01
#[test]
fn ordering_and_fingerprints_are_deterministic() {
    let repository = TestRepository::new("deterministic");
    repository.write("z.txt", "last");
    repository.write("a.txt", "first");
    let first = build_repository_snapshot(
        repository.path(),
        &ObservationPolicy::default(),
        &contracts(),
        &standard(),
        &documents(),
    )
    .expect("first snapshot must succeed");
    let second = build_repository_snapshot(
        repository.path(),
        &ObservationPolicy::default(),
        &contracts(),
        &standard(),
        &documents(),
    )
    .expect("second snapshot must succeed");
    assert_eq!(first, second);
    assert_eq!(first.files()[0].path(), "a.txt");
    assert_eq!(first.to_json_pretty().ok(), second.to_json_pretty().ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R01-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R01
#[test]
fn empty_repository_and_explicit_exclusions_are_supported() {
    let empty = TestRepository::new("empty");
    let observation =
        observe_repository_stably_with(empty.path(), &ObservationPolicy::default(), || {})
            .expect("empty repository is a valid boundary");
    assert!(observation.files().is_empty());

    let excluded = TestRepository::new("excluded");
    excluded.write("state/cache.txt", "first");
    let policy = ObservationPolicy::new(["state"]).expect("policy must validate");
    let observation = observe_repository_stably_with(excluded.path(), &policy, || {
        excluded.write("state/cache.txt", "second");
    })
    .expect("excluded mutation must not destabilize governed content");
    assert!(observation.files().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R02
#[test]
fn changed_file_between_passes_is_rejected() {
    let repository = TestRepository::new("changed");
    repository.write("file.txt", "first");
    let result =
        observe_repository_stably_with(repository.path(), &ObservationPolicy::default(), || {
            repository.write("file.txt", "second");
        });
    assert!(matches!(
        result,
        Err(SnapshotError::UnstableRepository { .. })
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R02
#[test]
fn added_file_between_passes_is_rejected() {
    let repository = TestRepository::new("added");
    repository.write("first.txt", "first");
    let result =
        observe_repository_stably_with(repository.path(), &ObservationPolicy::default(), || {
            repository.write("added.txt", "added");
        });
    assert!(matches!(
        result,
        Err(SnapshotError::UnstableRepository { .. })
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R02-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R02
#[test]
fn removed_file_between_passes_is_rejected() {
    let repository = TestRepository::new("removed");
    repository.write("removed.txt", "removed");
    let result =
        observe_repository_stably_with(repository.path(), &ObservationPolicy::default(), || {
            fs::remove_file(repository.path().join("removed.txt"))
                .expect("test file must be removed");
        });
    assert!(matches!(
        result,
        Err(SnapshotError::UnstableRepository { .. })
    ));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R03-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R03
#[test]
fn finding_rejects_invalid_rule_and_location_inputs() {
    assert!(
        RuleFindingDefinition::new("NOT-A-RULE", 1, FindingCategory::Architecture, "Repair it.")
            .is_err()
    );
    assert!(FindingLocation::at_path("../outside").is_err());
    assert!(FindingLocation::at_path("C:/outside").is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R03-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R03
#[test]
fn equivalent_findings_have_identical_identity_and_json() {
    let first = finding(
        "ARCH-DEPENDENCY-001",
        "mods/engine/code/lib.rs",
        "Violation.",
    );
    let second = finding(
        "ARCH-DEPENDENCY-001",
        "mods/engine/code/lib.rs",
        "Violation.",
    );
    assert_eq!(first, second);
    assert!(first.finding_fingerprint().starts_with("sha256:"));
    assert_eq!(
        serde_json::to_string(&first).ok(),
        serde_json::to_string(&second).ok()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R03-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R03
#[test]
fn findings_sort_by_rule_path_entities_and_message() {
    let mut findings = [
        finding("REPO-MODULE-001", "z.txt", "Second."),
        finding("ARCH-DEPENDENCY-001", "z.txt", "Third."),
        finding("ARCH-DEPENDENCY-001", "a.txt", "First."),
    ];
    findings.sort();
    assert_eq!(findings[0].message(), "First.");
    assert_eq!(findings[1].message(), "Third.");
    assert_eq!(findings[2].message(), "Second.");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn structured_analyzer_extracts_identity_classification_and_requirement() {
    let source = r"
        /// `T-AF-SAMPLE-0001-R01-001`
        /// Fortress requirement: AF-SAMPLE-0001-R01
        #[test]
        fn behavior() {}

        /// `T-AF-SAMPLE-0001-INFRA-001`
        /// Fortress classification: infrastructure
        #[test]
        fn helper() {}
    ";
    let facts =
        analyze_rust_source("mods/testing/code/sample.rs", source).expect("source analyzes");
    assert_eq!(facts.len(), 2);
    assert_eq!(
        facts[0].classification(),
        RustTestClassification::Infrastructure
    );
    assert_eq!(facts[1].declared_requirement(), Some("AF-SAMPLE-0001-R01"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R06
#[test]
fn structured_analyzer_rejects_unidentified_behavior_test() {
    let error = analyze_rust_source(
        "mods/testing/code/sample.rs",
        "#[test]\nfn missing_identity() {}",
    )
    .expect_err("missing identity must fail");
    assert!(matches!(error, RustAnalyzerError::MissingTestId(_)));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R09-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn lexical_names_accept_three_words_and_canonical_versions() {
    assert!(is_lexical_name("repository_schema_rule_v2.json", true));
    assert!(is_lexical_name("snapshot_governance", false));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R09-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R09
#[test]
fn lexical_names_reject_noncanonical_forms() {
    for name in [
        "Bad.rs",
        "bad-name.rs",
        "bad__name.rs",
        "_bad.rs",
        "one_two_three_four.rs",
        "schema_v01.json",
    ] {
        assert!(!is_lexical_name(name, true), "{name} must be rejected");
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R04-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R04
#[test]
fn exact_draft_standard_documents_load_as_one_validated_bundle() {
    let root = repository_root();
    let manifest = fs::read_to_string(
        root.join("mods/engine/mods/standard_registry/data/standard_manifest.json"),
    )
    .expect("manifest reads");
    let paths = [
        "mods/engine/mods/standard_registry/data/std_id_rule.json",
        "mods/engine/mods/architecture_evaluation/data/dependency_rule.json",
        "mods/engine/mods/snapshot_governance/data/ownership_rule.json",
        "mods/engine/mods/snapshot_governance/data/traceability_rule.json",
        "mods/engine/mods/snapshot_governance/data/test_boundary_rule.json",
        "mods/engine/mods/snapshot_governance/data/module_rule.json",
        "mods/engine/mods/snapshot_governance/data/documentation_rule.json",
        "mods/engine/mods/snapshot_governance/data/contract_rule.json",
    ];
    let sources: Vec<String> = paths
        .iter()
        .map(|path| fs::read_to_string(root.join(path)).expect("rule reads"))
        .collect();
    let documents: Vec<(&str, &str)> = paths
        .iter()
        .copied()
        .zip(sources.iter().map(String::as_str))
        .collect();
    let bundle = StandardBundle::from_json_documents(&manifest, &documents)
        .expect("draft bundle must validate");
    assert_eq!(bundle.edition(), "1.0.0-draft.1");
    assert_eq!(bundle.rules().len(), 8);
    assert!(matches!(
        StandardBundle::from_json_documents(&manifest, &[(paths[0], sources[0].as_str())]),
        Err(StandardLoadError::MissingRuleDocument(_))
    ));
}
