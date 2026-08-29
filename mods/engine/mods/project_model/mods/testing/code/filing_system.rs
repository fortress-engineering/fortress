//! Conformance for the canonical Project Filing System model.

use std::path::{Path, PathBuf};

use fortress_core::filing::{
    DATA_ROLES, EcosystemFilingProfile, FilingSystemProfiles, FilingSystemViolation,
    FilingViolationKind, INFO_ROLES, MechanicalCodeStructure, RegisteredRootEntry,
    RootEntryClassification, RootEntryKind, analyze_project_filing_system,
};
use fortress_core::observation::{ObservationPolicy, observe_repository};

fn atomic_root() -> Vec<String> {
    paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
    ])
}

fn paths(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn standard() -> FilingSystemProfiles {
    FilingSystemProfiles::standard()
}

fn kinds(paths: &[String]) -> Vec<FilingViolationKind> {
    analyze_project_filing_system(paths, &standard())
        .violations()
        .iter()
        .map(FilingSystemViolation::kind)
        .collect()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `T-AF-PROJECT-MODEL-0001-R04-001`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn atomic_composite_and_pure_composite_modules_follow_one_recursive_law() {
    let atomic = analyze_project_filing_system(&atomic_root(), &standard());
    assert!(atomic.is_valid(), "{:?}", atomic.violations());
    assert_eq!(atomic.modules().len(), 1);

    let composite = paths(&[
        "README.md",
        "contract.json",
        "code/facade.rs",
        "docs/code_docs.md",
        "docs/mods_docs.md",
        "mods/child/README.md",
        "mods/child/contract.json",
        "mods/child/code/lib.rs",
        "mods/child/docs/code_docs.md",
    ]);
    let model = analyze_project_filing_system(&composite, &standard());
    assert!(model.is_valid(), "{:?}", model.violations());
    assert_eq!(model.modules().len(), 2);

    let pure_composite = paths(&[
        "README.md",
        "contract.json",
        "docs/mods_docs.md",
        "mods/child/README.md",
        "mods/child/contract.json",
        "mods/child/code/lib.rs",
        "mods/child/docs/code_docs.md",
    ]);
    assert!(analyze_project_filing_system(&pure_composite, &standard()).is_valid());
}

/// `T-AF-PROJECT-MODEL-0001-R04-002`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn root_and_module_surfaces_are_closed_and_ecosystem_entries_are_registered() {
    let mut invalid_file = atomic_root();
    invalid_file.push("notes.md".into());
    let invalid_model = analyze_project_filing_system(&invalid_file, &standard());
    assert!(
        invalid_model
            .violations()
            .iter()
            .any(|violation| violation.kind() == FilingViolationKind::UnknownModuleRootEntry)
    );
    assert_eq!(
        invalid_model
            .root_entries()
            .iter()
            .find(|entry| entry.path() == "notes.md")
            .expect("invalid root entry is classified")
            .classification(),
        RootEntryClassification::Invalid
    );

    let mut invalid_directory = atomic_root();
    invalid_directory.push("scripts/tool.sh".into());
    assert!(kinds(&invalid_directory).contains(&FilingViolationKind::UnknownModuleRootEntry));

    let mut registered = atomic_root();
    registered.extend(paths(&[".github/workflows/ci.yml", ".gitignore"]));
    let registered_model = analyze_project_filing_system(&registered, &standard());
    assert!(registered_model.is_valid());
    assert_eq!(
        registered_model
            .root_entries()
            .iter()
            .find(|entry| entry.path() == ".gitignore")
            .expect("Git root entry is classified")
            .classification(),
        RootEntryClassification::EcosystemRequired
    );

    let generated_profile = EcosystemFilingProfile::new(
        "ECOSYSTEM-GENERATOR-FIXTURE-0001",
        vec![RegisteredRootEntry::new(
            "generated.json",
            RootEntryKind::File,
            RootEntryClassification::GeneratedAllowed,
        )],
        Vec::new(),
        Vec::new(),
    );
    let generated_profiles =
        FilingSystemProfiles::from_profiles(vec![generated_profile]).expect("profile validates");
    let mut generated = atomic_root();
    generated.push("generated.json".into());
    let generated_model = analyze_project_filing_system(&generated, &generated_profiles);
    assert!(generated_model.is_valid());
    assert_eq!(
        generated_model
            .root_entries()
            .iter()
            .find(|entry| entry.path() == "generated.json")
            .expect("generated root entry is classified")
            .classification(),
        RootEntryClassification::GeneratedAllowed
    );

    let invalid_profile = r#"{
      "$schema":"urn:fortress:schema:v1:filing-system-profiles",
      "schema_version":1,
      "profiles":[{"id":"ECOSYSTEM-X-0001","root_entries":[{"path":"../escape","kind":"FILE","classification":"ECOSYSTEM_REQUIRED"}],"element_files":[],"mechanical_code_structures":[]}]
    }"#;
    assert!(FilingSystemProfiles::from_json_str(invalid_profile).is_err());
}

/// `T-AF-PROJECT-MODEL-0001-R04-003`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn code_is_flat_except_for_registered_mechanical_namespace_structure() {
    let flat = atomic_root();
    assert!(analyze_project_filing_system(&flat, &standard()).is_valid());

    let mut semantic = atomic_root();
    semantic.push("code/parsing/parser.rs".into());
    assert!(kinds(&semantic).contains(&FilingViolationKind::CodeSemanticSubdirectory));

    let profile = EcosystemFilingProfile::new(
        "ECOSYSTEM-JAVA-FIXTURE-0001",
        Vec::new(),
        Vec::new(),
        vec![MechanicalCodeStructure::new("com/example", true)],
    );
    let profiles = FilingSystemProfiles::from_profiles(vec![profile]).expect("profile validates");
    let mechanical = paths(&[
        "README.md",
        "contract.json",
        "code/com/example/main.java",
        "docs/code_docs.md",
    ]);
    assert!(analyze_project_filing_system(&mechanical, &profiles).is_valid());

    let unregistered = paths(&[
        "README.md",
        "contract.json",
        "code/org/other/main.java",
        "docs/code_docs.md",
    ]);
    assert!(
        analyze_project_filing_system(&unregistered, &profiles)
            .violations()
            .iter()
            .any(|violation| violation.kind() == FilingViolationKind::UnregisteredCodeStructure)
    );

    let generated = paths(&[
        "README.md",
        "contract.json",
        "code/generated_file.rs",
        "docs/code_docs.md",
    ]);
    assert!(analyze_project_filing_system(&generated, &standard()).is_valid());
}

/// `T-AF-PROJECT-MODEL-0001-R04-004`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn documentation_is_a_closed_applicable_companion_set() {
    let exact = atomic_root();
    assert!(analyze_project_filing_system(&exact, &standard()).is_valid());

    let missing = paths(&["README.md", "contract.json", "code/main.rs"]);
    assert!(kinds(&missing).contains(&FilingViolationKind::MissingRequiredElementDoc));

    let mut extra = atomic_root();
    extra.push("docs/design.md".into());
    assert!(kinds(&extra).contains(&FilingViolationKind::UnrecognizedDocFile));

    let mut nested = atomic_root();
    nested.push("docs/history/adr.md".into());
    assert!(kinds(&nested).contains(&FilingViolationKind::DocSubdirectoryForbidden));
}

/// `T-AF-PROJECT-MODEL-0001-R04-005`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn data_supports_flat_role_collection_and_one_partition_forms() {
    for data_path in [
        "data/config.json",
        "data/schema/request.json",
        "data/schema/customer_v2/request.json",
        "data/dataset/historical_events_v3/part_000001/event.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "code/main.rs",
            data_path,
            "docs/code_docs.md",
            "docs/data_docs.md",
        ]);
        let model = analyze_project_filing_system(&fixture, &standard());
        assert!(model.is_valid(), "{data_path}: {:?}", model.violations());
    }
    for role in DATA_ROLES {
        let role_path = format!("data/{role}/artifact.json");
        let fixture = vec![
            "README.md".into(),
            "contract.json".into(),
            "code/main.rs".into(),
            "docs/code_docs.md".into(),
            "docs/data_docs.md".into(),
            role_path,
        ];
        assert!(
            analyze_project_filing_system(&fixture, &standard()).is_valid(),
            "role {role} must remain canonical"
        );
    }

    let unknown = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "data/sample/item.json",
        "docs/code_docs.md",
        "docs/data_docs.md",
    ]);
    assert!(kinds(&unknown).contains(&FilingViolationKind::UnknownDataRole));

    let excessive = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "data/dataset/customer/north_america/florida/item.json",
        "docs/code_docs.md",
        "docs/data_docs.md",
    ]);
    let result = kinds(&excessive);
    assert!(result.contains(&FilingViolationKind::InvalidPartition));
    assert!(result.contains(&FilingViolationKind::PartitionRecursion));
    assert!(result.contains(&FilingViolationKind::ExcessiveCollectionDepth));
}

/// `T-AF-PROJECT-MODEL-0001-R04-006`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn info_uses_the_same_bounded_grammar_with_its_own_frozen_roles() {
    for info_path in [
        "info/report.json",
        "info/graph/ccg.json",
        "info/evidence/certification_v1/result.json",
        "info/evidence/certification_v1/part_000012/result.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "code/main.rs",
            "docs/code_docs.md",
            "docs/info_docs.md",
            info_path,
        ]);
        let model = analyze_project_filing_system(&fixture, &standard());
        assert!(model.is_valid(), "{info_path}: {:?}", model.violations());
    }
    for role in INFO_ROLES {
        let role_path = format!("info/{role}/artifact.json");
        let fixture = vec![
            "README.md".into(),
            "contract.json".into(),
            "code/main.rs".into(),
            "docs/code_docs.md".into(),
            "docs/info_docs.md".into(),
            role_path,
        ];
        assert!(
            analyze_project_filing_system(&fixture, &standard()).is_valid(),
            "role {role} must remain canonical"
        );
    }

    let unknown = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/info_docs.md",
        "info/cache/item.json",
    ]);
    assert!(kinds(&unknown).contains(&FilingViolationKind::UnknownInfoRole));
}

/// `T-AF-PROJECT-MODEL-0001-R04-007`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn versions_collections_partitions_and_minimum_depth_are_canonical() {
    for valid in [
        "data/schema_v1/request.json",
        "data/schema/customer_v12/request.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "code/main.rs",
            "docs/code_docs.md",
            "docs/data_docs.md",
            valid,
        ]);
        assert!(analyze_project_filing_system(&fixture, &standard()).is_valid());
    }

    for malformed in [
        "data/schema_v02/request.json",
        "data/schema-v2/request.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "code/main.rs",
            "docs/code_docs.md",
            "docs/data_docs.md",
            malformed,
        ]);
        assert!(kinds(&fixture).contains(&FilingViolationKind::InvalidVersionSuffix));
    }

    let duplicate_version = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/data_docs.md",
        "data/schema_v2/customer_v2/request.json",
    ]);
    assert!(kinds(&duplicate_version).contains(&FilingViolationKind::InvalidVersionSuffix));

    let invalid_collection = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/data_docs.md",
        "data/schema/Too_Many_Semantic_Words/request.json",
    ]);
    assert!(kinds(&invalid_collection).contains(&FilingViolationKind::InvalidCollectionName));

    let redundant = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/data_docs.md",
        "data/schema/schemas/request.json",
    ]);
    assert!(kinds(&redundant).contains(&FilingViolationKind::RedundantDirectoryLevel));

    let invalid_partition = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/data_docs.md",
        "data/dataset/events/part_1/item.json",
    ]);
    let model = analyze_project_filing_system(&invalid_partition, &standard());
    let finding = model
        .violations()
        .iter()
        .find(|violation| violation.kind() == FilingViolationKind::InvalidPartition)
        .expect("invalid partition is reported");
    assert_eq!(finding.module(), ".");
    assert_eq!(finding.element(), "data");
    assert_eq!(finding.path(), "data/dataset/events/part_1");
    assert_eq!(
        finding.expected(),
        "part_ followed by exactly six decimal digits from 000001"
    );
}

/// `T-AF-PROJECT-MODEL-0001-R04-008`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn flat_and_structured_elements_never_mix() {
    let data = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "data/config.json",
        "data/schema/request.json",
        "docs/code_docs.md",
        "docs/data_docs.md",
    ]);
    assert!(kinds(&data).contains(&FilingViolationKind::MixedFlatAndStructuredElement));

    let info = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "docs/code_docs.md",
        "docs/info_docs.md",
        "info/report.json",
        "info/graph/ccg.json",
    ]);
    assert!(kinds(&info).contains(&FilingViolationKind::MixedFlatAndStructuredElement));
}

/// `T-AF-PROJECT-MODEL-0001-R04-009`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn machine_inventory_is_complete_deterministic_and_catalogs_collections_not_leaves() {
    let fixture = paths(&[
        "README.md",
        "contract.json",
        "code/main.rs",
        "data/dataset/events/part_000001/a.json",
        "data/dataset/events/part_000002/b.json",
        "docs/code_docs.md",
        "docs/data_docs.md",
    ]);
    let first = analyze_project_filing_system(&fixture, &standard());
    let second = analyze_project_filing_system(&fixture, &standard());
    assert_eq!(first, second);
    assert_eq!(first.inventory().entries().len(), fixture.len());
    assert!(first.inventory().digest().starts_with("sha256:"));
    let collection = first
        .collections()
        .iter()
        .find(|collection| collection.collection() == Some("events"))
        .expect("events collection exists");
    assert_eq!(collection.partitions(), 2);
    assert_eq!(collection.files(), 2);
}

/// `T-AF-PROJECT-MODEL-0001-R04-010`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn massive_repository_remains_linear_without_module_proliferation_for_volume() {
    let mut fixture = paths(&[
        "README.md",
        "contract.json",
        "docs/data_docs.md",
        "docs/mods_docs.md",
    ]);
    for module in 0..300 {
        fixture.extend([
            format!("mods/module_{module}/README.md"),
            format!("mods/module_{module}/contract.json"),
            format!("mods/module_{module}/code/lib.rs"),
            format!("mods/module_{module}/docs/code_docs.md"),
        ]);
    }
    for partition in 1..=2_000 {
        fixture.push(format!(
            "data/dataset/historical_events_v3/part_{partition:06}/event.json"
        ));
    }
    let model = analyze_project_filing_system(&fixture, &standard());
    assert!(model.is_valid(), "{:?}", model.violations());
    assert_eq!(model.modules().len(), 301);
    assert_eq!(model.inventory().entries().len(), fixture.len());
    let collection = model
        .collections()
        .iter()
        .find(|collection| collection.collection() == Some("historical_events_v3"))
        .expect("large collection exists");
    assert_eq!(collection.partitions(), 2_000);
    assert_eq!(collection.files(), 2_000);
}

/// `T-AF-PROJECT-MODEL-0001-R04-011`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn physical_module_relocation_preserves_internal_filing_validity() {
    let before = paths(&[
        "README.md",
        "contract.json",
        "docs/mods_docs.md",
        "mods/payments/README.md",
        "mods/payments/contract.json",
        "mods/payments/docs/mods_docs.md",
        "mods/payments/mods/currency/README.md",
        "mods/payments/mods/currency/contract.json",
        "mods/payments/mods/currency/code/lib.rs",
        "mods/payments/mods/currency/docs/code_docs.md",
    ]);
    let after = paths(&[
        "README.md",
        "contract.json",
        "docs/mods_docs.md",
        "mods/currency/README.md",
        "mods/currency/contract.json",
        "mods/currency/code/lib.rs",
        "mods/currency/docs/code_docs.md",
    ]);
    let before_model = analyze_project_filing_system(&before, &standard());
    let after_model = analyze_project_filing_system(&after, &standard());
    assert!(before_model.is_valid(), "{:?}", before_model.violations());
    assert!(after_model.is_valid(), "{:?}", after_model.violations());
    assert_eq!(
        before_model.inventory().entries().len() - 3,
        after_model.inventory().entries().len()
    );
}

/// `T-AF-PROJECT-MODEL-0001-R04-012`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn live_fortress_filing_model_is_valid_and_deterministic() {
    let root = repository_root();
    let observation = observe_repository(
        &root,
        &ObservationPolicy::new([".git"]).expect("policy validates"),
    )
    .expect("repository observes");
    let paths: Vec<String> = observation
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect();
    let first = analyze_project_filing_system(&paths, &standard());
    let second = analyze_project_filing_system(&paths, &standard());
    assert_eq!(first, second);
    assert!(first.is_valid(), "{:?}", first.violations());
    assert_eq!(first.modules().len(), 38);
    assert_eq!(first.inventory().entries().len(), paths.len());
}
