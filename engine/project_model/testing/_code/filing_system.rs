//! Conformance for the canonical Project Filing System model.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::filing::{
    DATA_ROLES, EcosystemEntryScope, EcosystemFilingProfile, FilingSystemProfiles,
    FilingSystemViolation, FilingViolationKind, INFO_ROLES, MechanicalCodeStructure,
    RegisteredRootEntry, RootEntryClassification, RootEntryKind, analyze_project_filing_system,
};
use fortress_core::module_index::CanonicalModuleIndex;
use fortress_core::observation::{ObservationPolicy, observe_repository};

fn atomic_root() -> Vec<String> {
    paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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
        "_code/facade.rs",
        "_docs/code_docs.md",
        "_docs/modules_docs.md",
        "child/README.md",
        "child/contract.json",
        "child/_code/lib.rs",
        "child/_docs/code_docs.md",
    ]);
    let model = analyze_project_filing_system(&composite, &standard());
    assert!(model.is_valid(), "{:?}", model.violations());
    assert_eq!(model.modules().len(), 2);

    let pure_composite = paths(&[
        "README.md",
        "contract.json",
        "_docs/modules_docs.md",
        "child/README.md",
        "child/contract.json",
        "child/_code/lib.rs",
        "child/_docs/code_docs.md",
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
      "$schema":"urn:fortress:schema:v2:filing-system-profiles",
      "schema_version":2,
      "profiles":[{"id":"ECOSYSTEM-X-0001","root_entries":[{"path":"../escape","kind":"FILE","classification":"ECOSYSTEM_REQUIRED","scope":"PROJECT_ROOT","opaque":false}],"element_files":[],"mechanical_code_structures":[]}]
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
    semantic.push("_code/parsing/parser.rs".into());
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
        "_code/com/example/main.java",
        "_docs/code_docs.md",
    ]);
    assert!(analyze_project_filing_system(&mechanical, &profiles).is_valid());

    let unregistered = paths(&[
        "README.md",
        "contract.json",
        "_code/org/other/main.java",
        "_docs/code_docs.md",
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
        "_code/generated_file.rs",
        "_docs/code_docs.md",
    ]);
    assert!(analyze_project_filing_system(&generated, &standard()).is_valid());
}

/// `T-AF-PROJECT-MODEL-0001-R04-004`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn documentation_is_a_closed_applicable_companion_set() {
    let exact = atomic_root();
    assert!(analyze_project_filing_system(&exact, &standard()).is_valid());

    let missing = paths(&["README.md", "contract.json", "_code/main.rs"]);
    assert!(kinds(&missing).contains(&FilingViolationKind::MissingRequiredElementDoc));

    let mut extra = atomic_root();
    extra.push("_docs/design.md".into());
    assert!(kinds(&extra).contains(&FilingViolationKind::UnrecognizedDocFile));

    let mut nested = atomic_root();
    nested.push("_docs/history/adr.md".into());
    assert!(kinds(&nested).contains(&FilingViolationKind::DocSubdirectoryForbidden));
}

/// `T-AF-PROJECT-MODEL-0001-R04-005`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn data_supports_flat_role_collection_and_one_partition_forms() {
    for data_path in [
        "_data/config.json",
        "_data/schema/request.json",
        "_data/schema/customer_v2/request.json",
        "_data/dataset/historical_events_v3/part_000001/event.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "_code/main.rs",
            data_path,
            "_docs/code_docs.md",
            "_docs/data_docs.md",
        ]);
        let model = analyze_project_filing_system(&fixture, &standard());
        assert!(model.is_valid(), "{data_path}: {:?}", model.violations());
    }
    for role in DATA_ROLES {
        let role_path = format!("_data/{role}/artifact.json");
        let fixture = vec![
            "README.md".into(),
            "contract.json".into(),
            "_code/main.rs".into(),
            "_docs/code_docs.md".into(),
            "_docs/data_docs.md".into(),
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
        "_code/main.rs",
        "_data/sample/item.json",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
    ]);
    assert!(kinds(&unknown).contains(&FilingViolationKind::UnknownDataRole));

    let excessive = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_data/dataset/customer/north_america/florida/item.json",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
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
        "_info/report.json",
        "_info/graph/ccg.json",
        "_info/evidence/certification_v1/result.json",
        "_info/evidence/certification_v1/part_000012/result.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "_code/main.rs",
            "_docs/code_docs.md",
            "_docs/info_docs.md",
            info_path,
        ]);
        let model = analyze_project_filing_system(&fixture, &standard());
        assert!(model.is_valid(), "{info_path}: {:?}", model.violations());
    }
    for role in INFO_ROLES {
        let role_path = format!("_info/{role}/artifact.json");
        let fixture = vec![
            "README.md".into(),
            "contract.json".into(),
            "_code/main.rs".into(),
            "_docs/code_docs.md".into(),
            "_docs/info_docs.md".into(),
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
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/info_docs.md",
        "_info/cache/item.json",
    ]);
    assert!(kinds(&unknown).contains(&FilingViolationKind::UnknownInfoRole));
}

/// `T-AF-PROJECT-MODEL-0001-R04-007`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn versions_collections_partitions_and_minimum_depth_are_canonical() {
    for valid in [
        "_data/schema_v1/request.json",
        "_data/schema/customer_v12/request.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "_code/main.rs",
            "_docs/code_docs.md",
            "_docs/data_docs.md",
            valid,
        ]);
        assert!(analyze_project_filing_system(&fixture, &standard()).is_valid());
    }

    for malformed in [
        "_data/schema_v02/request.json",
        "_data/schema-v2/request.json",
    ] {
        let fixture = paths(&[
            "README.md",
            "contract.json",
            "_code/main.rs",
            "_docs/code_docs.md",
            "_docs/data_docs.md",
            malformed,
        ]);
        assert!(kinds(&fixture).contains(&FilingViolationKind::InvalidVersionSuffix));
    }

    let duplicate_version = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
        "_data/schema_v2/customer_v2/request.json",
    ]);
    assert!(kinds(&duplicate_version).contains(&FilingViolationKind::InvalidVersionSuffix));

    let invalid_collection = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
        "_data/schema/Too_Many_Semantic_Words/request.json",
    ]);
    assert!(kinds(&invalid_collection).contains(&FilingViolationKind::InvalidCollectionName));

    let redundant = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
        "_data/schema/schemas/request.json",
    ]);
    assert!(kinds(&redundant).contains(&FilingViolationKind::RedundantDirectoryLevel));

    let invalid_partition = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
        "_data/dataset/events/part_1/item.json",
    ]);
    let model = analyze_project_filing_system(&invalid_partition, &standard());
    let finding = model
        .violations()
        .iter()
        .find(|violation| violation.kind() == FilingViolationKind::InvalidPartition)
        .expect("invalid partition is reported");
    assert_eq!(finding.module(), ".");
    assert_eq!(finding.element(), "data");
    assert_eq!(finding.path(), "_data/dataset/events/part_1");
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
        "_code/main.rs",
        "_data/config.json",
        "_data/schema/request.json",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
    ]);
    assert!(kinds(&data).contains(&FilingViolationKind::MixedFlatAndStructuredElement));

    let info = paths(&[
        "README.md",
        "contract.json",
        "_code/main.rs",
        "_docs/code_docs.md",
        "_docs/info_docs.md",
        "_info/report.json",
        "_info/graph/ccg.json",
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
        "_code/main.rs",
        "_data/dataset/events/part_000001/a.json",
        "_data/dataset/events/part_000002/b.json",
        "_docs/code_docs.md",
        "_docs/data_docs.md",
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
        "_docs/data_docs.md",
        "_docs/modules_docs.md",
    ]);
    for module in 0..300 {
        fixture.extend([
            format!("module_{module}/README.md"),
            format!("module_{module}/contract.json"),
            format!("module_{module}/_code/lib.rs"),
            format!("module_{module}/_docs/code_docs.md"),
        ]);
    }
    for partition in 1..=2_000 {
        fixture.push(format!(
            "_data/dataset/historical_events_v3/part_{partition:06}/event.json"
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
        "_docs/modules_docs.md",
        "payments/README.md",
        "payments/contract.json",
        "payments/_docs/modules_docs.md",
        "payments/currency/README.md",
        "payments/currency/contract.json",
        "payments/currency/_code/lib.rs",
        "payments/currency/_docs/code_docs.md",
    ]);
    let after = paths(&[
        "README.md",
        "contract.json",
        "_docs/modules_docs.md",
        "currency/README.md",
        "currency/contract.json",
        "currency/_code/lib.rs",
        "currency/_docs/code_docs.md",
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

/// `T-AF-PROJECT-MODEL-0001-R04-013`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn direct_module_names_reserved_entries_and_partial_layouts_fail_explicitly() {
    for name in [
        "PascalCase",
        "camelCase",
        "kebab-case",
        "two__words",
        "trailing_",
    ] {
        let fixture = paths(&["README.md", "contract.json", "_docs/modules_docs.md"]);
        let mut fixture = fixture;
        fixture.extend([
            format!("{name}/README.md"),
            format!("{name}/contract.json"),
            format!("{name}/_code/lib.rs"),
            format!("{name}/_docs/code_docs.md"),
        ]);
        assert!(
            kinds(&fixture).contains(&FilingViolationKind::InvalidModuleName),
            "{name} must fail Module naming"
        );
    }

    for path in ["_custom/item.txt", "_module/contract.json"] {
        let mut fixture = atomic_root();
        fixture.push(path.to_owned());
        assert!(
            kinds(&fixture).contains(&FilingViolationKind::UnknownReservedEntry),
            "{path} must fail the reserved namespace"
        );
    }

    for path in [
        "code/old.rs",
        "data/config.json",
        "docs/code_docs.md",
        "info/report.json",
        "assets/logo.svg",
    ] {
        let mut fixture = atomic_root();
        fixture.push(path.to_owned());
        assert!(
            kinds(&fixture).contains(&FilingViolationKind::UnknownModuleRootEntry),
            "{path} must fail the closed Module root"
        );
    }

    let retired_container = ["mo", "ds"].concat();
    let mut retired = atomic_root();
    retired.push(format!("{retired_container}/child/contract.json"));
    assert!(kinds(&retired).contains(&FilingViolationKind::UnknownModuleRootEntry));

    let mut removed_marker = atomic_root();
    removed_marker.extend(paths(&[
        "child/README.md",
        "child/_code/lib.rs",
        "child/_docs/code_docs.md",
    ]));
    assert!(kinds(&removed_marker).contains(&FilingViolationKind::UnknownModuleRootEntry));

    let mut collision = paths(&["README.md", "contract.json", "_docs/modules_docs.md"]);
    for name in ["child", "Child"] {
        collision.extend([
            format!("{name}/README.md"),
            format!("{name}/contract.json"),
            format!("{name}/_code/lib.rs"),
            format!("{name}/_docs/code_docs.md"),
        ]);
    }
    assert!(kinds(&collision).contains(&FilingViolationKind::CaseFoldCollision));
}

/// `T-AF-PROJECT-MODEL-0001-R04-014`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn ecosystem_scope_and_opacity_precede_contract_markers() {
    let opaque = EcosystemFilingProfile::new(
        "ECOSYSTEM-OPAQUE-FIXTURE-0001",
        vec![
            RegisteredRootEntry::new(
                "vendor",
                RootEntryKind::Directory,
                RootEntryClassification::EcosystemRequired,
            )
            .with_scope(EcosystemEntryScope::ProjectRoot)
            .with_opacity(true),
        ],
        Vec::new(),
        Vec::new(),
    );
    let profiles = FilingSystemProfiles::from_profiles(vec![opaque]).expect("profile validates");
    let mut fixture = atomic_root();
    fixture.push("vendor/contract.json".into());
    let model = analyze_project_filing_system(&fixture, &profiles);
    assert!(model.is_valid(), "{:?}", model.violations());
    assert_eq!(
        model.modules().len(),
        1,
        "opaque marker must not create a Module"
    );

    let mut nested_root_only = paths(&[
        "README.md",
        "contract.json",
        "_docs/modules_docs.md",
        "child/README.md",
        "child/contract.json",
        "child/_code/lib.rs",
        "child/_docs/code_docs.md",
        "child/vendor/file.txt",
    ]);
    nested_root_only.sort();
    assert!(
        kinds_with_profiles(&nested_root_only, &profiles)
            .contains(&FilingViolationKind::UnknownModuleRootEntry)
    );

    let underscore_profile = r#"{
      "$schema":"urn:fortress:schema:v2:filing-system-profiles",
      "schema_version":2,
      "profiles":[{"id":"ECOSYSTEM-X-0001","root_entries":[{"path":"_cache","kind":"DIRECTORY","classification":"ECOSYSTEM_REQUIRED","scope":"MODULE_ROOT","opaque":true}],"element_files":[],"mechanical_code_structures":[]}]
    }"#;
    assert!(FilingSystemProfiles::from_json_str(underscore_profile).is_err());
}

fn kinds_with_profiles(
    paths: &[String],
    profiles: &FilingSystemProfiles,
) -> Vec<FilingViolationKind> {
    analyze_project_filing_system(paths, profiles)
        .violations()
        .iter()
        .map(FilingSystemViolation::kind)
        .collect()
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
    assert_eq!(first.modules().len(), 42);
    assert_eq!(first.inventory().entries().len(), paths.len());
}

/// `T-AF-PROJECT-MODEL-0001-R04-015`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn current_governed_content_contains_only_the_authoritative_filing_vocabulary() {
    let root = repository_root();
    let observation = observe_repository(
        &root,
        &ObservationPolicy::new([".git", "target"]).expect("policy validates"),
    )
    .expect("repository observes");
    let retired = ["mo", "ds"].concat();
    let retired_title = ["Mo", "ds"].concat();
    let retired_catalog = format!("{retired}_docs");
    let mut violations = Vec::new();

    for file in observation.files() {
        let path = file.path();
        if path.split('/').any(|segment| segment == retired) {
            violations.push(format!("retired directory segment: {path}"));
        }
        let Ok(bytes) = fs::read(root.join(path)) else {
            violations.push(format!("unreadable governed file: {path}"));
            continue;
        };
        let Ok(content) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if content.contains(&retired_catalog)
            || content.contains(&retired_title)
            || content.contains(&retired)
        {
            violations.push(format!("retired filing vocabulary: {path}"));
        }
    }

    assert!(violations.is_empty(), "{violations:#?}");
}

/// `T-AF-PROJECT-MODEL-0001-R04-016`
/// Fortress requirement: AF-PROJECT-MODEL-0001-R04
#[test]
fn authoritative_module_index_is_recursive_wide_opaque_and_deterministic() {
    let mut observed = atomic_root();
    for sibling in 0..32 {
        observed.extend(paths(&[
            &format!("sibling_{sibling:03}/README.md"),
            &format!("sibling_{sibling:03}/contract.json"),
            &format!("sibling_{sibling:03}/_code/lib.rs"),
        ]));
    }
    observed.extend(paths(&[
        "sibling_000/deep_child/README.md",
        "sibling_000/deep_child/contract.json",
        "sibling_000/deep_child/_code/lib.rs",
        "sibling_000/deep_child/grandchild/README.md",
        "sibling_000/deep_child/grandchild/contract.json",
        "sibling_000/deep_child/grandchild/_code/lib.rs",
        "vendor/contract.json",
        "vendor/nested/contract.json",
    ]));
    let build = || {
        CanonicalModuleIndex::from_paths(observed.iter().map(String::as_str), |module, name| {
            module.is_empty() && name == "vendor"
        })
    };
    let first = build();
    let second = build();
    assert_eq!(first, second);
    assert_eq!(first.entries().len(), 35);
    assert_eq!(first.get("").expect("root").children().len(), 32);
    assert_eq!(
        first
            .get("sibling_000/deep_child")
            .expect("deep child")
            .parent(),
        Some("sibling_000")
    );
    assert_eq!(
        first.owning_module("sibling_000/deep_child/grandchild/_code/lib.rs"),
        "sibling_000/deep_child/grandchild"
    );
    assert!(first.get("vendor").is_none());
    assert_eq!(
        first
            .get("sibling_000")
            .and_then(|module| module.element_path("code")),
        Some("sibling_000/_code")
    );
}
