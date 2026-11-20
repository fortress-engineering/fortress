//! Equivalence and integrity controls; numerical timings are diagnostic only.
use fortress_core::audit::{
    compile_repository_certification_bundle, compile_repository_projection_bundle,
    prepare_repository_certification_source,
};
use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
};
use fortress_core::certification::{
    EvidenceResult, RustSuiteExecution, certification_source_digest,
};
use fortress_core::runtime_storage::StoragePolicy;
use fortress_core::session::{Session, SessionOptions, SourceDelta};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[path = "resident_campaign.rs"]
mod resident_campaign;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn explicit_campaign_accounts_preserve_populations_and_production_defaults() {
    use resident_campaign::{Campaign, Scenario, Selection};
    let parse =
        |values: &[&str]| Campaign::from_arguments(values.iter().map(|value| (*value).to_owned()));
    let default_limit = SessionOptions::default().limits.max_accounted_bytes;
    let baseline = parse(&[]).unwrap();
    assert_eq!(baseline.accounted_bytes(), default_limit);
    let configured = parse(&["--core", "--accounted-bytes", "34359738368"]).unwrap();
    for campaign in [baseline, configured] {
        assert!(campaign.is_full());
        assert!(campaign.is_core());
        assert_eq!(campaign.actual_samples(), 6);
        assert_eq!(campaign.expected_comparisons(), 30);
        assert_eq!(campaign.fixture_samples(34), 4);
        assert_eq!(campaign.fixture_samples(33), 4);
        assert_eq!(campaign.name(), "registered_core_equivalence_v2");
    }
    let selection = Selection::registered().unwrap();
    assert_eq!(selection.core_count(), 30);
    assert_eq!(selection.fixture_sizes, [32, 128, 512]);
    assert_eq!(
        selection.actual,
        [
            Scenario::BaselineRefresh,
            Scenario::PathPredicateBody,
            Scenario::ReadBudgetBody,
            Scenario::InterproceduralDependency,
            Scenario::AuthorityInvalidation,
            Scenario::BaselineAfterCandidates,
        ]
    );
    assert_eq!(
        selection.independent,
        [
            Scenario::LocalBody,
            Scenario::Signature,
            Scenario::DependencyInput,
            Scenario::UnavailablePreparation,
        ]
    );
    assert_eq!(
        selection.graph,
        [
            Scenario::CalleeBody,
            Scenario::FilesystemEffect,
            Scenario::TransitiveInvalidation,
            Scenario::UnresolvedRelationship,
        ]
    );
    assert_eq!(selection.lifecycle_operations.values().sum::<usize>(), 100);
    assert_eq!(
        selection.differential_corpora,
        [("candidate".into(), 1_000), ("resident".into(), 1_000)].into()
    );
    let historical = parse(&["--historical-300"]).unwrap();
    assert!(!historical.is_core());
    assert_eq!(historical.expected_comparisons(), 300);
    assert_eq!(historical.name(), "historical_300_observation");
    let endurance = parse(&["--endurance"]).unwrap();
    assert!(endurance.is_endurance());
    assert_eq!(endurance.expected_comparisons(), 0);
    let registered_fixtures = parse(&["--registered-fixture-probe"]).unwrap();
    assert!(!registered_fixtures.is_core());
    assert!(registered_fixtures.uses_registered_fixtures());
    assert_eq!(registered_fixtures.actual_samples(), 0);
    assert_eq!(registered_fixtures.expected_comparisons(), 24);
    assert_eq!(configured.accounted_bytes(), 32 * 1024 * 1024 * 1024);
    assert_eq!(
        SessionOptions::default().limits.max_accounted_bytes,
        default_limit
    );
    let development = parse(&["--development-probe"]).unwrap();
    assert!(!development.is_full());
    assert_eq!(development.expected_comparisons(), 8);
    let fixtures = parse(&["--fixture-development-probe"]).unwrap();
    assert!(!fixtures.is_full());
    assert_eq!(fixtures.actual_samples(), 0);
    assert_eq!(fixtures.fixture_samples(34), 1);
    assert_eq!(fixtures.expected_comparisons(), 6);
    for values in [
        vec!["--accounted-bytes"],
        vec!["--accounted-bytes", "0"],
        vec!["--accounted-bytes", "68719476737"],
        vec!["--accounted-bytes", "18446744073709551616"],
        vec!["--accounted-bytes", "-1"],
        vec!["--accounted-bytes", "NaN"],
        vec!["--accounted-bytes", "1", "--accounted-bytes", "2"],
        vec!["--development-probe", "--fixture-development-probe"],
        vec!["--unknown"],
    ] {
        assert!(parse(&values).is_err(), "unexpected admission: {values:?}");
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn optimized_dependency_profiles_preserve_debug_and_overflow_checks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("_data/Cargo.toml")).unwrap();
    let profiles = toml::from_str::<toml::Value>(&source).unwrap();
    for profile in ["dev", "test"] {
        for package in ["fortress-core", "serde_json", "sha2", "syn", "proc-macro2"] {
            let configuration = &profiles["profile"][profile]["package"][package];
            assert_eq!(configuration["opt-level"].as_integer(), Some(3));
            assert_eq!(configuration["debug-assertions"].as_bool(), Some(true));
            assert_eq!(configuration["overflow-checks"].as_bool(), Some(true));
        }
    }
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
    storage: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "fortress-projection-controls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let root = base.join("repository");
        let storage = base.join("storage");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::create_dir(&storage).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='projection_fixture'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"),"pub fn leaf(value:i32)->i32 { value + 1 }\npub fn caller(value:i32)->i32 { leaf(value) }\n").unwrap();
        let proposal = discover_repository_bootstrap(
            &root,
            &BootstrapDiscoveryOptions::new(
                Some("PF-PROJECTION-FIXTURE".into()),
                Some("Projection Fixture".into()),
            ),
        )
        .unwrap();
        apply_repository_bootstrap(&root, &proposal, false).unwrap();
        let profile = "engine/standard_registry/_data/cert_full_snapshot_v1.json";
        let profile_path = root.join(profile);
        fs::create_dir_all(profile_path.parent().unwrap()).unwrap();
        fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(profile),
            profile_path,
        )
        .unwrap();
        Self {
            base,
            root,
            storage,
        }
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
    fn failed_execution(&self) -> RustSuiteExecution {
        let source = prepare_repository_certification_source(&self.root).unwrap();
        RustSuiteExecution {
            executor: "explicit-negative-fixture".into(),
            executor_version: "1".into(),
            toolchain: "fixture-toolchain".into(),
            certification_source_digest: source.digest,
            test_inventory_digest: source.test_inventory_digest,
            canonical_unfiltered: false,
            passed: false,
            eligible_test_ids: source.eligible_test_ids,
            ignored_test_ids: source.ignored_test_ids,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn transient_prepared_cold_and_evicted_projections_are_identical() {
    let fixture = Fixture::new();
    let mut session = Session::open(&fixture.root, &fixture.storage, Fixture::options()).unwrap();
    let original = session.acquire_generation().unwrap();
    let history = original.canonical_artifacts().clone();
    for source in [
        "pub fn leaf(value:i32)->i32 { value + 1 }\npub fn caller(value:i32)->i32 { leaf(value) }\n",
        "pub fn leaf(value:i32)->i32 { if value>0 { value } else { 0 } }\npub fn caller(value:i32)->i32 { leaf(value) }\n",
        "pub fn leaf(value:i32)->i32 { opaque!(value) }\npub fn caller(value:i32)->i32 { leaf(value) }\n",
    ] {
        fs::write(fixture.root.join("src/lib.rs"), source).unwrap();
        let one_shot = compile_repository_projection_bundle(&fixture.root).unwrap();
        let prepared = session.refresh(&SourceDelta::default()).unwrap();
        assert_eq!(
            one_shot.projections,
            *prepared.generation.canonical_artifacts()
        );
        assert_eq!(
            one_shot.audit_json,
            prepared.generation.audit().to_json_pretty().unwrap()
        );
        assert_eq!(
            one_shot.source_ref,
            certification_source_digest(prepared.generation.source_view().files())
        );
        let cold = session
            .evaluate_view_cold(prepared.generation.source_view().clone())
            .unwrap();
        assert_eq!(one_shot.projections, *cold.generation.canonical_artifacts());
        assert_eq!(cold.work.program.reused_bodies, 0);
        assert_eq!(cold.work.semantic.reused_domain_rounds, 0);
        assert_eq!(cold.work.state_effect.reused_direct_units, 0);
        drop(cold);
        drop(prepared);
        session.evict_preparation().unwrap();
        assert_eq!(
            one_shot.projections,
            *session
                .refresh(&SourceDelta::default())
                .unwrap()
                .generation
                .canonical_artifacts()
        );
        let measured = one_shot
            .phase_measurements
            .iter()
            .map(|p| p.phase)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(measured.len(), one_shot.phase_measurements.len());
        assert!(measured.contains("program_semantics"));
        assert!(measured.contains("governance_composition"));
        assert!(measured.contains("canonical_serialization"));
    }
    assert_eq!(original.canonical_artifacts(), &history);
    session.close().unwrap();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn transient_certification_preserves_all_products_without_freshening_execution() {
    let fixture = Fixture::new();
    let execution = fixture.failed_execution();
    let bundle = compile_repository_certification_bundle(&fixture.root, execution.clone()).unwrap();
    // Empty authored test scope can have a vacuous aggregate. The failed
    // execution itself must remain failed and cannot create passing test proof.
    let nodes = bundle.products().evidence_graph.nodes();
    let suite = nodes
        .iter()
        .filter(|node| node.kind() == "rust_workspace_suite_execution")
        .collect::<Vec<_>>();
    assert_eq!(suite.len(), 1);
    assert_eq!(suite[0].result(), EvidenceResult::Fail);
    assert!(
        !nodes
            .iter()
            .any(|node| node.kind() == "rust_test_execution"
                && node.result() == EvidenceResult::Pass)
    );
    let mut options = Fixture::options();
    options.suite_execution = Some(execution);
    let mut session = Session::open(&fixture.root, &fixture.storage, options).unwrap();
    let head = session.acquire_generation().unwrap();
    for (path, bytes) in bundle.projections() {
        assert_eq!(head.canonical_artifacts().get(path), Some(bytes));
    }
    for (path, bytes) in [
        (
            "_info/evidence_graph.json",
            bundle.products().evidence_graph.to_json_pretty().unwrap(),
        ),
        (
            "_info/certification.json",
            bundle.products().certification.to_json_pretty().unwrap(),
        ),
        (
            "_info/verified_behavioral_flow_graph.json",
            bundle.products().verified_bfg.to_json_pretty().unwrap(),
        ),
    ] {
        assert_eq!(head.canonical_artifacts().get(path), Some(&bytes));
    }
    assert!(!bundle.phase_measurements().is_empty());
    session.close().unwrap();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn streaming_integrity_controls_preserve_fail_closed_publication() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-I", "-B"])
        .arg(root.join("testing/_code/performance_controls.py"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn candidate_base_reuses_only_an_exact_canonical_session_endpoint() {
    use fortress_core::candidate::{CandidateRequest, CandidateWorkspace};
    use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
    use fortress_core::migration_adapter::CanonicalMigrationAuthority;
    use fortress_core::migration_governance::MigrationOperation;
    use std::sync::atomic::AtomicBool;
    let fixture = Fixture::new();
    let before = fs::read(fixture.root.join("src/lib.rs")).unwrap();
    let cold = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let mut options = Fixture::options();
    options.suite_execution = Some(fixture.failed_execution());
    let mut resident = CandidateWorkspace::open(&fixture.root, &fixture.storage, options).unwrap();
    assert_eq!(
        resident.base_state().digest().unwrap(),
        cold.base_state().digest().unwrap()
    );
    assert_eq!(resident.base_source_ref(), cold.base_source_ref());
    assert_eq!(resident.context_ref(), cold.context_ref());
    let authority = CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let operations=vec![MigrationOperation::ReplaceFile{path:"src/lib.rs".into(),preimage:before.clone(),postimage:b"pub fn leaf(value:i32)->i32 { value }\npub fn caller(value:i32)->i32 { leaf(value) }\n".to_vec()}];
    let request = CandidateRequest {
        schema_version: 1,
        base_source_ref: resident.base_source_ref().into(),
        context_ref: resident.context_ref().into(),
        operations,
        comparison_context: fortress_core::state_governance::ComparisonContext::default(),
    };
    let mut cold = cold;
    let fast = resident
        .evaluate(
            "performance_client",
            "prepared",
            request.clone(),
            &authority,
            &AtomicBool::new(false),
        )
        .unwrap();
    let slow = cold
        .evaluate(
            "performance_client",
            "cold",
            request,
            &authority,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(fast.evaluation_ref(), slow.evaluation_ref());
    let value: serde_json::Value =
        serde_json::from_slice(&fast.to_canonical_bytes().unwrap()).unwrap();
    assert_eq!(value["actual_state"], false);
    assert_eq!(fs::read(fixture.root.join("src/lib.rs")).unwrap(), before);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn failed_candidate_acceleration_preserves_canonical_input_error_precedence() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("_data")).unwrap();
    fs::write(fixture.root.join("_data/function_contracts.json"), b"{").unwrap();
    let cold = fortress_core::candidate::CandidateWorkspace::open_cold(&fixture.root)
        .err()
        .expect("malformed contract must fail canonical loading");
    let mut options = Fixture::options();
    options.limits.max_accounted_bytes = 0;
    let accelerated = fortress_core::candidate::CandidateWorkspace::open(
        &fixture.root,
        &fixture.storage,
        options,
    )
    .err()
    .expect("invalid inputs remain refused");
    assert_eq!(accelerated.code, cold.code);
    assert_eq!(accelerated.message, cold.message);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R25-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R25
#[test]
fn same_evaluation_reference_assets_match_independent_canonical_capture() {
    let fixture = Fixture::new();
    let contract = fixture.root.join("contract.json");
    let mut parent: serde_json::Value =
        serde_json::from_slice(&fs::read(&contract).unwrap()).unwrap();
    let mut child = parent.clone();
    child.as_object_mut().unwrap().remove("ecosystem");
    child["id"] = serde_json::json!("AF-PROJECTION-CHILD");
    child["display_name"] = serde_json::json!("Projection Child");
    child["provides"] =
        serde_json::json!([{"id":"CAP-PROJECTION-CHILD","version":"0.1.0","visibility":"project"}]);
    fs::create_dir(fixture.root.join("child")).unwrap();
    fs::write(fixture.root.join("child/README.md"), "# Projection Child\n").unwrap();
    fs::write(
        fixture.root.join("child/contract.json"),
        serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(child.clone())
            .unwrap()
            .to_canonical_json()
            .unwrap(),
    )
    .unwrap();
    parent["requires"] = serde_json::json!([{"provider":"AF-PROJECTION-CHILD","capability":"CAP-PROJECTION-CHILD","version":"^0.1.0"}]);
    fs::write(
        &contract,
        serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(parent.clone())
            .unwrap()
            .to_canonical_json()
            .unwrap(),
    )
    .unwrap();
    if !fixture.root.join("README.md").exists() {
        fs::write(fixture.root.join("README.md"), "# Projection Fixture\n").unwrap();
    }
    for links in [
        "[source](src/lib.rs)\n",
        "[missing](src/absent.rs)\n",
        "[anchor](README.md#absent)\n",
    ] {
        let readme = fixture.root.join("README.md");
        let original = fs::read_to_string(&readme).unwrap();
        fs::write(&readme, format!("{original}\n{links}")).unwrap();
        let (shared, _) = fortress_core::audit::capture_finding_inputs(&fixture.root)
            .unwrap_or_else(|cause| {
                let diagnostics =
                    fortress_core::candidate::CandidateWorkspace::open_cold(&fixture.root).err();
                panic!("{cause}; independent admission diagnostics: {diagnostics:?}");
            });
        let independent =
            fortress_core::transition_load::load_comparison_state(&fixture.root, "current")
                .unwrap();
        assert_eq!(
            serde_json::to_value(&shared.assets).unwrap(),
            serde_json::to_value(&independent.assets).unwrap()
        );
        assert!(!shared.assets.unwrap().reference_facts.unwrap().is_empty());
        fs::write(readme, original).unwrap();
    }
    parent["requires"] = serde_json::json!([]);
    fs::write(
        contract,
        serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(parent.clone())
            .unwrap()
            .to_canonical_json()
            .unwrap(),
    )
    .unwrap();
    let (shared, _) =
        fortress_core::audit::capture_finding_inputs(&fixture.root).unwrap_or_else(|cause| {
            let diagnostics =
                fortress_core::candidate::CandidateWorkspace::open_cold(&fixture.root).err();
            panic!("{cause}; independent admission diagnostics: {diagnostics:?}");
        });
    let independent =
        fortress_core::transition_load::load_comparison_state(&fixture.root, "current").unwrap();
    assert_eq!(
        serde_json::to_value(&shared.assets).unwrap(),
        serde_json::to_value(&independent.assets).unwrap()
    );
    assert!(shared.assets.unwrap().reference_facts.unwrap().is_empty());
}
