//! Exact hypothetical evaluation and actual-state reconciliation controls.
use fortress_core::candidate::HypotheticalEvaluation;
use fortress_core::candidate::{CandidateRequest, CandidateWorkspace, NoActualExecution};
use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::{CanonicalMigrationAuthority, CanonicalMigrationEvaluator};
use fortress_core::migration_governance::{MigrationEvaluator, MigrationOperation as Op};
use fortress_core::runtime_storage::StoragePolicy;
use fortress_core::session::SessionOptions;
use fortress_core::state_governance::ComparisonContext;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    base: PathBuf,
    root: PathBuf,
    storage: PathBuf,
}
impl Fixture {
    fn with_violation() -> Self {
        let fixture = Self::new(true);
        let before = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
        let owner = CanonicalMigrationEvaluator
            .evaluate(&before)
            .unwrap()
            .ownership["src/lib.rs"]
            .clone();
        let (original_path, mut contract) = before
            .iter()
            .filter_map(|(p, b)| {
                serde_json::from_slice::<serde_json::Value>(b)
                    .ok()
                    .map(|v| (p, v))
            })
            .find(|(_, v)| v["id"].as_str() == Some(&owner))
            .unwrap();
        let mut path = original_path.to_owned();
        if owner.starts_with("PF-") {
            path = "_data/logical_modules/overlay_semantics/contract.json".into();
            contract = serde_json::json!({"id":"AF-OVERLAY-SEMANTICS-0001","display_name":"Overlay Semantics","provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]});
            let configuration_path = fortress_core::control_layout::ControlLayout::standard()
                .role_path(fortress_core::control_layout::ControlRole::ProjectConfiguration)
                .unwrap()
                .to_owned();
            let mut configuration: serde_json::Value =
                serde_json::from_slice(&fs::read(fixture.root.join(&configuration_path)).unwrap())
                    .unwrap();
            configuration["logical_modules"].as_array_mut().unwrap().push(serde_json::json!({"module":"AF-OVERLAY-SEMANTICS-0001","contract":path,"parent":owner,"bindings":[{"kind":"directory","path":"src"}]}));
            fs::write(
                fixture.root.join(configuration_path),
                serde_json::to_vec_pretty(&configuration).unwrap(),
            )
            .unwrap();
        }
        contract["$schema"] = "urn:fortress:schema:v3:module-contract".into();
        contract["schema_version"] = 3.into();
        contract["guarantees"] = serde_json::json!([]);
        contract["semantic_policy"] = serde_json::json!({"default":"UNDECLARED","capabilities":{"allow":[],"deny":["filesystem","network.client"]},"effects":{"allow":[],"deny":[]}});
        let contract: fortress_core::contract_coherency::ModuleContract =
            serde_json::from_value(contract).expect("valid explicit Module policy fixture");
        fs::create_dir_all(fixture.root.join(&path).parent().unwrap()).unwrap();
        fs::write(
            fixture.root.join(&path),
            contract.to_canonical_json().unwrap(),
        )
        .unwrap();
        fs::write(
            fixture.root.join("src/lib.rs"),
            b"pub fn value() { let _ = std::fs::read(\"input\"); }\n",
        )
        .unwrap();
        fixture
    }
    fn new(governed: bool) -> Self {
        let base = std::env::temp_dir().join(format!(
            "fortress-overlay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root = base.join("repository");
        let storage = base.join("storage");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&storage).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"overlay_fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), b"pub fn value() -> u32 { 1 }\n").unwrap();
        if governed {
            let proposal = fortress_core::bootstrap::discover_repository_bootstrap(
                &root,
                &fortress_core::bootstrap::BootstrapDiscoveryOptions::new(
                    Some("PF-OVERLAY-FIXTURE".into()),
                    Some("Overlay Fixture".into()),
                ),
            )
            .unwrap();
            fortress_core::bootstrap::apply_repository_bootstrap(&root, &proposal, false).unwrap();
        }
        Self {
            base,
            root,
            storage,
        }
    }
    fn open(&self) -> CandidateWorkspace {
        CandidateWorkspace::open(
            &self.root,
            &self.storage,
            SessionOptions {
                storage_policy: StoragePolicy {
                    reserve_bytes: 0,
                    retain_shared_compiler: false,
                    ..StoragePolicy::default()
                },
                ..SessionOptions::default()
            },
        )
        .unwrap()
    }
    fn replace(&self, path: &str, bytes: &[u8]) -> Op {
        Op::ReplaceFile {
            path: path.into(),
            preimage: fs::read(self.root.join(path)).unwrap(),
            postimage: bytes.to_vec(),
        }
    }
}

fn anchored_fixture() -> (
    Fixture,
    fortress_core::state_governance::ComparisonState,
    fortress_core::finding_governance::FindingGovernanceDocument,
    String,
) {
    let fixture = Fixture::with_violation();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let original = CanonicalMigrationEvaluator.evaluate(&source).unwrap().state;
    let audit = fortress_core::audit::audit_repository(&fixture.root).unwrap();
    let raw = audit
        .findings()
        .iter()
        .find(|f| f.rule_id() == "ARCH-SEMANTIC-001")
        .expect("supported original semantic violation")
        .clone();
    let id = raw.finding_id().to_owned();
    let mut governance =
        fortress_core::finding_governance::FindingGovernanceDocument::empty_current();
    governance
        .create_anchored_baseline(
            "STD-FORTRESS-ENGINEERING",
            raw.standard_edition(),
            std::slice::from_ref(&raw),
            fortress_core::state_governance::finding_anchors(&original, std::slice::from_ref(&raw))
                .unwrap(),
        )
        .unwrap();
    let path = fortress_core::control_layout::ControlLayout::standard()
        .role_path(fortress_core::control_layout::ControlRole::FindingGovernance)
        .unwrap()
        .to_owned();
    fs::create_dir_all(fixture.root.join(&path).parent().unwrap()).unwrap();
    fs::write(
        fixture.root.join(path),
        governance.to_canonical_json().unwrap(),
    )
    .unwrap();
    (fixture, original, governance, id)
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-018`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn comparable_remediation_uses_original_evidence_without_retiring_history() {
    let (fixture, original, governance, id) = anchored_fixture();
    let bytes = governance.to_canonical_json().unwrap();
    let mut work = CandidateWorkspace::open_cold(&fixture.root)
        .unwrap()
        .with_original_states(vec![original.clone()])
        .unwrap();
    let proposal = evaluate(
        &mut work,
        "fix",
        vec![fixture.replace("src/lib.rs", b"pub fn value() {}\n")],
    );
    let value: serde_json::Value =
        serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
    let resolution = value["finding_lifecycle"]["baseline_retirement_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["finding_id"] == id)
        .unwrap();
    assert_eq!(resolution["outcome"], "RESOLVED", "{value}");
    assert_eq!(
        resolution["comparison_basis"]["from_state"],
        original.digest().unwrap()
    );
    assert!(!resolution["proof_refs"].as_array().unwrap().is_empty());
    let path = fortress_core::control_layout::ControlLayout::standard()
        .role_path(fortress_core::control_layout::ControlRole::FindingGovernance)
        .unwrap()
        .to_owned();
    assert_eq!(fs::read_to_string(fixture.root.join(path)).unwrap(), bytes);
    assert_eq!(governance.baseline().unwrap().active_entries().len(), 1);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-019`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn weakened_policy_unknown_coverage_and_missing_history_do_not_resolve() {
    let (fixture, original, _, id) = anchored_fixture();
    let mut work = CandidateWorkspace::open_cold(&fixture.root)
        .unwrap()
        .with_original_states(vec![original])
        .unwrap();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let owner = CanonicalMigrationEvaluator
        .evaluate(&source)
        .unwrap()
        .ownership["src/lib.rs"]
        .clone();
    let (path, mut contract) = source
        .iter()
        .filter_map(|(p, b)| {
            serde_json::from_slice::<serde_json::Value>(b)
                .ok()
                .map(|v| (p, v))
        })
        .find(|(_, v)| v["id"].as_str() == Some(&owner))
        .unwrap();
    contract["semantic_policy"]["capabilities"]["deny"] = serde_json::json!(["network.client"]);
    let contract: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(contract).unwrap();
    let weakened = evaluate(
        &mut work,
        "weaken",
        vec![fixture.replace(path, contract.to_canonical_json().unwrap().as_bytes())],
    );
    let unknown = evaluate(
        &mut work,
        "unknown",
        vec![fixture.replace("src/lib.rs", b"pub fn value() { unknown_external(); }\n")],
    );
    let mut missing = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let missing = evaluate(
        &mut missing,
        "missing",
        vec![fixture.replace("src/lib.rs", b"pub fn value() {}\n")],
    );
    for proposal in [&weakened, &unknown, &missing] {
        let value: serde_json::Value =
            serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
        let evidence = value["finding_lifecycle"]["baseline_retirement_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["finding_id"] == id)
            .unwrap_or_else(|| {
                panic!(
                    "missing unresolved retirement record: {}",
                    value["finding_lifecycle"]["errors"]
                )
            });
        assert_ne!(evidence["outcome"], "RESOLVED", "{value}");
    }
    assert!(weakened.transition().semantic_deltas.iter().any(|delta| {
        delta.category == "policy"
            && delta.change == fortress_core::state_governance::Change::Weakened
    }));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-020`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn reintroduced_prediction_keeps_raw_violation_and_blocks_progressive_enforcement() {
    let (fixture, original, mut governance, id) = anchored_fixture();
    let violation = fs::read(fixture.root.join("src/lib.rs")).unwrap();
    fs::write(fixture.root.join("src/lib.rs"), b"pub fn value() {}\n").unwrap();
    let current = CanonicalMigrationEvaluator
        .evaluate(&CanonicalMigrationEvaluator.observe(&fixture.root).unwrap())
        .unwrap()
        .state;
    let evidence = fortress_core::state_governance::assess_retirements(
        &original,
        &current,
        &governance,
        &ComparisonContext::default(),
    )
    .unwrap();
    assert_eq!(
        evidence[0].outcome,
        fortress_core::finding_governance::RetirementOutcome::Resolved
    );
    governance.prune_with_evidence(&evidence).unwrap();
    let path = fortress_core::control_layout::ControlLayout::standard()
        .role_path(fortress_core::control_layout::ControlRole::FindingGovernance)
        .unwrap()
        .to_owned();
    let bytes = governance.to_canonical_json().unwrap();
    fs::write(fixture.root.join(&path), &bytes).unwrap();
    let mut work = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let proposal = evaluate(
        &mut work,
        "reintroduce",
        vec![fixture.replace("src/lib.rs", &violation)],
    );
    let value: serde_json::Value =
        serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
    let finding = value["finding_lifecycle"]["predicted_governance"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding_id"] == id)
        .unwrap();
    assert_eq!(finding["lifecycle"], "REINTRODUCED");
    assert_eq!(finding["raw_conformance"], "FAIL");
    assert_eq!(finding["enforcement"], "BLOCKING");
    assert_eq!(fs::read_to_string(fixture.root.join(path)).unwrap(), bytes);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-021`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn physical_repository_replacement_and_ambiguous_history_are_refused() {
    let fixture = Fixture::new(true);
    let mut work = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let original = work.base_state().clone();
    assert!(
        CandidateWorkspace::open_cold(&fixture.root)
            .unwrap()
            .with_original_states(vec![original.clone(), original])
            .is_err()
    );
    let before = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let request = request(&work, vec![]);
    fs::rename(&fixture.root, fixture.base.join("preserved-original")).unwrap();
    fs::create_dir(&fixture.root).unwrap();
    for (path, bytes) in &before {
        let target = fixture.root.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    assert_eq!(
        work.evaluate(
            "client",
            "replacement",
            request,
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "SOURCE_DRIFT"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-024`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn cancellation_at_model_completion_retains_no_candidate_or_actual_generation() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let before = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let control = work.session_control().unwrap();
    work.set_progress_observer(move |stage| {
        if stage == fortress_core::session::SessionStage::ModelsPrepared {
            control.cancel();
        }
    })
    .unwrap();
    let req = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn changed() {}\n")],
    );
    assert_eq!(
        work.evaluate(
            "client",
            "cancelled",
            req.clone(),
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "CANCELLED"
    );
    work.set_progress_observer(|_| {}).unwrap();
    work.evaluate(
        "client",
        "cancelled",
        req,
        &authority(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        before
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-025`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn concurrent_edit_at_model_completion_is_preserved_and_invalidates_proposal() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let path = fixture.root.join("src/lib.rs");
    work.set_progress_observer(move |stage| {
        if stage == fortress_core::session::SessionStage::ModelsPrepared {
            fs::write(&path, b"pub fn independently_edited() {}\n").unwrap();
        }
    })
    .unwrap();
    let req = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn changed() {}\n")],
    );
    assert_eq!(
        work.evaluate(
            "client",
            "concurrent",
            req,
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "STALE_BASE"
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).unwrap(),
        b"pub fn independently_edited() {}\n"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-026`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn invalid_source_cannot_hide_under_nonrecursive_proposal_roots() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let req = request(&work, vec![]);
    let role = fortress_core::control_layout::ControlLayout::standard()
        .hypothetical_proposal_path(&format!("sha256:{}", "a".repeat(64)))
        .unwrap();
    let directory = fixture.root.join(role).parent().unwrap().to_owned();
    fs::create_dir_all(&directory).unwrap();
    let hidden = directory.join("hidden.rs");
    fs::write(&hidden, b"pub fn hidden() {}\n").unwrap();
    let failure = work
        .evaluate(
            "client",
            "hidden",
            req,
            &authority(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
    assert!(
        failure.message.contains("unregistered control file"),
        "{failure}"
    );
    assert!(CandidateWorkspace::open_cold(&fixture.root).is_err());
    assert_eq!(fs::read(hidden).unwrap(), b"pub fn hidden() {}\n");
}

fn registered_public_schemas() -> Vec<serde_json::Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    manifest["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(root.join(p.as_str().unwrap())).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-022`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn public_candidate_serializers_and_rpc_validate_against_registered_schemas() {
    let schemas = registered_public_schemas();
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let req = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn value() -> u32 { 2 }\n")],
    );
    let request_value = serde_json::to_value(&req).unwrap();
    let proposal = work
        .evaluate(
            "client",
            "schemas",
            req,
            &authority(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let proposal_value: serde_json::Value =
        serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
    assert!(!proposal_value["authorization_error"].is_null());
    let reconciliation = fortress_core::candidate::inspect_post_write(
        &fixture.root,
        &proposal,
        &AtomicBool::new(false),
    )
    .unwrap();
    let service = fortress_core::query::QueryService::new(fortress_core::query::QueryInput::empty(
        proposal_value["base_subject"].as_str().unwrap().into(),
    ))
    .unwrap()
    .with_candidates(vec![proposal])
    .unwrap();
    let rpc_request = fortress_core::query::QueryRequest {
        protocol_version: 5,
        request_id: "schema".into(),
        method: "candidate".into(),
        state_ref: None,
        context_ref: None,
        parameters: serde_json::json!({"candidate_ref":null}),
    };
    let response = service.execute(&rpc_request, &AtomicBool::new(false));
    assert!(response.error.is_none());
    for (schema_id, value) in [
        (
            "urn:fortress:derived:v2:comparison-state",
            serde_json::to_value(work.base_state()).unwrap(),
        ),
        (
            "urn:fortress:derived:v2:authority-snapshot",
            serde_json::to_value(
                fortress_core::authority_load::capture_authority_snapshot(&fixture.root).unwrap(),
            )
            .unwrap(),
        ),
        ("urn:fortress:derived:v1:candidate-request", request_value),
        (
            "urn:fortress:derived:v1:hypothetical-evaluation",
            proposal_value,
        ),
        (
            "urn:fortress:derived:v1:candidate-reconciliation",
            serde_json::to_value(reconciliation).unwrap(),
        ),
        (
            "urn:fortress:protocol:v5:query-request",
            serde_json::to_value(rpc_request).unwrap(),
        ),
        (
            "urn:fortress:protocol:v5:query-response",
            serde_json::to_value(response).unwrap(),
        ),
    ] {
        let schema = schemas.iter().find(|s| s["$id"] == schema_id).unwrap();
        let resources = schemas.iter().map(|s| {
            (
                s["$id"].as_str().unwrap().to_owned(),
                jsonschema::Resource::from_contents(s.clone()).unwrap(),
            )
        });
        let validator = jsonschema::options()
            .with_resources(resources)
            .build(schema)
            .unwrap();
        validator
            .validate(&value)
            .unwrap_or_else(|error| panic!("{schema_id}: {error}"));
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-023`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn migrate_owns_writes_and_in_progress_source_cannot_reconcile() {
    use fortress_core::migration_governance::{
        BoundaryPhase, MigrationError, MigrationOptions, MigrationServices, MutationBoundary,
        MutationObserver, apply_migration, preview_migration,
    };
    struct Reader<'a> {
        root: &'a std::path::Path,
        proposal: &'a HypotheticalEvaluation,
        checks: AtomicU64,
    }
    impl MutationObserver for Reader<'_> {
        fn boundary(
            &self,
            _: u64,
            boundary: MutationBoundary,
            phase: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if boundary == MutationBoundary::Evacuate && phase == BoundaryPhase::Before {
                let error = fortress_core::candidate::inspect_post_write(
                    self.root,
                    self.proposal,
                    &AtomicBool::new(false),
                )
                .unwrap_err();
                assert!(error.message.contains("MIGRATION_IN_PROGRESS"), "{error}");
                self.checks.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let op = fixture.replace("src/lib.rs", b"pub fn migrated() {}\n");
    let proposal = evaluate(&mut work, "migrate", vec![op.clone()]);
    let permit = work
        .authorize_before_write("client", "migrate", &authority(), &AtomicBool::new(false))
        .unwrap();
    let before = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let plan = preview_migration(
        &CanonicalMigrationEvaluator,
        &authority(),
        &before,
        vec![op],
        MigrationOptions::default(),
    )
    .unwrap()
    .plan;
    let storage = fortress_core::runtime_storage::MigrationStorage::new(
        fixture.storage.clone(),
        StoragePolicy {
            reserve_bytes: 0,
            ..StoragePolicy::default()
        },
    )
    .unwrap();
    let observer = Reader {
        root: &fixture.root,
        proposal: &proposal,
        checks: AtomicU64::new(0),
    };
    let applied = apply_migration(
        &fixture.root,
        &plan,
        &MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &authority(),
            resources: &storage,
            observer: &observer,
        },
    )
    .unwrap();
    assert!(!applied.receipt.to_canonical_bytes().unwrap().is_empty());
    assert!(observer.checks.load(Ordering::Relaxed) > 0);
    let result = work
        .reconcile(
            "client",
            "migrate",
            Some(&permit),
            &authority(),
            &NoActualExecution,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(result.status(), "EXACT_MATCH_UNVERIFIED");
    assert!(!result.actual_state());
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn authority() -> CanonicalMigrationAuthority<'static, UnmediatedHost, NoGrantValidator> {
    CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    }
}
fn request(work: &CandidateWorkspace, operations: Vec<Op>) -> CandidateRequest {
    CandidateRequest {
        schema_version: 1,
        base_source_ref: work.base_source_ref().into(),
        context_ref: work.context_ref().into(),
        operations,
        comparison_context: ComparisonContext::default(),
    }
}
fn evaluate(
    work: &mut CandidateWorkspace,
    id: &str,
    operations: Vec<Op>,
) -> HypotheticalEvaluation {
    let req = request(work, operations);
    work.evaluate("client", id, req, &authority(), &AtomicBool::new(false))
        .unwrap()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn hypothetical_cannot_discharge_current_obligation() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let proposal = evaluate(&mut work, "not_actual", vec![]);
    let bytes = proposal.to_canonical_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(fortress_core::state_view::StateView::from_json_str(text).is_err());
    assert!(fortress_core::state_governance::ComparisonState::from_json_str(text).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["actual_state"], false);
    value["actual_state"] = true.into();
    assert!(serde_json::from_value::<HypotheticalEvaluation>(value.clone()).is_err());
    assert!(HypotheticalEvaluation::from_json_str(&value.to_string()).is_err());
    assert!(
        !fixture
            .root
            .join("__fortress/evidence/current.json")
            .exists()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn candidate_equals_clean_materialization() {
    let fixture = Fixture::with_violation();
    let mut work = fixture.open();
    let original = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let after = b"pub fn value() { let _ = std::fs::read(\"other\"); }\n";
    let result = evaluate(
        &mut work,
        "first",
        vec![fixture.replace("src/lib.rs", after)],
    );
    assert_eq!(
        result.evaluation_mode(),
        "SELECTIVE_REBUILD",
        "{}",
        serde_json::to_value(&result).unwrap()["fallback_reasons"]
    );
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        original
    );
    // Independently materialized reference tree, never mutation of the compared repository.
    let materialized = fixture.base.join("materialized");
    for (path, bytes) in &original {
        let target = materialized.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            target,
            if path == "src/lib.rs" {
                after.as_slice()
            } else {
                bytes
            },
        )
        .unwrap();
    }
    let observed = CanonicalMigrationEvaluator.observe(&materialized).unwrap();
    let cold = CanonicalMigrationEvaluator.evaluate(&observed).unwrap();
    assert_eq!(
        result.predicted_state().to_canonical_bytes().unwrap(),
        cold.state.to_canonical_bytes().unwrap()
    );
    let bytes = result.to_canonical_bytes().unwrap();
    assert_eq!(
        HypotheticalEvaluation::from_json_str(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .to_canonical_bytes()
            .unwrap(),
        bytes
    );
    assert!(result.to_human().contains("PROPOSED"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn metadata_change_uses_full_fallback() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let manifest = fs::read_to_string(fixture.root.join("Cargo.toml"))
        .unwrap()
        .replace("0.1.0", "0.1.1");
    let result = evaluate(
        &mut work,
        "metadata",
        vec![fixture.replace("Cargo.toml", manifest.as_bytes())],
    );
    assert_eq!(result.evaluation_mode(), "FULL_REEVALUATION_REQUIRED");
    assert!(result.predicted_state().view.is_some());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn two_clients_keep_separate_buffers() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let a = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn a() {}\n")],
    );
    let b = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn b() {}\n")],
    );
    let first = work
        .evaluate(
            "first",
            "same",
            a.clone(),
            &authority(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let second = work
        .evaluate("second", "same", b, &authority(), &AtomicBool::new(false))
        .unwrap();
    assert_ne!(first.candidate_digest(), second.candidate_digest());
    assert_eq!(
        work.evaluate("first", "same", a, &authority(), &AtomicBool::new(false))
            .unwrap_err()
            .code,
        "CANDIDATE_EXISTS"
    );
    work.release("first", "same");
    assert_eq!(
        work.reconcile(
            "second",
            "same",
            None,
            &authority(),
            &NoActualExecution,
            &AtomicBool::new(false)
        )
        .unwrap()
        .status(),
        "DIVERGED"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn base_changes_after_approval_invalidate_candidate() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    evaluate(
        &mut work,
        "write",
        vec![fixture.replace("src/lib.rs", b"pub fn changed() {}\n")],
    );
    let _permit = work
        .authorize_before_write("client", "write", &authority(), &AtomicBool::new(false))
        .unwrap();
    fs::write(fixture.root.join("untracked.txt"), b"concurrent edit").unwrap();
    assert_eq!(
        work.authorize_before_write("client", "write", &authority(), &AtomicBool::new(false))
            .err()
            .unwrap()
            .code,
        "STALE_BASE"
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).unwrap(),
        b"pub fn value() -> u32 { 1 }\n"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn actual_bytes_different_from_prediction_require_reassessment() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    evaluate(
        &mut work,
        "write",
        vec![fixture.replace("src/lib.rs", b"pub fn changed() {}\n")],
    );
    let permit = work
        .authorize_before_write("client", "write", &authority(), &AtomicBool::new(false))
        .unwrap();
    fs::write(
        fixture.root.join("src/lib.rs"),
        b"pub fn independent_edit() {}\n",
    )
    .unwrap();
    let result = work
        .reconcile(
            "client",
            "write",
            Some(&permit),
            &authority(),
            &NoActualExecution,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(result.status(), "DIVERGED");
    assert!(!result.actual_state());
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).unwrap(),
        b"pub fn independent_edit() {}\n"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn exact_match_without_execution_is_never_actual_certification() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let bytes = b"pub fn changed() {}\n";
    evaluate(
        &mut work,
        "write",
        vec![fixture.replace("src/lib.rs", bytes)],
    );
    let permit = work
        .authorize_before_write("client", "write", &authority(), &AtomicBool::new(false))
        .unwrap();
    fs::write(fixture.root.join("src/lib.rs"), bytes).unwrap(); // independent host fixture
    let result = work
        .reconcile(
            "client",
            "write",
            Some(&permit),
            &authority(),
            &NoActualExecution,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(result.status(), "EXACT_MATCH_UNVERIFIED");
    assert!(!result.actual_state());
    assert!(
        String::from_utf8(result.to_canonical_bytes().unwrap())
            .unwrap()
            .contains("no independently established")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn cancelled_candidate_does_not_publish_generation() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let req = request(
        &work,
        vec![fixture.replace("src/lib.rs", b"pub fn changed() {}\n")],
    );
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        work.evaluate("client", "cancelled", req.clone(), &authority(), &cancelled)
            .unwrap_err()
            .code,
        "CANCELLED"
    );
    cancelled.store(false, Ordering::Release);
    work.evaluate("client", "cancelled", req, &authority(), &cancelled)
        .unwrap();
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        source
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn moves_collisions_conflicts_and_stale_preimages() {
    let fixture = Fixture::new(false);
    fs::write(fixture.root.join("a.txt"), b"A").unwrap();
    fs::write(fixture.root.join("b.txt"), b"B").unwrap();
    let mut work = fixture.open();
    let good = vec![
        Op::MovePath {
            source: "a.txt".into(),
            destination: "b.txt".into(),
            preimage: b"A".to_vec(),
        },
        Op::MovePath {
            source: "b.txt".into(),
            destination: "a.txt".into(),
            preimage: b"B".to_vec(),
        },
    ];
    let first = evaluate(&mut work, "moves", good.clone());
    work.release("client", "moves");
    let mut reversed = good;
    reversed.reverse();
    assert_eq!(
        first.evaluation_ref(),
        evaluate(&mut work, "moves", reversed).evaluation_ref()
    );
    for op in [
        Op::CreateFile {
            path: "A.txt".into(),
            postimage: vec![],
        },
        Op::CreateFile {
            path: "../outside".into(),
            postimage: vec![],
        },
        Op::ReplaceFile {
            path: "a.txt".into(),
            preimage: b"wrong".to_vec(),
            postimage: vec![],
        },
    ] {
        let req = request(&work, vec![op]);
        assert!(
            work.evaluate("client", "bad", req, &authority(), &AtomicBool::new(false))
                .is_err()
        );
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn changed_protected_governance_cannot_authorize_itself() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let path = fortress_core::control_layout::ControlLayout::standard()
        .role_path(fortress_core::control_layout::ControlRole::ProjectConfiguration)
        .unwrap()
        .to_owned();
    let before = fs::read_to_string(fixture.root.join(&path)).unwrap();
    let result = evaluate(
        &mut work,
        "protected",
        vec![fixture.replace(&path, format!("{before}\n ").as_bytes())],
    );
    let value: serde_json::Value =
        serde_json::from_slice(&result.to_canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        value["authorization_error"]["code"],
        "TRUSTED_BASE_POLICY_REQUIRED"
    );
    assert!(value["change_decision"].is_null());
    assert!(
        work.authorize_before_write("client", "protected", &authority(), &AtomicBool::new(false))
            .is_err()
    );
    assert_eq!(fs::read_to_string(fixture.root.join(path)).unwrap(), before);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-027`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn logical_non_rust_assessor_membership_preserves_protection_without_coverage() {
    let fixture = Fixture::with_violation();
    let layout = fortress_core::control_layout::ControlLayout::standard();
    let config_path = layout
        .role_path(fortress_core::control_layout::ControlRole::ProjectConfiguration)
        .unwrap();
    let contract_path = "_data/logical_modules/overlay_semantics/contract.json";
    let owner = "AF-MIGRATION-GOVERNANCE-0001";
    for path in [config_path, contract_path] {
        let bytes = fs::read_to_string(fixture.root.join(path)).unwrap();
        fs::write(
            fixture.root.join(path),
            bytes.replace("AF-OVERLAY-SEMANTICS-0001", owner),
        )
        .unwrap();
    }
    fs::write(
        fixture.root.join("src/assessor.py"),
        b"# no execution or Python coverage claimed\n",
    )
    .unwrap();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let endpoint = CanonicalMigrationEvaluator.evaluate(&source).unwrap();
    assert_eq!(endpoint.ownership["src/assessor.py"], owner);
    assert!(endpoint.protected_inputs.iter().any(|input| {
        input.path == "src/assessor.py"
            && input.scope == owner
            && input.class == fortress_core::authority_roles::ProtectedClass::AssessorTrust
    }));
    let mut work = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let proposal = evaluate(
        &mut work,
        "assessor",
        vec![fixture.replace("src/assessor.py", b"# changed\n")],
    );
    let value: serde_json::Value =
        serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
    assert!(!value["authorization_error"].is_null());
    assert!(!value["actual_state"].as_bool().unwrap());
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        source
    );

    let configuration = fortress_core::project::ProjectConfiguration::from_json_str(
        &fs::read_to_string(fixture.root.join(config_path)).unwrap(),
    )
    .unwrap();
    let declaration = &configuration.logical_modules()[0];
    let mut other = serde_json::to_value(declaration).unwrap();
    other["module"] = "AF-OTHER-0001".into();
    let other = serde_json::from_value(other).unwrap();
    let resolution =
        fortress_core::implementation_observation::resolve_inventory_ownership_with_logical_modules(
            ["src/assessor.py"],
            &[],
            &[declaration.clone(), other],
            &std::collections::BTreeSet::from([owner.into(), "AF-OTHER-0001".into()]),
        );
    assert!(resolution.ownerships().is_empty());
    assert_eq!(
        resolution.diagnostics()[0].code(),
        "LOGICAL_MODULE_BINDING_AMBIGUOUS"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn malformed_tampered_and_context_mismatched_proposals_are_rejected() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let mut unsupported = request(&work, vec![]);
    unsupported.schema_version = 2;
    assert_eq!(
        work.evaluate(
            "client",
            "unsupported",
            unsupported,
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "UNSUPPORTED_VERSION"
    );
    let mut req = request(&work, vec![]);
    req.context_ref = "sha256:bad".into();
    assert_eq!(
        work.evaluate("client", "bad", req, &authority(), &AtomicBool::new(false))
            .unwrap_err()
            .code,
        "STALE_BASE"
    );
    let result = evaluate(&mut work, "noop", vec![]);
    let mut value: serde_json::Value =
        serde_json::from_slice(&result.to_canonical_bytes().unwrap()).unwrap();
    value["actual_state"] = true.into();
    assert!(HypotheticalEvaluation::from_json_str(&value.to_string()).is_err());
    value["actual_state"] = false.into();
    value["candidate_digest"] = format!("sha256:{}", "0".repeat(64)).into();
    assert!(HypotheticalEvaluation::from_json_str(&value.to_string()).is_err());
    assert!(
        HypotheticalEvaluation::from_json_str("{\"actual_state\":false,\"actual_state\":true}")
            .is_err()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn candidate_count_and_identity_admission_is_bounded() {
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    for i in 0..16 {
        evaluate(&mut work, &format!("candidate{i}"), vec![]);
    }
    let req = request(&work, vec![]);
    assert_eq!(
        work.evaluate(
            "client",
            "overflow",
            req,
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "RESOURCE_LIMIT"
    );
    work.release("client", "candidate0");
    let req = request(&work, vec![]);
    assert_eq!(
        work.evaluate(
            "../client",
            "invalid",
            req,
            &authority(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .code,
        "INVALID_IDENTITY"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-013`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn query_v5_pages_every_proposed_field_without_evaluating() {
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let proposal = evaluate(
        &mut work,
        "query",
        vec![fixture.replace("src/lib.rs", b"pub fn unknown() { external(); }\n")],
    );
    let original: serde_json::Value =
        serde_json::from_slice(&proposal.to_canonical_bytes().unwrap()).unwrap();
    let id = proposal.evaluation_ref().to_owned();
    let service = QueryService::new(QueryInput::empty(
        original["base_subject"].as_str().unwrap().into(),
    ))
    .unwrap()
    .with_candidates(vec![proposal])
    .unwrap();
    assert_operational_provenance_has_distinct_query_scope(&original, &service);
    // Removing the repository after explicit preload proves there is no hidden observation/evaluation.
    fs::remove_dir_all(&fixture.root).unwrap();
    let mut request = QueryRequest {
        protocol_version: 5,
        request_id: "read".into(),
        method: "candidate".into(),
        state_ref: Some(service.state_ref().into()),
        context_ref: None,
        parameters: serde_json::json!({"candidate_ref":id,"page":{"limit":3}}),
    };
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let response = service.execute(&request, &AtomicBool::new(false));
        let value: serde_json::Value =
            serde_json::from_slice(&response.to_canonical_bytes().unwrap()).unwrap();
        assert!(value["error"].is_null(), "{value}");
        let data = &value["result"]["data"];
        assert_eq!(data["description"]["actual_state"], false);
        for record in data["evidence"]["records"].as_array().unwrap() {
            let pointer = record["value"]["pointer"].as_str().unwrap();
            assert_eq!(
                original.pointer(pointer).unwrap(),
                &record["value"]["value"]
            );
            assert!(seen.insert(pointer.to_owned()));
        }
        if let Some(cursor) = data["evidence"]["next_cursor"].as_str() {
            request.parameters["page"]["cursor"] = cursor.into();
        } else {
            assert_eq!(
                seen.len(),
                usize::try_from(data["evidence"]["total"].as_u64().unwrap()).unwrap()
            );
            break;
        }
    }
    assert!(seen.contains("/actual_state"));
    assert!(seen.contains("/status"));
    request.protocol_version = 4;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNKNOWN_METHOD"
    );
    request.protocol_version = 6;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNSUPPORTED_VERSION"
    );
    request.protocol_version = 5;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(true))
            .error
            .unwrap()
            .code,
        "CANCELLED"
    );
}

fn assert_operational_provenance_has_distinct_query_scope(
    original: &serde_json::Value,
    service: &fortress_core::query::QueryService,
) {
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    let mut alternative = original.clone();
    alternative["fallback_reasons"] = serde_json::json!(["Different local cache availability"]);
    let alternative = HypotheticalEvaluation::from_json_str(&alternative.to_string()).unwrap();
    assert_eq!(alternative.evaluation_ref(), original["evaluation_ref"]);
    let other = QueryService::new(QueryInput::empty(
        original["base_subject"].as_str().unwrap().into(),
    ))
    .unwrap()
    .with_candidates(vec![alternative])
    .unwrap();
    assert_ne!(service.state_ref(), other.state_ref());
    let mut request = QueryRequest {
        protocol_version: 5,
        request_id: "record-scope".into(),
        method: "candidate".into(),
        state_ref: None,
        context_ref: None,
        parameters: serde_json::json!({"candidate_ref":original["evaluation_ref"],"page":{"limit":1}}),
    };
    let first = serde_json::to_value(service.execute(&request, &AtomicBool::new(false))).unwrap();
    let cursor = &first["result"]["data"]["evidence"]["next_cursor"];
    assert!(cursor.is_string());
    request.parameters["page"]["cursor"] = cursor.clone();
    assert_eq!(
        other
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "INVALID_CURSOR"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-014`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn explicit_registered_proposal_export_is_nonrecursive_and_immutable() {
    use sha2::{Digest, Sha256};
    let historical = fortress_core::control_layout::ControlLayout::from_json_str(
        fortress_core::control_layout::CONTROL_LAYOUT_V6_SOURCE,
    )
    .unwrap();
    assert_eq!(
        historical.digest(),
        format!(
            "sha256:{:x}",
            Sha256::digest(fortress_core::control_layout::CONTROL_LAYOUT_V6_SOURCE.as_bytes())
        )
    );
    let fixture = Fixture::new(false);
    let mut work = fixture.open();
    let before = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let proposal = evaluate(&mut work, "export", vec![]);
    let relative = proposal.export_proposal(&fixture.root).unwrap();
    assert_eq!(relative, proposal.export_proposal(&fixture.root).unwrap());
    let resolved = fortress_core::control_layout::ControlLayout::standard()
        .resolve(&relative)
        .unwrap();
    assert_eq!(
        resolved.role(),
        fortress_core::control_layout::ControlRole::HypotheticalProposal
    );
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        before
    );
    fs::write(fixture.root.join(relative), b"independent record edit").unwrap();
    assert_eq!(
        proposal.export_proposal(&fixture.root).unwrap_err().code,
        "IMMUTABLE_RECORD_CONFLICT"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-015`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn unsupported_paths_and_uncertainty_do_not_become_proof() {
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    let proposal = evaluate(
        &mut work,
        "unknown",
        vec![fixture.replace("src/lib.rs", b"pub fn value() { external_unknown(); }\n")],
    );
    let bytes = proposal.to_canonical_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.contains("NOT_EVALUABLE") || text.contains("UNSUPPORTED") || text.contains("UNKNOWN")
    );
    assert!(
        !serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["actual_state"]
            .as_bool()
            .unwrap()
    );
    // A second occurrence with ambiguous authored Module identity is an error, not favorable absence.
    let root_contract = fs::read(fixture.root.join("contract.json")).unwrap();
    let req = request(
        &work,
        vec![Op::CreateFile {
            path: "duplicate/contract.json".into(),
            postimage: root_contract,
        }],
    );
    assert!(
        work.evaluate(
            "client",
            "ambiguous",
            req,
            &authority(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-016`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn actual_execution_port_cannot_reuse_failed_filtered_or_stale_assertions() {
    use fortress_core::candidate::ActualExecutionEvidence;
    use fortress_core::certification::RustSuiteExecution;
    use fortress_core::migration_governance::MigrationError;
    struct HostFixture(RustSuiteExecution);
    impl ActualExecutionEvidence for HostFixture {
        fn current_execution(
            &self,
            _: &std::path::Path,
            _: &str,
        ) -> Result<Option<RustSuiteExecution>, MigrationError> {
            Ok(Some(self.0.clone()))
        }
    }
    let fixture = Fixture::new(true);
    let mut work = fixture.open();
    evaluate(&mut work, "noop", vec![]);
    let permit = work
        .authorize_before_write("client", "noop", &authority(), &AtomicBool::new(false))
        .unwrap();
    let source =
        fortress_core::audit::prepare_repository_certification_source(&fixture.root).unwrap();
    let original = RustSuiteExecution {
        executor: "trusted-test-port-fixture".into(),
        executor_version: "1.0.0".into(),
        toolchain: "fixture-only".into(),
        certification_source_digest: source.digest,
        test_inventory_digest: source.test_inventory_digest,
        canonical_unfiltered: true,
        passed: true,
        eligible_test_ids: source.eligible_test_ids,
        ignored_test_ids: source.ignored_test_ids,
    };
    for kind in 0..3 {
        let mut suite = original.clone();
        if kind == 0 {
            suite.passed = false;
        } else if kind == 1 {
            suite.canonical_unfiltered = false;
        } else {
            suite.certification_source_digest = format!("sha256:{}", "0".repeat(64));
        }
        let result = work
            .reconcile(
                "client",
                "noop",
                Some(&permit),
                &authority(),
                &HostFixture(suite),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(!result.actual_state());
        assert_eq!(result.status(), "EXACT_MATCH_UNVERIFIED");
    }
    // The host port is simulated here, never evidence that a fixture suite really ran.
    // Only complete existing canonical certification may promote this exact static match.
    let failure = work
        .reconcile(
            "client",
            "noop",
            Some(&permit),
            &authority(),
            &HostFixture(original),
            &AtomicBool::new(false),
        )
        .unwrap_err();
    assert_eq!(failure.code, "INVALID_INPUT");
    assert!(
        failure
            .message
            .contains("missing CERT-FULL-SNAPSHOT-V1 authority")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R22-017`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R22
#[test]
fn one_thousand_retained_candidate_differentials() {
    use std::io::Write;
    use std::time::Instant;
    let fixture = Fixture::new(true);
    let physical = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let base = CanonicalMigrationEvaluator.evaluate(&physical).unwrap();
    let mut prepared = fixture.open();
    let mut cold = CandidateWorkspace::open_cold(&fixture.root).unwrap();
    let report_root = std::env::var_os("FORTRESS_OVERLAY_REPORT_DIR")
        .map_or_else(std::env::temp_dir, PathBuf::from);
    fs::create_dir_all(&report_root).unwrap();
    let report_path = report_root.join(format!(
        "overlay-differential-{}-{}.jsonl",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut report = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)
        .unwrap();
    writeln!(report, "{}", serde_json::json!({"protocol":"overlay-differential-v1","cases":1000,"baseline_inventory":physical.digest(),"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"method":"paired prepared and complete cold canonical evaluation; isolated immutable candidates; timing is uncontrolled-host diagnostic only","certification_thresholds":"zero semantic mismatches, exact bindings, explicit uncertainty; no numerical performance gate"})).unwrap();
    let mut modes = std::collections::BTreeSet::new();
    for n in 0..1000 {
        let operations = differential_operations(&fixture, &physical, &base.ownership, n);
        let timer = Instant::now();
        let a = evaluate(&mut prepared, "paired", operations.clone());
        modes.insert(a.evaluation_mode().to_owned());
        let prepared_us = timer.elapsed().as_micros();
        let timer = Instant::now();
        let b = evaluate(&mut cold, "paired", operations);
        let cold_us = timer.elapsed().as_micros();
        assert_eq!(a.evaluation_ref(), b.evaluation_ref(), "case {n}");
        assert_eq!(
            a.predicted_state().to_canonical_bytes().unwrap(),
            b.predicted_state().to_canonical_bytes().unwrap(),
            "case {n}"
        );
        writeln!(report, "{}", serde_json::json!({"case":n,"category":n%10,"candidate":a.candidate_digest(),"assessment":a.evaluation_ref(),"mode":a.evaluation_mode(),"prepared_us":prepared_us,"cold_us":cold_us,"equal":true})).unwrap();
        prepared.release("client", "paired");
        cold.release("client", "paired");
    }
    assert!(modes.contains("SELECTIVE_REBUILD"));
    assert!(modes.contains("FULL_REEVALUATION_REQUIRED"));
    writeln!(report, "{}", serde_json::json!({"status":"PASS","equal_differentials":1000,"mismatches":0,"actual_certification_from_prediction":false,"evaluation_modes":modes})).unwrap();
    report.sync_all().unwrap();
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&fixture.root).unwrap(),
        physical
    );
    eprintln!(
        "OVERLAY retained differential report: {}",
        report_path.display()
    );
}

fn differential_operations(
    fixture: &Fixture,
    physical: &fortress_core::observation::SourceView,
    ownership: &std::collections::BTreeMap<String, String>,
    n: u32,
) -> Vec<Op> {
    let mut operations = Vec::new();
    match n % 10 {
        0 => operations.push(fixture.replace(
            "src/lib.rs",
            format!("pub fn value() -> u32 {{ {n} }}\n").as_bytes(),
        )),
        1 => operations.push(
            fixture.replace(
                "src/lib.rs",
                format!("pub fn value(flag: bool) -> u32 {{ if flag {{ {n} }} else {{ 1 }} }}\n")
                    .as_bytes(),
            ),
        ),
        2 => operations.push(fixture.replace(
            "src/lib.rs",
            format!("pub fn value() {{ external_{n}(); }}\n").as_bytes(),
        )),
        3 => operations.push(fixture.replace(
            "src/lib.rs",
            format!("#[cfg(unknown_{n})]\npub fn value() {{}}\n").as_bytes(),
        )),
        4 => operations.push(fixture.replace(
            "src/lib.rs",
            format!("// location-only-{n}\n\npub fn value() -> u32 {{ 1 }}\n").as_bytes(),
        )),
        5 => {
            let manifest = fs::read_to_string(fixture.root.join("Cargo.toml"))
                .unwrap()
                .replace("0.1.0", &format!("0.1.{n}"));
            operations.push(fixture.replace("Cargo.toml", manifest.as_bytes()));
        }
        6 => {
            operations.push(fixture.replace("src/lib.rs", b"pub fn value() { resolved(); }\n"));
            operations.push(Op::CreateFile {
                path: format!("src/added_{n}.rs"),
                postimage: b"pub fn resolved() {}\n".to_vec(),
            });
        }
        7 => operations.push(Op::MovePath {
            source: "src/lib.rs".into(),
            destination: format!("src/moved_{n}.rs"),
            preimage: physical["src/lib.rs"].clone(),
        }),
        8 => operations.push(Op::DeleteOwnedFile {
            path: "src/lib.rs".into(),
            preimage: physical["src/lib.rs"].clone(),
            owner_ref: ownership["src/lib.rs"].clone(),
        }),
        _ => {
            operations.push(Op::CreateFile {
                path: format!("_data/binary_{n}.bin"),
                postimage: vec![0, 255, u8::try_from(n % 256).unwrap()],
            });
            operations.push(fixture.replace(
                "src/lib.rs",
                b"pub fn value() { loop { if unknown() { return; } } }\n",
            ));
        }
    }
    operations
}
