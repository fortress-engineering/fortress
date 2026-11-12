//! Reviewed native adoption and strict canonical adoption conformance.
use fortress_core::bootstrap::{
    OnboardingMode, OnboardingOptions, OnboardingProposal, apply_repository_onboarding,
    discover_repository_onboarding, review_onboarding_baseline,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fortress-native-adoption-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        for (path, contents) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        Self { root }
    }
    fn native() -> Self {
        Self::new(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers=[\"alpha\",\"beta\"]\nresolver=\"2\"\n",
            ),
            (
                "alpha/Cargo.toml",
                "[package]\nname=\"alpha\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            ),
            ("alpha/src/lib.rs", "pub fn answer()->u8{42}\n"),
            (
                "beta/Cargo.toml",
                "[package]\nname=\"beta\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            ),
            ("beta/src/lib.rs", "pub fn ready()->bool{true}\n"),
            (
                "README.md",
                "# Ordinary workspace\n\nApplication-owned documentation.\n",
            ),
        ])
    }
    fn options() -> OnboardingOptions {
        OnboardingOptions::new(
            Some("PF-ADOPTION-FIXTURE".into()),
            Some("Adoption Fixture".into()),
        )
    }
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        inventory(&self.root, &self.root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn inventory(root: &Path, dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            result.extend(inventory(root, &p));
        } else {
            result.insert(
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                fs::read(p).unwrap(),
            );
        }
    }
    result
}
fn json(p: &OnboardingProposal) -> Value {
    serde_json::from_str(&p.to_canonical_json().unwrap()).unwrap()
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-024`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn implicit_integration_targets_preserve_observer_coherence_and_explicit_disablement() {
    let f = Fixture::native();
    fs::create_dir_all(f.root.join("alpha/tests")).unwrap();
    fs::write(
        f.root.join("alpha/tests/smoke.rs"),
        "#[test] fn check(){ let _ = beta::ready(); }\n",
    )
    .unwrap();
    for (settings, explicit, expected_calls) in [
        ("", "", true),
        ("autotests=false\n", "", false),
        (
            "autotests=false\n",
            "[[test]]\nname='smoke'\npath='tests/smoke.rs'\n",
            true,
        ),
    ] {
        fs::write(f.root.join("alpha/Cargo.toml"), format!("[package]\nname='alpha'\nversion='0.1.0'\nedition='2021'\n{settings}[dev-dependencies]\nbeta={{path='../beta'}}\n{explicit}")).unwrap();
        let before = f.files();
        let proposal = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
        assert!(proposal.is_ready(), "{}", proposal.to_human());
        let value = json(&proposal);
        let calls = value["observed_facts"]["semantic_observation"]["relationships"]["total"]
            .as_u64()
            .unwrap();
        assert_eq!(calls > 0, expected_calls);
        assert_eq!(before, f.files());
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-023`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn discovery_preserves_authored_relationships_and_nested_observed_calls() {
    let f = Fixture::native();
    fs::write(
        f.root.join("alpha/src/lib.rs"),
        "mod inline { pub mod deeper; } pub fn answer()->u8 { inline::deeper::value() }\n",
    )
    .unwrap();
    fs::create_dir_all(f.root.join("alpha/src/inline")).unwrap();
    fs::write(
        f.root.join("alpha/src/inline/deeper.rs"),
        "pub fn value()->u8 {42}\n",
    )
    .unwrap();
    let before = f.files();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    assert!(p.is_ready());
    let v = json(&p);
    let relationships = &v["observed_facts"]["semantic_observation"]["relationships"];
    assert_eq!(relationships["kind"], "OBSERVED_CALLS");
    assert_eq!(relationships["permission_inferred"], false);
    let model = fortress_core::audit::compile_repository_psm(&f.root).unwrap();
    assert_eq!(relationships["total"], model.calls().len());
    for (row, call) in relationships["included"]
        .as_array()
        .unwrap()
        .iter()
        .zip(model.calls())
    {
        assert_eq!(row["caller"], call.caller());
        assert_eq!(row["callee"], serde_json::to_value(call.callee()).unwrap());
    }
    assert!(model.calls().iter().any(|call| call.callee().is_some()));
    assert_eq!(before, f.files());
    let root = v["proposed_authority"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["path"] == "contract.json")
        .unwrap();
    let mut contract: Value = serde_json::from_str(root["content"].as_str().unwrap()).unwrap();
    contract["requires"] = serde_json::json!([{"provider":"AF-DEPENDENCY-0001","capability":"CAP-API-0001","version":"^1.0.0"}]);
    contract["relationships"] =
        serde_json::json!([{"type":"verifies","target":"AF-DEPENDENCY-0001","subjects":[]}]);
    fs::write(
        f.root.join("contract.json"),
        serde_json::from_value::<fortress_core::contract_coherency::ModuleContract>(
            contract.clone(),
        )
        .unwrap()
        .to_canonical_json()
        .unwrap(),
    )
    .unwrap();
    fs::write(f.root.join("authored-operation.json"), r#"{"$schema":"urn:fortress:schema:v1:function-contract","claim":"not independently validated"}"#).unwrap();
    let existing = f.files();
    let discovered = json(&discover_repository_onboarding(&f.root, &Fixture::options()).unwrap());
    let records = discovered["existing_contracts"].as_array().unwrap();
    let module = records
        .iter()
        .find(|r| r["path"] == "contract.json")
        .unwrap();
    assert_eq!(module["requires"], contract["requires"]);
    assert_eq!(module["relationships"], contract["relationships"]);
    let unverified = records
        .iter()
        .find(|r| r["path"] == "authored-operation.json")
        .unwrap();
    assert_eq!(unverified["state"], "UNVERIFIED_DECLARATION_OCCURRENCE");
    assert!(
        !discovered["unresolved_choices"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(existing, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn native_discovery_is_exact_read_only_and_has_no_inferred_permissions() {
    let f = Fixture::native();
    let before = f.files();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let v = json(&p);
    assert_eq!(before, f.files());
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["mode"], "NATIVE");
    assert_eq!(v["state"], "PROPOSED");
    assert_eq!(v["actual_state"], false);
    assert_eq!(v["candidate_modules"].as_array().unwrap().len(), 3);
    for a in v["proposed_authority"].as_array().unwrap() {
        assert!(!a["content"].as_str().unwrap().contains("\"ALLOW\""));
    }
    let second = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    assert_eq!(
        p.to_canonical_json().unwrap(),
        second.to_canonical_json().unwrap()
    );
    assert_eq!(
        OnboardingProposal::from_json_str(&p.to_canonical_json().unwrap())
            .unwrap()
            .digest(),
        p.digest()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn native_application_preserves_all_existing_bytes_and_uses_shared_receipts() {
    let f = Fixture::native();
    let before = f.files();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    assert!(p.is_ready(), "{}", json(&p)["unresolved_choices"]);
    let applied = apply_repository_onboarding(&f.root, &p).unwrap();
    let v: Value = serde_json::from_str(&applied.to_canonical_json().unwrap()).unwrap();
    for (path, bytes) in before {
        assert_eq!(fs::read(f.root.join(&path)).unwrap(), bytes, "{path}");
    }
    assert!(!f.root.join("_data").exists());
    assert!(!f.root.join("_info").exists());
    assert!(f.root.join("__fortress/.fsconfig").is_file());
    assert!(f.root.join("alpha/contract.json").is_file());
    assert!(
        v["migration_receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(v["certification"], "NOT_ESTABLISHED");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn stale_or_tampered_review_writes_nothing() {
    let f = Fixture::native();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let tampered = p
        .to_canonical_json()
        .unwrap()
        .replace("Adoption Fixture", "Altered Fixture");
    assert!(OnboardingProposal::from_json_str(&tampered).is_err());
    fs::write(f.root.join("alpha/src/lib.rs"), "pub fn answer()->u8{43}\n").unwrap();
    let before = f.files();
    assert!(apply_repository_onboarding(&f.root, &p).is_err());
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn canonical_recursive_proposals_keep_strict_filing_and_do_not_create_empty_elements() {
    let f = Fixture::new(&[
        ("child/_code/value.rs", "pub fn value()->u8{7}\n"),
        ("child/grand/_code/measure.rs", "pub fn measure()->u8{7}\n"),
        ("child/grand/_data/settings.json", "{\"value\":7}\n"),
        (
            "child/grand/_info/trace.json",
            "{\"observation\":\"unverified\"}\n",
        ),
    ]);
    let o = Fixture::options().with_mode(OnboardingMode::Canonical);
    let p = discover_repository_onboarding(&f.root, &o).unwrap();
    assert!(p.is_ready(), "{}", p.to_canonical_json().unwrap());
    let v = json(&p);
    assert_eq!(v["mode"], "CANONICAL");
    apply_repository_onboarding(&f.root, &p).unwrap();
    assert!(f.root.join("child/README.md").is_file());
    assert!(f.root.join("child/_docs/code_docs.md").is_file());
    assert!(f.root.join("_docs/modules_docs.md").is_file());
    assert!(f.root.join("child/grand/contract.json").is_file());
    assert!(f.root.join("child/grand/_docs/data_docs.md").is_file());
    assert!(f.root.join("child/grand/_docs/info_docs.md").is_file());
    assert!(f.root.join("child/grand/_docs/code_docs.md").is_file());
    assert!(!f.root.join("child/_data").exists());
    assert!(!f.root.join("child/_info").exists());
    let report = fortress_core::audit::audit_repository(&f.root).unwrap();
    assert!(
        !report
            .findings()
            .iter()
            .any(|x| matches!(x.rule_id(), "REPO-MODULE-001" | "REPO-DOCS-001")),
        "{}",
        report.to_json_pretty().unwrap()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn partial_or_conflicting_authority_is_not_overwritten() {
    let f = Fixture::native();
    fs::create_dir(f.root.join("__fortress")).unwrap();
    fs::write(f.root.join("__fortress/.fsconfig"), "{}").unwrap();
    let before = f.files();
    if let Ok(p) = discover_repository_onboarding(&f.root, &Fixture::options()) {
        assert!(!p.is_ready());
        assert!(apply_repository_onboarding(&f.root, &p).is_err());
    }
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn initial_residue_requires_exact_target_and_explicit_finding_selection() {
    let f = Fixture::native();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let before = f.files();
    assert!(
        review_onboarding_baseline(&f.root, &p, &format!("sha256:{}", "a".repeat(64)), &[])
            .is_err()
    );
    assert_eq!(before, f.files());
    let state = json(&p)["assessment"]["predicted_state_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        review_onboarding_baseline(&f.root, &p, &state, &["unobserved-finding".into()]).is_err()
    );
    assert_eq!(before, f.files());
    let reviewed = review_onboarding_baseline(&f.root, &p, &state, &[]).unwrap();
    assert_eq!(
        json(&reviewed)["baseline_review"]["finding_ids"],
        serde_json::json!([])
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn native_requests_cannot_change_source_or_infer_grants() {
    use fortress_core::migration_governance::MigrationOperation;
    let f = Fixture::native();
    let before = f.files();
    let request = Fixture::options().with_source_operations(vec![MigrationOperation::CreateFile {
        path: "src/permission.rs".into(),
        postimage: b"// approved".to_vec(),
    }]);
    assert!(discover_repository_onboarding(&f.root, &request).is_err());
    assert!(OnboardingOptions::from_json_str(r#"{"schema_version":1,"approved":true}"#).is_err());
    assert!(
        OnboardingOptions::from_json_str(r#"{"schema_version":1,"schema_version":1}"#).is_err()
    );
    assert!(OnboardingOptions::from_json_str(r#"{"schema_version":99}"#).is_err());
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn module_identity_and_parent_ambiguity_are_rejected_before_writing() {
    use fortress_core::bootstrap::OnboardingModuleChoice;
    let f = Fixture::native();
    let before = f.files();
    let root = OnboardingModuleChoice {
        module: "PF-ADOPTION-FIXTURE".into(),
        display_name: "Root".into(),
        contract: "contract.json".into(),
        parent: String::new(),
        bindings: vec![],
    };
    let request = Fixture::options().with_modules(vec![root.clone(), root.clone()]);
    assert!(discover_repository_onboarding(&f.root, &request).is_err());
    let child = OnboardingModuleChoice {
        module: "MOD-CHILD".into(),
        display_name: "Child".into(),
        contract: "child/contract.json".into(),
        parent: "MOD-MISSING".into(),
        bindings: vec![],
    };
    assert!(
        discover_repository_onboarding(
            &f.root,
            &Fixture::options().with_modules(vec![root, child])
        )
        .is_err()
    );
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn unsupported_profiles_and_forged_initial_exceptions_are_not_permission() {
    use fortress_core::bootstrap::OnboardingAuthorityFile;
    let f = Fixture::native();
    let before = f.files();
    assert!(
        discover_repository_onboarding(
            &f.root,
            &Fixture::options().with_profiles(vec!["GOV-UNREGISTERED".into()], vec![])
        )
        .is_err()
    );
    let document = serde_json::json!({"$schema":"urn:fortress:schema:v2:finding-governance","schema_version":2,"approved":true});
    let request = Fixture::options().with_authority_files(vec![OnboardingAuthorityFile {
        path: "__fortress/governance/finding_governance.json".into(),
        content: document.to_string(),
    }]);
    assert!(discover_repository_onboarding(&f.root, &request).is_err());
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn canonical_adoption_does_not_accept_retired_or_unfiled_grammar() {
    let f = Fixture::new(&[("WrongName/src/lib.rs", "pub fn x() {}\n")]);
    let before = f.files();
    let p = discover_repository_onboarding(
        &f.root,
        &Fixture::options().with_mode(OnboardingMode::Canonical),
    )
    .unwrap();
    assert!(!p.is_ready());
    assert!(apply_repository_onboarding(&f.root, &p).is_err());
    assert_eq!(before, f.files());
    let metadata_only = Fixture::new(&[("child/_data/settings.json", "{}\n")]);
    let p = discover_repository_onboarding(
        &metadata_only.root,
        &Fixture::options().with_mode(OnboardingMode::Canonical),
    )
    .unwrap();
    assert!(!p.is_ready());
}

struct CancelAfterInstall;
impl fortress_core::migration_governance::MutationObserver for CancelAfterInstall {
    fn boundary(
        &self,
        _: u64,
        b: fortress_core::migration_governance::MutationBoundary,
        p: fortress_core::migration_governance::BoundaryPhase,
    ) -> Result<(), fortress_core::migration_governance::MigrationError> {
        use fortress_core::migration_governance::{
            BoundaryPhase, MigrationError, MutationBoundary,
        };
        if b == MutationBoundary::Install && p == BoundaryPhase::After {
            return Err(MigrationError {
                code: "CANCELLED".into(),
                message: "Injected cancellation after a durable source installation".into(),
                transaction_ref: None,
            });
        }
        Ok(())
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn interrupted_application_uses_shared_verified_rollback() {
    use fortress_core::bootstrap::{
        BootstrapError, apply_repository_onboarding_with_ports, recover_repository_onboarding,
    };
    use fortress_core::migration_governance::{MigrationRecoveryMode, NoMutationFaults};
    let f = Fixture::native();
    let before = f.files();
    let proposal = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let storage = fortress_core::migration_adapter::default_migration_storage().unwrap();
    let err = apply_repository_onboarding_with_ports(
        &f.root,
        &proposal,
        None,
        &storage,
        &CancelAfterInstall,
    )
    .unwrap_err();
    let transaction = match err {
        BootstrapError::Migration(e) => e.transaction_ref.unwrap(),
        e => panic!("{e}"),
    };
    let restored = recover_repository_onboarding(
        &f.root,
        &proposal,
        &transaction,
        MigrationRecoveryMode::Rollback,
        None,
        &storage,
        &NoMutationFaults,
    )
    .unwrap();
    assert_eq!(restored.outcome, "ROLLED_BACK_BYTES_VERIFIED");
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn readable_inspection_is_a_projection_of_loaded_evidence() {
    let f = Fixture::native();
    let proposal = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let before = f.files();
    let human = proposal.to_human();
    let machine = json(&proposal);
    assert!(human.contains(proposal.digest()));
    assert!(human.contains(machine["base_source_ref"].as_str().unwrap()));
    for module in machine["candidate_modules"].as_array().unwrap() {
        let id = module["choice"]["module"].as_str().unwrap();
        assert_eq!(
            serde_json::to_value(proposal.resolve_module(id).unwrap()).unwrap(),
            module["choice"]
        );
    }
    assert!(proposal.resolve_module("unavailable").is_err());
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-013`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn selected_historical_residue_preserves_raw_violations_and_exact_origin() {
    use fortress_core::bootstrap::OnboardingAuthorityFile;
    fs::metadata(std::env::temp_dir()).unwrap();
    let f = Fixture::native();
    fs::write(
        f.root.join("alpha/src/lib.rs"),
        "pub fn write(){ std::fs::write(\"x\",b\"a\").unwrap(); }\n",
    )
    .unwrap();
    let initial = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let artifact = json(&initial)["proposed_authority"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["path"] == "alpha/contract.json")
        .unwrap()
        .clone();
    let mut contract: Value = serde_json::from_str(artifact["content"].as_str().unwrap()).unwrap();
    contract["semantic_policy"]["capabilities"]["deny"] = serde_json::json!(["filesystem"]);
    let typed: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(contract).unwrap();
    let request = Fixture::options().with_authority_files(vec![OnboardingAuthorityFile {
        path: "alpha/contract.json".into(),
        content: typed.to_canonical_json().unwrap(),
    }]);
    let p = discover_repository_onboarding(&f.root, &request).unwrap();
    let v = json(&p);
    let findings = v["predicted_findings"].as_array().unwrap();
    let eligible: Vec<String> = findings
        .iter()
        .filter(|f| f["identity_eligibility"] == "ELIGIBLE")
        .map(|f| f["finding_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(!eligible.is_empty(), "{findings:?}");
    let state = p.assessment().unwrap().predicted_state().digest().unwrap();
    let reviewed = review_onboarding_baseline(&f.root, &p, &state, &eligible).unwrap();
    let r = json(&reviewed);
    assert_eq!(r["predicted_findings"], v["predicted_findings"]);
    assert_eq!(
        r["baseline_origin_assessment"]["evaluation_ref"],
        v["assessment"]["evaluation_ref"]
    );
    assert_eq!(
        r["baseline_review"]["finding_ids"],
        serde_json::to_value(&eligible).unwrap()
    );
    assert_eq!(r["baseline_origin_assessment"]["actual_state"], false);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-014`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn canonical_exact_moves_are_reviewed_without_another_filesystem_writer() {
    use fortress_core::migration_governance::MigrationOperation;
    let f = Fixture::new(&[("value.rs", "pub fn value()->u8{7}\n")]);
    let bytes = fs::read(f.root.join("value.rs")).unwrap();
    let options = Fixture::options()
        .with_mode(OnboardingMode::Canonical)
        .with_source_operations(vec![MigrationOperation::MovePath {
            source: "value.rs".into(),
            destination: "service/_code/value.rs".into(),
            preimage: bytes.clone(),
        }]);
    let p = discover_repository_onboarding(&f.root, &options).unwrap();
    assert!(p.is_ready(), "{}", json(&p)["unresolved_choices"]);
    assert!(f.root.join("value.rs").exists());
    assert!(!f.root.join("service").exists());
    apply_repository_onboarding(&f.root, &p).unwrap();
    assert!(!f.root.join("value.rs").exists());
    assert_eq!(
        fs::read(f.root.join("service/_code/value.rs")).unwrap(),
        bytes
    );
    assert!(f.root.join("service/contract.json").is_file());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-015`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn public_onboarding_serializers_validate_against_registered_schemas() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let schemas: Vec<Value> = manifest["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            serde_json::from_slice(&fs::read(root.join(p.as_str().unwrap())).unwrap()).unwrap()
        })
        .collect();
    let f = Fixture::native();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let result = apply_repository_onboarding(&f.root, &p).unwrap();
    let records = [
        (
            "urn:fortress:schema:v1:repository-onboarding-request",
            serde_json::to_value(p.request()).unwrap(),
        ),
        (
            "urn:fortress:schema:v2:repository-bootstrap-proposal",
            json(&p),
        ),
        (
            "urn:fortress:derived:v1:repository-onboarding-result",
            serde_json::from_str(&result.to_canonical_json().unwrap()).unwrap(),
        ),
        (
            "urn:fortress:schema:v8:control-layout",
            serde_json::from_str(fortress_core::control_layout::CONTROL_LAYOUT_SOURCE).unwrap(),
        ),
    ];
    for (id, value) in records {
        let schema = schemas.iter().find(|s| s["$id"] == id).unwrap();
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
            .unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-016`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn linked_authority_escapes_never_modify_the_external_target() {
    let f = Fixture::native();
    let outside = Fixture::new(&[("sentinel", "independent bytes")]);
    let before = outside.files();
    let link = f.root.join("__fortress");
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside.root, &link).unwrap();
    let refused = match discover_repository_onboarding(&f.root, &Fixture::options()) {
        Err(_) => true,
        Ok(p) => !p.is_ready() && apply_repository_onboarding(&f.root, &p).is_err(),
    };
    #[cfg(windows)]
    fs::remove_dir(link).unwrap();
    #[cfg(unix)]
    fs::remove_file(link).unwrap();
    assert!(refused);
    assert_eq!(before, outside.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-017`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn duplicate_readable_module_names_require_qualified_identity() {
    use fortress_core::bootstrap::OnboardingModuleChoice;
    let f = Fixture::native();
    let original = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let choices: Vec<OnboardingModuleChoice> = json(&original)["candidate_modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let mut c = m["choice"].clone();
            if !c["parent"].as_str().unwrap().is_empty() {
                c["display_name"] = "Shared name".into();
            }
            serde_json::from_value(c).unwrap()
        })
        .collect();
    let p =
        discover_repository_onboarding(&f.root, &Fixture::options().with_modules(choices)).unwrap();
    assert!(p.resolve_module("Shared name").is_err());
    assert!(p.resolve_module("Adoption Fixture::Shared name").is_err());
    assert!(p.resolve_module("PF-ADOPTION-FIXTURE-ALPHA").is_ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-018`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn case_colliding_control_roots_are_not_silently_initialized() {
    let f = Fixture::native();
    fs::create_dir(f.root.join("__Fortress")).unwrap();
    fs::write(f.root.join("__Fortress/.fsconfig"), "{}").unwrap();
    let before = f.files();
    match discover_repository_onboarding(&f.root, &Fixture::options()) {
        Err(_) => {}
        Ok(p) => {
            assert!(!p.is_ready());
            assert!(apply_repository_onboarding(&f.root, &p).is_err());
        }
    }
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-019`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn recovery_preserves_independently_modified_authority() {
    use fortress_core::bootstrap::{
        BootstrapError, apply_repository_onboarding_with_ports, recover_repository_onboarding,
    };
    use fortress_core::migration_governance::{MigrationRecoveryMode, NoMutationFaults};
    let f = Fixture::native();
    let before = f.files();
    let proposal = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let storage = fortress_core::migration_adapter::default_migration_storage().unwrap();
    let transaction = match apply_repository_onboarding_with_ports(
        &f.root,
        &proposal,
        None,
        &storage,
        &CancelAfterInstall,
    )
    .unwrap_err()
    {
        BootstrapError::Migration(e) => e.transaction_ref.unwrap(),
        e => panic!("{e}"),
    };
    assert!(fortress_core::audit::compile_repository_state_view(&f.root).is_err());
    let installed = f
        .files()
        .into_iter()
        .find(|(p, _)| !before.contains_key(p))
        .unwrap();
    fs::write(f.root.join(&installed.0), "independent user content").unwrap();
    assert!(
        recover_repository_onboarding(
            &f.root,
            &proposal,
            &transaction,
            MigrationRecoveryMode::Rollback,
            None,
            &storage,
            &NoMutationFaults
        )
        .is_err()
    );
    assert_eq!(
        fs::read(f.root.join(&installed.0)).unwrap(),
        b"independent user content"
    );
    fs::write(f.root.join(&installed.0), installed.1).unwrap();
    recover_repository_onboarding(
        &f.root,
        &proposal,
        &transaction,
        MigrationRecoveryMode::Rollback,
        None,
        &storage,
        &NoMutationFaults,
    )
    .unwrap();
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-020`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn interrupted_native_adoption_resumes_only_to_the_verified_target() {
    use fortress_core::bootstrap::{
        BootstrapError, apply_repository_onboarding_with_ports, recover_repository_onboarding,
    };
    use fortress_core::migration_governance::{MigrationRecoveryMode, NoMutationFaults};
    let f = Fixture::native();
    let before = f.files();
    let proposal = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let storage = fortress_core::migration_adapter::default_migration_storage().unwrap();
    let transaction = match apply_repository_onboarding_with_ports(
        &f.root,
        &proposal,
        None,
        &storage,
        &CancelAfterInstall,
    )
    .unwrap_err()
    {
        BootstrapError::Migration(e) => e.transaction_ref.unwrap(),
        e => panic!("{e}"),
    };
    let recovered = recover_repository_onboarding(
        &f.root,
        &proposal,
        &transaction,
        MigrationRecoveryMode::Resume,
        None,
        &storage,
        &NoMutationFaults,
    )
    .unwrap();
    assert_eq!(recovered.outcome, "COMMITTED_ACTUAL_TARGET_VERIFIED");
    assert!(recovered.receipt.is_some());
    for (path, bytes) in before {
        assert_eq!(fs::read(f.root.join(path)).unwrap(), bytes);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-021`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn bounded_requests_fail_before_analysis_and_missing_choices_remain_reviewable() {
    let f = Fixture::native();
    let before = f.files();
    let request = serde_json::json!({"schema_version":1,"governance_profiles":vec!["GOV-FORTRESS-NATIVE";65]});
    assert!(OnboardingOptions::from_json_str(&request.to_string()).is_err());
    let partial = OnboardingOptions::new(Some("PF-REVIEW-PENDING".into()), None);
    let p = discover_repository_onboarding(&f.root, &partial).unwrap();
    assert!(!p.is_ready());
    assert!(
        json(&p)["unresolved_choices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["code"] == "DISPLAY_NAME_REQUIRED")
    );
    assert_eq!(before, f.files());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R23-022`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R23
#[test]
fn rehashed_records_cannot_mislabel_authority_or_native_source_operations() {
    use sha2::{Digest, Sha256};
    let f = Fixture::native();
    let p = discover_repository_onboarding(&f.root, &Fixture::options()).unwrap();
    let before = f.files();
    let rehash = |mut value: Value| {
        value["proposal_digest"] = "".into();
        value["proposal_digest"] = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json_canonicalizer::to_vec(&value).unwrap())
        )
        .into();
        value.to_string()
    };
    let mut unknown = json(&p);
    unknown["proposed_authority"][0]["authority_kind"] = "APPROVAL".into();
    assert!(OnboardingProposal::from_json_str(&rehash(unknown)).is_err());
    let mut source = json(&p);
    source["operations"][0]["path"] = "alpha/src/lib.rs".into();
    assert!(OnboardingProposal::from_json_str(&rehash(source)).is_err());
    let mut context = json(&p);
    context["context_ref"] = format!("sha256:{}", "a".repeat(64)).into();
    assert!(OnboardingProposal::from_json_str(&rehash(context)).is_err());
    assert_eq!(before, f.files());
}
