//! Actual process controls for the local agent integration.

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

#[path = "../../_code/mcp_wire.rs"]
mod agent_wire;
mod github_controls;
mod mcp_controls;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Client {
    owned: PathBuf,
    root: PathBuf,
    child: Child,
    input: Option<ChildStdin>,
    messages: Receiver<Value>,
}

impl Client {
    fn launch() -> Self {
        Self::launch_mode(false)
    }

    fn launch_mode(previews: bool) -> Self {
        let owned = std::env::temp_dir().join(format!(
            "fortress-agent-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&owned).unwrap();
        let root = owned.join("repository");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), b"pub fn fixture() {}\n").unwrap();
        fs::write(root.join("fixture.txt"), b"reviewed bytes").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = 'agent_transport_fixture'\nversion = '0.1.0'\nedition = '2024'\n",
        )
        .unwrap();
        fs::write(
            root.join("build.rs"),
            "fn main() { std::fs::write(\"forbidden-build-marker\", b\"executed\").unwrap(); }\n",
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_fortress"));
        command.args(["serve", "--mcp"]).arg(&root);
        if previews {
            let storage = owned.join("storage");
            fs::create_dir(&storage).unwrap();
            command.arg("--candidate-storage").arg(&storage);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, messages) = mpsc::sync_channel(8);
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let parsed = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(parsed).is_err() {
                    break;
                }
            }
        });
        Self {
            owned,
            root,
            child,
            input: Some(input),
            messages,
        }
    }

    fn send(&mut self, frame: &Value) {
        let input = self.input();
        writeln!(input, "{frame}").unwrap();
        input.flush().unwrap();
    }

    fn input(&mut self) -> &mut ChildStdin {
        self.input.as_mut().expect("the test connection is open")
    }

    fn close(&mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "service did not dispose on EOF");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn receive(&self) -> Value {
        self.messages.recv_timeout(Duration::from_secs(30)).unwrap()
    }

    fn initialize(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "actual-test", "version": "1"}}
        }));
        let response = self.receive();
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.owned);
    }
}

fn call(id: u32, name: &str, arguments: Value) -> Value {
    let mut request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name}});
    request["params"]["arguments"] = arguments;
    request
}

/// `T-TF-AGENT-INTEGRATION-0001-R01-001`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn installed_mcp_and_native_query_preserve_the_same_status() {
    let mut client = Client::launch();
    client.initialize();
    client.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let tools = client.receive();
    let capability = &tools["result"]["_meta"]["fortress/hostCapability"];
    assert_eq!(
        capability["$schema"],
        "urn:fortress:derived:v1:host-capability"
    );
    assert_eq!(capability["intercepted_operations"], json!([]));
    assert_eq!(capability["grant_channel"], "NONE");
    let tools = tools["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "fortress_inspect");
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
    let request =
        json!({"protocol_version":1,"request_id":"test","method":"status","parameters":{}});
    client.send(&call(3, "fortress_inspect", json!({"request":request})));
    let result = client.receive();
    assert_eq!(result["id"], 3);
    let received = &result["result"]["structuredContent"];
    let cli = Command::new(env!("CARGO_BIN_EXE_fortress"))
        .args(["status", "--format", "json"])
        .arg(&client.root)
        .output()
        .unwrap();
    assert!(cli.status.success());
    let native: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(received["state_ref"], native["state_ref"]);
    assert_eq!(received["result"], native["result"]);
    assert_eq!(
        fs::read(client.root.join("fixture.txt")).unwrap(),
        b"reviewed bytes"
    );
    assert!(!client.root.join("forbidden-build-marker").exists());
}

// The controlled issuer is intentionally test-only. It cannot be installed by the MCP client.
mod mediation {
    use super::*;
    use fortress_cli::mediator::{
        ClaimedReview, InvocationAuthority, ReviewBinding, ReviewedAction, TrustedMediator,
    };
    use fortress_core::bootstrap::{
        BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
    };
    use fortress_core::development_governance::{
        Action, AuthorizationRule, GrantRequest, GrantValidation, GrantValidator, HostAssertion,
        ProtectedClass, TrustedBasePolicy,
    };
    use fortress_core::migration_adapter::CanonicalMigrationEvaluator;
    use fortress_core::migration_governance::{
        MigrationError, MigrationEvaluator, MigrationOperation,
    };
    use fortress_core::runtime_storage::{MigrationStorage, StoragePolicy};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;

    fn fixed_digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn fault(code: &str) -> MigrationError {
        MigrationError {
            code: code.into(),
            message: code.into(),
            transaction_ref: None,
        }
    }

    struct Owned {
        outer: PathBuf,
        root: PathBuf,
        storage: MigrationStorage,
    }
    impl Owned {
        fn new() -> Self {
            Self::with_source(None)
        }

        fn with_source(source: Option<&fortress_core::observation::SourceView>) -> Self {
            let outer = std::env::temp_dir().join(format!(
                "fortress-local-mediator-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&outer).unwrap();
            let root = outer.join("repository");
            fs::create_dir(&root).unwrap();
            if let Some(source) = source {
                assert!(source.bytes("Cargo.toml").is_some());
                for (path, bytes) in source {
                    let destination = root.join(path);
                    fs::create_dir_all(destination.parent().unwrap()).unwrap();
                    fs::write(destination, bytes).unwrap();
                }
            } else {
                fs::create_dir(root.join("src")).unwrap();
                fs::write(
                    root.join("Cargo.toml"),
                    "[package]\nname = 'mediator_fixture'\nversion = '0.1.0'\nedition = '2024'\n",
                )
                .unwrap();
                fs::write(root.join("src/lib.rs"), b"pub fn value() -> u8 { 1 }\n").unwrap();
            }
            let proposal = discover_repository_bootstrap(
                &root,
                &BootstrapDiscoveryOptions::new(
                    Some("PF-MEDIATOR-FIXTURE".into()),
                    Some("Mediator Fixture".into()),
                ),
            )
            .unwrap();
            apply_repository_bootstrap(&root, &proposal, false).unwrap();
            let storage =
                MigrationStorage::new(outer.join("ops"), StoragePolicy::default()).unwrap();
            Self {
                outer,
                root,
                storage,
            }
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.outer);
        }
    }

    struct FixtureReview {
        expected: RefCell<Option<String>>,
        rollback: RefCell<Option<String>>,
        claimed: Cell<bool>,
        revoked: Cell<bool>,
        revoke_after_write: RefCell<Option<(PathBuf, Vec<u8>)>>,
        expired: Cell<bool>,
        trust_ref: RefCell<String>,
        concurrent_write: RefCell<Option<ConcurrentWrite>>,
    }

    struct ConcurrentWrite {
        installed: PathBuf,
        expected: Vec<u8>,
        unrelated: PathBuf,
    }
    impl FixtureReview {
        fn new() -> Self {
            Self {
                expected: RefCell::new(None),
                rollback: RefCell::new(None),
                claimed: Cell::new(false),
                revoked: Cell::new(false),
                revoke_after_write: RefCell::new(None),
                expired: Cell::new(false),
                trust_ref: RefCell::new(fixed_digest('a')),
                concurrent_write: RefCell::new(None),
            }
        }
        fn explicit_review(&self, reference: &str) {
            self.expected.replace(Some(reference.into()));
            self.claimed.set(false);
        }
    }
    impl InvocationAuthority for FixtureReview {
        fn current_trust_ref(&self) -> Result<String, MigrationError> {
            Ok(self.trust_ref.borrow().clone())
        }
        fn claim(&self, binding: &ReviewBinding<'_>) -> Result<ClaimedReview, MigrationError> {
            assert!(!binding.repository_key.is_empty());
            let rollback = self.rollback.borrow();
            let required = rollback
                .as_deref()
                .map_or(ReviewedAction::Apply, ReviewedAction::Rollback);
            if binding.action != required {
                return Err(fault("REVIEW_REQUIRED"));
            }
            if self.expected.borrow().as_deref() != Some(binding.plan_ref) {
                return Err(fault("REVIEW_REQUIRED"));
            }
            if self.claimed.replace(true) {
                return Err(fault("REVIEW_REPLAYED"));
            }
            Ok(ClaimedReview {
                review_ref: fixed_digest('b'),
                expires_at: if self.expired.get() { 0 } else { 4_102_444_800 },
            })
        }
        fn recheck(&self, _: &ReviewBinding<'_>, _: &ClaimedReview) -> Result<(), MigrationError> {
            let mut concurrent_write = self.concurrent_write.borrow_mut();
            if concurrent_write.as_ref().is_some_and(|write| {
                fs::read(&write.installed).is_ok_and(|bytes| bytes == write.expected)
            }) {
                let write = concurrent_write.take().unwrap();
                fs::write(write.unrelated, b"independent writer\n").unwrap();
            }
            if self.revoked.get()
                || self
                    .revoke_after_write
                    .borrow()
                    .as_ref()
                    .is_some_and(|(path, expected)| {
                        fs::read(path).is_ok_and(|actual| actual == *expected)
                    })
            {
                Err(fault("REVIEW_REVOKED"))
            } else {
                Ok(())
            }
        }
    }

    struct FixtureGrant {
        path: &'static str,
        exact: RefCell<Option<String>>,
    }
    impl GrantValidator for FixtureGrant {
        fn validate(&self, request: &GrantRequest) -> GrantValidation {
            if self.exact.borrow().as_deref() != Some(&request.proposal_ref) {
                return GrantValidation::Missing;
            }
            if request.requirement.path != self.path
                || request.requirement.action != Action::Replace
                || request.requirement.issuer_policy_ref.as_deref() != Some(&fixed_digest('7'))
            {
                return GrantValidation::Unsupported;
            }
            GrantValidation::Authenticated(Box::new(HostAssertion::for_request(
                request,
                "controlled-fixture-reviewer",
                fixed_digest('c'),
                Some(4_102_444_800),
                None,
            )))
        }
    }

    fn policy(root: &Path) -> TrustedBasePolicy {
        policy_for(root, "contract.json")
    }

    fn policy_for(root: &Path, path: &str) -> TrustedBasePolicy {
        let evaluator = CanonicalMigrationEvaluator;
        let observed = evaluator
            .evaluate(&evaluator.observe(root).unwrap())
            .unwrap();
        let scopes = observed
            .protected_inputs
            .iter()
            .filter(|input| input.path == path)
            .map(|input| input.scope.clone())
            .collect::<BTreeSet<_>>();
        assert!(!scopes.is_empty());
        let rules = scopes
            .into_iter()
            .enumerate()
            .map(|(i, scope)| AuthorizationRule {
                id: format!("fixture-root-contract-{i}"),
                scope,
                issuer_policy_ref: fixed_digest('7'),
                actions: BTreeSet::from([Action::Replace]),
                classes: ProtectedClass::all().into_iter().collect(),
            })
            .collect();
        TrustedBasePolicy::from_host(
            observed.state.digest().unwrap(),
            observed.state.governing_identity().unwrap().unwrap(),
            fixed_digest('d'),
            false,
            rules,
        )
        .unwrap()
    }

    struct NativeUpgradeFixture {
        proposed: fortress_core::migration_governance::upgrade::EditionUpgrade,
        original: fortress_core::observation::SourceView,
        original_config: Vec<u8>,
        selected: TrustedBasePolicy,
        state_ref: String,
    }

    fn prepare_native_upgrade(fixture: &Owned, path: &str) -> NativeUpgradeFixture {
        use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
        use fortress_core::migration_adapter::CanonicalMigrationAuthority;
        use fortress_core::migration_governance::upgrade::UpgradeAdapter;
        use fortress_core::upgrade_load::{
            UpgradeOperations, inspect_upgrade_base, preview_repository_upgrade,
        };

        let config = fixture.root.join(path);
        let mut legacy: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        legacy["$schema"] = json!("urn:fortress:schema:v3:project-configuration");
        legacy["schema_version"] = json!(3);
        legacy.as_object_mut().unwrap().remove("governance");
        legacy.as_object_mut().unwrap().remove("assurance_profiles");
        let original_config = serde_json::to_vec(&legacy).unwrap();
        fs::write(&config, &original_config).unwrap();
        let original = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
        let base = inspect_upgrade_base(&fixture.root).unwrap();
        let printed = std::process::Command::new(env!("CARGO_BIN_EXE_fortress"))
            .args(["upgrade", "inspect", "--root"])
            .arg(&fixture.root)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(
            printed.status.success(),
            "{}",
            String::from_utf8_lossy(&printed.stderr)
        );
        let printed: serde_json::Value = serde_json::from_slice(&printed.stdout).unwrap();
        assert_eq!(printed["state_ref"], base.state_ref);
        let selected = policy_for(&fixture.root, path);
        let authority = CanonicalMigrationAuthority {
            policy: Some(&selected),
            host: &UnmediatedHost,
            validator: &NoGrantValidator,
            evaluation_time: None,
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        };
        let adapter = UpgradeAdapter {
            from_bundle: base.edition.clone(),
            to_bundle: base.edition.clone(),
            preview_admission: true,
        };
        let proposed = preview_repository_upgrade(
            &fixture.root,
            &adapter,
            UpgradeOperations::NativeConfiguration,
            &authority,
        )
        .unwrap();
        let repeated = preview_repository_upgrade(
            &fixture.root,
            &adapter,
            UpgradeOperations::NativeConfiguration,
            &authority,
        )
        .unwrap();
        assert_eq!(
            proposed.to_canonical_bytes().unwrap(),
            repeated.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            inspect_upgrade_base(&fixture.root).unwrap().state_ref,
            base.state_ref
        );
        assert_eq!(fs::read(&config).unwrap(), original_config);
        assert_eq!(proposed.original.profiles, proposed.target.profiles);
        assert_eq!(proposed.operations.len(), 1);
        assert!(proposed.rules.is_empty());
        assert!(proposed.admission.is_some());
        NativeUpgradeFixture {
            proposed,
            original,
            original_config,
            selected,
            state_ref: base.state_ref,
        }
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R04-001`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R04
    #[test]
    fn native_edition_upgrade_reuses_review_and_preserves_original_source() {
        use fortress_core::upgrade_load::inspect_upgrade_base;

        let external = std::env::var_os("FORTRESS_UPGRADE_NATIVE_FIXTURE").map(PathBuf::from);
        let external_snapshot = external
            .as_ref()
            .map(|path| CanonicalMigrationEvaluator.observe(path).unwrap());
        let fixture = Owned::with_source(external_snapshot.as_ref());
        let path = "__fortress/.fsconfig";
        let config = fixture.root.join(path);
        let NativeUpgradeFixture {
            proposed,
            original,
            original_config,
            selected,
            state_ref,
        } = prepare_native_upgrade(&fixture, path);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path,
            exact: RefCell::new(None),
        };
        let historical = proposed
            .original
            .application
            .as_ref()
            .unwrap()
            .declaration
            .clone();
        let historical_bytes = historical.to_canonical_bytes().unwrap();
        let historical_artifact = fixture.outer.join("original-declaration.json");
        fs::write(&historical_artifact, &historical_bytes).unwrap();

        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let token = AtomicBool::new(false);
        let plan = proposed.plan.as_ref().unwrap();
        assert_eq!(
            host.apply(plan, &token).err().unwrap().code,
            "REVIEW_REQUIRED"
        );
        review.explicit_review(plan.digest());
        assert_eq!(
            host.apply(plan, &token).err().unwrap().code,
            "AUTHORIZATION_REQUIRED"
        );
        assert_eq!(fs::read(&config).unwrap(), original_config);
        let decision = plan.authorization().governed_decision.as_ref().unwrap();
        assert!(
            decision
                .requirements
                .iter()
                .any(|requirement| requirement.path == path)
        );
        grants.exact.replace(Some(decision.proposal_ref.clone()));
        review.explicit_review(plan.digest());
        let actual = host.apply(plan, &token).unwrap().actual;
        assert_eq!(actual.receipt.actual_source_ref, plan.target_source_ref());
        assert_eq!(actual.receipt.actual_state_ref, plan.target_state_ref());
        let observed = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
        for (name, bytes) in original.iter().filter(|(name, _)| *name != path) {
            assert_eq!(observed.bytes(name), Some(bytes.as_slice()), "{name}");
        }
        if let Some(external) = external {
            assert_eq!(
                CanonicalMigrationEvaluator.observe(&external).unwrap(),
                external_snapshot.unwrap()
            );
        }
        assert_ne!(fs::read(&config).unwrap(), original_config);
        let retained = fs::read_to_string(&historical_artifact).unwrap();
        assert_eq!(retained.as_bytes(), historical_bytes);
        let retained =
            fortress_core::declaration::ConformanceDeclaration::from_json_str(&retained).unwrap();
        assert_eq!(retained, historical);
        assert_ne!(
            retained.binding.authority_ref,
            proposed
                .target
                .application
                .as_ref()
                .unwrap()
                .declaration
                .binding
                .authority_ref
        );
        assert_ne!(
            inspect_upgrade_base(&fixture.root).unwrap().state_ref,
            state_ref
        );
        assert!(host.apply(plan, &token).is_err());
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-001`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn exact_review_and_protected_grants_are_required_before_real_writes() {
        let fixture = Owned::new();
        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let file = fixture.root.join("contract.json");
        let original = fs::read_to_string(&file).unwrap();
        let replacement = original.replace("Mediator Fixture", "Reviewed Fixture");
        assert_ne!(original, replacement);
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "contract.json".into(),
                preimage: original.as_bytes().into(),
                postimage: replacement.as_bytes().into(),
            }])
            .unwrap();
        let token = AtomicBool::new(false);
        assert_eq!(
            host.apply(&plan, &token).err().unwrap().code,
            "REVIEW_REQUIRED"
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
        review.explicit_review(plan.digest());
        assert_eq!(
            host.apply(&plan, &token).err().unwrap().code,
            "AUTHORIZATION_REQUIRED"
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
        assert_eq!(
            host.apply(&plan, &token).err().unwrap().code,
            "REVIEW_REPLAYED"
        );

        let decision = plan.authorization().governed_decision.as_ref().unwrap();
        assert!(!decision.requirements.is_empty());
        grants.exact.replace(Some(decision.proposal_ref.clone()));
        review.explicit_review(plan.digest());
        let applied = host.apply(&plan, &token).unwrap();
        assert_eq!(applied.review_provenance.plan_ref, plan.digest());
        assert_eq!(
            applied.review_provenance.semantics,
            "PROVENANCE_ONLY_NOT_TRANSFERABLE"
        );
        let result = applied.actual;
        assert_eq!(result.receipt.actual_state_ref, plan.target_state_ref());
        assert_eq!(result.receipt.actual_source_ref, plan.target_source_ref());
        assert_eq!(fs::read_to_string(&file).unwrap(), replacement);
        assert!(!result.receipt.grant_provenance.is_empty());
        assert_eq!(
            result
                .receipt
                .authorization
                .governed_decision
                .as_ref()
                .unwrap()
                .host_coverage
                .state,
            "MEDIATED"
        );
        let exported = result.receipt.to_canonical_bytes().unwrap();
        assert_eq!(
            fs::read(fixture.root.join(&result.record_path)).unwrap(),
            exported
        );
        assert!(
            fortress_core::migration_governance::MigrationPlan::from_json_str(
                std::str::from_utf8(&exported).unwrap()
            )
            .is_err()
        );
        let restarted = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        assert_eq!(
            restarted.apply(&plan, &token).err().unwrap().code,
            "REVIEW_REPLAYED"
        );
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-002`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn cancellation_revocation_policy_change_and_stale_base_do_not_write() {
        let fixture = Owned::new();
        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let file = fixture.root.join("src/lib.rs");
        let original = fs::read(&file).unwrap();
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "src/lib.rs".into(),
                preimage: original.clone(),
                postimage: b"pub fn value() -> u8 { 2 }\n".to_vec(),
            }])
            .unwrap();
        review.explicit_review(plan.digest());
        let stopped = AtomicBool::new(true);
        assert_eq!(host.apply(&plan, &stopped).err().unwrap().code, "CANCELLED");
        assert!(!review.claimed.get());
        let running = AtomicBool::new(false);
        review.revoked.set(true);
        assert_eq!(
            host.apply(&plan, &running).err().unwrap().code,
            "REVIEW_REVOKED"
        );
        review.revoked.set(false);
        review.explicit_review(plan.digest());
        review.expired.set(true);
        assert_eq!(
            host.apply(&plan, &running).err().unwrap().code,
            "AUTHORIZATION_EXPIRED"
        );
        review.expired.set(false);
        review.explicit_review(plan.digest());
        review.trust_ref.replace(fixed_digest('e'));
        assert_eq!(
            host.apply(&plan, &running).err().unwrap().code,
            "TRUST_CONTEXT_CHANGED"
        );
        assert_eq!(fs::read(&file).unwrap(), original);
        review.trust_ref.replace(fixed_digest('a'));
        fs::write(&file, b"independent bytes").unwrap();
        assert_eq!(
            host.apply(&plan, &running).err().unwrap().code,
            "STALE_REVIEWED_PLAN"
        );
        assert_eq!(fs::read(&file).unwrap(), b"independent bytes");
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-003`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn post_image_revocation_requires_fresh_review_for_recovery() {
        use fortress_core::migration_governance::MigrationRecoveryMode;
        let fixture = Owned::new();
        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let file = fixture.root.join("contract.json");
        let original = fs::read_to_string(&file).unwrap();
        let replacement = original
            .replace("Mediator Fixture", "Reviewed Fixture")
            .into_bytes();
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "contract.json".into(),
                preimage: original.as_bytes().into(),
                postimage: replacement.clone(),
            }])
            .unwrap();
        let proposal = &plan
            .authorization()
            .governed_decision
            .as_ref()
            .unwrap()
            .proposal_ref;
        grants.exact.replace(Some(proposal.clone()));
        review.explicit_review(plan.digest());
        review
            .revoke_after_write
            .replace(Some((file.clone(), replacement.clone())));

        let token = AtomicBool::new(false);
        let error = host.apply(&plan, &token).err().unwrap();
        assert_eq!(error.code, "REVIEW_REVOKED");
        let transaction = error.transaction_ref.unwrap();
        assert_eq!(fs::read(&file).unwrap(), replacement);
        assert!(
            host.recover(&plan, &transaction, MigrationRecoveryMode::Rollback, &token)
                .is_err()
        );

        review.revoke_after_write.replace(None);
        review.rollback.replace(Some(transaction.clone()));
        review.explicit_review(plan.digest());
        let recovered = host
            .recover(&plan, &transaction, MigrationRecoveryMode::Rollback, &token)
            .unwrap()
            .actual;
        assert_eq!(recovered.actual_source_ref, plan.base_source_ref());
        assert!(recovered.receipt.is_none());
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-004`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn postwrite_divergence_invalidates_prediction() {
        let fixture = Owned::new();
        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let file = fixture.root.join("src/lib.rs");
        let independent = fixture.root.join("src/independent.rs");
        let records = fixture.root.join("__fortress/records/migrations");
        let original_receipts = fs::read_dir(&records).unwrap().count();
        let original = fs::read(&file).unwrap();
        let replacement = b"pub fn value() -> u8 { 3 }\n".to_vec();
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "src/lib.rs".into(),
                preimage: original,
                postimage: replacement.clone(),
            }])
            .unwrap();
        review.explicit_review(plan.digest());
        review.concurrent_write.replace(Some(ConcurrentWrite {
            installed: file.clone(),
            expected: replacement.clone(),
            unrelated: independent.clone(),
        }));
        let error = host.apply(&plan, &AtomicBool::new(false)).err().unwrap();
        assert_eq!(error.code, "ACTUAL_TARGET_MISMATCH");
        assert!(error.transaction_ref.is_some());
        assert_eq!(fs::read(&file).unwrap(), replacement);
        assert_eq!(fs::read(&independent).unwrap(), b"independent writer\n");
        assert_eq!(fs::read_dir(records).unwrap().count(), original_receipts);
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-005`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn advertised_forbidden_edit_is_blocked_before_write() {
        use fortress_core::contract_coherency::ModuleContract;
        use fortress_core::development_governance::Disposition;
        use fortress_core::project::ProjectConfiguration;

        let fixture = Owned::new();
        let mut contract: Value =
            serde_json::from_slice(&fs::read(fixture.root.join("contract.json")).unwrap()).unwrap();
        let directory = fixture.root.join("_data/logical_modules/code");
        fs::create_dir_all(&directory).unwrap();
        contract["id"] = json!("AF-MEDIATOR-CODE-0001");
        contract["display_name"] = json!("Reviewed Code");
        contract.as_object_mut().unwrap().remove("ecosystem");
        contract["$schema"] = json!("urn:fortress:schema:v3:module-contract");
        contract["schema_version"] = json!(3);
        contract["semantic_policy"] = json!({
            "default": "UNDECLARED",
            "capabilities": {"allow": [], "deny": []},
            "effects": {"allow": [], "deny": ["filesystem.write"]}
        });
        let contract: ModuleContract = serde_json::from_value(contract).unwrap();
        fs::write(
            directory.join("contract.json"),
            contract.to_canonical_json().unwrap(),
        )
        .unwrap();
        let config_path = fixture.root.join("__fortress/.fsconfig");
        let mut configuration: Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        configuration["logical_modules"] = json!([{
            "module": "AF-MEDIATOR-CODE-0001", "contract": "_data/logical_modules/code/contract.json",
            "parent": "PF-MEDIATOR-FIXTURE", "bindings": [{"kind": "directory", "path": "src"}]
        }]);
        let mut config_bytes = serde_json::to_string_pretty(&configuration).unwrap();
        config_bytes.push('\n');
        ProjectConfiguration::from_json_str(&config_bytes).unwrap();
        fs::write(config_path, config_bytes).unwrap();

        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let file = fixture.root.join("src/lib.rs");
        let original = fs::read(&file).unwrap();
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "src/lib.rs".into(),
                preimage: original.clone(),
                postimage: b"pub fn value() { let _ = std::fs::write(\"output\", b\"x\"); }\n"
                    .to_vec(),
            }])
            .unwrap();
        let decision = plan.authorization().governed_decision.as_ref().unwrap();
        assert_eq!(decision.disposition, Disposition::DenySupportedViolation);
        assert!(decision.requirements.is_empty());
        review.explicit_review(plan.digest());
        let error = host.apply(&plan, &AtomicBool::new(false)).err().unwrap();
        assert_eq!(error.code, "AUTHORIZATION_REQUIRED");
        assert!(error.message.contains("DenySupportedViolation"));
        assert!(error.transaction_ref.is_none());
        assert_eq!(fs::read(&file).unwrap(), original);
        assert!(!fixture.root.join("output").exists());
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-006`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn stale_or_forged_evidence_selection_cannot_use_the_mediator() {
        use fortress_core::control_layout::{ControlLayout, ControlRole};

        let fixture = Owned::new();
        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let layout = ControlLayout::standard();
        let path = layout
            .role_path(ControlRole::AssessmentSelectionIndex)
            .unwrap();
        let selected_path = fixture.root.join(path);
        assert!(!selected_path.exists());
        let result = host.preview(vec![MigrationOperation::CreateFile {
            path: path.into(),
            postimage: br#"{"schema_version":1,"generation_digest":"forged"}"#.to_vec(),
        }]);
        assert_eq!(result.err().unwrap().code, "PROTECTED_OUTPUT_PATH");
        assert!(!selected_path.exists());
        assert!(!review.claimed.get());
    }

    /// `T-TF-AGENT-INTEGRATION-0001-R02-007`
    /// Fortress requirement: TF-AGENT-INTEGRATION-0001-R02
    #[test]
    fn valid_edit_with_unrelated_unknown_is_not_false_denied() {
        use fortress_core::audit::compile_repository_state_effect_analysis;
        use fortress_core::development_governance::Disposition;

        let fixture = Owned::new();
        let file = fixture.root.join("src/lib.rs");
        let original = b"pub fn value() -> u8 { 1 }\npub fn invoke<F: Fn()>(f: F) { f(); }\n";
        let replacement = b"pub fn value() -> u8 { 2 }\npub fn invoke<F: Fn()>(f: F) { f(); }\n";
        fs::write(&file, original).unwrap();
        let effects = compile_repository_state_effect_analysis(&fixture.root).unwrap();
        let uncertainty =
            |effects: &fortress_core::state_effect_analysis::StateEffectAnalysisEvaluation| {
                effects
                    .model()
                    .summaries()
                    .iter()
                    .filter(|summary| !summary.uncertainty().is_empty())
                    .map(|summary| (summary.symbol().to_owned(), summary.uncertainty().to_vec()))
                    .collect::<Vec<_>>()
            };
        let original_uncertainty = uncertainty(&effects);
        assert!(!original_uncertainty.is_empty());

        let selected = policy(&fixture.root);
        let review = FixtureReview::new();
        let grants = FixtureGrant {
            path: "contract.json",
            exact: RefCell::new(None),
        };
        let host = TrustedMediator::from_host(
            &fixture.root,
            &fixed_digest('a'),
            &selected,
            &review,
            &grants,
            &fixture.storage,
        )
        .unwrap();
        let plan = host
            .preview(vec![MigrationOperation::ReplaceFile {
                path: "src/lib.rs".into(),
                preimage: original.to_vec(),
                postimage: replacement.to_vec(),
            }])
            .unwrap();
        let decision = plan.authorization().governed_decision.as_ref().unwrap();
        assert_eq!(decision.disposition, Disposition::Permit);
        assert!(decision.requirements.is_empty());
        review.explicit_review(plan.digest());
        let result = host.apply(&plan, &AtomicBool::new(false)).unwrap().actual;
        assert_eq!(result.receipt.actual_source_ref, plan.target_source_ref());
        assert_eq!(fs::read(file).unwrap(), replacement);
        let effects = compile_repository_state_effect_analysis(&fixture.root).unwrap();
        assert_eq!(uncertainty(&effects), original_uncertainty);
    }
}

/// `T-TF-AGENT-INTEGRATION-0001-R01-002`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn installed_mcp_rejects_replayed_ids_malformed_frames_and_unadvertised_writes() {
    let mut client = Client::launch();
    client.initialize();
    client.send(&call(
        2,
        "migrate_apply",
        json!({"authorization":"fabricated"}),
    ));
    assert_eq!(client.receive()["error"]["code"], -32602);
    client.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
    assert_eq!(client.receive()["error"]["code"], -32600);
    writeln!(client.input(), "{{\"id\":3,\"id\":4}}").unwrap();
    assert_eq!(client.receive()["error"]["code"], -32700);
    writeln!(client.input(), "{}", "x".repeat(65_537)).unwrap();
    assert_eq!(client.receive()["error"]["data"]["code"], "RESOURCE_LIMIT");
    client.send(&json!({"jsonrpc":"2.0","id":5,"method":"ping"}));
    assert_eq!(client.receive()["id"], 5);
    assert_eq!(
        fs::read(client.root.join("fixture.txt")).unwrap(),
        b"reviewed bytes"
    );
}

/// `T-TF-AGENT-INTEGRATION-0001-R01-003`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn installed_mcp_previews_exact_candidate_without_writing_or_claiming_authority() {
    let mut client = Client::launch_mode(true);
    client.initialize();
    client.send(&call(2, "fortress_candidate_base", json!({})));
    let base = client.receive();
    let base = &base["result"]["structuredContent"];
    assert_eq!(base["status"], "OBSERVED_BASE");
    let operation = fortress_core::migration_governance::MigrationOperation::ReplaceFile {
        path: "fixture.txt".into(),
        preimage: b"reviewed bytes".to_vec(),
        postimage: b"candidate only".to_vec(),
    };
    let mut request = json!({
        "schema_version":1,"base_source_ref":base["base_source_ref"],
        "context_ref":base["context_ref"],"operations":[operation]
    });
    client.send(&call(
        3,
        "fortress_evaluate_candidate",
        json!({"request":request}),
    ));
    let result = client.receive();
    assert_eq!(result["result"]["isError"], false, "{result}");
    let proposed = &result["result"]["structuredContent"];
    assert_eq!(proposed["status"], "PROPOSED");
    assert_eq!(proposed["actual_state"], false);
    request["base_source_ref"] = json!(format!("sha256:{}", "7".repeat(64)));
    client.send(&call(
        4,
        "fortress_evaluate_candidate",
        json!({"request":request}),
    ));
    let stale = client.receive();
    assert_eq!(
        stale["result"]["structuredContent"]["error"]["code"],
        "STALE_BASE"
    );
    assert_eq!(
        fs::read(client.root.join("fixture.txt")).unwrap(),
        b"reviewed bytes"
    );
    assert!(!client.root.join("forbidden-build-marker").exists());
    assert!(!client.root.join("__fortress").exists());
    client.close();
}

/// `T-TF-AGENT-INTEGRATION-0001-R01-004`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R01
#[test]
fn process_negotiation_and_disconnect_keep_native_editions_and_connections_separate() {
    let mut first = Client::launch();
    first.send(&json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}));
    assert_eq!(first.receive()["error"]["data"]["code"], "NOT_INITIALIZED");
    first.send(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2099-01-01", "capabilities": {},
                   "clientInfo": {"name": "unsupported-edition", "version": "1"}}
    }));
    assert_eq!(first.receive()["result"]["protocolVersion"], "2025-11-25");
    first.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let request =
        json!({"protocol_version":6,"request_id":"unsupported","method":"status","parameters":{}});
    first.send(&call(2, "fortress_inspect", json!({"request":request})));
    assert_eq!(
        first.receive()["result"]["structuredContent"]["error"]["code"],
        "UNSUPPORTED_VERSION"
    );
    first.close();

    let mut second = Client::launch();
    second.initialize();
    second.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
    assert_eq!(second.receive()["result"], json!({}));
    second.close();
}

/// `T-TF-AGENT-INTEGRATION-0001-R03-001`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R03
#[test]
fn provider_configuration_is_distinct_from_enforcement_and_grants() {
    use fortress_cli::github_rules::*;
    use std::cell::Cell;

    struct Read {
        branch: BranchIdentity,
        requests: Cell<u16>,
        mode: &'static str,
    }
    impl GitHubRulesRead for Read {
        fn branch_identity(&self) -> Result<BranchIdentity, ProviderFailure> {
            let mut value = self.branch.clone();
            if self.mode == "drift" && self.requests.get() > 0 {
                value.head = "1".repeat(40);
            }
            Ok(value)
        }
        fn rules_page(&self, page: u16) -> Result<RulePage, ProviderFailure> {
            self.requests.set(self.requests.get() + 1);
            let verify = match self.mode {
                "outage" => return Err(ProviderFailure::Unavailable),
                "permission" => return Err(ProviderFailure::InsufficientPermission),
                "invalid" => {
                    return Ok(RulePage {
                        body: br#"[{"type":"creation","type":"update"}]"#.to_vec(),
                        next_page: None,
                    });
                }
                "gap" => Some(3),
                _ if page == 1 => Some(2),
                _ => None,
            };
            let body = if page == 1 {
                br#"[{"type":"required_status_checks","ruleset_id":92}]"#.to_vec()
            } else if self.mode == "rule_drift" && self.requests.get() > 2 {
                br#"[{"type":"required_linear_history","ruleset_id":92}]"#.to_vec()
            } else {
                br#"[{"ruleset_id":92,"type":"non_fast_forward"}]"#.to_vec()
            };
            Ok(RulePage {
                body,
                next_page: verify,
            })
        }
    }
    let target = BranchIdentity {
        repository_id: 72,
        branch: "protected".into(),
        head: "a".repeat(40),
    };
    let read = |mode| Read {
        branch: target.clone(),
        requests: Cell::new(0),
        mode,
    };
    let ok = observe_rules(&target, &read("ok"));
    assert_eq!(ok.configuration_status, "ACTIVE_RULES_OBSERVED");
    assert_eq!(
        ok.rule_types,
        ["non_fast_forward", "required_status_checks"]
    );
    assert_eq!(ok.active_rule_refs.len(), 2);
    assert_eq!(ok.write_enforcement, "UNVERIFIED");
    assert_eq!(ok.proposal_authorization, "NONE");
    assert_eq!(
        observe_rules(&target, &read("drift")).configuration_status,
        "TARGET_CHANGED"
    );
    assert_eq!(
        observe_rules(&target, &read("rule_drift")).configuration_status,
        "CONFIGURATION_CHANGED"
    );
    for (mode, reason) in [
        ("outage", ProviderFailure::Unavailable),
        ("permission", ProviderFailure::InsufficientPermission),
        ("gap", ProviderFailure::Incomplete),
        ("invalid", ProviderFailure::Incomplete),
    ] {
        let result = observe_rules(&target, &read(mode));
        assert_eq!(result.unavailable, Some(reason));
        assert!(result.active_rule_refs.is_empty());
        assert_eq!(result.write_enforcement, "UNVERIFIED");
    }
}
