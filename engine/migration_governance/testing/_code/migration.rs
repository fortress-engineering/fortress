//! Transaction planning and recovery regression controls.
use std::collections::BTreeMap;

use fortress_core::migration_governance::{MigrationOperation as Op, OperationGraph};
use fortress_core::observation::SourceView;

fn source(files: &[(&str, &[u8])]) -> SourceView {
    SourceView::from_bytes(files.iter().map(|(p, b)| (*p, b.to_vec()))).unwrap()
}
fn moved(from: &str, to: &str, bytes: &[u8]) -> Op {
    Op::MovePath {
        source: from.into(),
        destination: to.into(),
        preimage: bytes.to_vec(),
    }
}
fn create(path: &str, bytes: &[u8]) -> Op {
    Op::CreateFile {
        path: path.into(),
        postimage: bytes.to_vec(),
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R01-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R01
#[test]
fn move_cycle_and_case_collision_are_explicit() {
    let base = source(&[("a", b"A"), ("b", b"B"), ("c", b"C")]);
    let operations = vec![
        moved("a", "b", b"A"),
        moved("b", "c", b"B"),
        moved("c", "a", b"C"),
    ];
    let graph = OperationGraph::compile(&base, operations.clone(), &BTreeMap::new()).unwrap();
    assert_eq!(graph.target().bytes("a"), Some(&b"C"[..]));
    assert_eq!(graph.target().bytes("b"), Some(&b"A"[..]));
    assert_eq!(graph.target().bytes("c"), Some(&b"B"[..]));
    for step in graph.steps() {
        assert!(step.dependencies.iter().all(|id| *id < step.id));
    }
    let mut reversed = operations;
    reversed.reverse();
    assert_eq!(
        graph.digest().unwrap(),
        OperationGraph::compile(&base, reversed, &BTreeMap::new())
            .unwrap()
            .digest()
            .unwrap()
    );
    assert!(OperationGraph::compile(&base, vec![create("A", b"other")], &BTreeMap::new()).is_err());
    assert!(OperationGraph::compile(&base, vec![moved("a", "A", b"A")], &BTreeMap::new()).is_err());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R01-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R01
#[test]
fn stale_preimages_and_overlapping_operations_are_rejected() {
    let base = source(&[("a", b"original")]);
    assert!(
        OperationGraph::compile(&base, vec![moved("a", "b", b"wrong")], &BTreeMap::new()).is_err()
    );
    assert!(
        OperationGraph::compile(
            &base,
            vec![moved("a", "b", b"original"), moved("a", "c", b"original")],
            &BTreeMap::new()
        )
        .is_err()
    );
    assert!(
        OperationGraph::compile(
            &base,
            vec![create("x", b"X"), create("x/y", b"Y")],
            &BTreeMap::new()
        )
        .is_err()
    );
    assert!(
        OperationGraph::compile(&base, vec![create("../outside", b"X")], &BTreeMap::new()).is_err()
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R01-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R01
#[test]
fn replacements_and_owned_deletions_preserve_exact_bytes() {
    let base = source(&[("replace", &[0, 255, 13, 10]), ("owned", b"remove")]);
    let operations = vec![
        Op::ReplaceFile {
            path: "replace".into(),
            preimage: vec![0, 255, 13, 10],
            postimage: vec![0, 254, 10],
        },
        Op::DeleteOwnedFile {
            path: "owned".into(),
            preimage: b"remove".to_vec(),
            owner_ref: "module:owned".into(),
        },
    ];
    assert!(OperationGraph::compile(&base, operations.clone(), &BTreeMap::new()).is_err());
    let owners = BTreeMap::from([("owned".into(), "module:owned".into())]);
    let graph = OperationGraph::compile(&base, operations, &owners).unwrap();
    assert_eq!(graph.target().bytes("replace"), Some(&[0, 254, 10][..]));
    assert!(graph.target().bytes("owned").is_none());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R01-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R01
#[test]
fn no_op_plans_are_deterministic_without_hidden_mutations() {
    let base = source(&[("same", b"same")]);
    let empty = OperationGraph::compile(&base, vec![], &BTreeMap::new()).unwrap();
    let same = OperationGraph::compile(
        &base,
        vec![
            moved("same", "same", b"same"),
            Op::ReplaceFile {
                path: "same".into(),
                preimage: b"same".to_vec(),
                postimage: b"same".to_vec(),
            },
        ],
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(same.steps().is_empty());
    assert_eq!(same.target(), &base);
    assert_eq!(same.digest().unwrap(), empty.digest().unwrap());
}

use fortress_core::development_governance::{
    ApplicationAuthorityRecord, ApplicationAuthorization, GrantRequest, GrantValidation,
    GrantValidator, HostAssertion, authorize_ungoverned_unprotected,
};
use fortress_core::migration_governance::*;
use fortress_core::observation::CandidateChangeSet;
use fortress_core::state_governance::{ComparisonContext, ComparisonState};
use fortress_core::state_view::{StateView, StateViewStatus};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn fault(code: &str) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: code.into(),
        transaction_ref: None,
    }
}
struct ByteEvaluator;
impl MigrationEvaluator for ByteEvaluator {
    fn evaluate(&self, s: &SourceView) -> Result<MigrationEvaluation, MigrationError> {
        let subject = fortress_core::certification::certification_source_digest(s.files());
        Ok(MigrationEvaluation {
            state: ComparisonState {
                schema: "urn:fortress:derived:v1:comparison-state".into(),
                schema_version: 1,
                source_ref: Some(subject.clone()),
                view: Some(StateView {
                    schema: "urn:fortress:derived:v3:state-view".into(),
                    schema_version: 3,
                    source_ref: subject,
                    status: StateViewStatus::Ungoverned,
                    detail: None,
                    application: None,
                    portable_evidence_graph: None,
                }),
                retained_application: None,
                assets: None,
                origin_ref: None,
                limitations: vec!["Test byte-only evaluator; no semantic assurance.".into()],
            },
            evaluated_source: s.clone(),
            ownership: BTreeMap::new(),
            protected_inputs: vec![],
            validations: BTreeMap::from([(
                MigrationValidation::EvaluationCompleted,
                MigrationValidationFact {
                    state: MigrationValidationState::Satisfied,
                    evidence_refs: vec![],
                    detail: "Fixture immutable bytes evaluated.".into(),
                },
            )]),
        })
    }
    fn observe(&self, root: &Path) -> Result<SourceView, MigrationError> {
        fn walk(
            root: &Path,
            dir: &Path,
            files: &mut Vec<(String, Vec<u8>)>,
        ) -> Result<(), MigrationError> {
            for item in fs::read_dir(dir).map_err(|_| fault("IO_ERROR"))? {
                let path = item.map_err(|_| fault("IO_ERROR"))?.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                if relative == ".git" {
                    continue;
                }
                let m = fs::symlink_metadata(&path).map_err(|_| fault("IO_ERROR"))?;
                if m.file_type().is_symlink() {
                    return Err(fault("UNSAFE_PATH"));
                }
                if m.is_dir() {
                    walk(root, &path, files)?;
                } else if fortress_core::control_layout::ControlLayout::standard()
                    .resolve(&relative)
                    .is_none_or(|r| {
                        r.source_binding()
                            == fortress_core::control_layout::ControlSourceBinding::Required
                    })
                {
                    files.push((relative, fs::read(path).map_err(|_| fault("IO_ERROR"))?));
                }
            }
            Ok(())
        }
        let mut files = vec![];
        walk(root, root, &mut files)?;
        SourceView::from_bytes(files).map_err(|_| fault("INVALID_SOURCE"))
    }
}
struct UnprotectedAuthority;
impl MigrationAuthority for UnprotectedAuthority {
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorityRecord, MigrationError> {
        Ok(self
            .authorize(base, target, source, changes, context)?
            .record()
            .clone())
    }
    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorization, MigrationError> {
        authorize_ungoverned_unprotected(&base.state, &target.state, context, source, changes)
            .map_err(|e| fault(&e.code))
    }
}
struct Fixture {
    root: PathBuf,
    transaction: PathBuf,
    active: Cell<bool>,
    leased: Cell<bool>,
    fail_storage: Cell<bool>,
    finished: RefCell<Vec<String>>,
}
impl Fixture {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "fx-migration-test-{}-{unique}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let root = parent.join("repository");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a"), b"A\r\n\0\xff").unwrap();
        fs::write(root.join("b"), b"B").unwrap();
        Self {
            root,
            transaction: parent.join("transaction"),
            active: Cell::new(false),
            leased: Cell::new(false),
            fail_storage: Cell::new(false),
            finished: RefCell::new(vec![]),
        }
    }
    fn plan(&self) -> MigrationPlan {
        preview_migration(
            &ByteEvaluator,
            &UnprotectedAuthority,
            &ByteEvaluator.observe(&self.root).unwrap(),
            vec![
                moved("a", "b", b"A\r\n\0\xff"),
                moved("b", "a", b"B"),
                create("nested/new", b"new\n"),
            ],
            MigrationOptions::default(),
        )
        .unwrap()
        .plan
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.root.parent().unwrap());
    }
}
struct FixtureLease<'a> {
    fixture: &'a Fixture,
    identity: String,
}
impl Drop for FixtureLease<'_> {
    fn drop(&mut self) {
        self.fixture.leased.set(false);
    }
}
struct FixtureResources<'a>(&'a Fixture);
impl<'a> ResourceLeasePort for FixtureResources<'a> {
    type Lease = FixtureLease<'a>;
    fn acquire(&self, _: &Path, _: &str, _: u64) -> Result<Self::Lease, MigrationError> {
        if self.0.fail_storage.get() {
            return Err(fault("INSUFFICIENT_STORAGE"));
        }
        if self.0.active.get() || self.0.leased.replace(true) {
            return Err(fault("LEASE_CONFLICT"));
        }
        fs::create_dir(&self.0.transaction).map_err(|_| fault("LEASE_CONFLICT"))?;
        Ok(FixtureLease {
            fixture: self.0,
            identity: fortress_core::heavy_admission::native_object_identity(&self.0.root).unwrap(),
        })
    }
    fn recover(&self, _: &Path, t: &str, _: &str) -> Result<Self::Lease, MigrationError> {
        if t != "fixture-transaction" || self.0.leased.replace(true) {
            return Err(fault("LEASE_CONFLICT"));
        }
        Ok(FixtureLease {
            fixture: self.0,
            identity: fortress_core::heavy_admission::native_object_identity(&self.0.root).unwrap(),
        })
    }
}
impl MigrationResourceLease for FixtureLease<'_> {
    fn root(&self) -> &Path {
        self.fixture.transaction.as_path()
    }
    fn transaction_ref(&self) -> &'static str {
        "fixture-transaction"
    }
    fn repository_identity(&self) -> &str {
        &self.identity
    }
    fn verify(&self, r: &Path) -> Result<(), MigrationError> {
        if fortress_core::heavy_admission::native_object_identity(r).unwrap() == self.identity {
            Ok(())
        } else {
            Err(fault("OWNERSHIP_CONFLICT"))
        }
    }
    fn reserve(&self, _: u64) -> Result<(), MigrationError> {
        if self.fixture.fail_storage.get() {
            Err(fault("INSUFFICIENT_STORAGE"))
        } else {
            Ok(())
        }
    }
    fn object_identity(&self, p: &Path) -> Result<String, MigrationError> {
        fortress_core::heavy_admission::native_object_identity(p)
            .map_err(|_| fault("OWNERSHIP_CONFLICT"))
    }
    fn applying(&mut self, _: &str, _: &Path) -> Result<(), MigrationError> {
        self.fixture.active.set(true);
        Ok(())
    }
    fn finish(&mut self, o: &str, _: &str) -> Result<(), MigrationError> {
        self.fixture.active.set(false);
        self.fixture.finished.borrow_mut().push(o.into());
        Ok(())
    }
}
struct StopAt {
    ordinal: Option<u64>,
    count: Cell<u64>,
    code: &'static str,
}
impl MutationObserver for StopAt {
    fn boundary(
        &self,
        n: u64,
        _: MutationBoundary,
        _: BoundaryPhase,
    ) -> Result<(), MigrationError> {
        self.count.set(n + 1);
        if self.ordinal == Some(n) {
            Err(fault(self.code))
        } else {
            Ok(())
        }
    }
}
fn execute<O: MutationObserver>(
    f: &Fixture,
    p: &MigrationPlan,
    o: &O,
) -> Result<MigrationApplication, MigrationError> {
    apply_migration(
        &f.root,
        p,
        &MigrationServices {
            evaluator: &ByteEvaluator,
            authority: &UnprotectedAuthority,
            resources: &FixtureResources(f),
            observer: o,
        },
    )
}
fn recover(
    f: &Fixture,
    p: &MigrationPlan,
    mode: MigrationRecoveryMode,
) -> Result<MigrationRecovery, MigrationError> {
    recover_migration(
        &f.root,
        p,
        "fixture-transaction",
        mode,
        &MigrationServices {
            evaluator: &ByteEvaluator,
            authority: &UnprotectedAuthority,
            resources: &FixtureResources(f),
            observer: &NoMutationFaults,
        },
    )
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R02-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R02
#[test]
fn stale_reviewed_plan_writes_nothing() {
    let f = Fixture::new();
    let p = f.plan();
    let bytes = p.to_canonical_bytes().unwrap();
    assert_eq!(
        MigrationPlan::from_json_str(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .digest(),
        p.digest()
    );
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["target_source_ref"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
    assert_eq!(
        MigrationPlan::from_json_str(&value.to_string())
            .unwrap_err()
            .code,
        "TAMPERED_PLAN"
    );
    fs::write(f.root.join("a"), b"independent").unwrap();
    assert_eq!(
        execute(&f, &p, &NoMutationFaults).err().unwrap().code,
        "STALE_REVIEWED_PLAN"
    );
    assert!(!f.transaction.exists());
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"independent");
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R06-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R06
#[test]
fn apply_cycle_preserves_exact_bytes_and_validates_actual_target() {
    let f = Fixture::new();
    let p = f.plan();
    let result = execute(&f, &p, &NoMutationFaults).unwrap();
    assert_eq!(fs::read(f.root.join("b")).unwrap(), b"A\r\n\0\xff");
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"B");
    assert_eq!(
        ByteEvaluator.observe(&f.root).unwrap().digest(),
        p.target_source_ref()
    );
    assert!(f.root.join(result.record_path).is_file());
    assert!(!f.active.get());
    assert_eq!(
        MigrationReceipt::from_json_str(
            std::str::from_utf8(&result.receipt.to_canonical_bytes().unwrap()).unwrap()
        )
        .unwrap()
        .digest(),
        result.receipt.digest()
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R04-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R04
#[test]
fn crash_at_every_write_boundary_recovers() {
    let completed = Fixture::new();
    let p = completed.plan();
    let counter = StopAt {
        ordinal: None,
        count: Cell::new(0),
        code: "INJECTED_CRASH",
    };
    execute(&completed, &p, &counter).unwrap();
    let count = counter.count.get();
    assert!(count > 50);
    for code in ["INJECTED_CRASH", "CANCELLED", "INSUFFICIENT_STORAGE"] {
        for ordinal in 0..count {
            let f = Fixture::new();
            let p = f.plan();
            let stopped = StopAt {
                ordinal: Some(ordinal),
                count: Cell::new(0),
                code,
            };
            let error = execute(&f, &p, &stopped).err().unwrap();
            assert_eq!(error.code, code, "boundary {ordinal}");
            let result = recover(&f, &p, MigrationRecoveryMode::Resume)
                .unwrap_or_else(|e| panic!("resume boundary {ordinal}: {e}"));
            assert!(!f.active.get(), "boundary {ordinal}");
            assert!(
                result.actual_source_ref == p.base_source_ref()
                    || result.actual_source_ref == p.target_source_ref()
            );
            assert_eq!(
                fs::read(f.root.join("a")).unwrap(),
                if result.receipt.is_some() {
                    b"B".as_slice()
                } else {
                    b"A\r\n\0\xff".as_slice()
                }
            );
        }
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R04-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R04
#[test]
fn user_edit_during_recovery_is_preserved() {
    struct StopAfterInstall;
    impl MutationObserver for StopAfterInstall {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::Install && p == BoundaryPhase::After {
                Err(fault("CANCELLED"))
            } else {
                Ok(())
            }
        }
    }
    let f = Fixture::new();
    let p = f.plan();
    f.fail_storage.set(true);
    assert_eq!(
        execute(&f, &p, &NoMutationFaults).err().unwrap().code,
        "INSUFFICIENT_STORAGE"
    );
    assert!(!f.transaction.exists());
    let f = Fixture::new();
    let p = f.plan();
    assert!(execute(&f, &p, &StopAfterInstall).is_err());
    fs::write(f.root.join("a"), b"user edit").unwrap();
    assert_eq!(
        recover(&f, &p, MigrationRecoveryMode::Rollback)
            .err()
            .unwrap()
            .code,
        "RECOVERY_CONFLICT"
    );
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"user edit");
    assert!(f.active.get());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R05-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R05
#[test]
fn rollback_is_idempotent_or_conflicted() {
    struct Stop;
    impl MutationObserver for Stop {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::Install && p == BoundaryPhase::After {
                Err(fault("CANCELLED"))
            } else {
                Ok(())
            }
        }
    }
    let f = Fixture::new();
    let plan = f.plan();
    execute(&f, &plan, &Stop).err().unwrap();
    let first = recover(&f, &plan, MigrationRecoveryMode::Rollback).unwrap();
    assert_eq!(first.actual_source_ref, plan.base_source_ref());
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"A\r\n\0\xff");
    let again = recover(&f, &plan, MigrationRecoveryMode::Rollback).unwrap();
    assert_eq!(again.actual_source_ref, first.actual_source_ref);
    assert!(recover(&f, &plan, MigrationRecoveryMode::Resume).is_err());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R06-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R06
#[test]
fn final_actual_state_must_match_evaluated_target() {
    struct Drift<'a>(&'a Path);
    impl MutationObserver for Drift<'_> {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::ReceiptPublication && p == BoundaryPhase::Before {
                fs::write(self.0.join("independent"), b"edit").unwrap();
            }
            Ok(())
        }
    }
    let f = Fixture::new();
    let plan = f.plan();
    assert_eq!(
        execute(&f, &plan, &Drift(&f.root)).err().unwrap().code,
        "ACTUAL_TARGET_MISMATCH"
    );
    assert_eq!(fs::read(f.root.join("independent")).unwrap(), b"edit");
    assert!(f.active.get());
    assert_eq!(
        fs::read_dir(f.root.join("__fortress/records/migrations"))
            .unwrap()
            .count(),
        0
    );
    assert!(recover(&f, &plan, MigrationRecoveryMode::Rollback).is_err());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R04-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R04
#[test]
fn readers_refuse_in_progress_generation() {
    use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
    use fortress_core::migration_adapter::{
        CanonicalMigrationAuthority, CanonicalMigrationEvaluator,
    };
    use fortress_core::runtime_storage::{MigrationStorage, StoragePolicy};
    let f = Fixture::new();
    let evaluator = CanonicalMigrationEvaluator;
    let authority = CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let before = evaluator.observe(&f.root).unwrap();
    let plan = preview_migration(
        &evaluator,
        &authority,
        &before,
        vec![create("extra", b"extra")],
        MigrationOptions::default(),
    )
    .unwrap()
    .plan;
    let root = f.root.parent().unwrap().join("ops");
    let policy = StoragePolicy {
        reserve_bytes: 0,
        projection_budget_bytes: 128 * 1024 * 1024,
        ..StoragePolicy::default()
    };
    let storage = MigrationStorage::new(root, policy).unwrap();
    let services = MigrationServices {
        evaluator: &evaluator,
        authority: &authority,
        resources: &storage,
        observer: &NoMutationFaults,
    };
    let error = apply_migration(
        &f.root,
        &plan,
        &MigrationServices {
            evaluator: &evaluator,
            authority: &authority,
            resources: &storage,
            observer: &StopAfterActive,
        },
    )
    .err()
    .unwrap();
    assert!(fortress_core::heavy_admission::assert_no_incomplete_migration(&f.root).is_err());
    assert!(fortress_core::audit::compile_repository_state_view(&f.root).is_err());
    let other = preview_migration(
        &evaluator,
        &authority,
        &before,
        vec![create("different", b"different")],
        MigrationOptions::default(),
    )
    .unwrap()
    .plan;
    assert!(
        recover_migration(
            &f.root,
            &other,
            error.transaction_ref.as_deref().unwrap(),
            MigrationRecoveryMode::Resume,
            &services
        )
        .is_err()
    );
    assert_eq!(evaluator.observe(&f.root).unwrap(), before);
    let python = python_reader(&f.root);
    assert!(!python.status.success());
    assert!(String::from_utf8_lossy(&python.stderr).contains("MIGRATION_IN_PROGRESS"));
    let recovered = recover_migration(
        &f.root,
        &plan,
        error.transaction_ref.as_deref().unwrap(),
        MigrationRecoveryMode::Resume,
        &services,
    )
    .unwrap();
    assert_eq!(recovered.actual_source_ref, plan.target_source_ref());
    fortress_core::heavy_admission::assert_no_incomplete_migration(&f.root).unwrap();
    assert!(python_reader(&f.root).status.success());
    assert!(fortress_core::audit::compile_repository_state_view(&f.root).is_ok());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R02-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R02
#[test]
fn unknown_validation_and_retirement_references_cannot_enable_application() {
    let f = Fixture::new();
    let before = ByteEvaluator.observe(&f.root).unwrap();
    let mut options = MigrationOptions::default();
    options
        .retirement_evidence_refs
        .insert(format!("sha256:{}", "a".repeat(64)));
    let preview = preview_migration(
        &ByteEvaluator,
        &UnprotectedAuthority,
        &before,
        vec![create("new", b"new")],
        options,
    )
    .unwrap();
    assert!(!preview.plan.validations_satisfied());
    assert_eq!(
        execute(&f, &preview.plan, &NoMutationFaults)
            .err()
            .unwrap()
            .code,
        "VALIDATION_REQUIRED"
    );
    assert!(!f.transaction.exists());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R02-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R02
#[test]
fn malformed_versions_duplicate_records_and_resource_exhaustion_are_explicit() {
    let f = Fixture::new();
    let plan = f.plan();
    let mut json: serde_json::Value =
        serde_json::from_slice(&plan.to_canonical_bytes().unwrap()).unwrap();
    json["schema_version"] = 2.into();
    assert_eq!(
        MigrationPlan::from_json_str(&json.to_string())
            .unwrap_err()
            .code,
        "UNSUPPORTED_VERSION"
    );
    assert!(MigrationPlan::from_json_str("{\"schema_version\":1,\"schema_version\":1}").is_err());
    let original: serde_json::Value =
        serde_json::from_slice(&plan.to_canonical_bytes().unwrap()).unwrap();
    for field in [
        "operation_graph",
        "preconditions",
        "inverse_expectations",
        "validation_facts",
    ] {
        let mut malformed = original.clone();
        malformed[field] = if field == "validation_facts" {
            serde_json::json!({})
        } else {
            serde_json::json!([])
        };
        malformed["plan_digest"] = "".into();
        let bytes = fortress_core::wire::canonicalize_public_json(&malformed.to_string()).unwrap();
        malformed["plan_digest"] = format!("sha256:{:x}", Sha256::digest(bytes)).into();
        assert!(
            MigrationPlan::from_json_str(&malformed.to_string()).is_err(),
            "rehashed malformed {field}"
        );
    }
    let too_many = vec![create("new", b"new"); MAX_MIGRATION_OPERATIONS + 1];
    assert_eq!(
        OperationGraph::compile(&source(&[]), too_many, &BTreeMap::new())
            .unwrap_err()
            .code,
        "RESOURCE_LIMIT"
    );
    for path in [
        "C:/outside",
        ".git/config",
        "../escape",
        "__fortress/records/migrations/arbitrary.json",
        "a/../b",
        "NUL.txt",
        "path ",
    ] {
        assert!(
            OperationGraph::compile(&source(&[]), vec![create(path, b"x")], &BTreeMap::new())
                .is_err(),
            "{path}"
        );
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R05-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R05
#[test]
fn identical_bytes_from_an_independent_postimage_are_not_owned() {
    struct Stop;
    impl MutationObserver for Stop {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::Install && p == BoundaryPhase::After {
                Err(fault("CANCELLED"))
            } else {
                Ok(())
            }
        }
    }
    let f = Fixture::new();
    let p = f.plan();
    execute(&f, &p, &Stop).err().unwrap();
    fs::remove_file(f.root.join("a")).unwrap();
    fs::write(f.root.join("a"), b"B").unwrap();
    assert!(recover(&f, &p, MigrationRecoveryMode::Rollback).is_err());
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"B");
    assert!(f.active.get());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R05-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R05
#[test]
fn incomplete_or_tampered_journals_preserve_source_and_recovery_material() {
    struct Stop;
    impl MutationObserver for Stop {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::Evacuate && p == BoundaryPhase::After {
                Err(fault("CANCELLED"))
            } else {
                Ok(())
            }
        }
    }
    let f = Fixture::new();
    let p = f.plan();
    execute(&f, &p, &Stop).err().unwrap();
    let before = ByteEvaluator.observe(&f.root).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(f.transaction.join("operations.jsonl"))
        .unwrap()
        .write_all(b"{incomplete")
        .unwrap();
    assert_eq!(
        recover(&f, &p, MigrationRecoveryMode::Resume)
            .err()
            .unwrap()
            .code,
        "JOURNAL_INCOMPLETE"
    );
    assert_eq!(ByteEvaluator.observe(&f.root).unwrap(), before);
    let slot = p
        .operation_graph()
        .iter()
        .find_map(|s| match &s.action {
            ExecutableAction::Evacuate { slot, .. } => Some(slot),
            _ => None,
        })
        .unwrap();
    assert!(f.transaction.join("slots").join(slot).exists());
    assert!(f.active.get());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R06-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R06
#[test]
fn public_schemas_digest_reproduction_and_registered_exports_agree() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    let p = f.plan();
    let applied = execute(&f, &p, &NoMutationFaults).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let schemas = manifest["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(root.join(p.as_str().unwrap())).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    for (value, digest, key) in [
        (serde_json::to_value(&p).unwrap(), p.digest(), "plan_digest"),
        (
            serde_json::to_value(&applied.receipt).unwrap(),
            applied.receipt.digest(),
            "receipt_digest",
        ),
    ] {
        let schema = schemas
            .iter()
            .find(|s| s["$id"] == value["$schema"])
            .unwrap();
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
        validator.validate(&value).unwrap();
        let mut unsigned = value;
        unsigned[key] = "".into();
        let bytes = fortress_core::wire::canonicalize_public_json(&unsigned.to_string()).unwrap();
        assert_eq!(digest, format!("sha256:{:x}", Sha256::digest(bytes)));
    }
    let before = ByteEvaluator.observe(&f.root).unwrap();
    let export = export_reviewed_migration_plan(&f.root, &p).unwrap();
    assert_eq!(ByteEvaluator.observe(&f.root).unwrap(), before);
    assert_eq!(
        MigrationPlan::from_json_str(&fs::read_to_string(f.root.join(export)).unwrap())
            .unwrap()
            .digest(),
        p.digest()
    );
    assert!(p.to_human().contains(p.base_state_ref()));
    assert!(
        applied
            .receipt
            .to_human()
            .contains(&applied.receipt.actual_source_ref)
    );
}

fn adopted() -> Fixture {
    let f = Fixture::new();
    let proposal = fortress_core::bootstrap::discover_repository_bootstrap(
        &f.root,
        &fortress_core::bootstrap::BootstrapDiscoveryOptions::new(
            Some("PF-MIGRATION-FIXTURE".into()),
            Some("Migration Fixture".into()),
        ),
    )
    .unwrap();
    let applied =
        fortress_core::bootstrap::apply_repository_bootstrap(&f.root, &proposal, false).unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&applied.to_canonical_json().unwrap()).unwrap();
    assert!(
        result["migration_receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    f
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R07-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R07
#[test]
fn bootstrap_uses_the_common_engine_and_preserves_existing_source() {
    let f = adopted();
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"A\r\n\0\xff");
    assert!(f.root.join("__fortress/.fsconfig").is_file());
    assert_eq!(
        fs::read_dir(f.root.join("__fortress/records/migrations"))
            .unwrap()
            .count(),
        1
    );
    assert!(fortress_core::audit::compile_repository_state_view(&f.root).is_ok());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R07-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R07
#[test]
fn identity_no_op_reuses_the_common_engine_without_a_false_grant() {
    let f = adopted();
    let before = CanonicalMigrationEvaluator.observe(&f.root).unwrap();
    let plan =
        fortress_core::identity_migration::plan_repository_identity_migration(&f.root).unwrap();
    assert!(plan.files().is_empty());
    let applied =
        fortress_core::identity_migration::apply_repository_identity_migration(&f.root, &plan)
            .unwrap();
    assert_eq!(applied.files_written(), 0);
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&f.root).unwrap(),
        before
    );
}

use fortress_core::migration_adapter::CanonicalMigrationEvaluator;
/// `T-AF-MIGRATION-GOVERNANCE-0001-R03-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R03
#[test]
fn local_approval_assertions_cannot_enable_protected_changes() {
    assert!(
        fortress_core::authority_roles::protected_owner_roles("AF-MIGRATION-GOVERNANCE-0001")
            .contains(&fortress_core::authority_roles::ProtectedClass::AssessorTrust)
    );
    let f = Fixture::new();
    let before = ByteEvaluator.observe(&f.root).unwrap();
    let error = preview_migration(
        &ByteEvaluator,
        &UnprotectedAuthority,
        &before,
        vec![create(
            "contract.json",
            br#"{"approved":true,"approval":"owner"}"#,
        )],
        MigrationOptions::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "AUTHORIZATION_REQUIRED");
    assert!(!f.transaction.exists());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R03-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R03
#[test]
fn protected_native_application_accepts_only_exact_external_grants() {
    use fortress_core::development_governance::*;
    use fortress_core::migration_adapter::CanonicalMigrationAuthority;
    let f = adopted();
    let before = CanonicalMigrationEvaluator.observe(&f.root).unwrap();
    let evaluated = CanonicalMigrationEvaluator.evaluate(&before).unwrap();
    let preimage = before.bytes("contract.json").unwrap().to_vec();
    let text = std::str::from_utf8(&preimage)
        .unwrap()
        .replace("Migration Fixture", "Reviewed Fixture");
    assert_ne!(text.as_bytes(), preimage);
    let policy = trusted_policy(&evaluated);
    let missing = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let operation = Op::ReplaceFile {
        path: "contract.json".into(),
        preimage,
        postimage: text.into_bytes(),
    };
    let preview = preview_migration(
        &CanonicalMigrationEvaluator,
        &missing,
        &before,
        vec![operation],
        MigrationOptions::default(),
    )
    .unwrap();
    assert!(
        apply_migration(
            &f.root,
            &preview.plan,
            &MigrationServices {
                evaluator: &CanonicalMigrationEvaluator,
                authority: &missing,
                resources: &FixtureResources(&f),
                observer: &NoMutationFaults
            }
        )
        .is_err()
    );
    assert!(!f.transaction.exists());
    let allowed = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &Owner,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let applied = apply_migration(
        &f.root,
        &preview.plan,
        &MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &allowed,
            resources: &FixtureResources(&f),
            observer: &NoMutationFaults,
        },
    );
    let dimensions = preview
        .base
        .state
        .view
        .as_ref()
        .unwrap()
        .application
        .as_ref()
        .unwrap()
        .declaration
        .dimensions
        .iter()
        .map(|d| (&d.id, d.truth))
        .collect::<Vec<_>>();
    assert!(
        applied.is_ok(),
        "{applied_error:?}; base dimensions={dimensions:?}; original cells={}",
        preview
            .plan
            .options()
            .comparison_context
            .counterfactuals
            .len(),
        applied_error = applied.as_ref().err()
    );
    let result = applied.unwrap();
    assert!(!result.receipt.grant_provenance.is_empty());
    assert_eq!(
        result.receipt.actual_state_ref,
        preview.plan.target_state_ref()
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R04-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R04
#[test]
fn reparse_or_symlink_parent_escape_writes_nothing_outside() {
    let f = Fixture::new();
    let plan = f.plan();
    let outside = f.root.parent().unwrap().join("independent-outside");
    fs::create_dir(&outside).unwrap();
    let link = f.root.join("nested");
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(execute(&f, &plan, &NoMutationFaults).is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"A\r\n\0\xff");
    #[cfg(windows)]
    fs::remove_dir(link).unwrap();
    #[cfg(unix)]
    fs::remove_file(link).unwrap();
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R05-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R05
#[test]
fn recovery_itself_can_be_interrupted_at_each_boundary() {
    struct InitialStop;
    impl MutationObserver for InitialStop {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::Install && p == BoundaryPhase::After {
                Err(fault("CANCELLED"))
            } else {
                Ok(())
            }
        }
    }
    fn recover_with<O: MutationObserver>(
        f: &Fixture,
        p: &MigrationPlan,
        mode: MigrationRecoveryMode,
        o: &O,
    ) -> Result<MigrationRecovery, MigrationError> {
        recover_migration(
            &f.root,
            p,
            "fixture-transaction",
            mode,
            &MigrationServices {
                evaluator: &ByteEvaluator,
                authority: &UnprotectedAuthority,
                resources: &FixtureResources(f),
                observer: o,
            },
        )
    }
    for mode in [
        MigrationRecoveryMode::Resume,
        MigrationRecoveryMode::Rollback,
    ] {
        let first = Fixture::new();
        let plan = first.plan();
        execute(&first, &plan, &InitialStop).err().unwrap();
        let counter = StopAt {
            ordinal: None,
            count: Cell::new(0),
            code: "INJECTED_CRASH",
        };
        recover_with(&first, &plan, mode, &counter).unwrap();
        for ordinal in 0..counter.count.get() {
            let f = Fixture::new();
            let plan = f.plan();
            execute(&f, &plan, &InitialStop).err().unwrap();
            let stop = StopAt {
                ordinal: Some(ordinal),
                count: Cell::new(0),
                code: "INJECTED_CRASH",
            };
            assert_eq!(
                recover_with(&f, &plan, mode, &stop).err().unwrap().code,
                "INJECTED_CRASH"
            );
            let final_result = recover(&f, &plan, mode)
                .unwrap_or_else(|e| panic!("{mode:?} recovery boundary {ordinal}: {e}"));
            assert_eq!(
                final_result.actual_source_ref,
                if mode == MigrationRecoveryMode::Resume {
                    plan.target_source_ref()
                } else {
                    plan.base_source_ref()
                }
            );
            assert!(!f.active.get());
        }
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R06-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R06
#[test]
fn final_path_kind_is_checked_independently_of_file_inventory() {
    struct DirectoryDrift<'a>(&'a Path);
    impl MutationObserver for DirectoryDrift<'_> {
        fn boundary(
            &self,
            _: u64,
            k: MutationBoundary,
            p: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if k == MutationBoundary::ReceiptPublication && p == BoundaryPhase::Before {
                fs::create_dir(self.0.join("a")).unwrap();
            }
            Ok(())
        }
    }
    let f = Fixture::new();
    let before = ByteEvaluator.observe(&f.root).unwrap();
    let p = preview_migration(
        &ByteEvaluator,
        &UnprotectedAuthority,
        &before,
        vec![moved("a", "renamed", b"A\r\n\0\xff")],
        MigrationOptions::default(),
    )
    .unwrap()
    .plan;
    assert!(execute(&f, &p, &DirectoryDrift(&f.root)).is_err());
    assert!(f.root.join("a").is_dir());
    assert!(f.active.get());
    assert_eq!(
        fs::read_dir(f.root.join("__fortress/records/migrations"))
            .unwrap()
            .count(),
        0
    );
    assert!(recover(&f, &p, MigrationRecoveryMode::Rollback).is_err());
    assert!(f.root.join("a").is_dir());
}

fn trusted_policy(
    evaluated: &MigrationEvaluation,
) -> fortress_core::development_governance::TrustedBasePolicy {
    use fortress_core::development_governance::*;
    use std::collections::BTreeSet;
    let scopes = evaluated
        .protected_inputs
        .iter()
        .map(|p| p.scope.clone())
        .chain(std::iter::once("project".into()))
        .collect::<BTreeSet<_>>();
    let rules = scopes
        .into_iter()
        .enumerate()
        .map(|(i, scope)| AuthorizationRule {
            id: format!("scope-{i}"),
            classes: ProtectedClass::all().into_iter().collect(),
            actions: BTreeSet::from([
                Action::Create,
                Action::Replace,
                Action::Delete,
                Action::Move,
            ]),
            scope,
            issuer_policy_ref: format!("sha256:{}", "7".repeat(64)),
        })
        .collect();
    TrustedBasePolicy::from_host(
        evaluated.state.digest().unwrap(),
        evaluated.state.governing_identity().unwrap().unwrap(),
        format!("sha256:{}", "8".repeat(64)),
        false,
        rules,
    )
    .unwrap()
}
struct Owner;
impl GrantValidator for Owner {
    fn validate(&self, r: &GrantRequest) -> GrantValidation {
        GrantValidation::Authenticated(Box::new(HostAssertion::for_request(
            r,
            "external-fixture-owner",
            format!("sha256:{}", "9".repeat(64)),
            None,
            None,
        )))
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R03-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R03
#[test]
fn finding_governance_requires_owner_review_separately_from_external_grants() {
    use fortress_core::development_governance::UnmediatedHost;
    use fortress_core::migration_adapter::CanonicalMigrationAuthority;
    let f = adopted();
    let before = CanonicalMigrationEvaluator.observe(&f.root).unwrap();
    let evaluated = CanonicalMigrationEvaluator.evaluate(&before).unwrap();
    let original = fortress_core::lifecycle_load::load_finding_authority(&f.root).unwrap();
    let audit = fortress_core::audit::audit_repository(&f.root).unwrap();
    let proposal = fortress_core::lifecycle_load::propose_baseline(
        &original,
        &evaluated.state,
        &[],
        audit.standard_id(),
        audit.standard_edition(),
    )
    .unwrap();
    let path = fortress_core::control_layout::ControlLayout::standard()
        .role_path(fortress_core::control_layout::ControlRole::FindingGovernance)
        .unwrap()
        .to_owned();
    let operation = Op::ReplaceFile {
        path: path.clone(),
        preimage: before.bytes(&path).unwrap().to_vec(),
        postimage: proposal
            .proposed_governance()
            .to_canonical_json()
            .unwrap()
            .into_bytes(),
    };
    let policy = trusted_policy(&evaluated);
    let mut authority = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &Owner,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let denied = preview_migration(
        &CanonicalMigrationEvaluator,
        &authority,
        &before,
        vec![operation.clone()],
        MigrationOptions::default(),
    )
    .err()
    .unwrap();
    assert_eq!(
        denied.code, "REVIEWED_LIFECYCLE_PROPOSAL_REQUIRED",
        "{denied:?}"
    );
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&f.root).unwrap(),
        before
    );
    authority.finding_proposal = Some(&proposal);
    assert!(
        preview_migration(
            &CanonicalMigrationEvaluator,
            &authority,
            &before,
            vec![operation.clone(), create("unrelated", b"drift")],
            MigrationOptions::default()
        )
        .is_err()
    );
    let preview = preview_migration(
        &CanonicalMigrationEvaluator,
        &authority,
        &before,
        vec![operation],
        MigrationOptions::default(),
    )
    .unwrap();
    let applied = apply_migration(
        &f.root,
        &preview.plan,
        &MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &authority,
            resources: &FixtureResources(&f),
            observer: &NoMutationFaults,
        },
    )
    .unwrap();
    assert!(!applied.receipt.grant_provenance.is_empty());
    assert_eq!(
        fs::read(f.root.join(&path)).unwrap(),
        proposal
            .proposed_governance()
            .to_canonical_json()
            .unwrap()
            .as_bytes()
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R07-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R07
#[test]
fn identity_schema_upgrade_routes_real_edits_through_authorized_common_writer() {
    use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
    use fortress_core::migration_adapter::CanonicalMigrationAuthority;
    let f = adopted();
    let path = "_data/function_contracts.json";
    fs::create_dir(f.root.join("_data")).unwrap();
    let legacy = b"{\n  \"$schema\": \"urn:fortress:schema:v4:function-contracts\",\n  \"schema_version\": 4,\n  \"functions\": []\n}\n";
    let legacy = fortress_core::semantic_analysis::canonicalize_function_contract_json(
        path,
        std::str::from_utf8(legacy).unwrap(),
    )
    .unwrap();
    fs::write(f.root.join(path), legacy).unwrap();
    let before = CanonicalMigrationEvaluator.observe(&f.root).unwrap();
    let evaluated = CanonicalMigrationEvaluator.evaluate(&before).unwrap();
    let policy = trusted_policy(&evaluated);
    let plan =
        fortress_core::identity_migration::plan_repository_identity_migration(&f.root).unwrap();
    assert_eq!(plan.files().len(), 1);
    let missing = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    assert!(
        fortress_core::identity_migration::apply_repository_identity_migration_with_services(
            &f.root,
            &plan,
            &MigrationServices {
                evaluator: &CanonicalMigrationEvaluator,
                authority: &missing,
                resources: &FixtureResources(&f),
                observer: &NoMutationFaults
            }
        )
        .is_err()
    );
    assert_eq!(
        CanonicalMigrationEvaluator.observe(&f.root).unwrap(),
        before
    );
    let allowed = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &Owner,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let result =
        fortress_core::identity_migration::apply_repository_identity_migration_with_services(
            &f.root,
            &plan,
            &MigrationServices {
                evaluator: &CanonicalMigrationEvaluator,
                authority: &allowed,
                resources: &FixtureResources(&f),
                observer: &NoMutationFaults,
            },
        )
        .unwrap();
    assert_eq!(result.files_written(), 1);
    let actual: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root.join(path)).unwrap()).unwrap();
    assert_eq!(actual["schema_version"], 5);
    assert!(
        fortress_core::identity_migration::plan_repository_identity_migration(&f.root)
            .unwrap()
            .files()
            .is_empty()
    );
}

fn python_reader(root: &Path) -> std::process::Output {
    let modules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../snapshot_governance/_code");
    std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-B", "-c", "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from heavy_admission import assert_no_incomplete_migration; assert_no_incomplete_migration(Path(sys.argv[2]))"])
        .arg(modules).arg(root).output().unwrap()
}

struct StopAfterActive;
impl MutationObserver for StopAfterActive {
    fn boundary(
        &self,
        _: u64,
        k: MutationBoundary,
        p: BoundaryPhase,
    ) -> Result<(), MigrationError> {
        if k == MutationBoundary::ActiveState && p == BoundaryPhase::After {
            Err(fault("CANCELLED"))
        } else {
            Ok(())
        }
    }
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R04-005`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R04
#[test]
fn header_without_operation_journal_recovers_only_verified_original_bytes() {
    struct Stop<'a>(&'a Path);
    impl MutationObserver for Stop<'_> {
        fn boundary(
            &self,
            _: u64,
            kind: MutationBoundary,
            phase: BoundaryPhase,
        ) -> Result<(), MigrationError> {
            if kind == MutationBoundary::Preparation
                && phase == BoundaryPhase::After
                && self.0.join("header.json").is_file()
                && !self.0.join("operations.jsonl").exists()
            {
                Err(fault("INJECTED_CRASH"))
            } else {
                Ok(())
            }
        }
    }
    let f = Fixture::new();
    let plan = f.plan();
    let original = ByteEvaluator.observe(&f.root).unwrap();
    assert_eq!(
        execute(&f, &plan, &Stop(&f.transaction))
            .err()
            .unwrap()
            .code,
        "INJECTED_CRASH"
    );
    assert!(f.transaction.join("header.json").is_file());
    assert!(!f.transaction.join("operations.jsonl").exists());
    let cancelled = StopAt {
        ordinal: Some(0),
        count: Cell::new(0),
        code: "CANCELLED",
    };
    let failure = recover_migration(
        &f.root,
        &plan,
        "fixture-transaction",
        MigrationRecoveryMode::Resume,
        &MigrationServices {
            evaluator: &ByteEvaluator,
            authority: &UnprotectedAuthority,
            resources: &FixtureResources(&f),
            observer: &cancelled,
        },
    )
    .err()
    .unwrap();
    assert_eq!(failure.code, "CANCELLED");
    let result = recover(&f, &plan, MigrationRecoveryMode::Resume).unwrap();
    assert_eq!(result.outcome, "ORIGINAL_BYTES_VERIFIED_INCOMPLETE_JOURNAL");
    assert!(result.receipt.is_none());
    assert_eq!(ByteEvaluator.observe(&f.root).unwrap(), original);
    assert!(f.transaction.join("header.json").is_file());
    let changed = Fixture::new();
    let reviewed = changed.plan();
    execute(&changed, &reviewed, &Stop(&changed.transaction))
        .err()
        .unwrap();
    fs::write(changed.root.join("a"), b"independent edit").unwrap();
    assert!(recover(&changed, &reviewed, MigrationRecoveryMode::Rollback).is_err());
    assert_eq!(
        fs::read(changed.root.join("a")).unwrap(),
        b"independent edit"
    );
    assert!(changed.transaction.join("header.json").is_file());
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R03-005`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R03
#[test]
fn excluded_non_rust_assessor_files_keep_their_declared_protected_owner() {
    let fixture = adopted();
    let path = "custom_surface/_code/runner.py";
    fs::create_dir_all(fixture.root.join("custom_surface/_code")).unwrap();
    let contract = serde_json::json!({"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,"id":"AF-MIGRATION-GOVERNANCE-0001","display_name":"Relocated Assessor","provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]});
    let contract: fortress_core::contract_coherency::ModuleContract =
        serde_json::from_value(contract).unwrap();
    fs::write(
        fixture.root.join("custom_surface/contract.json"),
        contract.to_canonical_json().unwrap(),
    )
    .unwrap();
    let script = b"raise RuntimeError('inspection must not execute this project file')\n";
    fs::write(fixture.root.join(path), script).unwrap();
    let config = fixture.root.join("__fortress/.fsconfig");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    document["observation_exclusions"]
        .as_array_mut()
        .unwrap()
        .push(path.into());
    fs::write(
        &config,
        format!("{}\n", serde_json::to_string_pretty(&document).unwrap()),
    )
    .unwrap();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    assert_eq!(source.bytes(path), Some(script.as_slice()));
    let evaluated = CanonicalMigrationEvaluator.evaluate(&source).unwrap();
    assert!(!evaluated.evaluated_source.contains_key(path));
    assert_eq!(
        evaluated.ownership.get(path).map(String::as_str),
        Some("AF-MIGRATION-GOVERNANCE-0001")
    );
    assert!(
        evaluated
            .protected_inputs
            .iter()
            .any(|input| input.path == path
                && input.class
                    == fortress_core::development_governance::ProtectedClass::AssessorTrust)
    );
    assert_eq!(fs::read(fixture.root.join(path)).unwrap(), script);
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R07-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R07
#[test]
fn identity_governance_normalization_requires_opaque_owner_output_and_external_permission() {
    use fortress_core::development_governance::UnmediatedHost;
    use fortress_core::migration_adapter::CanonicalMigrationAuthority;
    let fixture = adopted();
    let path = "__fortress/governance/finding_governance.json";
    let original = fortress_core::lifecycle_load::load_finding_authority(&fixture.root).unwrap();
    fs::write(
        fixture.root.join(path),
        serde_json::to_vec(&original).unwrap(),
    )
    .unwrap();
    let source = CanonicalMigrationEvaluator.observe(&fixture.root).unwrap();
    let evaluated = CanonicalMigrationEvaluator.evaluate(&source).unwrap();
    let plan = fortress_core::identity_migration::plan_repository_identity_migration(&fixture.root)
        .unwrap();
    assert_eq!(plan.files().len(), 1);
    let policy = trusted_policy(&evaluated);
    let audit = fortress_core::audit::audit_repository(&fixture.root).unwrap();
    let conflicting = fortress_core::lifecycle_load::propose_baseline(
        &original,
        &evaluated.state,
        &[],
        audit.standard_id(),
        audit.standard_edition(),
    )
    .unwrap();

    let mut authority = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &Owner,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    assert!(
        fortress_core::identity_migration::preview_repository_identity_migration(
            &fixture.root,
            &plan,
            &CanonicalMigrationEvaluator,
            &authority
        )
        .is_err()
    );
    authority.identity_plan = Some(&plan);
    authority.finding_proposal = Some(&conflicting);
    let denied = fortress_core::identity_migration::preview_repository_identity_migration(
        &fixture.root,
        &plan,
        &CanonicalMigrationEvaluator,
        &authority,
    )
    .err()
    .unwrap();
    assert!(denied.to_string().contains("AMBIGUOUS_MAINTENANCE_PROOF"));
    authority.finding_proposal = None;

    let result =
        fortress_core::identity_migration::apply_repository_identity_migration_with_services(
            &fixture.root,
            &plan,
            &MigrationServices {
                evaluator: &CanonicalMigrationEvaluator,
                authority: &authority,
                resources: &FixtureResources(&fixture),
                observer: &NoMutationFaults,
            },
        )
        .unwrap();
    assert_eq!(result.files_written(), 1);
    let current = fortress_core::lifecycle_load::load_finding_authority(&fixture.root).unwrap();
    assert_eq!(
        original.authority_digest().unwrap(),
        current.authority_digest().unwrap()
    );
    assert_eq!(
        fs::read(fixture.root.join(path)).unwrap(),
        current.to_canonical_json().unwrap().as_bytes()
    );
}
