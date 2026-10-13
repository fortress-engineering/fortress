//! Storage lifecycle contract vectors for the installed Rust runtime.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fortress_core::heavy_admission::DirectoryIdentity;
use fortress_core::runtime_storage::{EmptyRunRetirement, RuntimeStorage, StoragePolicy};
use fortress_core::wire::parse_strict_json_bytes;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fortress-runtime-storage-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("repository")).expect("test repository");
        fs::create_dir_all(root.join("storage")).expect("test storage");
        Self(root)
    }

    fn storage(&self) -> RuntimeStorage {
        RuntimeStorage::new(
            &self.0.join("repository"),
            &self.0.join("storage"),
            StoragePolicy {
                reserve_bytes: 0,
                ..StoragePolicy::default()
            },
        )
        .expect("runtime storage")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn active_runtime_target_lease_prevents_second_job() {
    let fixture = Fixture::new();
    let runtime = fixture.storage();
    let first = runtime.acquire_workspace().expect("first lease");
    assert!(runtime.acquire_workspace().is_err());
    drop(first);
    assert!(runtime.acquire_workspace().is_ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn runtime_reserve_rejects_before_staging() {
    let fixture = Fixture::new();
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: u64::MAX,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime storage");
    assert!(runtime.acquire_workspace().is_err());
    assert!(!fixture.0.join("storage/rust/r").exists());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn runtime_retains_staging_for_unwaited_child() {
    let fixture = Fixture::new();
    let runtime = fixture.storage();
    let mut workspace = runtime.acquire_workspace().expect("workspace");
    let staging = workspace.staging();
    fs::write(staging.join("child-output"), b"in use").expect("child output");
    workspace
        .record_child(std::process::id())
        .expect("record child");
    let report = workspace.release().expect("release with uncertain child");
    assert_eq!(report.lifecycle, "RECOVERY_REQUIRED");
    assert!(staging.exists());
    let recovered = runtime.recover_owned_orphans().expect("recovery review");
    assert!(
        recovered
            .iter()
            .any(|(_, status)| status == "RETAINED_UNCERTAIN")
    );
    assert!(runtime.acquire_workspace().is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn selected_runtime_compiler_cleanup_requires_marker() {
    let fixture = Fixture::new();
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: 0,
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime storage");
    let mut workspace = runtime.acquire_workspace().expect("workspace");
    let target = workspace.compiler_target().to_path_buf();
    fs::write(target.join("compiled"), b"owned").expect("compiler output");
    workspace.validating().expect("validation");
    workspace.publish("generation").expect("publication");
    let report = workspace.release().expect("owned cleanup");
    assert_eq!(report.retained_bytes, 0);
    assert!(!target.exists());
}

const INTERRUPTED_FIXTURE_ENV: &str = "FORTRESS_R17_INTERRUPTED_FIXTURE";
const INTERRUPTED_FIXTURE_TEST: &str =
    "empty_interrupted_runtime_preserves_residue_and_publication";
const FIXTURE_RECORD_LIMIT: usize = 128 * 1024;
const REGISTRY_RECORD_LIMIT: usize = 16 * 1024;

fn fixture_file_identity(file: &File) -> (u64, u64) {
    #[cfg(windows)]
    {
        let info = winapi_util::file::information(file).expect("fixture file identity");
        (info.volume_serial_number(), info.file_index())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let info = file.metadata().expect("fixture file metadata");
        (info.dev(), info.ino())
    }
    #[cfg(not(any(windows, unix)))]
    {
        panic!("native fixture identity is unsupported")
    }
}

fn plain_fixture_file(path: &Path) {
    let info = fs::symlink_metadata(path).expect("fixture record metadata");
    assert!(info.is_file() && !info.file_type().is_symlink());
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(info.file_attributes() & 0x400, 0, "fixture reparse record");
    }
}

// These reads are only of paths handed off by a freshly created child fixture.
// They retain an opened identity, impose admission before capture, and compare
// a complete literal second read rather than trusting JSON equivalence.
fn fixture_bytes(path: &Path, limit: usize) -> Vec<u8> {
    plain_fixture_file(path);
    let mut file = File::open(path).expect("open fixture record");
    let before = file.metadata().expect("opened fixture metadata");
    let limit = u64::try_from(limit).expect("fixture limit fits u64");
    assert!(before.len() <= limit, "fixture record exceeds bound");
    let identity = fixture_file_identity(&file);
    let mut first = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut first)
        .expect("first fixture read");
    assert_eq!(u64::try_from(first.len()).unwrap(), before.len());
    file.rewind().expect("rewind fixture record");
    let mut second = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut second)
        .expect("second fixture read");
    assert_eq!(first, second, "fixture literal preimage changed");
    let after = file.metadata().expect("final opened fixture metadata");
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    assert_eq!(identity, fixture_file_identity(&file));
    plain_fixture_file(path);
    let path_file = File::open(path).expect("reopen fixture path");
    assert_eq!(identity, fixture_file_identity(&path_file));
    assert_eq!(after.len(), path_file.metadata().unwrap().len());
    assert_eq!(
        after.modified().unwrap(),
        path_file.metadata().unwrap().modified().unwrap()
    );
    first
}

fn fixture_json(path: &Path, limit: usize) -> (Value, Vec<u8>) {
    let bytes = fixture_bytes(path, limit);
    let value = parse_strict_json_bytes(&bytes).expect("strict fixture JSON");
    (value, bytes)
}

fn fixture_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("write only fixture-owned record");
    file.write_all(bytes).expect("fixture write");
    file.sync_all().expect("fixture sync");
}

fn fixture_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn common_fixture_root(native_key: &str) -> PathBuf {
    #[cfg(windows)]
    let anchor = PathBuf::from(r"\\?\GLOBALROOT\SystemRoot\Temp");
    #[cfg(unix)]
    let anchor = PathBuf::from("/tmp");
    #[cfg(not(any(windows, unix)))]
    let anchor = PathBuf::new();
    anchor.join("fortress-ops/admission-v1").join(native_key)
}

fn interrupted_fixture_child(root: &Path) -> ! {
    let runtime = RuntimeStorage::new(
        &root.join("repository"),
        &root.join("storage"),
        StoragePolicy {
            reserve_bytes: 0,
            ..StoragePolicy::default()
        },
    )
    .expect("child runtime storage");
    let mut workspace = runtime.acquire_workspace().expect("child workspace");
    workspace.validating().expect("child validation boundary");
    workspace
        .publish("empty-retirement-fixture")
        .expect("child publication");
    let staging = workspace.staging();
    let run_root = staging.parent().expect("child run root");
    let nonce = run_root.file_name().unwrap().to_str().unwrap();
    let short = run_root.parent().unwrap().file_name().unwrap();
    let storage = run_root.ancestors().nth(4).unwrap();
    let journal = storage
        .join("rust/x")
        .join(short)
        .join(format!("{nonce}.json"));
    let handoff = json!({
        "nonce": nonce,
        "run_root": run_root,
        "journal_path": journal,
        "compiler_path": workspace.compiler_target(),
    });
    fixture_write(
        &root.join("interrupted-fixture.json"),
        &serde_json::to_vec(&handoff).unwrap(),
    );
    // This deliberately bypasses RunWorkspace::drop in the isolated child.
    // The operating system releases its actual leases; the parent forgets no
    // live workspace, handle, or lease and makes no PID/age recovery decision.
    std::process::exit(0)
}

fn spawn_interrupted_fixture(root: &Path) {
    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            INTERRUPTED_FIXTURE_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(INTERRUPTED_FIXTURE_ENV, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn isolated interrupted workspace fixture");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("observe fixture child") {
            assert!(
                status.success(),
                "interrupted fixture child failed: {status}"
            );
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated interrupted fixture exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn interrupted_fixture_paths(fixture: &Fixture) -> (String, PathBuf, PathBuf, PathBuf) {
    let (handoff, _) = fixture_json(
        &fixture.0.join("interrupted-fixture.json"),
        FIXTURE_RECORD_LIMIT,
    );
    let nonce = handoff["nonce"]
        .as_str()
        .expect("typed fixture nonce")
        .to_owned();
    assert_eq!(nonce.len(), 24);
    assert!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let journal = PathBuf::from(handoff["journal_path"].as_str().unwrap());
    let run_root = PathBuf::from(handoff["run_root"].as_str().unwrap());
    let target = PathBuf::from(handoff["compiler_path"].as_str().unwrap());
    let (original, _) = fixture_json(&journal, FIXTURE_RECORD_LIMIT);
    let root_identity = original["root_identity"].as_str().unwrap();
    assert_eq!(root_identity.len(), 64);
    let storage = fixture.0.join("storage").canonicalize().unwrap();
    assert_eq!(
        journal,
        storage
            .join("rust/x")
            .join(&root_identity[..16])
            .join(format!("{nonce}.json"))
    );
    assert_eq!(
        run_root,
        storage
            .join("rust/r")
            .join(&root_identity[..16])
            .join(&nonce)
    );
    assert_eq!(target, storage.join("rust/c").join(&root_identity[..16]));
    assert_eq!(original["run_nonce"], nonce);
    assert_eq!(original["lease_state"], "ACTIVE");
    assert_eq!(original["lifecycle"], "PUBLISHED");
    assert_eq!(original["child_processes"], json!([]));
    assert_eq!(original["owned"], json!([]));
    assert_eq!(original["preexisting_files"], json!([]));
    (nonce, journal, run_root, target)
}

struct InterruptedRun {
    fixture: Fixture,
    nonce: String,
    journal: PathBuf,
    run_root: PathBuf,
    target: PathBuf,
    common_root: PathBuf,
    repository_identity: DirectoryIdentity,
    run_identity: DirectoryIdentity,
    staging_identity: DirectoryIdentity,
    target_identity: DirectoryIdentity,
}

impl InterruptedRun {
    fn new() -> Self {
        let fixture = Fixture::new();
        spawn_interrupted_fixture(&fixture.0);
        let (nonce, journal, run_root, target) = interrupted_fixture_paths(&fixture);
        let (original, _) = fixture_json(&journal, FIXTURE_RECORD_LIMIT);
        let root_identity = original["root_identity"].as_str().unwrap();
        let repository_identity =
            DirectoryIdentity::capture(&fixture.0.join("repository")).unwrap();
        let common_root = common_fixture_root(repository_identity.key());
        let run_identity = DirectoryIdentity::capture(&run_root).unwrap();
        let staging_identity = DirectoryIdentity::capture(&run_root.join("s")).unwrap();
        let target_identity = DirectoryIdentity::capture(&target).unwrap();
        let (owner, _) = fixture_json(&run_root.join("owner.json"), REGISTRY_RECORD_LIMIT);
        assert_eq!(owner["run_nonce"], nonce);
        assert_eq!(owner["root_identity"], root_identity);
        let (target_owner, _) = fixture_json(&target.join("_owner.json"), REGISTRY_RECORD_LIMIT);
        assert_eq!(target_owner["root_identity"], root_identity);
        assert_eq!(target_owner["namespace"], "rust");
        // Marker loss is simulated only in the child's freshly owned fixture.
        fs::remove_file(run_root.join("owner.json")).expect("simulate fixture owner marker loss");
        fs::remove_file(target.join("_owner.json")).expect("simulate fixture compiler marker loss");
        let result = Self {
            fixture,
            nonce,
            journal,
            run_root,
            target,
            common_root,
            repository_identity,
            run_identity,
            staging_identity,
            target_identity,
        };
        result.registry();
        result.assert_empty_residue();
        result
    }

    fn record(&self) -> PathBuf {
        self.journal.with_extension("retained")
    }

    fn pending(&self) -> PathBuf {
        self.journal.with_extension("retirement-pending")
    }

    fn bytes(&self) -> Vec<u8> {
        fixture_bytes(&self.journal, FIXTURE_RECORD_LIMIT)
    }

    fn retire(&self, digest: &str) -> std::io::Result<EmptyRunRetirement> {
        self.fixture
            .storage()
            .retain_empty_interrupted_run(&self.nonce, digest)
    }

    fn registry(&self) -> (Value, Vec<u8>) {
        assert!(
            self.repository_identity
                .matches(&self.fixture.0.join("repository"))
                .unwrap()
        );
        let (registry, bytes) =
            fixture_json(&self.common_root.join("owners.json"), REGISTRY_RECORD_LIMIT);
        assert_eq!(registry["version"].as_u64(), Some(1));
        assert_eq!(registry["native_identity"], self.repository_identity.key());
        let entries = registry["registrations"]
            .as_object()
            .expect("typed fixture registrations");
        if let Some(entry) = entries.get("rust") {
            let (journal, _) = fixture_json(&self.journal, FIXTURE_RECORD_LIMIT);
            assert_eq!(entry["root_identity"], journal["root_identity"]);
            assert_eq!(entry["run_nonce"], self.nonce);
            assert_eq!(entry["journal_path"].as_str(), self.journal.to_str());
            assert_eq!(entry["compiler_path"].as_str(), self.target.to_str());
            assert!(entry["completed"].is_boolean());
        }
        (registry, bytes)
    }

    fn assert_identities(&self) {
        assert!(
            self.repository_identity
                .matches(&self.fixture.0.join("repository"))
                .unwrap()
        );
        assert!(self.run_identity.matches(&self.run_root).unwrap());
        assert!(
            self.staging_identity
                .matches(&self.run_root.join("s"))
                .unwrap()
        );
        assert!(self.target_identity.matches(&self.target).unwrap());
        assert!(!self.run_root.join("owner.json").exists());
        assert!(!self.target.join("_owner.json").exists());
    }

    fn assert_empty_residue(&self) {
        self.assert_identities();
        let names: Vec<_> = fs::read_dir(&self.run_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("s")]);
        assert!(
            fs::read_dir(self.run_root.join("s"))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(fs::read_dir(&self.target).unwrap().next().is_none());
    }

    fn assert_refusal(&self, expected_digest: &str) {
        let original = self.bytes();
        let registry = fixture_bytes(&self.common_root.join("owners.json"), REGISTRY_RECORD_LIMIT);
        let record = self
            .record()
            .exists()
            .then(|| fixture_bytes(&self.record(), 2 * 1024 * 1024));
        let pending = self
            .pending()
            .exists()
            .then(|| fixture_bytes(&self.pending(), FIXTURE_RECORD_LIMIT));
        assert!(
            self.retire(expected_digest).is_err(),
            "unsafe fixture was admitted"
        );
        assert_eq!(self.bytes(), original, "refusal changed journal bytes");
        assert_eq!(
            fixture_bytes(&self.common_root.join("owners.json"), REGISTRY_RECORD_LIMIT),
            registry
        );
        assert_eq!(
            self.record()
                .exists()
                .then(|| fixture_bytes(&self.record(), 2 * 1024 * 1024)),
            record
        );
        assert_eq!(
            self.pending()
                .exists()
                .then(|| fixture_bytes(&self.pending(), FIXTURE_RECORD_LIMIT)),
            pending
        );
        self.assert_identities();
    }

    fn assert_success(&self, original: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let before: Value = parse_strict_json_bytes(original).unwrap();
        let (after, after_bytes) = fixture_json(&self.journal, 64 * 1024);
        let mut expected = before;
        expected["lifecycle"] = json!("FAILED");
        expected["lease_state"] = json!("RELEASED");
        expected["cleaned_bytes"] = json!(0);
        expected["retained_bytes"] = json!(0);
        expected["disk_free_after"] = after["disk_free_after"].clone();
        assert!(after["disk_free_after"].as_u64().is_some());
        assert_eq!(after, expected, "retirement changed source journal fields");
        let (record, record_bytes) = fixture_json(&self.record(), 1024 * 1024);
        let expected_keys = [
            "compiler_path",
            "disposition",
            "journal_path",
            "native_repository_identity",
            "original_journal",
            "retired_journal",
            "run_root_identity",
            "staging_identity",
            "target_identity",
            "version",
        ];
        let mut actual_keys = record
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        actual_keys.sort_unstable();
        assert_eq!(actual_keys, expected_keys);
        assert_eq!(record["version"].as_u64(), Some(1));
        assert_eq!(record["journal_path"].as_str(), self.journal.to_str());
        assert_eq!(record["compiler_path"].as_str(), self.target.to_str());
        assert_eq!(record["disposition"], "EMPTY_RESIDUE_RETAINED");
        assert_eq!(
            record["original_journal"].as_str(),
            Some(std::str::from_utf8(original).unwrap())
        );
        assert_eq!(
            record["retired_journal"].as_str(),
            Some(std::str::from_utf8(&after_bytes).unwrap())
        );
        assert_eq!(
            record["native_repository_identity"],
            self.repository_identity.key()
        );
        assert_eq!(record["run_root_identity"], self.run_identity.key());
        assert_eq!(record["staging_identity"], self.staging_identity.key());
        assert_eq!(record["target_identity"], self.target_identity.key());
        assert!(!self.pending().exists());
        self.assert_empty_residue();
        (after_bytes, record_bytes)
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_interrupted_runtime_preserves_residue_and_publication() {
    if let Some(root) = std::env::var_os(INTERRUPTED_FIXTURE_ENV) {
        interrupted_fixture_child(Path::new(&root));
    }
    for phase in ["PUBLISHED", "VALIDATING"] {
        let interrupted = InterruptedRun::new();
        if phase == "VALIDATING" {
            let (mut journal, _) = fixture_json(&interrupted.journal, 64 * 1024);
            journal["lifecycle"] = json!(phase);
            journal["publication_intent"] = Value::Null;
            fixture_write(
                &interrupted.journal,
                &serde_json::to_vec_pretty(&journal).unwrap(),
            );
        }
        let original = interrupted.bytes();
        let (_, registry) = interrupted.registry();
        let report = interrupted
            .retire(&fixture_digest(&original))
            .expect("retain empty interrupted run");
        assert_eq!(report.journal_path, interrupted.journal);
        assert_eq!(report.record_path, interrupted.record());
        assert_eq!(report.disposition, "EMPTY_RESIDUE_RETAINED");
        assert_eq!(report.cleaned_bytes, 0);
        assert_eq!(report.retained_bytes, 0);
        interrupted.assert_success(&original);
        assert_eq!(
            interrupted.registry().1,
            registry,
            "retirement changed common registrations"
        );
        let next = interrupted
            .fixture
            .storage()
            .acquire_workspace()
            .expect("normal admission sees terminal journal");
        drop(next);
        assert!(
            interrupted
                .run_identity
                .matches(&interrupted.run_root)
                .unwrap()
        );
        assert!(
            interrupted
                .staging_identity
                .matches(&interrupted.run_root.join("s"))
                .unwrap()
        );
        assert!(
            interrupted
                .target_identity
                .matches(&interrupted.target)
                .unwrap()
        );
        assert!(!interrupted.run_root.join("owner.json").exists());
        assert!(
            interrupted.run_root.exists(),
            "retained residue was reclaimed"
        );
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_is_immutable_and_idempotent() {
    let interrupted = InterruptedRun::new();
    let original = interrupted.bytes();
    let pin = fixture_digest(&original);
    interrupted.retire(&pin).unwrap();
    let (journal, record) = interrupted.assert_success(&original);
    let (_, registry) = interrupted.registry();
    let retry = interrupted
        .retire(&pin)
        .expect("idempotent original-preimage retry");
    assert_eq!(retry.record_path, interrupted.record());
    assert_eq!(retry.cleaned_bytes, 0);
    assert_eq!(retry.retained_bytes, 0);
    assert_eq!(interrupted.bytes(), journal);
    assert_eq!(fixture_bytes(&interrupted.record(), 1024 * 1024), record);
    assert_eq!(interrupted.registry().1, registry);
    interrupted.assert_empty_residue();
    // The postimage is not authority to reinterpret a new expected preimage.
    interrupted.assert_refusal(&fixture_digest(&journal));
    let payload = interrupted.run_root.join("s/after-retirement");
    fixture_write(&payload, b"new retained bytes");
    interrupted.assert_refusal(&pin);
    assert_eq!(fixture_bytes(&payload, 64), b"new retained bytes");

    let changed_incarnation = InterruptedRun::new();
    let original = changed_incarnation.bytes();
    let pin = fixture_digest(&original);
    changed_incarnation.retire(&pin).unwrap();
    let (journal, record) = changed_incarnation.assert_success(&original);
    fs::remove_dir(&changed_incarnation.target).expect("replace only fixture's empty target");
    fs::create_dir(&changed_incarnation.target).unwrap();
    assert!(
        !changed_incarnation
            .target_identity
            .matches(&changed_incarnation.target)
            .unwrap()
    );
    assert!(
        changed_incarnation.retire(&pin).is_err(),
        "receipt admitted a new directory incarnation"
    );
    assert_eq!(changed_incarnation.bytes(), journal);
    assert_eq!(
        fixture_bytes(&changed_incarnation.record(), 1024 * 1024),
        record
    );
    assert!(
        fs::read_dir(&changed_incarnation.target)
            .unwrap()
            .next()
            .is_none()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_refuses_payloads_and_unknown_entries() {
    let interrupted = InterruptedRun::new();
    let pin = fixture_digest(&interrupted.bytes());
    for (path, bytes) in [
        (
            interrupted.run_root.join("s/payload"),
            b"staged bytes".as_slice(),
        ),
        (
            interrupted.run_root.join("s/zero-byte-file"),
            b"".as_slice(),
        ),
        (
            interrupted.target.join("payload"),
            b"target bytes".as_slice(),
        ),
        (interrupted.target.join("zero-byte-file"), b"".as_slice()),
        (interrupted.run_root.join("unexpected-file"), b"".as_slice()),
    ] {
        fixture_write(&path, bytes);
        interrupted.assert_refusal(&pin);
        assert_eq!(fixture_bytes(&path, 64), bytes);
        fs::remove_file(path).unwrap();
    }
    for path in [
        interrupted.run_root.join("s/nested"),
        interrupted.run_root.join("unknown"),
    ] {
        fs::create_dir(&path).unwrap();
        interrupted.assert_refusal(&pin);
        assert!(path.is_dir());
        fs::remove_dir(path).unwrap();
    }
    interrupted.assert_empty_residue();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_refuses_running_children_and_owned_paths() {
    let interrupted = InterruptedRun::new();
    let (original, bytes) = fixture_json(&interrupted.journal, 64 * 1024);
    let cases = [
        ("lifecycle", json!("RUNNING")),
        ("lease_state", json!("RELEASED")),
        ("child_processes", json!([std::process::id()])),
        (
            "owned",
            json!([{"path": interrupted.run_root.join("s/owned"), "digest": "sha256:fixture"}]),
        ),
        (
            "preexisting_files",
            json!([{"path": interrupted.target.join("prior"), "digest": "sha256:fixture"}]),
        ),
        ("cleaned_bytes", json!(0)),
        ("retained_bytes", json!(0)),
    ];
    for (field, value) in cases {
        let mut changed = original.clone();
        changed[field] = value;
        fixture_write(
            &interrupted.journal,
            &serde_json::to_vec_pretty(&changed).unwrap(),
        );
        interrupted.assert_refusal(&fixture_digest(&interrupted.bytes()));
        fixture_write(&interrupted.journal, &bytes);
    }
    assert_eq!(interrupted.bytes(), bytes);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_requires_exact_journal_and_registration_bindings() {
    let interrupted = InterruptedRun::new();
    let bytes = interrupted.bytes();
    for pin in [
        "not-a-digest".to_owned(),
        format!("sha256:{}", "0".repeat(64)),
    ] {
        interrupted.assert_refusal(&pin);
    }
    let runtime = interrupted.fixture.storage();
    for nonce in ["../outside", "000000000000000000000000"] {
        assert!(
            runtime
                .retain_empty_interrupted_run(nonce, &fixture_digest(&bytes))
                .is_err()
        );
        assert_eq!(interrupted.bytes(), bytes);
        assert!(!interrupted.record().exists());
    }
    let original: Value = parse_strict_json_bytes(&bytes).unwrap();
    for (field, value) in [
        ("run_nonce", json!("000000000000000000000000")),
        ("root_identity", json!("0".repeat(64))),
        ("run_root", json!(interrupted.fixture.0.join("wrong-run"))),
        ("publication_intent", Value::Null),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        fixture_write(
            &interrupted.journal,
            &serde_json::to_vec_pretty(&changed).unwrap(),
        );
        interrupted.assert_refusal(&fixture_digest(&interrupted.bytes()));
        fixture_write(&interrupted.journal, &bytes);
    }
    let mut duplicate = std::str::from_utf8(&bytes)
        .unwrap()
        .trim_end()
        .trim_end_matches('}')
        .to_owned();
    duplicate.push_str(",\"lifecycle\":\"PUBLISHED\"}");
    fixture_write(&interrupted.journal, duplicate.as_bytes());
    interrupted.assert_refusal(&fixture_digest(duplicate.as_bytes()));
    fixture_write(&interrupted.journal, &bytes);
    let finite_field = format!(
        "\"disk_free_before\": {}",
        original["disk_free_before"].as_u64().unwrap()
    );
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.matches(&finite_field).count(), 1);
    let overflow = text.replace(&finite_field, "\"disk_free_before\": 1e999");
    fixture_write(&interrupted.journal, overflow.as_bytes());
    interrupted.assert_refusal(&fixture_digest(overflow.as_bytes()));
    fixture_write(&interrupted.journal, &bytes);
    let (registry, registry_bytes) = interrupted.registry();
    for (field, value) in [
        ("root_identity", json!("0".repeat(64))),
        ("run_nonce", json!("000000000000000000000000")),
        (
            "journal_path",
            json!(
                interrupted
                    .journal
                    .with_file_name("000000000000000000000000.json")
            ),
        ),
        (
            "compiler_path",
            json!(interrupted.fixture.0.join("wrong-target")),
        ),
    ] {
        let mut changed = registry.clone();
        changed["registrations"]["rust"][field] = value;
        fixture_write(
            &interrupted.common_root.join("owners.json"),
            &serde_json::to_vec_pretty(&changed).unwrap(),
        );
        interrupted.assert_refusal(&fixture_digest(&bytes));
        fixture_write(
            &interrupted.common_root.join("owners.json"),
            &registry_bytes,
        );
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_requires_both_idle_lease_domains() {
    let interrupted = InterruptedRun::new();
    let pin = fixture_digest(&interrupted.bytes());
    for path in [
        interrupted.journal.parent().unwrap().join("heavy.lock"),
        interrupted.common_root.join("heavy.lock"),
    ] {
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lease.try_lock().expect("hold fixture's existing lease");
        interrupted.assert_refusal(&pin);
        drop(lease);
    }
    interrupted
        .retire(&pin)
        .expect("idle existing leases admit retirement");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_preserves_conflicts_and_durable_partial_record() {
    let collision = InterruptedRun::new();
    let pin = fixture_digest(&collision.bytes());
    fixture_write(&collision.record(), b"conflicting original record");
    collision.assert_refusal(&pin);
    assert_eq!(
        fixture_bytes(&collision.record(), 64),
        b"conflicting original record"
    );

    let partial = InterruptedRun::new();
    let original = partial.bytes();
    let pin = fixture_digest(&original);
    fixture_write(&partial.pending(), b"conflicting pending postimage");
    assert!(partial.retire(&pin).is_err());
    assert_eq!(partial.bytes(), original);
    assert_eq!(
        fixture_bytes(&partial.pending(), 64),
        b"conflicting pending postimage"
    );
    let (record, record_bytes) = fixture_json(&partial.record(), 1024 * 1024);
    assert_eq!(
        record["original_journal"].as_str(),
        Some(std::str::from_utf8(&original).unwrap())
    );
    partial.assert_empty_residue();
    fs::remove_file(partial.pending()).unwrap();
    partial
        .retire(&pin)
        .expect("retry uses the durable exact original record");
    partial.assert_success(&original);
    assert_eq!(fixture_bytes(&partial.record(), 1024 * 1024), record_bytes);
    let mut conflict = record;
    conflict["original_journal"] = json!("different authority");
    fixture_write(
        &partial.record(),
        &serde_json::to_vec_pretty(&conflict).unwrap(),
    );
    partial.assert_refusal(&pin);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_rejects_oversized_preimages() {
    let interrupted = InterruptedRun::new();
    let (mut journal, original) = fixture_json(&interrupted.journal, 64 * 1024);
    journal["owner_identity"] = json!("x".repeat(64 * 1024));
    let oversized = serde_json::to_vec_pretty(&journal).unwrap();
    assert!(oversized.len() > 64 * 1024 && oversized.len() < FIXTURE_RECORD_LIMIT);
    fixture_write(&interrupted.journal, &oversized);
    interrupted.assert_refusal(&fixture_digest(&oversized));
    fixture_write(&interrupted.journal, &original);
    let record = vec![b'x'; 1024 * 1024 + 1];
    fixture_write(&interrupted.record(), &record);
    interrupted.assert_refusal(&fixture_digest(&original));
    assert_eq!(
        fixture_bytes(&interrupted.record(), 2 * 1024 * 1024),
        record
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-013`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_does_not_recreate_an_absent_registration() {
    let interrupted = InterruptedRun::new();
    let (mut registry, _) = interrupted.registry();
    let other_entries = registry["registrations"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| name.as_str() != "rust")
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<serde_json::Map<String, Value>>();
    assert!(
        registry["registrations"]
            .as_object_mut()
            .unwrap()
            .remove("rust")
            .is_some()
    );
    assert_eq!(registry["registrations"], Value::Object(other_entries));
    assert_eq!(
        registry["native_identity"],
        interrupted.repository_identity.key()
    );
    assert!(
        interrupted
            .repository_identity
            .matches(&interrupted.fixture.0.join("repository"))
            .unwrap()
    );
    let mut bytes = serde_json::to_vec_pretty(&registry).unwrap();
    bytes.push(b'\n');
    assert!(bytes.len() <= REGISTRY_RECORD_LIMIT);
    fixture_write(&interrupted.common_root.join("owners.json"), &bytes);
    assert_eq!(interrupted.registry().1, bytes);
    let original = interrupted.bytes();
    interrupted
        .retire(&fixture_digest(&original))
        .expect("absence creates no new common owner authority");
    interrupted.assert_success(&original);
    assert_eq!(
        interrupted.registry().1,
        bytes,
        "absent registration was recreated or other entries changed"
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R17-014`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R17
#[test]
fn empty_runtime_retirement_does_not_create_missing_lease_files() {
    for common in [false, true] {
        let interrupted = InterruptedRun::new();
        let lock = if common {
            interrupted.common_root.join("heavy.lock")
        } else {
            interrupted.journal.parent().unwrap().join("heavy.lock")
        };
        plain_fixture_file(&lock);
        fs::remove_file(&lock).expect("remove only fresh fixture's known idle lock");
        interrupted.assert_refusal(&fixture_digest(&interrupted.bytes()));
        assert!(!lock.exists(), "retirement created a missing lease file");
        interrupted.assert_empty_residue();
    }
}
