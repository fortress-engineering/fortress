//! Physical-directory admission controls shared by runtime adapters.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fortress_core::heavy_admission::{DirectoryIdentity, HeavyAdmissionGuard};
use fortress_core::runtime_storage::{RuntimeStorage, StoragePolicy};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("fortress-admission-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture");
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn physical_directory_admission_excludes_a_second_adapter() {
    let fixture = Fixture::new();
    let first_identity = DirectoryIdentity::capture(&fixture.0).expect("identity");
    let alias_identity = DirectoryIdentity::capture(&fixture.0.join(".")).expect("alias");
    assert_eq!(first_identity.key(), alias_identity.key());
    let first = HeavyAdmissionGuard::acquire(first_identity).expect("first admission");
    assert!(HeavyAdmissionGuard::acquire(alias_identity).is_err());
    drop(first);
    let identity = DirectoryIdentity::capture(&fixture.0).expect("identity");
    assert!(HeavyAdmissionGuard::acquire(identity).is_ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn admission_identity_requires_an_open_directory() {
    let fixture = Fixture::new();
    let file = fixture.0.join("ordinary-file");
    fs::write(&file, b"source").expect("file");
    assert!(DirectoryIdentity::capture(&file).is_err());
    assert!(DirectoryIdentity::capture(&fixture.0.join("absent")).is_err());
    let identity = DirectoryIdentity::capture(&fixture.0).expect("directory");
    assert!(identity.matches(&fixture.0).expect("same directory"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[cfg(windows)]
#[test]
fn windows_case_and_extended_paths_use_the_same_admission() {
    let fixture = Fixture::new();
    let canonical = fixture.0.canonicalize().expect("canonical path");
    let case_alias = PathBuf::from(fixture.0.to_string_lossy().to_uppercase());
    let first = DirectoryIdentity::capture(&fixture.0).expect("identity");
    let extended = DirectoryIdentity::capture(&canonical).expect("extended identity");
    let alternate = DirectoryIdentity::capture(&case_alias).expect("case identity");
    assert_eq!(first.key(), extended.key());
    assert_eq!(first.key(), alternate.key());
    let admission = HeavyAdmissionGuard::acquire(first).expect("admission");
    assert!(HeavyAdmissionGuard::acquire(extended).is_err());
    assert!(HeavyAdmissionGuard::acquire(alternate).is_err());
    drop(admission);
}

fn python(fixture: &Fixture, code: &str) -> std::process::Output {
    let code_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../snapshot_governance/_code");
    Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg("-B")
        .arg("-c")
        .arg(code)
        .arg(&code_root)
        .arg(&fixture.0)
        .output()
        .expect("Python storage conformance adapter")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn runtime_and_issuer_adapters_share_native_exclusion() {
    let fixture = Fixture::new();
    let guard =
        HeavyAdmissionGuard::acquire(DirectoryIdentity::capture(&fixture.0).expect("identity"))
            .expect("runtime admission");
    let output = python(
        &fixture,
        r"import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from heavy_admission import DirectoryIdentity, HeavyAdmissionGuard
root = Path(sys.argv[2])
print(DirectoryIdentity(root).key)
try:
    HeavyAdmissionGuard(root)
except OSError:
    sys.exit(0)
sys.exit(1)",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("identity text")
            .trim(),
        guard.directory().key()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn unfinished_foreign_owner_is_retained_after_process_exit() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("storage")).expect("storage");
    fs::create_dir(fixture.0.join("repository")).expect("repository");
    let output = python(
        &fixture,
        r"import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from execution_storage import RunWorkspace, StoragePolicy
root = Path(sys.argv[2])
with RunWorkspace(root / 'repository', root / 'storage', StoragePolicy(reserve_bytes=0)) as run:
    run.record_child(os.getpid())",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: 0,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime");
    assert!(runtime.acquire_workspace().is_err());
    assert!(runtime.recover_owned_orphans().is_err());
    assert!(fixture.0.join("storage/python/r").exists());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn compiler_budget_includes_retained_foreign_adapter_target() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("repository")).expect("repository");
    fs::create_dir(fixture.0.join("storage")).expect("storage");
    let output = python(
        &fixture,
        r"import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from execution_storage import RunWorkspace, StoragePolicy
root = Path(sys.argv[2])
with RunWorkspace(root / 'repository', root / 'storage', StoragePolicy(reserve_bytes=0)) as run:
    (run.target / 'retained-object').write_bytes(b'x' * 4096)",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime = RuntimeStorage::new(
        &fixture.0.join("repository"),
        &fixture.0.join("storage"),
        StoragePolicy {
            reserve_bytes: 0,
            compiler_budget_bytes: 1024,
            ..StoragePolicy::default()
        },
    )
    .expect("runtime");
    assert!(runtime.acquire_workspace().is_err());
    assert!(!fixture.0.join("storage/rust/r").exists());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn temporary_environment_changes_cannot_split_cross_adapter_admission() {
    let fixture = Fixture::new();
    let guard = HeavyAdmissionGuard::acquire(DirectoryIdentity::capture(&fixture.0).unwrap())
        .expect("runtime admission");
    let code_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../snapshot_governance/_code");
    let alternate = fixture.0.join("alternate_temporary_storage");
    fs::create_dir(&alternate).unwrap();
    let output = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg("-B")
        .arg("-c")
        .arg(
            r"import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from heavy_admission import DirectoryIdentity, HeavyAdmissionGuard
root = Path(sys.argv[2])
assert Path(tempfile.gettempdir()).resolve() == Path(sys.argv[3]).resolve()
print(DirectoryIdentity(root).key)
try:
    HeavyAdmissionGuard(root)
except OSError:
    sys.exit(0)
sys.exit(1)",
        )
        .arg(&code_root)
        .arg(&fixture.0)
        .arg(&alternate)
        .env("TEMP", &alternate)
        .env("TMP", &alternate)
        .env("TMPDIR", &alternate)
        .output()
        .expect("isolated environment adapter");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        guard.directory().key()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn retained_compiler_target_blocks_retargeting_until_owned_cleanup_proves_absence() {
    let fixture = Fixture::new();
    let root = fixture.0.join("repository");
    let first_storage = fixture.0.join("first_storage");
    let next_storage = fixture.0.join("next_storage");
    for path in [&root, &first_storage, &next_storage] {
        fs::create_dir(path).unwrap();
    }
    let retained_policy = StoragePolicy {
        reserve_bytes: 0,
        retain_shared_compiler: true,
        ..StoragePolicy::default()
    };
    let runtime = RuntimeStorage::new(&root, &first_storage, retained_policy.clone()).unwrap();
    let first = runtime.acquire_workspace().expect("first target");
    let target = first.compiler_target().to_path_buf();
    fs::write(target.join("retained_object"), b"owned compiler bytes").unwrap();
    first.release().unwrap();
    let before = fs::read(target.join("retained_object")).unwrap();
    let relocated = RuntimeStorage::new(&root, &next_storage, retained_policy).unwrap();
    assert!(
        relocated.acquire_workspace().is_err(),
        "retained native target remains accounted before relocation"
    );
    assert_eq!(fs::read(target.join("retained_object")).unwrap(), before);
    assert!(
        !next_storage.join("rust/r").exists(),
        "reject before creating staging"
    );
    let cleanup = RuntimeStorage::new(
        &root,
        &first_storage,
        StoragePolicy {
            reserve_bytes: 0,
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        },
    )
    .unwrap();
    cleanup.acquire_workspace().unwrap().release().unwrap();
    assert_eq!(
        fs::symlink_metadata(&target).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    relocated
        .acquire_workspace()
        .expect("proven absent prior target permits relocation")
        .release()
        .unwrap();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R18-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R18
#[test]
fn fixed_native_registry_stays_external_to_watched_repository_inputs() {
    let fixture = Fixture::new();
    let source_before = fs::read_dir(&fixture.0).unwrap().count();
    let guard =
        HeavyAdmissionGuard::acquire(DirectoryIdentity::capture(&fixture.0).unwrap()).unwrap();
    let anchor = if cfg!(windows) {
        PathBuf::from(r"\\?\GLOBALROOT\SystemRoot\Temp")
    } else {
        PathBuf::from("/tmp")
    }
    .canonicalize()
    .unwrap();
    let expected = anchor
        .join("fortress-ops/admission-v1")
        .join(guard.directory().key());
    assert_eq!(guard.registry_root(), expected);
    assert!(!guard.registry_root().starts_with(&fixture.0));
    let metadata = fs::symlink_metadata(guard.registry_root()).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(metadata.file_attributes() & 0x400, 0);
    }
    let lock_path = guard.registry_root().join("heavy.lock");
    assert!(fs::symlink_metadata(&lock_path).unwrap().is_file());
    #[cfg(windows)]
    assert!(
        fs::remove_file(&lock_path).is_err(),
        "live native lease denies unlink/recreate"
    );
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), source_before);
    drop(guard);
    assert!(
        lock_path.is_file(),
        "adapter release preserves the persistent lease file"
    );
}
