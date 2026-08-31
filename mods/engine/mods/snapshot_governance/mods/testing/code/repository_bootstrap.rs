//! Conformance evidence for read-only discovery and explicit repository adoption.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::audit::audit_repository;
use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, BootstrapProposal, ProposedAuthorityState,
    apply_repository_bootstrap, discover_repository_bootstrap,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let identity = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-repository-bootstrap-{}-{identity}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src/runtime")).expect("source directories create");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"ordinary\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest writes");
        fs::write(
            root.join("src/lib.rs"),
            "pub mod runtime;\npub fn run() -> bool { runtime::ready() }\n#[test]\nfn plain_test() { assert!(run()); }\n",
        )
        .expect("library writes");
        fs::write(
            root.join("src/runtime/mod.rs"),
            "pub fn ready() -> bool { true }\n",
        )
        .expect("nested source writes");
        Self { root }
    }

    fn explicit_options() -> BootstrapDiscoveryOptions {
        BootstrapDiscoveryOptions::new(Some("PF-ORDINARY".into()), Some("Ordinary Project".into()))
    }

    fn inventory(&self) -> BTreeMap<String, Vec<u8>> {
        inventory(&self.root, &self.root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("bootstrap fixture removes");
    }
}

fn inventory(root: &Path, current: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(current).expect("directory reads") {
        let entry = entry.expect("entry reads");
        let path = entry.path();
        if path.is_dir() {
            result.extend(inventory(root, &path));
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("path belongs")
                .to_string_lossy()
                .replace('\\', "/");
            result.insert(relative, fs::read(path).expect("file reads"));
        }
    }
    result
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R16-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R16
#[test]
fn discovery_is_read_only_deterministic_and_separates_owner_choices() {
    let fixture = Fixture::new();
    let before = fixture.inventory();
    let unresolved =
        discover_repository_bootstrap(&fixture.root, &BootstrapDiscoveryOptions::default())
            .expect("read-only discovery completes");
    assert_eq!(
        unresolved.authority_state(),
        ProposedAuthorityState::Unresolved
    );
    assert_eq!(unresolved.unresolved_choices().len(), 2);
    assert_eq!(unresolved.observed_facts().cargo_territories().len(), 1);
    assert_eq!(fixture.inventory(), before);

    let first = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("explicit proposal compiles");
    let second = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("proposal repeats");
    assert_eq!(first, second);
    let bytes = first.to_canonical_json().expect("proposal serializes");
    assert_eq!(BootstrapProposal::from_json_str(&bytes).unwrap(), first);
    assert_eq!(fixture.inventory(), before);
    assert!(!bytes.contains(&fixture.root.to_string_lossy().to_string()));
    assert!(bytes.contains("SRC-ANALYSIS-CARGO-"));
    assert!(bytes.contains("rust_tests_without_stable_identity"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R16-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R16
#[test]
fn stale_or_conflicting_proposal_never_partially_initializes() {
    let fixture = Fixture::new();
    let proposal = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("proposal compiles");
    fs::write(fixture.root.join("src/new.rs"), "pub fn changed() {}\n")
        .expect("authoritative source changes");
    let error = apply_repository_bootstrap(&fixture.root, &proposal, false)
        .expect_err("stale proposal fails");
    assert!(error.to_string().contains("proposal is stale"));
    assert!(!fixture.root.join("contract.json").exists());
    assert!(!fixture.root.join("data/project.json").exists());
    assert!(!fixture.root.join("data/finding_governance.json").exists());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R16-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R16
#[test]
fn apply_materializes_only_reviewed_minimal_authority() {
    let fixture = Fixture::new();
    let cargo_before = fs::read(fixture.root.join("Cargo.toml")).unwrap();
    let source_before = fs::read(fixture.root.join("src/lib.rs")).unwrap();
    let proposal = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("proposal compiles");
    let result = apply_repository_bootstrap(&fixture.root, &proposal, false)
        .expect("explicit adoption succeeds");
    let result_json = result.to_canonical_json().expect("apply result serializes");
    assert!(result_json.contains("data/project.json"));
    assert_eq!(
        fs::read(fixture.root.join("Cargo.toml")).unwrap(),
        cargo_before
    );
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).unwrap(),
        source_before
    );
    assert!(fixture.root.join("contract.json").is_file());
    assert!(fixture.root.join("data/project.json").is_file());
    assert!(fixture.root.join("data/finding_governance.json").is_file());
    assert!(
        !fixture
            .root
            .join("mods/engine/mods/standard_registry")
            .exists()
    );
    assert!(apply_repository_bootstrap(&fixture.root, &proposal, false).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R16-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R16
#[test]
fn explicit_baseline_bootstrap_preserves_raw_failure_and_green_check_semantics() {
    let fixture = Fixture::new();
    let proposal = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("proposal compiles");
    let result = apply_repository_bootstrap(&fixture.root, &proposal, true)
        .expect("explicit baseline bootstrap succeeds");
    let result_json: serde_json::Value =
        serde_json::from_str(&result.to_canonical_json().unwrap()).unwrap();
    assert_eq!(result_json["baseline_created"], true);
    assert_eq!(result_json["strict_conformance"], "FAIL");
    assert_eq!(result_json["progressive_enforcement"], "PASS");

    let audit = audit_repository(&fixture.root).expect("adopted repository audits");
    assert!(!audit.is_success());
    assert!(audit.enforcement_success());
    assert!(audit.finding_governance().summary().baselined_non_blocking > 0);
    fs::write(fixture.root.join("new-unrecognized.txt"), "new violation")
        .expect("new violation writes");
    let changed = audit_repository(&fixture.root).expect("changed repository audits");
    assert!(!changed.enforcement_success());
    assert!(changed.finding_governance().summary().new_blocking > 0);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R16-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R16
#[test]
fn proposal_digest_rejects_reviewed_content_tampering() {
    let fixture = Fixture::new();
    let proposal = discover_repository_bootstrap(&fixture.root, &Fixture::explicit_options())
        .expect("proposal compiles");
    let source = proposal
        .to_canonical_json()
        .unwrap()
        .replace("Ordinary Project", "Altered Project");
    assert!(BootstrapProposal::from_json_str(&source).is_err());
    assert!(!fixture.root.join("contract.json").exists());
}
