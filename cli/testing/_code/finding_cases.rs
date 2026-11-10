//! Process-level lifecycle inspection uses the same records as machine clients.
use super::{AuditFixture, ObservationFixture, fs, run};
use serde_json::{Value, json};

/// `T-TF-CLI-0001-R15-004`
/// Fortress requirement: TF-CLI-0001-R15
#[test]
fn lifecycle_proposals_are_read_only_and_current_baselines_do_not_expand() {
    let fixture = AuditFixture::new();
    fs::write(fixture.root.join("unexpected.txt"), "historical residue").unwrap();
    let root = fixture.argument();
    let path = fixture
        .root
        .join("__fortress/governance/finding_governance.json");
    let output = run(&["baseline", "create", &root, "--format", "json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proposal: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(proposal["authorization"], "REQUIRE_AUTHORITY_DECISION");
    assert_eq!(proposal["host_coverage"], "UNMEDIATED");
    assert_eq!(proposal["proposed_governance"]["schema_version"], 2);
    assert!(!path.exists());
    let reference = fortress_core::finding_governance::lifecycle_digest(&proposal).unwrap();
    let human = run(&["baseline", "create", &root]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains(&reference));
    assert!(!path.exists());
    // A fixture owner installs the reviewed bytes explicitly; the CLI never does so.
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        fortress_core::wire::canonicalize_public_json(&proposal["proposed_governance"].to_string())
            .unwrap(),
    )
    .unwrap();
    let original = fs::read(&path).unwrap();
    let baseline = run(&["check", &root, "--format=json"]);
    let result: Value = serde_json::from_slice(&baseline.stdout).unwrap();
    assert!(baseline.status.success(), "{result}");
    assert_eq!(result["outcome"], "FAIL");
    assert_eq!(
        result["finding_governance"]["summary"]["baselined_non_blocking"],
        1
    );
    verify_portable_authority(&root);
    let failed_expansion = run(&["baseline", "create", &root, "--format", "json"]);
    assert!(!failed_expansion.status.success());
    fs::write(fixture.root.join("new.txt"), "new violation").unwrap();
    let current = run(&["check", &root, "--format=json"]);
    assert!(!current.status.success());
    let result: Value = serde_json::from_slice(&current.stdout).unwrap();
    assert_eq!(result["finding_governance"]["summary"]["new_blocking"], 1);
    assert_eq!(
        result["finding_governance"]["summary"]["baselined_non_blocking"],
        1
    );
    fs::remove_file(fixture.root.join("unexpected.txt")).unwrap();
    let missing = run(&["audit", &root, "--format=json"]);
    let result: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(
        result["finding_governance"]["summary"]["resolved_baseline_entries"],
        0
    );
    assert_eq!(
        result["finding_governance"]["unresolved_baseline_entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}

fn verify_portable_authority(root: &str) {
    let storage = ObservationFixture::new();
    let state = storage.root.join("state.json");
    let output = run(&["state-view", root, "--format", "json"]);
    assert!(output.status.success());
    let view: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(view["application"]["assessment"]["decision"], "SATISFIED");
    fs::write(&state, output.stdout).unwrap();
    let destination = storage.root.join("bundle");
    let predicate = "https://example.invalid/fortress/assurance/v1";
    let exported = run(&[
        "bundle",
        "export",
        root,
        "--state",
        state.to_str().unwrap(),
        "--output",
        destination.to_str().unwrap(),
        "--predicate-type",
        predicate,
    ]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let verified = run(&[
        "bundle",
        "verify",
        destination.to_str().unwrap(),
        "--predicate-type",
        predicate,
    ]);
    let result: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert!(verified.status.success(), "{result}");
    assert_eq!(result["integrity"], "VERIFIED");
    assert_eq!(result["authenticity"], "UNVERIFIED");
    assert!(
        result["unproven"]
            .as_array()
            .unwrap()
            .contains(&json!("EXTERNAL_AUTHORIZATION"))
    );
}

/// `T-TF-CLI-0001-R15-005`
/// Fortress requirement: TF-CLI-0001-R15
#[test]
fn lifecycle_malformed_inputs_and_local_approval_flags_cannot_mutate_authority() {
    let fixture = ObservationFixture::new();
    let root = fixture.argument();
    for arguments in [
        vec!["baseline", "create", &root, "--apply", "--format", "json"],
        vec![
            "baseline", "review", &root, "--from", "missing", "--to", "current", "--format", "json",
        ],
        vec![
            "exceptions",
            "review",
            &root,
            "--to",
            "current",
            "--assessment-time",
            "9007199254740992",
            "--format",
            "json",
        ],
        vec![
            "exceptions",
            "review",
            &root,
            "--to",
            "current",
            "--assessment-time",
            "-1",
            "--format",
            "json",
        ],
        vec![
            "baseline", "capture", &root, "--format", "json", "--format", "human",
        ],
        vec![
            "baseline",
            "prune",
            &root,
            "--finding",
            "x",
            "--finding",
            "x",
            "--format",
            "json",
        ],
    ] {
        let output = run(&arguments);
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["mutated"], false);
        assert_eq!(error["authorization"], "NOT_GRANTED");
    }
    assert!(!fixture.root.join("__fortress").exists());
    let output = run(&["exceptions", "list", &root, "--format", "json"]);
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["exceptions"], json!([]));
    assert!(!fixture.root.join("__fortress").exists());
}
