//! Preview-only authority adapters preserve exact read-only result semantics.
use fortress_core::authority_load::AuthoritySnapshot;
use fortress_core::state_governance::{Axis, ComparisonState, StateAssets};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
fn d(n: u8) -> String {
    format!("sha256:{n:064x}")
}
fn snapshot(bytes: &[u8]) -> AuthoritySnapshot {
    let files = BTreeMap::from([("intent/new-name".into(), bytes.to_vec())]);
    let source = fortress_core::certification::certification_source_digest(&files);
    AuthoritySnapshot {
        schema: "urn:fortress:derived:v1:authority-snapshot".into(),
        schema_version: 1,
        state: ComparisonState {
            schema: "urn:fortress:derived:v1:comparison-state".into(),
            schema_version: 1,
            source_ref: Some(source.clone()),
            view: None,
            retained_application: None,
            origin_ref: None,
            limitations: vec![],
            assets: Some(StateAssets {
                subject_ref: source,
                complete_axes: BTreeSet::from([
                    Axis::Subject,
                    Axis::Intent,
                    Axis::Authority,
                    Axis::Governance,
                ]),
                inputs: vec![],
                entities: vec![],
                policies: vec![],
                standard_ref: Some(d(4)),
                profile_refs: BTreeSet::new(),
                evaluator_ref: Some(d(6)),
                exclusions_ref: None,
                exclusions: None,
                reference_facts: None,
            }),
        },
        files,
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        for n in 0..128 {
            let path = std::env::temp_dir()
                .join(format!("fortress-authority-cli-{}-{n}", std::process::id()));
            if std::fs::create_dir(&path).is_ok() {
                return Self(path);
            }
        }
        panic!("bounded fixture admission exhausted");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn run(args: &[&str]) -> (u8, Vec<u8>, Vec<u8>) {
    let mut out = vec![];
    let mut err = vec![];
    let code = fortress_cli::run(args.iter().map(|s| (*s).to_owned()), &mut out, &mut err).unwrap();
    (code, out, err)
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
/// `T-TF-CLI-0001-R24-001`
/// Fortress requirement: TF-CLI-0001-R24
#[test]
fn preview_and_inspect_are_identical_readonly_provenance_without_external_approval() {
    let f = Fixture::new();
    let before = snapshot(br#"{"$schema":"urn:fortress:schema:v2:module-contract","deny":true}"#);
    let after = snapshot(
        br#"{"$schema":"urn:fortress:schema:v2:module-contract","deny":false,"approved":true}"#,
    );
    let a = before.to_canonical_bytes().unwrap();
    let b = after.to_canonical_bytes().unwrap();
    let before_path = f.0.join("before.json");
    let after_path = f.0.join("after.json");
    let selection_path = f.0.join("selection.json");
    let decision_path = f.0.join("decision.json");
    std::fs::write(&before_path, &a).unwrap();
    std::fs::write(&after_path, &b).unwrap();
    let selection = json!({"base_state_ref":before.state.digest().unwrap(),"base_authority_ref":before.state.governing_identity().unwrap().unwrap(),"root_policy_ref":d(8),"require_assurance":false,"rules":[{"id":"owner","classes":["MODULE_INTENT"],"actions":["REPLACE"],"scope":"project","issuer_policy_ref":d(7)}]});
    std::fs::write(&selection_path, serde_json::to_vec(&selection).unwrap()).unwrap();
    std::fs::write(
        f.0.join("build.rs"),
        b"fn main(){panic!(\"project code must not execute\");}",
    )
    .unwrap();
    let (code, bytes, err) = run(&[
        "authority",
        "preview",
        "--from",
        path(&before_path),
        "--to",
        path(&after_path),
        "--base-selection",
        path(&selection_path),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["disposition"], "REQUIRE_AUTHORIZATION");
    assert_eq!(value["authorization"][0]["state"], "MISSING");
    assert_eq!(value["host_coverage"]["state"], "UNMEDIATED");
    assert_eq!(value["enforced"], false);
    std::fs::write(&decision_path, &bytes).unwrap();
    let (code, again, _) = run(&[
        "authority",
        "inspect",
        "--decision",
        path(&decision_path),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    assert_eq!(bytes, again);
    let (code, human, _) = run(&["authority", "inspect", "--decision", path(&decision_path)]);
    assert_eq!(code, 0);
    let human = String::from_utf8(human).unwrap();
    for state in ["MISSING", "UNMEDIATED", "intent/new-name"] {
        assert!(human.contains(state));
    }
    let id = fortress_core::development_governance::ChangeDecision::from_json_str(
        std::str::from_utf8(&bytes).unwrap(),
    )
    .unwrap()
    .digest()
    .unwrap();
    let (code, rpc, err) = run(&[
        "explain",
        &id,
        path(&f.0),
        "--decision",
        path(&decision_path),
        "--format",
        "json",
        "--limit",
        "1",
    ]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let response: Value = serde_json::from_slice(&rpc).unwrap();
    assert_eq!(response["result"]["data"]["evidence"]["total"], 2);
    assert_eq!(std::fs::read(&before_path).unwrap(), a);
    assert_eq!(std::fs::read(&after_path).unwrap(), b);
    assert!(!f.0.join("target").exists());
}
/// `T-TF-CLI-0001-R24-002`
/// Fortress requirement: TF-CLI-0001-R24
#[test]
fn preview_rejects_missing_base_selection_malformed_receipts_and_grant_options() {
    for args in [
        vec!["authority", "preview"],
        vec!["authority", "inspect", "--decision", "../missing.json"],
        vec!["authority", "preview", "--grant", "approved:true"],
        vec!["authority", "preview", "--from", "a", "--from", "b"],
    ] {
        let (code, _, err) = run(&args);
        assert_ne!(code, 0);
        assert!(!err.is_empty());
    }
}
