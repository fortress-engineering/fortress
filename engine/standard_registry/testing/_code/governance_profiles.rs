//! Focused qualification for selectable governance and assurance profiles.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::placement::evaluate_module_grammar;
use fortress_core::profile::{AssuranceOutcome, resolve_profiles};
use fortress_core::program_semantics::program_input_descriptor;
use fortress_core::project::ProjectConfiguration;
use fortress_core::standard::StandardBundle;
use serde_json::Value;

const CANONICAL_DIGEST: &str =
    "sha256:7640a6e2c9a7fcf5f0a0d10bcd776914412b80c364162c24d013094de2ff883a";
const NATIVE_DIGEST: &str =
    "sha256:ac541bb1e1dd0f7f6ef6c8f1c1babcbe62c9a13cc507e74ad0058454baa7c475";
const SEMANTIC_DIGEST: &str =
    "sha256:cedf72ff808e6bef344ecdced91111fcf56ba3d0f3894d25fa5bfa0f1e61073f";
const ASSURANCE_DIGEST: &str =
    "sha256:590aa518f3ea324d396877362e6a68c98febf297990810e46523729aa35786c8";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn installed_standard() -> StandardBundle {
    let root = repository_root();
    let manifest =
        fs::read_to_string(root.join("engine/standard_registry/_data/standard_manifest.json"))
            .expect("standard manifest");
    let value: Value = serde_json::from_str(&manifest).expect("manifest JSON");
    let paths = value["rules"]
        .as_array()
        .expect("rule paths")
        .iter()
        .map(|path| path.as_str().expect("rule path").to_owned())
        .collect::<Vec<_>>();
    let sources = paths
        .iter()
        .map(|path| fs::read_to_string(root.join(path)).expect("rule source"))
        .collect::<Vec<_>>();
    let documents = paths
        .iter()
        .zip(&sources)
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    StandardBundle::from_json_documents(&manifest, &documents).expect("installed Standard")
}

fn reference(id: &str, digest: &str) -> String {
    format!(r#"{{"id":"{id}","version":"1.0.0","digest":"{digest}"}}"#)
}

fn configuration(
    layout: &str,
    selected_profiles: &[(&str, &str)],
    assurance_profiles: &[(&str, &str)],
    module_overrides: &str,
    coverage_floor: &str,
) -> ProjectConfiguration {
    let selected = selected_profiles
        .iter()
        .map(|(id, digest)| reference(id, digest))
        .collect::<Vec<_>>()
        .join(",");
    let assurance = assurance_profiles
        .iter()
        .map(|(id, digest)| reference(id, digest))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"{{
          "$schema":"urn:fortress:schema:v4:project-configuration",
          "schema_version":4,
          "observation_exclusions":[".git"],
          "logical_modules":[],
          "governance":{{
            "default_layout":"{layout}",
            "selected_profiles":[{selected}],
            "module_overrides":{module_overrides}{coverage_floor}
          }},
          "assurance_profiles":[{assurance}]
        }}"#,
    );
    ProjectConfiguration::from_json_str(&source).expect("profile configuration")
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-001`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn native_mode_avoids_unselected_filing_findings() {
    let legacy = ProjectConfiguration::from_json_str(
        r#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":[".git"],"logical_modules":[]}"#,
    )
    .expect("legacy existing repository configuration");
    let selection = legacy.profile_selection();
    let resolved = resolve_profiles(&installed_standard(), selection.as_ref(), &BTreeSet::new())
        .expect("native default resolves");
    assert_eq!(resolved.layout_id(), "native-logical-v1");
    assert!(!resolved.rule_applicable("REPO-MODULE-001"));
    assert!(!resolved.rule_applicable("REPO-DOCS-001"));
    assert!(!resolved.rule_applicable("TEST-TRACEABILITY-001"));
    assert!(resolved.rule_applicable("PROGRAM-EFFECT-001"));
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-002`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn canonical_mode_rejects_invalid_names_and_structure() {
    let project = configuration(
        "canonical-filing-v1",
        &[("GOV-FORTRESS-CANONICAL", CANONICAL_DIGEST)],
        &[],
        "[]",
        "",
    );
    let standard = installed_standard();
    let selection = project.profile_selection();
    let resolved = resolve_profiles(&standard, selection.as_ref(), &BTreeSet::new())
        .expect("canonical profile resolves");
    assert!(resolved.rule_applicable("REPO-MODULE-001"));
    let findings = evaluate_module_grammar(
        &["contract.json".into(), "BadName/contract.json".into()],
        standard.edition(),
    )
    .expect("filing evaluation");
    assert!(!findings.is_empty());
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-003`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn profile_composition_order_is_irrelevant() {
    let left = configuration(
        "canonical-filing-v1",
        &[
            ("GOV-FORTRESS-CANONICAL", CANONICAL_DIGEST),
            ("GOV-FORTRESS-SEMANTIC", SEMANTIC_DIGEST),
        ],
        &[],
        "[]",
        "",
    );
    let right = configuration(
        "canonical-filing-v1",
        &[
            ("GOV-FORTRESS-SEMANTIC", SEMANTIC_DIGEST),
            ("GOV-FORTRESS-CANONICAL", CANONICAL_DIGEST),
        ],
        &[],
        "[]",
        "",
    );
    let standard = installed_standard();
    let ids = BTreeSet::new();
    let left_selection = left.profile_selection();
    let right_selection = right.profile_selection();
    assert_eq!(
        resolve_profiles(&standard, left_selection.as_ref(), &ids).expect("left composition"),
        resolve_profiles(&standard, right_selection.as_ref(), &ids).expect("right composition")
    );
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-004`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn incompatible_profile_requirements_fail() {
    let project = configuration(
        "canonical-filing-v1",
        &[
            ("GOV-FORTRESS-CANONICAL", CANONICAL_DIGEST),
            ("GOV-FORTRESS-NATIVE", NATIVE_DIGEST),
        ],
        &[],
        "[]",
        "",
    );
    let selection = project.profile_selection();
    assert!(resolve_profiles(&installed_standard(), selection.as_ref(), &BTreeSet::new()).is_err());
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-005`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn missing_required_evaluability_is_assurance_hold() {
    let project = configuration(
        "native-logical-v1",
        &[("GOV-FORTRESS-NATIVE", NATIVE_DIGEST)],
        &[("ASSURE-SEMANTIC-EVALUABILITY", ASSURANCE_DIGEST)],
        "[]",
        "",
    );
    let selection = project.profile_selection();
    let resolved = resolve_profiles(&installed_standard(), selection.as_ref(), &BTreeSet::new())
        .expect("assurance profile resolves");
    let semantic_verdict = "UNKNOWN";
    let assessments = resolved.assess_required_evidence(&BTreeSet::new());
    assert_eq!(semantic_verdict, "UNKNOWN");
    assert_eq!(
        assessments[0].outcome(),
        AssuranceOutcome::RequiredEvidenceMissing
    );
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-006`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn module_scope_uses_stable_ids() {
    let module_profile = reference("GOV-FORTRESS-SEMANTIC", SEMANTIC_DIGEST);
    let overrides = format!(
        r#"[{{"module":"AF-PAYMENTS-0001","selected_profiles":[{module_profile}],"assurance_profiles":[]}}]"#,
    );
    let project = configuration(
        "native-logical-v1",
        &[("GOV-FORTRESS-NATIVE", NATIVE_DIGEST)],
        &[],
        &overrides,
        "",
    );
    let modules = BTreeSet::from(["AF-PAYMENTS-0001".to_owned()]);
    let selection = project.profile_selection();
    let resolved = resolve_profiles(&installed_standard(), selection.as_ref(), &modules)
        .expect("stable Module scope resolves");
    assert!(resolved.module("AF-PAYMENTS-0001").is_some());
    assert!(resolved.module("physical/path").is_none());
}

/// `T-AF-STANDARD-REGISTRY-0001-R06-007`
/// Fortress requirement: AF-STANDARD-REGISTRY-0001-R06
#[test]
fn policy_only_changes_reuse_unaffected_program_facts() {
    let first = format!(
        r#"{{"$schema":"urn:fortress:schema:v4:project-configuration","schema_version":4,"observation_exclusions":[".git"],"logical_modules":[],"governance":{{"default_layout":"native-logical-v1","selected_profiles":[{}],"module_overrides":[]}},"assurance_profiles":[]}}"#,
        reference("GOV-FORTRESS-NATIVE", NATIVE_DIGEST),
    );
    let second = format!(
        r#"{{"$schema":"urn:fortress:schema:v4:project-configuration","schema_version":4,"observation_exclusions":[".git"],"logical_modules":[],"governance":{{"default_layout":"native-logical-v1","selected_profiles":[{}],"module_overrides":[],"coverage_floor":{{"minimum_semantic_functions":10,"minimum_evaluable_basis_points":9000}}}},"assurance_profiles":[{}]}}"#,
        reference("GOV-FORTRESS-NATIVE", NATIVE_DIGEST),
        reference("ASSURE-SEMANTIC-EVALUABILITY", ASSURANCE_DIGEST),
    );
    let first_configuration =
        ProjectConfiguration::from_json_str(&first).expect("first policy authority");
    let second_configuration =
        ProjectConfiguration::from_json_str(&second).expect("second policy authority");
    let standard = installed_standard();
    let modules = BTreeSet::new();
    let first_selection = first_configuration.profile_selection();
    let second_selection = second_configuration.profile_selection();
    let first_profiles = resolve_profiles(&standard, first_selection.as_ref(), &modules)
        .expect("first policy resolves");
    let second_profiles = resolve_profiles(&standard, second_selection.as_ref(), &modules)
        .expect("second policy resolves");
    assert_ne!(
        first_profiles.authority_digests(),
        second_profiles.authority_digests()
    );
    let first = program_input_descriptor("__fortress/.fsconfig", first.as_bytes())
        .expect("first program authority descriptor");
    let second = program_input_descriptor("__fortress/.fsconfig", second.as_bytes())
        .expect("second program authority descriptor");
    assert_eq!(first, second);
}
