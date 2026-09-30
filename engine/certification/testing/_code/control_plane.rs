//! Cross-owner contract tests for the fixed control namespace.

use fortress_core::control_layout::{
    CONTROL_LAYOUT_SOURCE, ControlLayout, ControlRole, ControlSourceBinding,
    EFFECT_SUMMARY_AUTHORITY_PATH, EVIDENCE_ROOT, LEGACY_CONTROL_LAYOUT_SOURCE,
    PROJECT_CONFIGURATION_PATH,
};
use fortress_core::control_manifest::{
    ArtifactStorage, AssessmentGenerationManifest, AssessmentSelectionIndex,
};
use fortress_core::program_semantics::{ProgramInputRole, program_input_descriptor};
use fortress_core::project::ProjectConfiguration;

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// `T-AF-CONTROL-LAYOUT-0001-R01-001`
/// Fortress classification: infrastructure
#[test]
fn installed_layout_has_one_fixed_config_and_closed_generation_members() {
    let layout = ControlLayout::standard();
    let config = layout
        .resolve(PROJECT_CONFIGURATION_PATH)
        .expect("config resolves");
    assert_eq!(config.role(), ControlRole::ProjectConfiguration);
    assert_eq!(config.source_binding(), ControlSourceBinding::Required);
    assert_eq!(config.owner(), "project_model");
    let manifest = layout
        .resolve(&format!(
            "{EVIDENCE_ROOT}/generations/{}/manifest.json",
            "a".repeat(64)
        ))
        .expect("manifest resolves");
    assert_eq!(manifest.role(), ControlRole::GenerationManifest);
    assert_eq!(
        manifest.source_binding(),
        ControlSourceBinding::Nonrecursive
    );
    assert_eq!(
        layout
            .resolve("__fortress/evidence/arbitrary.json")
            .expect("control path classifies")
            .role(),
        ControlRole::Unrecognized
    );
    assert!(layout.resolve("__Fortress/.fsconfig").is_none());
    assert_eq!(
        layout.artifact_ids(),
        vec![
            "bfg",
            "ccg",
            "certification",
            "environmental",
            "evidence-graph",
            "information-flow",
            "psm",
            "quality-certificate",
            "realized-bfg",
            "references",
            "semantic",
            "semantic-conformance",
            "source-artifacts",
            "state-effect",
            "verified-bfg",
        ]
    );
}

/// `T-AF-CONTROL-LAYOUT-0001-R01-002`
/// Fortress classification: infrastructure
#[test]
fn project_configuration_cannot_hide_or_bind_control_storage() {
    let hidden = r#"{
      "$schema":"urn:fortress:schema:v3:project-configuration",
      "schema_version":3,
      "observation_exclusions":["__fortress"],
      "logical_modules":[]
    }"#;
    assert!(ProjectConfiguration::from_json_str(hidden).is_err());
    let bound = r#"{
      "$schema":"urn:fortress:schema:v3:project-configuration",
      "schema_version":3,
      "observation_exclusions":[".git"],
      "logical_modules":[{
        "module":"AF-CONTROL-0001",
        "contract":"x/contract.json",
        "parent":"PF-CONTROL",
        "bindings":[{"kind":"directory","path":"__fortress/evidence"}]
      }]
    }"#;
    assert!(ProjectConfiguration::from_json_str(bound).is_err());
}

/// `T-AF-CONTROL-LAYOUT-0001-R01-003`
/// Fortress classification: infrastructure
#[test]
fn profile_selection_uses_the_registered_project_configuration_role() {
    let source = br#"{
      "$schema":"urn:fortress:schema:v4:project-configuration",
      "schema_version":4,
      "observation_exclusions":[".git"],
      "logical_modules":[],
      "governance":{
        "default_layout":"native-logical-v1",
        "selected_profiles":[{
          "id":"GOV-FORTRESS-NATIVE",
          "version":"1.0.0",
          "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }],
        "module_overrides":[]
      },
      "assurance_profiles":[]
    }"#;
    let role = ControlLayout::standard()
        .resolve(PROJECT_CONFIGURATION_PATH)
        .expect("registered configuration")
        .role();
    assert_eq!(role, ControlRole::ProjectConfiguration);
    let descriptor = program_input_descriptor(PROJECT_CONFIGURATION_PATH, source)
        .expect("active control authority is a program context input");
    assert_eq!(descriptor.role(), ProgramInputRole::ProjectIdentity);
}

/// `T-AF-CONTROL-LAYOUT-0001-R01-004`
/// Fortress classification: infrastructure
#[test]
fn summary_authority_has_one_exact_required_role() {
    let layout = ControlLayout::standard();
    let entry = layout
        .resolve(EFFECT_SUMMARY_AUTHORITY_PATH)
        .expect("summary authority resolves");
    assert_eq!(entry.role(), ControlRole::EffectSummaryAuthority);
    assert_eq!(entry.owner(), "state_effect_analysis");
    assert_eq!(entry.source_binding(), ControlSourceBinding::Required);
    for path in [
        "__fortress",
        "__fortress/governance",
        "__fortress/governance/effect_summaries",
        "__fortress/evidence",
        "__fortress/evidence/generations",
    ] {
        assert!(layout.allows_directory(path), "registered parent {path}");
    }
    assert!(layout.allows_directory(&format!(
        "__fortress/evidence/generations/{}",
        "a".repeat(64)
    )));
    for path in [
        "__Fortress/governance/effect_summaries",
        "__fortress/governance/effect_summaries_extra",
        "__fortress/governance/effect_summaries/extra",
        "__fortress/governance/unregistered",
        EFFECT_SUMMARY_AUTHORITY_PATH,
        "__fortress/governance/effect_summaries/../unregistered",
        "__fortress/evidence/generations/not-a-digest",
        "__fortress/evidence/generations/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(
            !layout.allows_directory(path),
            "unregistered directory {path}"
        );
    }
    assert!(!layout.allows_directory(&format!(
        "__fortress/evidence/generations/{}/extra",
        "a".repeat(64)
    )));
    assert_eq!(
        layout
            .resolve("__fortress/governance/effect_summaries/other.json")
            .expect("unregistered control path resolves")
            .role(),
        ControlRole::Unrecognized
    );
    assert!(
        program_input_descriptor(EFFECT_SUMMARY_AUTHORITY_PATH, b"{}").is_none(),
        "effect authority does not change unrelated program facts"
    );
    let mut weakened: serde_json::Value = serde_json::from_str(CONTROL_LAYOUT_SOURCE).unwrap();
    let record = weakened["roles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["path"] == EFFECT_SUMMARY_AUTHORITY_PATH)
        .unwrap();
    record["source_binding"] = serde_json::json!("NONRECURSIVE");
    assert!(ControlLayout::from_json_str(&weakened.to_string()).is_err());
}

/// `T-AF-CONTROL-LAYOUT-0001-R01-005`
/// Fortress classification: infrastructure
#[test]
fn historical_layout_retains_its_role_boundary_and_digest() {
    let historical = ControlLayout::from_json_str(LEGACY_CONTROL_LAYOUT_SOURCE)
        .expect("historical layout retains its reader");
    assert_eq!(
        historical
            .resolve(EFFECT_SUMMARY_AUTHORITY_PATH)
            .expect("historical control path resolves")
            .role(),
        ControlRole::Unrecognized
    );
    assert_ne!(historical.digest(), ControlLayout::standard().digest());
    assert!(!historical.allows_directory("__fortress/governance/effect_summaries"));
    assert!(
        ControlLayout::from_json_str(
            &CONTROL_LAYOUT_SOURCE.replace("\"schema_version\": 2", "\"schema_version\": 1")
        )
        .is_err()
    );
}

fn manifest(member: &str) -> String {
    format!(
        r#"{{
  "$schema":"urn:fortress:derived:v2:assessment-generation-manifest",
  "schema_version":2,
  "generation_kind":"LOCAL_QUALITY",
  "project":"PF-FORTRESS",
  "profile":"fortress-complete-local-v1",
  "selection_key":"{DIGEST_A}",
  "source":{{"fingerprint":"{DIGEST_B}","file_count":1}},
  "control_layout":{{"id":"fortress-control-layout-v2","digest":"{DIGEST_A}"}},
  "artifacts":[{{
    "id":"quality-certificate",
    "producer_id":"snapshot_governance",
    "schema_ref":"urn:fortress:derived:v3:local-quality-certificate",
    "producer_semantic_version":"quality-certificate-v3.0",
    "content_digest":"{DIGEST_B}",
    "byte_count":1,
    "disposition":"REQUIRED",
    "storage":{{"kind":"INCLUDED","member_name":"{member}"}}
  }}]
}}"#
    )
}

/// `T-AF-CONTROL-PUBLICATION-0001-R01-001`
/// Fortress classification: infrastructure
#[test]
fn manifest_digest_is_deterministic_and_locators_are_safe() {
    let first = AssessmentGenerationManifest::from_json_str(&manifest("quality_certificate.json"))
        .expect("manifest validates");
    let second = AssessmentGenerationManifest::from_json_str(&manifest("quality_certificate.json"))
        .expect("manifest validates twice");
    assert_eq!(
        first.generation_digest().unwrap(),
        second.generation_digest().unwrap()
    );
    assert!(matches!(
        first.artifacts()[0].storage(),
        ArtifactStorage::Included { .. }
    ));
    assert!(AssessmentGenerationManifest::from_json_str(&manifest("../escape.json")).is_err());
}

/// `T-AF-CONTROL-PUBLICATION-0001-R01-003`
/// Fortress classification: infrastructure
#[test]
fn generation_manifest_requires_matching_historical_or_current_layout_version() {
    let current = manifest("quality_certificate.json");
    let historical = current
        .replace(
            "derived:v2:assessment-generation-manifest",
            "derived:v1:assessment-generation-manifest",
        )
        .replace("\"schema_version\":2", "\"schema_version\":1")
        .replace("fortress-control-layout-v2", "fortress-control-layout-v1");
    let retained = AssessmentGenerationManifest::from_json_str(&historical)
        .expect("historical manifest retains its original reader");
    let active = AssessmentGenerationManifest::from_json_str(&current)
        .expect("current manifest uses the current layout");
    assert_ne!(
        retained.generation_digest().unwrap(),
        active.generation_digest().unwrap()
    );
    for mismatched in [
        historical.replace("fortress-control-layout-v1", "fortress-control-layout-v2"),
        current.replace("fortress-control-layout-v2", "fortress-control-layout-v1"),
        current.replace("\"schema_version\":2", "\"schema_version\":1"),
    ] {
        assert!(AssessmentGenerationManifest::from_json_str(&mismatched).is_err());
    }
}

/// `T-AF-CONTROL-PUBLICATION-0001-R01-002`
/// Fortress classification: infrastructure
#[test]
fn selection_index_resolves_only_the_exact_context_key() {
    let source = format!(
        r#"{{"$schema":"urn:fortress:derived:v1:assessment-selection-index","schema_version":1,"selections":[{{"selection_key":"{DIGEST_A}","generation_digest":"{DIGEST_B}"}}]}}"#
    );
    let index = AssessmentSelectionIndex::from_json_str(&source).expect("index validates");
    assert_eq!(index.generation(DIGEST_A), Some(DIGEST_B));
    assert_eq!(index.generation(DIGEST_B), None);
    let mut fixture: serde_json::Value =
        serde_json::from_str(&source).expect("index fixture parses");
    let entries = &mut fixture["selections"];
    *entries = serde_json::json!([
        {"selection_key": DIGEST_A, "generation_digest": DIGEST_A},
        {"selection_key": DIGEST_A, "generation_digest": DIGEST_B},
    ]);
    assert!(AssessmentSelectionIndex::from_json_str(&fixture.to_string()).is_err());
    fixture["selections"][1]["generation_digest"] = serde_json::json!(DIGEST_A);
    assert!(AssessmentSelectionIndex::from_json_str(&fixture.to_string()).is_err());
    fixture["selections"][1]["selection_key"] = serde_json::json!(DIGEST_B);
    let independent = AssessmentSelectionIndex::from_json_str(&fixture.to_string())
        .expect("independent contexts may select the same generation");
    assert_eq!(independent.generation(DIGEST_A), Some(DIGEST_A));
    assert_eq!(independent.generation(DIGEST_B), Some(DIGEST_A));
    fixture["selections"]
        .as_array_mut()
        .expect("fixture array")
        .reverse();
    assert!(AssessmentSelectionIndex::from_json_str(&fixture.to_string()).is_err());
    fixture["selections"] = serde_json::json!([]);
    assert!(AssessmentSelectionIndex::from_json_str(&fixture.to_string()).is_ok());
}
