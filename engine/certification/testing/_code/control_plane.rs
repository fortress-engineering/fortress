//! Cross-owner contract tests for the fixed control namespace.

use fortress_core::control_layout::{
    ControlLayout, ControlRole, ControlSourceBinding, EVIDENCE_ROOT, PROJECT_CONFIGURATION_PATH,
};
use fortress_core::control_manifest::{
    ArtifactStorage, AssessmentGenerationManifest, AssessmentSelectionIndex,
};
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

fn manifest(member: &str) -> String {
    format!(
        r#"{{
  "$schema":"urn:fortress:derived:v1:assessment-generation-manifest",
  "schema_version":1,
  "generation_kind":"LOCAL_QUALITY",
  "project":"PF-FORTRESS",
  "profile":"fortress-complete-local-v1",
  "selection_key":"{DIGEST_A}",
  "source":{{"fingerprint":"{DIGEST_B}","file_count":1}},
  "control_layout":{{"id":"fortress-control-layout-v1","digest":"{DIGEST_A}"}},
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
}
