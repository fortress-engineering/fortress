//! Universal Source Architecture conformance tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fortress_core::audit::compile_repository_source_artifact_model;
use fortress_core::contract_coherency::{
    ContractCoherencyGraph, ContractStandardIndex, ModuleContract, compile_contract_coherency_graph,
};
use fortress_core::documentation::code_file_responsibilities;
use fortress_core::filing::{FilingSystemProfiles, analyze_project_filing_system};
use fortress_core::source_architecture::{
    ArchetypeResolution, GeneratedSource, LanguageAssignment, RegionCoverage, SEMANTIC_REGIONS,
    SOURCE_ARTIFACT_MODEL_SCHEMA, SemanticRegion, SourceArchitectureInput, SourceFindingKind,
    SourceObservation, SourceProfileRegistry, SourceProvenanceKind, SourceVerificationRelationship,
    evaluate_source_architecture,
};
use serde_json::{Value, json};

const EDITION: &str = "1.0.0-draft.1";

fn canonical_contract(value: Value) -> Vec<u8> {
    serde_json::from_value::<ModuleContract>(value)
        .expect("fixture contract shape")
        .to_canonical_json()
        .expect("fixture contract serializes")
        .into_bytes()
}

fn contract(id: &str, display_name: &str, root: bool) -> Vec<u8> {
    let mut value = json!({
        "$schema": "urn:fortress:schema:v2:module-contract",
        "schema_version": 2,
        "id": id,
        "display_name": display_name,
        "provides": [],
        "requires": [],
        "relationships": [],
        "constraints": [],
        "guarantees": [],
        "features": [],
        "behavior": []
    });
    if root {
        value.as_object_mut().expect("object").insert(
            "ecosystem".into(),
            json!({
                "repository_grammar": 1,
                "standard": {"id": "STD-FIXTURE", "edition": EDITION}
            }),
        );
    }
    canonical_contract(value)
}

fn fixture_files(extension: &str) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("README.md".into(), b"# Fixture\n".to_vec()),
        ("contract.json".into(), contract("PF-SOURCE-FIXTURE", "Fixture", true)),
        (
            format!("code/artifact.{extension}"),
            b"fixture source bytes\n".to_vec(),
        ),
        (
            "docs/code_docs.md".into(),
            format!(
                "# Code\n\n## Role\n\nFixture.\n\n## Execution\n\nFixture.\n\n## State\n\nFixture.\n\n## Failure Semantics\n\nFixture.\n\n## Files\n\n### [`artifact.{extension}`](../code/artifact.{extension})\n\nOwns one coherent fixture responsibility.\n"
            )
            .into_bytes(),
        ),
    ])
}

fn fixture_ccg(files: &BTreeMap<String, Vec<u8>>) -> ContractCoherencyGraph {
    let compilation = compile_contract_coherency_graph(
        files,
        &ContractStandardIndex::new(
            "STD-FIXTURE",
            EDITION,
            ["SOURCE-ARTIFACT-001", "SOURCE-PROFILE-001"],
        ),
        None,
    );
    assert!(compilation.is_success(), "{:?}", compilation.violations());
    compilation.graph().expect("fixture CCG").clone()
}

#[allow(clippy::needless_pass_by_value)]
fn profile(
    language: &str,
    extension: &str,
    adapter: &str,
    version: &str,
    archetypes: Value,
) -> SourceProfileRegistry {
    SourceProfileRegistry::from_json_str(
        &serde_json::to_string_pretty(&json!({
            "$schema": "urn:fortress:schema:v1:source-profiles",
            "schema_version": 1,
            "profiles": [{
                "id": format!("PROFILE-{}", language.to_ascii_uppercase()),
                "language": language,
                "version": version,
                "extensions": [extension],
                "generated_source_recognition": "explicit fixture generator authority",
                "observation_adapter": adapter,
                "archetypes": archetypes,
                "semantic_region_mapping": [
                    {"fact": "declaration", "region": "DECLARATIONS"},
                    {"fact": "implementation", "region": "IMPLEMENTATION"}
                ],
                "visibility_mapping": [{"native": "public", "public": true}],
                "responsibility_required": true,
                "coverage_limitations": ["fixture-only observation"]
            }]
        }))
        .expect("profile JSON"),
    )
    .expect("valid profile")
}

fn archetype(id: &str, required: &[&str], allowed: &[&str], forbidden: &[&str]) -> Value {
    json!({
        "id": id,
        "required_regions": required,
        "allowed_regions": allowed,
        "forbidden_regions": forbidden
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    files: &BTreeMap<String, Vec<u8>>,
    profiles: &SourceProfileRegistry,
    language: &str,
    extension: &str,
    observations: &[SourceObservation],
    generated: &[GeneratedSource],
    verifications: &[SourceVerificationRelationship],
    responsibility: bool,
    adapters: &[&str],
) -> fortress_core::source_architecture::SourceArchitectureEvaluation {
    let ccg = fixture_ccg(files);
    let paths = files.keys().cloned().collect::<Vec<_>>();
    let filing = analyze_project_filing_system(&paths, &FilingSystemProfiles::standard());
    let responsibilities = if responsibility {
        code_file_responsibilities(files, &ccg).expect("canonical responsibility projection")
    } else {
        Vec::new()
    };
    let languages = [LanguageAssignment::new(
        extension,
        language,
        "fixture-language",
    )];
    let available_adapters = adapters
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    evaluate_source_architecture(&SourceArchitectureInput {
        project_id: "PF-SOURCE-FIXTURE",
        source_identity: "sha256:fixture-source",
        filing: &filing,
        ccg: &ccg,
        files,
        responsibilities: &responsibilities,
        profiles,
        languages: &languages,
        observations,
        generated_sources: generated,
        verification_relationships: verifications,
        available_adapters: &available_adapters,
        psm_digest: Some("sha256:fixture-psm"),
        standard_edition: EDITION,
    })
    .expect("source architecture evaluates")
}

fn observation(
    extension: &str,
    region: SemanticRegion,
    coverage: RegionCoverage,
    reference: &str,
) -> SourceObservation {
    SourceObservation::new(
        format!("code/artifact.{extension}"),
        region,
        coverage,
        "fixture-adapter",
        reference,
        Some(1),
    )
}

fn kinds(
    evaluation: &fortress_core::source_architecture::SourceArchitectureEvaluation,
) -> BTreeSet<SourceFindingKind> {
    evaluation.model().artifacts()[0]
        .conclusions()
        .iter()
        .map(fortress_core::source_architecture::SourceConclusion::kind)
        .collect()
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R01-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R01
#[test]
fn canonical_documentation_parser_supplies_authoritative_responsibility() {
    let files = fixture_files("nom");
    let ccg = fixture_ccg(&files);
    let responsibilities = code_file_responsibilities(&files, &ccg).expect("catalog");
    assert_eq!(responsibilities.len(), 1);
    assert_eq!(responsibilities[0].source_path(), "code/artifact.nom");
    assert_eq!(responsibilities[0].module_id(), "PF-SOURCE-FIXTURE");
    assert_eq!(
        responsibilities[0].responsibility(),
        "Owns one coherent fixture responsibility."
    );
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R01-002`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R01
#[test]
fn project_filing_ownership_and_content_identity_remain_separate() {
    let files = fixture_files("nom");
    let first = evaluate(
        &files,
        &SourceProfileRegistry::standard(),
        "nominal",
        "nom",
        &[],
        &[],
        &[],
        true,
        &[],
    );
    let mut changed = files.clone();
    changed.insert("code/artifact.nom".into(), b"changed\n".to_vec());
    let second = evaluate(
        &changed,
        &SourceProfileRegistry::standard(),
        "nominal",
        "nom",
        &[],
        &[],
        &[],
        true,
        &[],
    );
    assert_eq!(
        first.model().artifacts()[0].id(),
        second.model().artifacts()[0].id()
    );
    assert_ne!(
        first.model().artifacts()[0].content_digest(),
        second.model().artifacts()[0].content_digest()
    );
    assert_eq!(
        first.model().artifacts()[0].module_id(),
        "PF-SOURCE-FIXTURE"
    );
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R01-003`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R01
#[test]
fn relocation_preserves_artifact_and_cross_module_semantic_identity() {
    fn moved_files(path: &str) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            ("README.md".into(), b"# Root\n".to_vec()),
            ("contract.json".into(), contract("PF-MOVE", "Root", true)),
            (format!("{path}/README.md"), b"# Moved\n".to_vec()),
            (format!("{path}/contract.json"), contract("AF-MOVED-0001", "Moved", false)),
            (format!("{path}/code/unit.nom"), b"same bytes\n".to_vec()),
            (
                format!("{path}/docs/code_docs.md"),
                b"# Code\n\n## Role\n\nRole.\n\n## Execution\n\nExecution.\n\n## State\n\nState.\n\n## Failure Semantics\n\nFailure.\n\n## Files\n\n### [`unit.nom`](../code/unit.nom)\n\nStable responsibility.\n".to_vec(),
            ),
        ])
    }
    fn model(
        files: &BTreeMap<String, Vec<u8>>,
    ) -> fortress_core::source_architecture::SourceArchitectureEvaluation {
        let ccg = fixture_ccg(files);
        let filing = analyze_project_filing_system(
            &files.keys().cloned().collect::<Vec<_>>(),
            &FilingSystemProfiles::standard(),
        );
        let responsibilities = code_file_responsibilities(files, &ccg).expect("catalog");
        let language = [LanguageAssignment::new("nom", "nominal", "fixture")];
        let source_path = files
            .keys()
            .find(|path| path.ends_with("/code/unit.nom"))
            .expect("source");
        let observation = [SourceObservation::new(
            source_path,
            SemanticRegion::Dependencies,
            RegionCoverage::Observed,
            "fixture",
            "module:AF-OTHER-0001",
            None,
        )];
        evaluate_source_architecture(&SourceArchitectureInput {
            project_id: "PF-MOVE",
            source_identity: "fixture",
            filing: &filing,
            ccg: &ccg,
            files,
            responsibilities: &responsibilities,
            profiles: &SourceProfileRegistry::standard(),
            languages: &language,
            observations: &observation,
            generated_sources: &[],
            verification_relationships: &[],
            available_adapters: &BTreeSet::new(),
            psm_digest: None,
            standard_edition: EDITION,
        })
        .expect("model")
    }
    let before = model(&moved_files("mods/old"));
    let after = model(&moved_files("mods/new"));
    assert_eq!(
        before.model().artifacts()[0].id(),
        after.model().artifacts()[0].id()
    );
    let before_json = before.model().to_canonical_json().expect("json");
    let after_json = after.model().to_canonical_json().expect("json");
    assert!(before_json.contains("module:AF-OTHER-0001"));
    assert!(after_json.contains("module:AF-OTHER-0001"));
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R02-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R02
#[test]
fn universal_region_vocabulary_and_empty_standard_registry_are_stable() {
    assert_eq!(SEMANTIC_REGIONS.len(), 11);
    assert!(SourceProfileRegistry::standard().profiles().is_empty());
    assert_eq!(SEMANTIC_REGIONS[0], SemanticRegion::IdentityResponsibility);
    assert_eq!(
        SEMANTIC_REGIONS[10],
        SemanticRegion::VerificationRelationships
    );
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R02-002`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R02
#[test]
fn valid_profile_resolves_exactly_one_primary_archetype() {
    let profiles = profile(
        "nominal",
        "nom",
        "fixture-adapter",
        "1.0.0",
        json!([archetype(
            "type_family",
            &["DECLARATIONS"],
            &["DECLARATIONS", "PUBLIC_INTERFACE", "IMPLEMENTATION"],
            &[]
        )]),
    );
    let evaluation = evaluate(
        &fixture_files("nom"),
        &profiles,
        "nominal",
        "nom",
        &[observation(
            "nom",
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            "decl:A",
        )],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    let artifact = &evaluation.model().artifacts()[0];
    assert_eq!(artifact.profile().status(), ArchetypeResolution::Resolved);
    assert_eq!(artifact.profile().archetype_id(), Some("type_family"));
    assert!(evaluation.findings().is_empty());
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R02-003`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R02
#[test]
fn archetype_missing_ambiguity_required_forbidden_and_unsupported_are_explicit() {
    let ambiguous_profiles = profile(
        "functional",
        "fun",
        "fixture-adapter",
        "1.0.0",
        json!([
            archetype("module", &["DECLARATIONS"], &["DECLARATIONS"], &[]),
            archetype("library", &["DECLARATIONS"], &["DECLARATIONS"], &[])
        ]),
    );
    let ambiguous = evaluate(
        &fixture_files("fun"),
        &ambiguous_profiles,
        "functional",
        "fun",
        &[observation(
            "fun",
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            "decl:many",
        )],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert_eq!(
        ambiguous.model().artifacts()[0].profile().status(),
        ArchetypeResolution::Ambiguous
    );
    assert_eq!(
        ambiguous.model().artifacts()[0]
            .profile()
            .candidate_archetypes()
            .len(),
        2
    );

    let strict = profile(
        "nominal",
        "nom",
        "fixture-adapter",
        "1.0.0",
        json!([archetype(
            "interface_surface",
            &["PUBLIC_INTERFACE"],
            &["PUBLIC_INTERFACE"],
            &["IMPLEMENTATION"]
        )]),
    );
    let missing = evaluate(
        &fixture_files("nom"),
        &strict,
        "nominal",
        "nom",
        &[
            observation(
                "nom",
                SemanticRegion::PublicInterface,
                RegionCoverage::Absent,
                "no-public",
            ),
            observation(
                "nom",
                SemanticRegion::Implementation,
                RegionCoverage::Observed,
                "implementation",
            ),
        ],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    let missing_kinds = kinds(&missing);
    assert!(missing_kinds.contains(&SourceFindingKind::SourceArchetypeMissing));
    assert!(missing_kinds.contains(&SourceFindingKind::SourceRequiredRegionMissing));
    assert!(missing_kinds.contains(&SourceFindingKind::SourceForbiddenRegionPresent));

    let unsupported = evaluate(
        &fixture_files("nom"),
        &strict,
        "nominal",
        "nom",
        &[observation(
            "nom",
            SemanticRegion::PublicInterface,
            RegionCoverage::Unsupported,
            "unsupported-public",
        )],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert!(kinds(&unsupported).contains(&SourceFindingKind::SourceObservationUnsupported));
}

/// `T-SOURCE-PROFILE-001-R01-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R02
#[test]
fn invalid_and_unavailable_profiles_never_receive_favorable_coverage() {
    let invalid = r#"{
      "$schema":"urn:fortress:schema:v1:source-profiles",
      "schema_version":1,
      "profiles":[],
      "unexpected":true
    }"#;
    assert!(SourceProfileRegistry::from_json_str(invalid).is_err());
    let profiles = profile(
        "script",
        "scr",
        "missing-adapter",
        "1.0.0",
        json!([archetype(
            "script",
            &["IMPLEMENTATION"],
            &["IMPLEMENTATION"],
            &[]
        )]),
    );
    let evaluation = evaluate(
        &fixture_files("scr"),
        &profiles,
        "script",
        "scr",
        &[],
        &[],
        &[],
        true,
        &[],
    );
    assert_eq!(
        evaluation.model().artifacts()[0].profile().status(),
        ArchetypeResolution::ProfileUnsupported
    );
    assert!(kinds(&evaluation).contains(&SourceFindingKind::SourceProfileUnsupported));
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R03-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R03
#[test]
fn generated_source_is_code_and_requires_explicit_generator_provenance() {
    let profiles = profile(
        "nominal",
        "nom",
        "fixture-adapter",
        "1.0.0",
        json!([archetype("generated_type", &[], &[], &[])]),
    );
    let valid = evaluate(
        &fixture_files("nom"),
        &profiles,
        "nominal",
        "nom",
        &[],
        &[GeneratedSource::new(
            "code/artifact.nom",
            Some("GEN-FIXTURE-0001".into()),
        )],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert_eq!(
        valid.model().artifacts()[0].provenance().kind(),
        SourceProvenanceKind::Generated
    );
    assert_eq!(
        valid.model().artifacts()[0].provenance().generator(),
        Some("GEN-FIXTURE-0001")
    );
    let missing = evaluate(
        &fixture_files("nom"),
        &profiles,
        "nominal",
        "nom",
        &[],
        &[GeneratedSource::new("code/artifact.nom", None)],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert!(kinds(&missing).contains(&SourceFindingKind::SourceGeneratedProvenanceMissing));
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R03-002`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R03
#[test]
fn synthetic_functional_profile_allows_cohesive_multi_declaration_composition() {
    let profiles = profile(
        "functional",
        "fun",
        "fixture-adapter",
        "1.0.0",
        json!([archetype(
            "functional_module",
            &["DECLARATIONS", "IMPLEMENTATION"],
            &["DECLARATIONS", "IMPLEMENTATION", "FAILURE_SEMANTICS"],
            &[]
        )]),
    );
    let evaluation = evaluate(
        &fixture_files("fun"),
        &profiles,
        "functional",
        "fun",
        &[
            observation(
                "fun",
                SemanticRegion::Declarations,
                RegionCoverage::Observed,
                "decl:a",
            ),
            observation(
                "fun",
                SemanticRegion::Declarations,
                RegionCoverage::Observed,
                "decl:b",
            ),
            observation(
                "fun",
                SemanticRegion::Implementation,
                RegionCoverage::Observed,
                "impl",
            ),
        ],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert_eq!(
        evaluation.model().artifacts()[0].profile().status(),
        ArchetypeResolution::Resolved
    );
    assert!(evaluation.findings().is_empty());
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R03-003`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R03
#[test]
fn orchestration_profile_requires_no_universal_order_or_one_x_per_file() {
    let profiles = profile(
        "script",
        "scr",
        "fixture-adapter",
        "1.0.0",
        json!([archetype(
            "orchestration_script",
            &["IMPLEMENTATION"],
            &[
                "DEPENDENCIES",
                "DECLARATIONS",
                "IMPLEMENTATION",
                "FAILURE_SEMANTICS"
            ],
            &[]
        )]),
    );
    let observations = [
        observation(
            "scr",
            SemanticRegion::Implementation,
            RegionCoverage::Observed,
            "step:3",
        ),
        observation(
            "scr",
            SemanticRegion::Dependencies,
            RegionCoverage::Observed,
            "step:1",
        ),
        observation(
            "scr",
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            "step:2",
        ),
    ];
    let first = evaluate(
        &fixture_files("scr"),
        &profiles,
        "script",
        "scr",
        &observations,
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    let reversed = observations.iter().cloned().rev().collect::<Vec<_>>();
    let second = evaluate(
        &fixture_files("scr"),
        &profiles,
        "script",
        "scr",
        &reversed,
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert_eq!(
        first.model().to_canonical_json().expect("json"),
        second.model().to_canonical_json().expect("json")
    );
}

/// `T-SOURCE-ARTIFACT-001-R01-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R03
#[test]
fn responsibility_and_verification_authorities_remain_explicit() {
    let profiles = profile(
        "nominal",
        "nom",
        "fixture-adapter",
        "1.0.0",
        json!([archetype("type", &[], &[], &[])]),
    );
    let verification = [SourceVerificationRelationship::new(
        "code/artifact.nom",
        "AF-FEATURE-0001",
        "AF-FEATURE-0001-R01",
        "T-AF-FEATURE-0001-R01-001",
    )];
    let evaluation = evaluate(
        &fixture_files("nom"),
        &profiles,
        "nominal",
        "nom",
        &[],
        &[],
        &verification,
        false,
        &["fixture-adapter"],
    );
    assert!(kinds(&evaluation).contains(&SourceFindingKind::SourceResponsibilityMissing));
    let verification_region = evaluation.model().artifacts()[0]
        .semantic_regions()
        .iter()
        .find(|region| region.region() == SemanticRegion::VerificationRelationships)
        .expect("verification region");
    assert_eq!(verification_region.coverage(), RegionCoverage::Observed);
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R04-001`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R04
#[test]
fn identical_inputs_are_byte_identical_and_profile_version_is_an_input() {
    let files = fixture_files("fun");
    let profiles_v1 = profile(
        "functional",
        "fun",
        "fixture-adapter",
        "1.0.0",
        json!([archetype("module", &[], &[], &[])]),
    );
    let profiles_v2 = profile(
        "functional",
        "fun",
        "fixture-adapter",
        "2.0.0",
        json!([archetype("module", &[], &[], &[])]),
    );
    let first = evaluate(
        &files,
        &profiles_v1,
        "functional",
        "fun",
        &[],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    let repeat = evaluate(
        &files,
        &profiles_v1,
        "functional",
        "fun",
        &[],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    let changed = evaluate(
        &files,
        &profiles_v2,
        "functional",
        "fun",
        &[],
        &[],
        &[],
        true,
        &["fixture-adapter"],
    );
    assert_eq!(
        first.model().to_canonical_json().expect("json"),
        repeat.model().to_canonical_json().expect("json")
    );
    assert_ne!(
        first.model().to_canonical_json().expect("json"),
        changed.model().to_canonical_json().expect("json")
    );
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R04-002`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R04
#[test]
fn projection_contains_stable_semantic_references_without_psm_graph_duplication() {
    let observation = [observation(
        "nom",
        SemanticRegion::Declarations,
        RegionCoverage::Observed,
        "symbol:sha256:abc",
    )];
    let evaluation = evaluate(
        &fixture_files("nom"),
        &SourceProfileRegistry::standard(),
        "nominal",
        "nom",
        &observation,
        &[],
        &[],
        true,
        &[],
    );
    let json = evaluation.model().to_canonical_json().expect("json");
    assert!(json.contains("symbol:sha256:abc"));
    assert!(json.contains("sha256:fixture-psm"));
    assert!(!json.contains("value_transfers"));
    assert!(!json.contains("call_topology"));
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R04-003`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R04
#[test]
fn live_fortress_inventory_is_complete_and_rust_profile_status_is_truthful() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let model = compile_repository_source_artifact_model(&root).expect("live model compiles");
    let expected = walk_code_files(&root);
    assert_eq!(model.artifacts().len(), expected.len());
    assert_eq!(
        model.summary().documented_responsibilities(),
        expected.len()
    );
    assert_eq!(model.summary().profile_not_registered(), expected.len());
    assert_eq!(model.summary().findings(), 0);
    assert!(
        model
            .artifacts()
            .iter()
            .filter(|artifact| {
                Path::new(artifact.path())
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            })
            .all(
                |artifact| artifact.profile().status() == ArchetypeResolution::ProfileNotRegistered
            )
    );
}

fn walk_code_files(root: &Path) -> Vec<String> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<String>) {
        for entry in std::fs::read_dir(directory).expect("read directory") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|value| value.to_str()) != Some(".git") {
                    visit(root, &path, files);
                }
            } else if path
                .parent()
                .and_then(Path::file_name)
                .and_then(|value| value.to_str())
                == Some("code")
            {
                files.push(
                    path.strip_prefix(root)
                        .expect("relative")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let mut files = Vec::new();
    visit(root, root, &mut files);
    files.sort();
    files
}

/// `T-AF-SOURCE-ARCHITECTURE-0001-R04-004`
/// Fortress requirement: AF-SOURCE-ARCHITECTURE-0001-R04
#[test]
fn ten_thousand_artifacts_remain_deterministic_and_lightweight() {
    let mut files = BTreeMap::from([
        ("README.md".into(), b"# Scale\n".to_vec()),
        ("contract.json".into(), contract("PF-SCALE", "Scale", true)),
        ("docs/code_docs.md".into(), b"# Code\n".to_vec()),
    ]);
    for index in 0..10_000 {
        files.insert(
            format!("code/artifact_{index:05}.mix"),
            format!("artifact {index}\n").into_bytes(),
        );
    }
    let ccg = fixture_ccg(&files);
    let filing = analyze_project_filing_system(
        &files.keys().cloned().collect::<Vec<_>>(),
        &FilingSystemProfiles::standard(),
    );
    let languages = [LanguageAssignment::new("mix", "mixed", "scale-adapter")];
    let compile = || {
        evaluate_source_architecture(&SourceArchitectureInput {
            project_id: "PF-SCALE",
            source_identity: "sha256:scale",
            filing: &filing,
            ccg: &ccg,
            files: &files,
            responsibilities: &[],
            profiles: &SourceProfileRegistry::standard(),
            languages: &languages,
            observations: &[],
            generated_sources: &[],
            verification_relationships: &[],
            available_adapters: &BTreeSet::new(),
            psm_digest: None,
            standard_edition: EDITION,
        })
        .expect("scale model")
    };
    let first = compile();
    let second = compile();
    assert_eq!(first.model().artifacts().len(), 10_000);
    assert_eq!(
        first.model().to_canonical_json().expect("json"),
        second.model().to_canonical_json().expect("json")
    );
    let value: Value = serde_json::from_str(&first.model().to_canonical_json().expect("json"))
        .expect("valid JSON");
    assert_eq!(value["$schema"], SOURCE_ARTIFACT_MODEL_SCHEMA);
    assert!(value.get("bodies").is_none());
}
