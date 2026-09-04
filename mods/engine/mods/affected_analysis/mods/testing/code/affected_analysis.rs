//! Affected Analysis conformance and scale tests.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fortress_core::affected_analysis::{
    AffectedInput, AffectedSnapshot, AffectedUnit, AffectedUnitKind, IncrementalCacheState,
    IncrementalProjectionCache, InputChangeKind, ProjectionCacheKey, ProjectionDependency,
    ProjectionKind, analyze_affected, sha256,
};
use fortress_core::audit::prepare_repository_projection_cache;

fn digest(value: &str) -> String {
    sha256(value.as_bytes())
}

fn input(path: &str, value: &str) -> AffectedInput {
    AffectedInput::new(
        path,
        digest(value),
        u64::try_from(value.len()).expect("fixture length fits u64"),
    )
    .expect("valid input")
}

fn unit(id: &str, kind: AffectedUnitKind, value: &str, dependencies: &[&str]) -> AffectedUnit {
    AffectedUnit::new(id, kind, digest(value), dependencies.iter().copied()).expect("valid unit")
}

fn snapshot(
    marker: &str,
    inputs: Vec<AffectedInput>,
    units: Vec<AffectedUnit>,
) -> AffectedSnapshot {
    AffectedSnapshot::new(digest(marker), inputs, units).expect("valid snapshot")
}

fn temporary_root(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fortress-affected-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn has_affected(analysis: &fortress_core::affected_analysis::AffectedAnalysis, id: &str) -> bool {
    analysis.affected().iter().any(|unit| unit.id() == id)
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R01-001`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R01
#[test]
fn independent_module_change_preserves_unrelated_reuse() {
    let previous = snapshot(
        "before",
        vec![input("a/code/a.rs", "a0"), input("b/code/b.rs", "b0")],
        vec![
            unit("authority:a", AffectedUnitKind::AuthorityInput, "a0", &[]),
            unit("authority:b", AffectedUnitKind::AuthorityInput, "b0", &[]),
            unit(
                "source:a",
                AffectedUnitKind::SourceArtifact,
                "a",
                &["authority:a"],
            ),
            unit(
                "source:b",
                AffectedUnitKind::SourceArtifact,
                "b",
                &["authority:b"],
            ),
            unit("module:A", AffectedUnitKind::Module, "A", &["source:a"]),
            unit("module:B", AffectedUnitKind::Module, "B", &["source:b"]),
        ],
    );
    let current = snapshot(
        "after",
        vec![input("a/code/a.rs", "a1"), input("b/code/b.rs", "b0")],
        vec![
            unit("authority:a", AffectedUnitKind::AuthorityInput, "a1", &[]),
            unit("authority:b", AffectedUnitKind::AuthorityInput, "b0", &[]),
            unit(
                "source:a",
                AffectedUnitKind::SourceArtifact,
                "a",
                &["authority:a"],
            ),
            unit(
                "source:b",
                AffectedUnitKind::SourceArtifact,
                "b",
                &["authority:b"],
            ),
            unit("module:A", AffectedUnitKind::Module, "A", &["source:a"]),
            unit("module:B", AffectedUnitKind::Module, "B", &["source:b"]),
        ],
    );
    let analysis = analyze_affected(&previous, &current);
    assert_eq!(
        analysis.input_changes()[0].kind(),
        InputChangeKind::Modified
    );
    assert!(has_affected(&analysis, "module:A"));
    assert!(!has_affected(&analysis, "module:B"));
    assert!(analysis.reusable().iter().any(|id| id == "module:B"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R01-002`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R01
#[test]
fn unique_content_relocation_is_classified_without_machine_root() {
    let previous = snapshot(
        "before",
        vec![input("code/old.rs", "same")],
        vec![unit(
            "authority:source",
            AffectedUnitKind::AuthorityInput,
            "same",
            &[],
        )],
    );
    let current = snapshot(
        "after",
        vec![input("code/new.rs", "same")],
        vec![unit(
            "authority:source",
            AffectedUnitKind::AuthorityInput,
            "same",
            &[],
        )],
    );
    let first = analyze_affected(&previous, &current);
    let second = analyze_affected(&previous, &current);
    assert_eq!(first, second);
    assert_eq!(first.input_changes()[0].kind(), InputChangeKind::Relocated);
    assert!(!first.to_canonical_json().expect("JSON").contains("C:\\"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R01-003`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R01
#[test]
fn standard_change_invalidates_dependent_obligations_conservatively() {
    let make = |standard: &str| {
        snapshot(
            standard,
            vec![input("standard/rule.json", standard)],
            vec![
                unit(
                    "authority:standard",
                    AffectedUnitKind::AuthorityInput,
                    standard,
                    &[],
                ),
                unit(
                    "claim:A",
                    AffectedUnitKind::ConformanceClaim,
                    "claim",
                    &["authority:standard"],
                ),
                unit(
                    "evidence:A",
                    AffectedUnitKind::Evidence,
                    "evidence",
                    &["claim:A"],
                ),
                unit(
                    "cert:A",
                    AffectedUnitKind::CertificationObligation,
                    "cert",
                    &["evidence:A"],
                ),
            ],
        )
    };
    let analysis = analyze_affected(&make("v1"), &make("v2"));
    assert!(has_affected(&analysis, "claim:A"));
    assert!(has_affected(&analysis, "cert:A"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R02-001`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R02
#[test]
fn transitive_effect_change_invalidates_callers_not_independent_module() {
    let make = |operation: &str| {
        snapshot(
            operation,
            vec![input("b/code/io.rs", operation)],
            vec![
                unit(
                    "authority:b",
                    AffectedUnitKind::AuthorityInput,
                    operation,
                    &[],
                ),
                unit(
                    "effect:B",
                    AffectedUnitKind::Effect,
                    operation,
                    &["authority:b"],
                ),
                unit(
                    "call:A-B",
                    AffectedUnitKind::CallRelationship,
                    "A-B",
                    &["effect:B"],
                ),
                unit("effect:A", AffectedUnitKind::Effect, "A", &["call:A-B"]),
                unit(
                    "claim:A",
                    AffectedUnitKind::ConformanceClaim,
                    "A-policy",
                    &["effect:A"],
                ),
                unit(
                    "claim:B",
                    AffectedUnitKind::ConformanceClaim,
                    "B-policy",
                    &["effect:B"],
                ),
                unit("effect:C", AffectedUnitKind::Effect, "C", &[]),
                unit(
                    "claim:C",
                    AffectedUnitKind::ConformanceClaim,
                    "C-policy",
                    &["effect:C"],
                ),
            ],
        )
    };
    let analysis = analyze_affected(&make("filesystem.write"), &make("filesystem.read"));
    assert!(has_affected(&analysis, "effect:B"));
    assert!(has_affected(&analysis, "effect:A"));
    assert!(has_affected(&analysis, "claim:A"));
    assert!(!has_affected(&analysis, "claim:C"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R02-002`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R02
#[test]
fn contract_binding_and_function_authority_have_narrow_dependencies() {
    let make = |policy: &str, binding: &str, function: &str| {
        snapshot(
            &format!("{policy}-{binding}-{function}"),
            vec![
                input("mods/a/contract.json", policy),
                input("data/project.json", binding),
                input("mods/a/data/function_contracts.json", function),
            ],
            vec![
                unit(
                    "authority:policy",
                    AffectedUnitKind::AuthorityInput,
                    policy,
                    &[],
                ),
                unit(
                    "authority:binding",
                    AffectedUnitKind::AuthorityInput,
                    binding,
                    &[],
                ),
                unit(
                    "authority:function",
                    AffectedUnitKind::AuthorityInput,
                    function,
                    &[],
                ),
                unit(
                    "source:a",
                    AffectedUnitKind::SourceArtifact,
                    binding,
                    &["authority:binding"],
                ),
                unit(
                    "projection:psm",
                    AffectedUnitKind::Projection,
                    "psm",
                    &["source:a"],
                ),
                unit(
                    "projection:semantic",
                    AffectedUnitKind::Projection,
                    function,
                    &["projection:psm", "authority:function"],
                ),
                unit(
                    "claim:A",
                    AffectedUnitKind::ConformanceClaim,
                    policy,
                    &["projection:semantic", "authority:policy"],
                ),
            ],
        )
    };
    let policy = analyze_affected(&make("allow", "A", "f0"), &make("deny", "A", "f0"));
    assert!(!has_affected(&policy, "projection:psm"));
    assert!(has_affected(&policy, "claim:A"));
    let binding = analyze_affected(&make("allow", "A", "f0"), &make("allow", "B", "f0"));
    assert!(has_affected(&binding, "source:a"));
    assert!(has_affected(&binding, "projection:psm"));
    let function = analyze_affected(&make("allow", "A", "f0"), &make("allow", "A", "f1"));
    assert!(!has_affected(&function, "projection:psm"));
    assert!(has_affected(&function, "projection:semantic"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R02-003`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R02
#[test]
fn finding_governance_updates_enforcement_without_raw_semantic_recomputation() {
    let make = |governance: &str| {
        snapshot(
            governance,
            vec![input("data/finding_governance.json", governance)],
            vec![
                unit(
                    "authority:governance",
                    AffectedUnitKind::AuthorityInput,
                    governance,
                    &[],
                ),
                unit(
                    "claim:A",
                    AffectedUnitKind::ConformanceClaim,
                    "raw-fail",
                    &[],
                ),
                unit(
                    "finding:A",
                    AffectedUnitKind::Finding,
                    "raw-finding",
                    &["claim:A"],
                ),
                unit(
                    "evidence:enforcement",
                    AffectedUnitKind::Evidence,
                    governance,
                    &["finding:A", "authority:governance"],
                ),
            ],
        )
    };
    let analysis = analyze_affected(&make("active"), &make("retired"));
    assert!(!has_affected(&analysis, "claim:A"));
    assert!(!has_affected(&analysis, "finding:A"));
    assert!(has_affected(&analysis, "evidence:enforcement"));
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R03-001`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R03
#[test]
fn cache_accepts_only_exact_dependency_bound_bytes() {
    let root = temporary_root("cache-current");
    let cache = IncrementalProjectionCache::new(&root, "PF-TEST").expect("cache");
    let key = ProjectionCacheKey::new(
        ProjectionKind::Psm,
        "test-generator",
        "1.0.0",
        vec![ProjectionDependency::new("source:a", digest("a")).expect("dependency")],
    )
    .expect("key");
    cache.store(&key, b"{\"model\":1}\n", 1).expect("store");
    let loaded = cache.load(&key).expect("load");
    assert_eq!(loaded.state(), IncrementalCacheState::ReusableCurrent);
    assert_eq!(loaded.content(), Some(b"{\"model\":1}\n".as_slice()));
    assert_eq!(loaded.exit_code(), Some(1));
    fs::remove_dir_all(&root).expect("remove isolated cache");
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R03-002`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R03
#[test]
fn cache_reports_missing_stale_and_invalid_without_supplying_bytes() {
    let root = temporary_root("cache-states");
    let cache = IncrementalProjectionCache::new(&root, "PF-TEST").expect("cache");
    let key = |value: &str| {
        ProjectionCacheKey::new(
            ProjectionKind::StateEffect,
            "test-generator",
            "1.0.0",
            vec![ProjectionDependency::new("psm", digest(value)).expect("dependency")],
        )
        .expect("key")
    };
    let first = key("first");
    assert_eq!(
        cache.load(&first).expect("missing").state(),
        IncrementalCacheState::Missing
    );
    cache.store(&first, b"first\n", 0).expect("store");
    let second = key("second");
    assert_eq!(
        cache.load(&second).expect("stale").state(),
        IncrementalCacheState::Stale
    );
    let artifact = root
        .join("PF-TEST")
        .join("incremental-v1")
        .join("state-effect")
        .join(first.digest().trim_start_matches("sha256:"))
        .join("artifact.json");
    fs::write(artifact, b"corrupt").expect("corrupt isolated cache");
    let invalid = cache.load(&first).expect("invalid");
    assert_eq!(invalid.state(), IncrementalCacheState::Invalid);
    assert!(invalid.content().is_none());
    fs::remove_dir_all(&root).expect("remove isolated cache");
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R03-003`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R03
#[test]
fn deleting_cache_changes_runtime_state_not_canonical_output() {
    let root = temporary_root("cache-delete");
    let key = ProjectionCacheKey::new(
        ProjectionKind::SourceArtifacts,
        "test-generator",
        "1.0.0",
        vec![ProjectionDependency::new("source:a", digest("a")).expect("dependency")],
    )
    .expect("key");
    let bytes = b"{\"artifact\":\"stable\"}\n";
    let cache = IncrementalProjectionCache::new(&root, "PF-TEST").expect("cache");
    cache.store(&key, bytes, 0).expect("store");
    assert_eq!(
        cache.load(&key).expect("warm").content(),
        Some(bytes.as_slice())
    );
    fs::remove_dir_all(&root).expect("delete isolated cache");
    let cold = IncrementalProjectionCache::new(&root, "PF-TEST").expect("cache");
    assert_eq!(
        cold.load(&key).expect("cold").state(),
        IncrementalCacheState::Missing
    );
    cold.store(&key, bytes, 0).expect("recompute store");
    assert_eq!(
        cold.load(&key).expect("rebuilt").content(),
        Some(bytes.as_slice())
    );
    fs::remove_dir_all(&root).expect("remove isolated cache");
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R03-004`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R03
#[test]
fn repository_projection_keys_bind_only_semantically_relevant_authority() {
    let root = temporary_root("repository-keys");
    fs::create_dir_all(root.join("data/logical_modules/worker")).expect("fixture directories");
    fs::create_dir_all(root.join("src")).expect("source directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='affected-fixture'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    )
    .expect("Cargo authority");
    fs::write(
        root.join("contract.json"),
        r#"{
  "$schema": "urn:fortress:schema:v2:module-contract",
  "schema_version": 2,
  "id": "PF-AFFECTED-FIXTURE",
  "display_name": "Affected Fixture",
  "ecosystem": {
    "repository_grammar": 1,
    "standard": { "id": "STD-FORTRESS-ENGINEERING", "edition": "1.0.0-draft.1" }
  },
  "provides": [], "requires": [], "relationships": [], "constraints": [],
  "guarantees": [], "features": [], "behavior": []
}
"#,
    )
    .expect("root contract");
    fs::write(
        root.join("data/project.json"),
        r#"{
  "$schema": "urn:fortress:schema:v3:project-configuration",
  "schema_version": 3,
  "observation_exclusions": [".git"],
  "logical_modules": [{
    "module": "AF-WORKER-0001",
    "contract": "data/logical_modules/worker/contract.json",
    "parent": "PF-AFFECTED-FIXTURE",
    "bindings": [{ "kind": "directory", "path": "src" }]
  }]
}
"#,
    )
    .expect("project configuration");
    fs::write(root.join("src/lib.rs"), "pub fn execute() {}\n").expect("source");
    let contract = |denied: &str| {
        format!(
            r#"{{
  "$schema": "urn:fortress:schema:v3:module-contract",
  "schema_version": 3,
  "id": "AF-WORKER-0001",
  "display_name": "Worker",
  "provides": [], "requires": [], "relationships": [], "constraints": [],
  "guarantees": [], "features": [], "behavior": [],
  "semantic_policy": {{
    "default": "UNDECLARED",
    "capabilities": {{ "allow": [], "deny": [] }},
    "effects": {{ "allow": [], "deny": [{denied}] }}
  }}
}}
"#
        )
    };
    let contract_path = root.join("data/logical_modules/worker/contract.json");
    fs::write(&contract_path, contract("\"filesystem.write\"")).expect("first policy");
    let psm_before = prepare_repository_projection_cache(&root, ProjectionKind::Psm)
        .expect("PSM key")
        .key()
        .digest()
        .to_owned();
    let conformance_before =
        prepare_repository_projection_cache(&root, ProjectionKind::SemanticConformance)
            .expect("conformance key")
            .key()
            .digest()
            .to_owned();

    fs::write(&contract_path, contract("\"filesystem.read\"")).expect("changed policy");
    let psm_after = prepare_repository_projection_cache(&root, ProjectionKind::Psm)
        .expect("PSM key")
        .key()
        .digest()
        .to_owned();
    let conformance_after =
        prepare_repository_projection_cache(&root, ProjectionKind::SemanticConformance)
            .expect("conformance key")
            .key()
            .digest()
            .to_owned();
    assert_eq!(psm_before, psm_after);
    assert_ne!(conformance_before, conformance_after);
    fs::remove_dir_all(&root).expect("remove isolated repository");
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R04-001`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R04
#[test]
fn canonical_output_is_stable_across_input_order() {
    let left = snapshot(
        "same",
        vec![input("b.rs", "b"), input("a.rs", "a")],
        vec![
            unit("source:b", AffectedUnitKind::SourceArtifact, "b", &[]),
            unit("source:a", AffectedUnitKind::SourceArtifact, "a", &[]),
        ],
    );
    let right = snapshot(
        "same",
        vec![input("a.rs", "a"), input("b.rs", "b")],
        vec![
            unit("source:a", AffectedUnitKind::SourceArtifact, "a", &[]),
            unit("source:b", AffectedUnitKind::SourceArtifact, "b", &[]),
        ],
    );
    assert_eq!(
        left.to_canonical_json().expect("left"),
        right.to_canonical_json().expect("right")
    );
    assert_eq!(
        analyze_affected(&left, &right)
            .to_canonical_json()
            .expect("first"),
        analyze_affected(&left, &right)
            .to_canonical_json()
            .expect("second")
    );
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R04-002`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R04
#[test]
fn ten_thousand_node_closure_is_deterministic_and_indexed() {
    const COUNT: usize = 10_000;
    let make = |changed: bool| {
        let mut units = Vec::with_capacity(COUNT);
        for index in 0..COUNT {
            let id = format!("symbol:{index:05}");
            let value = if changed && index == 0 {
                "changed"
            } else {
                "same"
            };
            let dependencies = if index == 0 {
                Vec::new()
            } else if index < COUNT / 2 {
                vec![format!("symbol:{:05}", index - 1)]
            } else {
                Vec::new()
            };
            units.push(
                AffectedUnit::new(id, AffectedUnitKind::Symbol, digest(value), dependencies)
                    .expect("stress unit"),
            );
        }
        snapshot(if changed { "after" } else { "before" }, Vec::new(), units)
    };
    let previous = make(false);
    let current = make(true);
    let started = Instant::now();
    let first = analyze_affected(&previous, &current);
    let elapsed = started.elapsed();
    let second = analyze_affected(&previous, &current);
    assert_eq!(first, second);
    assert_eq!(first.summary().affected_units(), COUNT / 2);
    assert_eq!(first.summary().reusable_units(), COUNT / 2);
    assert!(
        elapsed < Duration::from_secs(10),
        "stress closure took {elapsed:?}"
    );
}
