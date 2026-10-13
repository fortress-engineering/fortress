//! Owner-local prepared domain evaluation equality and actual work controls.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{
    PreparationRetention, SemanticAnalysisPreparation, SemanticPreparationWork,
    analyze_program_domains, analyze_program_domains_prepared,
    analyze_program_domains_prepared_with_retention, load_function_contracts,
};

fn psm(source: &str) -> ProgramSemanticModel {
    compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-DOMAIN-PREPARATION",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes(
                    "sample/_data/Cargo.toml",
                    b"[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n",
                ),
                SnapshotBoundFile::from_bytes("sample/_code/lib.rs", source.as_bytes()),
            ],
            vec![
                ModuleTerritory::new("PF-DOMAIN-PREPARATION", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        Vec::new(),
        Vec::new(),
    ))
    .expect("fixture compiles")
}

fn prepared(
    model: &ProgramSemanticModel,
    previous: Option<&SemanticAnalysisPreparation>,
) -> (
    fortress_core::semantic_analysis::SemanticAnalysisEvaluation,
    SemanticAnalysisPreparation,
    fortress_core::semantic_analysis::SemanticPreparationWork,
) {
    let contracts = load_function_contracts(model, Vec::new()).expect("contracts resolve");
    let cold = analyze_program_domains(model, &contracts, "1.0.0-draft.1")
        .expect("cold evaluation succeeds");
    let uncached = cold.clone();
    let bytes = cold.model().to_canonical_json().expect("canonical bytes");
    let expected_digest = format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()));
    assert_eq!(
        cold.model().digest().expect("streamed digest"),
        expected_digest
    );
    assert_eq!(
        cold.model().digest().expect("memoized digest"),
        expected_digest
    );
    assert_eq!(cold, uncached, "memo population is not semantic state");
    assert_eq!(
        cold.model().to_canonical_json().expect("memoized bytes"),
        bytes
    );
    let result = analyze_program_domains_prepared(model, &contracts, "1.0.0-draft.1", previous)
        .expect("prepared evaluation succeeds");
    assert_eq!(
        result.0, cold,
        "prepared facts, headers, findings and iterations equal cold"
    );
    result
}

fn bounded_prepared(
    model: &ProgramSemanticModel,
    previous: Option<&SemanticAnalysisPreparation>,
    retention: PreparationRetention,
) -> (SemanticAnalysisPreparation, SemanticPreparationWork) {
    let contracts = load_function_contracts(model, Vec::new()).expect("contracts resolve");
    let cold = analyze_program_domains(model, &contracts, "1.0.0-draft.1")
        .expect("cold evaluation succeeds");
    let (evaluation, preparation, work) = analyze_program_domains_prepared_with_retention(
        model,
        &contracts,
        "1.0.0-draft.1",
        previous,
        retention,
    )
    .expect("bounded preparation still evaluates");
    assert_eq!(evaluation, cold, "bounded facts and findings equal cold");
    assert_eq!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("bounded JSON"),
        cold.model().to_canonical_json().expect("cold JSON"),
        "retention preserves exact canonical bytes"
    );
    assert!(preparation.accounted_resident_bytes() <= retention.max_accounted_bytes);
    assert!(preparation.cached_round_cardinality() <= retention.max_round_values);
    assert_eq!(work.fallback_reasons, ["domain_retention_limit"]);
    (preparation, work)
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R05-001`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R05
#[test]
fn unchanged_domains_replay_actual_prior_rounds() {
    let model = psm("pub fn one() -> u8 { 1 }\npub fn caller() -> u8 { one() }\n");
    let (_, previous, first) = prepared(&model, None);
    assert!(first.rebuilt_domain_rounds > 0);
    let (_, _, work) = prepared(&model, Some(&previous));
    assert!(work.reused_domain_rounds > 0);
    assert_eq!(work.rebuilt_domain_rounds, 0);
    assert!(work.reused_scc_rounds > 0);
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R05-002`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R05
#[test]
fn changed_provider_rebuilds_dependents_and_reuses_disconnected_domains() {
    let before = psm(
        "pub fn stable() -> u8 { 7 }\npub fn leaf() -> u8 { 1 }\npub fn caller() -> u8 { leaf() }\n",
    );
    let (_, previous, _) = prepared(&before, None);
    let after = psm(
        "pub fn stable() -> u8 { 7 }\npub fn leaf() -> u8 { 2 }\npub fn caller() -> u8 { leaf() }\n",
    );
    assert_ne!(
        before.types(),
        after.types(),
        "literal spelling changes the aggregate type record"
    );
    assert_eq!(
        before
            .types()
            .iter()
            .map(|value| (value.id(), value.semantic()))
            .collect::<Vec<_>>(),
        after
            .types()
            .iter()
            .map(|value| (value.id(), value.semantic()))
            .collect::<Vec<_>>(),
        "the domain interpreter sees the same type identities and shapes"
    );
    let (_, _, work) = prepared(&after, Some(&previous));
    assert!(work.rebuilt_domain_rounds > 0);
    assert!(work.reused_domain_rounds > 0);
    assert!(!work.full_reevaluation_required);
    let changed_shape = psm(
        "pub fn stable() -> u8 { 7 }\npub fn leaf() -> u8 { 2_u16 }\npub fn caller() -> u8 { leaf() }\n",
    );
    let (_, _, shape_work) = prepared(&changed_shape, Some(&previous));
    assert!(shape_work.full_reevaluation_required);
    assert_eq!(shape_work.reused_domain_rounds, 0);
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R05-003`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R05
#[test]
fn disconnected_rounds_extend_through_changed_global_stop_and_widening() {
    let mut before_source = "pub fn stable() -> u8 { 7 }\n".to_owned();
    let mut after_source = before_source.clone();
    for index in 0..12 {
        let next = index + 1;
        writeln!(
            before_source,
            "pub fn c{index}() -> u8 {{ let _ = c{next}(); 0 }}"
        )
        .expect("source text");
        writeln!(
            after_source,
            "pub fn c{index}() -> u8 {{ let _ = c{next}(); c{next}() }}"
        )
        .expect("source text");
    }
    before_source.push_str("pub fn c12() -> u8 { 0 }\n");
    after_source.push_str("pub fn c12() -> u8 { 0 }\n");
    let before = psm(&before_source);
    let (_, previous, _) = prepared(&before, None);
    let after = psm(&after_source);
    let (evaluation, _, work) = prepared(&after, Some(&previous));
    let model: serde_json::Value = serde_json::from_str(
        &evaluation
            .model()
            .to_canonical_json()
            .expect("model serializes"),
    )
    .expect("model JSON");
    assert!(
        model["coverage"]["fixed_point_iterations"]
            .as_u64()
            .expect("iteration count")
            > 8
    );
    assert!(work.reused_domain_rounds > 0);
    assert!(
        work.extended_domain_rounds > 0,
        "missing historical rounds execute the owner interpreter"
    );
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R05-004`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R05
#[test]
fn call_join_and_symbol_deletion_select_full_domain_reconstruction() {
    let before = psm(
        "pub fn one() -> u8 { 1 }\npub fn other() -> u8 { 2 }\npub fn caller() -> u8 { one() }\n",
    );
    let (_, previous, _) = prepared(&before, None);
    let joined = psm(
        "pub fn one() -> u8 { 1 }\npub fn other() -> u8 { 2 }\npub fn caller() -> u8 { other() }\n",
    );
    let (_, _, joined_work) = prepared(&joined, Some(&previous));
    assert!(joined_work.full_reevaluation_required);
    assert_eq!(joined_work.reused_domain_rounds, 0);
    let deleted = psm("pub fn one() -> u8 { 1 }\npub fn caller() -> u8 { one() }\n");
    let (_, _, deleted_work) = prepared(&deleted, Some(&previous));
    assert!(deleted_work.full_reevaluation_required);
    assert_eq!(deleted_work.reused_domain_rounds, 0);
}

/// `T-AF-SEMANTIC-ANALYSIS-0001-R05-005`
/// Fortress requirement: AF-SEMANTIC-ANALYSIS-0001-R05
#[test]
fn bounded_domain_retention_changes_work_without_changing_facts() {
    let model = psm("pub fn one() -> u8 { 1 }\npub fn caller() -> u8 { one() }\n");
    let (_, previous, full_work) = prepared(&model, None);
    for retention in [
        PreparationRetention {
            max_accounted_bytes: 0,
            max_round_values: 0,
        },
        PreparationRetention {
            max_accounted_bytes: 128 * 1024,
            max_round_values: 0,
        },
        PreparationRetention {
            max_accounted_bytes: 128 * 1024,
            max_round_values: 1,
        },
    ] {
        for prior in [None, Some(&previous)] {
            let (mut bounded, mut work) = bounded_prepared(&model, prior, retention);
            for replay in 0..3 {
                assert_eq!(
                    bounded.cached_round_cardinality(),
                    retention.max_round_values
                );
                assert_eq!(
                    work.reused_domain_rounds, 0,
                    "no replay after a round-zero gap"
                );
                assert_eq!(work.rebuilt_domain_rounds, full_work.rebuilt_domain_rounds);
                assert_eq!(work.reused_scc_rounds, 0);
                assert_eq!(
                    work.full_reevaluation_required,
                    retention.max_accounted_bytes == 0
                );
                if replay < 2 {
                    (bounded, work) = bounded_prepared(&model, Some(&bounded), retention);
                }
            }
        }
    }

    // A single symbol makes every executed/replayed round attributable to its
    // exact contiguous prefix, including the permanently missing final round.
    let single = psm("pub fn one() -> u8 { 1 }\n");
    let (_, full, full_work) = prepared(&single, None);
    let retention = PreparationRetention {
        max_accounted_bytes: full.accounted_resident_bytes() - 1,
        max_round_values: full.cached_round_cardinality(),
    };
    for prior in [None, Some(&full)] {
        let (mut bounded, mut work) = bounded_prepared(&single, prior, retention);
        let retained_rounds = bounded.cached_round_cardinality();
        let retained_bytes = bounded.accounted_resident_bytes();
        assert!(retained_rounds > 1 && retained_rounds < full.cached_round_cardinality());
        assert!(!work.full_reevaluation_required);
        if prior.is_none() {
            assert_eq!(work.reused_domain_rounds, 0);
            assert_eq!(work.rebuilt_domain_rounds, full_work.rebuilt_domain_rounds);
        }
        for _ in 0..2 {
            (bounded, work) = bounded_prepared(&single, Some(&bounded), retention);
            assert_eq!(bounded.cached_round_cardinality(), retained_rounds);
            assert_eq!(bounded.accounted_resident_bytes(), retained_bytes);
            assert!(!work.full_reevaluation_required);
            assert_eq!(work.reused_domain_rounds, retained_rounds - 1);
            assert_eq!(
                work.rebuilt_domain_rounds,
                full_work.rebuilt_domain_rounds - (retained_rounds - 1),
                "every round beyond the retained prefix executes, never replays"
            );
            assert!(work.rebuilt_domain_rounds > 0);
        }
    }
}
