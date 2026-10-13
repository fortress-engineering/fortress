//! Owner-local prepared direct-effect and synchronous closure equality controls.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    ContextKnowledge, ExecutionProvenance, ProgramSemanticInput, ProgramSemanticModel,
    SemanticType, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{
    FunctionEffect, analyze_program_domains, load_function_contracts,
};
use fortress_core::state_effect_analysis::{
    EffectEvidence, OperationSummaryCatalog, OperationSummaryInstantiation, PreparationRetention,
    StateEffectAnalysisError, StateEffectAnalysisEvaluation, StateEffectPreparation,
    StateEffectPreparationWork, StateEffectSummary, SummaryContext, SummaryEffectBound,
    SummaryPremise, analyze_state_effects_with_summaries,
    analyze_state_effects_with_summaries_prepared,
    analyze_state_effects_with_summaries_prepared_with_retention, load_state_contracts,
    primitive_destructor_premise,
};

fn psm(source: &str) -> ProgramSemanticModel {
    compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-EFFECT-PREPARATION",
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
                ModuleTerritory::new("PF-EFFECT-PREPARATION", ""),
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
    previous: Option<&StateEffectPreparation>,
) -> (
    fortress_core::state_effect_analysis::StateEffectAnalysisEvaluation,
    StateEffectPreparation,
    StateEffectPreparationWork,
) {
    let functions = load_function_contracts(model, Vec::new()).expect("contracts resolve");
    let states = load_state_contracts(model, Vec::new()).expect("state contracts resolve");
    let semantic =
        analyze_program_domains(model, &functions, "1.0.0-draft.1").expect("domains evaluate");
    let catalog = OperationSummaryCatalog::from_json_str(
        fortress_core::standard::installed_operation_summaries(),
    )
    .expect("installed summaries validate");
    let cold = analyze_state_effects_with_summaries(
        model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &BTreeMap::new(),
    )
    .expect("cold effects evaluate");
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
    let result = analyze_state_effects_with_summaries_prepared(
        model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &BTreeMap::new(),
        previous,
    )
    .expect("prepared effects evaluate");
    assert_eq!(
        result.0, cold,
        "prepared seeds, closure, witnesses, headers and iterations equal cold"
    );
    result
}

fn prepared_with_limits(
    model: &ProgramSemanticModel,
    previous: Option<&StateEffectPreparation>,
    retention: PreparationRetention,
) -> (
    fortress_core::state_effect_analysis::StateEffectAnalysisEvaluation,
    StateEffectPreparation,
    StateEffectPreparationWork,
) {
    let functions = load_function_contracts(model, Vec::new()).expect("contracts resolve");
    let states = load_state_contracts(model, Vec::new()).expect("state contracts resolve");
    let semantic =
        analyze_program_domains(model, &functions, "1.0.0-draft.1").expect("domains evaluate");
    let catalog = OperationSummaryCatalog::from_json_str(
        fortress_core::standard::installed_operation_summaries(),
    )
    .expect("installed summaries validate");
    analyze_state_effects_with_summaries_prepared_with_retention(
        model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &BTreeMap::new(),
        previous,
        retention,
    )
    .expect("bounded effects still evaluate")
}

fn assert_bounded_effect_equality(
    cold: &StateEffectAnalysisEvaluation,
    evaluation: &StateEffectAnalysisEvaluation,
    bounded: &StateEffectPreparation,
    work: &StateEffectPreparationWork,
    cold_work: &StateEffectPreparationWork,
    retention: PreparationRetention,
) {
    assert_eq!(evaluation, cold);
    assert_eq!(
        evaluation
            .model()
            .to_canonical_json()
            .expect("bounded bytes"),
        cold.model().to_canonical_json().expect("cold bytes")
    );
    assert!(bounded.accounted_resident_bytes() <= retention.max_accounted_bytes);
    assert!(bounded.cached_round_cardinality() <= retention.max_round_values);
    assert_eq!(work.fallback_reasons, vec!["effect_retention_limit"]);
    assert_eq!(
        work.rebuilt_closure_rounds + work.reused_closure_rounds,
        cold_work.rebuilt_closure_rounds
    );
    assert_eq!(
        work.rebuilt_edge_rounds + work.reused_edge_rounds,
        cold_work.rebuilt_edge_rounds
    );
    assert_eq!(
        work.rebuilt_scc_rounds + work.reused_scc_rounds,
        cold_work.rebuilt_scc_rounds
    );
}

fn assert_gap_rebuild(work: &StateEffectPreparationWork, reused_direct_units: usize) {
    assert_eq!(work.reused_closure_rounds, 0, "permanent gaps never replay");
    assert_eq!(work.reused_edge_rounds, 0);
    assert_eq!(work.reused_scc_rounds, 0);
    assert!(!work.full_reevaluation_required);
    assert_eq!(work.reused_direct_units, reused_direct_units);
}

fn assert_bounded_replays(
    model: &ProgramSemanticModel,
    cold: &StateEffectAnalysisEvaluation,
    initial: &StateEffectPreparation,
    cold_work: &StateEffectPreparationWork,
    retention: PreparationRetention,
) {
    let mut retained = None;
    for _ in 0..2 {
        let prior = retained.as_ref().unwrap_or(initial);
        let (evaluation, bounded, work) = prepared_with_limits(model, Some(prior), retention);
        assert_bounded_effect_equality(cold, &evaluation, &bounded, &work, cold_work, retention);
        if retention.max_round_values <= 1 {
            assert_gap_rebuild(&work, model.symbols().len());
            assert_eq!(
                (
                    bounded.accounted_resident_bytes(),
                    bounded.cached_round_cardinality()
                ),
                (
                    prior.accounted_resident_bytes(),
                    prior.cached_round_cardinality()
                )
            );
        }
        retained = Some(bounded);
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn unchanged_effect_seeds_and_rounds_are_actually_reused() {
    let model =
        psm("pub fn leaf() { let _ = std::fs::read(\"a\"); }\npub fn caller() { leaf(); }\n");
    let (_, previous, first) = prepared(&model, None);
    assert!(first.rebuilt_direct_units > 0);
    let (_, _, work) = prepared(&model, Some(&previous));
    assert!(work.reused_direct_units > 0);
    assert_eq!(work.rebuilt_direct_units, 0);
    assert!(work.reused_closure_rounds > 0);
    assert_eq!(work.rebuilt_closure_rounds, 0);
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn direct_effect_changes_rebuild_reverse_dependencies_only_with_exact_witnesses() {
    let before = psm(
        "pub fn stable() {}\npub fn leaf() { let _ = std::fs::read(\"a\"); }\npub fn caller() { leaf(); }\n",
    );
    let (_, previous, _) = prepared(&before, None);
    let after = psm(
        "pub fn stable() {}\npub fn leaf() { let _ = std::fs::read(\"b\"); }\npub fn caller() { leaf(); }\n",
    );
    assert_ne!(
        before.types(),
        after.types(),
        "literal spelling changes the aggregate type record"
    );
    let (_, _, work) = prepared(&after, Some(&previous));
    assert!(work.rebuilt_direct_units > 0);
    assert!(work.reused_direct_units > 0);
    assert!(work.reused_closure_rounds > 0);
    assert!(!work.full_reevaluation_required);
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn cycles_and_witness_budget_keep_cold_closure_bytes() {
    check_transitive_witness_ordering();
    let source = "pub fn a() { let _ = std::fs::read(\"a\"); }\npub fn b() { let _ = std::fs::read(\"b\"); }\npub fn c() { let _ = std::fs::read(\"c\"); }\npub fn d() { let _ = std::fs::read(\"d\"); }\npub fn e() { let _ = std::fs::read(\"e\"); }\npub fn left() { a(); b(); c(); d(); e(); right(); }\npub fn right() { left(); }\npub fn entry() { left(); right(); }\n";
    let model = psm(source);
    let (evaluation, previous, _) = prepared(&model, None);
    assert!(
        evaluation.model().summaries().iter().any(|summary| {
            summary
                .uncertainty()
                .iter()
                .any(|reason| reason == "analyser_limit:witness_budget_exhausted")
        }),
        "fixture reaches the retained four-witness budget"
    );
    let (_, _, work) = prepared(&model, Some(&previous));
    assert!(work.reused_scc_rounds > 0);
    assert_eq!(work.rebuilt_closure_rounds, 0);
    let original_bytes = evaluation.model().to_canonical_json().expect("prior bytes");
    let original_charge = previous.accounted_resident_bytes();
    // Changing or removing a provider inside the capped cycle must detach both
    // current evidence and uncertainty without mutating the retained trajectory
    // used by a later baseline replay. The cold comparison checks every reason,
    // changed flag and closure iteration, including repeated fan-in reasons.
    for operation in [
        "std::fs::write(\"a\", b\"value\")",
        "std::fs::read(\"changed\")",
        "()",
    ] {
        let changed = psm(&source.replacen("std::fs::read(\"a\")", operation, 1));
        let (_, _, changed_work) = prepared(&changed, Some(&previous));
        assert!(changed_work.rebuilt_direct_units > 0);
        let (restored, _, restored_work) = prepared(&model, Some(&previous));
        assert_eq!(
            restored
                .model()
                .to_canonical_json()
                .expect("restored bytes"),
            original_bytes
        );
        assert_eq!(previous.accounted_resident_bytes(), original_charge);
        assert_eq!(restored_work.rebuilt_closure_rounds, 0);
    }
}

fn check_transitive_witness_ordering() {
    let source = "pub fn leaf() { let _ = std::fs::read(\"a\"); }\n\
        pub fn a() { leaf(); }\n\
        pub fn z() { leaf(); }\n\
        pub fn long() { z(); }\n\
        pub fn bridge() { long(); a(); }\n\
        pub fn entry() { bridge(); a(); z(); leaf(); }\n\
        #[cfg(test)] pub fn test_entry() { entry(); }\n\
        #[cfg(opaque())] pub fn unknown_entry() { entry(); }\n";
    for calls in ["long(); a();", "a(); long();", "a(); z(); long(); a();"] {
        let model = psm(&source.replace("long(); a();", calls));
        let (cold, previous, _) = prepared(&model, None);
        let (replayed, _, _) = prepared(&model, Some(&previous));
        assert_eq!(replayed, cold);
        let provenances = cold
            .model()
            .summaries()
            .iter()
            .flat_map(StateEffectSummary::effect_evidence)
            .map(EffectEvidence::entry_execution_provenance)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(provenances.contains(&ExecutionProvenance::ProductionCapable));
        assert!(provenances.contains(&ExecutionProvenance::TestOnly));
        assert!(provenances.contains(&ExecutionProvenance::Unknown));
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-005`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn bounded_effect_retention_changes_work_without_changing_facts() {
    let model =
        psm("pub fn leaf() { let _ = std::fs::read(\"a\"); }\npub fn caller() { leaf(); }\n");
    let (cold, previous, cold_work) = prepared(&model, None);
    assert!(cold_work.rebuilt_closure_rounds > model.symbols().len());
    let (evaluation, preparation, work) = prepared_with_limits(
        &model,
        Some(&previous),
        PreparationRetention {
            max_accounted_bytes: 0,
            max_round_values: 0,
        },
    );
    assert_eq!(evaluation, cold);
    assert_eq!(preparation.accounted_resident_bytes(), 0);
    assert_eq!(preparation.cached_round_cardinality(), 0);
    assert_eq!(work.fallback_reasons, vec!["effect_retention_limit"]);
    assert!(work.full_reevaluation_required);
    let partial_bytes = previous.accounted_resident_bytes() / 2;
    assert!(partial_bytes > 0 && partial_bytes < previous.accounted_resident_bytes());
    for retention in [
        PreparationRetention {
            max_accounted_bytes: 128 * 1024,
            max_round_values: 0,
        },
        PreparationRetention {
            max_accounted_bytes: 128 * 1024,
            max_round_values: 1,
        },
        PreparationRetention {
            max_accounted_bytes: partial_bytes,
            max_round_values: usize::MAX,
        },
    ] {
        let mut retained = Vec::new();
        for prior in [None, Some(&previous)] {
            let (evaluation, bounded, work) = prepared_with_limits(&model, prior, retention);
            assert_bounded_effect_equality(
                &cold,
                &evaluation,
                &bounded,
                &work,
                &cold_work,
                retention,
            );
            if retention.max_round_values <= 1 {
                assert_eq!(
                    bounded.cached_round_cardinality(),
                    retention.max_round_values
                );
                assert_gap_rebuild(
                    &work,
                    if prior.is_some() {
                        model.symbols().len()
                    } else {
                        0
                    },
                );
            } else {
                assert!(bounded.cached_round_cardinality() < previous.cached_round_cardinality());
            }
            retained.push((
                bounded.accounted_resident_bytes(),
                bounded.cached_round_cardinality(),
            ));
            assert_bounded_replays(&model, &cold, &bounded, &cold_work, retention);
        }
        if retention.max_round_values <= 1 {
            assert_eq!(
                retained[0], retained[1],
                "round caps preserve exact retained accounting"
            );
        }
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn unrelated_catalog_change_rebinds_current_authority_with_seed_reuse() {
    let model =
        psm("pub fn leaf() { let _ = std::fs::read(\"a\"); }\npub fn caller() { leaf(); }\n");
    let (_, previous, _) = prepared(&model, None);
    let functions = load_function_contracts(&model, Vec::new()).expect("contracts resolve");
    let states = load_state_contracts(&model, Vec::new()).expect("states resolve");
    let semantic =
        analyze_program_domains(&model, &functions, "1.0.0-draft.1").expect("domains evaluate");
    let source = fortress_core::standard::installed_operation_summaries();
    let installed =
        OperationSummaryCatalog::from_json_str(source).expect("installed summaries validate");
    let mut document: serde_json::Value = serde_json::from_str(source).expect("catalog JSON");
    let mut extra = document["summaries"][0].clone();
    extra["id"] = serde_json::json!("fixture_unrelated_assumption");
    extra["operation_selector"] = serde_json::json!("external::unrelated");
    extra["observed_effects"] = serde_json::json!([]);
    extra["authority_class"] = serde_json::json!("ASSUMED");
    document["summaries"] = serde_json::json!([extra]);
    let catalog = installed
        .with_assumed_catalog(&document.to_string())
        .expect("unrelated assumption validates");
    let cold = analyze_state_effects_with_summaries(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &BTreeMap::new(),
    )
    .expect("cold effects evaluate");
    let (evaluation, _, work) = analyze_state_effects_with_summaries_prepared(
        &model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &BTreeMap::new(),
        Some(&previous),
    )
    .expect("prepared effects evaluate");
    assert_eq!(evaluation, cold);
    assert_eq!(
        evaluation.model().operation_summary_catalog_digest(),
        catalog.digest()
    );
    assert!(work.reused_direct_units > 0);
    assert_eq!(work.rebuilt_direct_units, 0);
}

fn evaluate_primitive(
    model: &ProgramSemanticModel,
    previous: Option<&StateEffectPreparation>,
    supplied: Option<SummaryPremise>,
) -> Result<
    (
        fortress_core::state_effect_analysis::StateEffectAnalysisEvaluation,
        StateEffectPreparation,
        StateEffectPreparationWork,
    ),
    StateEffectAnalysisError,
> {
    let functions = load_function_contracts(model, Vec::new()).expect("functions resolve");
    let states = load_state_contracts(model, Vec::new()).expect("states resolve");
    let semantic =
        analyze_program_domains(model, &functions, "1.0.0-draft.1").expect("domains evaluate");
    let catalog = OperationSummaryCatalog::from_json_str(
        fortress_core::standard::installed_operation_summaries(),
    )
    .expect("installed summaries validate");
    let unit = model
        .types()
        .iter()
        .find(|value| matches!(value.semantic(), SemanticType::Unit))
        .expect("unit type");
    let premise = primitive_destructor_premise(model, unit.id());
    assert!(
        premise
            .refs
            .iter()
            .any(|reference| reference.contains(&model.digest().expect("PSM digest")))
    );
    let premise = supplied.unwrap_or(premise);
    let site = model
        .calls()
        .iter()
        .find(|call| call.external_target() == Some("std::mem::drop"))
        .expect("Drop site")
        .evidence()[0]
        .operation_site_id();
    let bindings = BTreeMap::from([(
        site.to_owned(),
        OperationSummaryInstantiation {
            context: SummaryContext {
                source_digest: ContextKnowledge::Unknown,
                version: ContextKnowledge::Unknown,
                target: ContextKnowledge::Unknown,
                features: ContextKnowledge::Unknown,
                type_bindings: ContextKnowledge::Unknown,
            },
            context_observation_refs: vec!["context-observation:fixture".into()],
            premises: BTreeMap::from([("drop:T".into(), premise)]),
            acceptance: None,
        },
    )]);
    let cold = analyze_state_effects_with_summaries(
        model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &bindings,
    );
    let result = analyze_state_effects_with_summaries_prepared(
        model,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &bindings,
        previous,
    );
    match (&cold, &result) {
        (Ok(cold), Ok((prepared, _, _))) => assert_eq!(prepared, cold),
        (Err(cold), Err(prepared)) => {
            assert!(matches!(
                cold,
                StateEffectAnalysisError::InvalidSummaryContext(_)
            ));
            assert!(matches!(
                prepared,
                StateEffectAnalysisError::InvalidSummaryContext(_)
            ));
            assert_eq!(cold.to_string(), prepared.to_string());
        }
        _ => panic!("cold and prepared primitive authority validation diverged"),
    }
    result
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-007`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn whole_psm_bound_premises_refresh_outside_changed_components() {
    let before = psm(
        "pub fn stable() {}\npub fn drop_unit(value: ()) { std::mem::drop(value); }\npub fn changed() -> u8 { 1 }\n",
    );
    let (_, previous, _) =
        evaluate_primitive(&before, None, None).expect("initial effects evaluate");
    let after = psm(
        "pub fn stable() {}\npub fn drop_unit(value: ()) { std::mem::drop(value); }\npub fn changed() -> u8 { 2 }\n",
    );
    assert_ne!(
        before.types(),
        after.types(),
        "literal spelling changes independently of the Unit premise"
    );
    let (_, _, work) =
        evaluate_primitive(&after, Some(&previous), None).expect("current effects evaluate");
    assert!(work.reused_direct_units > 0);
    assert!(
        work.rebuilt_direct_units >= 2,
        "changed body and current whole-PSM premise rebuild independently"
    );
    let unit = after
        .types()
        .iter()
        .find(|value| matches!(value.semantic(), SemanticType::Unit))
        .expect("syntactic unit type");
    let old_unit = before
        .types()
        .iter()
        .find(|value| matches!(value.semantic(), SemanticType::Unit))
        .expect("prior syntactic unit type");
    let current = primitive_destructor_premise(&after, unit.id());
    let nonunit_id = after
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::changed"))
        .expect("integer-returning symbol")
        .return_type()
        .type_id();
    assert_ne!(nonunit_id, unit.id());
    let identity = |type_id: &str| {
        format!(
            "psm_primitive_drop:v1:{}:{type_id}",
            after.digest().expect("PSM digest")
        )
    };
    for invalid in [
        primitive_destructor_premise(&before, old_unit.id()),
        SummaryPremise {
            bound: SummaryEffectBound::Known(Vec::new()),
            refs: vec![identity(nonunit_id)],
        },
        SummaryPremise {
            bound: SummaryEffectBound::Known(Vec::new()),
            refs: vec![identity("type:missing")],
        },
        SummaryPremise {
            bound: SummaryEffectBound::Known(Vec::new()),
            refs: vec![current.refs[0].replacen(":v1:", ":v2:", 1)],
        },
        SummaryPremise {
            bound: SummaryEffectBound::Unknown,
            refs: current.refs.clone(),
        },
        SummaryPremise {
            bound: SummaryEffectBound::Known(vec![FunctionEffect::FilesystemRead]),
            refs: current.refs.clone(),
        },
    ] {
        assert!(matches!(
            evaluate_primitive(&after, Some(&previous), Some(invalid)),
            Err(StateEffectAnalysisError::InvalidSummaryContext(_))
        ));
    }
    evaluate_primitive(
        &after,
        Some(&previous),
        Some(SummaryPremise {
            bound: SummaryEffectBound::Known(vec![FunctionEffect::FilesystemRead]),
            refs: vec!["external-premise:reviewed-context".into()],
        }),
    )
    .expect("caller-established nonreserved authority remains accepted");
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R07-004`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R07
#[test]
fn changed_call_join_and_deleted_symbols_use_full_effect_reconstruction() {
    let before = psm("pub fn one() {}\npub fn other() {}\npub fn entry() { one(); }\n");
    let (_, previous, _) = prepared(&before, None);
    let joined = psm("pub fn one() {}\npub fn other() {}\npub fn entry() { other(); }\n");
    let (_, _, work) = prepared(&joined, Some(&previous));
    assert!(work.full_reevaluation_required);
    assert_eq!(work.reused_closure_rounds, 0);
    let deleted = psm("pub fn one() {}\npub fn entry() { one(); }\n");
    let (_, _, work) = prepared(&deleted, Some(&previous));
    assert!(work.full_reevaluation_required);
    assert_eq!(work.reused_direct_units, 0);
}
