//! Tests of the actual private aggregation source and complete public evaluations.

use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
};
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::state_effect_analysis::{
    OperationSummaryCatalog, analyze_state_effects_with_summaries,
    analyze_state_effects_with_summaries_prepared, load_state_contracts,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::field_projection::{
    FIELD_PROJECTION_SCRATCH_BYTES, FieldProjection, field_projection_index, symbol_fields,
};

fn fixture(padding: usize) -> ProgramSemanticModel {
    let mut source = "pub struct Cell { pub value:i64,pub ready:bool } impl Cell { pub fn step(&mut self,x:i64)->i64 {self.value=x;self.ready=true;self.value+self.value} } pub fn other(x:(i64,i64))->i64{x.0} pub fn empty()->i64{0}".to_owned();
    for index in 0..padding {
        writeln!(source, " pub fn padding_{index}()->i64{{0}}").expect("fixture source");
    }
    compile_program_semantic_model(&ProgramSemanticInput::new(
        "PF-STATE-FIXTURE",
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
                ModuleTerritory::new("PF-STATE-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        Vec::new(),
        Vec::new(),
    ))
    .expect("fixture compiles")
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-007`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn complete_projection_matches_scan_and_refuses_incomplete_owner_inventory() {
    let psm = fixture(0);
    let symbols: BTreeMap<_, _> = psm.symbols().iter().map(|s| (s.id(), s)).collect();
    assert!(!psm.state_reads().is_empty() && !psm.mutations().is_empty());
    let index = field_projection_index(&psm, &symbols, FIELD_PROJECTION_SCRATCH_BYTES)
        .expect("complete inventory admitted");
    for symbol in psm.symbols() {
        let reads: BTreeSet<_> = psm
            .state_reads()
            .iter()
            .filter(|r| r.symbol() == symbol.id())
            .filter_map(|r| r.place().field_name())
            .collect();
        let writes: BTreeSet<_> = psm
            .mutations()
            .iter()
            .filter(|r| r.symbol() == symbol.id())
            .filter_map(|r| r.target().field_name())
            .collect();
        let expected: [Vec<String>; 2] = [
            reads.iter().copied().map(str::to_owned).collect(),
            writes.iter().copied().map(str::to_owned).collect(),
        ];
        assert_eq!(symbol_fields(&psm, symbol.id(), Some(&index)), expected);
        assert_eq!(symbol_fields(&psm, symbol.id(), None), expected);
        assert_eq!(
            index
                .get(symbol.id())
                .map_or_else(BTreeSet::new, |f| f[0].clone()),
            reads
        );
        assert_eq!(
            index
                .get(symbol.id())
                .map_or_else(BTreeSet::new, |f| f[1].clone()),
            writes
        );
    }
    assert!(!index.contains_key("absent-symbol"));
    assert_eq!(
        symbol_fields(&psm, "absent-symbol", Some(&index)),
        [Vec::<String>::new(), Vec::new()]
    );
    assert_eq!(
        symbol_fields(&psm, "absent-symbol", None),
        [Vec::<String>::new(), Vec::new()]
    );
    assert!(field_projection_index(&psm, &symbols, 0).is_none());
    assert!(
        field_projection_index(&psm, &BTreeMap::new(), FIELD_PROJECTION_SCRATCH_BYTES).is_none()
    );
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-008`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn exact_scratch_boundary_keeps_zero_admission_scan_available() {
    let psm = fixture(0);
    let symbols: BTreeMap<_, _> = psm.symbols().iter().map(|s| (s.id(), s)).collect();
    let charge = (psm.state_reads().len() + psm.mutations().len()) * 512
        + symbols.len() * 2048
        + std::mem::size_of::<FieldProjection<'_>>();
    assert!(field_projection_index(&psm, &symbols, charge - 1).is_none());
    assert!(field_projection_index(&psm, &symbols, charge).is_some());
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R02-009`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R02
#[test]
fn admitted_and_refused_assembly_preserve_complete_cold_models() {
    for padding in [0, 8192] {
        verify_complete_public_evaluation(&fixture(padding), padding == 0);
    }
}

fn verify_complete_public_evaluation(psm: &ProgramSemanticModel, admission_expected: bool) {
    let symbols: BTreeMap<_, _> = psm.symbols().iter().map(|s| (s.id(), s)).collect();
    assert_eq!(
        field_projection_index(psm, &symbols, FIELD_PROJECTION_SCRATCH_BYTES).is_some(),
        admission_expected,
        "the public evaluator's fixed budget admits the small case and refuses the large case"
    );
    let functions = load_function_contracts(psm, Vec::new()).expect("function contracts");
    let states = load_state_contracts(psm, Vec::new()).expect("state contracts");
    let semantic =
        analyze_program_domains(psm, &functions, "1.0.0-draft.1").expect("semantic analysis");
    let catalog = OperationSummaryCatalog::from_json_str(
        fortress_core::standard::installed_operation_summaries(),
    )
    .expect("installed catalog");
    let instantiations = BTreeMap::new();
    let cold = analyze_state_effects_with_summaries(
        psm,
        &semantic,
        &states,
        &functions,
        "1.0.0-draft.1",
        &catalog,
        &instantiations,
    )
    .expect("independent complete cold evaluation");
    let mut previous = None;
    for _ in 0..2 {
        let (prepared, preparation, _) = analyze_state_effects_with_summaries_prepared(
            psm,
            &semantic,
            &states,
            &functions,
            "1.0.0-draft.1",
            &catalog,
            &instantiations,
            previous.as_ref(),
        )
        .expect("complete prepared evaluation");
        assert_eq!(prepared, cold, "complete model, findings and provenance");
        assert_eq!(
            prepared
                .model()
                .to_canonical_json()
                .expect("prepared bytes"),
            cold.model().to_canonical_json().expect("cold bytes")
        );
        previous = Some(preparation);
    }
    for summary in cold.model().summaries() {
        let value = serde_json::to_value(summary).expect("complete summary");
        let symbol = value["symbol"].as_str().expect("symbol identity");
        let expected_reads: BTreeSet<_> = psm
            .state_reads()
            .iter()
            .filter(|read| read.symbol() == symbol)
            .filter_map(|read| read.place().field_name())
            .collect();
        let expected_writes: BTreeSet<_> = psm
            .mutations()
            .iter()
            .filter(|mutation| mutation.symbol() == symbol)
            .filter_map(|mutation| mutation.target().field_name())
            .collect();
        assert_eq!(value["field_reads"], serde_json::json!(expected_reads));
        assert_eq!(value["field_writes"], serde_json::json!(expected_writes));
    }
}
