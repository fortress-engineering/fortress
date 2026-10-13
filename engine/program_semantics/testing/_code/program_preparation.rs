//! Owner-local conformance for reusable immutable program preparation.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    CallResolutionState, CallSiteEvidence, ProgramCall, ProgramDependencyKind,
    ProgramDependencyResult, ProgramSemanticInput, ProgramSemanticModel,
    compile_program_semantic_model, prepare_program_semantics,
};

const MANIFEST: &str =
    "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n";

fn input(files: &[(&str, &str)], owner: &str) -> ProgramSemanticInput {
    ProgramSemanticInput::new(
        "PF-PREPARATION-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            files
                .iter()
                .map(|(path, source)| SnapshotBoundFile::from_bytes(*path, source.as_bytes()))
                .collect(),
            vec![
                ModuleTerritory::new("PF-PREPARATION-FIXTURE", ""),
                ModuleTerritory::new(owner, "sample"),
            ],
        ),
        [],
        [],
    )
}

fn one_file(source: &str) -> ProgramSemanticInput {
    input(
        &[
            ("sample/_data/Cargo.toml", MANIFEST),
            ("sample/_code/lib.rs", source),
        ],
        "AF-SAMPLE-0001",
    )
}

fn two_files(worker: &str) -> ProgramSemanticInput {
    input(
        &[
            ("sample/_data/Cargo.toml", MANIFEST),
            ("sample/_code/lib.rs", "mod worker; fn stable() {}"),
            ("sample/_code/worker.rs", worker),
        ],
        "AF-SAMPLE-0001",
    )
}

fn assert_clean(input: &ProgramSemanticInput, model: &ProgramSemanticModel) {
    let cold = compile_program_semantic_model(input).expect("cold input compiles");
    let uncached = cold.clone();
    let bytes = cold.to_canonical_json().expect("cold bytes");
    let document: serde_json::Value = serde_json::from_str(&bytes).expect("canonical model");
    assert_eq!(
        serde_json::to_value(cold.semantic_inputs()).expect("typed inputs"),
        document["provenance"]["semantic_inputs"]
    );
    let expected_digest = format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()));
    assert_eq!(cold.digest().expect("streamed digest"), expected_digest);
    assert_eq!(cold.digest().expect("memoized digest"), expected_digest);
    assert_eq!(cold, uncached, "memo population is not semantic state");
    assert_eq!(cold.to_canonical_json().expect("memoized bytes"), bytes);
    assert_eq!(
        model
            .to_canonical_json()
            .expect("prepared model serializes"),
        cold.to_canonical_json().expect("cold model serializes")
    );
    assert_eq!(model.digest().unwrap(), cold.digest().unwrap());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn exact_preparation_reuses_owned_units_and_preserves_canonical_model() {
    fn finished_is_send_sync<T: Send + Sync>() {}
    finished_is_send_sync::<ProgramSemanticModel>();
    let source = two_files("fn first() {} fn second() { first(); }");
    let first = prepare_program_semantics(&source, None).expect("initial preparation compiles");
    let readers = std::thread::scope(|scope| {
        let handles = (0..4)
            .map(|_| scope.spawn(|| first.model.digest().expect("reader digest")))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("reader joins"))
            .collect::<Vec<_>>()
    });
    assert!(readers.iter().all(|digest| digest == &readers[0]));
    assert_clean(&source, &first.model);
    assert_eq!(first.preparation.retained_parse_files(), 2);
    assert_eq!(first.preparation.retained_bodies(), 3);
    assert!(first.preparation.retained_components() > 0);
    assert!(first.preparation.accounted_resident_bytes() > 0);
    let replay = prepare_program_semantics(&source, Some(&first.preparation))
        .expect("exact preparation compiles");
    assert_clean(&source, &replay.model);
    assert_eq!(replay.work.parsed_files, 0);
    assert_eq!(replay.work.reused_parse_files, 2);
    assert_eq!(replay.work.analyzed_bodies, 0);
    assert_eq!(replay.work.reused_bodies, 3);
    assert_eq!(replay.work.type_fixed_point_rounds, 0);
    assert_eq!(replay.work.recomputed_components, 0);
    assert!(replay.work.reused_components > 0);
    assert_eq!(replay.dependencies, first.dependencies);
    assert!(replay.fallback.is_none());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn changed_file_reanalyzes_all_its_bodies_and_rebinds_shifted_spans() {
    let first = prepare_program_semantics(
        &two_files("fn first() { let value = 1; }\nfn second() { first(); }"),
        None,
    )
    .expect("first preparation compiles");
    let changed = two_files("fn first() {\n let value = 2;\n}\nfn second() { first(); }");
    let next = prepare_program_semantics(&changed, Some(&first.preparation))
        .expect("body-only preparation compiles");
    assert_clean(&changed, &next.model);
    assert!(next.fallback.is_none());
    assert_eq!(next.work.parsed_files, 1);
    assert_eq!(next.work.reused_parse_files, 1);
    assert_eq!(next.work.analyzed_bodies, 2);
    assert_eq!(next.work.reused_bodies, 1);
    let before = first
        .model
        .calls()
        .iter()
        .flat_map(ProgramCall::evidence)
        .find(|site| site.reference() == "first")
        .expect("original direct call exists");
    let after = next
        .model
        .calls()
        .iter()
        .flat_map(ProgramCall::evidence)
        .find(|site| site.reference() == "first")
        .expect("shifted direct call exists");
    assert_ne!(
        before.provenance().location(),
        after.provenance().location()
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn removed_body_type_contributions_leave_no_ghost_spelling() {
    let first = prepare_program_semantics(
        &two_files("fn first() { let value: Vec<u8> = Vec::new(); } fn second() {}"),
        None,
    )
    .expect("typed body compiles");
    let changed = two_files("fn first() { let value: u32 = 0; } fn second() {}");
    let next = prepare_program_semantics(&changed, Some(&first.preparation))
        .expect("type contribution removal compiles");
    assert_clean(&changed, &next.model);
    let value: serde_json::Value =
        serde_json::from_str(&next.model.to_canonical_json().unwrap()).unwrap();
    assert!(!value["types"].to_string().contains("Vec"));
    assert!(next.fallback.is_none());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-004`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn new_declaration_invalidates_unresolved_lookup() {
    let first = prepare_program_semantics(&one_file("fn run() { absent(); }"), None)
        .expect("unresolved source compiles");
    assert!(first.dependencies.iter().any(|read| {
        read.kind == ProgramDependencyKind::Name
            && read.query.contains("absent")
            && read.result == ProgramDependencyResult::Unresolved
    }));
    let changed = one_file("fn run() { absent(); } fn absent() {}");
    let next = prepare_program_semantics(&changed, Some(&first.preparation))
        .expect("new declaration source compiles");
    assert_clean(&changed, &next.model);
    assert!(next.fallback.is_some());
    assert_eq!(next.work.reused_bodies, 0);
    assert!(next.model.calls().iter().any(|call| {
        call.state() == CallResolutionState::ResolvedStatic
            && call
                .evidence()
                .iter()
                .any(|site| site.reference() == "absent")
    }));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-005`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn context_ownership_import_and_destructor_drift_use_full_reconstruction() {
    let original = one_file("struct Value; fn run() { let value = Value; }");
    let first = prepare_program_semantics(&original, None).unwrap();
    let context = original.clone().with_selected_context(
        "sample/library:sample",
        ["extra"],
        ["feature=extra"],
        "x86_64-pc-windows-msvc",
    );
    let ownership = input(
        &[
            ("sample/_data/Cargo.toml", MANIFEST),
            (
                "sample/_code/lib.rs",
                "struct Value; fn run() { let value = Value; }",
            ),
        ],
        "AF-OTHER-0001",
    );
    let import = one_file("use std::fs::File; struct Value; fn run() { let value = Value; }");
    let destructor = one_file(
        "struct Value; impl Drop for Value { fn drop(&mut self) {} } fn run() { let value = Value; }",
    );
    for changed in [context, ownership, import, destructor] {
        let next = prepare_program_semantics(&changed, Some(&first.preparation)).unwrap();
        assert_clean(&changed, &next.model);
        assert!(next.fallback.is_some());
        assert_eq!(next.work.reused_bodies, 0);
    }
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-006`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn repeated_call_deletion_and_recursive_edge_changes_rebuild_topology() {
    let first = prepare_program_semantics(
        &one_file("fn left() { right(); right(); } fn right() {}"),
        None,
    )
    .unwrap();
    let changed = one_file("fn left() { right(); } fn right() { left(); }");
    let next = prepare_program_semantics(&changed, Some(&first.preparation)).unwrap();
    assert_clean(&changed, &next.model);
    let operation_ids = next
        .model
        .calls()
        .iter()
        .flat_map(|call| {
            call.evidence()
                .iter()
                .map(CallSiteEvidence::operation_site_id)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(operation_ids.len(), 2);
    assert!(next.work.recomputed_components > 0);
    let value: serde_json::Value =
        serde_json::from_str(&next.model.to_canonical_json().unwrap()).unwrap();
    assert_eq!(
        value["call_topology"]["recursive_symbols"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let broken = one_file("fn left() {} fn right() { left(); }");
    let rebuilt = prepare_program_semantics(&broken, Some(&next.preparation)).unwrap();
    assert_clean(&broken, &rebuilt.model);
    let value: serde_json::Value =
        serde_json::from_str(&rebuilt.model.to_canonical_json().unwrap()).unwrap();
    assert!(
        value["call_topology"]["recursive_symbols"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let deleted = one_file("fn left() { right(); }");
    let removed = prepare_program_semantics(&deleted, Some(&rebuilt.preparation)).unwrap();
    assert_clean(&deleted, &removed.model);
    assert!(removed.fallback.is_some());
    assert_eq!(removed.model.symbols().len(), 1);
    assert!(
        removed
            .model
            .calls()
            .iter()
            .all(|call| call.callee().is_none())
    );
    let readded = prepare_program_semantics(&changed, Some(&removed.preparation)).unwrap();
    assert_clean(&changed, &readded.model);
    assert!(readded.fallback.is_some());
    assert_eq!(readded.model.symbols().len(), 2);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-007`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn malformed_prepared_input_preserves_cold_error_precedence() {
    let first = prepare_program_semantics(&one_file("fn run() {}"), None).unwrap();
    let non_utf8 = ProgramSemanticInput::new(
        "PF-PREPARATION-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![
                SnapshotBoundFile::from_bytes("sample/_data/Cargo.toml", MANIFEST.as_bytes()),
                SnapshotBoundFile::from_bytes("sample/_code/lib.rs", [0xff]),
            ],
            vec![
                ModuleTerritory::new("PF-PREPARATION-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        [],
        [],
    );
    for changed in [
        one_file("fn run( {"),
        input(
            &[
                ("sample/_data/Cargo.toml", "[package"),
                ("sample/_code/lib.rs", "fn run( {"),
            ],
            "AF-SAMPLE-0001",
        ),
        one_file("fn run() {}").with_selected_context(
            "sample/binary:missing",
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
            "x86_64-pc-windows-msvc",
        ),
        non_utf8,
    ] {
        let Err(cold) = compile_program_semantic_model(&changed) else {
            panic!("cold error expected");
        };
        let Err(prepared) = prepare_program_semantics(&changed, Some(&first.preparation)) else {
            panic!("prepared error expected");
        };
        assert_eq!(cold.to_string(), prepared.to_string());
        assert_eq!(
            std::mem::discriminant(&cold),
            std::mem::discriminant(&prepared)
        );
    }
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R09-008`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R09
#[test]
fn incremental_equals_clean_for_registered_mutations() {
    let initial = two_files("fn first() { let value: u32 = 0; } fn second() { first(); }");
    let mut previous = prepare_program_semantics(&initial, None)
        .unwrap()
        .preparation;
    let mut seed = 0x4d59_5df4_d0f3_3173_u64;
    for case in 0..1_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let value = seed % 10_000;
        let padding = "\n".repeat(usize::try_from(seed % 4).expect("bounded remainder"));
        let calls = if seed & 1 == 0 {
            "second();"
        } else {
            "second(); second();"
        };
        let worker = format!(
            "fn first() {{ let value: u32 = {value};{padding} {calls} }} fn second() {{ first(); }}"
        );
        let candidate = two_files(&worker);
        let next = prepare_program_semantics(&candidate, Some(&previous))
            .unwrap_or_else(|error| panic!("case {case}: {error}"));
        assert_clean(&candidate, &next.model);
        assert!(next.fallback.is_none(), "case {case}");
        assert_eq!(next.work.reused_parse_files, 1, "case {case}");
        assert_eq!(next.work.reused_bodies, 1, "case {case}");
        previous = next.preparation;
    }
}
