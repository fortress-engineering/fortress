//! Parent-local Program Semantic Model v5 conformance.

use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_psm;
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    CallResolutionReason, CallResolutionState, ExecutableSymbol, ExecutableSymbolKind,
    ExecutionProvenance, NominalType, NominalTypeKind, ProgramCall, ProgramSemanticError,
    ProgramSemanticInput, SymbolClassification, compile_program_semantic_model,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

fn input(
    files: &[(&str, &str)],
    modules: &[(&str, &str)],
    testing: &[&str],
    observed: &[(&str, &str)],
) -> ProgramSemanticInput {
    ProgramSemanticInput::new(
        "PF-PSM-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            files
                .iter()
                .map(|(path, source)| SnapshotBoundFile::from_bytes(*path, source.as_bytes()))
                .collect(),
            modules
                .iter()
                .map(|(id, path)| ModuleTerritory::new(*id, *path))
                .collect(),
        ),
        testing.iter().map(|value| (*value).to_owned()),
        observed
            .iter()
            .map(|(source, target)| ((*source).to_owned(), (*target).to_owned())),
    )
}

fn one_package(source: &str) -> ProgramSemanticInput {
    input(
        &[
            (
                "sample/_data/Cargo.toml",
                "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n",
            ),
            ("sample/_code/lib.rs", source),
        ],
        &[("PF-PSM-FIXTURE", ""), ("AF-SAMPLE-0001", "sample")],
        &[],
        &[],
    )
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn symbols_and_recursive_types_preserve_declared_rust_interfaces() {
    let model = compile_program_semantic_model(&one_package(
        "pub fn typed<'a, T>(flag: bool, pair: (u32, &'a str), values: [T; 2]) -> Result<Option<T>, String> { todo!() }\n",
    ))
    .expect("typed fixture compiles");
    assert_eq!(model.symbols().len(), 1);
    let symbol = &model.symbols()[0];
    assert_eq!(symbol.kind(), ExecutableSymbolKind::FreeFunction);
    assert_eq!(symbol.parameters().len(), 3);
    let result = model
        .to_canonical_json()
        .expect("PSM serializes")
        .parse::<serde_json::Value>()
        .expect("PSM JSON parses");
    assert!(contains_kind(&result, "result"));
    assert!(contains_kind(&result, "option"));
    assert!(contains_kind(&result, "array"));
    assert!(contains_kind(&result, "tuple"));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn methods_associated_functions_and_traits_receive_distinct_identities() {
    let model = compile_program_semantic_model(&one_package(
        "pub struct Item;\npub trait Work { fn declared(&self); }\nimpl Item { pub fn make() -> Self { Self } pub fn run(&self) {} }\nimpl Work for Item { fn declared(&self) {} }\n",
    ))
    .expect("method fixture compiles");
    let kinds = model
        .symbols()
        .iter()
        .map(ExecutableSymbol::kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&ExecutableSymbolKind::AssociatedFunction));
    assert!(kinds.contains(&ExecutableSymbolKind::InherentMethod));
    assert!(kinds.contains(&ExecutableSymbolKind::TraitMethodDeclaration));
    assert!(kinds.contains(&ExecutableSymbolKind::TraitMethodImplementation));
    let identities = model
        .symbols()
        .iter()
        .map(ExecutableSymbol::id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(identities.len(), model.symbols().len());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-004`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn rust_symbol_identity_ignores_incidental_spelling_and_preserves_meaningful_structure() {
    fn id(source: &str, name: &str) -> String {
        compile_program_semantic_model(&one_package(source))
            .expect("identity fixture compiles")
            .symbols()
            .iter()
            .find(|symbol| symbol.qualified_name().ends_with(name))
            .expect("symbol exists")
            .id()
            .to_owned()
    }

    let baseline = id(
        "/// docs\npub fn transform<'a, T: Clone>(value: &'a T) -> &'a T where T: Send { value }\n",
        "transform",
    );
    assert!(baseline.starts_with("rust_symbol:v2:sha256:"));
    assert_eq!(
        baseline,
        id(
            "\n// moved and reformatted\npub fn transform<'scope, U: Clone>(renamed: &'scope U)->&'scope U where U: Send { renamed }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub fn renamed<'a, T: Clone>(value: &'a T) -> &'a T where T: Send { value }\n",
            "renamed",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub fn transform<'a, T: Clone>(value: &'a mut T) -> &'a T where T: Send { value }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub fn transform<'a, T: Clone>(value: &'a T, other: u8) -> &'a T where T: Send { let _ = other; value }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub fn transform<'a, T: Copy>(value: &'a T) -> &'a T where T: Send { value }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub fn transform<'a, T: Clone>(value: &'a T) -> bool where T: Send { true }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub unsafe fn transform<'a, T: Clone>(value: &'a T) -> &'a T where T: Send { value }\n",
            "transform",
        )
    );
    assert_ne!(
        baseline,
        id(
            "pub async fn transform<'a, T: Clone>(value: &'a T) -> &'a T where T: Send { value }\n",
            "transform",
        )
    );
    assert_ne!(
        id("pub fn abi(value: u8) {}\n", "abi"),
        id("pub extern \"C\" fn abi(value: u8) {}\n", "abi")
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-005`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn rust_symbol_identity_distinguishes_namespace_owner_trait_receiver_and_item_kind() {
    let model = compile_program_semantic_model(&one_package(
        r"
mod left { pub fn same() {} }
mod right { pub fn same() {} }
struct First;
struct Second;
trait Left { fn run(&self); }
trait Right { fn run(&self); }
impl First { fn run(&self) {} fn make() {} }
impl Second { fn run(&mut self) {} }
impl Left for First { fn run(&self) {} }
impl Right for First { fn run(&self) {} }
",
    ))
    .expect("distinct identity fixture compiles");
    let identities = model
        .symbols()
        .iter()
        .map(ExecutableSymbol::id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(identities.len(), model.symbols().len());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-006`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn semantic_namespace_preserves_symbol_identity_across_physical_source_relocation() {
    let manifest = "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n";
    let old = input(
        &[
            ("sample/_data/Cargo.toml", manifest),
            ("sample/_code/lib.rs", "#[path=\"old/place.rs\"] mod api;\n"),
            ("sample/_code/old/place.rs", "pub fn stable() {}\n"),
        ],
        &[("PF-PSM-FIXTURE", ""), ("AF-SAMPLE-0001", "sample")],
        &[],
        &[],
    );
    let moved = input(
        &[
            ("sample/_data/Cargo.toml", manifest),
            ("sample/_code/lib.rs", "#[path=\"new/place.rs\"] mod api;\n"),
            ("sample/_code/new/place.rs", "pub fn stable() {}\n"),
        ],
        &[("PF-PSM-FIXTURE", ""), ("AF-SAMPLE-0001", "sample")],
        &[],
        &[],
    );
    let old = compile_program_semantic_model(&old).expect("old placement compiles");
    let moved = compile_program_semantic_model(&moved).expect("new placement compiles");
    let old_symbol = old
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name() == "sample::api::stable")
        .expect("old symbol");
    let moved_symbol = moved
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name() == "sample::api::stable")
        .expect("moved symbol");
    assert_eq!(old_symbol.id(), moved_symbol.id());
    assert_ne!(old_symbol.source_path(), moved_symbol.source_path());
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-007`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn operation_site_identity_survives_line_drift_and_distinguishes_repeated_operations() {
    fn sites(source: &str) -> Vec<String> {
        let model = compile_program_semantic_model(&one_package(source))
            .expect("operation-site fixture compiles");
        let mut result = model
            .calls()
            .iter()
            .filter(|call| call.external_target() == Some("std::fs::write"))
            .flat_map(ProgramCall::evidence)
            .map(|evidence| evidence.operation_site_id().to_owned())
            .collect::<Vec<_>>();
        result.sort();
        result
    }
    let before = sites(
        "fn persist(path: &str) { std::fs::write(path, b\"one\").unwrap(); std::fs::write(path, b\"two\").unwrap(); }\n",
    );
    let after = sites(
        "// unrelated line\nfn persist(renamed: &str) { let unrelated = 1 + 1; std::fs::write(renamed,b\"one\").unwrap();\nstd::fs::write(renamed, b\"two\").unwrap(); let _ = unrelated; }\n",
    );
    assert_eq!(before, after);
    assert_eq!(before.len(), 2);
    assert_ne!(before[0], before[1]);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-008`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn rust_symbol_identity_scales_without_collision_or_traversal_order_dependence() {
    let declarations = (0..10_000)
        .map(|index| format!("fn item_{index}<T: Clone>(value: T) -> T {{ value }}\n"))
        .collect::<Vec<_>>();
    let forward = declarations.join("");
    let reverse = declarations.iter().rev().cloned().collect::<String>();
    let first = compile_program_semantic_model(&one_package(&forward))
        .expect("large forward identity corpus compiles");
    let second = compile_program_semantic_model(&one_package(&reverse))
        .expect("large reverse identity corpus compiles");
    let first_ids = first
        .symbols()
        .iter()
        .map(ExecutableSymbol::id)
        .collect::<std::collections::BTreeSet<_>>();
    let second_ids = second
        .symbols()
        .iter()
        .map(ExecutableSymbol::id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(first_ids.len(), 10_000);
    assert_eq!(first_ids, second_ids);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn deepest_module_ownership_and_testing_classification_are_independent_of_rust_namespaces() {
    let fixture = input(
        &[
            (
                "subject/testing/_data/Cargo.toml",
                "[package]\nname='checks'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/check.rs'\n",
            ),
            ("subject/testing/_code/check.rs", "pub fn verify() {}\n"),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-SUBJECT-0001", "subject"),
            ("TEST-SUBJECT-0001", "subject/testing"),
        ],
        &["TEST-SUBJECT-0001"],
        &[],
    );
    let model = compile_program_semantic_model(&fixture).expect("Testing fixture compiles");
    assert_eq!(model.symbols()[0].fortress_module(), "TEST-SUBJECT-0001");
    assert_eq!(
        model.symbols()[0].classification(),
        SymbolClassification::Testing
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-005`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn rust_execution_provenance_follows_test_attributes_and_lexical_ancestry() {
    let model = compile_program_semantic_model(&one_package(
        r"
fn production() {}
fn test_helper_name_is_not_authority() {}
#[test] fn direct_test() {}
#[bench] fn direct_bench() {}
#[cfg(test)] mod tests {
    fn helper() {}
    mod nested { fn another_helper() {} }
    struct Subject;
    impl Subject { fn method(&self) {} }
}
",
    ))
    .expect("provenance fixture compiles");
    let provenance = model
        .symbols()
        .iter()
        .map(|symbol| (symbol.qualified_name(), symbol.execution_provenance()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        provenance["sample::production"],
        ExecutionProvenance::ProductionCapable
    );
    assert_eq!(
        provenance["sample::test_helper_name_is_not_authority"],
        ExecutionProvenance::ProductionCapable
    );
    assert_eq!(
        provenance["sample::direct_test"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::direct_bench"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::tests::helper"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::tests::nested::another_helper"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::tests::Subject::method"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(model.coverage().test_only_symbols(), 5);
    assert_eq!(model.coverage().unknown_provenance_symbols(), 0);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-006`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn compound_cfg_provenance_is_conservative() {
    let model = compile_program_semantic_model(&one_package(
        r#"
#[cfg(all(test, unix))] fn conjunctive() {}
#[cfg(any(test, feature = "extra"))] fn alternative() {}
#[cfg(not(test))] fn non_test() {}
#[cfg(any(all(test, unix), all(test, windows)))] fn every_branch_requires_test() {}
#[cfg(platform(test))] fn unsupported_predicate() {}
"#,
    ))
    .expect("compound cfg fixture compiles structurally");
    let provenance = model
        .symbols()
        .iter()
        .map(|symbol| (symbol.qualified_name(), symbol.execution_provenance()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        provenance["sample::conjunctive"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::alternative"],
        ExecutionProvenance::ProductionCapable
    );
    assert_eq!(
        provenance["sample::non_test"],
        ExecutionProvenance::ProductionCapable
    );
    assert_eq!(
        provenance["sample::every_branch_requires_test"],
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        provenance["sample::unsupported_predicate"],
        ExecutionProvenance::Unknown
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-007`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn cargo_integration_test_targets_are_test_only_without_naming_inference() {
    let fixture = input(
        &[
            (
                "sample/_data/Cargo.toml",
                "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n[[test]]\nname='integration'\npath='../_code/tests/integration.rs'\n",
            ),
            ("sample/_code/lib.rs", "fn production() {}\n"),
            (
                "sample/_code/tests/integration.rs",
                "fn ordinary_name() {}\n",
            ),
        ],
        &[("PF-PSM-FIXTURE", ""), ("AF-SAMPLE-0001", "sample")],
        &[],
        &[],
    );
    let model = compile_program_semantic_model(&fixture).expect("Cargo test target compiles");
    assert_eq!(
        model
            .symbols()
            .iter()
            .find(|symbol| symbol.qualified_name() == "integration::ordinary_name")
            .expect("integration symbol exists")
            .execution_provenance(),
        ExecutionProvenance::TestOnly
    );
    assert_eq!(
        model
            .symbols()
            .iter()
            .find(|symbol| symbol.qualified_name() == "sample::production")
            .expect("production symbol exists")
            .execution_provenance(),
        ExecutionProvenance::ProductionCapable
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R02-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R02
#[test]
fn static_external_dynamic_unresolved_and_collapsed_call_states_are_explicit() {
    let model = compile_program_semantic_model(&one_package(
        "fn target(value: u32) -> u32 { value }\nfn caller(callback: fn(u32) -> u32) { let _ = target(1); let _ = target(2); let _ = callback(3); missing(4); let _message = format!(\"x\"); }\n",
    ))
    .expect("call-state fixture compiles structurally");
    let resolved = model
        .calls()
        .iter()
        .find(|call| call.state() == CallResolutionState::ResolvedStatic)
        .expect("static call resolves");
    assert_eq!(resolved.evidence().len(), 2);
    assert!(
        model
            .calls()
            .iter()
            .any(|call| { call.state() == CallResolutionState::DynamicDispatch })
    );
    assert!(
        model
            .calls()
            .iter()
            .any(|call| call.state() == CallResolutionState::Unresolved)
    );
    assert!(
        model
            .calls()
            .iter()
            .any(|call| call.state() == CallResolutionState::Unsupported)
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R02-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R02
#[test]
fn cross_module_cross_crate_alias_and_facade_calls_preserve_the_boundary() {
    let fixture = input(
        &[
            (
                "app/_data/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n[dependencies]\nprovider={path='../../provider/_data'}\n",
            ),
            (
                "app/_code/lib.rs",
                "use provider::serve as invoke; pub fn run() { invoke(); }\n",
            ),
            (
                "provider/_data/Cargo.toml",
                "[package]\nname='provider'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n",
            ),
            (
                "provider/_code/lib.rs",
                "#[path=\"../../worker/_code/worker.rs\"] mod worker; pub use worker::serve;\n",
            ),
            ("worker/_code/worker.rs", "pub fn serve() {}\n"),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-APP-0001", "app"),
            ("AF-PROVIDER-0001", "provider"),
            ("AF-WORKER-0001", "worker"),
        ],
        &[],
        &[("AF-APP-0001", "AF-PROVIDER-0001")],
    );
    let model = compile_program_semantic_model(&fixture).expect("facade call is coherent");
    assert_eq!(model.module_boundaries().len(), 1);
    let json: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    assert_eq!(
        json["module_boundaries"][0]["target_module"],
        "AF-PROVIDER-0001"
    );
    assert_eq!(
        json["module_boundaries"][0]["callee_module"],
        "AF-WORKER-0001"
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R02-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R02
#[test]
fn direct_and_mutual_recursion_form_deterministic_call_components() {
    let model = compile_program_semantic_model(&one_package(
        "fn direct() { direct(); } fn left() { right(); } fn right() { left(); }\n",
    ))
    .expect("recursive fixture compiles");
    let json: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    let recursive = json["call_topology"]["strongly_connected_components"]
        .as_array()
        .expect("components exist")
        .iter()
        .filter(|component| component["recursive"] == true)
        .count();
    assert_eq!(recursive, 2);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn assignments_arguments_returns_and_option_result_transforms_are_retained() {
    let model = compile_program_semantic_model(&one_package(
        "fn consume(value: u32) -> Result<Option<u32>, ()> { let mut next: u32 = value; next = next; let wrapped = Some(next); Ok(wrapped) } fn caller() { let _result = consume(1); }\n",
    ))
    .expect("transfer fixture compiles");
    let json: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    let kinds = json["value_transfers"]
        .as_array()
        .expect("transfers exist")
        .iter()
        .map(|value| value["kind"].as_str().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(kinds.contains("parameter_to_binding"));
    assert!(kinds.contains("expression_to_binding"));
    assert!(kinds.contains("assignment"));
    assert!(kinds.contains("expression_to_return"));
    assert!(kinds.contains("argument_to_parameter"));
    assert!(kinds.contains("return_to_consumer"));
    assert!(
        json["transformations"]
            .as_array()
            .is_some_and(|values| values.len() >= 2)
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn snapshot_mutation_is_rejected_and_canonical_bytes_and_digest_repeat() {
    let fixture = one_package("pub fn stable() {}\n");
    let first = compile_program_semantic_model(&fixture).expect("first model compiles");
    let second = compile_program_semantic_model(&fixture).expect("second model compiles");
    assert_eq!(first, second);
    assert_eq!(
        first.to_canonical_json().expect("first serializes"),
        second.to_canonical_json().expect("second serializes")
    );
    assert_eq!(
        first.digest().expect("first digest"),
        second.digest().expect("second digest")
    );

    let mutated = ProgramSemanticInput::new(
        "PF-PSM-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            vec![SnapshotBoundFile::new(
                "sample/_code/lib.rs",
                0,
                "sha256:invalid",
                b"pub fn changed() {}".to_vec(),
            )],
            vec![ModuleTerritory::new("AF-SAMPLE-0001", "sample")],
        ),
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(
        compile_program_semantic_model(&mutated),
        Err(ProgramSemanticError::Observation(_))
    ));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn analyzer_disagreement_is_a_hard_coherency_failure() {
    let fixture = input(
        &[
            (
                "a/_data/Cargo.toml",
                "[package]\nname='a'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n",
            ),
            (
                "a/_code/lib.rs",
                "#[path=\"../../b/_code/b.rs\"] mod b; pub fn run() { b::target(); }\n",
            ),
            ("b/_code/b.rs", "pub fn target() {}\n"),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-A-0001", "a"),
            ("AF-B-0001", "b"),
        ],
        &[],
        &[],
    );
    assert!(matches!(
        compile_program_semantic_model(&fixture),
        Err(ProgramSemanticError::AnalyzerDisagreement(_))
    ));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R03-004`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R03
#[test]
fn live_fortress_psm_is_coherent_deterministic_and_invalid_free() {
    let first = compile_repository_psm(repository_root()).expect("Fortress self-PSM compiles");
    let second = compile_repository_psm(repository_root()).expect("Fortress self-PSM repeats");
    assert_eq!(first, second);
    assert!(first.analyzer_coherency().is_coherent());
    assert_eq!(first.coverage().invalid_calls(), 0);
    assert!(first.coverage().executable_symbols() > 0);
    assert!(
        first
            .unsupported_semantics()
            .contains(&"behavioral_realization".to_owned())
    );
    assert!(first.symbols().iter().any(|symbol| {
        matches!(symbol.return_type().type_id(), id if !id.is_empty())
            && matches!(symbol.classification(), SymbolClassification::Production)
    }));
    assert!(
        first
            .symbols()
            .iter()
            .any(|symbol| { matches!(symbol.classification(), SymbolClassification::Testing) })
    );
    assert!(
        first
            .symbols()
            .iter()
            .flat_map(ExecutableSymbol::parameters)
            .any(|parameter| matches!(parameter.parameter_type().type_id(), id if !id.is_empty()))
    );
    assert!(
        first
            .to_canonical_json()
            .expect("first serializes")
            .ends_with('\n')
    );
    assert!(
        first
            .symbols()
            .iter()
            .any(|symbol| { model_type_is_structural(&first, symbol.return_type().type_id()) })
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R04-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R04
#[test]
fn supported_rust_bodies_are_lowered_into_neutral_control_facts() {
    let model = compile_program_semantic_model(&one_package(
        "fn flow(value: Option<i32>, flag: bool) -> i32 { if flag { return value.unwrap(); } match value { Some(next) => next, None => 0 } }\n",
    ))
    .expect("body fixture compiles");
    let value: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    let bodies = value["bodies"].as_array().expect("body facts exist");
    assert_eq!(bodies.len(), 1);
    assert!(contains_kind(&value["bodies"], "if"));
    assert!(contains_kind(&value["bodies"], "match"));
    assert!(contains_kind(&value["bodies"], "return"));
    assert!(contains_kind(&value["bodies"], "method_call"));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R05-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R05
#[test]
fn nominal_struct_enum_trait_alias_fields_variants_and_impls_are_indexed() {
    let model = compile_program_semantic_model(&one_package(
        "pub struct Record { pub value: u32 }\npub struct Pair(pub u8, pub bool);\npub enum Choice { Empty, Value(u32), Named { flag: bool } }\npub trait Inspect { fn inspect(&self) -> bool; }\npub type RecordAlias = Record;\nimpl Record { pub fn value(&self) -> u32 { self.value } }\nimpl Inspect for Record { fn inspect(&self) -> bool { true } }\nfn exercise(record: &Record) { let _ = record.inspect(); }\n",
    ))
    .expect("nominal fixture compiles");
    let kinds = model
        .nominal_types()
        .iter()
        .map(NominalType::kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == NominalTypeKind::Struct)
            .count(),
        2
    );
    assert!(kinds.contains(&NominalTypeKind::Enum));
    assert!(kinds.contains(&NominalTypeKind::Trait));
    assert!(kinds.contains(&NominalTypeKind::TypeAlias));
    assert_eq!(model.impls().len(), 2);
    assert!(
        model
            .calls()
            .iter()
            .filter_map(|call| call.callee())
            .filter_map(|id| model.symbols().iter().find(|symbol| symbol.id() == id))
            .any(|symbol| symbol.qualified_name().ends_with("Record::inspect"))
    );
    let value: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    assert_eq!(value["coverage"]["nominal_variants"], 3);
    assert_eq!(value["coverage"]["nominal_fields"], 5);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R05-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R05
#[test]
fn imported_aliases_and_field_access_retain_canonical_static_types() {
    let model = compile_program_semantic_model(&one_package(
        "mod model { pub struct Project { pub count: u32 } }\nuse crate::model::Project as P;\nfn count(project: P) -> u32 { let value = project.count; value }\n",
    ))
    .expect("alias and field fixture compiles");
    let value: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    let parameter_type = &value["symbols"]
        .as_array()
        .expect("symbols")
        .iter()
        .find(|symbol| symbol["qualified_name"] == "sample::count")
        .expect("count symbol")["parameters"][0]["parameter_type"]["type_id"];
    let semantic = value["types"]
        .as_array()
        .expect("types")
        .iter()
        .find(|candidate| candidate["id"] == *parameter_type)
        .expect("parameter semantic");
    assert_eq!(semantic["semantic"]["name"], "crate::model::Project");
    assert!(
        value["value_transfers"]
            .as_array()
            .expect("transfers")
            .iter()
            .any(|transfer| transfer["producer"]["name"] == "project . count"
                && !transfer["producer"]["static_type"].is_null())
    );
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R06-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R06
#[test]
fn receiver_types_resolve_inherent_methods_references_collisions_and_chains() {
    let model = compile_program_semantic_model(&one_package(
        "struct Builder; struct Checked; struct Other;\nimpl Builder { fn build() -> Self { Builder } fn validate(&self) -> Checked { Checked } }\nimpl Checked { fn finish(&mut self) -> u32 { 1 } }\nimpl Other { fn validate(&self) -> bool { true } }\nfn identity<T>(value: T) -> T { value }\nfn run(value: &Builder, checked: &mut Checked) -> u32 { let _ = value.validate(); let _ = checked.finish(); let _ = identity(Checked).finish(); let mut next = Builder::build().validate(); next.finish() }\n",
    ))
    .expect("type-directed fixture compiles");
    let resolved_names = model
        .calls()
        .iter()
        .filter(|call| call.state() == CallResolutionState::ResolvedStatic)
        .filter_map(|call| call.callee())
        .filter_map(|id| model.symbols().iter().find(|symbol| symbol.id() == id))
        .map(ExecutableSymbol::qualified_name)
        .collect::<Vec<_>>();
    assert!(
        resolved_names
            .iter()
            .any(|name| name.ends_with("Builder::validate"))
    );
    assert!(
        resolved_names
            .iter()
            .any(|name| name.ends_with("Checked::finish"))
    );
    assert!(
        !resolved_names
            .iter()
            .any(|name| name.ends_with("Other::validate"))
    );
    assert!(model.calls().iter().any(|call| {
        call.callee()
            .and_then(|id| model.symbols().iter().find(|symbol| symbol.id() == id))
            .is_some_and(|symbol| symbol.qualified_name().ends_with("Builder::validate"))
            && call
                .evidence()
                .iter()
                .any(|evidence| evidence.reference().contains("Builder :: build"))
    }));
    assert!(model.value_transfers().len() > 4);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R06-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R06
#[test]
fn residual_calls_distinguish_trait_objects_generics_external_and_unknown_receivers() {
    let model = compile_program_semantic_model(&one_package(
        "trait Work { fn work(&self); }\nfn dynamic(value: &dyn Work) { value.work(); }\nfn generic<T>(value: T) { value.work(); }\nfn external(value: &String) { value.len(); }\nfn unknown() { missing().work(); }\n",
    ))
    .expect("residual-resolution fixture compiles");
    let reasons = model
        .calls()
        .iter()
        .filter_map(ProgramCall::reason)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(reasons.contains(&CallResolutionReason::TraitObjectDispatch));
    assert!(reasons.contains(&CallResolutionReason::GenericReceiver));
    assert!(reasons.contains(&CallResolutionReason::ExternalReceiver));
    assert!(reasons.contains(&CallResolutionReason::UnknownReceiverType));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R06-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R06
#[test]
fn ambiguity_and_user_defined_dereference_remain_explicit_without_guessing() {
    let model = compile_program_semantic_model(&one_package(
        "trait Left { fn run(&self); } trait Right { fn run(&self); } struct Item; impl Left for Item { fn run(&self) {} } impl Right for Item { fn run(&self) {} } struct Wrapper(Item); fn ambiguous(value: &Item) { value.run(); } fn deref(value: Wrapper) { (*value).run(); }\n",
    ))
    .expect("ambiguous fixture compiles structurally");
    assert!(model.calls().iter().any(|call| {
        call.state() == CallResolutionState::Unresolved
            && call.reason() == Some(CallResolutionReason::AmbiguousLocalMethod)
    }));
    assert!(model.calls().iter().any(|call| {
        call.state() == CallResolutionState::Unresolved
            && call.reason() == Some(CallResolutionReason::UnsupportedDeref)
    }));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R07-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R07
#[test]
fn structured_places_distinguish_receiver_reads_and_writes() {
    let model = compile_program_semantic_model(&one_package(
        "struct Item { ready: bool, count: u32 } impl Item { fn update(&mut self) { if self.ready { self.count = 1; } self.count += 1; } }\n",
    ))
    .expect("state-place fixture compiles");
    assert!(
        model.state_reads().iter().any(|read| {
            read.place().is_receiver() && read.place().field_name() == Some("ready")
        })
    );
    assert!(model.mutations().iter().any(|mutation| {
        mutation.target().is_receiver() && mutation.target().field_name() == Some("count")
    }));
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R07-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R07
#[test]
fn mutation_facts_are_canonical_and_carry_exact_provenance() {
    let first = compile_program_semantic_model(&one_package(
        "struct Item(bool); fn update(mut item: Item) { item.0 = true; }\n",
    ))
    .expect("tuple-field fixture compiles");
    let second = compile_program_semantic_model(&one_package(
        "struct Item(bool); fn update(mut item: Item) { item.0 = true; }\n",
    ))
    .expect("repeated tuple-field fixture compiles");
    assert_eq!(
        first.to_canonical_json().expect("first serializes"),
        second.to_canonical_json().expect("second serializes")
    );
    assert_eq!(first.mutations().len(), 1);
    assert_eq!(
        first.mutations()[0].provenance().path(),
        "sample/_code/lib.rs"
    );
}

fn model_type_is_structural(
    model: &fortress_core::program_semantics::ProgramSemanticModel,
    type_id: &str,
) -> bool {
    let value: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().expect("model serializes"))
            .expect("model parses");
    value["types"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|candidate| candidate["id"] == type_id)
        .is_some_and(|candidate| !matches!(candidate["semantic"]["kind"].as_str(), Some("unknown")))
}

fn contains_kind(value: &serde_json::Value, kind: &str) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(|value| contains_kind(value, kind)),
        serde_json::Value::Object(values) => {
            values.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
                || values.values().any(|value| contains_kind(value, kind))
        }
        _ => false,
    }
}
