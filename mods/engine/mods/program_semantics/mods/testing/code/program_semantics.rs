//! Parent-local Program Semantic Model v3 conformance.

use std::path::{Path, PathBuf};

use fortress_core::audit::compile_repository_psm;
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    CallResolutionReason, CallResolutionState, ExecutableSymbol, ExecutableSymbolKind, NominalType,
    NominalTypeKind, ProgramCall, ProgramSemanticError, ProgramSemanticInput, SymbolClassification,
    compile_program_semantic_model,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
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
                "mods/sample/data/Cargo.toml",
                "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n",
            ),
            ("mods/sample/code/lib.rs", source),
        ],
        &[("PF-PSM-FIXTURE", ""), ("AF-SAMPLE-0001", "mods/sample")],
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

/// `T-AF-PROGRAM-SEMANTICS-0001-R01-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R01
#[test]
fn deepest_module_ownership_and_testing_classification_are_independent_of_rust_namespaces() {
    let fixture = input(
        &[
            (
                "mods/subject/mods/testing/data/Cargo.toml",
                "[package]\nname='checks'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/check.rs'\n",
            ),
            (
                "mods/subject/mods/testing/code/check.rs",
                "pub fn verify() {}\n",
            ),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-SUBJECT-0001", "mods/subject"),
            ("TEST-SUBJECT-0001", "mods/subject/mods/testing"),
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
                "mods/app/data/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n[dependencies]\nprovider={path='../../provider/data'}\n",
            ),
            (
                "mods/app/code/lib.rs",
                "use provider::serve as invoke; pub fn run() { invoke(); }\n",
            ),
            (
                "mods/provider/data/Cargo.toml",
                "[package]\nname='provider'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n",
            ),
            (
                "mods/provider/code/lib.rs",
                "#[path=\"../../worker/code/worker.rs\"] mod worker; pub use worker::serve;\n",
            ),
            ("mods/worker/code/worker.rs", "pub fn serve() {}\n"),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-APP-0001", "mods/app"),
            ("AF-PROVIDER-0001", "mods/provider"),
            ("AF-WORKER-0001", "mods/worker"),
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
                "mods/sample/code/lib.rs",
                0,
                "sha256:invalid",
                b"pub fn changed() {}".to_vec(),
            )],
            vec![ModuleTerritory::new("AF-SAMPLE-0001", "mods/sample")],
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
                "mods/a/data/Cargo.toml",
                "[package]\nname='a'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../code/lib.rs'\n",
            ),
            (
                "mods/a/code/lib.rs",
                "#[path=\"../../b/code/b.rs\"] mod b; pub fn run() { b::target(); }\n",
            ),
            ("mods/b/code/b.rs", "pub fn target() {}\n"),
        ],
        &[
            ("PF-PSM-FIXTURE", ""),
            ("AF-A-0001", "mods/a"),
            ("AF-B-0001", "mods/b"),
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
        "mods/sample/code/lib.rs"
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
