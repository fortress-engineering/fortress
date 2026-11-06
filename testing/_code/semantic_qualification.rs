//! Test-owned observation driver; expected answers are never evaluator inputs.

use fortress_semantic_oracle as oracle;

use fortress_core::architecture_realization::reconcile_implementation;
use fortress_core::contract_coherency::{
    ContractStandardIndex, LogicalModuleContractSource,
    compile_contract_coherency_graph_with_logical_modules,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
    observe_rust_implementation, resolve_source_ownership_with_logical_modules,
};
use fortress_core::program_semantics::{
    ProgramSemanticInput, ProgramSemanticModel, compile_program_semantic_model,
    prepare_program_semantics,
};
use fortress_core::project::ProjectConfiguration;
use fortress_core::semantic_analysis::{analyze_program_domains, load_function_contracts};
use fortress_core::semantic_conformance::{BlockingEligibility, evaluate_semantic_conformance};
use fortress_core::state_effect_analysis::{
    OperationSummaryCatalog, OperationSummaryInstantiation, SummaryAcceptance, SummaryContext,
    SummaryEffectBound, SummaryPremise, analyze_state_effects_with_summaries,
};
use fortress_core::state_effect_analysis::{analyze_state_effects, load_state_contracts};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;

const EDITION: &str = "1.0.0-draft.1";
const ROOT: &str = "PF-SEMANTIC-QUALIFICATION";
const OWNER: &str = "AF-SAMPLE-0001";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationCase {
    case_id: String,
    files: BTreeMap<String, String>,
    source_path: Option<String>,
    logical: bool,
    context_selected: bool,
    primitive_source: Option<String>,
    test_context: bool,
    target: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn derived(
    case: &ObservationCase,
    psm: &ProgramSemanticModel,
    input: &ImplementationObservationInput,
    ccg: &fortress_core::contract_coherency::ContractCoherencyGraph,
) -> Result<Value, String> {
    let observed = observe_rust_implementation(input).map_err(|e| e.to_string())?;
    let functions = load_function_contracts(psm, Vec::new()).map_err(|e| e.to_string())?;
    let domains = analyze_program_domains(psm, &functions, EDITION).map_err(|e| e.to_string())?;
    let states = load_state_contracts(psm, Vec::new()).map_err(|e| e.to_string())?;
    let (catalog, bindings) = primitive_summary_inputs(case, psm)?;
    let effects = analyze_state_effects_with_summaries(
        psm, &domains, &states, &functions, EDITION, &catalog, &bindings,
    )
    .map_err(|e| e.to_string())?;
    let realization =
        reconcile_implementation(ccg, &observed, EDITION).map_err(|e| e.to_string())?;
    let conformance = evaluate_semantic_conformance(
        ccg,
        psm,
        effects.model(),
        &realization,
        input.ownerships(),
        EDITION,
    )
    .map_err(|e| e.to_string())?;
    let unconfigured = if bindings.is_empty() {
        None
    } else {
        let defaults = analyze_state_effects(psm, &domains, &states, &functions, EDITION)
            .map_err(|e| e.to_string())?;
        Some(
            evaluate_semantic_conformance(
                ccg,
                psm,
                defaults.model(),
                &realization,
                input.ownerships(),
                EDITION,
            )
            .map_err(|e| e.to_string())?
            .model()
            .to_canonical_json()
            .map_err(|e| e.to_string())?,
        )
    };
    Ok(json!({
        "program": psm.to_canonical_json().map_err(|e| e.to_string())?,
        "domains": domains.model().to_canonical_json().map_err(|e| e.to_string())?,
        "domain_findings": domains.findings(),
        "effects": effects.model().to_canonical_json().map_err(|e| e.to_string())?,
        "state_findings": effects.state_findings(),
        "effect_findings": effects.effect_findings(),
        "realization": {"records":realization.records(),"findings":realization.findings(),
            "summary":realization.summary(),"unsupported_semantics":realization.unsupported_semantics()},
        "conformance": conformance.model().to_canonical_json().map_err(|e| e.to_string())?,
        "findings": conformance.findings(), "coverage_findings": conformance.coverage_findings(),
        "unconfigured_conformance": unconfigured,
    }))
}

fn primitive_catalog() -> Result<(OperationSummaryCatalog, Value, String), String> {
    let raw = include_str!("../_data/primitive_profile_inputs.json");
    let profile: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let mut value: Value =
        serde_json::from_str(fortress_core::standard::installed_operation_summaries())
            .map_err(|e| e.to_string())?;
    let all_effects = [
        "environment.read",
        "environment.write",
        "external_interaction",
        "filesystem.read",
        "filesystem.write",
        "may_panic",
        "network.connect",
        "network.io",
        "network.listen",
        "owned_state_read",
        "owned_state_write",
        "process.spawn",
        "random.read",
        "receiver_state_read",
        "receiver_state_write",
        "time.monotonic_read",
        "time.wall_read",
        "unsafe_execution",
    ];
    for operation in profile["operations"]
        .as_array()
        .ok_or("profile operations absent")?
    {
        let excluded = operation["excluded_effects"]
            .as_array()
            .ok_or("profile exclusions absent")?;
        let effects = all_effects
            .iter()
            .filter(|effect| !excluded.contains(&json!(effect)))
            .collect::<Vec<_>>();
        value["summaries"].as_array_mut().ok_or("installed summaries absent")?.push(json!({
            "id":format!("qualification-assumed:{}",operation["operation"].as_str().ok_or("profile selector absent")?),
            "operation_selector":operation["operation"], "toolchain_or_package_source_digest":operation["source_digest"],
            "supported_versions":[profile["version"]], "target_features_constraints":{"targets":[profile["target"]],"features":[]},
            "type_constraints":[profile["type_binding"]], "observed_effects":[],
            "effect_upper_bound":{"state":"KNOWN","effects":effects}, "callback_dependencies":operation["callback_dependencies"],
            "destructor_dependencies":operation["destructor_dependencies"], "completeness":"COMPLETE","authority_class":"ASSUMED",
            "qualification_refs":[format!("research-primitive-premises:{}",digest(raw.as_bytes()))],
        }));
    }
    Ok((
        OperationSummaryCatalog::from_json_str(&value.to_string()).map_err(|e| e.to_string())?,
        profile,
        digest(raw.as_bytes()),
    ))
}

fn verify_primitive_source(case: &ObservationCase, source_digest: &str) -> Result<(), String> {
    let source = case
        .files
        .get("sample/_code/lib.rs")
        .ok_or("primitive source absent")?;
    let frozen: Value = serde_json::from_str(include_str!("../_data/synthetic_scopes_freeze.json"))
        .map_err(|e| e.to_string())?;
    let reviewed = frozen["cases"]
        .as_array()
        .ok_or("frozen cases absent")?
        .iter()
        .any(|row| {
            row["case_id"] == case.case_id
                && row["source"] == *source
                && row.get("opcodes").is_some()
        });
    if !reviewed || digest(source.as_bytes()) != source_digest {
        return Err(
            "primitive premises require exact preregistered source, never inferred argument types"
                .into(),
        );
    }
    Ok(())
}

fn primitive_summary_inputs(
    case: &ObservationCase,
    psm: &ProgramSemanticModel,
) -> Result<
    (
        OperationSummaryCatalog,
        BTreeMap<String, OperationSummaryInstantiation>,
    ),
    String,
> {
    use fortress_core::program_semantics::ContextKnowledge;
    let Some(source_digest) = &case.primitive_source else {
        let installed = OperationSummaryCatalog::from_json_str(
            fortress_core::standard::installed_operation_summaries(),
        )
        .map_err(|e| e.to_string())?;
        return Ok((installed, BTreeMap::new()));
    };
    verify_primitive_source(case, source_digest)?;
    let (catalog, profile, profile_digest) = primitive_catalog()?;
    let accepted = catalog
        .summaries()
        .iter()
        .filter(|s| s.id.starts_with("qualification-assumed:"))
        .map(|s| s.id.clone())
        .collect::<Vec<_>>();
    let mut bindings = BTreeMap::new();
    for call in psm.calls() {
        let Some(operation) = call.external_target() else {
            continue;
        };
        let Some(summary) = catalog.summaries().iter().find(|s| {
            s.operation_selector == operation && s.id.starts_with("qualification-assumed:")
        }) else {
            continue;
        };
        let refs = vec![
            format!("research-profile:{profile_digest}"),
            format!("reviewed-literal-source:{source_digest}"),
        ];
        let premises = summary
            .callback_dependencies
            .iter()
            .chain(&summary.destructor_dependencies)
            .map(|key| {
                (
                    key.clone(),
                    SummaryPremise {
                        bound: SummaryEffectBound::Known(Vec::new()),
                        refs: refs.clone(),
                    },
                )
            })
            .collect();
        let input = OperationSummaryInstantiation {
            context: SummaryContext {
                source_digest: ContextKnowledge::Known(
                    summary.toolchain_or_package_source_digest.clone(),
                ),
                version: ContextKnowledge::Known(
                    profile["version"]
                        .as_str()
                        .ok_or("profile version absent")?
                        .into(),
                ),
                target: ContextKnowledge::Known(
                    profile["target"]
                        .as_str()
                        .ok_or("profile target absent")?
                        .into(),
                ),
                features: ContextKnowledge::Known(Vec::new()),
                type_bindings: ContextKnowledge::Known(vec![
                    profile["type_binding"]
                        .as_str()
                        .ok_or("profile type absent")?
                        .into(),
                ]),
            },
            context_observation_refs: refs,
            premises,
            acceptance: Some(SummaryAcceptance {
                profile_digest: profile_digest.clone(),
                accepted_summary_ids: accepted.clone(),
            }),
        };
        for evidence in call.evidence() {
            bindings.insert(evidence.operation_site_id().to_owned(), input.clone());
        }
    }
    Ok((catalog, bindings))
}

struct FixtureScope {
    files: BTreeMap<String, Vec<u8>>,
    compilation: fortress_core::contract_coherency::CcgCompilation,
    observation: ImplementationObservationInput,
    snapshot: String,
}

fn build_scope(case: &ObservationCase) -> Result<FixtureScope, String> {
    let files = case
        .files
        .iter()
        .map(|(p, b)| (p.clone(), b.as_bytes().to_vec()))
        .collect::<BTreeMap<_, _>>();
    let standard =
        ContractStandardIndex::new("STD-FORTRESS-ENGINEERING", EDITION, ["ARCH-SEMANTIC-001"]);
    let logical = if case.logical {
        vec![LogicalModuleContractSource::new(
            OWNER,
            "_data/logical_modules/sample/contract.json",
            ROOT,
        )]
    } else {
        Vec::new()
    };
    let compilation =
        compile_contract_coherency_graph_with_logical_modules(&files, &standard, None, &logical);
    let ccg = compilation
        .graph()
        .ok_or_else(|| format!("invalid CCG: {:?}", compilation.violations()))?;
    let territories = ccg
        .modules()
        .iter()
        .filter(|(id, _)| !case.logical || id.as_str() != OWNER)
        .map(|(id, m)| ModuleTerritory::new(id, m.path()))
        .collect::<Vec<_>>();
    let ownerships = if case.logical {
        let project = ProjectConfiguration::from_json_str(&case.files["__fortress/.fsconfig"])
            .map_err(|e| e.to_string())?;
        let resolution = resolve_source_ownership_with_logical_modules(
            files.keys().map(String::as_str),
            &territories,
            project.logical_modules(),
            &ccg.modules().keys().cloned().collect::<BTreeSet<_>>(),
        );
        if !resolution.diagnostics().is_empty() {
            return Err(format!(
                "ownership diagnostics: {:?}",
                resolution.diagnostics()
            ));
        }
        resolution.ownerships().to_vec()
    } else {
        ImplementationObservationInput::new("unused", Vec::new(), Vec::new())
            .ownerships()
            .to_vec()
    };
    let snapshot = digest(&serde_json::to_vec(&files).map_err(|e| e.to_string())?);
    let bound = files
        .iter()
        .map(|(p, b)| SnapshotBoundFile::from_bytes(p, b.clone()))
        .collect();
    let observation = if case.logical {
        ImplementationObservationInput::new_with_ownership(snapshot.clone(), bound, ownerships)
    } else {
        ImplementationObservationInput::new(snapshot.clone(), bound, territories)
    };
    Ok(FixtureScope {
        files,
        compilation,
        observation,
        snapshot,
    })
}

fn select_context(
    case: &ObservationCase,
    value: ProgramSemanticInput,
    alternate: bool,
) -> ProgramSemanticInput {
    if case.source_path.is_none() {
        return if alternate {
            value
        } else {
            value.with_generated_inputs([])
        };
    }
    value
        .with_selected_context(
            &case.target,
            Vec::<String>::new(),
            if case.test_context {
                vec!["test"]
            } else {
                Vec::new()
            },
            if alternate {
                "qualification-alternate-platform"
            } else {
                "qualification-frozen-platform"
            },
        )
        .with_generated_inputs([])
}

fn metadata_neutral(
    case: &ObservationCase,
    files: &BTreeMap<String, Vec<u8>>,
    observation: &ImplementationObservationInput,
    observed: &fortress_core::implementation_observation::ObservedImplementation,
    ccg: &fortress_core::contract_coherency::ContractCoherencyGraph,
    snapshot: &str,
    expected: &Value,
) -> Result<bool, String> {
    let mut metadata_files = files
        .iter()
        .map(|(p, b)| SnapshotBoundFile::from_bytes(p, b.clone()))
        .collect::<Vec<_>>();
    let metadata_path = format!(
        "__fortress/evidence/generations/{}/semantic_qualification.json",
        "a".repeat(64)
    );
    let metadata_role = fortress_core::control_layout::ControlLayout::standard()
        .resolve(&metadata_path)
        .ok_or("metadata role absent")?;
    if metadata_role.role()
        != fortress_core::control_layout::ControlRole::GeneratedAssessmentPayload
        || metadata_role.source_binding()
            != fortress_core::control_layout::ControlSourceBinding::Nonrecursive
    {
        return Err("metadata control is not a registered nonrecursive record".into());
    }
    metadata_files.push(SnapshotBoundFile::from_bytes(
        metadata_path,
        b"{\"kind\":\"NONAUTHORITATIVE_EXECUTION_RECORD\",\"status\":\"INCOMPLETE\"}\n",
    ));
    let metadata_observation = ImplementationObservationInput::new_with_ownership(
        snapshot,
        metadata_files,
        observation.ownerships().to_vec(),
    );
    let dependencies = observed
        .module_dependencies()
        .iter()
        .map(|d| (d.source_module().to_owned(), d.target_module().to_owned()));
    let metadata_original =
        ProgramSemanticInput::new(ROOT, metadata_observation.clone(), [], dependencies);
    let metadata_input = if case.context_selected {
        select_context(case, metadata_original, false)
    } else {
        metadata_original
    };
    let metadata_model =
        compile_program_semantic_model(&metadata_input).map_err(|e| e.to_string())?;
    Ok(derived(case, &metadata_model, &metadata_observation, ccg)? == *expected)
}

fn verify_context(case: &ObservationCase, model: &ProgramSemanticModel) -> Result<(), String> {
    if case.source_path.is_some() && case.context_selected {
        let context = serde_json::to_value(model.program_context()).map_err(|e| e.to_string())?;
        let cfg = if case.test_context {
            vec!["test"]
        } else {
            Vec::new()
        };
        let selected = context["packages"].as_array().is_some_and(|packages| {
            packages.iter().any(|package| {
                package["target_identity"] == case.target
                    && package["features"] == json!({"state":"KNOWN","value":[]})
                    && package["cfg"] == json!({"state":"KNOWN","value":cfg})
            })
        });
        if !selected
            || context["target_platform"]
                != json!({"state":"KNOWN","value":"qualification-frozen-platform"})
            || context["generated_inputs"] != json!({"state":"KNOWN","value":[]})
        {
            return Err(
                "fixture selection differs from exact caller-supplied context facts".into(),
            );
        }
    } else if model.program_context().configuration_known() {
        return Err("unselected fixture invented complete configuration knowledge".into());
    }
    Ok(())
}

fn evaluate(case: &ObservationCase) -> Result<Value, String> {
    let FixtureScope {
        files,
        compilation,
        observation,
        snapshot,
    } = build_scope(case)?;
    let ccg = compilation.graph().expect("validated scope CCG");
    let observed = match observe_rust_implementation(&observation) {
        Ok(observed) => observed,
        Err(error) => {
            let input = ProgramSemanticInput::new(ROOT, observation, [], []);
            let cold = compile_program_semantic_model(&input)
                .err()
                .map(|e| e.to_string());
            let prepared = prepare_program_semantics(&input, None)
                .err()
                .map(|e| e.to_string());
            let replay = prepare_program_semantics(&input, None)
                .err()
                .map(|e| e.to_string());
            return Ok(json!({"case_id":case.case_id,"status":"INVALID_DIAGNOSTIC",
                "observation_error":error.to_string(),"cold_error":cold,"prepared_error":prepared,
                "invalid_port_equivalence":cold.is_some() && cold==prepared && cold==replay,
                "limitation":"No invalid preparation can be admitted for reuse; valid cases exercise reuse and foreign-context reconstruction."}));
        }
    };
    let dependencies = observed
        .module_dependencies()
        .iter()
        .map(|d| (d.source_module().to_owned(), d.target_module().to_owned()));
    let original = ProgramSemanticInput::new(ROOT, observation.clone(), [], dependencies);
    let input = if case.context_selected {
        select_context(case, original.clone(), false)
    } else {
        original.clone()
    };
    let cold =
        compile_program_semantic_model(&input).map_err(|e| format!("invalid program: {e}"))?;
    verify_context(case, &cold)?;
    let first = prepare_program_semantics(&input, None).map_err(|e| e.to_string())?;
    let reused =
        prepare_program_semantics(&input, Some(first.preparation())).map_err(|e| e.to_string())?;
    let foreign = prepare_program_semantics(&select_context(case, original, true), None)
        .map_err(|e| e.to_string())?;
    if foreign.model.program_context().digest() == cold.program_context().digest() {
        return Err("foreign-context comparison did not change actual context".into());
    }
    let fallback = prepare_program_semantics(&input, Some(foreign.preparation()))
        .map_err(|e| e.to_string())?;
    let expected = derived(case, &cold, &observation, ccg)?;
    let equal_metadata_control = metadata_neutral(
        case,
        &files,
        &observation,
        &observed,
        ccg,
        &snapshot,
        &expected,
    )?;
    let equal = [&first.model, &reused.model, &fallback.model]
        .into_iter()
        .map(|model| derived(case, model, &observation, ccg).map(|actual| actual == expected))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .all(|equal| equal);
    let program_json: Value =
        serde_json::from_str(expected["program"].as_str().unwrap()).map_err(|e| e.to_string())?;
    let conformance: Value = serde_json::from_str(expected["conformance"].as_str().unwrap())
        .map_err(|e| e.to_string())?;
    // This summary is an observation only. The external scorer supplies truth.
    let module = conformance["modules"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["module"] == OWNER))
        .ok_or("owner conformance absent")?;
    let bytes = serde_json_canonicalizer::to_vec(&expected).map_err(|e| e.to_string())?;
    Ok(
        json!({"case_id":case.case_id,"status":"OBSERVED", "equal_differentials":equal,
        "equal_metadata_control":equal_metadata_control,
        "comparison_ports":["COLD","PREPARED","REUSED","FOREIGN_CONTEXT_RECONSTRUCTED"],
        "fallback":format!("{:?}",fallback.fallback()), "context":cold.program_context(),
        "context_digest":cold.program_context().digest(),"source_identity":cold.source_identity(),
        "authoritative_products_digest":digest(&bytes), "authoritative_products":expected,
        "module":module,"operation_inventory":program_json["operation_inventory"],
        "symbols":cold.symbols().len(), "blocking_vocabulary":serde_json::to_value(BlockingEligibility::BlockSupported).unwrap()}),
    )
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|a| a == "--reference") {
        return reference(&args[1..]);
    }
    if args.first().is_some_and(|a| a == "--validate-metadata") {
        return validate_metadata(&args[1..]);
    }
    if args.len() != 2 {
        return Err("expected bounded case input and exclusive observation output".into());
    }
    let source = fs::read(&args[0])?;
    if source.len() > 4 * 1024 * 1024 {
        return Err("case inputs exceed 4 MiB".into());
    }
    let cases: Vec<ObservationCase> = serde_json::from_slice(&source)?;
    if cases.is_empty() || cases.len() > 256 {
        return Err("case count outside bound".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[1])?;
    let mut total = 0_usize;
    for case in &cases {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluate(case)));
        let value = match result {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                json!({"case_id":case.case_id,"status":"INVALID_OR_UNAVAILABLE","error":error})
            }
            Err(_) => json!({"case_id":case.case_id,"status":"DRIVER_PANIC"}),
        };
        let bytes = serde_json::to_vec(&value)?;
        total = total
            .checked_add(bytes.len() + 1)
            .ok_or("observation size overflow")?;
        if total > 64 * 1024 * 1024 {
            return Err("observations exceed 64 MiB; retained prefix is incomplete".into());
        }
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.flush()?;
        output.sync_data()?;
    }
    Ok(())
}

fn validate_metadata(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 3 {
        return Err("expected qualification report, independent current inputs and scope".into());
    }
    let mut records = Vec::new();
    for path in args {
        let bytes = fs::read(path)?;
        if bytes.len() > 1024 * 1024 {
            return Err("qualification metadata exceeds 1 MiB".into());
        }
        records.push(String::from_utf8(bytes)?);
    }
    let report = fortress_core::qualification::QualificationManifest::from_json_str(&records[0])?;
    let current: fortress_core::qualification::QualificationInputs =
        fortress_core::wire::parse_public_json(&records[1])?;
    let scope = fortress_core::qualification::SupportedScope::from_json_str(&records[2])?;
    report.admit_for(&current, &scope)?;
    println!(
        "qualification metadata matches independently supplied current premises; authenticity UNVERIFIED"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceCase {
    case_id: String,
    first: u8,
    second: u8,
    second_reachable: bool,
    disposition: u8,
    denied_effect: u8,
    source: ReferenceSource,
    production: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceSource {
    has_subject: bool,
    has_support: bool,
    complete: bool,
}

fn reference(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 2 {
        return Err("expected reference-language input and exclusive output".into());
    }
    let source = fs::read(&args[0])?;
    if source.len() > 1024 * 1024 {
        return Err("reference inputs exceed 1 MiB".into());
    }
    let cases: Vec<ReferenceCase> = serde_json::from_slice(&source)?;
    if cases.is_empty() || cases.len() > 256 {
        return Err("reference case bound".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[1])?;
    for case in cases {
        let effects = oracle::expected_effects(case.first, case.second, case.second_reachable);
        let truth = oracle::expected_truth(
            case.disposition,
            case.denied_effect,
            effects,
            case.source.has_subject,
            case.source.has_support,
            case.source.complete,
        );
        let row = json!({"case_id":case.case_id,"effects":effects,"truth":truth,"blocking":oracle::expected_blocking(truth,case.production)});
        output.write_all(&serde_json::to_vec(&row)?)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("semantic qualification observation failed: {error}");
        std::process::exit(1);
    }
}
