//! Declared-boundary qualification, independent of effect-policy conclusions.
use fortress_core::information_flow::{FLOW_PROFILE_ID, analyze_information_flow_with_profile};

use super::{
    InformationFlowAnalysisError, InformationFlowEvaluation, InformationFlowPolicy,
    InformationFlowPolicyError, InformationFlowPolicySource, ProgramSemanticModel,
    analyze_program_domains, analyze_state_effects, canonicalize_information_flow_policy_json,
    json, load_function_contracts, load_information_flow_policy, load_state_contracts, policy,
    program_input, psm,
};

fn operation_policy(
    model: &ProgramSemanticModel,
    source: &str,
    sink: &str,
) -> InformationFlowPolicy {
    let mut document = serde_json::to_value(policy()).unwrap();
    document = serde_json::json!({
        "$schema":"urn:fortress:schema:v2:information-flow-policy", "schema_version":2,
        "facets":document["facets"],
        "sources":[{"operation_selector":{"reference":source,"context_digest":model.program_context().digest()},"output_slot":{"kind":"return"},"facet":"FLOW-CONFIDENTIALITY","level":"SECRET"}],
        "sinks":[{"operation_selector":{"reference":sink,"context_digest":model.program_context().digest()},"input_slot":{"kind":"parameter","position":0},"facet":"FLOW-CONFIDENTIALITY","bound":"PUBLIC"}],
        "transforms":[]
    });
    let bytes =
        canonicalize_information_flow_policy_json("fixture", &document.to_string()).unwrap();
    load_information_flow_policy(vec![InformationFlowPolicySource::new(
        "__fortress/governance/information_flow_policy.json",
        bytes,
    )])
    .unwrap()
}

fn evaluate_operations(
    model: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    selected: bool,
) -> Result<InformationFlowEvaluation, InformationFlowAnalysisError> {
    let contracts = load_function_contracts(model, vec![]).unwrap();
    let semantic = analyze_program_domains(model, &contracts, "1.0.0-draft.1").unwrap();
    let states = load_state_contracts(model, vec![]).unwrap();
    let effects =
        analyze_state_effects(model, &semantic, &states, &contracts, "1.0.0-draft.1").unwrap();
    analyze_information_flow_with_profile(
        model,
        &semantic,
        &effects,
        policy,
        &contracts,
        "1.0.0-draft.1",
        selected,
    )
}

/// `T-AF-INFORMATION-FLOW-0001-R05-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn declared_external_source_to_sink_leak_is_detected() {
    assert_eq!(FLOW_PROFILE_ID, "GOV-FORTRESS-DECLARED-FLOW");
    let model = psm("fn log(value:u32){} fn send(){let secret=std::process::id();log(secret);}");
    let policy = operation_policy(&model, "std::process::id", "sample::log");
    let value = evaluate_operations(&model, &policy, true).unwrap();
    assert_eq!(value.findings().len(), 1);
    let coverage = &json(&value)["coverage"];
    assert_eq!(coverage["classified_sources"], 1);
    assert_eq!(coverage["declared_sinks"], 1);
    assert_eq!(coverage["sink_checks"], 1);
    assert_eq!(coverage["sink_violations"], 1);
    assert_eq!(coverage["unknown_sinks"], 0);
    assert_eq!(
        json(&value)["operation_claims"][0]["verdict"],
        "SUPPORTED_VIOLATION"
    );
}

fn edit_policy(
    policy: &InformationFlowPolicy,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<InformationFlowPolicy, InformationFlowPolicyError> {
    let mut value = serde_json::to_value(policy).unwrap();
    value = serde_json::json!({"$schema":"urn:fortress:schema:v2:information-flow-policy","schema_version":2,"facets":value["facets"],"sources":value["sources"],"sinks":value["sinks"],"transforms":value["transforms"]});
    edit(&mut value);
    let bytes = canonicalize_information_flow_policy_json("fixture", &value.to_string())?;
    load_information_flow_policy(vec![InformationFlowPolicySource::new(
        "__fortress/governance/information_flow_policy.json",
        bytes,
    )])
}

/// `T-AF-INFORMATION-FLOW-0001-R05-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn explicit_permitted_transform_has_visible_trust_basis() {
    let model = psm(
        "fn credential()->u8{7} fn redact(value:u8)->u8{0} fn log(value:u8){} fn send(){let secret=credential();let clean=redact(secret);log(clean);}",
    );
    let original = operation_policy(&model, "sample::credential", "sample::log");
    let policy = edit_policy(&original,|doc|doc["transforms"]=serde_json::json!([{
        "operation_selector":{"reference":"sample::redact","context_digest":model.program_context().digest()},
        "input_to_output":{"input":{"kind":"parameter","position":0},"output":{"kind":"return"}},
        "classification_rule":{"kind":"declassification","facet":"FLOW-CONFIDENTIALITY","from":"SECRET","to":"PUBLIC"},
        "trust_basis":{"authority_ref":"review:redaction-assumption","rationale":"Explicitly accepted intent, implementation unverified","state":"DECLARED_ASSUMPTION"}
    }])).unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty(), "{}", json(&result));
    let claim = &json(&result)["operation_claims"][0];
    assert_eq!(claim["verdict"], "NOT_EVALUABLE");
    assert!(!claim["assumptions"].as_array().unwrap().is_empty());
    assert!(
        claim["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(
                "TRANSFORMATION_IMPLEMENTATION_NOT_PROVEN"
            ))
    );
    let duplicate = duplicate_resolved_boundary(&model, &policy, "transforms", "sample::redact");
    assert!(evaluate_operations(&model, &duplicate, true).is_err());
}

/// `T-AF-INFORMATION-FLOW-0001-R05-003`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn unrelated_flow_is_not_a_violation() {
    let model = psm(
        "fn credential()->u8{7} fn public()->u8{0} fn log(value:u8){} fn send(){let unused=credential();let clean=public();log(clean);}",
    );
    let policy = edit_policy(
        &operation_policy(&model, "sample::credential", "sample::log"),
        |doc| {
            let mut source = doc["sources"][0].clone();
            source["operation_selector"]["reference"] = serde_json::json!("sample::public");
            source["level"] = serde_json::json!("PUBLIC");
            doc["sources"].as_array_mut().unwrap().push(source);
        },
    )
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty());
    assert_eq!(
        json(&result)["operation_claims"][0]["verdict"],
        "NO_SUPPORTED_VIOLATION"
    );
    let leak = psm(
        "fn credential()->u8{7} fn public()->u8{0} fn log(value:u8){} fn send(){let unused=credential();let clean=public();log(unused);}",
    );
    assert_eq!(effect_signature(&model), effect_signature(&leak));
    let calls = |p: &ProgramSemanticModel| {
        p.calls()
            .iter()
            .map(|c| {
                (
                    c.caller().to_owned(),
                    c.callee().map(str::to_owned),
                    c.external_target().map(str::to_owned),
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(calls(&model), calls(&leak));
    assert_eq!(
        json(&evaluate_operations(&leak, &policy, true).unwrap())["operation_claims"][0]["verdict"],
        "SUPPORTED_VIOLATION"
    );
}

fn effect_signature(model: &ProgramSemanticModel) -> serde_json::Value {
    let contracts = load_function_contracts(model, vec![]).unwrap();
    let semantic = analyze_program_domains(model, &contracts, "1.0.0-draft.1").unwrap();
    let states = load_state_contracts(model, vec![]).unwrap();
    let result =
        analyze_state_effects(model, &semantic, &states, &contracts, "1.0.0-draft.1").unwrap();
    serde_json::json!(
        result
            .model()
            .summaries()
            .iter()
            .map(|s| (s.symbol(), s.direct_effects(), s.transitive_effects()))
            .collect::<Vec<_>>()
    )
}

/// `T-AF-INFORMATION-FLOW-0001-R05-004`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn unknown_alias_or_callback_is_not_clean() {
    let model = psm(
        "fn credential()->u8{7} fn log(value:u8){} fn send(callback:fn(u8)->u8){let secret=credential();let opaque=callback(secret);log(opaque);}",
    );
    let policy = operation_policy(&model, "sample::credential", "sample::log");
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty(), "{}", json(&result));
    assert_eq!(json(&result)["coverage"]["sink_checks"], 1);
    assert_eq!(json(&result)["coverage"]["unknown_sinks"], 1);
    assert_eq!(json(&result)["coverage"]["sink_verification"], "PARTIAL");
    assert_eq!(
        json(&result)["operation_claims"][0]["verdict"],
        "NOT_EVALUABLE"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-005`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn one_classified_argument_does_not_cover_an_unclassified_invocation() {
    let model = psm(
        "fn public()->u8{0} fn log(value:u8){} fn send(opaque:u8){let clean=public();log(clean);log(opaque);}",
    );
    let original = operation_policy(&model, "sample::public", "sample::log");
    let policy = edit_policy(&original, |doc| {
        doc["sources"][0]["level"] = serde_json::json!("PUBLIC");
    })
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty());
    assert_eq!(
        json(&result)["operation_claims"][0]["verdict"],
        "NOT_EVALUABLE"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-006`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn reassignment_and_path_feasibility_do_not_manufacture_proofs() {
    for source in [
        "fn credential()->u8{7} fn public()->u8{0} fn log(value:u8){} fn send(){let mut secret=credential();secret=public();log(secret);}",
        "fn credential()->u8{7} fn log(value:u8){} fn send(){let secret=credential();if false {log(secret);}}",
        "fn credential()->u8{7} fn log(value:u8){} fn send(){let mut secret=credential();let alias=&mut secret;*alias=0;log(secret);}",
    ] {
        let model = psm(source);
        let policy = operation_policy(&model, "sample::credential", "sample::log");
        let result = evaluate_operations(&model, &policy, true).unwrap();
        assert!(result.findings().is_empty(), "{}", json(&result));
        assert_eq!(
            json(&result)["operation_claims"][0]["verdict"],
            "NOT_EVALUABLE"
        );
    }
}

/// `T-AF-INFORMATION-FLOW-0001-R05-007`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn exported_evidence_omits_secret_literals_by_default() {
    let model = psm(
        "fn credential()->&'static str{\"ACTUAL_SECRET_MUST_NOT_BE_EXPORTED\"} fn log(value:&str){} fn send(){let secret=credential();log(secret);}",
    );
    let result = evaluate_operations(
        &model,
        &operation_policy(&model, "sample::credential", "sample::log"),
        true,
    )
    .unwrap();
    let bytes = result.model().to_canonical_json().unwrap();
    assert!(!bytes.contains("ACTUAL_SECRET_MUST_NOT_BE_EXPORTED"));
    assert_eq!(result.findings().len(), 1);
}

/// `T-AF-INFORMATION-FLOW-0001-R05-008`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn duplicate_and_contradictory_policies_are_rejected() {
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let original = operation_policy(&model, "sample::credential", "sample::log");
    assert!(
        edit_policy(&original, |doc| {
            let value = doc["sources"][0].clone();
            doc["sources"].as_array_mut().unwrap().push(value);
        })
        .is_err()
    );
    assert!(
        edit_policy(&original, |doc| {
            let mut value = doc["sources"][0].clone();
            value["level"] = serde_json::json!("PUBLIC");
            doc["sources"].as_array_mut().unwrap().insert(0, value);
        })
        .is_err()
    );
    for (kind, name) in [("sources", "sample::credential"), ("sinks", "sample::log")] {
        let duplicate = duplicate_resolved_boundary(&model, &original, kind, name);
        assert!(evaluate_operations(&model, &duplicate, true).is_err());
    }
}

fn duplicate_resolved_boundary(
    model: &ProgramSemanticModel,
    policy: &InformationFlowPolicy,
    kind: &str,
    name: &str,
) -> InformationFlowPolicy {
    let id = model
        .symbols()
        .iter()
        .find(|s| s.qualified_name() == name)
        .unwrap()
        .id();
    edit_policy(policy, |doc| {
        let mut alias = doc[kind][0].clone();
        alias["operation_selector"]["reference"] = serde_json::json!(id);
        doc[kind].as_array_mut().unwrap().push(alias);
        doc[kind].as_array_mut().unwrap().sort_by(|a, b| {
            a["operation_selector"]["reference"]
                .as_str()
                .cmp(&b["operation_selector"]["reference"].as_str())
        });
    })
    .unwrap()
}

/// `T-AF-INFORMATION-FLOW-0001-R05-009`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn author_preview_is_readable_unapproved_and_context_bound() {
    use fortress_core::information_flow::{FlowAuthorParameters, preview_operation_policy};
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let preview = preview_operation_policy(
        &model,
        &policy(),
        &FlowAuthorParameters {
            source: "sample::credential".into(),
            sink: "sample::log".into(),
            facet: "FLOW-CONFIDENTIALITY".into(),
            level: "SECRET".into(),
            bound: "PUBLIC".into(),
            parameter: 0,
        },
    )
    .unwrap();
    assert_eq!(preview["acceptance"], "UNAPPROVED");
    assert_eq!(preview["context_ref"], model.program_context().digest());
    assert!(
        preview["canonical_policy_preview"]
            .as_str()
            .unwrap()
            .contains("sample::credential")
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-010`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn optional_profile_nonselection_is_not_pass() {
    let model = psm("fn credential()->u8{7} fn log(value:u8){} fn send(){log(credential());}");
    let policy = operation_policy(&model, "sample::credential", "sample::log");
    let value = evaluate_operations(&model, &policy, false).unwrap();
    assert!(value.findings().is_empty());
    assert_eq!(json(&value)["coverage"]["sink_checks"], 0);
    assert_eq!(
        json(&value)["operation_claims"][0]["reason_codes"],
        serde_json::json!(["FLOW_PROFILE_NOT_SELECTED_FOR_SCOPE"])
    );
    assert!(
        json(&value)["operation_claims"][0]["defeaters"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        json(&value)["operation_claims"][0]["verdict"],
        "NOT_APPLICABLE"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-011`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn operation_version_mismatch_breaks_binding() {
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let mut document: serde_json::Value = serde_json::from_str(&canonicalize_information_flow_policy_json("fixture", &serde_json::json!({
        "$schema":"urn:fortress:schema:v2:information-flow-policy","schema_version":2,"facets":serde_json::to_value(policy()).unwrap()["facets"],
        "sources":[],"sinks":[],"transforms":[]
    }).to_string()).unwrap()).unwrap();
    document["sources"] = serde_json::json!([{"operation_selector":{"reference":"sample::credential","context_digest":format!("sha256:{}","0".repeat(64))},"output_slot":{"kind":"return"},"facet":"FLOW-CONFIDENTIALITY","level":"SECRET"}]);
    let bytes =
        canonicalize_information_flow_policy_json("fixture", &document.to_string()).unwrap();
    let policy = load_information_flow_policy(vec![InformationFlowPolicySource::new(
        "__fortress/governance/information_flow_policy.json",
        bytes,
    )])
    .unwrap();
    assert!(evaluate_operations(&model, &policy, true).is_err());
}

/// `T-AF-INFORMATION-FLOW-0001-R05-012`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn ambiguous_qualified_operation_names_are_never_selected_by_order() {
    let model = psm(
        "struct Service; trait First{fn read()->u8;} trait Second{fn read()->u8;} impl First for Service{fn read()->u8{1}} impl Second for Service{fn read()->u8{2}} fn log(value:u8){}",
    );
    let matches = model
        .symbols()
        .iter()
        .filter(|v| v.qualified_name() == "sample::Service::read")
        .count();
    assert_eq!(
        matches, 2,
        "qualified operation fixture must actually be ambiguous"
    );
    let policy = operation_policy(&model, "sample::Service::read", "sample::log");
    let error = evaluate_operations(&model, &policy, true).unwrap_err();
    assert!(error.to_string().contains("AMBIGUOUS_OPERATION"));
}

/// `T-AF-INFORMATION-FLOW-0001-R05-013`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn cold_and_prepared_operation_results_are_byte_identical() {
    use fortress_core::program_semantics::prepare_program_semantics;
    let input = program_input(
        "fn credential()->u8{7} fn forward(value:u8)->u8{value} fn log(value:u8){} fn send(){let secret=credential();let moved=forward(secret);log(moved);}",
    );
    let cold = prepare_program_semantics(&input, None).unwrap();
    let prepared = prepare_program_semantics(&input, Some(&cold.preparation)).unwrap();
    let policy = operation_policy(&cold.model, "sample::credential", "sample::log");
    let first = evaluate_operations(&cold.model, &policy, true).unwrap();
    let second = evaluate_operations(&prepared.model, &policy, true).unwrap();
    assert_eq!(
        first.model().to_canonical_json().unwrap(),
        second.model().to_canonical_json().unwrap()
    );
    assert_eq!(first.findings().len(), 1);
}

/// `T-AF-INFORMATION-FLOW-0001-R05-014`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn multiple_facets_remain_independent() {
    let model = psm(
        "fn credential()->u8{7} fn log(value:u8){} fn send(){let secret=credential();log(secret);}",
    );
    let policy = edit_policy(
        &operation_policy(&model, "sample::credential", "sample::log"),
        |doc| {
            let mut source = doc["sources"][0].clone();
            source["facet"] = serde_json::json!("FLOW-INTEGRITY");
            source["level"] = serde_json::json!("TRUSTED");
            doc["sources"].as_array_mut().unwrap().push(source);
            let mut sink = doc["sinks"][0].clone();
            sink["facet"] = serde_json::json!("FLOW-INTEGRITY");
            sink["bound"] = serde_json::json!("VALIDATED");
            doc["sinks"].as_array_mut().unwrap().push(sink);
        },
    )
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    let claims = json(&result)["operation_claims"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(claims.len(), 2);
    assert_eq!(result.findings().len(), 1);
    assert_eq!(
        claims
            .iter()
            .find(|v| v["facet"] == "FLOW-INTEGRITY")
            .unwrap()["verdict"],
        "NO_SUPPORTED_VIOLATION"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-015`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn shared_helper_contexts_do_not_manufacture_violation_witnesses() {
    let model = psm(
        "fn credential()->u8{7} fn public()->u8{0} fn forward(value:u8)->u8{value} fn log(value:u8){} fn send(){let secret=credential();let unused=forward(secret);let clean=public();let moved=forward(clean);log(moved);}",
    );
    let policy = edit_policy(
        &operation_policy(&model, "sample::credential", "sample::log"),
        |doc| {
            let mut source = doc["sources"][0].clone();
            source["operation_selector"]["reference"] = serde_json::json!("sample::public");
            source["level"] = serde_json::json!("PUBLIC");
            doc["sources"].as_array_mut().unwrap().push(source);
        },
    )
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty(), "{}", json(&result));
    assert_eq!(
        json(&result)["operation_claims"][0]["verdict"],
        "NOT_EVALUABLE"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-020`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn a_supported_production_witness_survives_other_test_and_unknown_paths() {
    let model = psm(
        "fn credential()->u8{7} fn log(value:u8){} fn production(){let secret=credential();log(secret);} #[test] fn other(){let mut secret=credential();secret=0;log(secret);}",
    );
    let result = evaluate_operations(
        &model,
        &operation_policy(&model, "sample::credential", "sample::log"),
        true,
    )
    .unwrap();
    assert_eq!(result.findings().len(), 1, "{}", json(&result));
    assert_eq!(
        result.findings()[0].enforcement_eligibility(),
        fortress_core::finding::FindingEnforcementEligibility::BlockSupported
    );
    let claim = &json(&result)["operation_claims"][0];
    assert_eq!(claim["coverage"]["blocking_eligibility"], "BLOCK_SUPPORTED");
    assert_eq!(claim["operation_name"], "sample::log");
    assert!(
        claim["source_names"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("sample::credential"))
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-021`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn field_slots_bind_only_observed_nominal_members_and_remain_precision_limited() {
    let model = psm(
        "struct Cache{value:u8} impl Cache{fn load(&self)->u8{self.value}} fn log(value:u8){} fn send(cache:&Cache){let value=cache.load();log(value);}",
    );
    let original = operation_policy(&model, "sample::Cache::load", "sample::log");
    let policy = edit_policy(&original, |doc| {
        doc["sources"][0]["output_slot"] =
            serde_json::json!({"kind":"field","owner":"sample::Cache","field":"value"});
    })
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    assert!(result.findings().is_empty());
    assert_eq!(
        json(&result)["operation_claims"][0]["verdict"],
        "NOT_EVALUABLE"
    );
    let bad = edit_policy(&policy, |doc| {
        doc["sources"][0]["output_slot"]["field"] = serde_json::json!("missing");
    })
    .unwrap();
    assert!(evaluate_operations(&model, &bad, true).is_err());
}

/// `T-AF-INFORMATION-FLOW-0001-R05-022`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn source_formatting_and_local_renaming_preserve_finding_identity() {
    let first = psm(
        "fn credential()->u8{7} fn log(value:u8){} fn send(){let secret=credential();log(secret);}",
    );
    let second = psm(
        "// relocated lines\nfn credential()->u8{7}\nfn log(renamed:u8){}\nfn send(){let moved=credential();log(moved);}\n",
    );
    let policy = operation_policy(&first, "sample::credential", "sample::log");
    let original = evaluate_operations(&first, &policy, true).unwrap();
    let moved = evaluate_operations(&second, &policy, true).unwrap();
    assert_eq!(
        original.findings()[0].finding_id(),
        moved.findings()[0].finding_id()
    );
    assert_ne!(
        original.model().digest().unwrap(),
        moved.model().digest().unwrap()
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-023`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn public_claim_versions_binding_and_unknown_favorability_are_validated() {
    use fortress_core::information_flow::validate_operation_claim_projection;
    let model =
        psm("fn public()->u8{0} fn log(value:u8){} fn send(){let clean=public();log(clean);}");
    let policy = edit_policy(
        &operation_policy(&model, "sample::public", "sample::log"),
        |doc| doc["sources"][0]["level"] = serde_json::json!("PUBLIC"),
    )
    .unwrap();
    let result = evaluate_operations(&model, &policy, true).unwrap();
    let claim = json(&result)["operation_claims"][0].clone();
    let context = model.program_context().digest();
    validate_operation_claim_projection(&claim, &context).unwrap();
    for (pointer, value) in [
        ("/schema_version", serde_json::json!(99)),
        (
            "/coverage/context_ref",
            serde_json::json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("/coverage/parsed_source_files", serde_json::json!(0)),
        ("/assumptions", serde_json::json!(["unverified-transform"])),
    ] {
        let mut bad = claim.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_operation_claim_projection(&bad, &context).is_err(),
            "{bad}"
        );
    }
}

/// `T-AF-INFORMATION-FLOW-0001-R05-024`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn policy_resource_limits_fail_without_attempting_analysis() {
    let facets=(0..65).map(|i|serde_json::json!({"id":format!("FLOW-FACET-{i:03}"),"direction":"higher_is_more_restricted","levels":["PUBLIC","SECRET"]})).collect::<Vec<_>>();
    let document = serde_json::json!({"$schema":"urn:fortress:schema:v2:information-flow-policy","schema_version":2,"facets":facets,"sources":[],"sinks":[],"transforms":[]});
    let bytes =
        canonicalize_information_flow_policy_json("fixture", &document.to_string()).unwrap();
    assert!(
        load_information_flow_policy(vec![InformationFlowPolicySource::new(
            "__fortress/governance/information_flow_policy.json",
            bytes
        )])
        .is_err()
    );
    assert!(
        load_information_flow_policy(vec![InformationFlowPolicySource::new(
            "__fortress/governance/information_flow_policy.json",
            " ".repeat(1_048_577)
        )])
        .is_err()
    );
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let policy = operation_policy(&model, "sample::credential", "sample::log");
    assert!(
        edit_policy(&policy, |doc| {
            let oversized = "X".repeat(1025);
            for facet in doc["facets"].as_array_mut().unwrap() {
                if facet["id"] == "FLOW-CONFIDENTIALITY" {
                    for level in facet["levels"].as_array_mut().unwrap() {
                        if level == "SECRET" {
                            *level = serde_json::json!(oversized);
                        }
                    }
                }
            }
            doc["sources"][0]["level"] = serde_json::json!(oversized);
        })
        .is_err()
    );
    let oversized_field = edit_policy(&policy, |doc| {
        doc["sources"][0]["output_slot"] =
            serde_json::json!({"kind":"field","owner":"sample::Cache","field":"x".repeat(1025)});
    })
    .unwrap();
    assert!(
        evaluate_operations(&model, &oversized_field, true)
            .unwrap_err()
            .to_string()
            .contains("FIELD_SLOT_STRING_RESOURCE_LIMIT")
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-016`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn forged_transformation_authentication_is_rejected() {
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let policy = operation_policy(&model, "sample::credential", "sample::log");
    let result = edit_policy(&policy, |doc| {
        doc["transforms"] = serde_json::json!([{
            "operation_selector":{"reference":"sample::credential","context_digest":model.program_context().digest()},
            "input_to_output":{"input":{"kind":"return"},"output":{"kind":"return"}},
            "classification_rule":{"kind":"declassification","facet":"FLOW-CONFIDENTIALITY","from":"SECRET","to":"PUBLIC"},
            "trust_basis":{"authority_ref":"unsigned-local-approval","rationale":"I approved myself","state":"AUTHENTICATED"}
        }]);
    });
    assert!(result.is_err());
}

/// `T-AF-INFORMATION-FLOW-0001-R05-017`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn scoped_profile_nonselection_preserves_applicability() {
    use fortress_core::information_flow::{FlowSelection, analyze_information_flow_with_selection};
    let model = psm(
        "fn credential()->u8{7} fn log(value:u8){} fn send(){let secret=credential();log(secret);}",
    );
    let policy = operation_policy(&model, "sample::credential", "sample::log");
    let contracts = load_function_contracts(&model, vec![]).unwrap();
    let semantic = analyze_program_domains(&model, &contracts, "1.0.0-draft.1").unwrap();
    let states = load_state_contracts(&model, vec![]).unwrap();
    let effects =
        analyze_state_effects(&model, &semantic, &states, &contracts, "1.0.0-draft.1").unwrap();
    for (module, expected) in [
        ("AF-SAMPLE-0001", "SUPPORTED_VIOLATION"),
        ("AF-UNRELATED-0001", "NOT_APPLICABLE"),
    ] {
        let selection = FlowSelection {
            project: false,
            modules: std::collections::BTreeSet::from([module.into()]),
        };
        let result = analyze_information_flow_with_selection(
            &model,
            &semantic,
            &effects,
            &policy,
            &contracts,
            "1.0.0-draft.1",
            &selection,
        )
        .unwrap();
        assert_eq!(json(&result)["operation_claims"][0]["verdict"], expected);
    }
}

/// `T-AF-INFORMATION-FLOW-0001-R05-018`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn loaded_rpc_preview_is_read_only_versioned_and_cancellable() {
    use fortress_core::query::{QueryInput, QueryRequest, QueryService};
    use std::sync::atomic::AtomicBool;
    let model = psm("fn credential()->u8{7} fn log(value:u8){}");
    let source = model.source_identity().to_owned();
    let context = model.program_context().digest();
    assert!(
        QueryService::new(QueryInput::empty(source.clone()))
            .unwrap()
            .with_flow_context(
                &format!("sha256:{}", "0".repeat(64)),
                model.clone(),
                policy()
            )
            .is_err()
    );
    let service = QueryService::new(QueryInput::empty(source.clone()))
        .unwrap()
        .with_flow_context(&source, model, policy())
        .unwrap();
    let mut request = QueryRequest {
        protocol_version: 3,
        request_id: "preview".into(),
        method: "flow_author".into(),
        state_ref: None,
        context_ref: Some(context.clone()),
        parameters: serde_json::json!({"source":"sample::credential","sink":"sample::log","facet":"FLOW-CONFIDENTIALITY","level":"SECRET","bound":"PUBLIC"}),
    };
    let response = service.execute(&request, &AtomicBool::new(false));
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.context_ref, Some(context));
    assert!(response.to_human().contains("UNAPPROVED"));
    assert_eq!(
        response.to_canonical_bytes().unwrap(),
        service
            .execute(&request, &AtomicBool::new(false))
            .to_canonical_bytes()
            .unwrap()
    );
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(true))
            .error
            .unwrap()
            .code,
        "CANCELLED"
    );
    request.protocol_version = 2;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNKNOWN_METHOD"
    );
    request.protocol_version = 99;
    assert_eq!(
        service
            .execute(&request, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "UNSUPPORTED_VERSION"
    );
}

/// `T-AF-INFORMATION-FLOW-0001-R05-019`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R05
#[test]
fn independently_compiled_source_controls_qualify_the_bounded_envelope() {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let corpus = include_str!("../_data/operation_cases_v1.json");
    let corpus: serde_json::Value = fortress_core::wire::parse_public_json(corpus).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut executable_source = String::from("#![allow(dead_code,unused_variables)]\n");
    let mut main = String::from("fn main(){");
    let mut expected_output = String::new();
    let mut results = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let source = case["source"].as_str().unwrap();
        let model = psm(source);
        let mut policy =
            operation_policy(&model, "sample::credential", case["sink"].as_str().unwrap());
        if case["id"] == "unrelated_flow" {
            policy = edit_policy(&policy, |doc| {
                let mut source = doc["sources"][0].clone();
                source["operation_selector"]["reference"] = serde_json::json!("sample::public");
                source["level"] = serde_json::json!("PUBLIC");
                doc["sources"].as_array_mut().unwrap().push(source);
            })
            .unwrap();
        }
        if case["transform"] == true {
            policy=edit_policy(&policy,|doc|doc["transforms"]=serde_json::json!([{
                "operation_selector":{"reference":"sample::redact","context_digest":model.program_context().digest()},
                "input_to_output":{"input":{"kind":"parameter","position":0},"output":{"kind":"return"}},
                "classification_rule":{"kind":"declassification","facet":"FLOW-CONFIDENTIALITY","from":"SECRET","to":"PUBLIC"},
                "trust_basis":{"authority_ref":"research:explicit-assumption","rationale":"Intent remains independent of executable source adjudication","state":"DECLARED_ASSUMPTION"}
            }])).unwrap();
        }
        let result = evaluate_operations(&model, &policy, true).unwrap();
        assert_eq!(
            json(&result)["operation_claims"][0]["verdict"],
            case["verdict"],
            "{}: {}",
            case["id"],
            json(&result)
        );
        // This oracle invokes the actual standalone source with every input in
        // its finite domain. It imports neither Fortress nor its expected labels.
        let check = match case["oracle"].as_str().unwrap() {
            "IDENTITY" => "assert_eq!(entry(seed),seed);",
            "ZERO" => "assert_eq!(entry(seed),0);",
            "BOTH_CALLBACKS" => {
                "assert_eq!(entry(seed,|value|value),seed);assert_eq!(entry(seed,|_|0),0);"
            }
            _ => panic!("unknown frozen source oracle"),
        };
        let prefix = if case["sink"].as_str().unwrap().ends_with("::log") {
            "log"
        } else {
            "telemetry"
        };
        for seed in 0..=u8::MAX {
            match case["oracle"].as_str().unwrap() {
                "IDENTITY" => writeln!(expected_output, "{prefix}:{seed}").unwrap(),
                "ZERO" => writeln!(expected_output, "{prefix}:0").unwrap(),
                "BOTH_CALLBACKS" => {
                    writeln!(expected_output, "{prefix}:{seed}\n{prefix}:0").unwrap();
                }
                _ => unreachable!("frozen oracle vocabulary"),
            }
        }
        writeln!(executable_source,"mod case_{index}{{{source}\npub fn adjudicate(){{for seed in 0..=u8::MAX{{{check}}}}}}}").unwrap();
        write!(main, "case_{index}::adjudicate();").unwrap();
        results.push(serde_json::json!({"id":case["id"],"source_digest":format!("sha256:{:x}",Sha256::digest(source.as_bytes())),"verdict":case["verdict"],"runtime_oracle":case["oracle"]}));
    }
    main.push_str("println!(\"finite-source-controls-ok\");}\n");
    executable_source.push_str(&main);
    expected_output.push_str("finite-source-controls-ok\n");
    execute_source_controls(&executable_source, &expected_output);
    let report = serde_json::json!({"method":"PINNED_COMPILER_EXHAUSTIVE_U8_SOURCE_CONTROLS","cases":results,"integrity":"SOURCE_BOUND","authenticity":"UNVERIFIED","human_adjudication":"NOT_PERFORMED","limitations":"Authored standalone consumer controls; no population accuracy or comprehensive security claim. Runtime control execution is separate from target application execution evidence."});
    println!("{report}");
}

fn reference_process(
    workspace: &mut fortress_core::runtime_storage::RunWorkspace,
    command: &mut std::process::Command,
    key: &str,
) -> String {
    use std::{
        fs,
        process::Stdio,
        time::{Duration, Instant},
    };
    let stdout = workspace.staging().join(format!("{key}.stdout"));
    let stderr = workspace.staging().join(format!("{key}.stderr"));
    let mut child = command
        .stdin(Stdio::null())
        .stdout(fs::File::create_new(&stdout).unwrap())
        .stderr(fs::File::create_new(&stderr).unwrap())
        .spawn()
        .unwrap();
    let pid = child.id();
    workspace.record_child(pid).unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        // An execution watchdog and output budget are resource-safety bounds,
        // not a performance certification target or benchmark.
        if start.elapsed() > Duration::from_mins(10)
            || fs::metadata(&stdout).unwrap().len() > 65_536
            || fs::metadata(&stderr).unwrap().len() > 65_536
        {
            child.kill().unwrap();
            child.wait().unwrap();
            workspace.clear_child(pid).unwrap();
            panic!("source-control execution resource limit");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    child.wait().unwrap();
    workspace.clear_child(pid).unwrap();
    assert!(status.success(), "{}", fs::read_to_string(stderr).unwrap());
    fs::read_to_string(stdout).unwrap().replace("\r\n", "\n")
}

fn execute_source_controls(executable_source: &str, expected_output: &str) {
    use fortress_core::runtime_storage::{RuntimeStorage, StoragePolicy};
    use std::{fs, process::Command};
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fortress-flow-reference-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let subject = directory.join("subject");
    fs::create_dir(&subject).unwrap();
    fs::create_dir(directory.join("storage")).unwrap();
    let storage = RuntimeStorage::new(
        &subject,
        &directory.join("storage"),
        StoragePolicy {
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        },
    )
    .unwrap();
    let mut workspace = storage.acquire_workspace().unwrap();
    workspace.reserve(16 * 1024 * 1024).unwrap();
    let source = workspace.staging().join("reference.rs");
    fs::write(&source, executable_source).unwrap();
    let binary = workspace.compiler_target().join(if cfg!(windows) {
        "reference.exe"
    } else {
        "reference"
    });
    let mut compiler = Command::new("rustup");
    compiler
        .args(["run", "1.97.1", "rustc", "--edition=2024"])
        .arg(&source)
        .arg("-o")
        .arg(&binary);
    reference_process(&mut workspace, &mut compiler, "compile");
    let output = reference_process(&mut workspace, &mut Command::new(&binary), "execute");
    assert_eq!(output, expected_output);
    workspace.release().unwrap();
    // Every recursively removed path belongs to this freshly created fixture.
    assert!(
        directory
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    fs::remove_dir_all(directory).unwrap();
}
