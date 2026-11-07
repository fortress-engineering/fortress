//! Read-only query and protocol acceptance controls over immutable upstream results.

use std::sync::atomic::AtomicBool;

use fortress_core::query::{QueryInput, QueryRequest, QueryService};
use serde_json::{Value, json};

fn binding() -> fortress_core::declaration::DeclarationBinding {
    fortress_core::declaration::DeclarationBinding {
        subject_ref: format!("sha256:{}", "a".repeat(64)),
        context_ref: format!("sha256:{}", "b".repeat(64)),
        authority_ref: format!("sha256:{}", "c".repeat(64)),
    }
}

fn application_input() -> QueryInput {
    application_fixture(true)
}

fn application_fixture(violation: bool) -> QueryInput {
    use fortress_core::assessment::*;
    use fortress_core::declaration::*;
    let binding = binding();
    let manifest = DimensionManifest {
        profiles: vec![ScopedProfileReference {
            module: None,
            id: "PROFILE".into(),
            version: "1.0.0".into(),
            digest: binding.authority_ref.clone(),
        }],
        dimensions: vec![RequiredDimension {
            id: "RULES".into(),
            claim_refs: vec!["claim-one".into()],
        }],
    };
    let claim = DeclarationClaim {
        kind: DeclarationClaimKind::RuleCheck,
        id: "claim-one".into(),
        scope_ref: "rule:STD-ID-001".into(),
        truth: if violation {
            DeclarationTruth::SupportedViolation
        } else {
            DeclarationTruth::NoSupportedViolation
        },
        proof_refs: vec!["leaf".into()],
        findings: if violation {
            vec!["finding-one".into()]
        } else {
            vec![]
        },
        defeater_refs: vec![],
        reason_codes: if violation {
            vec!["KNOWN_CONTRADICTION".into()]
        } else {
            vec![]
        },
        assumptions: vec![],
        semantic_claim: None,
        rule_result: Some(RuleClaimDetail {
            outcome: if violation {
                fortress_core::application::ApplicationRuleOutcome::Failed
            } else {
                fortress_core::application::ApplicationRuleOutcome::Passed
            },
            applicable: true,
            applicability_reason: None,
            detail: "An observed identifier violates the governing grammar.".into(),
        }),
    };
    let declaration = ConformanceDeclaration::compose(
        binding.clone(),
        manifest.clone(),
        vec![claim],
        vec![],
        DeclarationResidue {
            accepted_baseline: if violation {
                vec!["finding-one".into()]
            } else {
                vec![]
            },
            accepted_exceptions: vec![],
            blocking_findings: vec![],
        },
    )
    .unwrap();
    let obligations = fixture_obligations();
    let (leaf, acceptance) = fixture_evidence(&binding, violation);
    let expected = ExpectedProfileAssessment {
        artifacts: vec![],
        binding: binding.clone(),
        dimensions: manifest,
        profile_digest: binding.authority_ref.clone(),
        obligations: obligations.clone(),
    };
    let assessment = ProfileAssessment::evaluate(
        &declaration,
        &expected,
        std::slice::from_ref(&leaf),
        &acceptance,
    )
    .unwrap();
    let inputs =
        fortress_core::provider_inputs::EvidenceInputSet::compose(binding.clone(), vec![]).unwrap();
    let app = fortress_core::application::ApplicationAssessment {
        project: "test-project".into(),
        declaration,
        assessment,
        evidence: vec![leaf],
        obligations,
        evidence_inputs: Some(inputs),
        provider_requirements: vec![],
    };
    wrap_application(app, violation)
}

fn fixture_evidence(
    binding: &fortress_core::declaration::DeclarationBinding,
    violation: bool,
) -> (
    fortress_core::assessment::AssessmentEvidence,
    fortress_core::assessment::EvidenceAcceptancePolicy,
) {
    use fortress_core::assessment::*;
    use fortress_core::certification::EvidenceClass;
    let leaf = AssessmentEvidence {
        id: "leaf".into(),
        source_ref: "leaf".into(),
        binding: binding.clone(),
        scope_ref: "rule:STD-ID-001".into(),
        evidence_class: EvidenceClass::StaticProof,
        proposition: if violation {
            EvidenceProposition::SupportedViolation
        } else {
            EvidenceProposition::NoSupportedViolation
        },
        payload_digest: binding.subject_ref.clone(),
        assumptions: vec![],
        valid_until: None,
    };
    let mut acceptance = EvidenceAcceptancePolicy::default();
    acceptance
        .verified_payloads
        .insert(leaf.id.clone(), leaf.payload_digest.clone());
    acceptance
        .verified_metadata
        .insert(leaf.id.clone(), leaf.metadata_digest().unwrap());
    (leaf, acceptance)
}

fn wrap_application(
    app: fortress_core::application::ApplicationAssessment,
    violation: bool,
) -> QueryInput {
    use fortress_core::assessment::AssessmentDecision;
    let binding = app.declaration.binding.clone();
    let status = match app.assessment.decision {
        AssessmentDecision::Satisfied => fortress_core::audit::StateViewStatus::Complete,
        AssessmentDecision::NotSatisfied => fortress_core::audit::StateViewStatus::Negative,
        _ => fortress_core::audit::StateViewStatus::Partial,
    };
    let mut input = QueryInput::empty(binding.subject_ref.clone());
    input.state_view = Some(fortress_core::audit::StateView {
        schema: "urn:fortress:derived:v2:state-view".into(),
        schema_version: 2,
        source_ref: binding.subject_ref,
        status,
        detail: None,
        application: Some(app),
    });
    if violation {
        input.findings = vec![
            json!({"finding_id":"finding-one","rule_id":"STD-ID-001","message":"Identifier does not match the declared grammar.","source_ref":"fixture-source"}),
        ];
    }
    input
}

fn graph_input() -> QueryInput {
    use fortress_core::contract_coherency::*;
    let mut contracts = std::collections::BTreeMap::new();
    for (path, id, name) in [
        ("contract.json", "AF-ROOT", "Root"),
        ("left/contract.json", "AF-LEFT", "Shared"),
        ("right/contract.json", "AF-RIGHT", "Shared"),
    ] {
        let mut value = json!({"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,"id":id,"display_name":name,"provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]});
        if path == "contract.json" {
            value["ecosystem"] =
                json!({"repository_grammar":1,"standard":{"id":"STD-FORTRESS","edition":"1.0.0"}});
        }
        if id == "AF-RIGHT" {
            value["provides"] =
                json!([{"id":"CAP-RIGHT","version":"0.1.0","visibility":"project"}]);
        }
        if id == "AF-LEFT" {
            value["requires"] =
                json!([{"provider":"AF-RIGHT","capability":"CAP-RIGHT","version":"^0.1.0"}]);
        }
        let contract: ModuleContract = serde_json::from_value(value).unwrap();
        contracts.insert(
            path.into(),
            contract.to_canonical_json().unwrap().into_bytes(),
        );
    }
    let compilation = compile_contract_coherency_graph(
        &contracts,
        &ContractStandardIndex::new("STD-FORTRESS", "1.0.0", ["STD-ID-001"]),
        Some(&[]),
    );
    assert!(compilation.is_success(), "{:?}", compilation.violations());
    let mut input = QueryInput::empty(binding().subject_ref);
    input.ccg = compilation.graph().cloned();
    input
        .observed_routes
        .push(fortress_core::query::ObservedRoute {
            consumer: "AF-RIGHT".into(),
            provider: "AF-LEFT".into(),
            evidence_ref: "observed-one".into(),
        });
    input
}

fn payload(service: &QueryService, method: &str, parameters: Value) -> Value {
    let response = service.execute(&request(method, parameters), &AtomicBool::new(false));
    assert!(response.error.is_none(), "{:?}", response.error);
    serde_json::to_value(response.result.unwrap()).unwrap()["data"].clone()
}

fn service() -> QueryService {
    QueryService::new(QueryInput::empty(format!("sha256:{}", "a".repeat(64)))).unwrap()
}

fn request(method: &str, parameters: Value) -> QueryRequest {
    QueryRequest {
        protocol_version: 1,
        request_id: "test".into(),
        method: method.into(),
        state_ref: None,
        context_ref: None,
        parameters,
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn rpc_unknown_version_is_typed_error() {
    let mut req = request("status", json!({}));
    req.protocol_version = 99;
    let response = service().execute(&req, &AtomicBool::new(false));
    assert_eq!(response.error.unwrap().code, "UNSUPPORTED_VERSION");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn unavailable_results_and_cancellation_are_explicit() {
    let query = service();
    let response = query.execute(&request("status", json!({})), &AtomicBool::new(false));
    let value = serde_json::to_value(response.result.unwrap()).unwrap();
    assert_eq!(value["data"]["evidence_state"], "MISSING");
    assert!(value["data"]["raw_conformance"].is_null());
    assert_eq!(
        query
            .execute(&request("status", json!({})), &AtomicBool::new(true))
            .error
            .unwrap()
            .code,
        "CANCELLED"
    );
    assert!(QueryRequest::from_json_str(r#"{"protocol_version":1,"protocol_version":1}"#).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn status_distinguishes_raw_progressive_assurance() {
    let input = application_input();
    let query = QueryService::new(input.clone()).unwrap();
    let status = payload(&query, "status", json!({}));
    assert_eq!(status["raw_conformance"][0]["truth"], "SUPPORTED_VIOLATION");
    assert_eq!(status["assurance_assessment"]["decision"], "NOT_SATISFIED");
    assert!(
        !status["assurance_assessment"]["obligations"][0]["blockers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        status["progressive_enforcement"]["blocking_findings"],
        json!([])
    );
    assert_eq!(status["source_freshness"], "FRESH");
    let mut stale = input;
    stale.source_ref = format!("sha256:{}", "d".repeat(64));
    let status = payload(&QueryService::new(stale).unwrap(), "status", json!({}));
    assert_eq!(status["source_freshness"], "STALE");
    assert_eq!(status["current_repository_proven"], false);
    let mut historical = application_fixture(false);
    historical.source_ref = format!("sha256:{}", "d".repeat(64));
    let status = payload(&QueryService::new(historical).unwrap(), "status", json!({}));
    assert_eq!(status["assurance_assessment"]["decision"], "SATISFIED");
    assert_eq!(status["source_freshness"], "STALE");
    assert_eq!(status["current_repository_proven"], false);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn explain_returns_minimal_support_and_limitations() {
    let query = QueryService::new(application_input()).unwrap();
    for selector in ["claim-one", "finding-one", "obligation-one"] {
        let explanation = payload(&query, "explain", json!({"selector":selector}));
        assert_eq!(
            explanation["description"]["minimal_sufficient_evidence"]["refs"],
            json!(["leaf"])
        );
        assert!(
            !explanation["description"]["limitations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            explanation["evidence"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["id"] == "leaf")
        );
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn qualified_name_ambiguity_does_not_choose_first() {
    let query = QueryService::new(graph_input()).unwrap();
    let response = query.execute(
        &request("query", json!({"kind":"policy","selector":"Shared"})),
        &AtomicBool::new(false),
    );
    let error = response.error.unwrap();
    assert_eq!(error.code, "AMBIGUOUS_SELECTOR");
    assert_eq!(error.candidates, vec!["AF-LEFT", "AF-RIGHT"]);
    let qualified = query.execute(
        &request("query", json!({"kind":"modules","selector":"Root::Shared"})),
        &AtomicBool::new(false),
    );
    assert_eq!(qualified.error.unwrap().code, "AMBIGUOUS_SELECTOR");
    let unique = payload(&query, "query", json!({"kind":"policy","selector":"left"}));
    assert_eq!(unique["records"][0]["scope_ref"], "AF-LEFT");
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn route_direction_and_permission_are_verified() {
    let query = QueryService::new(graph_input()).unwrap();
    let dependents = payload(
        &query,
        "query",
        json!({"kind":"dependents","selector":"AF-RIGHT"}),
    );
    assert_eq!(dependents["records"][0]["value"]["consumer"], "AF-LEFT");
    assert_eq!(dependents["records"][0]["value"]["provider"], "AF-RIGHT");
    assert_eq!(
        dependents["records"][0]["value"]["classification"],
        "DECLARED_PERMITTED"
    );
    let reverse = payload(
        &query,
        "query",
        json!({"kind":"dependents","selector":"AF-LEFT"}),
    );
    assert_eq!(reverse["total"], 0);
    let observed = payload(
        &query,
        "query",
        json!({"kind":"routes","selector":"AF-RIGHT"}),
    );
    assert_eq!(
        observed["records"][0]["value"]["classification"],
        "OBSERVED"
    );
    let proposal = payload(
        &query,
        "author",
        json!({"module":"AF-LEFT","target":"filesystem.write","disposition":"DENY"}),
    );
    assert_eq!(proposal["classification"], "PROPOSED");
    assert!(
        proposal["canonical_contract_preview"]
            .as_str()
            .unwrap()
            .contains("filesystem.write")
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn large_path_results_page_without_evidence_loss() {
    let mut input = application_input();
    for index in 0..501 {
        let id = format!("node-{index:04}");
        input.evidence_nodes.push(json!({"id":id,"inputs":if index == 500 {vec![]}else{vec![format!("node-{:04}",index+1)]},"payload":{"path_position":index}}));
    }
    input
        .evidence_nodes
        .push(json!({"id":"leaf","inputs":["node-0000"]}));
    let query = QueryService::new(input).unwrap();
    let mut cursor = Value::Null;
    let mut seen = std::collections::BTreeSet::new();
    let total = loop {
        let result = payload(
            &query,
            "explain",
            json!({"selector":"claim-one","page":{"limit":17,"cursor":cursor}}),
        );
        let page = &result["evidence"];
        for row in page["records"].as_array().unwrap() {
            assert!(seen.insert((
                row["kind"].as_str().unwrap().to_owned(),
                row["id"].as_str().unwrap().to_owned()
            )));
        }
        cursor = page["next_cursor"].clone();
        if cursor.is_null() {
            break page["total"].as_u64().unwrap();
        }
    };
    assert_eq!(seen.len() as u64, total);
    assert!(seen.iter().any(|(_, id)| id == "node-0500"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn malformed_parameters_context_limits_and_continuations_are_rejected() {
    let query = QueryService::new(graph_input()).unwrap();
    for (parameters, code) in [
        (json!({"kind":"modules","extra":true}), "INVALID_PARAMETERS"),
        (
            json!({"kind":"modules","page":{"limit":201}}),
            "RESOURCE_LIMIT",
        ),
        (
            json!({"kind":"modules","page":{"cursor":"../../etc/passwd"}}),
            "INVALID_CURSOR",
        ),
    ] {
        assert_eq!(
            query
                .execute(&request("query", parameters), &AtomicBool::new(false))
                .error
                .unwrap()
                .code,
            code
        );
    }
    let mut req = request("status", json!({}));
    req.state_ref = Some(binding().subject_ref);
    assert_eq!(
        query
            .execute(&req, &AtomicBool::new(false))
            .error
            .unwrap()
            .code,
        "STATE_MISMATCH"
    );
    let response = query.execute(&request("status", json!({})), &AtomicBool::new(false));
    let human = response.to_human();
    let decoded: Value = serde_json::from_slice(&response.to_canonical_bytes().unwrap()).unwrap();
    assert!(human.contains(decoded["state_ref"].as_str().unwrap()));
    assert!(human.contains("raw conformance"));
}

struct ReadOnlyFixture(std::path::PathBuf);
impl ReadOnlyFixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("fortress-query-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='untrusted'\nversion='0.1.0'\nbuild='build.rs'\n",
        )
        .unwrap();
        std::fs::write(
            root.join("build.rs"),
            "fn main() { std::fs::write(\"executed-marker\", \"bad\").unwrap(); }\n",
        )
        .unwrap();
        std::fs::write(root.join("rust-toolchain.toml"), "invalid=[").unwrap();
        Self(root)
    }
}
impl Drop for ReadOnlyFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn doctor_is_read_only() {
    let fixture = ReadOnlyFixture::new();
    let before = std::fs::read_dir(&fixture.0)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), std::fs::read(path).unwrap())
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let query = fortress_core::query::load_repository_query(
        &fixture.0,
        &fortress_core::query::QueryLoadOptions::default(),
    )
    .unwrap();
    let doctor = payload(&query, "doctor", json!({}));
    assert_eq!(doctor["environment"]["project_commands_executed"], false);
    assert_eq!(doctor["storage"]["repairs_performed"], false);
    assert_eq!(
        doctor["toolchain"]["declared_inputs"][0]["state"],
        "INVALID_DECLARATION"
    );
    assert!(!fixture.0.join("executed-marker").exists());
    let after = std::fs::read_dir(&fixture.0)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), std::fs::read(path).unwrap())
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(before, after);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn countervailing_and_unresolved_evidence_are_not_hidden_as_minimal_proof() {
    let mut input = application_input();
    let app = input
        .state_view
        .as_mut()
        .unwrap()
        .application
        .as_mut()
        .unwrap();
    let mut claims = app.declaration.claims.clone();
    claims[0].defeater_refs = vec!["defeater-one".into(), "unresolved-premise".into()];
    app.declaration = fortress_core::declaration::ConformanceDeclaration::compose(
        app.declaration.binding.clone(),
        app.declaration.required_dimension_manifest.clone(),
        claims,
        vec![],
        app.declaration.residue_summary.clone(),
    )
    .unwrap();
    app.assessment.declaration_digest = app.declaration.digest().unwrap();
    input.defeaters.push(json!({"id":"defeater-one","description":"A reachable dependency is unresolved.","kind":"UNRESOLVED_CALL_PATH","supporting_refs":["missing-source"]}));
    let query = QueryService::new(input).unwrap();
    let explanation = payload(&query, "explain", json!({"selector":"defeater-one"}));
    assert_eq!(
        explanation["description"]["minimal_sufficient_evidence"]["basis"],
        "NOT_ESTABLISHED"
    );
    assert!(
        explanation["description"]["unresolved_dependencies"]
            .as_array()
            .unwrap()
            .contains(&json!("unresolved-premise"))
    );
    assert!(
        explanation["evidence"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == "defeater-one")
    );
    let unsupported = query.execute(
        &request(
            "author",
            json!({"module":"absent","target":"invented.proof","disposition":"ALLOW"}),
        ),
        &AtomicBool::new(false),
    );
    assert!(unsupported.error.is_some());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn protocol_schemas_and_human_projection_preserve_machine_meaning() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let request_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/snapshot_governance/_data/query_request_schema_v1.json"))
            .unwrap(),
    )
    .unwrap();
    let response_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/snapshot_governance/_data/query_response_schema_v1.json"))
            .unwrap(),
    )
    .unwrap();
    let query = QueryService::new(application_input()).unwrap();
    for (method, parameters) in [
        ("status", json!({})),
        ("doctor", json!({})),
        ("explain", json!({"selector":"finding-one"})),
        ("protocol", json!({})),
        ("query", json!({"kind":"modules"})),
    ] {
        let req = request(method, parameters);
        jsonschema::draft202012::validate(&request_schema, &serde_json::to_value(&req).unwrap())
            .unwrap();
        let response = query.execute(&req, &AtomicBool::new(false));
        let canonical = response.to_canonical_bytes().unwrap();
        assert_eq!(canonical, response.to_canonical_bytes().unwrap());
        let value: Value = serde_json::from_slice(&canonical).unwrap();
        jsonschema::draft202012::validate(&response_schema, &value).unwrap();
        verify_strings(&value, &response.to_human());
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R21-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R21
#[test]
fn adversarial_state_paths_and_input_resource_limits_do_not_trigger_analysis() {
    let fixture = ReadOnlyFixture::new();
    let mut options = fortress_core::query::QueryLoadOptions {
        max_source_bytes: 1,
        ..Default::default()
    };
    assert!(fortress_core::query::load_repository_query(&fixture.0, &options).is_err());
    options.max_source_bytes = 1024 * 1024;
    options.state_path = Some(fixture.0.join("../absent-state.json"));
    assert!(fortress_core::query::load_repository_query(&fixture.0, &options).is_err());
    assert!(!fixture.0.join("executed-marker").exists());
    let query = QueryService::new(graph_input()).unwrap();
    assert_eq!(
        query
            .execute(
                &request(
                    "author",
                    json!({"module":"AF-LEFT","target":"invented.proof","disposition":"ALLOW"})
                ),
                &AtomicBool::new(false)
            )
            .error
            .unwrap()
            .code,
        "UNSUPPORTED_SEMANTICS"
    );
}

fn verify_strings(value: &Value, human: &str) {
    match value {
        Value::String(value) => {
            assert!(human.contains(value), "missing human value {value}");
        }
        Value::Array(values) => {
            for value in values {
                verify_strings(value, human);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                verify_strings(value, human);
            }
        }
        _ => {}
    }
}

fn fixture_obligations() -> Vec<fortress_core::assessment::ProfileObligation> {
    use fortress_core::assessment::*;
    use fortress_core::certification::EvidenceClass;
    let proof = serde_json::from_value(json!({"schema_version":1,"root_node_id":"root","nodes":[{"node_id":"root","operator":"LEAF","required_refs":["leaf"],"children":[]}]})).unwrap();
    vec![ProfileObligation {
        id: "obligation-one".into(),
        scope_ref: "rule:STD-ID-001".into(),
        predicate: ObligationPredicate::RuleCheck,
        evidence_class: EvidenceClass::StaticProof,
        authenticated_producer_required: false,
        proof: Some(proof),
    }]
}
