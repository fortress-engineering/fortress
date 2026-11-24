//! Exact native-body inputs and independent source-site transfer expectations.

use fortress_core::information_flow::{InformationFlowCoverage, observe_native_scalar_flow};
use fortress_core::program_semantics::native_body::{
    NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome,
};
use fortress_core::project::EvaluationKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PIN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALTERNATE: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FIXTURE_REF: &str = "sha256:1aab62de475435c507ef0ac209e51273262e684f934b0045c54dc136164790df";
const FIXTURES: &[u8] = include_bytes!("../_data/native_flow_cases_v1.json");

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn admit(case: &Value, context: &str) -> NativeBodyOutcome {
    let language = match case["language"].as_str() {
        Some("go") => NativeBodyLanguage::Go,
        Some("python") => NativeBodyLanguage::Python,
        _ => panic!("frozen language selection"),
    };
    let source = case["source"]
        .as_str()
        .expect("exact fixture bytes")
        .as_bytes();
    let parameters = if language == NativeBodyLanguage::Python {
        ["input", "gate"].as_slice()
    } else {
        [].as_slice()
    };
    NativeBodyInput {
        language,
        evaluation: &EvaluationKey::new(PIN, context, PIN),
        exchange_ref: PIN,
        producer_ref: PIN,
        source_path: case["path"].as_str().expect("exact path"),
        source_ref: &digest(source),
        source,
        python_bool_parameters: parameters,
    }
    .admit(&serde_json::to_vec(&case["reply"]).expect("typed fixture payload"))
    .expect("native body fixture admits within its exact scope")
}

/// `T-AF-INFORMATION-FLOW-0001-R07-001`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R07
#[test]
fn native_explicit_data_and_condition_inputs_do_not_enter_proof_lanes() {
    assert_eq!(digest(FIXTURES), FIXTURE_REF);
    let document: Value = serde_json::from_slice(FIXTURES).expect("frozen population");
    let cases = document["fixtures"]
        .as_array()
        .expect("go and Python cases");
    assert_eq!(cases.len(), 14);
    for case in cases {
        let admitted = admit(case, PIN);
        let observation = observe_native_scalar_flow(&admitted);
        assert_eq!(
            observation.control_influence_coverage(),
            InformationFlowCoverage::Unsupported
        );
        let canonical = observation.to_canonical_json().expect("bounded projection");
        assert_eq!(
            canonical,
            observe_native_scalar_flow(&admitted)
                .to_canonical_json()
                .unwrap()
        );
        let report: Value = serde_json::from_slice(&canonical).expect("exact report");
        assert_eq!(report["classification_authority"], "UNKNOWN");
        let facts = &report["facts"];
        let NativeBodyOutcome::Lowered(body) = admitted else {
            assert_eq!(facts["status"], "UNAVAILABLE");
            assert_eq!(facts["code"], "CALL_UNSUPPORTED");
            assert_eq!(observation.explicit_edge_count(), None);
            assert_eq!(observation.projection_ref(), None);
            continue;
        };
        assert_eq!(facts["status"], "OBSERVED");
        assert_eq!(report["occurrence_ref"], body.binding());
        assert_eq!(report["explicit_data_coverage"], "PARTIAL");
        let edges = facts["explicit_data_edges"]
            .as_array()
            .expect("direct data sites");
        let mut sites = Vec::new();
        for edge in edges {
            assert_eq!(edge["producer"]["symbol"], body.binding());
            assert_eq!(edge["consumer"]["symbol"], body.binding());
            assert_eq!(edge["path"], case["path"]);
            assert!(edge["line"].as_u64().is_some_and(|line| line > 0));
            let producer = edge["producer"]["name"].as_str().unwrap();
            let consumer = edge["consumer"]["name"].as_str().unwrap();
            sites.push(format!("{producer}->{consumer}"));
        }
        sites.sort_unstable();
        assert_eq!(json!(sites), case["expected_edges"]);
        assert_eq!(observation.explicit_edge_count(), Some(sites.len()));
        let conditions = facts["condition_inputs"]
            .as_array()
            .expect("recorded guard sites");
        let sources = conditions
            .iter()
            .flat_map(|guard| {
                guard["sources"]
                    .as_array()
                    .expect("condition references")
                    .iter()
                    .map(|source| source["name"].clone())
            })
            .collect::<Vec<_>>();
        assert_eq!(json!(sources), case["expected_conditions"]);
        let changed = observe_native_scalar_flow(&admit(case, ALTERNATE));
        assert_ne!(observation.projection_ref(), changed.projection_ref());
    }
}

fn span(path: &str, source: &str, start: usize, size: usize) -> Value {
    let before = &source[..start];
    let line = before.split('\n').count();
    let column = before.rsplit('\n').next().expect("source location").len() + 1;
    json!({"path":path,"start_byte":start,"end_byte":start+size,"start_line":line,
           "start_byte_column":column})
}

/// `T-AF-INFORMATION-FLOW-0001-R07-002`
/// Fortress requirement: AF-INFORMATION-FLOW-0001-R07
#[test]
fn repeated_exact_sites_refuse_an_oversized_sidecar_without_partial_publication() {
    const PATH: &str = "src/subject.py";
    const HEADER: &str = "def subject(input, gate):\n";
    const ASSIGN: &str = "    value = input\n";
    const RETURN: &str = "    return value\n";
    const SITE_COUNT: usize = 450;
    let source = format!("{HEADER}{}{RETURN}", ASSIGN.repeat(SITE_COUNT));
    let mut statements = (0..SITE_COUNT)
        .map(|index| {
            let position = HEADER.len() + index * ASSIGN.len() + 4;
            json!({"kind":"assign","target":"value","value":{"kind":"binding","name":"input"},
               "span":span(PATH,&source,position,ASSIGN.len()-5)})
        })
        .collect::<Vec<_>>();
    statements.push(json!({
        "kind":"return","value":{"kind":"binding","name":"value"},
        "span":span(PATH,&source,HEADER.len()+SITE_COUNT*ASSIGN.len()+4,RETURN.len()-5)
    }));
    let input = json!({"path":PATH,"language":"python","source":source,"reply":{
        "status":"LOWERABLE","symbol":{"name":"subject","span":span(PATH,&source,4,7),
           "declaration_span":span(PATH,&source,0,source.len()-1)},
        "result_scalar":"BOOL","parameters":[
            {"name":"input","scalar":"BOOL","span":span(PATH,&source,12,5)},
            {"name":"gate","scalar":"BOOL","span":span(PATH,&source,19,4)}],
        "locals":[{"name":"value","scalar":"BOOL","span":span(PATH,&source,HEADER.len()+4,5)}],
        "body":statements
    }});
    let body = admit(&input, PIN);
    assert!(matches!(&body, NativeBodyOutcome::Lowered(_)));
    let report = observe_native_scalar_flow(&body);
    assert_eq!(report.projection_ref(), None);
    assert_eq!(report.explicit_edge_count(), None);
    let json: Value = serde_json::from_slice(&report.to_canonical_json().unwrap()).unwrap();
    assert_eq!(
        json["facts"],
        json!({"status":"UNAVAILABLE","code":"RESOURCE_LIMIT","location":null})
    );
    assert!(json["occurrence_ref"].as_str().is_some());
}
