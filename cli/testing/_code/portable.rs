//! Portable presentation and independent consumer integration controls.
use fortress_core::declaration::*;
use serde_json::{Value, json};

fn declaration(truth: DeclarationTruth) -> Value {
    let digest = format!("sha256:{}", "a".repeat(64));
    let detail = SemanticClaimDetail {
        upstream_proof_refs: vec!["premise".into()],
        instance_id: "scope".into(),
        slot_id: "slot".into(),
        module_id: "AF-FIXTURE".into(),
        scope_selector: "ALL_MODULE_OWNED_EXECUTABLE_ENTRIES".into(),
        context_family: "fixture".into(),
        policy_digest: digest.clone(),
        context_digest: digest.clone(),
        governed_universe_digest: digest.clone(),
        producer_identity: "synthetic-protocol-control".into(),
        target_kind: "EFFECT".into(),
        target: "filesystem.write".into(),
        disposition: if truth == DeclarationTruth::Authorization {
            "ALLOW"
        } else {
            "DENY"
        }
        .into(),
        governed_source_files: 1,
        analysed_source_files: 1,
        production_observations: vec![],
        test_observations: vec![],
        unknown_observations: vec![],
        proof_graph: None,
        blocking_eligibility: None,
    };
    let mut residue = DeclarationResidue::default();
    if truth == DeclarationTruth::SupportedViolation {
        residue.blocking_findings.push(digest.clone());
    }
    let declaration = ConformanceDeclaration::compose(
        DeclarationBinding {
            subject_ref: digest.clone(),
            context_ref: digest.clone(),
            authority_ref: digest.clone(),
        },
        DimensionManifest {
            profiles: vec![ScopedProfileReference {
                module: None,
                id: "PROFILE".into(),
                version: "1.0.0".into(),
                digest: digest.clone(),
            }],
            dimensions: vec![RequiredDimension {
                id: "SEMANTICS".into(),
                claim_refs: vec!["claim".into()],
            }],
        },
        vec![DeclarationClaim {
            kind: DeclarationClaimKind::SemanticPolicy,
            id: "claim".into(),
            scope_ref: "scope".into(),
            truth,
            proof_refs: vec!["premise".into()],
            findings: if truth == DeclarationTruth::SupportedViolation {
                vec![digest]
            } else {
                vec![]
            },
            defeater_refs: vec![],
            reason_codes: vec![],
            assumptions: vec![],
            semantic_claim: Some(detail),
            rule_result: None,
        }],
        vec![],
        residue,
    )
    .unwrap();
    serde_json::to_value(declaration).unwrap()
}

fn audit(violation: bool) -> Value {
    let digest = format!("sha256:{}", "a".repeat(64));
    let findings = if violation {
        vec![
            json!({"finding_id":digest,"rule_id":"ARCH-SEMANTIC-001","state":"FAIL","integrity_tier":0,
        "enforcement_eligibility":"ADVISORY_ONLY","identity_eligibility":"ELIGIBLE","entities":["AF-FIXTURE"],
        "location":{"path":"sample/_code/é file.rs","span":{"start_line":2,"start_column":1,"end_line":2,"end_column":8},"symbol":"entry"},
        "message":"Observed write conflicts with the scoped declaration.","remediation":"Remove the write or propose an authored policy change.",
        "evaluator":{"id":"synthetic-protocol-control","version":"1.0.0"},"standard_edition":"fixture"}),
        ]
    } else {
        vec![]
    };
    json!({"findings":findings,"unsupported_analysis":[],"finding_governance":{"authenticity":"UNVERIFIED"},
        "portable_traces":{digest:[{"call_chain":["entry","middle","source"],"operation":"std::fs::write"},
            {"call_chain":["alternative_entry","source"],"operation":"std::fs::write"}]}})
}

/// `T-TF-CLI-0001-R23-001`
/// Fortress requirement: TF-CLI-0001-R23
#[test]
fn deterministic_sarif_preserves_scoped_truth_identities_residue_and_ordered_observations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/certification/testing/_data/portable_vectors_v1.json"))
            .unwrap(),
    )
    .unwrap();
    for row in vectors["cases"].as_array().unwrap() {
        let truth = if row["residue"] == "AUTHORIZATION_ONLY" {
            DeclarationTruth::Authorization
        } else {
            serde_json::from_value(row["truth"].clone()).unwrap()
        };
        let mut declaration = declaration(truth);
        if row["residue"] == "BASELINED" {
            declaration["residue_summary"]["accepted_baseline"] =
                json!([format!("sha256:{}", "a".repeat(64))]);
        }
        if row["residue"] == "EXCEPTED" {
            declaration["residue_summary"]["accepted_exceptions"] =
                json!([format!("sha256:{}", "a".repeat(64))]);
        }
        let mut audit = audit(truth == DeclarationTruth::SupportedViolation);
        audit["portable_freshness"] = json!(if row["residue"] == "STALE" {
            "STALE"
        } else {
            "UNKNOWN"
        });
        let result = fortress_cli::sarif::export(&audit, &declaration, None).unwrap();
        assert_eq!(
            result,
            fortress_cli::sarif::export(&audit, &declaration, None).unwrap()
        );
        let results = result["runs"][0]["results"].as_array().unwrap();
        let claim = results
            .iter()
            .find(|r| !r["properties"]["fortressClaim"].is_null())
            .unwrap();
        assert_eq!(claim["kind"], row["kind"]);
        assert_eq!(
            claim["properties"]["fortressClaim"],
            declaration["claims"][0]
        );
        if truth == DeclarationTruth::SupportedViolation {
            let finding = results
                .iter()
                .find(|r| !r["properties"]["fortressFinding"].is_null())
                .unwrap();
            assert_eq!(
                finding["properties"]["fortressFinding"],
                audit["findings"][0]
            );
            assert_eq!(finding["level"], "warning");
            assert_eq!(
                finding["properties"]["fortressFinding"]["enforcement_eligibility"],
                "ADVISORY_ONLY"
            );
            assert_eq!(
                finding["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["logicalLocations"]
                    [0]["fullyQualifiedName"],
                "entry"
            );
            assert_eq!(
                finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "sample/_code/%C3%A9%20file.rs"
            );
        }
        assert_eq!(
            result["runs"][0]["properties"]["assuranceAuthority"],
            "NONE"
        );
        assert_eq!(
            result["runs"][0]["properties"]["sourceFreshness"],
            audit["portable_freshness"]
        );
        // Explicit research runs may retain exact producer bytes. Canonical
        // qualification omits this operational output directory.
        if let Some(directory) = std::env::var_os("FORTRESS_RETAIN_PORTABLE_FIXTURES") {
            use std::io::Write;
            let path = std::path::Path::new(&directory)
                .join(format!("{}.sarif", row["name"].as_str().unwrap()));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            file.write_all(&fortress_core::portable::canonical(&result).unwrap())
                .unwrap();
        }
    }
}

/// `T-TF-CLI-0001-R23-002`
/// Fortress requirement: TF-CLI-0001-R23
#[test]
fn malformed_and_adversarial_portable_inputs_fail_without_repair_or_analysis() {
    let audit_only = json!({"findings":[],"rules":[{"rule_id":"RULE-UNKNOWN","state":"UNSUPPORTED","detail":"Coverage unavailable."}],"unsupported_analysis":["Coverage unavailable."]});
    let observed = fortress_cli::sarif::export(&audit_only, &Value::Null, None).unwrap();
    assert_eq!(observed["runs"][0]["results"][0]["kind"], "open");
    assert_eq!(
        observed["runs"][0]["properties"]["declarationAvailability"],
        "UNAVAILABLE"
    );
    let mut malicious = audit(true);
    for path in [
        "../secret",
        "C:/secret",
        "/absolute",
        "safe\\secret",
        "a//b",
    ] {
        malicious["findings"][0]["location"]["path"] = json!(path);
        assert_eq!(
            fortress_cli::sarif::export(
                &malicious,
                &declaration(DeclarationTruth::SupportedViolation),
                None
            )
            .unwrap_err()
            .code,
            "UNSAFE_PATH"
        );
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let exit = fortress_cli::run(
        ["bundle", "export", "--unknown", "value"],
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(exit, 2);
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_PARAMETERS");
}
