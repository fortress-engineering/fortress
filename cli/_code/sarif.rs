//! SARIF 2.1.0 projection of retained meanings, without new evaluation authority.

use fortress_core::portable::{PortableError, failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Renders exact normalized findings and scoped declaration results as SARIF.
/// Severity `warning` denotes the documented existence of a problem; it never
/// grants blocking eligibility or infers serious/minor severity from a tier.
/// # Errors
/// Rejects malformed records, duplicate identities and unsupported truth values.
pub fn export(
    audit: &Value,
    declaration: &Value,
    authority: Option<&Value>,
) -> Result<Value, PortableError> {
    let findings = audit["findings"]
        .as_array()
        .ok_or_else(|| failure("INVALID_FINDINGS", "normalized findings array missing"))?;
    let claims = if declaration.is_null() {
        &[][..]
    } else {
        declaration["claims"]
            .as_array()
            .ok_or_else(|| failure("INVALID_DECLARATION", "claims array missing"))?
            .as_slice()
    };
    if findings.len() + claims.len() > 100_000 {
        return Err(failure(
            "RESOURCE_LIMIT",
            "SARIF result inventory exceeds 100000",
        ));
    }
    let mut rules = rule_catalog(authority)?;
    let mut results = BTreeMap::new();
    for finding in findings {
        if finding["state"] != "FAIL" {
            return Err(failure(
                "UNSUPPORTED_FINDING",
                "finding state cannot be projected as a problem",
            ));
        }
        let id = text(finding, "finding_id")?;
        let rule = text(finding, "rule_id")?;
        require_rule(&mut rules, rule);
        let mut result = json!({"ruleId":rule,"kind":"fail","level":"warning",
            "message":{"text":format!("{}\nRemediation: {}",text(finding,"message")?,text(finding,"remediation")?)},
            "partialFingerprints":{"fortressFindingId/v1":id},
            "properties":{"fortressFinding":finding,"findingId":id,"governanceReference":id,"blockingAuthority":"NONE_FROM_SARIF"}});
        if let Some(location) = location(&finding["location"])? {
            result["locations"] = json!([location]);
        }
        if let Some(flows) = code_flows(audit["portable_traces"].get(id).unwrap_or(&Value::Null))? {
            result["codeFlows"] = flows;
        }
        if results.insert(format!("finding:{id}"), result).is_some() {
            return Err(failure("DUPLICATE_IDENTITY", "duplicate finding"));
        }
    }
    for claim in claims {
        let id = text(claim, "id")?;
        let rule = claim
            .get("rule_result")
            .and_then(|_| id.strip_prefix("rule:"))
            .unwrap_or(id);
        require_rule(&mut rules, rule);
        let kind = match text(claim, "truth")? {
            "SUPPORTED_VIOLATION" => "fail",
            "NO_SUPPORTED_VIOLATION" => "pass",
            "NOT_EVALUABLE" => "open",
            "NOT_APPLICABLE" => "notApplicable",
            "AUTHORIZATION" => "informational",
            _ => {
                return Err(failure(
                    "UNSUPPORTED_TRUTH",
                    "unknown declaration proposition",
                ));
            }
        };
        let message = format!(
            "Scoped {}: {} at {}. Supporting references: {}. This result does not establish profile satisfaction, authenticity or current freshness.",
            text(claim, "truth")?,
            id,
            text(claim, "scope_ref")?,
            claim["proof_refs"]
        );
        let result = json!({"ruleId":rule,"kind":kind,"level":if kind=="fail" {"warning"} else {"none"},"message":{"text":message},
            "partialFingerprints":{"fortressClaimId/v1":id},"properties":{"fortressClaim":claim,"binding":declaration["binding"],"residueFindingReferences":claim["findings"],"authorizationOnly":claim["truth"]=="AUTHORIZATION"}});
        if results.insert(format!("claim:{id}"), result).is_some() {
            return Err(failure("DUPLICATE_IDENTITY", "duplicate claim"));
        }
    }
    if declaration.is_null() {
        audit_rule_rows(audit, &mut results, &mut rules)?;
    }
    let rule_indexes = rules
        .keys()
        .enumerate()
        .map(|(i, k)| (k.clone(), i))
        .collect::<BTreeMap<_, _>>();
    for result in results.values_mut() {
        result["ruleIndex"] = json!(rule_indexes[text(result, "ruleId")?]);
    }
    let losses = projection_losses(findings);
    Ok(
        json!({"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json","version":"2.1.0",
        "runs":[{"tool":{"driver":{"name":"Fortress","semanticVersion":env!("CARGO_PKG_VERSION"),"rules":rules.into_values().collect::<Vec<_>>()}},
            "results":results.into_values().collect::<Vec<_>>(),"properties":{"fortressProjectionVersion":1,"binding":declaration["binding"],"projectionLosses":losses,
                "sourceFreshness":audit["portable_freshness"].as_str().unwrap_or("UNKNOWN"),"authenticity":"UNVERIFIED","traceMaterializationLosses":audit["portable_trace_losses"],
                "findingGovernance":audit["finding_governance"],"residue":declaration["residue_summary"],
                "declarationAvailability":if declaration.is_null() {"UNAVAILABLE"} else {"INCLUDED"},"auditGovernance":audit["governance"],"observedSnapshot":audit["snapshot_fingerprint"],
                "assuranceAuthority":"NONE","emptyResultsMeaning":"NO_EXPORTED_RESULTS_NOT_ALL_CLAIMS_PASSED","unsupportedAnalysis":audit["unsupported_analysis"]}}]}),
    )
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, PortableError> {
    v[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| failure("INVALID_RECORD", format!("missing {key}")))
}

fn audit_rule_rows(
    audit: &Value,
    results: &mut BTreeMap<String, Value>,
    rules: &mut BTreeMap<String, Value>,
) -> Result<(), PortableError> {
    if let Some(executions) = audit["rules"].as_array() {
        if executions.len() + results.len() > 100_000 {
            return Err(failure(
                "RESOURCE_LIMIT",
                "SARIF record inventory exceeds admission",
            ));
        }
        for execution in executions {
            let id = text(execution, "rule_id")?;
            let kind = match text(execution, "state")? {
                "PASSED" => "pass",
                "FAILED" => "fail",
                "UNSUPPORTED" => "open",
                "NOT_APPLICABLE" => "notApplicable",
                _ => {
                    return Err(failure(
                        "UNSUPPORTED_SEMANTICS",
                        "unknown rule execution state",
                    ));
                }
            };
            require_rule(rules, id);
            let row = json!({"ruleId":id,"kind":kind,"level":if kind=="fail" {"warning"}else{"none"},
                "message":{"text":format!("Recorded registered-rule diagnostic only; no declaration, scope completeness or assurance supplied. {}",execution["detail"].as_str().unwrap_or("Detail not retained."))},
                "properties":{"fortressRuleExecution":execution,"classification":"REGISTERED_RULE_DIAGNOSTIC","identityEligibility":"BASELINE_INELIGIBLE"}});
            if results.insert(format!("diagnostic:{id}"), row).is_some() {
                return Err(failure("DUPLICATE_IDENTITY", "duplicate rule diagnostic"));
            }
        }
    }
    Ok(())
}
fn require_rule(rules: &mut BTreeMap<String, Value>, id: &str) {
    rules
        .entry(id.into())
        .or_insert_with(|| json!({"id":id,"properties":{"metadataAvailability":"NOT_RETAINED"}}));
}
fn location(value: &Value) -> Result<Option<Value>, PortableError> {
    let Some(path) = value["path"].as_str() else {
        return Ok(None);
    };
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(failure(
            "UNSAFE_PATH",
            "finding path is not portable repository-relative",
        ));
    }
    let uri = path
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect::<String>();
    let mut physical = json!({"artifactLocation":{"uri":uri}});
    if let Some(line) = value["span"]["start_line"].as_u64().filter(|n| *n > 0) {
        physical["region"] = json!({"startLine":line});
    }
    Ok(Some(
        json!({"physicalLocation":physical,"properties":{"fortressLocation":value}}),
    ))
}
fn projection_losses(findings: &[Value]) -> Value {
    let mut losses = BTreeSet::from([
        "SARIF presentation does not enforce Fortress proof, profile, authentication or freshness semantics.",
        "Microsoft SARIF Viewer 3.4.5 displays open/review as warnings and pass/notApplicable as notes; consult fortressClaim.truth.",
        "Microsoft SARIF Viewer 3.4.5 shows only its supported trace view; all original codeFlows remain in exported bytes.",
        "Baseline and exception dispositions remain properties; they do not erase raw findings or become external permission.",
    ]);
    if findings.iter().any(|f| !f["location"]["span"].is_null()) {
        losses.insert("Original inclusive columns have no declared SARIF column unit; only known lines are projected and original spans remain properties.");
    }
    json!({"schema_version":1,"losses":losses,"gate_authority":"NONE"})
}

fn code_flows(value: &Value) -> Result<Option<Value>, PortableError> {
    if value.is_null() {
        return Ok(None);
    }
    let traces = value
        .as_array()
        .ok_or_else(|| failure("INVALID_TRACE", "trace inventory must be an array"))?;
    let mut flows = Vec::new();
    for trace in traces {
        let chain = trace["call_chain"]
            .as_array()
            .ok_or_else(|| failure("INVALID_TRACE", "ordered call chain missing"))?;
        let displays = trace.get("call_chain_display");
        if chain.iter().any(|s| s.as_str().is_none_or(str::is_empty))
            || displays.is_some_and(|d| {
                d.as_array().is_none_or(|d| {
                    d.len() != chain.len() || d.iter().any(|s| s.as_str().is_none_or(str::is_empty))
                })
            })
        {
            return Err(failure(
                "INVALID_TRACE",
                "call path labels must be nonempty strings",
            ));
        }
        let steps = chain.iter().enumerate().map(|(index, symbol)| {
            let display = trace["call_chain_display"].get(index).unwrap_or(symbol);
            json!({"executionOrder":index,"location":{"message":{"text":display},
                "logicalLocations":[{"fullyQualifiedName":display,"kind":"function","properties":{"fortressSymbolId":symbol}}]}})
        }).collect::<Vec<_>>();
        if !steps.is_empty() {
            flows.push(json!({"message":{"text":"Observed ordered call path; not permission."},"threadFlows":[{"locations":steps}],"properties":{"fortressObservation":trace}}));
        }
    }
    Ok((!flows.is_empty()).then(|| json!(flows)))
}

fn rule_catalog(authority: Option<&Value>) -> Result<BTreeMap<String, Value>, PortableError> {
    let mut rules = BTreeMap::new();
    if let Some(authority) = authority {
        for row in authority["rules"]
            .as_array()
            .ok_or_else(|| failure("INVALID_AUTHORITY", "rule metadata missing"))?
        {
            let rule = fortress_core::portable::parse(text(row, "utf8")?.as_bytes())?;
            let id = text(&rule, "id")?.to_owned();
            if rules.contains_key(&id) {
                return Err(failure("DUPLICATE_IDENTITY", "duplicate rule metadata"));
            }
            rules.insert(id.clone(), json!({"id":id,"shortDescription":{"text":rule["title"].as_str().unwrap_or(&id)},
                "help":{"text":format!("{}\nRationale: {}\nFailure prevented: {}\nRemediation: {}",rule["statement"].as_str().unwrap_or(""),rule["rationale"].as_str().unwrap_or(""),rule["failure_prevented"].as_str().unwrap_or(""),rule["remediation"].as_str().unwrap_or(""))},
                "properties":{"fortressRule":rule}}));
        }
    }
    Ok(rules)
}
