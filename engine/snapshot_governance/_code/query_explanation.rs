//! Evidence-linked explanations and schema-informed, unapplied authoring previews.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

use super::{
    AuthorParameters, ExplainParameters, ExplanationPage, QueryError, QueryService,
    check_cancelled, digest,
};
use crate::declaration::DeclarationTruth;

impl QueryService {
    pub(super) fn index_application(&mut self) -> Result<(), QueryError> {
        let Some(app) = self.application().cloned() else {
            return Ok(());
        };
        for claim in &app.declaration.claims {
            let mut value = serde_json::to_value(claim)
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
            if let Some(detail) = &claim.semantic_claim {
                value["semantic_claim"]["proof_graph"] = Value::Null;
                for (kind, observations) in [
                    ("production_observations", &detail.production_observations),
                    ("test_observations", &detail.test_observations),
                    ("unknown_observations", &detail.unknown_observations),
                ] {
                    value["semantic_claim"][kind] =
                        json!({"paged_record_count":observations.len()});
                    for (index, observation) in observations.iter().enumerate() {
                        self.add_record(
                            "provenance",
                            format!("{}:{kind}:{index}", claim.id),
                            &claim.id,
                            json!({"classification":kind,"observation_ref":observation}),
                        )?;
                    }
                }
                if let Some(graph) = &detail.proof_graph {
                    for node in &graph.nodes {
                        self.add_record(
                            "proof_node",
                            format!("{}:{}", claim.id, node.node_id),
                            &claim.id,
                            json!(node),
                        )?;
                    }
                }
            }
            let scope = claim
                .semantic_claim
                .as_ref()
                .map_or(claim.scope_ref.as_str(), |detail| detail.module_id.as_str());
            self.add_record("claim", &claim.id, scope, value)?;
        }
        for evidence in &app.evidence {
            self.add_record(
                "evidence",
                &evidence.id,
                &evidence.scope_ref,
                json!(evidence),
            )?;
            self.evidence_edges
                .entry(evidence.source_ref.clone())
                .or_default()
                .push(evidence.id.clone());
        }
        for obligation in &app.obligations {
            let assessment = app
                .assessment
                .obligations
                .iter()
                .find(|result| result.id == obligation.id);
            self.add_record("obligation",&obligation.id,&obligation.scope_ref,json!({"id":obligation.id,"scope_ref":obligation.scope_ref,"predicate":obligation.predicate,"evidence_class":obligation.evidence_class,"authenticated_producer_required":obligation.authenticated_producer_required,"assessment":assessment,"proof_root":obligation.proof.as_ref().map(|proof|&proof.root_node_id)}))?;
            if let Some(proof) = &obligation.proof {
                for node in &proof.nodes {
                    self.add_record(
                        "proof_node",
                        format!("{}:{}", obligation.id, node.node_id),
                        &obligation.id,
                        json!(node),
                    )?;
                }
            }
        }
        for outcome in &app.assessment.obligations {
            if !app
                .obligations
                .iter()
                .any(|obligation| obligation.id == outcome.id)
            {
                self.add_record("obligation",&outcome.id,"UNAVAILABLE",json!({"assessment":outcome,"scope":"UNAVAILABLE","proof_metadata":"UNAVAILABLE: retained generation omitted the complete obligation manifest"}))?;
            }
        }
        Ok(())
    }

    pub(super) fn explain(
        &self,
        parameters: &ExplainParameters,
        cancelled: &AtomicBool,
    ) -> Result<ExplanationPage, QueryError> {
        let selector = &parameters.selector;
        let app = self.application().ok_or_else(|| {
            QueryError::new(
                "UNAVAILABLE",
                "a validated application endpoint is not loaded",
            )
        })?;
        let (claims, mut references) = self.explanation_references(selector, cancelled)?;
        let direct = self.records.iter().find(|record| record.id == *selector);
        // Expand actual evidence edges only. Cycles and shared nodes never explode paths.
        let mut pending = references.iter().cloned().collect::<VecDeque<_>>();
        while let Some(id) = pending.pop_front() {
            check_cancelled(cancelled)?;
            for target in self.evidence_edges.get(&id).into_iter().flatten() {
                if references.insert(target.clone()) {
                    pending.push_back(target.clone());
                }
            }
            if references.len() > 100_000 {
                return Err(QueryError::new(
                    "RESOURCE_LIMIT",
                    "explanation dependency closure exceeds limit",
                ));
            }
        }
        let selected = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                references.contains(&record.id)
                    || (matches!(record.kind.as_str(), "proof_node" | "provenance")
                        && references.contains(&record.scope_ref))
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let known = selected
            .iter()
            .filter(|index| self.records[**index].kind != "unresolved_reference")
            .map(|index| self.records[*index].id.as_str())
            .collect::<BTreeSet<_>>();
        let unresolved = references
            .iter()
            .filter(|reference| {
                !known.contains(reference.as_str())
                    && !app
                        .declaration
                        .claims
                        .iter()
                        .any(|claim| claim.scope_ref == **reference)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut rules = BTreeSet::new();
        for claim in &claims {
            if claim.rule_result.is_some() {
                rules.insert(
                    claim
                        .scope_ref
                        .strip_prefix("rule:")
                        .unwrap_or(&claim.scope_ref)
                        .to_owned(),
                );
            }
            if claim.semantic_claim.is_some() {
                rules.insert("ARCH-SEMANTIC-001".into());
            }
        }
        if let Some(rule) = direct
            .and_then(|record| record.value.get("rule_id"))
            .and_then(Value::as_str)
        {
            rules.insert(rule.into());
        }
        let descriptions = rules.iter().map(|id|self.input.standard.as_ref().and_then(|standard|standard.rules().iter().find(|rule|rule.id() == id)).map_or_else(||json!({"id":id,"meaning":"UNAVAILABLE: governing Standard rule text was not loaded"}),|rule|json!({"id":id,"statement":rule.statement(),"rationale":rule.rationale(),"failure_prevented":rule.failure_prevented(),"remediation":rule.remediation(),"provenance":{"path":rule.source_path(),"digest":rule.source_digest()}}))).collect::<Vec<_>>();
        let rule_text_basis = if app.declaration.binding.subject_ref == self.input.source_ref {
            "SOURCE_BOUND_AUTHORITY"
        } else {
            "CURRENT_AUTHORING_GUIDANCE_ONLY: historical rule text equivalence is not established"
        };
        let minimal = minimal_support(app, &claims, unresolved.is_empty());
        let description = json!({"governing_rules":descriptions,"rule_text_basis":rule_text_basis,"evaluated_scope_count":claims.len(),"scope_continuation":"All scopes are preserved in paged claim and obligation records; the description previews the first scope.","evaluated_scope":claims.iter().take(1).map(|claim|json!({"claim":claim.id,"scope_ref":claim.scope_ref,"truth":claim.truth,"semantic_scope":claim.semantic_claim.as_ref().map(|detail|json!({"module":detail.module_id,"selector":detail.scope_selector,"context_ref":detail.context_digest,"policy_digest":detail.policy_digest,"governed_source_files":detail.governed_source_files,"analysed_source_files":detail.analysed_source_files})),"reasons":claim.reason_codes,"assumptions":claim.assumptions,"defeaters":claim.defeater_refs})).collect::<Vec<_>>(),"binding":app.declaration.binding,"minimal_sufficient_evidence":minimal,"unresolved_dependency_count":unresolved.len(),"unresolved_dependencies":unresolved.iter().take(20).collect::<Vec<_>>(),"unresolved_continuation":"All unresolved references are retained in evidence pages; this description previews at most twenty.","evidence_availability":self.input.availability,"support_and_counterevidence":"Paged records include all supplied evidence, defeaters, provenance partitions and mandatory proof premises; no unresolved dependency is removed to obtain a favorable explanation.","remediation":"Follow the governing rule remediation and inspect unresolved premises. Any proposed authority or implementation change requires separate acceptance and fresh evaluation.","limitations":["Explanation reports the recorded upstream conclusion; no additional semantic evaluator or trust decision ran.","Missing raw evidence payloads and external producer authentication are not supplied by explanatory text."]});
        let evidence = self.page(
            &selected,
            &parameters.page,
            &digest(&json!({"explain":selector}))?,
            cancelled,
        )?;
        Ok(ExplanationPage {
            selector: selector.clone(),
            description,
            evidence,
        })
    }

    fn explanation_references<'a>(
        &'a self,
        selector: &String,
        cancelled: &AtomicBool,
    ) -> Result<
        (
            Vec<&'a crate::declaration::DeclarationClaim>,
            BTreeSet<String>,
        ),
        QueryError,
    > {
        let app = self
            .application()
            .ok_or_else(|| QueryError::new("UNAVAILABLE", "application is not loaded"))?;
        let mut references = BTreeSet::from([selector.clone()]);
        let mut claims = Vec::new();
        let obligation = app
            .obligations
            .iter()
            .find(|obligation| obligation.id == *selector);
        if let Some(obligation) = obligation {
            references.insert(obligation.scope_ref.clone());
            if let Some(proof) = &obligation.proof {
                for node in &proof.nodes {
                    references.extend(
                        node.required_refs
                            .iter()
                            .map(|reference| reference.id().to_owned()),
                    );
                }
            }
        }
        for claim in &app.declaration.claims {
            check_cancelled(cancelled)?;
            if claim.id == *selector
                || claim.scope_ref == *selector
                || claim.findings.contains(selector)
                || claim.defeater_refs.contains(selector)
                || obligation.is_some_and(|obligation| obligation.scope_ref == claim.scope_ref)
            {
                references.insert(claim.id.clone());
                references.extend(claim.proof_refs.clone());
                references.extend(claim.defeater_refs.clone());
                references.extend(claim.findings.clone());
                if let Some(detail) = &claim.semantic_claim {
                    references.extend(detail.upstream_proof_refs.clone());
                    if let Some(proof) = &detail.proof_graph {
                        for node in &proof.nodes {
                            references.extend(
                                node.required_refs
                                    .iter()
                                    .map(|reference| reference.id().to_owned()),
                            );
                        }
                    }
                }
                claims.push(claim);
            }
        }
        let direct = self.records.iter().find(|record| {
            record.id == *selector
                && matches!(
                    record.kind.as_str(),
                    "finding" | "defeater" | "obligation" | "claim"
                )
        });
        if claims.is_empty() && obligation.is_none() && direct.is_none() {
            return Err(QueryError::new(
                "NOT_FOUND",
                "no finding, claim, obligation or defeater has this exact identity",
            ));
        }
        Ok((claims, references))
    }

    pub(super) fn author(&self, parameters: &AuthorParameters) -> Result<Value, QueryError> {
        let module_id = self.resolve(&parameters.module)?;
        let module = self
            .input
            .ccg
            .as_ref()
            .and_then(|graph| graph.modules().get(&module_id))
            .ok_or_else(|| QueryError::new("UNAVAILABLE", "Module contract is unavailable"))?;
        let schema: Value =
            serde_json::from_str(crate::contract_coherency::module_contract_schema())
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        let effects = schema
            .pointer("/$defs/effect_id/enum")
            .or_else(|| schema.pointer("/$defs/effect/enum"));
        let capabilities = schema
            .pointer("/$defs/capability_id/enum")
            .or_else(|| schema.pointer("/$defs/capability/enum"));
        let mut preview = None;
        if let Some(target) = &parameters.target {
            let group = if effects
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(&json!(target)))
            {
                "effects"
            } else if capabilities
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(&json!(target)))
            {
                "capabilities"
            } else {
                return Err(QueryError::new(
                    "UNSUPPORTED_SEMANTICS",
                    "target is outside the supported policy schema vocabulary",
                ));
            };
            let disposition = parameters.disposition.ok_or_else(|| {
                QueryError::new(
                    "INVALID_PARAMETERS",
                    "a target preview requires ALLOW or DENY",
                )
            })?;
            let mut contract = serde_json::to_value(module.contract())
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
            contract["$schema"] = json!(crate::contract_coherency::MODULE_CONTRACT_SCHEMA);
            contract["schema_version"] =
                json!(crate::contract_coherency::MODULE_CONTRACT_SCHEMA_VERSION);
            if contract.get("semantic_policy").is_none() {
                contract["semantic_policy"] = json!({"default":"UNDECLARED","capabilities":{"allow":[],"deny":[]},"effects":{"allow":[],"deny":[]}});
            }
            let selected = match disposition {
                super::PolicyDisposition::Allow => "allow",
                super::PolicyDisposition::Deny => "deny",
            };
            for key in ["allow", "deny"] {
                let values = contract["semantic_policy"][group][key]
                    .as_array_mut()
                    .ok_or_else(|| QueryError::new("INVALID_INPUT", "policy schema mismatch"))?;
                values.retain(|value| value != target);
                if key == selected {
                    values.push(json!(target));
                    values.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                }
            }
            let proposed: crate::contract_coherency::ModuleContract =
                serde_json::from_value(contract)
                    .map_err(|error| QueryError::new("INVALID_PROPOSAL", error.to_string()))?;
            let bytes = proposed
                .to_canonical_json()
                .map_err(|error| QueryError::new("INVALID_PROPOSAL", error.to_string()))?;
            let validated = crate::contract_coherency::ModuleContract::from_json_str(&bytes)
                .map_err(|error| QueryError::new("INVALID_PROPOSAL", error.to_string()))?;
            preview = Some(
                validated
                    .to_canonical_json()
                    .map_err(|error| QueryError::new("INVALID_PROPOSAL", error.to_string()))?,
            );
        } else if parameters.disposition.is_some() {
            return Err(QueryError::new(
                "INVALID_PARAMETERS",
                "disposition requires a target",
            ));
        }
        Ok(
            json!({"classification":"PROPOSED","module":module_id,"contract_path":module.contract_path(),"preimage_digest":module.digest(),"schema_ref":schema["$id"],"schema_guidance":schema["$defs"]["semantic_policy"],"supported_effects":effects,"supported_capabilities":capabilities,"canonical_contract_preview":preview,"effect_precedence":"Explicit effect disposition overrides encompassing capability disposition; unlisted effects remain UNDECLARED.","acceptance":"UNAPPROVED: no authority write, permission grant, migration or evaluation occurred.","workflow":["Select a unique readable Module name or canonical ID.","Choose a supported target and explicit disposition.","Review the canonical proposed contract against its preimage.","Apply and accept through an independently authorized workflow, then evaluate the exact resulting state."]}),
        )
    }
}

fn minimal_support(
    app: &crate::application::ApplicationAssessment,
    claims: &[&crate::declaration::DeclarationClaim],
    dependencies_available: bool,
) -> Value {
    if claims.len() == 1 {
        let claim = claims[0];
        if claim.proof_refs.len() == 1
            && dependencies_available
            && claim.semantic_claim.is_none()
            && claim.defeater_refs.is_empty()
            && claim.assumptions.is_empty()
            && app.evidence.iter().any(|evidence| {
                evidence.source_ref == claim.proof_refs[0]
                    && evidence.binding == app.declaration.binding
                    && evidence.scope_ref == claim.scope_ref
                    && evidence.assumptions.is_empty()
                    && matches!(
                        (claim.truth, evidence.proposition),
                        (
                            DeclarationTruth::SupportedViolation,
                            crate::assessment::EvidenceProposition::SupportedViolation
                        ) | (
                            DeclarationTruth::NoSupportedViolation,
                            crate::assessment::EvidenceProposition::NoSupportedViolation
                        )
                    )
            })
        {
            json!({"basis":"RECORDED_SINGLE_PREMISE","refs":claim.proof_refs,"limitations":"Minimal for this recorded single-premise upstream conclusion, not a newly authenticated proof or a global minimum across unknown alternatives."})
        } else {
            json!({"basis":"NOT_ESTABLISHED","refs":[],"limitations":"No accepted minimal alternative is recorded. All supplied proof nodes, assumptions and unresolved dependencies remain available in evidence pages."})
        }
    } else {
        json!({"basis":"NOT_ESTABLISHED","refs":[],"limitations":"Multiple or unavailable upstream conclusions; no joint minimum is asserted."})
    }
}
