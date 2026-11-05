//! Application composition over existing evaluator and Standard-owned results.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assessment::{
    AssessmentEvidence, EvidenceAcceptancePolicy, EvidenceProposition, ExpectedProfileAssessment,
    ObligationPredicate, ProfileAssessment, ProfileObligation,
};
use crate::certification::EvidenceClass;
use crate::declaration::{
    ConformanceDeclaration, DeclarationArtifact, DeclarationBinding, DeclarationClaim,
    DeclarationClaimKind, DeclarationError, DeclarationResidue, DeclarationTruth,
    DimensionManifest, RequiredDimension, ScopedProfileReference, SemanticClaimDetail, canonical,
};
use crate::finding_governance::{
    FindingDisposition, FindingEnforcement, FindingGovernanceEvaluation, FindingLifecycle,
};
use crate::profile::{RequiredEvidenceClass, ResolvedProfiles};
use crate::program_semantics::ExecutionProvenance;
use crate::proof::{EvidenceReference, ProofExpression, ProofGraph, ProofOperator};
use crate::semantic_conformance::{SemanticConformanceModel, SemanticConformanceState};

/// Typed upstream rule execution, supplied by orchestration without a dependency
/// from Certification back into Snapshot Governance.
#[derive(Clone, Debug)]
pub struct ApplicationRuleInput {
    /// Exact Standard rule identity.
    pub rule_id: String,
    /// Raw upstream outcome; not a Module policy proposition.
    pub outcome: ApplicationRuleOutcome,
    /// Exact upstream applicability decision.
    pub applicable: bool,
    /// Every raw finding produced by this rule.
    pub findings: Vec<String>,
    /// Original evaluator detail, retained without interpreting it as policy.
    pub detail: String,
    /// Original upstream applicability reason.
    pub applicability_reason: Option<String>,
}

/// Closed projection of existing rule execution states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationRuleOutcome {
    /// The registered check succeeded.
    Passed,
    /// The registered check found a contradiction.
    Failed,
    /// The registered check has required uncertainty.
    Unsupported,
    /// The registered check has no current applicable subject.
    NotApplicable,
}

/// Application reporting products; no successful Rust execution is synthesized.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationAssessment {
    /// Stable project identity supplied by the compiled authored root authority.
    pub project: String,
    /// Complete truthful reporting, even for a failing application.
    pub declaration: ConformanceDeclaration,
    /// Exact selected-profile assessment, separate from implementation qualification.
    pub assessment: ProfileAssessment,
    /// Replayable scoped static evidence metadata.
    pub evidence: Vec<AssessmentEvidence>,
    /// Complete expected obligations for independent replay against trusted authority.
    pub obligations: Vec<ProfileObligation>,
}

/// Composes application reporting from typed upstream results and selected authority.
///
/// # Errors
/// Rejects missing selected results, inconsistent reporting or invalid proof structure.
#[allow(clippy::too_many_lines)]
pub fn compose_application(
    project: &str,
    binding: DeclarationBinding,
    profiles: &ResolvedProfiles,
    model: &SemanticConformanceModel,
    rules: &[ApplicationRuleInput],
    governance: &FindingGovernanceEvaluation,
    artifacts: Vec<DeclarationArtifact>,
) -> Result<ApplicationAssessment, DeclarationError> {
    let policy = crate::profile::ApplicationAssessmentPolicy::installed()
        .map_err(|e| DeclarationError::Invalid(e.to_string()))?;
    let mut references = Vec::new();
    let scoped = |module: Option<String>, p: &crate::profile::ResolvedProfileReference| {
        ScopedProfileReference {
            module,
            id: p.id.clone(),
            version: p.version.clone(),
            digest: p.digest.clone(),
        }
    };
    references.extend(profiles.references().iter().map(|p| scoped(None, p)));
    for (module, selection) in profiles.module_overrides() {
        references.extend(
            selection
                .references()
                .iter()
                .map(|p| scoped(Some(module.clone()), p)),
        );
    }
    references.sort();
    let mut dimensions = profiles
        .semantic_scopes()
        .iter()
        .map(|scope| (scope.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    dimensions.insert(
        "RULE_CHECKS".into(),
        profiles
            .active_rules()
            .iter()
            .map(|rule| format!("rule:{rule}"))
            .collect(),
    );
    for (module, selection) in profiles.module_overrides() {
        for scope in selection.declaration_scopes() {
            dimensions.insert(format!("MODULE:{module}:{scope}"), Vec::new());
        }
    }
    for (dimension, rules) in policy.dimension_rule_sets() {
        if profiles.semantic_scopes().contains(dimension)
            || (dimension == "PROGRAM_SEMANTICS_CHECKS"
                && profiles.semantic_scopes().contains("PROGRAM_SEMANTICS"))
        {
            dimensions.entry(dimension.clone()).or_default().extend(
                rules
                    .iter()
                    .filter(|r| profiles.rule_applicable(r))
                    .map(|r| format!("rule:{r}")),
            );
        }
    }
    let mut claims = Vec::new();
    let mut obligations = Vec::new();
    let mut evidence = Vec::new();
    let mut acceptance = EvidenceAcceptancePolicy::default();
    for rule in profiles.active_rules() {
        let execution = rules.iter().find(|r| &r.rule_id == rule).ok_or_else(|| {
            DeclarationError::Invalid(format!("selected rule result missing: {rule}"))
        })?;
        let id = format!("rule:{rule}");
        let truth = match execution.outcome {
            ApplicationRuleOutcome::Passed => DeclarationTruth::NoSupportedViolation,
            ApplicationRuleOutcome::Failed => DeclarationTruth::SupportedViolation,
            ApplicationRuleOutcome::Unsupported => DeclarationTruth::NotEvaluable,
            ApplicationRuleOutcome::NotApplicable => DeclarationTruth::NotApplicable,
        };
        let leaf_id = format!("rule-result:{rule}");
        let mut findings = execution.findings.clone();
        findings.sort();
        findings.dedup();
        let claim = DeclarationClaim {
            rule_result: Some(crate::declaration::RuleClaimDetail {
                outcome: execution.outcome,
                applicable: execution.applicable,
                detail: execution.detail.clone(),
                applicability_reason: execution.applicability_reason.clone(),
            }),
            kind: DeclarationClaimKind::RuleCheck,
            id: id.clone(),
            scope_ref: id.clone(),
            truth,
            proof_refs: vec![leaf_id.clone()],
            findings,
            defeater_refs: vec![],
            reason_codes: vec![],
            assumptions: vec![],
            semantic_claim: None,
        };
        add_static_leaves(&claim, &binding, &mut evidence, &mut acceptance)?;
        // Not applicable checks are explicitly reported but impose no fictional
        // application subject. They never satisfy a semantic evaluability obligation.
        if execution.applicable {
            obligations.push(ProfileObligation {
                id: id.clone(),
                scope_ref: id,
                predicate: ObligationPredicate::RuleCheck,
                evidence_class: EvidenceClass::StaticProof,
                authenticated_producer_required: false,
                proof: Some(single_leaf(&scoped_leaf_id(&claim.scope_ref, &leaf_id))),
            });
        }
        claims.push(claim);
    }
    for module in model.modules() {
        if !dimensions.contains_key("PROGRAM_SEMANTICS")
            && !dimensions.contains_key(&format!("MODULE:{}:PROGRAM_SEMANTICS", module.module()))
        {
            continue;
        }
        let ids = module.required_claim_ids();
        if let Some(required) = dimensions.get_mut("PROGRAM_SEMANTICS") {
            required.extend(ids.iter().cloned());
        }
        if let Some(required) =
            dimensions.get_mut(&format!("MODULE:{}:PROGRAM_SEMANTICS", module.module()))
        {
            required.extend(ids);
        }
        for conclusion in module.conclusions() {
            let truth = match conclusion.conformance() {
                None => DeclarationTruth::Authorization,
                Some(SemanticConformanceState::SupportedViolation) => {
                    DeclarationTruth::SupportedViolation
                }
                Some(SemanticConformanceState::NoSupportedViolation) => {
                    DeclarationTruth::NoSupportedViolation
                }
                Some(SemanticConformanceState::NotEvaluable) => DeclarationTruth::NotEvaluable,
                Some(SemanticConformanceState::NotApplicable) => DeclarationTruth::NotApplicable,
            };
            let evaluation = conclusion.evaluation();
            let instance = conclusion.instance();
            let mut detail = SemanticClaimDetail {
                upstream_proof_refs: evaluation.proof_refs().to_vec(),
                instance_id: instance.id().into(),
                slot_id: conclusion.slot().id().into(),
                module_id: module.module().into(),
                scope_selector: conclusion.slot().scope_selector().into(),
                context_family: conclusion.slot().context_family().into(),
                policy_digest: instance.policy_digest().into(),
                context_digest: instance.context_digest().into(),
                governed_universe_digest: instance.governed_universe_digest().into(),
                producer_identity: instance.producer_identity().into(),
                target_kind: format!("{:?}", conclusion.target_kind()).to_uppercase(),
                target: conclusion.target().into(),
                disposition: format!("{:?}", conclusion.disposition()).to_uppercase(),
                governed_source_files: conclusion.coverage().governed_source_files() as u64,
                analysed_source_files: conclusion.coverage().analysed_source_files() as u64,
                production_observations: vec![],
                test_observations: vec![],
                unknown_observations: vec![],
                proof_graph: evaluation.proof_graph().cloned(),
                blocking_eligibility: conclusion.blocking_eligibility().map(|e| match e {
                    crate::semantic_conformance::BlockingEligibility::BlockSupported => {
                        "BLOCK_SUPPORTED".into()
                    }
                    crate::semantic_conformance::BlockingEligibility::AdvisoryOnly => {
                        "ADVISORY_ONLY".into()
                    }
                    crate::semantic_conformance::BlockingEligibility::NotEvaluable => {
                        "NOT_EVALUABLE".into()
                    }
                }),
            };
            for partition in evaluation.supported_partitions() {
                let target = match partition.execution_provenance() {
                    ExecutionProvenance::ProductionCapable => &mut detail.production_observations,
                    ExecutionProvenance::TestOnly => &mut detail.test_observations,
                    ExecutionProvenance::Unknown => &mut detail.unknown_observations,
                };
                target.extend(partition.observation_refs().iter().cloned());
                target.sort();
                target.dedup();
            }
            let mut proof_refs = evaluation.proof_refs().to_vec();
            if let Some(graph) = evaluation.proof_graph() {
                proof_refs.extend(
                    graph
                        .nodes
                        .iter()
                        .flat_map(|node| node.required_refs.iter().map(|r| r.id().to_owned())),
                );
            }
            proof_refs.sort();
            proof_refs.dedup();
            let claim = DeclarationClaim {
                rule_result: None,
                kind: DeclarationClaimKind::SemanticPolicy,
                id: conclusion.id().into(),
                scope_ref: instance.id().into(),
                truth,
                proof_refs,
                findings: evaluation.findings().to_vec(),
                defeater_refs: conclusion.defeater_refs().to_vec(),
                reason_codes: evaluation.reason_codes().to_vec(),
                assumptions: evaluation.assumptions().to_vec(),
                semantic_claim: Some(detail),
            };
            add_static_leaves(&claim, &binding, &mut evidence, &mut acceptance)?;
            if truth != DeclarationTruth::Authorization {
                obligations.push(ProfileObligation {
                    id: format!("conformance:{}", claim.id),
                    scope_ref: claim.scope_ref.clone(),
                    predicate: ObligationPredicate::Conformance,
                    evidence_class: EvidenceClass::StaticProof,
                    authenticated_producer_required: false,
                    proof: evaluation
                        .proof_graph()
                        .map(|graph| scoped_proof(&claim.scope_ref, graph)),
                });
            }
            claims.push(claim);
        }
    }
    // Required evidence descriptors add sufficiency requirements. Presence alone,
    // a rule-check PASS, authorization, and an empty claim universe are insufficient.
    for (module, required) in std::iter::once((None, profiles.required_evidence())).chain(
        profiles
            .module_overrides()
            .iter()
            .map(|(id, p)| (Some(id.as_str()), p.required_evidence())),
    ) {
        for requirement in required {
            let relevant = claims
                .iter()
                .filter(|c| {
                    c.semantic_claim
                        .as_ref()
                        .is_some_and(|s| module.is_none_or(|id| s.module_id == id))
                        && c.truth != DeclarationTruth::Authorization
                })
                .collect::<Vec<_>>();
            let class = match requirement.evidence_class() {
                RequiredEvidenceClass::StaticProof => EvidenceClass::StaticProof,
                RequiredEvidenceClass::ExecutedTest => EvidenceClass::ExecutedTest,
                RequiredEvidenceClass::ExecutedScenario => EvidenceClass::ExecutedScenario,
                RequiredEvidenceClass::Authority => EvidenceClass::Authority,
            };
            if relevant.is_empty() || !policy.requires_evaluability(requirement) {
                obligations.push(ProfileObligation {
                    id: format!(
                        "required:{}:{}",
                        module.unwrap_or("repository"),
                        requirement.id()
                    ),
                    scope_ref: requirement.semantic_scope().into(),
                    predicate: ObligationPredicate::Evaluability,
                    evidence_class: class,
                    authenticated_producer_required: false,
                    proof: None,
                });
            } else {
                for claim in relevant {
                    obligations.push(ProfileObligation {
                        id: format!(
                            "required:{}:{}:{}",
                            module.unwrap_or("repository"),
                            requirement.id(),
                            claim.id
                        ),
                        scope_ref: claim.scope_ref.clone(),
                        predicate: ObligationPredicate::Evaluability,
                        evidence_class: class,
                        authenticated_producer_required: false,
                        proof: claim
                            .semantic_claim
                            .as_ref()
                            .and_then(|s| s.proof_graph.as_ref())
                            .map(|graph| scoped_proof(&claim.scope_ref, graph)),
                    });
                }
            }
        }
    }
    for refs in dimensions.values_mut() {
        refs.sort();
        refs.dedup();
    }
    let manifest = DimensionManifest {
        profiles: references,
        dimensions: dimensions
            .into_iter()
            .map(|(id, claim_refs)| RequiredDimension { id, claim_refs })
            .collect(),
    };
    let mut residue = DeclarationResidue::default();
    for finding in governance.findings() {
        let id = finding.finding_id().to_owned();
        if finding.lifecycle() == FindingLifecycle::Baselined {
            residue.accepted_baseline.push(id.clone());
        }
        if finding.disposition() == FindingDisposition::Excepted {
            residue.accepted_exceptions.push(id.clone());
        }
        if finding.enforcement() == FindingEnforcement::Blocking {
            residue.blocking_findings.push(id);
        }
    }
    for refs in [
        &mut residue.accepted_baseline,
        &mut residue.accepted_exceptions,
        &mut residue.blocking_findings,
    ] {
        refs.sort();
        refs.dedup();
    }
    obligations.sort_by(|a, b| a.id.cmp(&b.id));
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    // A shared premise may support multiple claims with different propositions.
    // Bind each admission to its scope so the producer cannot transfer authority.
    let mut expected_artifacts = artifacts.clone();
    expected_artifacts.sort();
    let declaration = ConformanceDeclaration::compose(
        binding.clone(),
        manifest.clone(),
        claims,
        artifacts,
        residue,
    )?;
    let profile_digest = format!(
        "sha256:{:x}",
        Sha256::digest(canonical(&(
            "application-assessment-policy-v1",
            policy.digest(),
            profiles.layout_id(),
            &manifest.profiles,
            profiles.module_overrides().keys().collect::<Vec<_>>()
        ))?)
    );
    let expected = ExpectedProfileAssessment {
        artifacts: expected_artifacts,
        binding,
        dimensions: manifest,
        profile_digest,
        obligations: obligations.clone(),
    };
    let assessment = ProfileAssessment::evaluate(&declaration, &expected, &evidence, &acceptance)?;
    Ok(ApplicationAssessment {
        project: project.into(),
        declaration,
        assessment,
        evidence,
        obligations,
    })
}

fn single_leaf(id: &str) -> ProofGraph {
    ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".into(),
            operator: ProofOperator::Leaf,
            required_refs: vec![
                EvidenceReference::new(id).expect("canonical evaluator evidence identity"),
            ],
            children: vec![],
        }],
    )
}

fn add_static_leaves(
    claim: &DeclarationClaim,
    binding: &DeclarationBinding,
    evidence: &mut Vec<AssessmentEvidence>,
    policy: &mut EvidenceAcceptancePolicy,
) -> Result<(), DeclarationError> {
    let claim_digest = format!("sha256:{:x}", Sha256::digest(canonical(claim)?));
    for source_ref in &claim.proof_refs {
        let payload_digest = format!(
            "sha256:{:x}",
            Sha256::digest(canonical(&(
                "static-claim-premise-v1",
                binding,
                &claim_digest,
                source_ref
            ))?)
        );
        let id = scoped_leaf_id(&claim.scope_ref, source_ref);
        let leaf = AssessmentEvidence {
            id: id.clone(),
            source_ref: source_ref.clone(),
            binding: binding.clone(),
            scope_ref: claim.scope_ref.clone(),
            evidence_class: if matches!(
                claim.truth,
                DeclarationTruth::SupportedViolation | DeclarationTruth::NoSupportedViolation
            ) {
                EvidenceClass::StaticProof
            } else {
                EvidenceClass::Observation
            },
            proposition: match claim.truth {
                DeclarationTruth::SupportedViolation => EvidenceProposition::SupportedViolation,
                DeclarationTruth::NoSupportedViolation => EvidenceProposition::NoSupportedViolation,
                _ => EvidenceProposition::ObservationOnly,
            },
            payload_digest: payload_digest.clone(),
            assumptions: claim.assumptions.clone(),
            valid_until: None,
        };
        policy.verified_payloads.insert(id.clone(), payload_digest);
        policy.verified_metadata.insert(id, leaf.metadata_digest()?);
        evidence.push(leaf);
    }
    Ok(())
}

fn scoped_leaf_id(scope: &str, id: &str) -> String {
    format!(
        "assessment-leaf:sha256:{:x}",
        Sha256::digest(canonical(&(scope, id)).expect("static strings serialize"))
    )
}

fn scoped_proof(scope: &str, graph: &ProofGraph) -> ProofGraph {
    let mut graph = graph.clone();
    for node in &mut graph.nodes {
        node.required_refs = node
            .required_refs
            .iter()
            .map(|r| {
                EvidenceReference::new(scoped_leaf_id(scope, r.id()))
                    .expect("scoped digest is stable")
            })
            .collect();
        node.required_refs.sort();
    }
    graph
}
