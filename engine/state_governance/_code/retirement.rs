//! Comparable retirement from existing declarations, four-axis comparison and proof assessor.
//! No absence-only fix inference, authority mutation or semantic evaluator.
use super::{
    Axis, Change, ComparisonContext, ComparisonState, MAX_TRANSITION_RECORDS, TransitionAnalysis,
    TransitionError, compare_states, digest, fail,
};
use crate::declaration::{DeclarationClaim, DeclarationClaimKind, DeclarationTruth};
use crate::finding::CanonicalFinding;
use crate::finding_governance::{
    FindingAnchor, FindingGovernanceDocument, RetirementComparisonBasis, RetirementEvidenceV2,
    RetirementOutcome as O, finding_semantic_ref, lifecycle_digest,
};
use std::collections::{BTreeMap, BTreeSet};
fn error(e: impl std::fmt::Display) -> TransitionError {
    fail("INVALID_INPUT", e.to_string())
}
fn slot(c: &DeclarationClaim) -> &str {
    c.semantic_claim
        .as_ref()
        .map_or(c.id.as_str(), |s| s.slot_id.as_str())
}
fn claims(state: &ComparisonState) -> &[DeclarationClaim] {
    super::claims::application(state).map_or(&[], |a| a.declaration.claims.as_slice())
}
struct StateIndex<'a> {
    findings: BTreeMap<&'a str, Vec<&'a DeclarationClaim>>,
    slots: BTreeMap<&'a str, Vec<&'a DeclarationClaim>>,
    definitions: BTreeMap<&'a str, Vec<(&'a str, &'a str)>>,
    basis: Option<String>,
    generic_intent_ref: String,
    source_scopes: BTreeSet<&'a str>,
}
impl<'a> StateIndex<'a> {
    fn new(state: &'a ComparisonState) -> Result<Self, TransitionError> {
        let mut findings = BTreeMap::<&str, Vec<&DeclarationClaim>>::new();
        let mut slots = BTreeMap::<&str, Vec<&DeclarationClaim>>::new();
        let mut count = 0usize;
        for c in claims(state) {
            count = count.saturating_add(1 + c.findings.len());
            if count > MAX_TRANSITION_RECORDS {
                return Err(fail(
                    "RESOURCE_LIMIT",
                    "retirement claim/reference admission exceeded",
                ));
            }
            slots.entry(slot(c)).or_default().push(c);
            for id in &c.findings {
                findings.entry(id).or_default().push(c);
            }
        }
        for values in findings.values_mut() {
            if values
                .iter()
                .any(|c| c.kind == DeclarationClaimKind::SemanticPolicy)
            {
                values.retain(|c| c.kind == DeclarationClaimKind::SemanticPolicy);
            }
        }
        let mut definitions = BTreeMap::<&str, Vec<(&str, &str)>>::new();
        if let Some(a) = &state.assets {
            for e in &a.entities {
                definitions
                    .entry(&e.id)
                    .or_default()
                    .push((&e.kind, &e.semantic_ref));
            }
        }
        for values in definitions.values_mut() {
            values.sort_unstable();
        }
        let basis = if super::comparison::comparable(state, state) {
            let a = state.assets.as_ref().expect("comparable");
            let app = super::claims::application(state).expect("comparable");
            let authority_inputs = a
                .inputs
                .iter()
                .filter_map(|i| i.roles.get(&Axis::Authority).map(|r| (&i.id, r)))
                .collect::<BTreeMap<_, _>>();
            Some(digest(&serde_json::json!([
                "retirement-definition-basis-v2",
                a.standard_ref,
                a.profile_refs,
                a.evaluator_ref,
                a.exclusions_ref,
                app.declaration.binding.context_ref,
                authority_inputs
            ]))?)
        } else {
            None
        };
        let source_scopes = state.assets.as_ref().map_or_else(BTreeSet::new, |a| {
            a.inputs
                .iter()
                .filter(|i| i.roles.contains_key(&Axis::Subject))
                .flat_map(|i| i.scope_refs.iter().map(String::as_str))
                .collect()
        });
        let generic_intent = state.assets.as_ref().map_or_else(BTreeMap::new, |a| {
            a.inputs
                .iter()
                .filter_map(|i| i.roles.get(&Axis::Intent).map(|r| (&i.id, r)))
                .collect()
        });
        Ok(Self {
            findings,
            slots,
            definitions,
            basis,
            generic_intent_ref: digest(&generic_intent)?,
            source_scopes,
        })
    }
    fn finding_claims(&self, id: &str) -> Vec<&'a DeclarationClaim> {
        self.findings.get(id).cloned().unwrap_or_default()
    }
    fn meaning(
        &self,
        c: &DeclarationClaim,
        subjects: &[String],
    ) -> Result<Option<String>, TransitionError> {
        let Some(basis) = &self.basis else {
            return Ok(None);
        };
        let detail = c.semantic_claim.as_ref().map(|s| {
            serde_json::json!([
                s.module_id,
                s.target_kind,
                s.target,
                s.scope_selector,
                s.context_family,
                s.context_digest,
                s.producer_identity,
                s.disposition,
                s.policy_digest
            ])
        });
        let definitions = if c.kind == DeclarationClaimKind::RuleCheck {
            subjects
                .iter()
                .map(|id| {
                    (
                        id,
                        self.definitions
                            .get(id.as_str())
                            .cloned()
                            .unwrap_or_default(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        Ok(Some(digest(&serde_json::json!([
            "finding-meaning-v2",
            basis,
            c.kind,
            slot(c),
            detail,
            (c.kind == DeclarationClaimKind::RuleCheck).then_some(&self.generic_intent_ref),
            definitions
        ]))?))
    }
}
/// Observes current meanings for already governed stable IDs, without changing admissions.
/// Consumers with raw findings must additionally check their original semantic metadata.
/// # Errors
/// Refuses ambiguous identity/slot projections and unavailable governing meaning.
pub fn current_governance_anchors(
    state: &ComparisonState,
    document: &FindingGovernanceDocument,
) -> Result<BTreeMap<String, FindingAnchor>, TransitionError> {
    document.authority_digest().map_err(error)?;
    state.validate()?;
    let index = StateIndex::new(state)?;
    let Some(records) = document.lifecycle() else {
        return Ok(BTreeMap::new());
    };
    let mut originals = BTreeMap::<String, &FindingAnchor>::new();
    for a in records.anchors.values().chain(
        records
            .exception_reviews
            .values()
            .filter_map(|r| r.anchor.as_ref()),
    ) {
        if originals.get(&a.finding_id).is_some_and(|old| {
            old.identity_ref != a.identity_ref || old.claim_scope_ref != a.claim_scope_ref
        }) {
            return Err(fail("IDENTITY_AMBIGUOUS", "governed identities disagree"));
        }
        originals.insert(a.finding_id.clone(), a);
    }
    let mut result = BTreeMap::new();
    let from = state.digest()?;
    for (id, original) in originals {
        if original.subject_refs.iter().any(|subject| {
            index
                .definitions
                .get(subject.as_str())
                .is_some_and(|v| v.len() > 1)
        }) {
            return Err(fail(
                "IDENTITY_AMBIGUOUS",
                "current governed subject has several occurrences",
            ));
        }
        let candidates = index.finding_claims(&id);
        if candidates.is_empty() {
            continue;
        }
        if candidates.len() != 1 {
            return Err(fail(
                "IDENTITY_AMBIGUOUS",
                "current governed finding has several claims",
            ));
        }
        let c = candidates[0];
        let Some(m) = index.meaning(c, &original.subject_refs)? else {
            continue;
        };
        let Some(app) = super::claims::application(state) else {
            continue;
        };
        let mut observed = original.clone();
        observed.from_state.clone_from(&from);
        observed
            .subject_ref
            .clone_from(&app.declaration.binding.subject_ref);
        observed
            .original_authority_ref
            .clone_from(&app.declaration.binding.authority_ref);
        observed.meaning_ref = m;
        observed.claim_scope_ref = slot(c).into();
        result.insert(id, observed);
    }
    Ok(result)
}
/// Anchors exact eligible findings to the original unique owner-produced claim and authority.
/// Rule summary duplicates do not compete with a more specific semantic claim.
/// # Errors
/// Rejects ambiguous semantic identities, missing historical authority and resource exhaustion.
pub fn finding_anchors(
    state: &ComparisonState,
    findings: &[CanonicalFinding],
) -> Result<BTreeMap<String, FindingAnchor>, TransitionError> {
    state.validate()?;
    let index = StateIndex::new(state)?;
    if findings.len() > MAX_TRANSITION_RECORDS {
        return Err(fail("RESOURCE_LIMIT", "finding anchor limit"));
    }
    let from = state.digest()?;
    let app = super::claims::application(state)
        .ok_or_else(|| fail("NOT_EVALUABLE", "original declaration unavailable"))?;
    let mut result: BTreeMap<String, FindingAnchor> = BTreeMap::new();
    for f in findings.iter().filter(|f| {
        f.identity_eligibility() == crate::finding::FindingIdentityEligibility::Eligible
    }) {
        let candidates = index.finding_claims(f.finding_id());
        if candidates.len() != 1
            || f.entities().iter().any(|subject| {
                index
                    .definitions
                    .get(subject.as_str())
                    .is_some_and(|v| v.len() > 1)
            })
        {
            return Err(fail(
                "IDENTITY_AMBIGUOUS",
                "finding must map to one original semantic obligation",
            ));
        }
        let c = candidates[0];
        if c.truth != DeclarationTruth::SupportedViolation {
            return Err(fail(
                "INVALID_INPUT",
                "finding anchor has no original supported violation",
            ));
        }
        let a = FindingAnchor {
            finding_id: f.finding_id().into(),
            rule_id: f.rule_id().into(),
            from_state: from.clone(),
            subject_ref: app.declaration.binding.subject_ref.clone(),
            original_authority_ref: app.declaration.binding.authority_ref.clone(),
            meaning_ref: index
                .meaning(c, f.entities())?
                .ok_or_else(|| fail("NOT_EVALUABLE", "complete original authority is required"))?,
            claim_scope_ref: slot(c).into(),
            identity_ref: finding_semantic_ref(f).map_err(error)?,
            subject_refs: f.entities().to_vec(),
        };
        a.validate().map_err(error)?;
        if result.get(&a.finding_id).is_some_and(|old| old != &a) {
            return Err(fail(
                "IDENTITY_AMBIGUOUS",
                "same finding identity has conflicting original metadata",
            ));
        }
        result.insert(a.finding_id.clone(), a);
    }
    Ok(result)
}
/// Assesses original active residue against two explicitly identified immutable endpoints.
/// The neutral records are derived, not permission to mutate authority or authenticate producers.
/// # Errors
/// Refuses malformed states, ambiguous authority and bounded-resource exhaustion.
pub fn assess_retirements(
    before: &ComparisonState,
    after: &ComparisonState,
    governance: &FindingGovernanceDocument,
    context: &ComparisonContext,
) -> Result<Vec<RetirementEvidenceV2>, TransitionError> {
    let entries = governance
        .baseline()
        .map(|b| {
            b.active_entries()
                .iter()
                .map(|e| {
                    (
                        e.finding_id().to_owned(),
                        governance
                            .lifecycle()
                            .and_then(|g| g.anchors.get(e.finding_id()))
                            .cloned(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assess_anchor_entries(before, after, entries, governance, context)
}

/// Compares exact owner-produced original findings without creating a baseline or authority.
/// Reuses the same comparable resolution classifier as governed baseline retirement.
/// # Errors
/// Refuses ambiguous identities, missing original meaning and exhausted input/output admission.
pub fn assess_original_findings(
    before: &ComparisonState,
    after: &ComparisonState,
    findings: &[CanonicalFinding],
    governance: &FindingGovernanceDocument,
    context: &ComparisonContext,
) -> Result<Vec<RetirementEvidenceV2>, TransitionError> {
    let entries = finding_anchors(before, findings)?
        .into_iter()
        .map(|(id, anchor)| (id, Some(anchor)))
        .collect();
    assess_anchor_entries(before, after, entries, governance, context)
}

fn assess_anchor_entries(
    before: &ComparisonState,
    after: &ComparisonState,
    entries: Vec<(String, Option<FindingAnchor>)>,
    governance: &FindingGovernanceDocument,
    context: &ComparisonContext,
) -> Result<Vec<RetirementEvidenceV2>, TransitionError> {
    let governance_ref = governance.authority_digest().map_err(error)?;
    let transition = compare_states(before, after, context)?;
    let before_index = StateIndex::new(before)?;
    let after_index = StateIndex::new(after)?;
    let mut resolution_cache = None;
    if entries.len() > MAX_TRANSITION_RECORDS {
        return Err(fail(
            "RESOURCE_LIMIT",
            "retirement record admission exceeded",
        ));
    }
    let transition_ref = transition.digest()?;
    let mut records = Vec::new();
    let mut retained_bytes = 2usize;
    for (finding_id, owned_anchor) in entries {
        let anchor = owned_anchor.as_ref();
        let (outcome, proofs, reason) = classify(
            before,
            after,
            anchor,
            &transition,
            &before_index,
            &after_index,
            &mut resolution_cache,
        )?;
        let record=RetirementEvidenceV2{schema:"urn:fortress:derived:v2:retirement-evidence".into(),schema_version:2,finding_id:finding_id.clone(),original_authority_ref:anchor.map(|a|a.original_authority_ref.clone()),from_subject:before.source_ref.clone(),to_subject:after.source_ref.clone(),claim_scope_ref:anchor.map(|a|a.claim_scope_ref.clone()),comparison_basis:RetirementComparisonBasis{from_state:transition.from_state.clone(),to_state:transition.to_state.clone(),transition_ref:transition_ref.clone(),governance_ref:governance_ref.clone(),anchor_ref:anchor.map(lifecycle_digest).transpose().map_err(error)?},outcome,proof_refs:proofs,reasons:vec![reason],limitations:vec!["Derived comparison preserves original authority and raw truth. Integrity is not producer authentication or external authorization.".into(),"Mutation requires deliberate selection, exact governance preimages and the existing protected AUTHORITY boundary; serialized records are not grants.".into()]};
        record.validate().map_err(error)?;
        let bytes = crate::finding_governance::lifecycle_bytes(&record)
            .map_err(error)?
            .len();
        retained_bytes = retained_bytes
            .checked_add(bytes + 1)
            .filter(|total| *total <= crate::finding_governance::MAX_GOVERNANCE_BYTES)
            .ok_or_else(|| {
                fail(
                    "RESOURCE_LIMIT",
                    "aggregate retirement output exceeds byte admission",
                )
            })?;
        records.push(record);
    }
    crate::finding_governance::lifecycle_bytes(&records).map_err(error)?;
    Ok(records)
}
fn classify(
    before: &ComparisonState,
    after: &ComparisonState,
    anchor: Option<&FindingAnchor>,
    transition: &TransitionAnalysis,
    before_index: &StateIndex,
    after_index: &StateIndex,
    resolution_cache: &mut Option<BTreeMap<String, Vec<String>>>,
) -> Result<(O, Vec<String>, String), TransitionError> {
    let result = |o, r: &str| Ok((o, vec![], r.into()));
    let Some(anchor) = anchor else {
        return result(
            O::NotObserved,
            "LEGACY_ANCHOR_MISSING: original source, meaning and admission cannot be invented.",
        );
    };
    if let Some(outcome) =
        comparison_gate(before, after, anchor, transition, before_index, after_index)?
    {
        return Ok(outcome);
    }
    let original = before_index.finding_claims(&anchor.finding_id);
    let Some(current) = after_index
        .slots
        .get(anchor.claim_scope_ref.as_str())
        .and_then(|v| v.first())
        .copied()
    else {
        return result(
            O::PolicyRetired,
            "The original claim is absent from the complete current declaration; policy retirement is not implementation remediation.",
        );
    };
    if original[0]
        .semantic_claim
        .as_ref()
        .is_some_and(|s| s.disposition == "DENY")
        && current
            .semantic_claim
            .as_ref()
            .is_some_and(|s| s.disposition != "DENY")
    {
        return result(
            O::PolicyRetired,
            "The original prohibition was removed or replaced with permission; no violation was proved fixed.",
        );
    }
    if current.truth == DeclarationTruth::NotApplicable
        && changed_subject(before, after, transition)
        && subject_removed(before_index, after_index, anchor)
    {
        let mut proofs = vec![
            digest(before.assets.as_ref().expect("checked"))?,
            digest(after.assets.as_ref().expect("checked"))?,
        ];
        proofs.sort();
        proofs.dedup();
        return Ok((O::SubjectRemoved,proofs,"Complete comparable inventories establish original subject removal; policy retirement is not called a code fix.".into()));
    }
    if after_index.meaning(current, &anchor.subject_refs)?.as_ref() != Some(&anchor.meaning_ref) {
        return result(
            O::AuthorityIncomparable,
            "Original rule, policy, applicability scope or interpretation changed.",
        );
    }
    if current.findings.iter().any(|id| id == &anchor.finding_id) {
        return result(
            O::Present,
            "The original stable violation is still present, independently of enforcement disposition.",
        );
    }
    if current.truth == DeclarationTruth::NoSupportedViolation {
        if !changed_subject(before, after, transition) {
            return result(
                O::NotObserved,
                "CONFLICTING_EVIDENCE: unchanged exact inputs reported incompatible static conclusions; a verdict change alone is not remediation.",
            );
        }
        if let Some(s) = &current.semantic_claim
            && (s.governed_source_files == 0 || s.analysed_source_files != s.governed_source_files)
        {
            return result(
                O::NotObserved,
                "Relevant source coverage is incomplete; no disappearance-based resolution.",
            );
        }
        if resolution_cache.is_none() {
            *resolution_cache = Some(resolution_proofs(after)?);
        }
        let proof = resolution_cache
            .as_ref()
            .expect("prepared once")
            .get(&current.scope_ref)
            .cloned()
            .unwrap_or_default();
        if !proof.is_empty() {
            return Ok((O::Resolved,proof,"Existing proof assessor supports the original negative proposition under comparable scope and authority.".into()));
        }
    }
    result(
        O::NotObserved,
        "No sufficient comparable proof of resolution or exact subject removal; uncertainty, missing premises and nonapplicability remain unresolved.",
    )
}
fn changed_subject(
    before: &ComparisonState,
    after: &ComparisonState,
    transition: &TransitionAnalysis,
) -> bool {
    before.source_ref != after.source_ref
        && transition
            .input_deltas
            .iter()
            .any(|d| d.axis == Axis::Subject && d.complete && d.change == Change::Changed)
}
fn comparison_gate(
    before: &ComparisonState,
    after: &ComparisonState,
    anchor: &FindingAnchor,
    transition: &TransitionAnalysis,
    before_index: &StateIndex,
    after_index: &StateIndex,
) -> Result<Option<(O, Vec<String>, String)>, TransitionError> {
    let reject = |o, r: &str| Ok(Some((o, vec![], r.into())));
    if anchor.from_state != transition.from_state
        || before.source_ref.as_ref() != Some(&anchor.subject_ref)
    {
        return reject(
            O::AuthorityIncomparable,
            "MISMATCHED_HISTORY: supplied original endpoint is not the admitted state.",
        );
    }
    let original = before_index.finding_claims(&anchor.finding_id);
    if anchor.subject_refs.iter().any(|id| {
        [before_index, after_index]
            .iter()
            .any(|i| i.definitions.get(id.as_str()).is_some_and(|v| v.len() > 1))
    }) {
        return reject(
            O::IdentityAmbiguous,
            "Original subject identity has several possible occurrences; no favorable pairing is selected.",
        );
    }
    if original.len() != 1 {
        return reject(
            O::IdentityAmbiguous,
            "Original finding does not resolve to one semantic claim.",
        );
    }
    if original[0].truth != DeclarationTruth::SupportedViolation
        || slot(original[0]) != anchor.claim_scope_ref
        || before_index
            .meaning(original[0], &anchor.subject_refs)?
            .as_ref()
            != Some(&anchor.meaning_ref)
    {
        return reject(
            O::AuthorityIncomparable,
            "Original authority or supported violated obligation differs from its admission.",
        );
    }
    let next = after_index
        .slots
        .get(anchor.claim_scope_ref.as_str())
        .cloned()
        .unwrap_or_default();
    if next.len() > 1 || after_index.finding_claims(&anchor.finding_id).len() > 1 {
        return reject(
            O::IdentityAmbiguous,
            "Several current claims compete for the original semantic slot.",
        );
    }
    if transition
        .coverage_deltas
        .iter()
        .any(|d| d.change == Change::ScopeExcluded)
    {
        return reject(
            O::ScopeExcluded,
            "Original observation visibility was reduced; absence is not a fix.",
        );
    }
    if before.assets.is_none()
        || after.assets.is_none()
        || super::claims::application(after).is_none()
    {
        return reject(
            O::NotObserved,
            "Current or original authoritative source/evidence is unavailable.",
        );
    }
    let left = before.assets.as_ref().expect("checked");
    let right = after.assets.as_ref().expect("checked");
    if next.is_empty()
        && left.standard_ref == right.standard_ref
        && left.evaluator_ref == right.evaluator_ref
        && [Axis::Intent, Axis::Authority]
            .iter()
            .all(|axis| right.complete_axes.contains(axis))
    {
        return reject(
            O::PolicyRetired,
            "Original policy/rule is absent from the complete selected claim universe; changed selection is not a code fix.",
        );
    }
    if !super::comparison::comparable(before, after) {
        return reject(
            O::AuthorityIncomparable,
            "Standard, profiles, evaluator, context or exclusions are not sufficiently comparable.",
        );
    }
    Ok(None)
}

fn subject_removed(left: &StateIndex, right: &StateIndex, a: &FindingAnchor) -> bool {
    !a.subject_refs.is_empty()
        && a.subject_refs.iter().all(|id| {
            left.definitions
                .get(id.as_str())
                .is_some_and(|v| v.len() == 1)
                && !right.definitions.contains_key(id.as_str())
        })
        && a.subject_refs
            .iter()
            .any(|id| left.source_scopes.contains(id.as_str()))
        && !a
            .subject_refs
            .iter()
            .any(|id| right.source_scopes.contains(id.as_str()))
}
fn resolution_proofs(
    state: &ComparisonState,
) -> Result<BTreeMap<String, Vec<String>>, TransitionError> {
    use crate::assessment::{
        AssessmentDecision, ExpectedProfileAssessment, ObligationPredicate, ProfileAssessment,
    };
    let Some(app) = super::claims::application(state) else {
        return Ok(BTreeMap::new());
    };
    let mut by_scope = BTreeMap::<&str, Vec<&DeclarationClaim>>::new();
    for c in &app.declaration.claims {
        by_scope.entry(&c.scope_ref).or_default().push(c);
    }
    let eligible = by_scope
        .into_iter()
        .filter_map(|(scope, c)| {
            if c.len() == 1
                && c[0].truth == DeclarationTruth::NoSupportedViolation
                && !c[0].proof_refs.is_empty()
                && c[0].defeater_refs.is_empty()
                && c[0].assumptions.is_empty()
            {
                Some((scope, c[0]))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    let binding = &app.declaration.binding;
    let (accepted, references) = static_premises(app, &eligible)?;
    let obligations = app
        .obligations
        .iter()
        .filter(|o| {
            eligible.contains_key(o.scope_ref.as_str())
                && matches!(
                    o.predicate,
                    ObligationPredicate::Conformance | ObligationPredicate::RuleCheck
                )
                && o.evidence_class == crate::certification::EvidenceClass::StaticProof
        })
        .cloned()
        .collect::<Vec<_>>();
    if obligations.is_empty() {
        return Ok(BTreeMap::new());
    }
    let expected = ExpectedProfileAssessment {
        binding: binding.clone(),
        dimensions: app.declaration.required_dimension_manifest.clone(),
        profile_digest: app.assessment.profile_digest.clone(),
        artifacts: app.declaration.proof_manifest.clone(),
        obligations,
    };
    let assessed =
        ProfileAssessment::evaluate(&app.declaration, &expected, &app.evidence, &accepted)
            .map_err(error)?;
    let obligations = expected
        .obligations
        .iter()
        .map(|o| (o.id.as_str(), o))
        .collect::<BTreeMap<_, _>>();
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    for outcome in &assessed.obligations {
        if outcome.decision != AssessmentDecision::Satisfied {
            continue;
        }
        let o = obligations[outcome.id.as_str()];
        if let Some(proof) = &o.proof {
            for node in &proof.nodes {
                for r in &node.required_refs {
                    if let Some(metadata) = references.get(r.id()) {
                        result
                            .entry(o.scope_ref.clone())
                            .or_default()
                            .insert(metadata.clone());
                    }
                }
            }
        }
    }
    Ok(result
        .into_iter()
        .map(|(scope, proof)| (scope, proof.into_iter().collect()))
        .collect())
}

fn static_premises(
    app: &crate::application::ApplicationAssessment,
    eligible: &BTreeMap<&str, &DeclarationClaim>,
) -> Result<
    (
        crate::assessment::EvidenceAcceptancePolicy,
        BTreeMap<String, String>,
    ),
    TransitionError,
> {
    use crate::assessment::{EvidenceAcceptancePolicy, EvidenceProposition};
    let claim_digests = eligible
        .iter()
        .map(|(scope, c)| Ok((*scope, digest(c)?)))
        .collect::<Result<BTreeMap<_, _>, TransitionError>>()?;
    let binding = &app.declaration.binding;
    let mut accepted = EvidenceAcceptancePolicy::default();
    let mut references = BTreeMap::new();
    for leaf in &app.evidence {
        let Some(claim) = eligible.get(leaf.scope_ref.as_str()) else {
            continue;
        };
        if leaf.binding != *binding
            || leaf.evidence_class != crate::certification::EvidenceClass::StaticProof
            || leaf.proposition != EvidenceProposition::NoSupportedViolation
            || !leaf.assumptions.is_empty()
            || leaf.valid_until.is_some()
            || !claim.proof_refs.contains(&leaf.source_ref)
        {
            continue;
        }
        let expected = digest(&(
            "static-claim-premise-v1",
            binding,
            &claim_digests[leaf.scope_ref.as_str()],
            &leaf.source_ref,
        ))?;
        if expected != leaf.payload_digest
            || leaf.id
                != format!(
                    "assessment-leaf:{}",
                    digest(&(&leaf.scope_ref, &leaf.source_ref))?
                )
        {
            continue;
        }
        let metadata = leaf.metadata_digest().map_err(error)?;
        accepted.verified_payloads.insert(leaf.id.clone(), expected);
        accepted
            .verified_metadata
            .insert(leaf.id.clone(), metadata.clone());
        references.insert(leaf.id.clone(), metadata);
    }
    Ok((accepted, references))
}
