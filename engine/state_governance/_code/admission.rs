//! Attribution from established owner results on explicitly pinned endpoints.
use super::claims::application;
use super::comparison::policy_relation;
use super::retirement::collect_finding_anchors;
use super::{Change, ComparisonContext, ComparisonState, StateAssets, TransitionError};
use super::{compare_states, digest, fail};
use crate::declaration::{DeclarationClaim, DeclarationClaimKind, DeclarationTruth};
use crate::finding::{CanonicalFinding, FindingEnforcementEligibility, FindingIdentityEligibility};
use crate::finding_governance::{
    ADMISSION_ASSESSMENT_SCHEMA, AdmissionAssessment, AdmissionClassification as Origin,
    AdmissionEndpoint, AdmissionFinding, MAX_ADMISSION_FINDINGS,
};
use std::collections::{BTreeMap, BTreeSet};

fn claims(state: &ComparisonState) -> &[DeclarationClaim] {
    application(state).map_or(&[], |a| &a.declaration.claims)
}

fn endpoint(state: &ComparisonState) -> Result<Option<AdmissionEndpoint>, TransitionError> {
    let Some((source_ref, app)) = state.source_ref.as_ref().zip(application(state)) else {
        return Ok(None);
    };
    let Some(authority_ref) = state.governing_identity()? else {
        return Ok(None);
    };
    Ok(Some(AdmissionEndpoint {
        state_ref: state.digest()?,
        source_ref: source_ref.clone(),
        context_ref: app.declaration.binding.context_ref.clone(),
        authority_ref,
    }))
}

fn slot_ref(claim: &DeclarationClaim) -> Result<String, TransitionError> {
    match &claim.semantic_claim {
        Some(d) => digest(&(
            "module-policy",
            &d.module_id,
            &d.scope_selector,
            &d.target_kind,
            &d.target,
        )),
        None => digest(&("registered-rule", &claim.scope_ref)),
    }
}

fn meaning_ref(claim: &DeclarationClaim, assets: &StateAssets) -> Result<String, TransitionError> {
    digest(&(
        "introduced-governing-scope-v1",
        assets.standard_ref.as_ref(),
        slot_ref(claim)?,
        claim.semantic_claim.as_ref().map(|d| {
            (
                &d.policy_digest,
                &d.context_digest,
                &d.producer_identity,
                &d.disposition,
            )
        }),
    ))
}

fn target_binding(claim: &DeclarationClaim) -> bool {
    claim.truth == DeclarationTruth::SupportedViolation
        && !claim.proof_refs.is_empty()
        && claim.assumptions.is_empty()
        && claim.semantic_claim.as_ref().is_none_or(|detail| {
            detail.governed_source_files > 0
                && detail.analysed_source_files == detail.governed_source_files
                && !detail.production_observations.is_empty()
                && detail.unknown_observations.is_empty()
        })
}

fn policy_introduced(claim: &DeclarationClaim, left: &StateAssets, right: &StateAssets) -> bool {
    let Some(detail) = &claim.semantic_claim else {
        return false;
    };
    if detail.target_kind != "EFFECT" || detail.disposition != "DENY" {
        return false;
    }
    let mut old = left.policies.iter().filter(|p| p.id == detail.module_id);
    let mut new = right.policies.iter().filter(|p| p.id == detail.module_id);
    let Some(new_policy) = new.next() else {
        return false;
    };
    let prior = match old.next() {
        Some(old_policy) => {
            // The existing projection uses its default spelling when no authored clause
            // produces a semantic claim. Preserve the endpoint bytes and normalize only
            // this recognized, completely unconstrained comparison input.
            let empty_scope = (old_policy.scope == "all-module-owned-executable"
                && new_policy.scope == "ALL_MODULE_OWNED_EXECUTABLE_ENTRIES"
                && old_policy.denied.is_empty()
                && old_policy.allowed.is_empty())
            .then(|| {
                let mut normalized = old_policy.clone();
                normalized.scope.clone_from(&new_policy.scope);
                normalized
            });
            let old_policy = empty_scope.as_ref().unwrap_or(old_policy);
            old.next().is_none()
                && policy_relation(old_policy, new_policy) == Change::Strengthened
                && old_policy.allowed == new_policy.allowed
                && !old_policy.denied.contains(&detail.target)
                && !old_policy.allowed.contains(&detail.target)
        }
        None => {
            new_policy.complete
                && new_policy.allowed.is_empty()
                && left
                    .entities
                    .iter()
                    .filter(|entity| entity.kind == "module" && entity.id == detail.module_id)
                    .count()
                    == 1
        }
    };
    prior
        && new.next().is_none()
        && new_policy.denied.contains(&detail.target)
        && left.profile_refs == right.profile_refs
}

fn rule_activated(
    claim: &DeclarationClaim,
    previous: Option<&DeclarationClaim>,
    left: &StateAssets,
    right: &StateAssets,
) -> bool {
    claim
        .rule_result
        .as_ref()
        .is_some_and(|rule| rule.applicable)
        && previous.is_none_or(|c| {
            c.truth == DeclarationTruth::NotApplicable
                && c.rule_result.as_ref().is_some_and(|rule| !rule.applicable)
        })
        && left.profile_refs.is_subset(&right.profile_refs)
        && left.profile_refs != right.profile_refs
        && !left.profile_refs.is_empty()
}

fn indexes(
    state: &ComparisonState,
) -> Result<BTreeMap<String, Vec<&DeclarationClaim>>, TransitionError> {
    let mut index = BTreeMap::<String, Vec<_>>::new();
    for claim in claims(state) {
        index.entry(slot_ref(claim)?).or_default().push(claim);
    }
    Ok(index)
}

fn was_applicable(claim: &DeclarationClaim) -> bool {
    claim
        .rule_result
        .as_ref()
        .is_none_or(|rule| rule.applicable)
}

fn comparable_observation(left: &StateAssets, right: &StateAssets) -> bool {
    left.standard_ref.is_some()
        && left.standard_ref == right.standard_ref
        && left.evaluator_ref.is_some()
        && left.evaluator_ref == right.evaluator_ref
        && left.exclusions.is_some()
        && left.exclusions == right.exclusions
        && left.exclusions_ref == right.exclusions_ref
}

fn original_ids(findings: &[CanonicalFinding]) -> BTreeSet<&str> {
    findings
        .iter()
        .flat_map(|finding| {
            std::iter::once(finding.finding_id())
                .chain(finding.legacy_finding_ids().iter().map(String::as_str))
        })
        .collect()
}

fn finding_row(
    finding: &CanonicalFinding,
    classification: Origin,
    reason: &str,
) -> AdmissionFinding {
    AdmissionFinding {
        finding_id: finding.finding_id().into(),
        rule_id: finding.rule_id().into(),
        classification,
        introduced_scope_ref: None,
        scope_slot_ref: None,
        anchor: None,
        evidence_refs: BTreeSet::new(),
        defeater_refs: BTreeSet::new(),
        reason: reason.into(),
    }
}

struct Attribution<'a> {
    original: &'a ComparisonState,
    target: &'a ComparisonState,
    prior: BTreeMap<String, Vec<&'a DeclarationClaim>>,
    historical_slots: BTreeSet<String>,
    original_ids: BTreeSet<&'a str>,
    claim_by_finding: BTreeMap<&'a str, Vec<&'a DeclarationClaim>>,
    anchors: BTreeMap<String, crate::finding_governance::FindingAnchor>,
    bindings: Option<(&'a AdmissionEndpoint, &'a AdmissionEndpoint)>,
    same_implementation: bool,
    complete_history: bool,
}

impl Attribution<'_> {
    fn classify(&self, finding: &CanonicalFinding) -> Result<AdmissionFinding, TransitionError> {
        let result = |origin, reason| Ok(finding_row(finding, origin, reason));
        let Some((base, next)) = self.bindings else {
            return result(
                Origin::OriginalHistoryUnavailable,
                "A complete original and target authority is required.",
            );
        };
        if finding.identity_eligibility() != FindingIdentityEligibility::Eligible {
            return result(
                Origin::IdentityAmbiguous,
                "The occurrence has no stable eligible identity.",
            );
        }
        if std::iter::once(finding.finding_id())
            .chain(finding.legacy_finding_ids().iter().map(String::as_str))
            .any(|id| self.original_ids.contains(id))
        {
            return result(
                Origin::ExistingViolation,
                "The original evaluation already reported this occurrence.",
            );
        }
        if !self.same_implementation && base.authority_ref != next.authority_ref {
            return result(
                Origin::MixedChange,
                "Both implementation and authority changed; split the operations.",
            );
        }
        let Some(target) = self
            .claim_by_finding
            .get(finding.finding_id())
            .and_then(|items| (items.len() == 1).then(|| items[0]))
        else {
            return result(
                Origin::IdentityAmbiguous,
                "The occurrence does not identify exactly one governing claim.",
            );
        };
        let slot = slot_ref(target)?;
        let previous = self.prior.get(&slot).map_or(&[][..], Vec::as_slice);
        if previous.len() > 1 {
            return result(
                Origin::IdentityAmbiguous,
                "The original authority has overlapping claim slots.",
            );
        }
        let left = self
            .original
            .assets
            .as_ref()
            .expect("complete original binding");
        let right = self
            .target
            .assets
            .as_ref()
            .expect("complete target binding");
        if !comparable_observation(left, right)
            || !target_binding(target)
            || finding.enforcement_eligibility() != FindingEnforcementEligibility::BlockSupported
        {
            return result(
                Origin::NotComparable,
                "The evaluator, visibility, coverage or supported proof is not comparable.",
            );
        }
        let previous = previous.first().copied();
        if !self.same_implementation {
            return if previous.is_some_and(|p| {
                p.truth == DeclarationTruth::NoSupportedViolation
                    && p.defeater_refs.is_empty()
                    && p.assumptions.is_empty()
                    && base.context_ref == next.context_ref
            }) {
                result(
                    Origin::ImplementationRegression,
                    "Comparable old authority established scoped absence before the implementation change.",
                )
            } else {
                result(
                    Origin::NotComparable,
                    "The old result does not establish comparable absence.",
                )
            };
        }
        self.introduction(
            finding,
            target,
            previous,
            slot,
            (left, right),
            base.context_ref == next.context_ref,
        )
    }

    fn introduction(
        &self,
        finding: &CanonicalFinding,
        target: &DeclarationClaim,
        previous: Option<&DeclarationClaim>,
        slot: String,
        (left, right): (&StateAssets, &StateAssets),
        same_context: bool,
    ) -> Result<AdmissionFinding, TransitionError> {
        let result = |origin, reason| Ok(finding_row(finding, origin, reason));
        if !self.complete_history {
            return result(
                Origin::OriginalHistoryUnavailable,
                "A supplied historical endpoint lacks required observation or governing authority.",
            );
        }
        if self.historical_slots.contains(&slot) || previous.is_some_and(was_applicable) {
            return result(
                Origin::PreviouslyGoverned,
                "The requirement was previously applicable; reactivation does not reset its history.",
            );
        }
        if !same_context
            || left.reference_facts.is_none()
            || left.reference_facts != right.reference_facts
            || !(policy_introduced(target, left, right)
                || rule_activated(target, previous, left, right))
        {
            return result(
                Origin::NotComparable,
                "No supported, purely additive requirement is established for the pinned implementation.",
            );
        }
        let Some(anchor) = self.anchors.get(finding.finding_id()) else {
            return result(
                Origin::IdentityAmbiguous,
                "The existing finding owner could not establish a unique comparable anchor.",
            );
        };
        let mut row = finding_row(
            finding,
            Origin::NewlyGoverned,
            "The same observed implementation violates a newly applicable supported requirement. The finding still requires explicit review and external authorization.",
        );
        row.introduced_scope_ref = Some(meaning_ref(target, right)?);
        row.scope_slot_ref = Some(slot);
        row.anchor = Some(anchor.clone());
        row.evidence_refs.extend(target.proof_refs.iter().cloned());
        row.defeater_refs
            .extend(target.defeater_refs.iter().cloned());
        Ok(row)
    }
}

struct PriorAuthority {
    refs: BTreeSet<String>,
    slots: BTreeSet<String>,
    complete: bool,
}

fn prior_authority(history: &[ComparisonState]) -> Result<PriorAuthority, TransitionError> {
    let mut prior = PriorAuthority {
        refs: BTreeSet::new(),
        slots: BTreeSet::new(),
        complete: true,
    };
    for state in history {
        if !prior.refs.insert(state.digest()?) {
            return Err(fail(
                "DUPLICATE_HISTORY",
                "historical state reference occurs twice",
            ));
        }
        prior.complete &= endpoint(state)?.is_some();
        for claim in claims(state).iter().filter(|claim| was_applicable(claim)) {
            prior.slots.insert(slot_ref(claim)?);
            if prior.slots.len() > super::MAX_TRANSITION_RECORDS {
                return Err(fail(
                    "RESOURCE_LIMIT",
                    "historical claim slot admission exceeded",
                ));
            }
        }
    }
    Ok(prior)
}

/// Classifies immutable target findings without interpreting review references or grants.
/// Callers may preview supplied historical citations; an application must establish the
/// actual original state and consider independent history through the trusted boundary.
/// # Errors
/// Refuses invalid endpoints and resource exhaustion.
pub fn classify_governance_introduction(
    original: &ComparisonState,
    target: &ComparisonState,
    original_findings: &[CanonicalFinding],
    target_findings: &[CanonicalFinding],
    history: &[ComparisonState],
) -> Result<AdmissionAssessment, TransitionError> {
    if target_findings.len() > MAX_ADMISSION_FINDINGS || history.len() > 64 {
        return Err(fail(
            "RESOURCE_LIMIT",
            "admission finding or historical endpoint limit",
        ));
    }
    let transition = compare_states(original, target, &ComparisonContext::default())?;
    let base = endpoint(original)?;
    let next = endpoint(target)?;
    let original_subject = original.subject_identity()?;
    let subject_ref = target.subject_identity()?;
    let history = prior_authority(history)?;
    let mut claim_by_finding = BTreeMap::<&str, Vec<_>>::new();
    for claim in claims(target) {
        for id in &claim.findings {
            claim_by_finding.entry(id).or_default().push(claim);
        }
    }
    for values in claim_by_finding.values_mut() {
        if values
            .iter()
            .any(|c| c.kind == DeclarationClaimKind::SemanticPolicy)
        {
            values.retain(|c| c.kind == DeclarationClaimKind::SemanticPolicy);
        }
    }
    let mut ordered = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for finding in target_findings {
        if ordered.insert(finding.finding_id(), finding).is_some() {
            duplicates.insert(finding.finding_id());
        }
    }
    let anchors = if base.is_some() && next.is_some() && original_subject == subject_ref {
        let certain = ordered
            .iter()
            .filter(|(id, _)| !duplicates.contains(*id))
            .map(|(_, finding)| (**finding).clone())
            .collect::<Vec<_>>();
        collect_finding_anchors(target, &certain, true)?
    } else {
        BTreeMap::new()
    };
    let attribution = Attribution {
        original,
        target,
        prior: indexes(original)?,
        historical_slots: history.slots,
        original_ids: original_ids(original_findings)
            .into_iter()
            .chain(
                claims(original)
                    .iter()
                    .flat_map(|claim| claim.findings.iter().map(String::as_str)),
            )
            .collect(),
        claim_by_finding,
        anchors,
        bindings: base.as_ref().zip(next.as_ref()),
        complete_history: history.complete,
        same_implementation: subject_ref.is_some() && original_subject == subject_ref,
    };
    let findings = ordered
        .into_iter()
        .map(|(id, finding)| {
            if duplicates.contains(id) {
                Ok(finding_row(
                    finding,
                    Origin::IdentityAmbiguous,
                    "Multiple occurrences share this canonical identity.",
                ))
            } else {
                attribution.classify(finding)
            }
        })
        .collect::<Result<_, _>>()?;
    let mut assessment = AdmissionAssessment {
        schema: ADMISSION_ASSESSMENT_SCHEMA.into(),
        schema_version: 1,
        assessment_ref: String::new(),
        original: base,
        target: next,
        transition_ref: transition.digest()?,
        subject_ref,
        history_refs: history.refs,
        findings,
    };
    assessment
        .bind_identity()
        .map_err(|e| fail("INVALID_ADMISSION", e.to_string()))?;
    Ok(assessment)
}
