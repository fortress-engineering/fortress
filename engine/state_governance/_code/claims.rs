//! Stable claim slots, coverage, evidence and original finding dispositions.
use super::comparison::{check_cancel, comparable, delta};
use super::{Change, ComparisonState, TransitionAnalysis, TransitionError, fail};
use crate::application::ApplicationAssessment;
use crate::declaration::{DeclarationClaim, DeclarationTruth};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

pub(super) fn application(s: &ComparisonState) -> Option<&ApplicationAssessment> {
    s.retained_application
        .as_ref()
        .or_else(|| s.view.as_ref().and_then(|v| v.application.as_ref()))
}
fn slot(c: &DeclarationClaim) -> &str {
    c.semantic_claim
        .as_ref()
        .map_or(c.id.as_str(), |d| d.slot_id.as_str())
}
fn indexed(app: &ApplicationAssessment) -> BTreeMap<String, Vec<&DeclarationClaim>> {
    let mut result = BTreeMap::<String, Vec<&DeclarationClaim>>::new();
    for c in &app.declaration.claims {
        result.entry(slot(c).into()).or_default().push(c);
    }
    result
}
fn evaluable(c: &DeclarationClaim) -> bool {
    matches!(
        c.truth,
        DeclarationTruth::SupportedViolation | DeclarationTruth::NoSupportedViolation
    )
}
fn pair_comparable(before: &DeclarationClaim, after: &DeclarationClaim, environment: bool) -> bool {
    if !environment {
        return false;
    }
    match (&before.semantic_claim, &after.semantic_claim) {
        (Some(prior), Some(next)) => {
            prior.target == next.target
                && prior.target_kind == next.target_kind
                && prior.scope_selector == next.scope_selector
                && prior.context_digest == next.context_digest
                && prior.context_family == next.context_family
                && prior.producer_identity == next.producer_identity
                && prior.disposition == next.disposition
                && prior.policy_digest == next.policy_digest
        }
        (None, None) => before.id == after.id,
        _ => false,
    }
}
pub(super) fn compare_claims(
    before: &ComparisonState,
    after: &ComparisonState,
    out: &mut TransitionAnalysis,
    cancelled: &AtomicBool,
) -> Result<(), TransitionError> {
    let (Some(left), Some(right)) = (application(before), application(after)) else {
        out.semantic_deltas.push(delta("semantic","endpoint-assessment",Change::NotComparable,before.view.as_ref().map(|v|json!(v.status)),after.view.as_ref().map(|v|json!(v.status)),"Ungoverned, invalid or missing endpoints retain known input deltas, but unavailable conformance cannot establish a favorable or unfavorable transition."));
        return Ok(());
    };
    let left_index = indexed(left);
    let right_index = indexed(right);
    let environment = comparable(before, after);
    for id in left_index
        .keys()
        .chain(right_index.keys())
        .collect::<BTreeSet<_>>()
    {
        check_cancel(cancelled)?;
        let (prior, next) = (left_index.get(id), right_index.get(id));
        if prior.is_some_and(|v| v.len() != 1) || next.is_some_and(|v| v.len() != 1) {
            out.semantic_deltas.push(delta(
                "semantic",
                id,
                Change::IdentityAmbiguous,
                prior.map(|v| json!(v)),
                next.map(|v| json!(v)),
                "Multiple claims share a stable slot; no first candidate is selected.",
            ));
            continue;
        }
        match (prior,next) {
            (Some(prior),Some(next))=>compare_pair(id,prior[0],next[0],environment,out),
            (Some(prior),None)=>out.semantic_deltas.push(delta("semantic",id,Change::NotObserved,Some(json!(prior[0])),None,"A missing claim is not resolved. The reporting universe or policy may have been retired or excluded.")),
            (None,Some(next))=>out.semantic_deltas.push(delta("semantic",id,Change::Added,None,Some(json!(next[0])),"A newly observed claim is not automatically a newly introduced implementation regression.")),
            _=>unreachable!(),
        }
    }
    if before.retained_application.is_some() || after.retained_application.is_some() {
        out.evidence_deltas.push(delta("obligation","retained-metadata",Change::NotComparable,None,None,"Historical pair omitted complete obligation/admission metadata. No obligations are inferred absent."));
        out.evidence_deltas.push(delta("assurance","profile-assessment",Change::NotComparable,Some(json!(left.assessment)),Some(json!(right.assessment)),"Original profile conclusions are retained; incomplete authority prevents sufficiency comparison."));
    } else {
        compare_obligations(left, right, environment, out)?;
    }
    compare_findings(left, right, environment, out);
    Ok(())
}
fn compare_pair(
    id: &str,
    before: &DeclarationClaim,
    after: &DeclarationClaim,
    environment: bool,
    out: &mut TransitionAnalysis,
) {
    let compatible = pair_comparable(before, after, environment);
    let change = if !compatible {
        Change::NotComparable
    } else if before == after {
        Change::Unchanged
    } else {
        Change::Changed
    };
    out.semantic_deltas.push(delta("semantic",id,change,Some(json!(before)),Some(json!(after)),"Original declarations remain intact. Truth changes describe endpoint results, not a regression, improvement or physical cause."));
    let state = if before.truth == DeclarationTruth::NotEvaluable && evaluable(after) {
        Change::NewlyEvaluable
    } else if evaluable(before) && after.truth == DeclarationTruth::NotEvaluable {
        Change::EvaluabilityLost
    } else if before.truth == DeclarationTruth::NotApplicable
        && after.truth == DeclarationTruth::NotApplicable
    {
        Change::NotApplicable
    } else if before.truth == DeclarationTruth::NotEvaluable
        && after.truth == DeclarationTruth::NotEvaluable
    {
        Change::NotEvaluable
    } else if !compatible {
        Change::NotComparable
    } else {
        Change::Unchanged
    };
    out.coverage_deltas.push(delta("evaluability",id,state,Some(json!(before.truth)),Some(json!(after.truth)),"Reported evaluability is independent from conformance and assurance. A gain/loss across different authority is descriptive only; semantic comparability remains separate. UNKNOWN/unsupported and nonapplicable states retain their original evidence."));
    if let (Some(prior), Some(next)) = (&before.semantic_claim, &after.semantic_claim) {
        let left = json!({"governed":prior.governed_source_files,"analysed":prior.analysed_source_files,"universe":prior.governed_universe_digest,"scope":prior.scope_selector});
        let right = json!({"governed":next.governed_source_files,"analysed":next.analysed_source_files,"universe":next.governed_universe_digest,"scope":next.scope_selector});
        out.coverage_deltas.push(delta("coverage",id,if !compatible {Change::NotComparable}else if left==right {Change::Unchanged}else {Change::Changed},Some(left),Some(right),"Counts, scope and universe identities remain distinct; changed coverage does not imply a fixed finding or analyzer change."));
    }
    out.evidence_deltas.push(delta("proof",id,if !compatible {Change::NotComparable}else if before.proof_refs==after.proof_refs && before.defeater_refs==after.defeater_refs {Change::Unchanged}else {Change::Changed},Some(json!({"support":before.proof_refs,"counterevidence":before.defeater_refs})),Some(json!({"support":after.proof_refs,"counterevidence":after.defeater_refs})),"Changed proof references are evidence changes. Missing evidence never establishes a favorable or unfavorable result."));
}
fn compare_obligations(
    before: &ApplicationAssessment,
    after: &ApplicationAssessment,
    environment: bool,
    out: &mut TransitionAnalysis,
) -> Result<(), TransitionError> {
    let key = |app: &ApplicationAssessment, o: &crate::assessment::ProfileObligation| {
        let scope = app
            .declaration
            .claims
            .iter()
            .find(|c| c.scope_ref == o.scope_ref)
            .map_or(o.scope_ref.as_str(), |c| slot(c));
        format!("{scope}:{:?}:{:?}", o.predicate, o.evidence_class)
    };
    let left_index = before
        .obligations
        .iter()
        .map(|o| (key(before, o), o))
        .collect::<BTreeMap<_, _>>();
    let right_index = after
        .obligations
        .iter()
        .map(|o| (key(after, o), o))
        .collect::<BTreeMap<_, _>>();
    for id in left_index
        .keys()
        .chain(right_index.keys())
        .collect::<BTreeSet<_>>()
    {
        let (prior, next) = (left_index.get(id), right_index.get(id));
        let change = match (prior, next) {
            (None, Some(_)) => Change::Added,
            (Some(_), None) => Change::Removed,
            (Some(prior), Some(next)) => {
                if !environment {
                    Change::NotComparable
                } else if prior == next {
                    Change::Unchanged
                } else {
                    Change::Changed
                }
            }
            _ => unreachable!(),
        };
        out.evidence_deltas.push(delta("obligation",id,change,prior.map(|o|json!(o)),next.map(|o|json!(o)),"Obligation introduction/retirement and evidence requirements are properties, not automatic strengthening of an observed conclusion."));
    }
    if left_index.len() != before.obligations.len() || right_index.len() != after.obligations.len()
    {
        return Err(fail(
            "INVALID_INPUT",
            "ambiguous obligation semantic identity",
        ));
    }
    out.evidence_deltas.push(delta("assurance","profile-assessment",if environment {if before.assessment==after.assessment {Change::Unchanged}else {Change::Changed}}else {Change::NotComparable},Some(json!(before.assessment)),Some(json!(after.assessment)),"Assurance sufficiency and raw conformance remain independent; changed profiles are not an implementation comparison."));
    Ok(())
}
fn finding_index(app: &ApplicationAssessment) -> BTreeMap<String, Vec<serde_json::Value>> {
    let mut result = BTreeMap::<String, Vec<serde_json::Value>>::new();
    for claim in &app.declaration.claims {
        for id in &claim.findings {
            result.entry(id.clone()).or_default().push(json!({"claim_slot":slot(claim),"raw_truth":claim.truth,"baselined":app.declaration.residue_summary.accepted_baseline.contains(id),"excepted":app.declaration.residue_summary.accepted_exceptions.contains(id),"blocking":app.declaration.residue_summary.blocking_findings.contains(id)}));
        }
    }
    result
}
fn compare_findings(
    before: &ApplicationAssessment,
    after: &ApplicationAssessment,
    environment: bool,
    out: &mut TransitionAnalysis,
) {
    use crate::finding_governance::{RetirementEvidence, RetirementReason as R};
    let scope_excluded = out
        .coverage_deltas
        .iter()
        .any(|d| d.change == Change::ScopeExcluded);
    let left = finding_index(before);
    let right = finding_index(after);
    for id in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
        let (prior, next) = (left.get(id), right.get(id));
        let ambiguous = prior.is_some_and(|v| v.len() != 1) || next.is_some_and(|v| v.len() != 1);
        let change = if ambiguous {
            Change::IdentityAmbiguous
        } else {
            match (prior, next) {
                (Some(prior), Some(next)) => {
                    if prior == next {
                        Change::Unchanged
                    } else {
                        Change::Changed
                    }
                }
                (None, Some(_)) => Change::Added,
                (Some(_), None) => {
                    if environment || scope_excluded {
                        Change::NotObserved
                    } else {
                        Change::AuthorityIncomparable
                    }
                }
                _ => unreachable!(),
            }
        };
        out.finding_deltas.push(delta("finding",id,change,prior.map(|v|json!(v)),next.map(|v|json!(v)),"Missing finding identity never proves resolution. Baselines and exceptions affect enforcement, not the original raw truth."));
        if prior.is_some() && next.is_none() {
            out.retirement_evidence.push(RetirementEvidence{finding_id:id.clone(),from_state:out.from_state.clone(),to_state:out.to_state.clone(),reason:if ambiguous {R::IdentityAmbiguous}else if !environment {R::AuthorityIncomparable}else{R::NotObserved},support_refs:vec![],limitations:vec!["No complete comparable retirement proof was supplied. This record cannot resolve a baseline entry or validate external approval.".into()]});
        }
    }
    out.finding_deltas.push(delta("governance","residue-summary",if before.declaration.residue_summary==after.declaration.residue_summary {Change::Unchanged}else {Change::Changed},Some(json!(before.declaration.residue_summary)),Some(json!(after.declaration.residue_summary)),"Observed enforcement disposition is separate from implementation truth and from supplied governance authority."));
}
