//! One pure comparator; no filesystem, evaluator, clock or grant validation.
use super::{
    AuthorizationReference, Axis, AxisDelta, AxisInput, Change, ComparisonContext, ComparisonState,
    Counterfactual, Delta, Entity, FinitePolicy, MAX_TRANSITION_RECORDS, ParentComparison,
    StateAssets, TransitionAnalysis, TransitionError, canonical, digest, fail, validation,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

/// Compares exact endpoints without treating verdict movement as causation.
/// # Errors
/// Refuses malformed/tampered inputs and bounded-resource exhaustion.
pub fn compare_states(
    before: &ComparisonState,
    after: &ComparisonState,
    context: &ComparisonContext,
) -> Result<TransitionAnalysis, TransitionError> {
    compare_states_cancellable(before, after, context, &AtomicBool::new(false))
}
/// Cooperative cancellation over the same deterministic pure comparison.
/// # Errors
/// Returns CANCELLED, resource, version or invalid-input errors without partial results.
pub fn compare_states_cancellable(
    before: &ComparisonState,
    after: &ComparisonState,
    context: &ComparisonContext,
    cancelled: &AtomicBool,
) -> Result<TransitionAnalysis, TransitionError> {
    check_cancel(cancelled)?;
    before.validate()?;
    after.validate()?;
    validate_context(before, after, context)?;
    let normalized_before = before.normalized();
    let normalized_after = after.normalized();
    let normalized = normalized_context(context);
    let (before, after, context) = (&normalized_before, &normalized_after, &normalized);
    let mut out=TransitionAnalysis {schema:"urn:fortress:derived:v1:transition-analysis".into(),schema_version:1,semantic_version:"1.0.0".into(),from_state:before.digest()?,to_state:after.digest()?,comparison_context:digest(&normalized_context(context))?,input_deltas:axis_deltas(before,after),semantic_deltas:vec![],coverage_deltas:vec![],evidence_deltas:vec![],finding_deltas:vec![],retirement_evidence:vec![],weakenings:vec![],strengthenings:vec![],incomparabilities:vec![],required_authorizations:vec![],limitations:vec!["A verdict change alone establishes neither regression, improvement nor a code fix.".into(),"Read-only comparison of supplied owner projections. Input integrity does not authenticate producers or validate external approval.".into(),"Placement identity is limited to supplied stable Module/reference identities; no whole-program equivalence is inferred.".into()]};
    out.evidence_deltas.push(delta("source_identity","exact-observed-source",match (&before.source_ref,&after.source_ref){(Some(a),Some(b))=>if a==b{Change::Unchanged}else{Change::Changed},_=>Change::Unknown},before.source_ref.as_ref().map(|s|json!(s)),after.source_ref.as_ref().map(|s|json!(s)),"Exact repository-source identity includes governing assets; its change alone cannot attribute an implementation change."));
    out.evidence_deltas.push(delta("authority_binding","original-aggregate-binding",match(authority(before),authority(after)){(Some(a),Some(b))=>if a==b{Change::Unchanged}else{Change::Changed},_=>Change::Unknown},authority(before).map(|s|json!(s)),authority(after).map(|s|json!(s)),"Original declaration authority can aggregate intent and governance. Its change alone does not establish governing-rule authority drift."));
    compare_assets(before, after, &mut out, cancelled)?;
    super::claims::compare_claims(before, after, &mut out, cancelled)?;
    compare_cells(context, &mut out)?;
    finalize(before, after, context, &mut out)?;
    check_cancel(cancelled)?;
    out.to_canonical_bytes()?;
    Ok(out)
}
pub(super) fn check_cancel(value: &AtomicBool) -> Result<(), TransitionError> {
    if value.load(Ordering::Relaxed) {
        Err(fail("CANCELLED", "comparison cancelled"))
    } else {
        Ok(())
    }
}
fn axis_deltas(before: &ComparisonState, after: &ComparisonState) -> Vec<AxisDelta> {
    [
        Axis::Subject,
        Axis::Intent,
        Axis::Authority,
        Axis::Governance,
    ]
    .into_iter()
    .map(|axis| {
        let left = axis_inputs(before, axis);
        let right = axis_inputs(after, axis);
        let left_complete = before
            .assets
            .as_ref()
            .is_some_and(|s| complete_axis(s, axis));
        let right_complete = after
            .assets
            .as_ref()
            .is_some_and(|s| complete_axis(s, axis));
        let complete = left_complete && right_complete;
        let ids = left
            .keys()
            .chain(right.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|id| match (left.get(*id), right.get(*id)) {
                (Some(a), Some(b)) => a.len() == 1 && b.len() == 1 && a != b,
                (Some(_), None) => right_complete,
                (None, Some(_)) => left_complete,
                _ => false,
            })
            .cloned()
            .collect::<Vec<_>>();
        let scope_changed = before
            .assets
            .as_ref()
            .zip(after.assets.as_ref())
            .is_some_and(|(a, b)| {
                known_reference_change(a.exclusions_ref.as_deref(), b.exclusions_ref.as_deref())
            });
        let known_authority = axis == Axis::Authority
            && (before
                .assets
                .as_ref()
                .zip(after.assets.as_ref())
                .is_some_and(|(a, b)| {
                    known_reference_change(a.standard_ref.as_deref(), b.standard_ref.as_deref())
                        || known_reference_change(
                            a.evaluator_ref.as_deref(),
                            b.evaluator_ref.as_deref(),
                        )
                        || (complete_axis(a, Axis::Authority)
                            && complete_axis(b, Axis::Authority)
                            && a.profile_refs != b.profile_refs)
                })
                || super::claims::application(before)
                    .zip(super::claims::application(after))
                    .is_some_and(|(a, b)| {
                        a.declaration.binding.context_ref != b.declaration.binding.context_ref
                            || a.declaration.producer != b.declaration.producer
                    }));
        AxisDelta {
            axis,
            change: if !ids.is_empty()
                || known_authority
                || (scope_changed && matches!(axis, Axis::Intent | Axis::Authority))
            {
                Change::Changed
            } else if complete {
                Change::Unchanged
            } else {
                Change::Unknown
            },
            input_ids: ids,
            complete,
        }
    })
    .collect()
}
fn known_reference_change(before: Option<&str>, after: Option<&str>) -> bool {
    before.zip(after).is_some_and(|(a, b)| a != b)
}

fn complete_axis(assets: &StateAssets, axis: Axis) -> bool {
    let mut ids = BTreeSet::new();
    assets.complete_axes.contains(&axis)
        && (axis != Axis::Authority
            || (assets.standard_ref.is_some() && assets.evaluator_ref.is_some()))
        && assets
            .inputs
            .iter()
            .filter(|i| i.roles.contains_key(&axis))
            .all(|i| ids.insert(&i.id))
}
fn axis_inputs(s: &ComparisonState, axis: Axis) -> BTreeMap<String, BTreeSet<String>> {
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    if let Some(after) = &s.assets {
        for i in &after.inputs {
            if let Some(d) = i.roles.get(&axis) {
                result.entry(i.id.clone()).or_default().insert(d.clone());
            }
        }
    }
    result
}
pub(super) fn authority(s: &ComparisonState) -> Option<&str> {
    super::claims::application(s).map(|after| after.declaration.binding.authority_ref.as_str())
}
pub(super) fn comparable(before: &ComparisonState, after: &ComparisonState) -> bool {
    let (Some(prior), Some(next)) = (&before.assets, &after.assets) else {
        return false;
    };
    [Axis::Subject, Axis::Intent, Axis::Authority]
        .into_iter()
        .all(|axis| complete_axis(prior, axis) && complete_axis(next, axis))
        && prior.exclusions_ref.is_some()
        && prior.exclusions_ref == next.exclusions_ref
        && prior.standard_ref.is_some()
        && prior.standard_ref == next.standard_ref
        && prior.profile_refs == next.profile_refs
        && prior.evaluator_ref.is_some()
        && prior.evaluator_ref == next.evaluator_ref
        && super::claims::application(before)
            .zip(super::claims::application(after))
            .is_some_and(|(left_index, right_index)| {
                left_index.declaration.binding.context_ref
                    == right_index.declaration.binding.context_ref
            })
}
fn matching_authority(before: &StateAssets, after: &StateAssets) -> bool {
    complete_axis(before, Axis::Authority)
        && complete_axis(after, Axis::Authority)
        && before.standard_ref.is_some()
        && before.standard_ref == after.standard_ref
        && before.profile_refs == after.profile_refs
        && before.evaluator_ref.is_some()
        && before.evaluator_ref == after.evaluator_ref
}
fn compare_assets(
    before: &ComparisonState,
    after: &ComparisonState,
    out: &mut TransitionAnalysis,
    cancelled: &AtomicBool,
) -> Result<(), TransitionError> {
    let (Some(left), Some(right)) = (&before.assets, &after.assets) else {
        out.incomparabilities.push("Necessary historical source/authority assets are unavailable; aggregate source identity is not an implementation-change oracle.".into());
        return Ok(());
    };
    compare_input_ambiguities(left, right, out);
    compare_entities(left, right, out, cancelled)?;
    let left_index = left
        .policies
        .iter()
        .map(|p| (&p.id, p))
        .collect::<BTreeMap<_, _>>();
    let right_index = right
        .policies
        .iter()
        .map(|p| (&p.id, p))
        .collect::<BTreeMap<_, _>>();
    for id in left_index
        .keys()
        .chain(right_index.keys())
        .collect::<BTreeSet<_>>()
    {
        check_cancel(cancelled)?;
        let (prior, next) = (left_index.get(id).copied(), right_index.get(id).copied());
        let change = match (prior, next) {
            (Some(prior), Some(next)) => {
                if matching_authority(left, right) {
                    policy_relation(prior, next)
                } else {
                    Change::NotComparable
                }
            }
            (None, Some(_)) => {
                if complete_axis(left, Axis::Intent) {
                    Change::Added
                } else {
                    Change::Unknown
                }
            }
            (Some(_), None) => {
                if complete_axis(right, Axis::Intent) {
                    Change::PolicyRetired
                } else {
                    Change::Unknown
                }
            }
            _ => unreachable!(),
        };
        out.semantic_deltas.push(delta("policy",id,change,prior.map(|v|json!(v)),next.map(|v|json!(v)),"Finite authored restrictions only; unlisted vocabulary members are unconstrained. No endpoint PASS establishes a code fix."));
    }
    if left.exclusions_ref != right.exclusions_ref {
        out.coverage_deltas.push(delta("coverage","scope/exclusions",exclusion_change(left,right),json_opt(left.exclusions_ref.as_ref()),json_opt(right.exclusions_ref.as_ref()),"Coverage authority changed; direction and resolution require exact comparable scope evidence, not missing IDs."));
    }
    match (&left.reference_facts,&right.reference_facts) {
        (Some(prior),Some(next))=>out.semantic_deltas.push(delta("reference","semantic-references",if prior==next {Change::Unchanged}else {Change::Changed},Some(json!(prior)),Some(json!(next)),"Existing reference-owner semantic identities are compared independently of occurrence paths.")),
        _=>out.incomparabilities.push("Semantic reference relationships were not supplied completely.".into()),
    }
    compare_storage(left, right, out);
    Ok(())
}
fn input_occurrences(assets: &StateAssets) -> BTreeMap<&String, Vec<&AxisInput>> {
    let mut result = BTreeMap::<&String, Vec<&AxisInput>>::new();
    for input in &assets.inputs {
        result.entry(&input.id).or_default().push(input);
    }
    result
}
fn compare_input_ambiguities(
    before: &StateAssets,
    after: &StateAssets,
    out: &mut TransitionAnalysis,
) {
    let left = input_occurrences(before);
    let right = input_occurrences(after);
    for id in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
        let (prior, next) = (left.get(id), right.get(id));
        if prior.is_some_and(|v| v.len() > 1) || next.is_some_and(|v| v.len() > 1) {
            out.semantic_deltas.push(delta(
                "input_identity",
                id,
                Change::IdentityAmbiguous,
                prior.map(|v| json!(v)),
                next.map(|v| json!(v)),
                "Multiple input occurrences share an identity; no first candidate is selected.",
            ));
        }
    }
}
fn compare_storage(before: &StateAssets, after: &StateAssets, out: &mut TransitionAnalysis) {
    let left = input_occurrences(before);
    let right = input_occurrences(after);
    for id in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (left.get(id), right.get(id));
        if a.is_some_and(|v| v.len() != 1) || b.is_some_and(|v| v.len() != 1) {
            continue;
        }
        let (prior, next) = (a.map(|v| v[0]), b.map(|v| v[0]));
        if prior.map(|i| &i.content_ref) != next.map(|i| &i.content_ref)
            && (prior.is_none_or(|i| i.roles.is_empty()) && next.is_none_or(|i| i.roles.is_empty())
                || prior.zip(next).is_some_and(|(a, b)| a.roles == b.roles))
        {
            out.evidence_deltas.push(delta("storage",id,Change::StorageOnly,prior.map(|i|json!(i.content_ref)),next.map(|i|json!(i.content_ref)),"Output or formatting bytes changed without a known governing-meaning change; this is not an implementation regression."));
        }
    }
}

/// Compares only a matching finite authored restriction algebra.
#[must_use]
pub(super) fn policy_relation(before: &FinitePolicy, after: &FinitePolicy) -> Change {
    if !before.complete
        || !after.complete
        || before.origin_kind != "AUTHORED"
        || after.origin_kind != "AUTHORED"
        || before.quantifier != "ALL"
        || after.quantifier != "ALL"
    {
        return Change::Unsupported;
    }
    if before.vocabulary_ref != after.vocabulary_ref
        || before.universe != after.universe
        || before.scope != after.scope
        || before.context_ref != after.context_ref
    {
        return Change::NotComparable;
    }
    if before.origin_ref == after.origin_ref
        && (before.denied != after.denied || before.allowed != after.allowed)
    {
        return Change::NotComparable;
    }
    let stronger =
        before.denied.is_subset(&after.denied) && after.allowed.is_subset(&before.allowed);
    let weaker = after.denied.is_subset(&before.denied) && before.allowed.is_subset(&after.allowed);
    match (stronger, weaker) {
        (true, true) => Change::Unchanged,
        (true, false) => Change::Strengthened,
        (false, true) => Change::Weakened,
        _ => Change::Mixed,
    }
}
fn compare_entities(
    before: &StateAssets,
    after: &StateAssets,
    out: &mut TransitionAnalysis,
    cancelled: &AtomicBool,
) -> Result<(), TransitionError> {
    let index = |s: &StateAssets| {
        let mut m = BTreeMap::<(String, String), Vec<Entity>>::new();
        for e in &s.entities {
            m.entry((e.kind.clone(), e.id.clone()))
                .or_default()
                .push(e.clone());
        }
        m
    };
    let left = index(before);
    let right = index(after);
    for key in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
        check_cancel(cancelled)?;
        let (prior, next) = (left.get(key), right.get(key));
        let change = if prior.is_some_and(|v| v.len() != 1) || next.is_some_and(|v| v.len() != 1) {
            Change::IdentityAmbiguous
        } else {
            match (prior, next) {
                (None, Some(_)) => {
                    if complete_axis(
                        before,
                        if key.0 == "observation" {
                            Axis::Subject
                        } else {
                            Axis::Intent
                        },
                    ) {
                        Change::Added
                    } else {
                        Change::Unknown
                    }
                }
                (Some(_), None) => {
                    if complete_axis(
                        after,
                        if key.0 == "observation" {
                            Axis::Subject
                        } else {
                            Axis::Intent
                        },
                    ) {
                        Change::Removed
                    } else {
                        Change::Unknown
                    }
                }
                (Some(prior), Some(next)) => {
                    if (prior[0].promise.is_some() || next[0].promise.is_some())
                        && !matching_authority(before, after)
                    {
                        Change::NotComparable
                    } else {
                        entity_relation(&prior[0], &next[0])
                    }
                }
                _ => unreachable!(),
            }
        };
        out.semantic_deltas.push(delta("entity",&format!("{}:{}",key.0,key.1),change,prior.map(|v|json!(v)),next.map(|v|json!(v)),"Pair by stable identity before content. Added/removed properties are separate from authored guarantee implication; ambiguous identities are not selected arbitrarily."));
    }
    Ok(())
}
fn entity_relation(before: &Entity, after: &Entity) -> Change {
    if before.semantic_ref == after.semantic_ref {
        return if before.path == after.path {
            Change::Unchanged
        } else if before.kind == "observation" {
            Change::NotComparable
        } else {
            Change::PlacementOnly
        };
    }
    let (Some(prior), Some(next)) = (&before.promise, &after.promise) else {
        return Change::Changed;
    };
    if prior.quantifier != "ALL" || next.quantifier != "ALL" {
        return Change::Unsupported;
    }
    if prior.subject != next.subject
        || prior
            .clauses
            .iter()
            .any(|(id, d)| next.clauses.get(id).is_some_and(|new| new != d))
    {
        return Change::NotComparable;
    }
    let left = prior.clauses.keys().collect::<BTreeSet<_>>();
    let right = next.clauses.keys().collect::<BTreeSet<_>>();
    if left == right {
        Change::NotComparable
    } else if left.is_subset(&right) {
        Change::Strengthened
    } else if right.is_subset(&left) {
        Change::Weakened
    } else {
        Change::Mixed
    }
}
pub(super) fn delta(
    category: &str,
    id: &str,
    change: Change,
    before: Option<Value>,
    after: Option<Value>,
    reason: &str,
) -> Delta {
    Delta {
        category: category.into(),
        id: id.into(),
        change,
        before,
        after,
        reasons: vec![reason.into()],
    }
}
fn json_opt(value: Option<&String>) -> Option<Value> {
    value.map(|prior| json!(prior))
}
fn finalize(
    before: &ComparisonState,
    after: &ComparisonState,
    context: &ComparisonContext,
    out: &mut TransitionAnalysis,
) -> Result<(), TransitionError> {
    for d in &out.semantic_deltas {
        if d.change == Change::Strengthened {
            out.strengthenings.push(format!("{}:{}", d.category, d.id));
        }
        if d.change == Change::Weakened {
            out.weakenings.push(format!("{}:{}", d.category, d.id));
        }
    }
    let relaxations = out
        .semantic_deltas
        .iter()
        .filter(|d| d.category == "policy" && d.change == Change::Weakened)
        .map(|d| d.id.clone())
        .collect::<BTreeSet<_>>();
    if !relaxations.is_empty()
        && out
            .input_deltas
            .iter()
            .any(|d| d.axis == Axis::Subject && d.change == Change::Changed)
    {
        let related = matching_source_changes(before, after, &relaxations);
        out.semantic_deltas.push(delta("policy","source-permission-comovement",if related {Change::CoMovingAuthorization}else {Change::Unknown},None,None,if related {"Source and permission relaxation changed in the same owner-resolved Module scope. Co-movement is not an approved authorization or implementation fix."}else {"Source and permission changes coexist, but matching ownership/scope was not established. No co-moving authorization is inferred."}));
    }
    for d in &out.input_deltas {
        if matches!(d.axis, Axis::Intent | Axis::Authority | Axis::Governance)
            && d.change == Change::Changed
        {
            out.required_authorizations.push(AuthorizationReference {
                axis: d.axis,
                base_authority_ref: authority(before).map(str::to_owned),
                citations: context.authorization_refs.clone(),
                validation: "NOT_VALIDATED".into(),
            });
        }
    }
    for d in out
        .semantic_deltas
        .iter()
        .chain(&out.coverage_deltas)
        .chain(&out.evidence_deltas)
        .chain(&out.finding_deltas)
    {
        if matches!(
            d.change,
            Change::NotComparable
                | Change::Unknown
                | Change::Unsupported
                | Change::IdentityAmbiguous
                | Change::AuthorityIncomparable
        ) {
            out.incomparabilities
                .push(format!("{}:{}:{:?}", d.category, d.id, d.change));
        }
    }
    for records in [
        &mut out.semantic_deltas,
        &mut out.coverage_deltas,
        &mut out.evidence_deltas,
        &mut out.finding_deltas,
    ] {
        records
            .sort_by(|prior, next| (&prior.category, &prior.id).cmp(&(&next.category, &next.id)));
    }
    out.limitations
        .extend(before.limitations.iter().chain(&after.limitations).cloned());
    out.limitations.sort();
    out.limitations.dedup();
    out.incomparabilities.sort();
    out.incomparabilities.dedup();
    out.strengthenings.sort();
    out.weakenings.sort();
    let count = out.semantic_deltas.len()
        + out.coverage_deltas.len()
        + out.evidence_deltas.len()
        + out.finding_deltas.len();
    if count > MAX_TRANSITION_RECORDS {
        return Err(fail("RESOURCE_LIMIT", "too many comparison result records"));
    }
    Ok(())
}
fn validate_context(
    before: &ComparisonState,
    after: &ComparisonState,
    c: &ComparisonContext,
) -> Result<(), TransitionError> {
    if c.counterfactuals.len() > 4 || c.authorization_refs.len() > 64 {
        return Err(fail(
            "RESOURCE_LIMIT",
            "comparison context exceeds admission",
        ));
    }
    let subjects = [
        before
            .subject_identity()?
            .or_else(|| before.source_ref.clone()),
        after
            .subject_identity()?
            .or_else(|| after.source_ref.clone()),
    ];
    let authorities = [
        before
            .governing_identity()?
            .or_else(|| authority(before).map(str::to_owned)),
        after
            .governing_identity()?
            .or_else(|| authority(after).map(str::to_owned)),
    ];
    let mut seen = BTreeSet::new();
    for citation in &c.authorization_refs {
        validation::check_text(citation)?;
    }
    for cell in &c.counterfactuals {
        cell.view
            .validate()
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        let Some(app) = &cell.view.application else {
            return Err(fail(
                "INVALID_INPUT",
                "counterfactual has no evaluated authority",
            ));
        };
        if !subjects.contains(&Some(cell.subject_ref.clone()))
            || !authorities.contains(&Some(cell.authority_ref.clone()))
            || !seen.insert((&cell.subject_ref, &cell.authority_ref))
        {
            return Err(fail(
                "INVALID_INPUT",
                "counterfactual cell is outside the comparison or duplicated",
            ));
        }
        let (subject, governing) = if let Some(assets) = &cell.assets {
            validation::validate_assets(assets)?;
            if assets.subject_ref != cell.view.source_ref {
                return Err(fail(
                    "INTEGRITY_ERROR",
                    "counterfactual assets differ from original full source",
                ));
            }
            (
                super::identity::subject(assets)?,
                super::identity::governing(assets, Some(&app.declaration.binding.context_ref))?,
            )
        } else {
            (None, None)
        };
        if subject.as_deref().unwrap_or(&cell.view.source_ref) != cell.subject_ref
            || governing
                .as_deref()
                .unwrap_or(&app.declaration.binding.authority_ref)
                != cell.authority_ref
        {
            return Err(fail(
                "INTEGRITY_ERROR",
                "counterfactual role bindings differ from original evidence",
            ));
        }
    }
    Ok(())
}
fn compare_cells(
    c: &ComparisonContext,
    out: &mut TransitionAnalysis,
) -> Result<(), TransitionError> {
    if c.counterfactuals.is_empty() {
        return Ok(());
    }
    let grouped = c.counterfactuals.iter().fold(
        BTreeMap::<String, Vec<&Counterfactual>>::new(),
        |mut m, cell| {
            m.entry(cell.authority_ref.clone()).or_default().push(cell);
            m
        },
    );
    for (authority, mut cells) in grouped {
        cells.sort_by_key(|cell| &cell.subject_ref);
        let change = if cells.len() == 2
            && cells.iter().all(|cell| {
                cell.assets.as_ref().is_some_and(|assets| {
                    [
                        Axis::Subject,
                        Axis::Intent,
                        Axis::Authority,
                        Axis::Governance,
                    ]
                    .iter()
                    .all(|a| complete_axis(assets, *a))
                })
            }) {
            Change::Changed
        } else {
            Change::NotComparable
        };
        out.semantic_deltas.push(delta("common_authority",&authority,change,Some(json!(cells)),None,"Explicit evaluated source contrast at a common authority. Cells are not executed or rewritten; this supports only the recorded contrast, not physical implementation causation or external approval."));
    }
    canonical(c)?;
    Ok(())
}
/// Produces independent base and labelled parent comparisons to one merge target.
/// # Errors
/// Refuses duplicate parent labels, malformed cells and bounded-resource exhaustion.
pub fn compare_merge(
    base: &ComparisonState,
    parents: &[(String, ComparisonState)],
    target: &ComparisonState,
    context: &ComparisonContext,
) -> Result<Vec<ParentComparison>, TransitionError> {
    if parents.len() > 8 {
        return Err(fail("RESOURCE_LIMIT", "too many merge parents"));
    }
    let mut labels = BTreeSet::from(["base".to_owned()]);
    let mut result = vec![ParentComparison {
        label: "base".into(),
        transition: compare_states(base, target, context)?,
    }];
    for (label, parent) in parents {
        validation::check_text(label)?;
        if !labels.insert(label.clone()) {
            return Err(fail("INVALID_INPUT", "ambiguous merge parent label"));
        }
        result.push(ParentComparison {
            label: label.clone(),
            transition: compare_states(parent, target, context)?,
        });
    }
    result[1..].sort_by(|after, before| after.label.cmp(&before.label));
    canonical(&result)?;
    Ok(result)
}

fn normalized_context(context: &ComparisonContext) -> ComparisonContext {
    let mut value = context.clone();
    for cell in &mut value.counterfactuals {
        if let Some(assets) = &mut cell.assets {
            assets.normalize();
        }
    }
    value.counterfactuals.sort_by(|after, before| {
        (&after.subject_ref, &after.authority_ref)
            .cmp(&(&before.subject_ref, &before.authority_ref))
    });
    value
}

fn exclusion_change(before: &StateAssets, after: &StateAssets) -> Change {
    let (Some(prior), Some(next)) = (&before.exclusions, &after.exclusions) else {
        return Change::NotComparable;
    };
    let covered = |path: &str, selectors: &BTreeSet<String>| {
        selectors.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    };
    if prior.iter().all(|path| covered(path, next)) && next.iter().any(|path| !covered(path, prior))
    {
        Change::ScopeExcluded
    } else {
        Change::NotComparable
    }
}

fn matching_source_changes(
    before: &ComparisonState,
    after: &ComparisonState,
    policies: &BTreeSet<String>,
) -> bool {
    let (Some(prior), Some(next)) = (&before.assets, &after.assets) else {
        return false;
    };
    let left = input_occurrences(prior);
    let right = input_occurrences(next);
    left.keys()
        .chain(right.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .any(|id| {
            let (a, b) = (left.get(id), right.get(id));
            if a.is_some_and(|v| v.len() != 1) || b.is_some_and(|v| v.len() != 1) {
                return false;
            }
            let (a, b) = (a.map(|v| v[0]), b.map(|v| v[0]));
            if a.and_then(|i| i.roles.get(&Axis::Subject))
                == b.and_then(|i| i.roles.get(&Axis::Subject))
            {
                return false;
            }
            policies.iter().any(|scope| {
                a.is_none_or(|i| i.scope_refs.contains(scope))
                    && b.is_none_or(|i| i.scope_refs.contains(scope))
            })
        })
}
