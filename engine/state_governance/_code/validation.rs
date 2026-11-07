//! Bounded validation of owner-supplied exact comparison inputs.
use super::{
    Axis, ComparisonState, FinitePolicy, MAX_TRANSITION_RECORDS, StateAssets, TransitionError,
    canonical, digest, fail,
};
use std::collections::BTreeSet;

pub(super) fn validate_state(state: &ComparisonState) -> Result<(), TransitionError> {
    if state.schema != "urn:fortress:derived:v1:comparison-state" || state.schema_version != 1 {
        return Err(fail("UNSUPPORTED_VERSION", "unsupported comparison input"));
    }
    for reference in [&state.source_ref, &state.origin_ref].into_iter().flatten() {
        check_digest(reference)?;
    }
    if let Some(view) = &state.view {
        view.validate()
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        if state.source_ref.as_ref() != Some(&view.source_ref) {
            return Err(fail(
                "INTEGRITY_ERROR",
                "endpoint source differs from original StateView",
            ));
        }
    }
    if let Some(app) = &state.retained_application {
        if state.view.is_some()
            || !app.evidence.is_empty()
            || !app.obligations.is_empty()
            || app.evidence_inputs.is_some()
            || !app.provider_requirements.is_empty()
        {
            return Err(fail(
                "INVALID_INPUT",
                "retained pair cannot fabricate omitted StateView metadata",
            ));
        }
        app.declaration
            .validate()
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        app.assessment
            .validate()
            .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
        if state.source_ref.as_ref() != Some(&app.declaration.binding.subject_ref)
            || app.assessment.binding != app.declaration.binding
            || app.assessment.declaration_digest
                != app
                    .declaration
                    .digest()
                    .map_err(|e| fail("INVALID_INPUT", e.to_string()))?
        {
            return Err(fail("INTEGRITY_ERROR", "retained pair binding differs"));
        }
    }
    if let Some(assets) = &state.assets {
        if state.source_ref.as_ref() != Some(&assets.subject_ref) {
            return Err(fail(
                "INTEGRITY_ERROR",
                "asset source differs from endpoint",
            ));
        }
        validate_assets(assets)?;
    }
    for text in &state.limitations {
        check_text(text)?;
    }
    canonical(state)?;
    Ok(())
}
pub(super) fn validate_assets(after: &StateAssets) -> Result<(), TransitionError> {
    if after
        .inputs
        .len()
        .saturating_add(after.entities.len())
        .saturating_add(after.policies.len())
        > MAX_TRANSITION_RECORDS
    {
        return Err(fail("RESOURCE_LIMIT", "too many comparison records"));
    }
    if after.profile_refs.len() > MAX_TRANSITION_RECORDS
        || after
            .reference_facts
            .as_ref()
            .is_some_and(|s| s.len() > MAX_TRANSITION_RECORDS)
        || after
            .exclusions
            .as_ref()
            .is_some_and(|s| s.len() > MAX_TRANSITION_RECORDS)
    {
        return Err(fail(
            "RESOURCE_LIMIT",
            "comparison semantic set exceeds admission",
        ));
    }
    let mut occurrences = BTreeSet::new();
    for input in &after.inputs {
        check_text(&input.id)?;
        check_path(&input.path)?;
        check_digest(&input.content_ref)?;
        if input.scope_refs.len() > MAX_TRANSITION_RECORDS {
            return Err(fail("RESOURCE_LIMIT", "too many ownership scopes"));
        }
        for scope in &input.scope_refs {
            check_text(scope)?;
        }
        if !occurrences.insert((&input.id, &input.path)) {
            return Err(fail("INVALID_INPUT", "duplicate input occurrence"));
        }
        for value in input.roles.values() {
            check_digest(value)?;
        }
    }
    validate_entities(after)?;
    let mut policies = BTreeSet::new();
    for policy in &after.policies {
        if !policies.insert(&policy.id) {
            return Err(fail("INVALID_INPUT", "ambiguous policy slot"));
        }
        validate_policy(policy, after)?;
    }
    for reference in [
        &after.standard_ref,
        &after.evaluator_ref,
        &after.exclusions_ref,
    ]
    .into_iter()
    .flatten()
    {
        check_digest(reference)?;
    }
    if let Some(exclusions) = &after.exclusions {
        for selector in exclusions {
            check_path(selector)?;
        }
        if after.exclusions_ref.as_ref() != Some(&digest(exclusions)?) {
            return Err(fail("INTEGRITY_ERROR", "exclusion selector digest differs"));
        }
    }
    for reference in &after.profile_refs {
        check_text(reference)?;
    }
    if let Some(facts) = &after.reference_facts {
        for fact in facts {
            check_text(fact)?;
        }
    }
    Ok(())
}
fn validate_entities(after: &StateAssets) -> Result<(), TransitionError> {
    let mut entity_occurrences = BTreeSet::new();
    for entity in &after.entities {
        check_text(&entity.id)?;
        check_digest(&entity.semantic_ref)?;
        if ![
            "module",
            "guarantee",
            "requirement",
            "reference",
            "observation",
        ]
        .contains(&entity.kind.as_str())
        {
            return Err(fail("UNSUPPORTED_SEMANTICS", "unknown entity namespace"));
        }
        if let Some(path) = &entity.path {
            check_path(path)?;
        }
        let path = entity.path.as_deref().unwrap_or("");
        if !entity_occurrences.insert((&entity.id, path)) {
            return Err(fail("INVALID_INPUT", "duplicate semantic occurrence"));
        }
        if let Some(promise) = &entity.promise {
            if entity.kind != "guarantee" {
                return Err(fail(
                    "INVALID_INPUT",
                    "observations cannot become authored guarantees",
                ));
            }
            check_text(&promise.subject)?;
            check_text(&promise.quantifier)?;
            for (id, meaning) in &promise.clauses {
                check_text(id)?;
                check_digest(meaning)?;
            }
        }
    }
    Ok(())
}
fn validate_policy(p: &FinitePolicy, after: &StateAssets) -> Result<(), TransitionError> {
    for text in [&p.id, &p.origin_kind, &p.scope, &p.quantifier] {
        check_text(text)?;
    }
    for d in [&p.origin_ref, &p.vocabulary_ref, &p.context_ref] {
        check_digest(d)?;
    }
    if !after
        .inputs
        .iter()
        .any(|i| i.content_ref == p.origin_ref && i.roles.contains_key(&Axis::Intent))
    {
        return Err(fail(
            "INTEGRITY_ERROR",
            "policy origin is absent from the authored intent inventory",
        ));
    }
    if !p.denied.is_subset(&p.universe)
        || !p.allowed.is_subset(&p.universe)
        || !p.denied.is_disjoint(&p.allowed)
    {
        return Err(fail("INVALID_INPUT", "invalid finite policy partition"));
    }
    if p.universe.len() > 4096 {
        return Err(fail(
            "RESOURCE_LIMIT",
            "policy vocabulary exceeds admission",
        ));
    }
    for target in &p.universe {
        check_text(target)?;
    }
    Ok(())
}
pub(crate) fn check_digest(value: &str) -> Result<(), TransitionError> {
    if !crate::declaration::is_digest(value) {
        return Err(fail("INVALID_INPUT", "expected an exact SHA-256 reference"));
    }
    Ok(())
}
pub(crate) fn check_text(value: &str) -> Result<(), TransitionError> {
    if value.is_empty()
        || value.len() > 8192
        || value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(fail("INVALID_INPUT", "invalid bounded comparison text"));
    }
    Ok(())
}
fn check_path(path: &str) -> Result<(), TransitionError> {
    if !crate::observation::is_canonical_relative_path(path) {
        return Err(fail("INVALID_INPUT", "unsafe comparison occurrence path"));
    }
    Ok(())
}

pub(super) fn validate_result(result: &super::TransitionAnalysis) -> Result<(), TransitionError> {
    for reference in [
        &result.from_state,
        &result.to_state,
        &result.comparison_context,
    ] {
        check_digest(reference)?;
    }
    if result.input_deltas.len() != 4
        || result.input_deltas.iter().map(|d| d.axis).ne([
            Axis::Subject,
            Axis::Intent,
            Axis::Authority,
            Axis::Governance,
        ])
    {
        return Err(fail(
            "INVALID_INPUT",
            "transition axes are incomplete or unordered",
        ));
    }
    let groups = [
        &result.semantic_deltas,
        &result.coverage_deltas,
        &result.evidence_deltas,
        &result.finding_deltas,
    ];
    let count = groups
        .iter()
        .map(|v| v.len())
        .sum::<usize>()
        .saturating_add(result.incomparabilities.len())
        .saturating_add(result.retirement_evidence.len());
    if count > MAX_TRANSITION_RECORDS {
        return Err(fail(
            "RESOURCE_LIMIT",
            "too many complete transition records",
        ));
    }
    for records in groups {
        if records
            .windows(2)
            .any(|p| (&p[0].category, &p[0].id) >= (&p[1].category, &p[1].id))
        {
            return Err(fail(
                "INVALID_INPUT",
                "transition delta identity collision or ordering error",
            ));
        }
    }
    for values in [
        &result.weakenings,
        &result.strengthenings,
        &result.incomparabilities,
        &result.limitations,
    ] {
        if values.len() > MAX_TRANSITION_RECORDS {
            return Err(fail("RESOURCE_LIMIT", "transition set exceeds admission"));
        }
        for value in values {
            check_text(value)?;
        }
    }
    if result.required_authorizations.len() > 3 {
        return Err(fail(
            "RESOURCE_LIMIT",
            "too many authorization citation classes",
        ));
    }
    for reference in &result.required_authorizations {
        if reference.validation != "NOT_VALIDATED" {
            return Err(fail(
                "INVALID_INPUT",
                "comparison cannot validate authorization",
            ));
        }
    }
    Ok(())
}
