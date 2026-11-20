//! Canonical orchestration for reviewed introduction of governance on pinned implementation.
use crate::affected_analysis::{AuthorityInputKind, classify_authority_path};
use crate::finding_governance::{
    AdmissionClassification, BaselineEntry, FindingException, FindingGovernanceDocument,
    FindingGovernanceEvaluation, MAX_ADMISSION_FINDINGS, RetiredBaselineEntry,
    evaluate_finding_governance_in_context,
};
use crate::migration_governance::{
    EvaluatedAdmission, MigrationError, MigrationOperation, OperationGraph,
    admission_governance_path,
};
use crate::observation::SourceView;
use crate::state_governance::{ComparisonState, classify_governance_introduction};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

fn error(code: &str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}

fn invalid(value: impl std::fmt::Display) -> MigrationError {
    error("INVALID_ADMISSION", value.to_string())
}

fn governance(view: &SourceView) -> Result<FindingGovernanceDocument, MigrationError> {
    view.bytes(&admission_governance_path()?)
        .map(|bytes| {
            FindingGovernanceDocument::from_json_str(std::str::from_utf8(bytes).map_err(invalid)?)
                .map_err(invalid)
        })
        .transpose()
        .map(|document| document.unwrap_or_else(FindingGovernanceDocument::empty_current))
}

fn reviewed_change(path: &str, left: &[u8], right: &[u8]) -> bool {
    fn other_inputs(raw: &[u8], kind: AuthorityInputKind) -> Option<Value> {
        let mut value: Value =
            crate::wire::parse_public_json(std::str::from_utf8(raw).ok()?).ok()?;
        let fields = value.as_object_mut()?;
        match kind {
            AuthorityInputKind::ProjectConfiguration => {
                fields.remove("assurance_profiles");
                if let Some(selection) = fields.get_mut("governance").and_then(Value::as_object_mut)
                {
                    selection.remove("selected_profiles");
                    selection.remove("module_overrides");
                }
            }
            AuthorityInputKind::ModuleContract => {
                fields.remove("$schema");
                fields.remove("schema_version");
                fields.remove("semantic_policy");
            }
            _ => return None,
        }
        Some(value)
    }
    let kind = classify_authority_path(path);
    other_inputs(left, kind)
        .zip(other_inputs(right, kind))
        .is_some_and(|(left, right)| left == right)
}

fn exact_introduction(original: &SourceView, proposed: &SourceView) -> bool {
    if !original.keys().eq(proposed.keys()) {
        return false;
    }
    let mut changes = original.iter().filter_map(|(path, before)| {
        proposed
            .bytes(path)
            .filter(|after| *after != before)
            .map(|after| (path, before, after))
    });
    changes
        .next()
        .is_some_and(|(path, before, after)| reviewed_change(path, before, after))
        && changes.next().is_none()
}

fn retained_history(document: &FindingGovernanceDocument) -> BTreeSet<&str> {
    let mut excluded = BTreeSet::new();
    if let Some(baseline) = document.baseline() {
        excluded.extend(
            baseline
                .active_entries()
                .iter()
                .map(BaselineEntry::finding_id),
        );
        excluded.extend(
            baseline
                .retired_entries()
                .iter()
                .map(RetiredBaselineEntry::finding_id),
        );
    }
    excluded.extend(
        document
            .exceptions()
            .iter()
            .map(FindingException::finding_id),
    );
    excluded.extend(document.admissions().keys().map(String::as_str));
    excluded
}

/// Evaluates an explicitly specified operation set on immutable original bytes through existing owners.
/// This result reports reviewed possibilities, without trust in supplied historical citations.
/// # Errors
/// Refuses malformed input, operation conflicts, unsupported evaluator input and resource exhaustion.
pub fn evaluate_governance_admission(
    before: &SourceView,
    operations: Vec<MigrationOperation>,
    history: &[ComparisonState],
) -> Result<EvaluatedAdmission, MigrationError> {
    evaluate_admission_cancellable(before, operations, history, &AtomicBool::new(false))
}

pub(crate) fn evaluate_admission_cancellable(
    before: &SourceView,
    operations: Vec<MigrationOperation>,
    history: &[ComparisonState],
    cancelled: &AtomicBool,
) -> Result<EvaluatedAdmission, MigrationError> {
    let check_cancelled = || {
        if cancelled.load(Ordering::Acquire) {
            Err(error(
                "CANCELLED",
                "admission did not retain or publish a result",
            ))
        } else {
            Ok(())
        }
    };
    check_cancelled()?;
    if operations.len() > MAX_ADMISSION_FINDINGS || history.len() > 64 {
        return Err(error("RESOURCE_LIMIT", "admission inputs exceed bounds"));
    }
    let (base, old_facts) =
        crate::audit::evaluate_candidate_source(before, None).map_err(invalid)?;
    check_cancelled()?;
    let graph = OperationGraph::compile(before, operations, &base.ownership)?;
    let target = graph.target();
    let (proposed, new_facts) =
        crate::audit::evaluate_candidate_source(target, None).map_err(invalid)?;
    check_cancelled()?;
    let old_findings = old_facts
        .as_ref()
        .map_or(&[][..], |facts| facts.findings.as_slice());
    let new_findings = new_facts
        .as_ref()
        .map_or(&[][..], |facts| facts.findings.as_slice());
    let mut assessment = classify_governance_introduction(
        &base.state,
        &proposed.state,
        old_findings,
        new_findings,
        history,
    )
    .map_err(|e| error(&e.code, e.message))?;
    let authority = governance(before)?;
    let previous = retained_history(&authority);
    let mut previous_aliases = BTreeSet::new();
    for finding in new_findings {
        if finding
            .legacy_finding_ids()
            .iter()
            .any(|alias| previous.contains(alias.as_str()))
        {
            previous_aliases.insert(finding.finding_id());
        }
    }
    let exact = exact_introduction(before, target);
    for row in &mut assessment.findings {
        if row.classification != AdmissionClassification::NewlyGoverned {
            continue;
        }
        if previous.contains(row.finding_id.as_str())
            || previous_aliases.contains(row.finding_id.as_str())
            || authority
                .admissions()
                .values()
                .any(|r| Some(&r.scope_slot_ref) == row.scope_slot_ref.as_ref())
        {
            row.classification = AdmissionClassification::PreviouslyGoverned;
            row.reason = "Retained finding or scope history prevents a second admission.".into();
        } else if !exact {
            row.classification = AdmissionClassification::NotComparable;
            row.reason = "Additional source, visibility, authority or ownership changes prevent isolated attribution.".into();
        } else {
            continue;
        }
        row.introduced_scope_ref = None;
        row.scope_slot_ref = None;
        row.anchor = None;
    }
    assessment.bind_identity().map_err(invalid)?;
    check_cancelled()?;
    Ok(EvaluatedAdmission {
        assessment,
        target_state: proposed.state,
        original: before.clone(),
        proposed: target.clone(),
        operations: graph.operations().to_vec(),
        ownership: base.ownership,
        governance: authority,
        exact_introduction_inputs: exact,
    })
}

/// Read-only actual observation followed by the existing canonical admission evaluation.
/// # Errors
/// Refuses unsafe repositories, active migration, invalid operations and incomplete source.
pub fn preview_repository_admission(
    root: &Path,
    operations: Vec<MigrationOperation>,
    history: &[ComparisonState],
) -> Result<EvaluatedAdmission, MigrationError> {
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(invalid)?;
    let before = crate::audit::observe_candidate_source(root).map_err(invalid)?;
    let result = evaluate_governance_admission(&before, operations, history)?;
    if crate::audit::observe_candidate_source(root).map_err(invalid)? != before {
        return Err(error(
            "STALE_BASE",
            "repository bytes changed during the read-only admission preview",
        ));
    }
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(invalid)?;
    Ok(result)
}

/// Reobserves the exact reviewed target and reuses its raw findings with process-local permission.
/// No receipt or document can reconstruct this permission. Actual test execution, profile
/// sufficiency and canonical certification remain the existing owners' independent outputs.
/// # Errors
/// Refuses stale bytes, missing grants, expired review or changed scope.
pub fn evaluate_authorized_admission(
    root: &Path,
    reviewed: &crate::migration_governance::ReviewedAdmission,
    permission: &crate::development_governance::ApplicationAuthorization,
    time: Option<u64>,
) -> Result<FindingGovernanceEvaluation, MigrationError> {
    crate::migration_adapter::require_finding_grant(permission)?;
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(invalid)?;
    let observed = crate::audit::observe_candidate_source(root).map_err(invalid)?;
    let (evaluation, facts) =
        crate::audit::evaluate_candidate_source(&observed, None).map_err(invalid)?;
    reviewed.validate_actual(&evaluation, &observed, permission, time)?;
    let facts =
        facts.ok_or_else(|| error("NOT_EVALUABLE", "canonical finding evidence is unavailable"))?;
    let document = governance(&observed)?;
    let mut context = crate::lifecycle_load::current_context(&evaluation.state, &document, time)
        .map_err(|e| error(&e.code, e.message))?;
    let eligible = facts
        .findings
        .iter()
        .filter(|finding| {
            document
                .admissions()
                .get(finding.finding_id())
                .is_some_and(|record| record.assessment_ref == reviewed.assessment_ref())
        })
        .cloned()
        .collect::<Vec<_>>();
    let anchors = crate::state_governance::finding_anchors(&evaluation.state, &eligible)
        .map_err(|e| error(&e.code, e.message))?;
    for (id, record) in document
        .admissions()
        .iter()
        .filter(|(_, record)| record.assessment_ref == reviewed.assessment_ref())
    {
        let anchor = anchors
            .get(id)
            .filter(|anchor| record.lifecycle_anchor.comparable_to(anchor))
            .ok_or_else(|| {
                error(
                    "NOT_COMPARABLE",
                    "current finding does not reproduce original governing meaning",
                )
            })?;
        context.admit_finding(anchor.clone(), record.digest().map_err(invalid)?);
    }
    let evaluated = evaluate_finding_governance_in_context(
        &facts.findings,
        Some(&document),
        &facts.standard.0,
        &facts.standard.1,
        &context,
    )
    .map_err(invalid)?;
    if crate::audit::observe_candidate_source(root).map_err(invalid)? != observed {
        return Err(error(
            "STALE_BASE",
            "actual repository bytes changed during enforcement evaluation",
        ));
    }
    crate::heavy_admission::assert_no_incomplete_migration(root).map_err(invalid)?;
    Ok(evaluated)
}
