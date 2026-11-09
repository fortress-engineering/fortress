//! Explicit bounded read-only authority snapshot capture and proposal composition.
use crate::development_governance::{
    ChangeDecision, NoGrantValidator, PreparedChange, ProtectedInput, TrustedBasePolicy,
    UnmediatedHost, evaluate_change,
};
use crate::observation::{CandidateChangeSet, ChangeOperation, SourceView};
use crate::state_governance::{ComparisonContext, ComparisonState, TransitionError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Public exact input capture; source bytes are observations and never authorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    /// Versioned public schema.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Supported capture edition.
    pub schema_version: u16,
    /// Original assessed state and immutable authority identities.
    pub state: ComparisonState,
    /// Bounded authoritative source inventory, excluding generated recursive evidence.
    pub files: BTreeMap<String, Vec<u8>>,
}
impl AuthoritySnapshot {
    /// Validates and serializes observations without performing new semantic analysis.
    /// # Errors
    /// Rejects invalid source, tampering, unsupported versions and resource exhaustion.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        self.source()?;
        let bytes =
            crate::wire::canonicalize_public_json(&serde_json::to_string(self).map_err(convert)?)
                .map_err(convert)?;
        if bytes.len() > crate::state_governance::MAX_TRANSITION_BYTES {
            return Err(fail(
                "RESOURCE_LIMIT",
                "authority capture exceeds byte limit",
            ));
        }
        Ok(bytes)
    }
    /// Reads exact immutable inputs; no code or analyzer runs.
    /// # Errors
    /// Rejects malformed public JSON, digest mismatches and unsafe paths.
    pub fn from_json_str(source: &str) -> Result<Self, TransitionError> {
        if source.len() > crate::state_governance::MAX_TRANSITION_BYTES {
            return Err(fail("RESOURCE_LIMIT", "authority input too large"));
        }
        let value: Self = crate::wire::parse_public_json(source).map_err(convert)?;
        value.source()?;
        Ok(value)
    }
    fn source(&self) -> Result<SourceView, TransitionError> {
        if self.schema != "urn:fortress:derived:v1:authority-snapshot" || self.schema_version != 1 {
            return Err(fail(
                "UNSUPPORTED_VERSION",
                "unsupported authority snapshot",
            ));
        }
        self.state.validate()?;
        if self.files.len() > crate::state_governance::MAX_TRANSITION_RECORDS
            || self.files.keys().any(|p| p.len() > 4096)
            || self
                .files
                .values()
                .try_fold(0usize, |n, b| n.checked_add(b.len()))
                .is_none_or(|n| n > crate::state_governance::MAX_TRANSITION_BYTES)
        {
            return Err(fail("RESOURCE_LIMIT", "source inventory exceeds admission"));
        }
        let source = SourceView::from_bytes(self.files.clone()).map_err(convert)?;
        if self.state.source_ref.as_deref()
            != Some(&crate::development_governance::source_subject(&source))
        {
            return Err(fail(
                "INVALID_BINDING",
                "authority snapshot source differs from original endpoint",
            ));
        }
        Ok(source)
    }
}
/// Explicit capture can invoke existing owner analysis; inspection of a capture never does.
/// # Errors
/// Refuses unstable, oversized or unavailable source. No project build code executes.
pub fn capture_authority_snapshot(root: &Path) -> Result<AuthoritySnapshot, TransitionError> {
    let state = crate::transition_load::load_comparison_state(root, "current")?;
    let (source, _) = crate::audit::observe_resident_source_bounded(root, 16 * 1024 * 1024, 50_000)
        .map_err(convert)?;
    let mut files = source.files().clone();
    let layout = crate::control_layout::ControlLayout::standard();
    if let Some(path) =
        layout.role_path(crate::control_layout::ControlRole::AssessmentSelectionIndex)
    {
        match crate::query::safe_read(root, &root.join(path), 1024 * 1024) {
            Ok(bytes) => {
                files.insert(path.into(), bytes);
            }
            Err(e) if e.code == "MISSING" => {}
            Err(e) => return Err(fail(&e.code, e.message)),
        }
    }
    let value = AuthoritySnapshot {
        schema: "urn:fortress:derived:v1:authority-snapshot".into(),
        schema_version: 1,
        state,
        files,
    };
    value.source()?;
    Ok(value)
}
/// Prepares a deterministic operation set from two explicitly captured states.
/// No snapshot is modified and no missing history is reconstructed.
/// # Errors
/// Refuses malformed identities, incomplete target authority and excessive input.
pub fn prepare_authority_change(
    base: &AuthoritySnapshot,
    candidate: &AuthoritySnapshot,
    context: &ComparisonContext,
) -> Result<PreparedChange, TransitionError> {
    let before = base.source()?;
    let after = candidate.source()?;
    let transition =
        crate::state_governance::compare_states(&base.state, &candidate.state, context)?;
    let paths = before.keys().chain(after.keys()).collect::<BTreeSet<_>>();
    let mut operations = vec![];
    for path in paths {
        match (before.get(path), after.get(path)) {
            (Some(a), Some(b)) if a != b => operations.push(ChangeOperation::Replace {
                path: path.clone(),
                base_bytes: a.clone(),
                candidate_bytes: b.clone(),
            }),
            (None, Some(b)) => operations.push(ChangeOperation::Create {
                path: path.clone(),
                candidate_bytes: b.clone(),
            }),
            (Some(a), None) => operations.push(ChangeOperation::Delete {
                path: path.clone(),
                base_bytes: a.clone(),
            }),
            _ => {}
        }
    }
    let target = candidate.state.governing_identity()?.ok_or_else(|| {
        fail(
            "INCOMPLETE_AUTHORITY",
            "target authority is missing or ambiguous",
        )
    })?;
    let changes =
        CandidateChangeSet::new(&before, transition.comparison_context, target, operations)
            .map_err(convert)?;
    let complete = [base, candidate].iter().all(|s| {
        s.state
            .assets
            .as_ref()
            .is_some_and(|a| a.complete_axes.len() == 4)
    });
    PreparedChange::new(
        &base.state,
        &candidate.state,
        context,
        &before,
        &changes,
        (roles(base)?, roles(candidate)?),
        complete,
    )
}
fn roles(snapshot: &AuthoritySnapshot) -> Result<Vec<ProtectedInput>, TransitionError> {
    use crate::authority_roles::{ProtectedClass, protected_input_roles, protected_owner_roles};
    let layout = crate::control_layout::ControlLayout::standard();
    let mut result = BTreeSet::new();
    let mut by_path = BTreeMap::new();
    if let Some(assets) = &snapshot.state.assets {
        for input in &assets.inputs {
            if by_path.insert(input.path.as_str(), input).is_some() {
                return Err(fail(
                    "AMBIGUOUS_AUTHORITY",
                    "multiple authority input identities occupy one path",
                ));
            }
        }
    }
    for (path, bytes) in &snapshot.files {
        let value = std::str::from_utf8(bytes)
            .ok()
            .filter(|s| s.trim_start().starts_with('{'))
            .and_then(|s| crate::wire::parse_public_json::<serde_json::Value>(s).ok());
        let schema = value.as_ref().and_then(|v| v["$schema"].as_str());
        let mut classes = protected_input_roles(&layout, path, schema);
        if value
            .as_ref()
            .and_then(|v| v["$id"].as_str())
            .is_some_and(|id| id.starts_with("urn:fortress:"))
        {
            classes.insert(ProtectedClass::SchemaCompatibility);
        }
        let input = by_path.get(path.as_str()).copied();
        let scopes = input
            .map(|i| i.scope_refs.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| BTreeSet::from(["project".into()]));
        if let Some(input) = input {
            for axis in input.roles.keys() {
                match axis {
                    crate::state_governance::Axis::Intent => {
                        classes.insert(ProtectedClass::ModuleIntent);
                    }
                    crate::state_governance::Axis::Authority => {
                        classes.insert(ProtectedClass::Standard);
                    }
                    crate::state_governance::Axis::Governance => {
                        classes.insert(ProtectedClass::FindingGovernance);
                    }
                    crate::state_governance::Axis::Subject => {}
                }
            }
        }
        for scope in scopes {
            let mut resolved_classes = classes.clone();
            resolved_classes.extend(protected_owner_roles(&scope));
            for class in resolved_classes {
                result.insert(ProtectedInput {
                    path: path.clone(),
                    class,
                    scope: scope.clone(),
                });
                if result.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
                    return Err(fail(
                        "RESOURCE_LIMIT",
                        "protected input inventory too large",
                    ));
                }
            }
        }
    }
    if result.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
        return Err(fail(
            "RESOURCE_LIMIT",
            "protected input inventory too large",
        ));
    }
    Ok(result.into_iter().collect())
}
/// Evaluates an explicitly selected base-policy preview. No production trust is claimed.
/// # Errors
/// Refuses incoherent trusted base selection; no mutation or approval occurs.
pub fn preview_authority_change(
    change: &PreparedChange,
    policy: &TrustedBasePolicy,
) -> Result<ChangeDecision, TransitionError> {
    evaluate_change(change, policy, &UnmediatedHost, &NoGrantValidator, None)
}
fn convert(e: impl std::fmt::Display) -> TransitionError {
    fail("INVALID_INPUT", e.to_string())
}
fn fail(code: &str, message: impl Into<String>) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
