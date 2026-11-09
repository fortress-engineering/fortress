//! Pure base-bound authorization requirements and injected external trust port.
#[path = "decision.rs"]
mod decision;
pub use crate::authority_roles::ProtectedClass;
use crate::observation::{CandidateChangeSet, ChangeOperation, SourceView};
use crate::state_governance::{
    ComparisonContext, ComparisonState, TransitionAnalysis, TransitionError, compare_states,
};
pub use decision::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Neutral operation kind; grants cannot silently cover another action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    /// Add exact bytes.
    Create,
    /// Replace exact bytes.
    Replace,
    /// Remove exact bytes.
    Delete,
    /// Relocate exact bytes.
    Move,
}
/// Registered protected role at one exact input path and authority scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedInput {
    /// Canonical repository-relative input.
    pub path: String,
    /// Protected meaning.
    pub class: ProtectedClass,
    /// Exact owner or project scope.
    pub scope: String,
}
/// Exact operation projection, retaining preimage and replacement identities.
#[derive(Clone, Debug, Serialize)]
pub struct ProposedOperation {
    /// Operation kind.
    pub action: Action,
    /// Source or created input.
    pub path: String,
    /// Move destination, if present.
    pub destination: Option<String>,
}
/// Immutable prepared input. Only the existing comparator evaluates transition meaning.
#[derive(Clone, Debug, Serialize)]
pub struct PreparedChange {
    base_state_ref: String,
    candidate_state_ref: String,
    base_authority_ref: Option<String>,
    candidate_authority_ref: Option<String>,
    changes_ref: String,
    base_bytes_ref: String,
    candidate_bytes_ref: String,
    context_ref: String,
    target_authority_ref: String,
    transition: TransitionAnalysis,
    operations: Vec<ProposedOperation>,
    roles: Vec<ProtectedInput>,
    inventory_complete: bool,
    base: ComparisonState,
    candidate: ComparisonState,
    comparison_context: ComparisonContext,
    /// Citations retained as unverified provenance, never authorization.
    pub authorization_references: Vec<String>,
}
impl PreparedChange {
    /// Prepares exact operations and the existing four-axis comparison without filesystem access.
    /// The composition root must bind the supplied observations to these exact byte views.
    /// # Errors
    /// Refuses malformed states, paths and resource exhaustion; identical union facts deduplicate.
    pub fn new(
        base: &ComparisonState,
        candidate: &ComparisonState,
        context: &ComparisonContext,
        base_bytes: &SourceView,
        changes: &CandidateChangeSet,
        roles: (Vec<ProtectedInput>, Vec<ProtectedInput>),
        inventory_complete: bool,
    ) -> Result<Self, TransitionError> {
        for source in [base_bytes, changes.view()] {
            if source.len() > crate::state_governance::MAX_TRANSITION_RECORDS
                || source
                    .values()
                    .try_fold(0usize, |n, b| n.checked_add(b.len()))
                    .is_none_or(|n| n > crate::state_governance::MAX_TRANSITION_BYTES)
            {
                return Err(error(
                    "RESOURCE_LIMIT",
                    "proposed source inventory exceeds admission",
                ));
            }
        }
        let transition = compare_states(base, candidate, context)?;
        if base_bytes.digest() != changes.base_view_digest()
            || base.source_ref.as_deref() != Some(&source_subject(base_bytes))
            || candidate.source_ref.as_deref() != Some(&source_subject(changes.view()))
            || changes.context_digest() != transition.comparison_context
            || candidate.governing_identity()?.as_deref() != Some(changes.target_authority_digest())
        {
            return Err(error(
                "INVALID_BINDING",
                "proposal bytes/context/target authority differ from compared states",
            ));
        }
        if changes.operations().len() > crate::state_governance::MAX_TRANSITION_RECORDS {
            return Err(error("RESOURCE_LIMIT", "too many proposed operations"));
        }
        let (mut base_roles, candidate_roles) = roles;
        base_roles.extend(candidate_roles);
        base_roles.sort();
        base_roles.dedup();
        if base_roles.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
            return Err(error("RESOURCE_LIMIT", "too many protected roles"));
        }
        for role in &base_roles {
            if !crate::observation::is_canonical_relative_path(&role.path) || role.scope.is_empty()
            {
                return Err(error("INVALID_INPUT", "invalid protected scope/path"));
            }
        }
        let operations = changes
            .operations()
            .iter()
            .map(|op| match op {
                ChangeOperation::Create { path, .. } => ProposedOperation {
                    action: Action::Create,
                    path: path.clone(),
                    destination: None,
                },
                ChangeOperation::Replace { path, .. } => ProposedOperation {
                    action: Action::Replace,
                    path: path.clone(),
                    destination: None,
                },
                ChangeOperation::Delete { path, .. } => ProposedOperation {
                    action: Action::Delete,
                    path: path.clone(),
                    destination: None,
                },
                ChangeOperation::Move {
                    source,
                    destination,
                    ..
                } => ProposedOperation {
                    action: Action::Move,
                    path: source.clone(),
                    destination: Some(destination.clone()),
                },
            })
            .collect();
        let value = Self {
            base_state_ref: base.digest()?,
            candidate_state_ref: candidate.digest()?,
            base_authority_ref: base.governing_identity()?,
            candidate_authority_ref: candidate.governing_identity()?,
            changes_ref: changes.digest().into(),
            base_bytes_ref: changes.base_view_digest().into(),
            candidate_bytes_ref: changes.view().digest().into(),
            context_ref: changes.context_digest().into(),
            target_authority_ref: changes.target_authority_digest().into(),
            transition,
            operations,
            roles: base_roles,
            inventory_complete,
            base: base.clone(),
            candidate: candidate.clone(),
            comparison_context: context.clone(),
            authorization_references: context.authorization_refs.iter().cloned().collect(),
        };
        canonical(&value)?;
        Ok(value)
    }
    /// Exact original endpoint identity.
    #[must_use]
    pub fn base_state_ref(&self) -> &str {
        &self.base_state_ref
    }
    /// Complete base governing projection, if available.
    #[must_use]
    pub fn base_authority_ref(&self) -> Option<&str> {
        self.base_authority_ref.as_deref()
    }
    /// Content-bound proposal identity, including exact operations and comparisons.
    /// # Errors
    /// Refuses excessive serialization.
    pub fn digest(&self) -> Result<String, TransitionError> {
        digest(self)
    }
}
/// Explicit trusted base rule. No candidate-owned policy selection is consulted.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRule {
    /// Stable base rule identifier.
    pub id: String,
    /// Protected classes covered.
    #[serde(deserialize_with = "strict_set")]
    pub classes: BTreeSet<ProtectedClass>,
    /// Permitted request action vocabulary.
    #[serde(deserialize_with = "strict_set")]
    pub actions: BTreeSet<Action>,
    /// Exact protected scope, with no wildcard expansion.
    pub scope: String,
    /// Independently selected issuer policy identity.
    pub issuer_policy_ref: String,
}
/// Process-local base selection supplied by a trusted embedding, never deserialized.
#[derive(Clone, Debug, Serialize)]
pub struct TrustedBasePolicy {
    base_state_ref: String,
    base_authority_ref: String,
    root_policy_ref: String,
    #[serde(skip)]
    policy_ref: String,
    require_assurance: bool,
    rules: Vec<AuthorizationRule>,
    #[serde(skip)]
    rule_index: BTreeMap<(String, ProtectedClass, Action), usize>,
}
impl TrustedBasePolicy {
    /// Installs host-selected base authority. Calling this is an external trust-boundary operation.
    /// # Errors
    /// Rejects malformed or ambiguous rules and identities.
    pub fn from_host(
        base_state_ref: impl Into<String>,
        base_authority_ref: impl Into<String>,
        policy_ref: impl Into<String>,
        require_assurance: bool,
        mut rules: Vec<AuthorizationRule>,
    ) -> Result<Self, TransitionError> {
        let root_policy_ref = policy_ref.into();
        let p = Self {
            base_state_ref: base_state_ref.into(),
            base_authority_ref: base_authority_ref.into(),
            policy_ref: root_policy_ref.clone(),
            root_policy_ref,
            require_assurance,
            rules: vec![],
            rule_index: BTreeMap::new(),
        };
        for id in [&p.base_state_ref, &p.base_authority_ref, &p.policy_ref] {
            check_digest(id)?;
        }
        let mut ids = BTreeSet::new();
        let mut cells = BTreeSet::new();
        if rules.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
            return Err(error("RESOURCE_LIMIT", "too many authorization rules"));
        }
        for r in &rules {
            check_digest(&r.issuer_policy_ref)?;
            if r.id.is_empty()
                || r.scope.is_empty()
                || r.classes.is_empty()
                || r.actions.is_empty()
                || !ids.insert(r.id.clone())
            {
                return Err(error("AMBIGUOUS_AUTHORITY", "empty or duplicate base rule"));
            }
            for c in &r.classes {
                for a in &r.actions {
                    if !cells.insert((r.scope.clone(), *c, *a)) {
                        return Err(error("AMBIGUOUS_AUTHORITY", "overlapping base rule"));
                    }
                    if cells.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
                        return Err(error("RESOURCE_LIMIT", "too many authority rule cells"));
                    }
                }
            }
        }
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        let mut selected = Self { rules, ..p };
        for (i, r) in selected.rules.iter().enumerate() {
            for c in &r.classes {
                for a in &r.actions {
                    selected.rule_index.insert((r.scope.clone(), *c, *a), i);
                }
            }
        }
        selected.policy_ref = digest(&selected)?;
        Ok(selected)
    }
    /// Original explicitly selected rule inventory.
    #[must_use]
    pub fn rules(&self) -> &[AuthorizationRule] {
        &self.rules
    }
}
/// Request to a separately trusted host validator. References are not proofs.
#[derive(Clone, Debug, Serialize)]
pub struct GrantRequest {
    /// Exact proposal.
    pub proposal_ref: String,
    /// Original base endpoint.
    pub base_state_ref: String,
    /// Proposed endpoint.
    pub candidate_state_ref: String,
    /// Governing base authority.
    pub base_authority_ref: String,
    /// Selected base policy.
    pub policy_ref: String,
    /// Exact governing requirement.
    pub requirement: AuthorizationRequirement,
    /// Explicit evaluation time, never a hidden clock.
    pub time: Option<u64>,
    /// Pinned original evaluator identity, independent of candidate evaluator changes.
    pub base_evaluator_ref: Option<String>,
    /// Externally selected root policy that must admit evaluator qualification.
    pub qualification_policy_ref: String,
}
impl GrantRequest {
    /// Creates a request for a requirement already prepared by the pure decision service.
    #[must_use]
    pub fn new(
        p: &PreparedChange,
        policy: &TrustedBasePolicy,
        requirement: &AuthorizationRequirement,
        time: Option<u64>,
    ) -> Self {
        Self {
            proposal_ref: requirement.proposal_ref.clone(),
            base_state_ref: p.base_state_ref.clone(),
            candidate_state_ref: p.candidate_state_ref.clone(),
            base_authority_ref: policy.base_authority_ref.clone(),
            policy_ref: policy.policy_ref.clone(),
            requirement: requirement.clone(),
            time,
            base_evaluator_ref: p.base.assets.as_ref().and_then(|a| a.evaluator_ref.clone()),
            qualification_policy_ref: policy.root_policy_ref.clone(),
        }
    }
}
/// Exact external qualification provenance admitted by the trusted validator.
/// These fields alone do not authenticate a qualification producer or execute tests.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAssertion {
    /// Exact proposed endpoint whose assessor implementation was qualified.
    pub candidate_state_ref: String,
    /// Original externally pinned evaluator under which installation is judged.
    pub base_evaluator_ref: String,
    /// Trusted original qualification policy, independent of candidate configuration.
    pub policy_ref: String,
    /// Actual external qualification evidence reference, never candidate self-certification.
    pub evidence_ref: String,
}
/// Authenticated host assertion. The port, not this serializable receipt, establishes trust.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostAssertion {
    /// Exact proposal identity.
    pub proposal_ref: String,
    /// Exact original endpoint.
    pub base_state_ref: String,
    /// Exact proposed endpoint.
    pub candidate_state_ref: String,
    /// Governing base identity.
    pub base_authority_ref: String,
    /// Selected base policy.
    pub policy_ref: String,
    /// Exact requirement identity.
    pub requirement_ref: String,
    /// Authorized operation.
    pub action: Action,
    /// Authorized protected class.
    pub class: ProtectedClass,
    /// Exact authorized scope.
    pub scope: String,
    /// Independently trusted issuer policy.
    pub issuer_policy_ref: String,
    /// Authenticated external issuer identifier.
    pub issuer: String,
    /// Trusted verifier/configuration identity.
    pub verifier_ref: String,
    /// Optional explicit expiry.
    pub expires_at: Option<u64>,
    /// Separately verified external qualification, required for assessor changes.
    pub qualification: Option<QualificationAssertion>,
}
impl HostAssertion {
    /// Builds an assertion inside an independently authenticated host adapter.
    #[must_use]
    pub fn for_request(
        r: &GrantRequest,
        issuer: impl Into<String>,
        verifier_ref: String,
        expires_at: Option<u64>,
        qualification: Option<QualificationAssertion>,
    ) -> Self {
        Self {
            proposal_ref: r.proposal_ref.clone(),
            base_state_ref: r.base_state_ref.clone(),
            candidate_state_ref: r.candidate_state_ref.clone(),
            base_authority_ref: r.base_authority_ref.clone(),
            policy_ref: r.policy_ref.clone(),
            requirement_ref: r.requirement.id.clone(),
            action: r.requirement.action,
            class: r.requirement.class,
            scope: r.requirement.scope.clone(),
            issuer_policy_ref: r.requirement.issuer_policy_ref.clone().unwrap_or_default(),
            issuer: issuer.into(),
            verifier_ref,
            expires_at,
            qualification,
        }
    }
}
/// Trusted port response; repository records cannot invoke this port implicitly.
#[derive(Clone, Debug)]
pub enum GrantValidation {
    /// No independently supplied evidence.
    Missing,
    /// Validation boundary could not be reached.
    Unavailable,
    /// Approval mechanism is outside this implementation.
    Unsupported,
    /// Independently rejected evidence.
    Invalid,
    /// Conflicting external assertions.
    Conflicting,
    /// Authenticated, scope-limited external assertion requiring local binding checks.
    Authenticated(Box<HostAssertion>),
}
/// Explicitly trusted injection point. Only hosts with independent authentication implement it.
pub trait GrantValidator {
    /// Checks externally supplied evidence, without treating a reference as approval.
    fn validate(&self, request: &GrantRequest) -> GrantValidation;
}
/// Default inspection port; neither repository JSON nor command arguments create grants.
pub struct NoGrantValidator;
impl GrantValidator for NoGrantValidator {
    fn validate(&self, _: &GrantRequest) -> GrantValidation {
        GrantValidation::Missing
    }
}
/// In-memory validated assertion; serialization is provenance, never a transferable grant.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatedGrant {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    assertion: HostAssertion,
    receipt_semantics: &'static str,
}
impl ValidatedGrant {
    /// Reads the exact externally authenticated assertion retained in this process.
    /// Serialized bytes cannot reconstruct this handle.
    #[must_use]
    pub fn assertion(&self) -> &HostAssertion {
        &self.assertion
    }
}
pub(crate) fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, TransitionError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(b.len())
                .filter(|n| *n <= crate::state_governance::MAX_TRANSITION_BYTES)
                .ok_or_else(|| std::io::Error::other("authorization document limit"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), v).map_err(|_| {
        error(
            "RESOURCE_LIMIT",
            "authorization serialization exceeds admission",
        )
    })?;
    let bytes =
        crate::declaration::canonical(v).map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    if bytes.len() > crate::state_governance::MAX_TRANSITION_BYTES {
        return Err(error(
            "RESOURCE_LIMIT",
            "authorization document exceeds admission",
        ));
    }
    Ok(bytes)
}
pub(crate) fn digest<T: Serialize>(v: &T) -> Result<String, TransitionError> {
    use sha2::{Digest, Sha256};
    Ok(format!("sha256:{:x}", Sha256::digest(canonical(v)?)))
}
pub(crate) fn error(code: &str, message: impl Into<String>) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
pub(crate) fn check_digest(id: &str) -> Result<(), TransitionError> {
    if id.len() != 71
        || !id.starts_with("sha256:")
        || !id[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error(
            "INVALID_BINDING",
            "expected canonical SHA-256 identity",
        ));
    }
    Ok(())
}

/// Source binding excludes only registered nonrecursive CONTROL payloads; exact
/// proposed byte identities still include them for publication authorization.
pub(crate) fn source_subject(source: &SourceView) -> String {
    let layout = crate::control_layout::ControlLayout::standard();
    let files = source
        .iter()
        .filter(|(path, _)| {
            layout.resolve(path).is_none_or(|entry| {
                entry.role() == crate::control_layout::ControlRole::Unrecognized
                    || entry.source_binding()
                        != crate::control_layout::ControlSourceBinding::Nonrecursive
            })
        })
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    crate::certification::certification_source_digest(&files)
}
fn strict_set<'de, T: Deserialize<'de> + Ord, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<BTreeSet<T>, D::Error> {
    let values = Vec::<T>::deserialize(decoder)?;
    let length = values.len();
    let set = values.into_iter().collect::<BTreeSet<_>>();
    if set.len() != length {
        return Err(serde::de::Error::custom(
            "duplicate authorization set member",
        ));
    }
    Ok(set)
}
