//! Independent semantic, assurance, authorization and host-coverage decision algebra.
use super::{
    Action, BTreeMap, BTreeSet, GrantRequest, GrantValidation, GrantValidator, PreparedChange,
    ProtectedClass, ProtectedInput, TransitionAnalysis, TransitionError, TrustedBasePolicy,
    ValidatedGrant, canonical, check_digest, digest, error,
};
use crate::assessment::AssessmentDecision;
use crate::declaration::DeclarationTruth;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::Write;

/// Final operational disposition, independent of raw semantic findings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Disposition {
    /// All selected premises support this transition.
    Permit,
    /// Existing base-authority evidence supports an enforced violation.
    DenySupportedViolation,
    /// Independently verified authorization is absent.
    RequireAuthorization,
    /// Selected base assurance policy lacks required support.
    HoldRequiredAssurance,
    /// Necessary comparison or assessment is unavailable.
    Unevaluated,
}
/// One independently reportable dimension.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDimension {
    /// Stable outcome vocabulary.
    pub state: String,
    /// Evidence-backed explanation or missing premise.
    pub reasons: Vec<String>,
}
/// Deterministic exact-proposal protected action requirement.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequirement {
    /// Content identity of all other fields.
    pub id: String,
    /// Exact proposed operation set and comparison.
    pub proposal_ref: String,
    /// Exact original governing rule.
    pub base_rule: String,
    /// Required protected action.
    pub action: Action,
    /// Protected meaning.
    pub class: ProtectedClass,
    /// Exact input path, or an explicit `@authority/` virtual identity selector.
    pub path: String,
    /// Exact protected authority scope.
    pub scope: String,
    /// Trusted issuer policy, absent when governing rule is unresolved.
    pub issuer_policy_ref: Option<String>,
}
/// Nontransferable record of the actual authorization check.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationOutcome {
    /// Exact requirement identity.
    pub requirement_ref: String,
    /// MISSING, INVALID, UNSUPPORTED, CONFLICTING, UNAVAILABLE, VERIFIED or `QUALIFICATION_REQUIRED`.
    pub state: String,
    /// Explicit reason, never inferred from a citation.
    pub reason: String,
    /// Original host assertion as provenance only.
    pub receipt: Option<serde_json::Value>,
}
/// Host adapter boundary, separate from repository-authored provider claims.
pub trait HostCoverage {
    /// Returns independently established coverage for this exact proposal.
    fn coverage(&self, proposal_ref: &str) -> DecisionDimension;
}
/// Read-only preview has no write-mediating host or provider protection verification.
pub struct UnmediatedHost;
impl HostCoverage for UnmediatedHost {
    fn coverage(&self, _: &str) -> DecisionDimension {
        dimension(
            "UNMEDIATED",
            "No write-mediating host is installed; provider protection is UNVERIFIED.",
        )
    }
}
/// Versioned derived decision. Reading this receipt never recreates a grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeDecision {
    /// Public schema identity.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Supported public edition.
    pub schema_version: u16,
    /// Exact prepared operation/comparison identity.
    pub proposal_ref: String,
    /// Exact original endpoint.
    pub base_state_ref: String,
    /// Exact proposed endpoint.
    pub candidate_state_ref: String,
    /// Original target declaration binding for Certification and portable consumers.
    pub candidate_binding: Option<crate::declaration::DeclarationBinding>,
    /// Explicit clock input used for time-limited authorization, never a hidden current time.
    pub evaluation_time: Option<u64>,
    /// Original governing authority.
    pub base_authority_ref: String,
    /// Explicit trusted policy identity.
    pub policy_ref: String,
    /// Exact existing four-axis analysis; historical findings remain unchanged.
    pub transition: TransitionAnalysis,
    /// Base-authority semantic result, never the favorable target policy result.
    pub semantic_enforcement: DecisionDimension,
    /// Explicit selected required-assurance result.
    pub assurance_requirements: DecisionDimension,
    /// Protected-surface and authorization result.
    pub protected_authority: DecisionDimension,
    /// Actual host mediation and provider protection knowledge.
    pub host_coverage: DecisionDimension,
    /// Complete deterministic request inventory.
    pub requirements: Vec<AuthorizationRequirement>,
    /// Actual external checks, one per requirement.
    pub authorization: Vec<AuthorizationOutcome>,
    /// References remain citations even when a separate grant was verified.
    pub authorization_references: Vec<String>,
    /// Permission/hold algebra; does not rewrite semantic truth.
    pub disposition: Disposition,
    /// Whether a trusted write-mediating host reported mediation.
    pub enforced: bool,
    /// Always provenance only when serialized or exported unsigned.
    pub receipt_semantics: String,
}
impl ChangeDecision {
    /// Checks an existing declaration/portable manifest binding without inferring approval.
    /// Matching unsigned records establish binding equality only, never authentication.
    #[must_use]
    pub fn portable_binding_status(
        &self,
        binding: &crate::declaration::DeclarationBinding,
    ) -> DecisionDimension {
        if self.candidate_binding.as_ref() == Some(binding) {
            dimension(
                "BOUND",
                "Exact original target subject/context/authority matches; portable integrity does not authenticate authorization.",
            )
        } else {
            dimension(
                "UNVERIFIED",
                "Target declaration binding is missing or differs; no favorable portable authorization conclusion is supported.",
            )
        }
    }
    /// Validated deterministic JCS result bytes.
    /// # Errors
    /// Refuses malformed versions, bindings and excessive documents.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        self.validate()?;
        canonical(self)
    }
    /// Exact public result identity; integrity is separate from authentication.
    /// # Errors
    /// Refuses malformed output.
    pub fn digest(&self) -> Result<String, TransitionError> {
        self.validate()?;
        digest(self)
    }
    /// Reads a public provenance receipt without reconstructing `ValidatedGrant`.
    /// # Errors
    /// Refuses duplicate keys, malformed versions, bindings or resource exhaustion.
    pub fn from_json_str(source: &str) -> Result<Self, TransitionError> {
        if source.len() > crate::state_governance::MAX_TRANSITION_BYTES {
            return Err(error("RESOURCE_LIMIT", "decision too large"));
        }
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    /// Reads a receipt only when its independently supplied full content digest matches.
    /// Integrity verification does not authenticate the recorded grant or producer.
    /// # Errors
    /// Rejects changed fields, malformed records, unsupported versions or resource limits.
    pub fn from_json_str_bound(source: &str, expected: &str) -> Result<Self, TransitionError> {
        check_digest(expected)?;
        let value = Self::from_json_str(source)?;
        if value.digest()? != expected {
            return Err(error(
                "INTEGRITY_ERROR",
                "change decision content differs from expected digest",
            ));
        }
        Ok(value)
    }
    fn validate(&self) -> Result<(), TransitionError> {
        validate_text_fields(self)?;
        if self.schema != "urn:fortress:derived:v1:change-decision"
            || self.schema_version != 1
            || self.receipt_semantics != "PROVENANCE_ONLY_NOT_TRANSFERABLE"
        {
            return Err(error(
                "UNSUPPORTED_VERSION",
                "unsupported decision semantics",
            ));
        }
        for id in [
            &self.proposal_ref,
            &self.base_state_ref,
            &self.candidate_state_ref,
            &self.base_authority_ref,
            &self.policy_ref,
        ] {
            check_digest(id)?;
        }
        self.transition.to_canonical_bytes()?;
        if let Some(binding) = &self.candidate_binding {
            for id in [
                &binding.subject_ref,
                &binding.context_ref,
                &binding.authority_ref,
            ] {
                check_digest(id)?;
            }
            let subject = self
                .transition
                .evidence_deltas
                .iter()
                .find(|d| d.category == "source_identity")
                .and_then(|d| d.after.as_ref())
                .and_then(serde_json::Value::as_str);
            if subject != Some(binding.subject_ref.as_str()) {
                return Err(error(
                    "INVALID_BINDING",
                    "portable target binding differs from original comparison subject",
                ));
            }
        }
        if self.transition.from_state != self.base_state_ref
            || self.transition.to_state != self.candidate_state_ref
            || self.requirements.len() != self.authorization.len()
        {
            return Err(error(
                "INVALID_BINDING",
                "decision endpoint/requirement mismatch",
            ));
        }
        let mut seen = BTreeSet::new();
        for (r, a) in self.requirements.iter().zip(&self.authorization) {
            let mut copy = r.clone();
            copy.id.clear();
            if r.id != digest(&copy)?
                || r.proposal_ref != self.proposal_ref
                || a.requirement_ref != r.id
                || !seen.insert(&r.id)
            {
                return Err(error("INVALID_BINDING", "requirement tampering/ambiguity"));
            }
            validate_recorded_authorization(self, r, a)?;
        }
        if self.protected_authority.state == "SATISFIED"
            && self.authorization.iter().any(|a| a.state != "VERIFIED")
        {
            return Err(error(
                "INVALID_BINDING",
                "unsatisfied authorization cannot be reported satisfied",
            ));
        }
        if self.enforced != (self.host_coverage.state == "MEDIATED")
            || self.disposition
                != disposition(
                    &self.semantic_enforcement,
                    &self.protected_authority,
                    &self.assurance_requirements,
                )
        {
            return Err(error(
                "INVALID_BINDING",
                "decision algebra or host coverage was altered",
            ));
        }
        Ok(())
    }
    /// Human rendering of the same machine result, including every protected requirement.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut s = format!("{:?} — proposal {}\n", self.disposition, self.proposal_ref);
        for (name, d) in [
            ("semantic", &self.semantic_enforcement),
            ("assurance", &self.assurance_requirements),
            ("authorization", &self.protected_authority),
            ("host", &self.host_coverage),
        ] {
            let _ = writeln!(s, "{name}: {} — {}", d.state, d.reasons.join("; "));
        }
        for (r, a) in self.requirements.iter().zip(&self.authorization) {
            let _ = writeln!(
                s,
                "{:?} {:?} {} [{}]: {} — {}",
                r.action, r.class, r.path, r.scope, a.state, a.reason
            );
        }
        for id in &self.transition.weakenings {
            let _ = writeln!(s, "Authored weakening retained: {id}");
        }
        for id in &self.transition.strengthenings {
            let _ = writeln!(s, "Authored strengthening retained: {id}");
        }
        s.push_str("Recorded checks are provenance. Reading this result does not reverify authorization, authenticate its producer, grant permission or establish provider enforcement.\n");
        s
    }
}
fn dimension(state: &str, reason: &str) -> DecisionDimension {
    DecisionDimension {
        state: state.into(),
        reasons: vec![reason.into()],
    }
}
/// Evaluates prepared data using only trusted base selection and injected host ports.
/// No code is compiled, files modified, approval URL followed or new semantic evaluation run.
/// # Errors
/// Refuses mismatched trusted selection, malformed output and resource exhaustion.
pub fn evaluate_change(
    p: &PreparedChange,
    policy: &TrustedBasePolicy,
    host: &impl HostCoverage,
    validator: &impl GrantValidator,
    time: Option<u64>,
) -> Result<ChangeDecision, TransitionError> {
    evaluate_change_with_grants(p, policy, host, validator, time)
        .map(|evaluated| evaluated.decision)
}
/// Process-local decision and opaque grants. This handle cannot be deserialized.
pub struct ChangeEvaluation {
    decision: ChangeDecision,
    grants: Vec<ValidatedGrant>,
}
impl ChangeEvaluation {
    /// Reads the independent decision without granting any additional action.
    #[must_use]
    pub fn decision(&self) -> &ChangeDecision {
        &self.decision
    }
    /// Reads exact grants produced by this evaluation's trusted host port.
    #[must_use]
    pub fn grants(&self) -> &[ValidatedGrant] {
        &self.grants
    }
}
/// Retains opaque validated grants for trusted host consumers without a receipt replay path.
/// # Errors
/// Refuses mismatched base selection, malformed data and bounded resource failures.
pub fn evaluate_change_with_grants(
    p: &PreparedChange,
    policy: &TrustedBasePolicy,
    host: &impl HostCoverage,
    validator: &impl GrantValidator,
    time: Option<u64>,
) -> Result<ChangeEvaluation, TransitionError> {
    if policy.base_state_ref != p.base_state_ref
        || Some(&policy.base_authority_ref) != p.base_authority_ref.as_ref()
    {
        return Err(error(
            "BASE_AUTHORITY_MISMATCH",
            "trusted base selection is not bound to this original state",
        ));
    }
    let proposal_ref = p.digest()?;
    let requirements = prepare_requirements(p, policy, &proposal_ref)?;
    let checks = requirements
        .iter()
        .map(|r| validate_grant(&GrantRequest::new(p, policy, r, time), validator))
        .collect::<Vec<_>>();
    let mut grants = Vec::new();
    let mut authorization = Vec::new();
    for check in checks {
        authorization.push(check.outcome);
        if let Some(grant) = check.grant {
            grants.push(grant);
        }
    }
    let protected_authority = if !p.inventory_complete {
        dimension(
            "UNRESOLVED",
            "Protected input inventory is incomplete; candidate exclusions cannot prove absence.",
        )
    } else if authorization.iter().any(|a| a.state != "VERIFIED") {
        dimension(
            "REQUIRED",
            "Protected changes require independently verified exact-proposal authorization.",
        )
    } else {
        dimension(
            "SATISFIED",
            if requirements.is_empty() {
                "No protected changed inputs in complete base/candidate role union."
            } else {
                "All protected requirements independently verified within their exact scope."
            },
        )
    };
    let (semantic_enforcement, assurance_requirements) = base_assessment(p, policy)?;
    let disposition = disposition(
        &semantic_enforcement,
        &protected_authority,
        &assurance_requirements,
    );
    let host_coverage = host.coverage(&proposal_ref);
    let enforced = host_coverage.state == "MEDIATED";
    let value = ChangeDecision {
        schema: "urn:fortress:derived:v1:change-decision".into(),
        schema_version: 1,
        proposal_ref,
        base_state_ref: p.base_state_ref.clone(),
        candidate_state_ref: p.candidate_state_ref.clone(),
        candidate_binding: p
            .candidate
            .view
            .as_ref()
            .and_then(|v| v.application.as_ref())
            .or(p.candidate.retained_application.as_ref())
            .map(|a| a.declaration.binding.clone()),
        evaluation_time: time,
        base_authority_ref: policy.base_authority_ref.clone(),
        policy_ref: policy.policy_ref.clone(),
        transition: p.transition.clone(),
        semantic_enforcement,
        assurance_requirements,
        protected_authority,
        host_coverage,
        requirements,
        authorization,
        authorization_references: p.authorization_references.clone(),
        disposition,
        enforced,
        receipt_semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE".into(),
    };
    value.validate()?;
    canonical(&value)?;
    Ok(ChangeEvaluation {
        decision: value,
        grants,
    })
}
fn disposition(
    semantic: &DecisionDimension,
    protected: &DecisionDimension,
    assurance: &DecisionDimension,
) -> Disposition {
    if semantic.state == "SUPPORTED_VIOLATION" {
        Disposition::DenySupportedViolation
    } else if protected.state == "REQUIRED" {
        Disposition::RequireAuthorization
    } else if assurance.state == "REQUIRED_EVIDENCE_MISSING" {
        Disposition::HoldRequiredAssurance
    } else if protected.state != "SATISFIED"
        || !matches!(assurance.state.as_str(), "SATISFIED" | "NOT_REQUIRED")
        || !matches!(
            semantic.state.as_str(),
            "NO_SUPPORTED_VIOLATION" | "NO_BLOCKING_SUPPORTED_VIOLATION"
        )
    {
        Disposition::Unevaluated
    } else {
        Disposition::Permit
    }
}
fn base_assessment(
    p: &PreparedChange,
    policy: &TrustedBasePolicy,
) -> Result<(DecisionDimension, DecisionDimension), TransitionError> {
    // Reuse a pre-evaluated common-authority cell, never substitute candidate policy.
    let same = p.base_authority_ref == p.candidate_authority_ref;
    let cell = if same {
        p.candidate
            .view
            .as_ref()
            .and_then(|v| v.application.as_ref())
            .or(p.candidate.retained_application.as_ref())
    } else {
        let subject = p.candidate.subject_identity()?;
        p.comparison_context
            .counterfactuals
            .iter()
            .find(|c| {
                Some(&c.subject_ref) == subject.as_ref()
                    && Some(&c.authority_ref) == p.base_authority_ref.as_ref()
            })
            .and_then(|c| c.view.application.as_ref())
    };
    let semantic=cell.map_or_else(||dimension("UNEVALUATED","No supported candidate assessment under the unchanged trusted base authority was supplied."),|a|{
        if !a.declaration.residue_summary.blocking_findings.is_empty(){dimension("SUPPORTED_VIOLATION","Existing base-authority declaration retains supported progressive blocking findings; authorization cannot erase them.")}
        else if a.declaration.claims.iter().any(|c|c.truth==DeclarationTruth::SupportedViolation){dimension("NO_BLOCKING_SUPPORTED_VIOLATION","Raw supported violations remain recorded; existing base-authority progressive dispositions report no blocking findings.")}
        else if a.declaration.dimensions.iter().any(|d|d.truth==DeclarationTruth::NoSupportedViolation)&&a.declaration.dimensions.iter().all(|d|matches!(d.truth,DeclarationTruth::NoSupportedViolation|DeclarationTruth::NotApplicable)){dimension("NO_SUPPORTED_VIOLATION","Existing exact base-authority declaration supports scoped absence in applicable dimensions. NOT_APPLICABLE dimensions remain neutral and supply no proof; an entirely nonapplicable, unknown or authorization-only declaration cannot satisfy this predicate.")}
        else {dimension("UNEVALUATED","Existing raw conformance is unknown, unsupported, nonapplicable or unevaluable; no violation is invented.")}
    });
    let assurance = if !policy.require_assurance {
        dimension(
            "NOT_REQUIRED",
            "Trusted base selection did not require an assurance admission predicate.",
        )
    } else if cell.is_some_and(|a| a.assessment.decision == AssessmentDecision::Satisfied) {
        dimension(
            "SATISFIED",
            "Existing exact base-authority Profile Assessment satisfies required assurance.",
        )
    } else {
        dimension(
            "REQUIRED_EVIDENCE_MISSING",
            "Explicit required assurance lacks current sufficient evidence; this is separate from semantic truth.",
        )
    };
    Ok((semantic, assurance))
}
struct GrantCheck {
    outcome: AuthorizationOutcome,
    grant: Option<ValidatedGrant>,
}
fn validate_grant(r: &GrantRequest, validator: &impl GrantValidator) -> GrantCheck {
    let outcome = |state: &str, reason: &str, receipt| GrantCheck {
        outcome: AuthorizationOutcome {
            requirement_ref: r.requirement.id.clone(),
            state: state.into(),
            reason: reason.into(),
            receipt,
        },
        grant: None,
    };
    if r.requirement.issuer_policy_ref.is_none() {
        return outcome(
            "UNSUPPORTED",
            "No unambiguous trusted base authorization rule covers this protected scope.",
            None,
        );
    }
    let a = match validator.validate(r) {
        GrantValidation::Authenticated(a) => *a,
        GrantValidation::Missing => {
            return outcome(
                "MISSING",
                "No independently verified external authorization supplied; citations are unverified.",
                None,
            );
        }
        GrantValidation::Unavailable => {
            return outcome(
                "UNAVAILABLE",
                "Trusted verification boundary unavailable; outage is not approval.",
                None,
            );
        }
        GrantValidation::Unsupported => {
            return outcome(
                "UNSUPPORTED",
                "Mechanism is outside the implemented trust model.",
                None,
            );
        }
        GrantValidation::Invalid => {
            return outcome(
                "INVALID",
                "External evidence rejected by trusted validator.",
                None,
            );
        }
        GrantValidation::Conflicting => {
            return outcome(
                "CONFLICTING",
                "External decisions conflict; no favorable selection.",
                None,
            );
        }
    };
    let bound = a.proposal_ref == r.proposal_ref
        && a.base_state_ref == r.base_state_ref
        && a.candidate_state_ref == r.candidate_state_ref
        && a.base_authority_ref == r.base_authority_ref
        && a.policy_ref == r.policy_ref
        && a.requirement_ref == r.requirement.id
        && a.action == r.requirement.action
        && a.class == r.requirement.class
        && a.scope == r.requirement.scope
        && Some(&a.issuer_policy_ref) == r.requirement.issuer_policy_ref.as_ref()
        && super::valid_text(&a.issuer)
        && check_digest(&a.verifier_ref).is_ok()
        && a.expires_at
            .is_none_or(|expiry| r.time.is_some_and(|now| now < expiry));
    if !bound {
        return outcome(
            "INVALID",
            "Authorization is stale, expired, ambiguous or outside exact proposal/base/candidate/action/class/scope/policy binding.",
            None,
        );
    }
    if a.class == ProtectedClass::AssessorTrust && !qualification_valid(&a, r) {
        return outcome(
            if a.qualification.is_some() {
                "INVALID"
            } else {
                "QUALIFICATION_REQUIRED"
            },
            "Modified assessor needs externally verified qualification evidence bound to the exact candidate, pinned base evaluator and original qualification policy; self-certification is insufficient.",
            None,
        );
    }
    let grant = ValidatedGrant {
        schema: "urn:fortress:derived:v1:validated-grant-receipt",
        schema_version: 1,
        assertion: a,
        receipt_semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE",
    };
    let mut checked = outcome(
        "VERIFIED",
        "Trusted external port authenticated this exact scoped assertion; semantic correctness and host enforcement remain separate.",
        Some(json!(&grant)),
    );
    checked.grant = Some(grant);
    checked
}

fn prepare_requirements(
    p: &PreparedChange,
    policy: &TrustedBasePolicy,
    proposal_ref: &str,
) -> Result<Vec<AuthorizationRequirement>, TransitionError> {
    let mut requirements = vec![];
    let mut role_index: BTreeMap<&str, Vec<&ProtectedInput>> = BTreeMap::new();
    for role in &p.roles {
        role_index.entry(&role.path).or_default().push(role);
    }
    for op in &p.operations {
        for role in std::iter::once(op.path.as_str())
            .chain(op.destination.as_deref())
            .flat_map(|path| role_index.get(path).into_iter().flatten())
        {
            let rule = policy
                .rule_index
                .get(&(role.scope.clone(), role.class, op.action))
                .map(|i| &policy.rules[*i]);
            let mut r = AuthorizationRequirement {
                id: String::new(),
                proposal_ref: proposal_ref.to_owned(),
                base_rule: rule
                    .map_or("UNRESOLVED_BASE_RULE", |r| r.id.as_str())
                    .into(),
                action: op.action,
                class: role.class,
                path: role.path.clone(),
                scope: role.scope.clone(),
                issuer_policy_ref: rule.map(|r| r.issuer_policy_ref.clone()),
            };
            r.id = digest(&r)?;
            requirements.push(r);
            if requirements.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
                return Err(error("RESOURCE_LIMIT", "too many protected requirements"));
            }
        }
    }
    if let Some((base, candidate)) = p.base.assets.as_ref().zip(p.candidate.assets.as_ref()) {
        for (changed, class, selector) in [
            (
                base.standard_ref != candidate.standard_ref,
                ProtectedClass::Standard,
                "standard",
            ),
            (
                base.profile_refs != candidate.profile_refs,
                ProtectedClass::Profile,
                "profiles",
            ),
            (
                base.evaluator_ref != candidate.evaluator_ref,
                ProtectedClass::AssessorTrust,
                "assessor",
            ),
            (
                base.exclusions_ref != candidate.exclusions_ref,
                ProtectedClass::OwnershipScope,
                "exclusions",
            ),
        ] {
            if !changed {
                continue;
            }
            let rule = policy
                .rule_index
                .get(&("project".into(), class, Action::Replace))
                .map(|i| &policy.rules[*i]);
            let mut r = AuthorizationRequirement {
                id: String::new(),
                proposal_ref: proposal_ref.to_owned(),
                base_rule: rule
                    .map_or("UNRESOLVED_BASE_RULE", |r| r.id.as_str())
                    .into(),
                action: Action::Replace,
                class,
                path: format!("@authority/{selector}"),
                scope: "project".into(),
                issuer_policy_ref: rule.map(|r| r.issuer_policy_ref.clone()),
            };
            r.id = digest(&r)?;
            requirements.push(r);
        }
    }
    if requirements.len() > crate::state_governance::MAX_TRANSITION_RECORDS {
        return Err(error(
            "RESOURCE_LIMIT",
            "protected requirement union exceeds schema admission",
        ));
    }
    requirements.sort_by(|a, b| a.id.cmp(&b.id));
    requirements.dedup_by(|a, b| a.id == b.id);
    Ok(requirements)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedGrant {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    assertion: super::HostAssertion,
    receipt_semantics: String,
}
fn qualification_valid(a: &super::HostAssertion, r: &GrantRequest) -> bool {
    a.qualification.as_ref().is_some_and(|q| {
        q.candidate_state_ref == r.candidate_state_ref
            && Some(&q.base_evaluator_ref) == r.base_evaluator_ref.as_ref()
            && q.policy_ref == r.qualification_policy_ref
            && check_digest(&q.evidence_ref).is_ok()
    })
}
fn validate_recorded_authorization(
    d: &ChangeDecision,
    r: &AuthorizationRequirement,
    a: &AuthorizationOutcome,
) -> Result<(), TransitionError> {
    if !matches!(
        a.state.as_str(),
        "MISSING"
            | "INVALID"
            | "UNSUPPORTED"
            | "CONFLICTING"
            | "UNAVAILABLE"
            | "VERIFIED"
            | "QUALIFICATION_REQUIRED"
    ) || !super::valid_text(&r.scope)
        || !super::valid_text(&r.base_rule)
        || !super::valid_text(&r.path)
        || !super::valid_text(&a.reason)
        || !crate::observation::is_canonical_relative_path(&r.path)
    {
        return Err(error(
            "INVALID_INPUT",
            "unknown authorization outcome or malformed requirement",
        ));
    }
    if let Some(id) = &r.issuer_policy_ref {
        check_digest(id)?;
    }
    if a.state != "VERIFIED" {
        if a.receipt.is_some() {
            return Err(error(
                "INVALID_BINDING",
                "unverified outcome cannot carry a validated receipt",
            ));
        }
        return Ok(());
    }
    let receipt: RecordedGrant = serde_json::from_value(
        a.receipt
            .clone()
            .ok_or_else(|| error("INVALID_BINDING", "verified outcome omitted its provenance"))?,
    )
    .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    let assertion = &receipt.assertion;
    if receipt.schema != "urn:fortress:derived:v1:validated-grant-receipt"
        || receipt.schema_version != 1
        || receipt.receipt_semantics != "PROVENANCE_ONLY_NOT_TRANSFERABLE"
        || assertion.proposal_ref != d.proposal_ref
        || assertion.base_state_ref != d.base_state_ref
        || assertion.candidate_state_ref != d.candidate_state_ref
        || assertion.base_authority_ref != d.base_authority_ref
        || assertion.policy_ref != d.policy_ref
        || assertion.requirement_ref != r.id
        || assertion.action != r.action
        || assertion.class != r.class
        || assertion.scope != r.scope
        || Some(&assertion.issuer_policy_ref) != r.issuer_policy_ref.as_ref()
        || !super::valid_text(&assertion.issuer)
        || assertion
            .expires_at
            .is_some_and(|expiry| d.evaluation_time.is_none_or(|now| now >= expiry))
    {
        return Err(error(
            "INVALID_BINDING",
            "recorded grant has inconsistent version, scope, time or exact proposal bindings",
        ));
    }
    check_digest(&assertion.verifier_ref)?;
    if r.class == ProtectedClass::AssessorTrust {
        let q = assertion
            .qualification
            .as_ref()
            .ok_or_else(|| error("INVALID_BINDING", "assessor receipt omitted qualification"))?;
        for id in [&q.base_evaluator_ref, &q.policy_ref, &q.evidence_ref] {
            check_digest(id)?;
        }
        if q.candidate_state_ref != d.candidate_state_ref {
            return Err(error(
                "INVALID_BINDING",
                "recorded qualification belongs to another candidate",
            ));
        }
    }
    Ok(())
}

fn validate_text_fields(d: &ChangeDecision) -> Result<(), TransitionError> {
    for dimension in [
        &d.semantic_enforcement,
        &d.assurance_requirements,
        &d.protected_authority,
        &d.host_coverage,
    ] {
        if !super::valid_text(&dimension.state)
            || dimension.reasons.len() > crate::state_governance::MAX_TRANSITION_RECORDS
            || dimension.reasons.iter().any(|s| !super::valid_text(s))
        {
            return Err(error(
                "INVALID_INPUT",
                "decision text exceeds its public schema admission",
            ));
        }
    }
    if d.authorization_references.len() > 64
        || d.authorization_references
            .iter()
            .any(|s| !super::valid_text(s))
    {
        return Err(error(
            "RESOURCE_LIMIT",
            "authorization citations exceed existing context admission",
        ));
    }
    Ok(())
}
