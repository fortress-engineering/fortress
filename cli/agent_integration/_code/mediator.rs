//! Local exact-operation mediation for independently trusted embeddings.

use fortress_core::development_governance::{
    ApplicationAuthorityKind, ApplicationAuthorityRecord, ApplicationAuthorization,
    DecisionDimension, GrantRequest, GrantValidation, GrantValidator, HostCoverage,
    TrustedBasePolicy, UnmediatedHost,
};
use fortress_core::heavy_admission::{DirectoryIdentity, assert_no_incomplete_migration};
use fortress_core::migration_adapter::{CanonicalMigrationAuthority, CanonicalMigrationEvaluator};
use fortress_core::migration_governance::{
    BoundaryPhase, MigrationApplication, MigrationAuthority, MigrationError, MigrationEvaluation,
    MigrationEvaluator, MigrationOperation, MigrationOptions, MigrationPlan, MigrationRecovery,
    MigrationRecoveryMode, MigrationServices, MutationBoundary, MutationObserver, apply_migration,
    preview_migration, recover_migration,
};
use fortress_core::observation::{CandidateChangeSet, SourceView};
use fortress_core::runtime_storage::MigrationStorage;
use fortress_core::state_governance::ComparisonContext;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The exact operation an independent host reviewer admits.
#[derive(Debug, Eq, PartialEq)]
pub enum ReviewedAction<'a> {
    /// Invoke Migration Governance on the exact reviewed plan.
    Apply,
    /// Reenter the recorded transaction with new authority and the original plan.
    Resume(&'a str),
    /// Ask Migration Governance to restore known original bytes.
    Rollback(&'a str),
}

/// Complete binding delivered privately to host-side review, never read from an agent.
pub struct ReviewBinding<'a> {
    /// Native machine-local repository identity from the retained directory handle.
    pub repository_key: &'a str,
    /// Independently configured issuer, actor and policy epoch identity.
    pub trust_ref: &'a str,
    /// Exact plan identity. It binds bytes, endpoints, authority, operations and requirements.
    pub plan_ref: &'a str,
    /// Exact invocation, including the transaction when recovering.
    pub action: ReviewedAction<'a>,
}

/// Process-local evidence returned by an independently authenticated review authority.
pub struct ClaimedReview {
    /// Identifier for rechecking the authority; this is provenance and must contain no credentials.
    pub review_ref: String,
    /// Explicit Unix seconds after which this attempt cannot continue.
    pub expires_at: u64,
}

/// A completed host invocation and its independent review provenance.
pub struct MediatedResult<T> {
    /// Verified application or recovery result from Migration Governance.
    pub actual: T,
    /// Report-only evidence of the review that permitted this invocation.
    pub review_provenance: ReviewProvenance,
}

/// Serializable explanation of a consumed host invocation. It carries no authority.
#[derive(serde::Serialize)]
pub struct ReviewProvenance {
    /// Exact consumed invocation review identity.
    pub review_ref: String,
    /// Independently selected trust context used for this invocation.
    pub trust_ref: String,
    /// Reviewed immutable migration plan.
    pub plan_ref: String,
    /// Mediated operation class.
    pub action: &'static str,
    /// Provenance semantics for offline readers.
    pub semantics: &'static str,
}

/// Trusted host-only port for explicit human or independently authorized invocation.
///
/// Implementations must isolate their code, credential store, actor and configuration
/// from candidate and agent processes. They must claim authorizations atomically once
/// across relevant sessions and processes. Returning candidate-authored or serialized
/// approval claims does not implement this contract.
pub trait InvocationAuthority {
    /// Reports the current independently selected trust identity.
    ///
    /// # Errors
    /// Returns a typed unavailable or invalid state when it cannot be checked.
    fn current_trust_ref(&self) -> Result<String, MigrationError>;

    /// Authenticates and claims one review of this exact binding. The review may
    /// not be claimed again after service restart, failure or recovery.
    ///
    /// # Errors
    /// Refuses missing, invalid, expired, stale, conflicting or already claimed reviews.
    fn claim(&self, binding: &ReviewBinding<'_>) -> Result<ClaimedReview, MigrationError>;

    /// Rechecks the claimed invocation and its external policy immediately before use.
    ///
    /// # Errors
    /// Refuses stale, revoked, failed or otherwise unverifiable authorization.
    fn recheck(
        &self,
        binding: &ReviewBinding<'_>,
        review: &ClaimedReview,
    ) -> Result<(), MigrationError>;
}

/// One externally selected, physically pinned local repository and its trusted ports.
///
/// This embedding supplies no public mutation RPC, and agent clients cannot select
/// a repository, policy, evaluator, verifier, approval or storage for this instance.
pub struct TrustedMediator<'host> {
    repository: PathBuf,
    directory: DirectoryIdentity,
    trust_ref: String,
    policy: &'host TrustedBasePolicy,
    invocation: &'host dyn InvocationAuthority,
    validator: &'host dyn GrantValidator,
    storage: &'host MigrationStorage,
}

impl<'host> TrustedMediator<'host> {
    /// Describes only this explicitly mediated route and its limitations.
    #[must_use]
    pub fn capability(&self) -> crate::agent_capabilities::HostCapability {
        crate::agent_capabilities::mediator()
    }

    /// Installs the trusted configuration supplied by the embedding.
    ///
    /// # Errors
    /// Refuses an ambiguous physical repository or invalid or changed trust context.
    pub fn from_host(
        repository: &Path,
        trust_ref: &str,
        policy: &'host TrustedBasePolicy,
        invocation: &'host dyn InvocationAuthority,
        validator: &'host dyn GrantValidator,
        storage: &'host MigrationStorage,
    ) -> Result<Self, MigrationError> {
        if !repository.is_absolute() || !digest(trust_ref) {
            return Err(failure(
                "INVALID_HOST_CONFIGURATION",
                "Use a pinned absolute repository and trust identity.",
            ));
        }
        let directory = DirectoryIdentity::capture(repository).map_err(io_error)?;
        let canonical = repository.canonicalize().map_err(io_error)?;
        if !directory.matches(&canonical).map_err(io_error)? {
            return Err(failure(
                "REPOSITORY_CHANGED",
                "The selected repository identity changed.",
            ));
        }
        let host = Self {
            repository: canonical,
            directory,
            trust_ref: trust_ref.into(),
            policy,
            invocation,
            validator,
            storage,
        };
        host.check_context()?;
        Ok(host)
    }

    /// Creates a reviewable plan through the canonical migration planner.
    ///
    /// This route handles previously governed repositories. First intent,
    /// finding maintenance and ungoverned operations keep their dedicated workflows.
    ///
    /// # Errors
    /// Refuses unavailable trust, incomplete migration, unsupported scope or input drift.
    pub fn preview(
        &self,
        operations: Vec<MigrationOperation>,
    ) -> Result<MigrationPlan, MigrationError> {
        self.check_context()?;
        assert_no_incomplete_migration(&self.repository).map_err(io_error)?;
        let evaluator = CanonicalMigrationEvaluator;
        let base = evaluator.observe(&self.repository)?;
        let authority = self.canonical(
            &UnmediatedHost,
            &fortress_core::development_governance::NoGrantValidator,
            None,
        );
        let preview = preview_migration(
            &evaluator,
            &authority,
            &base,
            operations,
            MigrationOptions::default(),
        )?;
        self.check_context()?;
        validate_scope(&preview.plan)?;
        Ok(preview.plan)
    }

    /// Claims exact external review and invokes the existing writer.
    ///
    /// # Errors
    /// Fails closed on stale inputs, cancellation, inconsistent review, missing
    /// protected grants, competing writes or before/after verification failure.
    pub fn apply(
        &self,
        plan: &MigrationPlan,
        cancelled: &AtomicBool,
    ) -> Result<MediatedResult<MigrationApplication>, MigrationError> {
        self.with_review(plan, ReviewedAction::Apply, cancelled, |services| {
            apply_migration(&self.repository, plan, services)
        })
    }

    /// Claims an independently reviewed recovery operation against an exact journal incarnation.
    ///
    /// # Errors
    /// Conflicting physical content and incomplete transaction premises remain failures.
    pub fn recover(
        &self,
        plan: &MigrationPlan,
        transaction: &str,
        mode: MigrationRecoveryMode,
        cancelled: &AtomicBool,
    ) -> Result<MediatedResult<MigrationRecovery>, MigrationError> {
        let action = match mode {
            MigrationRecoveryMode::Resume => ReviewedAction::Resume(transaction),
            MigrationRecoveryMode::Rollback => ReviewedAction::Rollback(transaction),
        };
        self.with_review(plan, action, cancelled, |services| {
            recover_migration(&self.repository, plan, transaction, mode, services)
        })
    }

    fn canonical<'a, H: HostCoverage, V: GrantValidator>(
        &'a self,
        coverage: &'a H,
        validator: &'a V,
        time: Option<u64>,
    ) -> CanonicalMigrationAuthority<'a, H, V> {
        CanonicalMigrationAuthority {
            policy: Some(self.policy),
            host: coverage,
            validator,
            evaluation_time: time,
            reviewed_initial_intent_ref: None,
            finding_proposal: None,
            identity_plan: None,
        }
    }

    fn check_context(&self) -> Result<(), MigrationError> {
        if !self.directory.matches(&self.repository).map_err(io_error)? {
            return Err(failure(
                "REPOSITORY_CHANGED",
                "Physical repository identity has changed.",
            ));
        }
        if self.invocation.current_trust_ref()? != self.trust_ref {
            return Err(failure(
                "TRUST_CONTEXT_CHANGED",
                "Trusted host policy or verifier configuration changed.",
            ));
        }
        Ok(())
    }

    fn with_review<T>(
        &self,
        plan: &MigrationPlan,
        action: ReviewedAction<'_>,
        cancelled: &AtomicBool,
        perform: impl FnOnce(
            &MigrationServices<
                '_,
                CanonicalMigrationEvaluator,
                Authority<'_, '_>,
                MigrationStorage,
                LiveReview<'_, '_>,
            >,
        ) -> Result<T, MigrationError>,
    ) -> Result<MediatedResult<T>, MigrationError> {
        check_cancelled(cancelled)?;
        validate_scope(plan)?;
        self.check_context()?;
        let binding = ReviewBinding {
            repository_key: self.directory.key(),
            trust_ref: &self.trust_ref,
            plan_ref: plan.digest(),
            action,
        };
        let review = self.invocation.claim(&binding)?;
        if !digest(&review.review_ref) {
            return Err(failure(
                "INVALID_REVIEW",
                "External review did not supply an admissible identity.",
            ));
        }
        let live = LiveReview {
            host: self,
            binding,
            review,
            cancelled,
            first_expiring_grant: Cell::new(None),
            grants: RefCell::new(Vec::new()),
        };
        live.check()?;
        let authority = Authority(&live);
        let actual = perform(&MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &authority,
            resources: self.storage,
            observer: &live,
        })?;
        Ok(MediatedResult {
            actual,
            review_provenance: ReviewProvenance {
                review_ref: live.review.review_ref.clone(),
                trust_ref: self.trust_ref.clone(),
                plan_ref: plan.digest().into(),
                action: match live.binding.action {
                    ReviewedAction::Apply => "APPLY",
                    ReviewedAction::Resume(_) => "RESUME",
                    ReviewedAction::Rollback(_) => "ROLLBACK",
                },
                semantics: "PROVENANCE_ONLY_NOT_TRANSFERABLE",
            },
        })
    }
}

fn validate_scope(plan: &MigrationPlan) -> Result<(), MigrationError> {
    if plan.authorization().kind != ApplicationAuthorityKind::Governed {
        return Err(failure(
            "UNSUPPORTED_MEDIATION_SCOPE",
            "This route requires an existing governing base and the canonical governed decision.",
        ));
    }
    Ok(())
}

struct LiveReview<'a, 'host> {
    host: &'a TrustedMediator<'host>,
    binding: ReviewBinding<'a>,
    review: ClaimedReview,
    cancelled: &'a AtomicBool,
    first_expiring_grant: Cell<Option<u64>>,
    grants: RefCell<Vec<(GrantRequest, String)>>,
}

impl LiveReview<'_, '_> {
    fn check(&self) -> Result<(), MigrationError> {
        check_cancelled(self.cancelled)?;
        self.host.check_context()?;
        self.host.invocation.recheck(&self.binding, &self.review)?;
        let current = now()?;
        if current >= self.review.expires_at
            || self
                .first_expiring_grant
                .get()
                .is_some_and(|deadline| current >= deadline)
        {
            return Err(failure(
                "AUTHORIZATION_EXPIRED",
                "Authorization expired before the next transactional action.",
            ));
        }
        check_cancelled(self.cancelled)
    }

    fn recheck_grants(&self) -> Result<(), MigrationError> {
        for (request, stamp) in self.grants.borrow().iter() {
            let mut current = request.clone();
            current.time = Some(now()?);
            let reply = self.host.validator.validate(&current);
            if grant_stamp(&reply).as_ref() != Some(stamp) {
                return Err(failure(
                    "GRANT_CHANGED",
                    "The exact scoped grant is no longer independently authenticated.",
                ));
            }
        }
        self.check()
    }
}

impl MutationObserver for LiveReview<'_, '_> {
    fn boundary(
        &self,
        _: u64,
        boundary: MutationBoundary,
        phase: BoundaryPhase,
    ) -> Result<(), MigrationError> {
        check_cancelled(self.cancelled)?;
        if phase == BoundaryPhase::Before
            && matches!(
                boundary,
                MutationBoundary::ActiveState
                    | MutationBoundary::Evacuate
                    | MutationBoundary::Install
                    | MutationBoundary::ParentInstall
                    | MutationBoundary::ReceiptPublication
            )
        {
            self.check()?;
            self.recheck_grants()?;
        }
        Ok(())
    }
}

impl GrantValidator for LiveReview<'_, '_> {
    fn validate(&self, request: &GrantRequest) -> GrantValidation {
        if self.check().is_err() {
            return GrantValidation::Unavailable;
        }
        let result = self.host.validator.validate(request);
        if let Some(stamp) = grant_stamp(&result) {
            self.grants.borrow_mut().push((request.clone(), stamp));
        }
        if let GrantValidation::Authenticated(assertion) = &result
            && let Some(deadline) = assertion.expires_at
        {
            if now().map_or(true, |current| current >= deadline) {
                return GrantValidation::Invalid;
            }
            let earliest = self
                .first_expiring_grant
                .get()
                .map_or(deadline, |old| old.min(deadline));
            self.first_expiring_grant.set(Some(earliest));
        }
        result
    }
}

fn grant_stamp(grant: &GrantValidation) -> Option<String> {
    let GrantValidation::Authenticated(assertion) = grant else {
        return None;
    };
    serde_json::to_vec(assertion)
        .ok()
        .map(|bytes| fortress_core::portable::digest(&bytes))
}

struct Mediated;
impl HostCoverage for Mediated {
    fn coverage(&self, _: &str) -> DecisionDimension {
        DecisionDimension {
            state: "MEDIATED".into(),
            reasons: vec!["Only this exact operation is routed through the trusted local migration writer. External provider protection and other write routes are UNVERIFIED.".into()],
        }
    }
}

struct Authority<'a, 'host>(&'a LiveReview<'a, 'host>);
impl MigrationAuthority for Authority<'_, '_> {
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorityRecord, MigrationError> {
        self.0.check()?;
        self.0
            .host
            .canonical(&UnmediatedHost, self.0, None)
            .preview(base, target, source, changes, context)
    }

    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        source: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<ApplicationAuthorization, MigrationError> {
        self.0.check()?;
        let permission = self
            .0
            .host
            .canonical(&Mediated, self.0, Some(now()?))
            .authorize(base, target, source, changes, context)?;
        if permission.record().kind != ApplicationAuthorityKind::Governed {
            return Err(failure(
                "UNSUPPORTED_MEDIATION_SCOPE",
                "The fresh decision lacks expected governing authority.",
            ));
        }
        self.0.check()?;
        Ok(permission)
    }
}

fn check_cancelled(token: &AtomicBool) -> Result<(), MigrationError> {
    if token.load(Ordering::Acquire) {
        return Err(failure("CANCELLED", "The host invocation was cancelled."));
    }
    Ok(())
}

fn digest(reference: &str) -> bool {
    reference.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn now() -> Result<u64, MigrationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            failure(
                "TRUST_CLOCK_UNAVAILABLE",
                "Current authorization time is unavailable.",
            )
        })
}

fn io_error(error: impl std::fmt::Display) -> MigrationError {
    failure("HOST_INPUT_ERROR", &error.to_string())
}

fn failure(code: &str, message: &str) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}
