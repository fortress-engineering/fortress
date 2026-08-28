//! Distributed Environment Contract v1 loading and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::StableId;
use crate::information_flow::InformationFlowPolicy;
use crate::program_semantics::{ExecutableSymbol, ProgramSemanticModel};
use crate::semantic_analysis::{DomainSpecification, FunctionEffect, resolve_domain};
use crate::state_effect_analysis::ResolvedStateContracts;

/// Canonical Environment Contract v1 schema identity.
pub const ENVIRONMENT_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v1:environment-contracts";
/// Canonical Environment Contract schema version.
pub const ENVIRONMENT_CONTRACT_SCHEMA_VERSION: u16 = 1;

/// One snapshot-bound Environment Contract source and its physical Module owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentContractSource {
    module_id: String,
    path: String,
    source: String,
}

impl EnvironmentContractSource {
    /// Creates one distributed contract source.
    #[must_use]
    pub fn new(
        module_id: impl Into<String>,
        path: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            path: path.into(),
            source: source.into(),
        }
    }

    /// Returns the repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Whether an external operation completed in external reality.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletionSemantics {
    /// The external operation definitely completed.
    Completed,
    /// The external operation definitely did not complete.
    NotCompleted,
    /// The caller cannot know whether completion occurred.
    UnknownCompletion,
}

/// Number of externally delivered responses admitted by one outcome.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseCardinality {
    /// No response is delivered.
    NoResponse,
    /// Exactly one response is delivered.
    OneResponse,
    /// More than one response may be delivered.
    MultipleResponses,
}

/// Qualitative timing class for one admissible outcome.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimingSemantics {
    /// The outcome is delivered before the declared deadline.
    WithinDeadline,
    /// The outcome is delivered only after the declared deadline.
    AfterDeadline,
    /// No finite delivery deadline is promised.
    Unbounded,
}

/// Generic external result class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalResultClass {
    /// The requested external operation succeeded.
    Success,
    /// The external actor intentionally rejected the operation.
    Rejected,
    /// The operation produced a defined failure.
    Failure,
    /// A response was delivered but violated the declared result shape.
    Malformed,
    /// A declared resource was unavailable.
    ResourceUnavailable,
}

/// Authored retry policy for an external operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryPolicy {
    /// Retrying is forbidden.
    Never,
    /// Every declared retry is contractually safe.
    Safe,
    /// Only explicitly enumerated outcomes may be retried.
    Conditional,
    /// Retry safety is not established.
    Unknown,
}

/// External operation idempotency semantics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdempotencySemantics {
    /// Repetition preserves the operation's semantic effect.
    Idempotent,
    /// Repetition is safe only under a stable idempotency identity.
    IdempotentWithKey,
    /// Repetition may produce another semantic effect.
    NonIdempotent,
    /// Idempotency is not established.
    Unknown,
}

/// External delivery semantics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliverySemantics {
    /// The external actor delivers no outcome more than once.
    AtMostOnce,
    /// The external actor may redeliver until at least one delivery occurs.
    AtLeastOnce,
    /// Duplicate delivery is explicitly admissible.
    MayDuplicate,
}

/// Atomicity asserted for the declared environmental effect group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AtomicitySemantics {
    /// The environment contract asserts one indivisible effect group.
    Atomic,
    /// Declared effect steps can become independently durable.
    NonAtomic,
    /// No atomicity conclusion is available.
    Unknown,
}

/// Duplicate-delivery handling strategy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DuplicateStrategy {
    /// No supported duplicate handling is declared.
    None,
    /// The continuation is contractually idempotent.
    IdempotentHandler,
    /// A stable deduplication identity guards repeated delivery.
    DeduplicationKey,
    /// Duplicate safety is not established.
    Unknown,
}

/// Recovery behavior after a modeled interruption.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestartSemantics {
    /// Recovery returns a defined failure without rerunning the operation.
    Abort,
    /// Recovery resumes through a dedicated continuation.
    Continue,
    /// Recovery reruns the external operation.
    RetryOperation,
}

/// Generic resource class for an explicitly modeled unavailable-resource outcome.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Process memory allocation capacity.
    Memory,
    /// Durable or transient storage capacity.
    Storage,
    /// Worker/executor capacity.
    WorkerCapacity,
    /// Queue admission capacity.
    QueueCapacity,
}

/// One outcome-provided information-flow label.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeFlowLabel {
    facet: String,
    level: String,
}

impl OutcomeFlowLabel {
    /// Returns the project-defined facet identity.
    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    /// Returns the project-defined level identity.
    #[must_use]
    pub fn level(&self) -> &str {
        &self.level
    }
}

/// Exact supported continuation for one environmental outcome.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeHandling {
    continuation: String,
    terminal: bool,
    retry: bool,
    idempotency_key_parameter: Option<String>,
    duplicate_strategy: DuplicateStrategy,
}

impl OutcomeHandling {
    /// Returns the governed continuation symbol.
    #[must_use]
    pub fn continuation(&self) -> &str {
        &self.continuation
    }

    /// Returns whether the continuation yields a defined terminal result.
    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }

    /// Returns whether this continuation retries the operation.
    #[must_use]
    pub const fn retries(&self) -> bool {
        self.retry
    }

    /// Returns the retry/deduplication key parameter, if declared.
    #[must_use]
    pub fn idempotency_key_parameter(&self) -> Option<&str> {
        self.idempotency_key_parameter.as_deref()
    }

    /// Returns duplicate-delivery handling semantics.
    #[must_use]
    pub const fn duplicate_strategy(&self) -> DuplicateStrategy {
        self.duplicate_strategy
    }
}

/// One independently durable semantic effect step.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectStep {
    id: String,
    durable: bool,
}

impl EffectStep {
    /// Returns the contract-local step identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns whether interruption may expose the step durably.
    #[must_use]
    pub const fn durable(&self) -> bool {
        self.durable
    }
}

/// Explicit bounded recovery obligation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContract {
    handler: String,
    permitted_states: Vec<String>,
    forbidden_states: Vec<String>,
    restart: RestartSemantics,
    idempotency_key_parameter: Option<String>,
}

impl RecoveryContract {
    /// Returns the exact governed recovery continuation.
    #[must_use]
    pub fn handler(&self) -> &str {
        &self.handler
    }

    /// Returns states permitted after restart/recovery.
    #[must_use]
    pub fn permitted_states(&self) -> &[String] {
        &self.permitted_states
    }

    /// Returns states forbidden after restart/recovery.
    #[must_use]
    pub fn forbidden_states(&self) -> &[String] {
        &self.forbidden_states
    }

    /// Returns restart behavior.
    #[must_use]
    pub const fn restart(&self) -> RestartSemantics {
        self.restart
    }

    /// Returns the restart idempotency key parameter, if declared.
    #[must_use]
    pub fn idempotency_key_parameter(&self) -> Option<&str> {
        self.idempotency_key_parameter.as_deref()
    }
}

/// One admissible nondeterministic external outcome.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOutcome {
    id: String,
    completion: CompletionSemantics,
    response: ResponseCardinality,
    timing: TimingSemantics,
    result: ExternalResultClass,
    domain: Option<DomainSpecification>,
    information_flow: Vec<OutcomeFlowLabel>,
    state: Option<String>,
    forbidden_effects: Vec<FunctionEffect>,
    resource: Option<ResourceKind>,
    handling: Option<OutcomeHandling>,
}

impl ExternalOutcome {
    /// Returns the stable outcome identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns completion certainty.
    #[must_use]
    pub const fn completion(&self) -> CompletionSemantics {
        self.completion
    }

    /// Returns response cardinality.
    #[must_use]
    pub const fn response(&self) -> ResponseCardinality {
        self.response
    }

    /// Returns qualitative timing.
    #[must_use]
    pub const fn timing(&self) -> TimingSemantics {
        self.timing
    }

    /// Returns the generic result class.
    #[must_use]
    pub const fn result(&self) -> ExternalResultClass {
        self.result
    }

    /// Returns the optional return-domain declaration.
    #[must_use]
    pub const fn domain(&self) -> Option<&DomainSpecification> {
        self.domain.as_ref()
    }

    /// Returns outcome-provided flow labels.
    #[must_use]
    pub fn information_flow(&self) -> &[OutcomeFlowLabel] {
        &self.information_flow
    }

    /// Returns the optional resulting typestate.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Returns effects forbidden under this outcome.
    #[must_use]
    pub fn forbidden_effects(&self) -> &[FunctionEffect] {
        &self.forbidden_effects
    }

    /// Returns an explicitly modeled unavailable resource.
    #[must_use]
    pub const fn resource(&self) -> Option<ResourceKind> {
        self.resource
    }

    /// Returns the exact declared continuation, if one exists.
    #[must_use]
    pub const fn handling(&self) -> Option<&OutcomeHandling> {
        self.handling.as_ref()
    }
}

/// One validated external/environmental operation declaration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentOperation {
    id: String,
    actor: String,
    boundary: String,
    retry_policy: RetryPolicy,
    retryable_outcomes: Vec<String>,
    idempotency: IdempotencySemantics,
    idempotency_key_parameter: Option<String>,
    delivery: DeliverySemantics,
    interruption_sensitive: bool,
    atomicity: AtomicitySemantics,
    effect_steps: Vec<EffectStep>,
    recovery: Option<RecoveryContract>,
    outcomes: Vec<ExternalOutcome>,
}

impl EnvironmentOperation {
    /// Returns the stable operation identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the project-defined external actor identity.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Returns the exact governed PSM boundary symbol.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Returns retry policy.
    #[must_use]
    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    /// Returns conditionally retryable outcome identities.
    #[must_use]
    pub fn retryable_outcomes(&self) -> &[String] {
        &self.retryable_outcomes
    }

    /// Returns idempotency semantics.
    #[must_use]
    pub const fn idempotency(&self) -> IdempotencySemantics {
        self.idempotency
    }

    /// Returns the boundary parameter carrying idempotency identity.
    #[must_use]
    pub fn idempotency_key_parameter(&self) -> Option<&str> {
        self.idempotency_key_parameter.as_deref()
    }

    /// Returns delivery semantics.
    #[must_use]
    pub const fn delivery(&self) -> DeliverySemantics {
        self.delivery
    }

    /// Returns whether bounded process interruption is modeled.
    #[must_use]
    pub const fn interruption_sensitive(&self) -> bool {
        self.interruption_sensitive
    }

    /// Returns environmental atomicity semantics.
    #[must_use]
    pub const fn atomicity(&self) -> AtomicitySemantics {
        self.atomicity
    }

    /// Returns independently meaningful effect steps.
    #[must_use]
    pub fn effect_steps(&self) -> &[EffectStep] {
        &self.effect_steps
    }

    /// Returns the optional recovery contract.
    #[must_use]
    pub const fn recovery(&self) -> Option<&RecoveryContract> {
        self.recovery.as_ref()
    }

    /// Returns all admissible outcomes.
    #[must_use]
    pub fn outcomes(&self) -> &[ExternalOutcome] {
        &self.outcomes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentContractDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    operations: Vec<EnvironmentOperation>,
}

/// Canonical resolved distributed Environment Contract set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedEnvironmentContracts {
    operations: Vec<EnvironmentOperation>,
    operation_sources: BTreeMap<String, String>,
    operation_modules: BTreeMap<String, String>,
    digest: String,
}

impl ResolvedEnvironmentContracts {
    /// Returns operations in stable identity order.
    #[must_use]
    pub fn operations(&self) -> &[EnvironmentOperation] {
        &self.operations
    }

    /// Returns the source path for an operation.
    #[must_use]
    pub fn source_path(&self, operation: &str) -> Option<&str> {
        self.operation_sources.get(operation).map(String::as_str)
    }

    /// Returns the declaring Module for an operation.
    #[must_use]
    pub fn module_id(&self, operation: &str) -> Option<&str> {
        self.operation_modules.get(operation).map(String::as_str)
    }

    /// Returns the deterministic distributed input digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Loads and validates distributed Environment Contract v1 authority.
///
/// # Errors
///
/// Rejects invalid or noncanonical JSON, foreign/unknown symbols, malformed
/// identities, invalid outcome domains or labels, unknown state identities,
/// and inconsistent retry/recovery declarations.
#[allow(clippy::too_many_lines)]
pub fn load_environment_contracts(
    psm: &ProgramSemanticModel,
    state_contracts: &ResolvedStateContracts,
    policy: &InformationFlowPolicy,
    mut sources: Vec<EnvironmentContractSource>,
) -> Result<ResolvedEnvironmentContracts, EnvironmentContractError> {
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let types = psm
        .types()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let mut operations = Vec::new();
    let mut operation_sources = BTreeMap::new();
    let mut operation_modules = BTreeMap::new();
    let mut outcome_ids = BTreeSet::new();
    for source in &sources {
        let document: EnvironmentContractDocument =
            serde_json::from_str(&source.source).map_err(|error| {
                EnvironmentContractError::InvalidJson {
                    path: source.path.clone(),
                    detail: error.to_string(),
                }
            })?;
        if document.schema != ENVIRONMENT_CONTRACT_SCHEMA
            || document.schema_version != ENVIRONMENT_CONTRACT_SCHEMA_VERSION
        {
            return Err(EnvironmentContractError::UnsupportedSchema(
                source.path.clone(),
            ));
        }
        if canonical_document(&document)? != source.source {
            return Err(EnvironmentContractError::NonCanonical(source.path.clone()));
        }
        validate_order(&document, &source.path)?;
        for operation in document.operations {
            validate_identity(&operation.id, "operation")?;
            if operation.actor.trim().is_empty() {
                return Err(EnvironmentContractError::EmptyActor(operation.id));
            }
            if operation_sources
                .insert(operation.id.clone(), source.path.clone())
                .is_some()
            {
                return Err(EnvironmentContractError::DuplicateOperation(operation.id));
            }
            operation_modules.insert(operation.id.clone(), source.module_id.clone());
            let boundary = resolve_local_symbol(
                &symbols,
                &source.module_id,
                &source.path,
                &operation.boundary,
            )?;
            validate_parameter(
                boundary,
                operation.idempotency_key_parameter.as_deref(),
                &operation.id,
            )?;
            let return_type = types
                .get(boundary.return_type().type_id())
                .ok_or_else(|| EnvironmentContractError::MissingReturnType(operation.id.clone()))?;
            let outcome_set = operation
                .outcomes
                .iter()
                .map(|outcome| outcome.id.as_str())
                .collect::<BTreeSet<_>>();
            for retryable in &operation.retryable_outcomes {
                if !outcome_set.contains(retryable.as_str()) {
                    return Err(EnvironmentContractError::UnknownRetryOutcome {
                        operation: operation.id.clone(),
                        outcome: retryable.clone(),
                    });
                }
            }
            if operation.retry_policy != RetryPolicy::Conditional
                && !operation.retryable_outcomes.is_empty()
            {
                return Err(EnvironmentContractError::UnexpectedRetryOutcomes(
                    operation.id.clone(),
                ));
            }
            if operation.idempotency == IdempotencySemantics::IdempotentWithKey
                && operation.idempotency_key_parameter.is_none()
            {
                return Err(EnvironmentContractError::MissingIdempotencyKey(
                    operation.id.clone(),
                ));
            }
            validate_recovery(&operation, source, &symbols, boundary, state_contracts)?;
            for outcome in &operation.outcomes {
                validate_identity(&outcome.id, "outcome")?;
                if !outcome_ids.insert(outcome.id.clone()) {
                    return Err(EnvironmentContractError::DuplicateOutcome(
                        outcome.id.clone(),
                    ));
                }
                if let Some(domain) = &outcome.domain {
                    let resolved = resolve_domain(domain, return_type).map_err(|detail| {
                        EnvironmentContractError::InvalidOutcomeDomain {
                            operation: operation.id.clone(),
                            outcome: outcome.id.clone(),
                            detail,
                        }
                    })?;
                    if resolved.is_bottom() {
                        return Err(EnvironmentContractError::ImpossibleOutcomeDomain {
                            operation: operation.id.clone(),
                            outcome: outcome.id.clone(),
                        });
                    }
                }
                validate_flow_labels(policy, &operation.id, outcome)?;
                if let Some(state) = &outcome.state
                    && state_contracts.get_state(state).is_none()
                {
                    return Err(EnvironmentContractError::UnknownState {
                        operation: operation.id.clone(),
                        state: state.clone(),
                    });
                }
                if outcome.result == ExternalResultClass::ResourceUnavailable
                    && outcome.resource.is_none()
                {
                    return Err(EnvironmentContractError::MissingResource {
                        operation: operation.id.clone(),
                        outcome: outcome.id.clone(),
                    });
                }
                if outcome.result != ExternalResultClass::ResourceUnavailable
                    && outcome.resource.is_some()
                {
                    return Err(EnvironmentContractError::UnexpectedResource {
                        operation: operation.id.clone(),
                        outcome: outcome.id.clone(),
                    });
                }
                if let Some(handling) = &outcome.handling {
                    let continuation = resolve_local_symbol(
                        &symbols,
                        &source.module_id,
                        &source.path,
                        &handling.continuation,
                    )?;
                    validate_parameter(
                        boundary,
                        handling.idempotency_key_parameter.as_deref(),
                        &operation.id,
                    )?;
                    if handling.duplicate_strategy == DuplicateStrategy::DeduplicationKey
                        && handling.idempotency_key_parameter.is_none()
                    {
                        return Err(EnvironmentContractError::MissingDuplicateKey {
                            operation: operation.id.clone(),
                            outcome: outcome.id.clone(),
                        });
                    }
                    let _ = continuation;
                }
            }
            operations.push(operation);
        }
    }
    operations.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(ResolvedEnvironmentContracts {
        operations,
        operation_sources,
        operation_modules,
        digest: distributed_digest(&sources),
    })
}

fn validate_identity(value: &str, kind: &'static str) -> Result<(), EnvironmentContractError> {
    StableId::parse(value).map_err(|error| EnvironmentContractError::InvalidIdentity {
        kind,
        value: value.into(),
        detail: error.to_string(),
    })?;
    Ok(())
}

fn resolve_local_symbol<'a>(
    symbols: &BTreeMap<&str, &'a ExecutableSymbol>,
    module_id: &str,
    path: &str,
    symbol_id: &str,
) -> Result<&'a ExecutableSymbol, EnvironmentContractError> {
    let symbol =
        symbols
            .get(symbol_id)
            .copied()
            .ok_or_else(|| EnvironmentContractError::UnknownSymbol {
                path: path.into(),
                symbol: symbol_id.into(),
            })?;
    if symbol.fortress_module() != module_id {
        return Err(EnvironmentContractError::ForeignSymbol {
            path: path.into(),
            symbol: symbol_id.into(),
            owner: symbol.fortress_module().into(),
            declaring_module: module_id.into(),
        });
    }
    Ok(symbol)
}

fn validate_parameter(
    symbol: &ExecutableSymbol,
    parameter: Option<&str>,
    operation: &str,
) -> Result<(), EnvironmentContractError> {
    if let Some(parameter) = parameter
        && !symbol
            .parameters()
            .iter()
            .any(|candidate| candidate.name() == parameter)
    {
        return Err(EnvironmentContractError::UnknownKeyParameter {
            operation: operation.into(),
            parameter: parameter.into(),
        });
    }
    Ok(())
}

fn validate_flow_labels(
    policy: &InformationFlowPolicy,
    operation: &str,
    outcome: &ExternalOutcome,
) -> Result<(), EnvironmentContractError> {
    for label in &outcome.information_flow {
        let facet =
            policy
                .facet(&label.facet)
                .ok_or_else(|| EnvironmentContractError::UnknownFacet {
                    operation: operation.into(),
                    outcome: outcome.id.clone(),
                    facet: label.facet.clone(),
                })?;
        if facet.index_of(&label.level).is_none() {
            return Err(EnvironmentContractError::UnknownLevel {
                operation: operation.into(),
                outcome: outcome.id.clone(),
                facet: label.facet.clone(),
                level: label.level.clone(),
            });
        }
    }
    Ok(())
}

fn validate_recovery(
    operation: &EnvironmentOperation,
    source: &EnvironmentContractSource,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
    boundary: &ExecutableSymbol,
    states: &ResolvedStateContracts,
) -> Result<(), EnvironmentContractError> {
    let Some(recovery) = &operation.recovery else {
        return Ok(());
    };
    let _handler =
        resolve_local_symbol(symbols, &source.module_id, &source.path, &recovery.handler)?;
    validate_parameter(
        boundary,
        recovery.idempotency_key_parameter.as_deref(),
        &operation.id,
    )?;
    for state in recovery
        .permitted_states
        .iter()
        .chain(&recovery.forbidden_states)
    {
        if states.get_state(state).is_none() {
            return Err(EnvironmentContractError::UnknownState {
                operation: operation.id.clone(),
                state: state.clone(),
            });
        }
    }
    if recovery
        .permitted_states
        .iter()
        .any(|state| recovery.forbidden_states.binary_search(state).is_ok())
    {
        return Err(EnvironmentContractError::ContradictoryRecoveryState(
            operation.id.clone(),
        ));
    }
    Ok(())
}

fn validate_order(
    document: &EnvironmentContractDocument,
    path: &str,
) -> Result<(), EnvironmentContractError> {
    if document.operations.is_empty()
        || !document
            .operations
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(EnvironmentContractError::NonCanonicalOrder(path.into()));
    }
    for operation in &document.operations {
        if operation.outcomes.is_empty()
            || !operation
                .outcomes
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
            || !strictly_sorted(&operation.retryable_outcomes)
            || !operation
                .effect_steps
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
        {
            return Err(EnvironmentContractError::NonCanonicalOrder(path.into()));
        }
        if let Some(recovery) = &operation.recovery
            && (!strictly_sorted(&recovery.permitted_states)
                || !strictly_sorted(&recovery.forbidden_states))
        {
            return Err(EnvironmentContractError::NonCanonicalOrder(path.into()));
        }
        for outcome in &operation.outcomes {
            if !outcome.information_flow.windows(2).all(|pair| {
                (pair[0].facet.as_str(), pair[0].level.as_str())
                    < (pair[1].facet.as_str(), pair[1].level.as_str())
            }) || !outcome
                .forbidden_effects
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            {
                return Err(EnvironmentContractError::NonCanonicalOrder(path.into()));
            }
        }
    }
    Ok(())
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_document(
    document: &EnvironmentContractDocument,
) -> Result<String, EnvironmentContractError> {
    let mut json = serde_json::to_string_pretty(document)
        .map_err(|error| EnvironmentContractError::Serialization(error.to_string()))?;
    json.push('\n');
    Ok(json)
}

/// Canonicalizes a parseable Environment Contract document.
///
/// # Errors
///
/// Returns an error for invalid JSON or serialization failure.
pub fn canonicalize_environment_contract_json(
    path: &str,
    source: &str,
) -> Result<String, EnvironmentContractError> {
    let document =
        serde_json::from_str(source).map_err(|error| EnvironmentContractError::InvalidJson {
            path: path.into(),
            detail: error.to_string(),
        })?;
    canonical_document(&document)
}

fn distributed_digest(sources: &[EnvironmentContractSource]) -> String {
    let mut hasher = Sha256::new();
    for source in sources {
        for value in [&source.module_id, &source.path, &source.source] {
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Explains invalid distributed Environment Contract authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvironmentContractError {
    /// JSON parsing failed.
    InvalidJson {
        /// Repository-relative path.
        path: String,
        /// Parser detail.
        detail: String,
    },
    /// Schema identity/version is unsupported.
    UnsupportedSchema(String),
    /// Parseable JSON is not canonical.
    NonCanonical(String),
    /// Canonical array ordering is violated.
    NonCanonicalOrder(String),
    /// A stable identity is malformed.
    InvalidIdentity {
        /// Identity role.
        kind: &'static str,
        /// Invalid identity.
        value: String,
        /// Stable-ID parser detail.
        detail: String,
    },
    /// One operation has no external actor.
    EmptyActor(String),
    /// Operation identity is duplicated.
    DuplicateOperation(String),
    /// Outcome identity is duplicated globally.
    DuplicateOutcome(String),
    /// A governed symbol does not exist.
    UnknownSymbol {
        /// Contract path.
        path: String,
        /// Missing PSM symbol.
        symbol: String,
    },
    /// A Module authored semantics for a foreign symbol.
    ForeignSymbol {
        /// Contract path.
        path: String,
        /// Target symbol.
        symbol: String,
        /// Physical symbol owner.
        owner: String,
        /// Contract Module.
        declaring_module: String,
    },
    /// Boundary return static type is absent.
    MissingReturnType(String),
    /// Outcome domain is incompatible with boundary return type.
    InvalidOutcomeDomain {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
        /// Domain resolution detail.
        detail: String,
    },
    /// Outcome domain is impossible.
    ImpossibleOutcomeDomain {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
    },
    /// Retry list references an unknown outcome.
    UnknownRetryOutcome {
        /// Operation identity.
        operation: String,
        /// Unknown outcome.
        outcome: String,
    },
    /// Non-conditional retry policy authored conditional outcomes.
    UnexpectedRetryOutcomes(String),
    /// Required idempotency key is absent.
    MissingIdempotencyKey(String),
    /// Key parameter is not present on the boundary.
    UnknownKeyParameter {
        /// Operation identity.
        operation: String,
        /// Unknown parameter.
        parameter: String,
    },
    /// Deduplication strategy lacks a key.
    MissingDuplicateKey {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
    },
    /// Outcome flow references an unknown facet.
    UnknownFacet {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
        /// Unknown facet.
        facet: String,
    },
    /// Outcome flow references an unknown level.
    UnknownLevel {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
        /// Facet identity.
        facet: String,
        /// Unknown level.
        level: String,
    },
    /// A referenced typestate does not exist.
    UnknownState {
        /// Operation identity.
        operation: String,
        /// Unknown state.
        state: String,
    },
    /// Resource-unavailable outcome omitted its resource.
    MissingResource {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
    },
    /// Non-resource outcome unexpectedly declares a resource.
    UnexpectedResource {
        /// Operation identity.
        operation: String,
        /// Outcome identity.
        outcome: String,
    },
    /// Recovery permits and forbids the same state.
    ContradictoryRecoveryState(String),
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for EnvironmentContractError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => {
                write!(
                    formatter,
                    "Environment Contract `{path}` is invalid JSON: {detail}"
                )
            }
            Self::UnsupportedSchema(path) => {
                write!(
                    formatter,
                    "Environment Contract `{path}` does not use schema v1"
                )
            }
            Self::NonCanonical(path) => {
                write!(
                    formatter,
                    "Environment Contract `{path}` is not canonical JSON"
                )
            }
            Self::NonCanonicalOrder(path) => {
                write!(
                    formatter,
                    "Environment Contract arrays are not canonical in `{path}`"
                )
            }
            Self::InvalidIdentity {
                kind,
                value,
                detail,
            } => {
                write!(
                    formatter,
                    "Environment Contract {kind} `{value}` is invalid: {detail}"
                )
            }
            Self::EmptyActor(operation) => {
                write!(
                    formatter,
                    "Environment operation `{operation}` has an empty actor"
                )
            }
            Self::DuplicateOperation(operation) => {
                write!(
                    formatter,
                    "Environment operation `{operation}` is duplicated"
                )
            }
            Self::DuplicateOutcome(outcome) => {
                write!(formatter, "Environment outcome `{outcome}` is duplicated")
            }
            Self::UnknownSymbol { path, symbol } => write!(
                formatter,
                "Environment Contract `{path}` references unknown symbol `{symbol}`"
            ),
            Self::ForeignSymbol {
                path,
                symbol,
                owner,
                declaring_module,
            } => write!(
                formatter,
                "Environment Contract `{path}` in `{declaring_module}` targets `{symbol}` owned by `{owner}`"
            ),
            Self::MissingReturnType(operation) => write!(
                formatter,
                "Environment operation `{operation}` has no resolved return type"
            ),
            Self::InvalidOutcomeDomain {
                operation,
                outcome,
                detail,
            } => write!(
                formatter,
                "Environment operation `{operation}` outcome `{outcome}` has an invalid domain: {detail}"
            ),
            Self::ImpossibleOutcomeDomain { operation, outcome } => write!(
                formatter,
                "Environment operation `{operation}` outcome `{outcome}` has an impossible domain"
            ),
            Self::UnknownRetryOutcome { operation, outcome } => write!(
                formatter,
                "Environment operation `{operation}` conditionally retries unknown outcome `{outcome}`"
            ),
            Self::UnexpectedRetryOutcomes(operation) => write!(
                formatter,
                "Environment operation `{operation}` declares retryable outcomes without CONDITIONAL policy"
            ),
            Self::MissingIdempotencyKey(operation) => write!(
                formatter,
                "Environment operation `{operation}` requires an idempotency key"
            ),
            Self::UnknownKeyParameter {
                operation,
                parameter,
            } => write!(
                formatter,
                "Environment operation `{operation}` references unknown key parameter `{parameter}`"
            ),
            Self::MissingDuplicateKey { operation, outcome } => write!(
                formatter,
                "Environment operation `{operation}` outcome `{outcome}` declares keyed deduplication without a key"
            ),
            Self::UnknownFacet {
                operation,
                outcome,
                facet,
            } => write!(
                formatter,
                "Environment operation `{operation}` outcome `{outcome}` references unknown facet `{facet}`"
            ),
            Self::UnknownLevel {
                operation,
                outcome,
                facet,
                level,
            } => write!(
                formatter,
                "Environment operation `{operation}` outcome `{outcome}` references unknown `{facet}` level `{level}`"
            ),
            Self::UnknownState { operation, state } => write!(
                formatter,
                "Environment operation `{operation}` references unknown state `{state}`"
            ),
            Self::MissingResource { operation, outcome } => write!(
                formatter,
                "Environment operation `{operation}` resource outcome `{outcome}` omits its resource"
            ),
            Self::UnexpectedResource { operation, outcome } => write!(
                formatter,
                "Environment operation `{operation}` non-resource outcome `{outcome}` declares a resource"
            ),
            Self::ContradictoryRecoveryState(operation) => write!(
                formatter,
                "Environment operation `{operation}` both permits and forbids one recovery state"
            ),
            Self::Serialization(detail) => {
                write!(
                    formatter,
                    "Environment Contract serialization failed: {detail}"
                )
            }
        }
    }
}

impl Error for EnvironmentContractError {}
