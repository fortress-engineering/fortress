//! Distributed Function Contract v3/v4 loading and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program_semantics::{ExecutableSymbol, ProgramSemanticModel, ProgramType, SemanticType};

use super::domain::{IntegerInterval, SemanticDomain};

/// Canonical Function Contract v4 schema identity.
pub const FUNCTION_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v4:function-contracts";
/// Canonical Function Contract schema version.
pub const FUNCTION_CONTRACT_SCHEMA_VERSION: u16 = 4;
/// Backward-compatible Function Contract v3 schema identity.
pub const LEGACY_FUNCTION_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v3:function-contracts";
/// Backward-compatible Function Contract schema version.
pub const LEGACY_FUNCTION_CONTRACT_SCHEMA_VERSION: u16 = 3;

/// One snapshot-bound authored Function Contract source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionContractSource {
    module_id: String,
    path: String,
    source: String,
}

impl FunctionContractSource {
    /// Creates one source attributed to its physical Module owner.
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

    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Authored semantic domain syntax resolved against one PSM static type.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DomainSpecification {
    /// Entire static type domain.
    Top,
    /// Impossible domain.
    Bottom,
    /// Finite Boolean subset.
    Boolean {
        /// Sorted included Boolean states.
        include: Vec<bool>,
    },
    /// Inclusive integer interval and optional excluded values.
    IntegerInterval {
        /// Inclusive lower bound.
        min: i64,
        /// Inclusive upper bound.
        max: i64,
        /// Sorted finite exclusions.
        #[serde(default)]
        exclude: Vec<i64>,
    },
    /// Allowed optional wrapper states.
    OptionStates {
        /// Sorted subset of `none` and `some`.
        include: Vec<String>,
        /// Optional refinement of a `Some` payload.
        some: Option<Box<DomainSpecification>>,
    },
    /// Allowed result wrapper states.
    ResultStates {
        /// Sorted subset of `ok` and `err`.
        include: Vec<String>,
        /// Optional success-payload refinement.
        ok: Option<Box<DomainSpecification>>,
        /// Optional error-payload refinement.
        err: Option<Box<DomainSpecification>>,
    },
    /// Allowed nominal enum variants.
    EnumVariants {
        /// Sorted canonical variant identities.
        include: Vec<String>,
    },
    /// Component-wise product refinement.
    Tuple {
        /// Ordered component domains.
        elements: Vec<DomainSpecification>,
    },
}

/// One parameter precondition.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionRequirement {
    parameter: String,
    domain: DomainSpecification,
}

/// One return postcondition.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionGuarantee {
    #[serde(rename = "return")]
    is_return: bool,
    domain: DomainSpecification,
}

/// One function-level typestate obligation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionStateObligation {
    target: String,
    state: String,
}

impl FunctionStateObligation {
    /// Returns `self`, `return`, or a mutable parameter identity.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the stable authored state identity.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }
}

/// Closed effect vocabulary shared by observed effects and Function Contract policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum FunctionEffect {
    /// Read state through the current receiver.
    #[serde(rename = "receiver_state_read")]
    ReceiverStateRead,
    /// Mutate state through the current receiver.
    #[serde(rename = "receiver_state_write")]
    ReceiverStateWrite,
    /// Read a directly owned non-receiver nominal value.
    #[serde(rename = "owned_state_read")]
    OwnedStateRead,
    /// Mutate a directly owned non-receiver nominal value.
    #[serde(rename = "owned_state_write")]
    OwnedStateWrite,
    /// Invoke an external operation whose resource semantics remain unclassified.
    #[serde(rename = "external_interaction")]
    ExternalInteraction,
    /// Read filesystem-backed content or metadata.
    #[serde(rename = "filesystem.read")]
    FilesystemRead,
    /// Mutate filesystem-backed content, metadata, or namespace state.
    #[serde(rename = "filesystem.write")]
    FilesystemWrite,
    /// Initiate an outbound network connection.
    #[serde(rename = "network.connect")]
    NetworkConnect,
    /// Bind, listen, or accept through a server network endpoint.
    #[serde(rename = "network.listen")]
    NetworkListen,
    /// Transfer bytes through a semantically identified network endpoint.
    #[serde(rename = "network.io")]
    NetworkIo,
    /// Spawn or execute an operating-system process.
    #[serde(rename = "process.spawn")]
    ProcessSpawn,
    /// Read process environment authority.
    #[serde(rename = "environment.read")]
    EnvironmentRead,
    /// Mutate process environment authority.
    #[serde(rename = "environment.write")]
    EnvironmentWrite,
    /// Read wall or system time.
    #[serde(rename = "time.wall_read")]
    TimeWallRead,
    /// Read a monotonic clock or elapsed monotonic time.
    #[serde(rename = "time.monotonic_read")]
    TimeMonotonicRead,
    /// Consume nondeterministic random input from a semantically identified provider.
    #[serde(rename = "random.read")]
    RandomRead,
    /// Reach a supported panic operation.
    #[serde(rename = "may_panic")]
    MayPanic,
    /// Execute an unsafe function/body region.
    #[serde(rename = "unsafe_execution")]
    UnsafeExecution,
}

impl FunctionEffect {
    /// Returns the stable policy and evidence identity.
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ReceiverStateRead => "receiver_state_read",
            Self::ReceiverStateWrite => "receiver_state_write",
            Self::OwnedStateRead => "owned_state_read",
            Self::OwnedStateWrite => "owned_state_write",
            Self::ExternalInteraction => "external_interaction",
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::NetworkConnect => "network.connect",
            Self::NetworkListen => "network.listen",
            Self::NetworkIo => "network.io",
            Self::ProcessSpawn => "process.spawn",
            Self::EnvironmentRead => "environment.read",
            Self::EnvironmentWrite => "environment.write",
            Self::TimeWallRead => "time.wall_read",
            Self::TimeMonotonicRead => "time.monotonic_read",
            Self::RandomRead => "random.read",
            Self::MayPanic => "may_panic",
            Self::UnsafeExecution => "unsafe_execution",
        }
    }

    /// Returns whether Function Contract v3 can author this exact effect identity.
    #[must_use]
    pub const fn is_legacy_v3(self) -> bool {
        matches!(
            self,
            Self::ReceiverStateRead
                | Self::ReceiverStateWrite
                | Self::OwnedStateRead
                | Self::OwnedStateWrite
                | Self::ExternalInteraction
                | Self::MayPanic
                | Self::UnsafeExecution
        )
    }

    /// Returns whether the legacy external-interaction umbrella covers this effect.
    #[must_use]
    pub const fn is_external_resource_effect(self) -> bool {
        matches!(
            self,
            Self::ExternalInteraction
                | Self::FilesystemRead
                | Self::FilesystemWrite
                | Self::NetworkConnect
                | Self::NetworkListen
                | Self::NetworkIo
                | Self::ProcessSpawn
                | Self::EnvironmentRead
                | Self::EnvironmentWrite
                | Self::TimeWallRead
                | Self::TimeMonotonicRead
                | Self::RandomRead
        )
    }

    /// Returns whether this authored effect identity covers an observed effect.
    ///
    /// The legacy `external_interaction` identity is an explicit umbrella over
    /// refined external-resource effects. No other effect gains umbrella semantics.
    #[must_use]
    pub const fn policy_covers(self, observed: Self) -> bool {
        self as u8 == observed as u8
            || (matches!(self, Self::ExternalInteraction) && observed.is_external_resource_effect())
    }
}

/// Optional authored restriction over supported direct and transitive effects.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionEffectPolicy {
    allowed: Vec<FunctionEffect>,
}

/// Exact executable interface target for one information-flow declaration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InformationFlowTarget {
    /// One named function parameter.
    Parameter {
        /// Stable source parameter identity.
        name: String,
    },
    /// The function receiver.
    Receiver,
    /// The function result.
    Return,
}

impl InformationFlowTarget {
    /// Returns a deterministic interface-local identity.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Parameter { name } => format!("parameter:{name}"),
            Self::Receiver => "receiver:self".into(),
            Self::Return => "return:return".into(),
        }
    }

    /// Returns the parameter name when this target is a parameter.
    #[must_use]
    pub fn parameter(&self) -> Option<&str> {
        match self {
            Self::Parameter { name } => Some(name),
            Self::Receiver | Self::Return => None,
        }
    }
}

/// One authoritative classification introduced at a function boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationFlowSource {
    target: InformationFlowTarget,
    facet: String,
    level: String,
}

impl InformationFlowSource {
    /// Returns the classified interface target.
    #[must_use]
    pub const fn target(&self) -> &InformationFlowTarget {
        &self.target
    }

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

/// One information-flow constraint imposed on an interface target.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationFlowRequirement {
    target: InformationFlowTarget,
    facet: String,
    #[serde(default)]
    minimum: Option<String>,
    #[serde(default)]
    maximum: Option<String>,
}

impl InformationFlowRequirement {
    /// Returns the constrained interface target.
    #[must_use]
    pub const fn target(&self) -> &InformationFlowTarget {
        &self.target
    }

    /// Returns the project-defined facet identity.
    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    /// Returns the inclusive lower bound when authored.
    #[must_use]
    pub fn minimum(&self) -> Option<&str> {
        self.minimum.as_deref()
    }

    /// Returns the inclusive upper bound when authored.
    #[must_use]
    pub fn maximum(&self) -> Option<&str> {
        self.maximum.as_deref()
    }
}

/// One explicit output classification promise.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationFlowEnsure {
    target: InformationFlowTarget,
    facet: String,
    level: String,
}

impl InformationFlowEnsure {
    /// Returns the promised target.
    #[must_use]
    pub const fn target(&self) -> &InformationFlowTarget {
        &self.target
    }

    /// Returns the facet identity.
    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    /// Returns the promised level.
    #[must_use]
    pub fn level(&self) -> &str {
        &self.level
    }
}

/// Security-sensitive explicit label transition authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InformationFlowTransformKind {
    /// Explicitly increases integrity/trust.
    Endorsement,
    /// Explicitly decreases confidentiality restriction.
    Declassification,
}

/// One explicit trusted information-flow transition.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationFlowTransform {
    kind: InformationFlowTransformKind,
    input: InformationFlowTarget,
    output: InformationFlowTarget,
    facet: String,
    from: String,
    to: String,
}

impl InformationFlowTransform {
    /// Returns the trusted-transition class.
    #[must_use]
    pub const fn kind(&self) -> InformationFlowTransformKind {
        self.kind
    }

    /// Returns the transition input target.
    #[must_use]
    pub const fn input(&self) -> &InformationFlowTarget {
        &self.input
    }

    /// Returns the transition output target.
    #[must_use]
    pub const fn output(&self) -> &InformationFlowTarget {
        &self.output
    }

    /// Returns the facet identity.
    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    /// Returns the admitted input level.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Returns the asserted output level.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }
}

/// Optional information-flow intent attached to one executable symbol.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionInformationFlow {
    sources: Vec<InformationFlowSource>,
    requires: Vec<InformationFlowRequirement>,
    ensures: Vec<InformationFlowEnsure>,
    transforms: Vec<InformationFlowTransform>,
}

impl FunctionInformationFlow {
    /// Returns authoritative source classifications.
    #[must_use]
    pub fn sources(&self) -> &[InformationFlowSource] {
        &self.sources
    }

    /// Returns interface sink constraints.
    #[must_use]
    pub fn requires(&self) -> &[InformationFlowRequirement] {
        &self.requires
    }

    /// Returns output classification promises.
    #[must_use]
    pub fn ensures(&self) -> &[InformationFlowEnsure] {
        &self.ensures
    }

    /// Returns explicit trusted transitions.
    #[must_use]
    pub fn transforms(&self) -> &[InformationFlowTransform] {
        &self.transforms
    }
}

impl FunctionEffectPolicy {
    /// Returns the sorted allowed effect set.
    #[must_use]
    pub fn allowed(&self) -> &[FunctionEffect] {
        &self.allowed
    }
}

/// One executable symbol's authored semantic intent.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionContract {
    symbol: String,
    requires: Vec<FunctionRequirement>,
    ensures: Vec<FunctionGuarantee>,
    #[serde(default)]
    state_requires: Vec<FunctionStateObligation>,
    #[serde(default)]
    state_ensures: Vec<FunctionStateObligation>,
    #[serde(default)]
    effects: Option<FunctionEffectPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    information_flow: Option<FunctionInformationFlow>,
}

impl FunctionContract {
    /// Returns the governed PSM symbol identity.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns authored parameter requirements.
    #[must_use]
    pub fn requires(&self) -> &[FunctionRequirement] {
        &self.requires
    }

    /// Returns the authored return guarantee when one exists.
    #[must_use]
    pub fn return_guarantee(&self) -> Option<&FunctionGuarantee> {
        self.ensures.first()
    }

    /// Returns authored state preconditions.
    #[must_use]
    pub fn state_requires(&self) -> &[FunctionStateObligation] {
        &self.state_requires
    }

    /// Returns authored state postconditions.
    #[must_use]
    pub fn state_ensures(&self) -> &[FunctionStateObligation] {
        &self.state_ensures
    }

    /// Returns the optional authored effect restriction.
    #[must_use]
    pub const fn effects(&self) -> Option<&FunctionEffectPolicy> {
        self.effects.as_ref()
    }

    /// Returns optional authored information-flow intent.
    #[must_use]
    pub const fn information_flow(&self) -> Option<&FunctionInformationFlow> {
        self.information_flow.as_ref()
    }
}

impl FunctionRequirement {
    /// Returns the parameter identity.
    #[must_use]
    pub fn parameter(&self) -> &str {
        &self.parameter
    }

    /// Returns the authored domain syntax.
    #[must_use]
    pub const fn domain(&self) -> &DomainSpecification {
        &self.domain
    }
}

impl FunctionGuarantee {
    /// Returns the authored return domain syntax.
    #[must_use]
    pub const fn domain(&self) -> &DomainSpecification {
        &self.domain
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionContractDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    functions: Vec<FunctionContract>,
}

/// A validated distributed Function Contract set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedFunctionContracts {
    contracts: BTreeMap<String, FunctionContract>,
    source_paths: Vec<String>,
    digest: String,
}

impl ResolvedFunctionContracts {
    /// Returns one contract by PSM symbol identity.
    #[must_use]
    pub fn get(&self, symbol: &str) -> Option<&FunctionContract> {
        self.contracts.get(symbol)
    }

    /// Returns contracts in deterministic symbol order.
    pub fn contracts(&self) -> impl Iterator<Item = &FunctionContract> {
        self.contracts.values()
    }

    /// Returns the content identity of canonical distributed sources.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the number of contracted executable symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    /// Returns whether no function contract is authored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

/// Loads and resolves distributed Function Contract v3/v4 sources against a PSM.
///
/// # Errors
///
/// Returns [`FunctionContractError`] for noncanonical JSON, unsupported schema,
/// foreign/unknown symbols, invalid parameter references, duplicate contracts,
/// or authored domains outside the corresponding static type.
pub fn load_function_contracts(
    psm: &ProgramSemanticModel,
    mut sources: Vec<FunctionContractSource>,
) -> Result<ResolvedFunctionContracts, FunctionContractError> {
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let types = psm
        .types()
        .iter()
        .map(|value| (value.id(), value))
        .collect::<BTreeMap<_, _>>();
    let mut contracts = BTreeMap::new();
    for source in &sources {
        let document: FunctionContractDocument =
            serde_json::from_str(&source.source).map_err(|error| {
                FunctionContractError::InvalidJson {
                    path: source.path.clone(),
                    detail: error.to_string(),
                }
            })?;
        if !supported_document_schema(&document) {
            return Err(FunctionContractError::UnsupportedSchema(
                source.path.clone(),
            ));
        }
        validate_effect_schema(&document, &source.path)?;
        let canonical = canonical_document(&document)?;
        if canonical != source.source {
            return Err(FunctionContractError::NonCanonical(source.path.clone()));
        }
        validate_sorted_unique_contracts(&document, &source.path)?;
        for contract in document.functions {
            let symbol = symbols.get(contract.symbol.as_str()).ok_or_else(|| {
                FunctionContractError::UnknownSymbol {
                    path: source.path.clone(),
                    symbol: contract.symbol.clone(),
                }
            })?;
            if symbol.fortress_module() != source.module_id {
                return Err(FunctionContractError::ForeignSymbol {
                    path: source.path.clone(),
                    symbol: contract.symbol.clone(),
                    owner: symbol.fortress_module().into(),
                    declaring_module: source.module_id.clone(),
                });
            }
            validate_contract_domains(&contract, symbol, &types, &source.path)?;
            if contracts
                .insert(contract.symbol.clone(), contract)
                .is_some()
            {
                return Err(FunctionContractError::DuplicateSymbol(source.path.clone()));
            }
        }
    }
    let source_paths = sources.iter().map(|source| source.path.clone()).collect();
    let digest = distributed_digest(&sources);
    Ok(ResolvedFunctionContracts {
        contracts,
        source_paths,
        digest,
    })
}

/// Formats one parseable Function Contract document into the exact canonical
/// bytes required by the contract gate.
///
/// # Errors
///
/// Returns [`FunctionContractError`] when `source` is not a Function Contract
/// v3/v4 JSON document or canonical serialization fails.
pub fn canonicalize_function_contract_json(
    path: &str,
    source: &str,
) -> Result<String, FunctionContractError> {
    let document: FunctionContractDocument =
        serde_json::from_str(source).map_err(|error| FunctionContractError::InvalidJson {
            path: path.into(),
            detail: error.to_string(),
        })?;
    if !supported_document_schema(&document) {
        return Err(FunctionContractError::UnsupportedSchema(path.into()));
    }
    validate_effect_schema(&document, path)?;
    canonical_document(&document)
}

fn supported_document_schema(document: &FunctionContractDocument) -> bool {
    (document.schema == FUNCTION_CONTRACT_SCHEMA
        && document.schema_version == FUNCTION_CONTRACT_SCHEMA_VERSION)
        || (document.schema == LEGACY_FUNCTION_CONTRACT_SCHEMA
            && document.schema_version == LEGACY_FUNCTION_CONTRACT_SCHEMA_VERSION)
}

fn validate_effect_schema(
    document: &FunctionContractDocument,
    path: &str,
) -> Result<(), FunctionContractError> {
    if document.schema_version != LEGACY_FUNCTION_CONTRACT_SCHEMA_VERSION {
        return Ok(());
    }
    let unsupported = document
        .functions
        .iter()
        .filter_map(|contract| contract.effects.as_ref())
        .flat_map(|policy| policy.allowed.iter().copied())
        .find(|effect| !effect.is_legacy_v3());
    if let Some(effect) = unsupported {
        return Err(FunctionContractError::EffectRequiresV4 {
            path: path.into(),
            effect: effect.stable_id().into(),
        });
    }
    Ok(())
}

/// Resolves one authored domain against its exact PSM static type.
///
/// # Errors
///
/// Returns a concise reason when the refinement is incompatible with the type.
pub fn resolve_domain(
    specification: &DomainSpecification,
    type_fact: &ProgramType,
) -> Result<SemanticDomain, String> {
    resolve_domain_for_semantic(specification, type_fact.id(), type_fact.semantic())
}

#[allow(clippy::too_many_lines)]
fn resolve_domain_for_semantic(
    specification: &DomainSpecification,
    type_id: &str,
    semantic: &SemanticType,
) -> Result<SemanticDomain, String> {
    let full = SemanticDomain::from_static_type(type_id, semantic);
    let domain = match specification {
        DomainSpecification::Top => full.clone(),
        DomainSpecification::Bottom => SemanticDomain::bottom(type_id),
        DomainSpecification::Boolean { include } if matches!(semantic, SemanticType::Bool) => {
            if !strictly_sorted_unique(include) {
                return Err("Boolean include values must be sorted and unique".into());
            }
            SemanticDomain::boolean(type_id, include.iter().copied())
        }
        DomainSpecification::IntegerInterval { min, max, exclude }
            if matches!(semantic, SemanticType::Integer { .. }) =>
        {
            if !strictly_sorted_unique(exclude) {
                return Err("integer exclusions must be sorted and unique".into());
            }
            let interval = IntegerInterval::new(i128::from(*min), i128::from(*max))
                .ok_or_else(|| "integer interval minimum exceeds maximum".to_owned())?;
            SemanticDomain::integer(type_id, [interval], exclude.iter().copied().map(i128::from))
        }
        DomainSpecification::OptionStates { include, some }
            if matches!(semantic, SemanticType::Option { .. }) =>
        {
            if !strictly_sorted_unique(include)
                || include
                    .iter()
                    .any(|state| !matches!(state.as_str(), "none" | "some"))
            {
                return Err("Option states must be a sorted unique subset of none/some".into());
            }
            let SemanticType::Option { value } = semantic else {
                unreachable!();
            };
            let payload_id = nested_type_id(value);
            let some_domain = if include.iter().any(|state| state == "some") {
                some.as_deref().map_or_else(
                    || Ok(SemanticDomain::from_static_type(&payload_id, value)),
                    |specification| resolve_domain_for_semantic(specification, &payload_id, value),
                )?
            } else {
                SemanticDomain::bottom(&payload_id)
            };
            SemanticDomain::Option {
                type_id: type_id.into(),
                none: include.iter().any(|state| state == "none"),
                some: Box::new(some_domain),
            }
        }
        DomainSpecification::ResultStates { include, ok, err }
            if matches!(semantic, SemanticType::Result { .. }) =>
        {
            if !strictly_sorted_unique(include)
                || include
                    .iter()
                    .any(|state| !matches!(state.as_str(), "err" | "ok"))
            {
                return Err("Result states must be a sorted unique subset of err/ok".into());
            }
            let SemanticType::Result { success, error } = semantic else {
                unreachable!();
            };
            let success_id = nested_type_id(success);
            let error_id = nested_type_id(error);
            let ok_domain = if include.iter().any(|state| state == "ok") {
                ok.as_deref().map_or_else(
                    || Ok(SemanticDomain::from_static_type(&success_id, success)),
                    |specification| {
                        resolve_domain_for_semantic(specification, &success_id, success)
                    },
                )?
            } else {
                SemanticDomain::bottom(&success_id)
            };
            let err_domain = if include.iter().any(|state| state == "err") {
                err.as_deref().map_or_else(
                    || Ok(SemanticDomain::from_static_type(&error_id, error)),
                    |specification| resolve_domain_for_semantic(specification, &error_id, error),
                )?
            } else {
                SemanticDomain::bottom(&error_id)
            };
            SemanticDomain::Result {
                type_id: type_id.into(),
                ok: Box::new(ok_domain),
                err: Box::new(err_domain),
            }
        }
        DomainSpecification::EnumVariants { include }
            if matches!(semantic, SemanticType::Named { .. }) =>
        {
            if include.is_empty() || !strictly_sorted_unique(include) {
                return Err("enum variants must be nonempty, sorted, and unique".into());
            }
            SemanticDomain::Enum {
                type_id: type_id.into(),
                variants: include.iter().map(|name| (name.clone(), None)).collect(),
            }
        }
        DomainSpecification::Tuple { elements }
            if matches!(semantic, SemanticType::Tuple { .. }) =>
        {
            let SemanticType::Tuple {
                elements: static_elements,
            } = semantic
            else {
                unreachable!();
            };
            if elements.len() != static_elements.len() {
                return Err("tuple domain arity differs from the static type".into());
            }
            SemanticDomain::Tuple {
                type_id: type_id.into(),
                elements: elements
                    .iter()
                    .zip(static_elements)
                    .map(|(specification, semantic)| {
                        resolve_domain_for_semantic(
                            specification,
                            &nested_type_id(semantic),
                            semantic,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }
        }
        _ => return Err("domain kind is incompatible with the PSM static type".into()),
    };
    if !domain.is_subset_of(&full) {
        return Err("authored domain is outside the PSM static type domain".into());
    }
    Ok(domain)
}

#[allow(clippy::too_many_lines)]
fn validate_contract_domains(
    contract: &FunctionContract,
    symbol: &ExecutableSymbol,
    types: &BTreeMap<&str, &ProgramType>,
    path: &str,
) -> Result<(), FunctionContractError> {
    let parameters = symbol
        .parameters()
        .iter()
        .map(|parameter| (parameter.name(), parameter))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for requirement in &contract.requires {
        if !seen.insert(requirement.parameter.as_str()) {
            return Err(FunctionContractError::DuplicateParameter {
                path: path.into(),
                symbol: contract.symbol.clone(),
                parameter: requirement.parameter.clone(),
            });
        }
        let parameter = parameters
            .get(requirement.parameter.as_str())
            .ok_or_else(|| FunctionContractError::UnknownParameter {
                path: path.into(),
                symbol: contract.symbol.clone(),
                parameter: requirement.parameter.clone(),
            })?;
        let type_fact = types
            .get(parameter.parameter_type().type_id())
            .ok_or_else(|| FunctionContractError::MissingType(path.into()))?;
        resolve_domain(&requirement.domain, type_fact).map_err(|detail| {
            FunctionContractError::InvalidDomain {
                path: path.into(),
                symbol: contract.symbol.clone(),
                target: requirement.parameter.clone(),
                detail,
            }
        })?;
    }
    if contract.ensures.len() > 1 || contract.ensures.iter().any(|value| !value.is_return) {
        return Err(FunctionContractError::InvalidReturnTarget(path.into()));
    }
    if let Some(guarantee) = contract.ensures.first() {
        let type_fact = types
            .get(symbol.return_type().type_id())
            .ok_or_else(|| FunctionContractError::MissingType(path.into()))?;
        resolve_domain(&guarantee.domain, type_fact).map_err(|detail| {
            FunctionContractError::InvalidDomain {
                path: path.into(),
                symbol: contract.symbol.clone(),
                target: "return".into(),
                detail,
            }
        })?;
    }
    for obligation in contract
        .state_requires
        .iter()
        .chain(&contract.state_ensures)
    {
        if !obligation.state.starts_with("STATE-") || obligation.state.len() <= "STATE-".len() {
            return Err(FunctionContractError::InvalidStateTarget {
                path: path.into(),
                symbol: contract.symbol.clone(),
                target: obligation.target.clone(),
                detail: "state identity must use the stable STATE-* vocabulary".into(),
            });
        }
        match obligation.target.as_str() {
            "self" if symbol.receiver().is_some() => {}
            "return" => {
                let return_fact = types
                    .get(symbol.return_type().type_id())
                    .ok_or_else(|| FunctionContractError::MissingType(path.into()))?;
                if !matches!(return_fact.semantic(), SemanticType::Named { .. }) {
                    return Err(FunctionContractError::InvalidStateTarget {
                        path: path.into(),
                        symbol: contract.symbol.clone(),
                        target: obligation.target.clone(),
                        detail: "return state requires a nominal return type".into(),
                    });
                }
            }
            parameter => {
                let Some(parameter) = parameters.get(parameter) else {
                    return Err(FunctionContractError::InvalidStateTarget {
                        path: path.into(),
                        symbol: contract.symbol.clone(),
                        target: obligation.target.clone(),
                        detail: "state target is neither self, return, nor a parameter".into(),
                    });
                };
                let type_fact = types
                    .get(parameter.parameter_type().type_id())
                    .ok_or_else(|| FunctionContractError::MissingType(path.into()))?;
                if !matches!(
                    type_fact.semantic(),
                    SemanticType::Reference { mutable: true, .. }
                ) {
                    return Err(FunctionContractError::InvalidStateTarget {
                        path: path.into(),
                        symbol: contract.symbol.clone(),
                        target: obligation.target.clone(),
                        detail: "parameter state targets require an exact mutable reference".into(),
                    });
                }
            }
        }
    }
    if let Some(flow) = &contract.information_flow {
        for target in flow
            .sources
            .iter()
            .map(|item| &item.target)
            .chain(flow.requires.iter().map(|item| &item.target))
            .chain(flow.ensures.iter().map(|item| &item.target))
            .chain(
                flow.transforms
                    .iter()
                    .flat_map(|item| [&item.input, &item.output]),
            )
        {
            validate_information_flow_target(target, symbol, &parameters, path)?;
        }
        for requirement in &flow.requires {
            if requirement.minimum.is_some() == requirement.maximum.is_some() {
                return Err(FunctionContractError::InvalidInformationFlow {
                    path: path.into(),
                    symbol: contract.symbol.clone(),
                    detail: "each flow requirement must declare exactly one of minimum or maximum"
                        .into(),
                });
            }
        }
    }
    Ok(())
}

fn validate_information_flow_target(
    target: &InformationFlowTarget,
    symbol: &ExecutableSymbol,
    parameters: &BTreeMap<&str, &crate::program_semantics::ProgramParameter>,
    path: &str,
) -> Result<(), FunctionContractError> {
    match target {
        InformationFlowTarget::Parameter { name } if parameters.contains_key(name.as_str()) => {
            Ok(())
        }
        InformationFlowTarget::Parameter { name } => {
            Err(FunctionContractError::InvalidInformationFlow {
                path: path.into(),
                symbol: symbol.id().into(),
                detail: format!("unknown information-flow parameter `{name}`"),
            })
        }
        InformationFlowTarget::Receiver if symbol.receiver().is_some() => Ok(()),
        InformationFlowTarget::Receiver => Err(FunctionContractError::InvalidInformationFlow {
            path: path.into(),
            symbol: symbol.id().into(),
            detail: "receiver target requires a method receiver".into(),
        }),
        InformationFlowTarget::Return => Ok(()),
    }
}

fn validate_sorted_unique_contracts(
    document: &FunctionContractDocument,
    path: &str,
) -> Result<(), FunctionContractError> {
    if !document
        .functions
        .windows(2)
        .all(|pair| pair[0].symbol < pair[1].symbol)
    {
        return Err(FunctionContractError::NonCanonicalOrder(path.into()));
    }
    for contract in &document.functions {
        if !contract
            .requires
            .windows(2)
            .all(|pair| pair[0].parameter < pair[1].parameter)
        {
            return Err(FunctionContractError::NonCanonicalOrder(path.into()));
        }
        if !contract
            .state_requires
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            || !contract
                .state_ensures
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || contract
                .effects
                .as_ref()
                .is_some_and(|policy| !policy.allowed.windows(2).all(|pair| pair[0] < pair[1]))
        {
            return Err(FunctionContractError::NonCanonicalOrder(path.into()));
        }
        if let Some(flow) = &contract.information_flow
            && (!strictly_sorted_unique(&flow.sources)
                || !strictly_sorted_unique(&flow.requires)
                || !strictly_sorted_unique(&flow.ensures)
                || !strictly_sorted_unique(&flow.transforms))
        {
            return Err(FunctionContractError::NonCanonicalOrder(path.into()));
        }
    }
    Ok(())
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_document(
    document: &FunctionContractDocument,
) -> Result<String, FunctionContractError> {
    let mut canonical = serde_json::to_string_pretty(document)
        .map_err(|error| FunctionContractError::Serialization(error.to_string()))?;
    canonical.push('\n');
    Ok(canonical)
}

fn distributed_digest(sources: &[FunctionContractSource]) -> String {
    let mut hasher = Sha256::new();
    for source in sources {
        update_digest(&mut hasher, source.module_id.as_bytes());
        update_digest(&mut hasher, source.path.as_bytes());
        update_digest(&mut hasher, source.source.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn update_digest(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn nested_type_id(semantic: &SemanticType) -> String {
    let bytes = serde_json::to_vec(semantic).expect("semantic type identity is serializable");
    format!("type:sha256:{:x}", Sha256::digest(bytes))
}

/// Explains why distributed Function Contract authority could not be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionContractError {
    /// JSON parsing failed.
    InvalidJson {
        /// Source path.
        path: String,
        /// Parser detail.
        detail: String,
    },
    /// Schema identity/version is not v1.
    UnsupportedSchema(String),
    /// A refined effect was authored under the legacy v3 vocabulary.
    EffectRequiresV4 {
        /// Source path.
        path: String,
        /// Refined effect identity.
        effect: String,
    },
    /// Valid JSON bytes are not canonical.
    NonCanonical(String),
    /// Canonical arrays are not sorted/unique.
    NonCanonicalOrder(String),
    /// A symbol is absent from the PSM.
    UnknownSymbol {
        /// Source path.
        path: String,
        /// Unknown PSM identity.
        symbol: String,
    },
    /// A contract targeted a symbol owned by another Module.
    ForeignSymbol {
        /// Source path.
        path: String,
        /// Targeted PSM identity.
        symbol: String,
        /// Physical owner Module.
        owner: String,
        /// Contract-declaring Module.
        declaring_module: String,
    },
    /// A symbol was contracted more than once.
    DuplicateSymbol(String),
    /// A parameter was contracted more than once.
    DuplicateParameter {
        /// Source path.
        path: String,
        /// Targeted PSM identity.
        symbol: String,
        /// Duplicate parameter.
        parameter: String,
    },
    /// A named parameter does not exist.
    UnknownParameter {
        /// Source path.
        path: String,
        /// Targeted PSM identity.
        symbol: String,
        /// Unknown parameter.
        parameter: String,
    },
    /// A PSM type fact was unexpectedly absent.
    MissingType(String),
    /// A domain is invalid for the target static type.
    InvalidDomain {
        /// Source path.
        path: String,
        /// Targeted PSM identity.
        symbol: String,
        /// Parameter or return target.
        target: String,
        /// Validation detail.
        detail: String,
    },
    /// Ensures did not name exactly one return target.
    InvalidReturnTarget(String),
    /// A state target or state identity is invalid for the executable interface.
    InvalidStateTarget {
        /// Source path.
        path: String,
        /// Targeted PSM symbol.
        symbol: String,
        /// Authored state target.
        target: String,
        /// Precise rejection reason.
        detail: String,
    },
    /// Information-flow declaration does not match the executable interface.
    InvalidInformationFlow {
        /// Source path.
        path: String,
        /// Targeted PSM symbol.
        symbol: String,
        /// Precise rejection reason.
        detail: String,
    },
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for FunctionContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => write!(
                formatter,
                "invalid Function Contract JSON `{path}`: {detail}"
            ),
            Self::UnsupportedSchema(path) => write!(
                formatter,
                "unsupported Function Contract schema in `{path}`"
            ),
            Self::EffectRequiresV4 { path, effect } => write!(
                formatter,
                "Function Contract `{path}` must use v4 to author refined effect `{effect}`"
            ),
            Self::NonCanonical(path) => write!(
                formatter,
                "Function Contract `{path}` is not canonical JSON"
            ),
            Self::NonCanonicalOrder(path) => write!(
                formatter,
                "Function Contract arrays are not canonical in `{path}`"
            ),
            Self::UnknownSymbol { path, symbol } => {
                write!(
                    formatter,
                    "Function Contract `{path}` targets unknown symbol `{symbol}`"
                )
            }
            Self::ForeignSymbol {
                path,
                symbol,
                owner,
                declaring_module,
            } => write!(
                formatter,
                "Function Contract `{path}` in `{declaring_module}` targets `{symbol}` owned by `{owner}`"
            ),
            Self::DuplicateSymbol(path) => {
                write!(
                    formatter,
                    "duplicate function contract encountered in `{path}`"
                )
            }
            Self::DuplicateParameter {
                path,
                symbol,
                parameter,
            } => write!(
                formatter,
                "Function Contract `{path}` duplicates parameter `{parameter}` for `{symbol}`"
            ),
            Self::UnknownParameter {
                path,
                symbol,
                parameter,
            } => write!(
                formatter,
                "Function Contract `{path}` names unknown parameter `{parameter}` for `{symbol}`"
            ),
            Self::MissingType(path) => {
                write!(formatter, "PSM type fact missing while loading `{path}`")
            }
            Self::InvalidDomain {
                path,
                symbol,
                target,
                detail,
            } => write!(
                formatter,
                "invalid domain for `{symbol}` `{target}` in `{path}`: {detail}"
            ),
            Self::InvalidReturnTarget(path) => {
                write!(
                    formatter,
                    "Function Contract `{path}` has invalid return guarantees"
                )
            }
            Self::InvalidStateTarget {
                path,
                symbol,
                target,
                detail,
            } => write!(
                formatter,
                "Function Contract `{path}` has invalid state target `{target}` for `{symbol}`: {detail}"
            ),
            Self::InvalidInformationFlow {
                path,
                symbol,
                detail,
            } => write!(
                formatter,
                "Function Contract `{path}` has invalid information flow for `{symbol}`: {detail}"
            ),
            Self::Serialization(detail) => {
                write!(
                    formatter,
                    "Function Contract serialization failed: {detail}"
                )
            }
        }
    }
}

impl Error for FunctionContractError {}
