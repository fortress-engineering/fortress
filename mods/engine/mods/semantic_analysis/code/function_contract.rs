//! Distributed Function Contract v1 loading and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program_semantics::{ExecutableSymbol, ProgramSemanticModel, ProgramType, SemanticType};

use super::domain::{IntegerInterval, SemanticDomain};

/// Canonical Function Contract v1 schema identity.
pub const FUNCTION_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v1:function-contracts";
/// Canonical Function Contract schema version.
pub const FUNCTION_CONTRACT_SCHEMA_VERSION: u16 = 1;

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

/// One executable symbol's authored semantic intent.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionContract {
    symbol: String,
    requires: Vec<FunctionRequirement>,
    ensures: Vec<FunctionGuarantee>,
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

/// Loads and resolves distributed Function Contract v1 sources against a PSM.
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
        if document.schema != FUNCTION_CONTRACT_SCHEMA
            || document.schema_version != FUNCTION_CONTRACT_SCHEMA_VERSION
        {
            return Err(FunctionContractError::UnsupportedSchema(
                source.path.clone(),
            ));
        }
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
/// v1 JSON document or canonical serialization fails.
pub fn canonicalize_function_contract_json(
    path: &str,
    source: &str,
) -> Result<String, FunctionContractError> {
    let document: FunctionContractDocument =
        serde_json::from_str(source).map_err(|error| FunctionContractError::InvalidJson {
            path: path.into(),
            detail: error.to_string(),
        })?;
    canonical_document(&document)
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
    Ok(())
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
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for FunctionContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => {
                write!(
                    formatter,
                    "invalid Function Contract JSON `{path}`: {detail}"
                )
            }
            Self::UnsupportedSchema(path) => {
                write!(
                    formatter,
                    "unsupported Function Contract schema in `{path}`"
                )
            }
            Self::NonCanonical(path) => {
                write!(
                    formatter,
                    "Function Contract `{path}` is not canonical JSON"
                )
            }
            Self::NonCanonicalOrder(path) => {
                write!(
                    formatter,
                    "Function Contract arrays are not canonical in `{path}`"
                )
            }
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
