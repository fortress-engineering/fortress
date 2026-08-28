//! Distributed State Contract v1 loading and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program_semantics::{NominalField, ProgramSemanticModel, ProgramType};
use crate::semantic_analysis::{DomainSpecification, SemanticDomain, resolve_domain};

/// Canonical State Contract v1 schema identity.
pub const STATE_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v1:state-contracts";
/// Canonical State Contract schema version.
pub const STATE_CONTRACT_SCHEMA_VERSION: u16 = 1;

/// One snapshot-bound State Contract source with physical Module provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateContractSource {
    module_id: String,
    path: String,
    source: String,
}

impl StateContractSource {
    /// Creates one distributed source.
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

    /// Returns its repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One direct-field predicate defining a modeled state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatePredicateSpecification {
    field: String,
    domain: DomainSpecification,
}

/// One stable modeled state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateSpecification {
    id: String,
    when: Vec<StatePredicateSpecification>,
}

/// State declaration for one locally owned nominal type.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateTypeSpecification {
    #[serde(rename = "type")]
    type_id: String,
    states: Vec<StateSpecification>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateContractDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    types: Vec<StateTypeSpecification>,
}

/// One validated field predicate resolved through Semantic Value Domains v1.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResolvedStatePredicate {
    field: String,
    field_type: String,
    domain: SemanticDomain,
}

impl ResolvedStatePredicate {
    /// Returns the direct field identity.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Returns the resolved field domain.
    #[must_use]
    pub const fn domain(&self) -> &SemanticDomain {
        &self.domain
    }
}

/// One validated nominal typestate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResolvedState {
    id: String,
    predicates: Vec<ResolvedStatePredicate>,
    source_path: String,
}

impl ResolvedState {
    /// Returns the stable state identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns direct-field admission predicates.
    #[must_use]
    pub fn predicates(&self) -> &[ResolvedStatePredicate] {
        &self.predicates
    }
}

/// Validated states for one governed nominal type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedStateType {
    nominal_type: String,
    module_id: String,
    states: Vec<ResolvedState>,
}

impl ResolvedStateType {
    /// Returns the PSM nominal type identity.
    #[must_use]
    pub fn nominal_type(&self) -> &str {
        &self.nominal_type
    }

    /// Returns modeled states in stable identity order.
    #[must_use]
    pub fn states(&self) -> &[ResolvedState] {
        &self.states
    }
}

/// Canonical resolved distributed State Contract set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedStateContracts {
    types: BTreeMap<String, ResolvedStateType>,
    state_owners: BTreeMap<String, String>,
    source_paths: Vec<String>,
    digest: String,
}

impl ResolvedStateContracts {
    /// Returns modeled states for one nominal type.
    #[must_use]
    pub fn get_type(&self, type_id: &str) -> Option<&ResolvedStateType> {
        self.types.get(type_id)
    }

    /// Resolves one stable state identity.
    #[must_use]
    pub fn get_state(&self, state_id: &str) -> Option<(&ResolvedStateType, &ResolvedState)> {
        let type_id = self.state_owners.get(state_id)?;
        let state_type = self.types.get(type_id)?;
        state_type
            .states
            .iter()
            .find(|state| state.id == state_id)
            .map(|state| (state_type, state))
    }

    /// Returns canonical state types.
    pub fn types(&self) -> impl Iterator<Item = &ResolvedStateType> {
        self.types.values()
    }

    /// Returns the distributed content identity.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Loads and validates all distributed State Contract sources.
///
/// # Errors
///
/// Rejects noncanonical JSON, foreign or unknown nominal types, unknown fields,
/// impossible predicates, duplicate identities, equivalent states, and
/// provably overlapping states.
pub fn load_state_contracts(
    psm: &ProgramSemanticModel,
    mut sources: Vec<StateContractSource>,
) -> Result<ResolvedStateContracts, StateContractError> {
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    let nominals = psm
        .nominal_types()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let types = psm
        .types()
        .iter()
        .map(|item| (item.id(), item))
        .collect::<BTreeMap<_, _>>();
    let mut resolved_types = BTreeMap::new();
    let mut state_owners = BTreeMap::new();
    for source in &sources {
        let document: StateContractDocument =
            serde_json::from_str(&source.source).map_err(|error| {
                StateContractError::InvalidJson {
                    path: source.path.clone(),
                    detail: error.to_string(),
                }
            })?;
        if document.schema != STATE_CONTRACT_SCHEMA
            || document.schema_version != STATE_CONTRACT_SCHEMA_VERSION
        {
            return Err(StateContractError::UnsupportedSchema(source.path.clone()));
        }
        if canonical_document(&document)? != source.source {
            return Err(StateContractError::NonCanonical(source.path.clone()));
        }
        validate_order(&document, &source.path)?;
        for declaration in document.types {
            let nominal = nominals.get(declaration.type_id.as_str()).ok_or_else(|| {
                StateContractError::UnknownType {
                    path: source.path.clone(),
                    type_id: declaration.type_id.clone(),
                }
            })?;
            if nominal.fortress_module() != source.module_id {
                return Err(StateContractError::ForeignType {
                    path: source.path.clone(),
                    type_id: declaration.type_id.clone(),
                    owner: nominal.fortress_module().into(),
                    declaring_module: source.module_id.clone(),
                });
            }
            if resolved_types.contains_key(&declaration.type_id) {
                return Err(StateContractError::DuplicateType(declaration.type_id));
            }
            let fields = nominal
                .fields()
                .iter()
                .map(|field| (field.name(), field))
                .collect::<BTreeMap<_, _>>();
            let mut states = Vec::new();
            for state in declaration.states {
                if state.id.len() <= 6 || !state.id.starts_with("STATE-") {
                    return Err(StateContractError::InvalidStateId(state.id));
                }
                if state_owners
                    .insert(state.id.clone(), declaration.type_id.clone())
                    .is_some()
                {
                    return Err(StateContractError::DuplicateState(state.id));
                }
                let predicates = resolve_predicates(&source.path, &state, &fields, &types)?;
                if states
                    .iter()
                    .any(|known: &ResolvedState| known.predicates == predicates)
                {
                    return Err(StateContractError::EquivalentStates {
                        path: source.path.clone(),
                        state: state.id,
                    });
                }
                states.push(ResolvedState {
                    id: state.id,
                    predicates,
                    source_path: source.path.clone(),
                });
            }
            reject_overlaps(&source.path, &states)?;
            resolved_types.insert(
                declaration.type_id.clone(),
                ResolvedStateType {
                    nominal_type: declaration.type_id,
                    module_id: source.module_id.clone(),
                    states,
                },
            );
        }
    }
    let digest = distributed_digest(&sources);
    Ok(ResolvedStateContracts {
        types: resolved_types,
        state_owners,
        source_paths: sources.iter().map(|source| source.path.clone()).collect(),
        digest,
    })
}

fn resolve_predicates(
    path: &str,
    state: &StateSpecification,
    fields: &BTreeMap<&str, &NominalField>,
    types: &BTreeMap<&str, &ProgramType>,
) -> Result<Vec<ResolvedStatePredicate>, StateContractError> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();
    for predicate in &state.when {
        if !seen.insert(predicate.field.as_str()) {
            return Err(StateContractError::DuplicateField {
                path: path.into(),
                state: state.id.clone(),
                field: predicate.field.clone(),
            });
        }
        let field = fields.get(predicate.field.as_str()).ok_or_else(|| {
            StateContractError::UnknownField {
                path: path.into(),
                type_id: state.id.clone(),
                field: predicate.field.clone(),
            }
        })?;
        let type_fact = types
            .get(field.field_type().type_id())
            .ok_or_else(|| StateContractError::MissingType(path.into()))?;
        let domain = resolve_domain(&predicate.domain, type_fact).map_err(|detail| {
            StateContractError::InvalidPredicate {
                path: path.into(),
                state: state.id.clone(),
                field: predicate.field.clone(),
                detail,
            }
        })?;
        if domain.is_bottom() {
            return Err(StateContractError::ImpossiblePredicate {
                path: path.into(),
                state: state.id.clone(),
                field: predicate.field.clone(),
            });
        }
        resolved.push(ResolvedStatePredicate {
            field: predicate.field.clone(),
            field_type: type_fact.id().into(),
            domain,
        });
    }
    Ok(resolved)
}

fn reject_overlaps(path: &str, states: &[ResolvedState]) -> Result<(), StateContractError> {
    for (index, left) in states.iter().enumerate() {
        for right in states.iter().skip(index + 1) {
            let left_fields = left
                .predicates
                .iter()
                .map(|item| (item.field.as_str(), &item.domain))
                .collect::<BTreeMap<_, _>>();
            let right_fields = right
                .predicates
                .iter()
                .map(|item| (item.field.as_str(), &item.domain))
                .collect::<BTreeMap<_, _>>();
            let provably_disjoint = left_fields.iter().any(|(field, left_domain)| {
                right_fields
                    .get(field)
                    .is_some_and(|right_domain| left_domain.intersection(right_domain).is_bottom())
            });
            if !provably_disjoint {
                return Err(StateContractError::OverlappingStates {
                    path: path.into(),
                    first: left.id.clone(),
                    second: right.id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_order(document: &StateContractDocument, path: &str) -> Result<(), StateContractError> {
    if !document
        .types
        .windows(2)
        .all(|pair| pair[0].type_id < pair[1].type_id)
    {
        return Err(StateContractError::NonCanonicalOrder(path.into()));
    }
    for declaration in &document.types {
        if declaration.states.is_empty()
            || !declaration
                .states
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
            || declaration.states.iter().any(|state| {
                state.when.is_empty()
                    || !state
                        .when
                        .windows(2)
                        .all(|pair| pair[0].field < pair[1].field)
            })
        {
            return Err(StateContractError::NonCanonicalOrder(path.into()));
        }
    }
    Ok(())
}

fn canonical_document(document: &StateContractDocument) -> Result<String, StateContractError> {
    let mut json = serde_json::to_string_pretty(document)
        .map_err(|error| StateContractError::Serialization(error.to_string()))?;
    json.push('\n');
    Ok(json)
}

/// Canonicalizes one parseable State Contract document.
///
/// # Errors
///
/// Returns an error for invalid JSON or serialization failure.
pub fn canonicalize_state_contract_json(
    path: &str,
    source: &str,
) -> Result<String, StateContractError> {
    let document =
        serde_json::from_str(source).map_err(|error| StateContractError::InvalidJson {
            path: path.into(),
            detail: error.to_string(),
        })?;
    canonical_document(&document)
}

fn distributed_digest(sources: &[StateContractSource]) -> String {
    let mut hasher = Sha256::new();
    for source in sources {
        for value in [&source.module_id, &source.path, &source.source] {
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Explains invalid distributed State Contract authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateContractError {
    /// JSON parsing failed.
    InvalidJson {
        /// Repository-relative contract path.
        path: String,
        /// Parser detail.
        detail: String,
    },
    /// Schema identity/version is unsupported.
    UnsupportedSchema(String),
    /// Valid JSON is not canonical.
    NonCanonical(String),
    /// Arrays are not strictly sorted and unique.
    NonCanonicalOrder(String),
    /// Nominal identity is unknown.
    UnknownType {
        /// Repository-relative contract path.
        path: String,
        /// Unknown nominal identity.
        type_id: String,
    },
    /// Nominal belongs to another Module.
    ForeignType {
        /// Repository-relative contract path.
        path: String,
        /// Foreign nominal identity.
        type_id: String,
        /// Physical owning Module.
        owner: String,
        /// Module declaring the invalid contract.
        declaring_module: String,
    },
    /// Nominal type was declared twice.
    DuplicateType(String),
    /// State identity is malformed.
    InvalidStateId(String),
    /// State identity is duplicated globally.
    DuplicateState(String),
    /// Direct field does not exist.
    UnknownField {
        /// Repository-relative contract path.
        path: String,
        /// Nominal identity.
        type_id: String,
        /// Unknown field name.
        field: String,
    },
    /// One state repeats a field predicate.
    DuplicateField {
        /// Repository-relative contract path.
        path: String,
        /// State identity.
        state: String,
        /// Repeated field name.
        field: String,
    },
    /// Static field type could not be resolved.
    MissingType(String),
    /// Predicate is incompatible with the field type.
    InvalidPredicate {
        /// Repository-relative contract path.
        path: String,
        /// State identity.
        state: String,
        /// Field name.
        field: String,
        /// Domain incompatibility detail.
        detail: String,
    },
    /// Predicate admits no value.
    ImpossiblePredicate {
        /// Repository-relative contract path.
        path: String,
        /// State identity.
        state: String,
        /// Field name.
        field: String,
    },
    /// Two state definitions are equivalent.
    EquivalentStates {
        /// Repository-relative contract path.
        path: String,
        /// Repeated state identity.
        state: String,
    },
    /// Two states provably overlap.
    OverlappingStates {
        /// Repository-relative contract path.
        path: String,
        /// First overlapping state.
        first: String,
        /// Second overlapping state.
        second: String,
    },
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for StateContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => write!(
                formatter,
                "State Contract `{path}` is invalid JSON: {detail}"
            ),
            Self::UnsupportedSchema(path) => {
                write!(formatter, "State Contract `{path}` does not use schema v1")
            }
            Self::NonCanonical(path) => {
                write!(formatter, "State Contract `{path}` is not canonical JSON")
            }
            Self::NonCanonicalOrder(path) => write!(
                formatter,
                "State Contract arrays are not canonical in `{path}`"
            ),
            Self::UnknownType { path, type_id } => write!(
                formatter,
                "State Contract `{path}` references unknown nominal type `{type_id}`"
            ),
            Self::ForeignType {
                path,
                type_id,
                owner,
                declaring_module,
            } => write!(
                formatter,
                "State Contract `{path}` in `{declaring_module}` targets `{type_id}` owned by `{owner}`"
            ),
            Self::DuplicateType(value) => write!(
                formatter,
                "State Contract nominal type `{value}` is duplicated"
            ),
            Self::InvalidStateId(value) => write!(
                formatter,
                "State Contract state identity `{value}` is invalid"
            ),
            Self::DuplicateState(value) => write!(
                formatter,
                "State Contract state identity `{value}` is duplicated"
            ),
            Self::UnknownField {
                path,
                type_id,
                field,
            } => write!(
                formatter,
                "State Contract `{path}` state/type `{type_id}` references unknown field `{field}`"
            ),
            Self::DuplicateField { path, state, field } => write!(
                formatter,
                "State Contract `{path}` state `{state}` repeats field `{field}`"
            ),
            Self::MissingType(path) => write!(
                formatter,
                "State Contract `{path}` references a missing PSM static type"
            ),
            Self::InvalidPredicate {
                path,
                state,
                field,
                detail,
            } => write!(
                formatter,
                "State Contract `{path}` state `{state}` field `{field}` is invalid: {detail}"
            ),
            Self::ImpossiblePredicate { path, state, field } => write!(
                formatter,
                "State Contract `{path}` state `{state}` field `{field}` is impossible"
            ),
            Self::EquivalentStates { path, state } => write!(
                formatter,
                "State Contract `{path}` state `{state}` duplicates an equivalent state"
            ),
            Self::OverlappingStates {
                path,
                first,
                second,
            } => write!(
                formatter,
                "State Contract `{path}` states `{first}` and `{second}` overlap"
            ),
            Self::Serialization(detail) => {
                write!(formatter, "State Contract serialization failed: {detail}")
            }
        }
    }
}

impl Error for StateContractError {}
