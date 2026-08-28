//! Distributed Behavior Realization Contract v1 authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::behavioral_semantics::IntendedBehavioralFlowGraph;
use crate::contract_coherency::ContractCoherencyGraph;
use crate::environmental_semantics::EnvironmentalAnalysisModel;
use crate::information_flow::InformationFlowAnalysisModel;
use crate::program_semantics::ProgramSemanticModel;
use crate::semantic_analysis::{FunctionEffect, InformationFlowTransformKind};
use crate::state_effect_analysis::StateEffectAnalysisModel;

/// Canonical Behavior Realization Contract schema identity.
pub const BEHAVIOR_REALIZATION_CONTRACT_SCHEMA: &str =
    "urn:fortress:schema:v1:behavior-realization-contracts";
/// Canonical Behavior Realization Contract schema version.
pub const BEHAVIOR_REALIZATION_CONTRACT_SCHEMA_VERSION: u16 = 1;

/// One snapshot-bound distributed realization-contract document.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BehaviorRealizationContractSource {
    module_id: String,
    path: String,
    source: String,
}

impl BehaviorRealizationContractSource {
    /// Creates a contract source owned by its deepest physical Fortress Module.
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
}

/// Closed implementation anchor vocabulary for checkpoint realization.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BehaviorAnchor {
    /// Execution enters one exact governed PSM symbol.
    SymbolEntry {
        /// Stable PSM executable identity.
        symbol: String,
    },
    /// Execution returns normally from one exact governed PSM symbol.
    SymbolReturn {
        /// Stable PSM executable identity.
        symbol: String,
        /// Optional exact Boolean outcome refinement.
        #[serde(skip_serializing_if = "Option::is_none")]
        boolean: Option<bool>,
    },
    /// One exact supported nominal receiver-state transition.
    StateTransition {
        /// Stable PSM nominal type identity.
        nominal_type: String,
        /// Exact responsible executable symbol.
        symbol: String,
        /// Sorted admitted source states.
        from_states: Vec<String>,
        /// Sorted resulting states.
        to_states: Vec<String>,
    },
    /// One supported effect associated with an exact executable symbol.
    Effect {
        /// Closed Function Contract effect vocabulary.
        effect: FunctionEffect,
        /// Exact responsible executable symbol.
        symbol: String,
    },
    /// One exact declared information-flow trusted transition.
    InformationTransition {
        /// Endorsement or declassification.
        transition: InformationFlowTransformKind,
        /// Exact responsible executable symbol.
        symbol: String,
        /// Project-defined information facet.
        facet: String,
        /// Declared source level.
        from: String,
        /// Declared target level.
        to: String,
    },
    /// One exact admissible Environmental Semantics outcome.
    EnvironmentOutcome {
        /// Project-defined external operation identity.
        operation: String,
        /// Project-defined outcome identity.
        outcome: String,
    },
}

impl BehaviorAnchor {
    /// Returns the stable anchor kind used in event identities.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SymbolEntry { .. } => "symbol_entry",
            Self::SymbolReturn { .. } => "symbol_return",
            Self::StateTransition { .. } => "state_transition",
            Self::Effect { .. } => "effect",
            Self::InformationTransition { .. } => "information_transition",
            Self::EnvironmentOutcome { .. } => "environment_outcome",
        }
    }

    /// Returns a responsible symbol when the anchor is symbol-bound.
    #[must_use]
    pub fn symbol(&self) -> Option<&str> {
        match self {
            Self::SymbolEntry { symbol }
            | Self::SymbolReturn { symbol, .. }
            | Self::StateTransition { symbol, .. }
            | Self::Effect { symbol, .. }
            | Self::InformationTransition { symbol, .. } => Some(symbol),
            Self::EnvironmentOutcome { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointContract {
    checkpoint: String,
    anchors: Vec<BehaviorAnchor>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FeatureContract {
    feature: String,
    checkpoints: Vec<CheckpointContract>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContractDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    features: Vec<FeatureContract>,
}

/// One validated checkpoint binding with complete authored provenance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResolvedCheckpointRealization {
    feature: String,
    checkpoint: String,
    declaring_module: String,
    source_path: String,
    pointer: String,
    anchors: Vec<BehaviorAnchor>,
}

impl ResolvedCheckpointRealization {
    /// Returns the Feature identity.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }
    /// Returns the Intended BFG checkpoint identity.
    #[must_use]
    pub fn checkpoint(&self) -> &str {
        &self.checkpoint
    }
    /// Returns alternative exact semantic anchors.
    #[must_use]
    pub fn anchors(&self) -> &[BehaviorAnchor] {
        &self.anchors
    }
    /// Returns the declaring Module.
    #[must_use]
    pub fn declaring_module(&self) -> &str {
        &self.declaring_module
    }
    /// Returns the source document path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    /// Returns the canonical JSON pointer.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}

/// Canonical validated distributed Behavior Realization Contract set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedBehaviorRealizationContracts {
    features: Vec<String>,
    checkpoints: Vec<ResolvedCheckpointRealization>,
    digest: String,
}

impl ResolvedBehaviorRealizationContracts {
    /// Returns opted-in Features in stable order.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.features
    }
    /// Returns all complete checkpoint bindings.
    #[must_use]
    pub fn checkpoints(&self) -> &[ResolvedCheckpointRealization] {
        &self.checkpoints
    }
    /// Returns the deterministic distributed-authority digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Behavior Realization Contract validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BehaviorRealizationContractError {
    /// JSON syntax or typed decoding failed.
    InvalidJson {
        /// Source document path.
        path: String,
        /// Parser diagnostic.
        detail: String,
    },
    /// Schema identity or version is unsupported.
    UnsupportedSchema(String),
    /// Input bytes are not canonical JSON.
    NonCanonical(String),
    /// Feature identity does not exist in the Intended BFG.
    UnknownFeature(String),
    /// Checkpoint does not belong to the declared Feature.
    UnknownCheckpoint {
        /// Declared Feature.
        feature: String,
        /// Unknown or foreign checkpoint.
        checkpoint: String,
    },
    /// A Feature or checkpoint was authored more than once.
    DuplicateIdentity(String),
    /// Opt-in omitted at least one Intended checkpoint.
    MissingCheckpoint {
        /// Opted-in Feature.
        feature: String,
        /// Omitted Intended BFG checkpoint.
        checkpoint: String,
    },
    /// A checkpoint has no semantic realization alternative.
    EmptyAnchors(String),
    /// Arrays are not sorted and unique.
    NonCanonicalOrder(String),
    /// The contract's Module is outside the Feature-owner subtree.
    ForeignContractOwner {
        /// Feature whose ownership boundary is enforced.
        feature: String,
        /// Foreign declaring Module.
        module: String,
    },
    /// A symbol anchor is absent from the PSM.
    UnknownSymbol(String),
    /// A symbol lies outside the Feature-owner subtree.
    ForeignSymbol {
        /// Feature whose ownership boundary is enforced.
        feature: String,
        /// Foreign executable symbol.
        symbol: String,
    },
    /// A nominal type anchor is absent from the PSM.
    UnknownNominalType(String),
    /// A state transition has no nonempty canonical state sets.
    InvalidStateTransition(String),
    /// A requested effect is not established by State/Effect Analysis.
    UnknownEffect {
        /// Responsible executable symbol.
        symbol: String,
        /// Effect not established by canonical analysis.
        effect: FunctionEffect,
    },
    /// A requested state transition is not established by State/Effect Analysis.
    UnknownStateTransition(String),
    /// A requested security transition is not established by Information Flow.
    UnknownInformationTransition(String),
    /// A requested environmental outcome is absent.
    UnknownEnvironmentOutcome {
        /// External operation identity.
        operation: String,
        /// Missing outcome identity.
        outcome: String,
    },
    /// Canonical serialization failed.
    Serialization(String),
}

impl Display for BehaviorRealizationContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, detail } => write!(formatter, "invalid '{path}': {detail}"),
            Self::UnsupportedSchema(path) => write!(formatter, "unsupported schema in '{path}'"),
            Self::NonCanonical(path) => write!(formatter, "noncanonical JSON in '{path}'"),
            Self::UnknownFeature(value) => write!(formatter, "unknown Feature '{value}'"),
            Self::UnknownCheckpoint {
                feature,
                checkpoint,
            } => {
                write!(
                    formatter,
                    "checkpoint '{checkpoint}' is not in Feature '{feature}'"
                )
            }
            Self::DuplicateIdentity(value) => write!(formatter, "duplicate realization '{value}'"),
            Self::MissingCheckpoint {
                feature,
                checkpoint,
            } => write!(
                formatter,
                "opted-in Feature '{feature}' omits checkpoint '{checkpoint}'"
            ),
            Self::EmptyAnchors(value) => write!(formatter, "checkpoint '{value}' has no anchors"),
            Self::NonCanonicalOrder(value) => {
                write!(formatter, "noncanonical ordering at '{value}'")
            }
            Self::ForeignContractOwner { feature, module } => write!(
                formatter,
                "Module '{module}' cannot author realization for Feature '{feature}'"
            ),
            Self::UnknownSymbol(value) => write!(formatter, "unknown symbol '{value}'"),
            Self::ForeignSymbol { feature, symbol } => write!(
                formatter,
                "symbol '{symbol}' lies outside Feature '{feature}' ownership"
            ),
            Self::UnknownNominalType(value) => write!(formatter, "unknown nominal type '{value}'"),
            Self::InvalidStateTransition(value) => {
                write!(formatter, "invalid state transition anchor '{value}'")
            }
            Self::UnknownEffect { symbol, effect } => {
                write!(
                    formatter,
                    "effect '{effect:?}' is not established for '{symbol}'"
                )
            }
            Self::UnknownStateTransition(value) => {
                write!(
                    formatter,
                    "state transition is not established for '{value}'"
                )
            }
            Self::UnknownInformationTransition(value) => write!(
                formatter,
                "information transition is not established for '{value}'"
            ),
            Self::UnknownEnvironmentOutcome { operation, outcome } => write!(
                formatter,
                "environment outcome '{operation}/{outcome}' is absent"
            ),
            Self::Serialization(detail) => write!(formatter, "serialization failed: {detail}"),
        }
    }
}

impl Error for BehaviorRealizationContractError {}

/// Loads and validates the complete distributed realization authority.
///
/// # Errors
///
/// Rejects noncanonical documents, partial opt-in, foreign or unknown anchors,
/// and anchor claims not established by their canonical semantic authority.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn load_behavior_realization_contracts(
    ccg: &ContractCoherencyGraph,
    intended: &IntendedBehavioralFlowGraph,
    psm: &ProgramSemanticModel,
    state_effect: &StateEffectAnalysisModel,
    information_flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
    mut sources: Vec<BehaviorRealizationContractSource>,
) -> Result<ResolvedBehaviorRealizationContracts, BehaviorRealizationContractError> {
    sources.sort();
    let flows = intended
        .flows()
        .iter()
        .map(|flow| (flow.feature(), flow))
        .collect::<BTreeMap<_, _>>();
    let symbols = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol))
        .collect::<BTreeMap<_, _>>();
    let nominal_types = psm
        .nominal_types()
        .iter()
        .map(crate::program_semantics::NominalType::id)
        .collect::<BTreeSet<_>>();
    let module_paths = ccg.module_paths();
    let mut features = BTreeSet::new();
    let mut checkpoint_ids = BTreeSet::new();
    let mut checkpoints = Vec::new();
    for source in &sources {
        let document: ContractDocument = serde_json::from_str(&source.source).map_err(|error| {
            BehaviorRealizationContractError::InvalidJson {
                path: source.path.clone(),
                detail: error.to_string(),
            }
        })?;
        if document.schema != BEHAVIOR_REALIZATION_CONTRACT_SCHEMA
            || document.schema_version != BEHAVIOR_REALIZATION_CONTRACT_SCHEMA_VERSION
        {
            return Err(BehaviorRealizationContractError::UnsupportedSchema(
                source.path.clone(),
            ));
        }
        if canonical_document(&document)? != source.source {
            return Err(BehaviorRealizationContractError::NonCanonical(
                source.path.clone(),
            ));
        }
        ensure_sorted_unique(
            document
                .features
                .iter()
                .map(|feature| feature.feature.as_str()),
            &format!("{}/features", source.path),
        )?;
        for (feature_index, feature) in document.features.iter().enumerate() {
            let flow = flows.get(feature.feature.as_str()).ok_or_else(|| {
                BehaviorRealizationContractError::UnknownFeature(feature.feature.clone())
            })?;
            if !features.insert(feature.feature.clone()) {
                return Err(BehaviorRealizationContractError::DuplicateIdentity(
                    feature.feature.clone(),
                ));
            }
            validate_module_in_subtree(
                module_paths,
                flow.owner(),
                &source.module_id,
                &feature.feature,
            )?;
            ensure_sorted_unique(
                feature
                    .checkpoints
                    .iter()
                    .map(|checkpoint| checkpoint.checkpoint.as_str()),
                &format!("{}/features/{feature_index}/checkpoints", source.path),
            )?;
            let intended_checkpoints = flow
                .nodes()
                .iter()
                .map(crate::behavioral_semantics::BfgNode::checkpoint)
                .collect::<BTreeSet<_>>();
            for (checkpoint_index, checkpoint) in feature.checkpoints.iter().enumerate() {
                if !intended_checkpoints.contains(checkpoint.checkpoint.as_str()) {
                    return Err(BehaviorRealizationContractError::UnknownCheckpoint {
                        feature: feature.feature.clone(),
                        checkpoint: checkpoint.checkpoint.clone(),
                    });
                }
                if !checkpoint_ids.insert(checkpoint.checkpoint.clone()) {
                    return Err(BehaviorRealizationContractError::DuplicateIdentity(
                        checkpoint.checkpoint.clone(),
                    ));
                }
                if checkpoint.anchors.is_empty() {
                    return Err(BehaviorRealizationContractError::EmptyAnchors(
                        checkpoint.checkpoint.clone(),
                    ));
                }
                if !is_sorted_unique(&checkpoint.anchors) {
                    return Err(BehaviorRealizationContractError::NonCanonicalOrder(
                        format!(
                            "{}/features/{feature_index}/checkpoints/{checkpoint_index}/anchors",
                            source.path
                        ),
                    ));
                }
                for anchor in &checkpoint.anchors {
                    validate_anchor(
                        anchor,
                        &feature.feature,
                        flow.owner(),
                        module_paths,
                        &symbols,
                        &nominal_types,
                        state_effect,
                        information_flow,
                        environmental,
                    )?;
                }
                checkpoints.push(ResolvedCheckpointRealization {
                    feature: feature.feature.clone(),
                    checkpoint: checkpoint.checkpoint.clone(),
                    declaring_module: source.module_id.clone(),
                    source_path: source.path.clone(),
                    pointer: format!("/features/{feature_index}/checkpoints/{checkpoint_index}"),
                    anchors: checkpoint.anchors.clone(),
                });
            }
            for expected in intended_checkpoints {
                if !feature
                    .checkpoints
                    .iter()
                    .any(|checkpoint| checkpoint.checkpoint == expected)
                {
                    return Err(BehaviorRealizationContractError::MissingCheckpoint {
                        feature: feature.feature.clone(),
                        checkpoint: expected.into(),
                    });
                }
            }
        }
    }
    checkpoints.sort();
    Ok(ResolvedBehaviorRealizationContracts {
        features: features.into_iter().collect(),
        checkpoints,
        digest: distributed_digest(&sources),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_anchor(
    anchor: &BehaviorAnchor,
    feature: &str,
    feature_owner: &str,
    module_paths: &BTreeMap<String, String>,
    symbols: &BTreeMap<&str, &crate::program_semantics::ExecutableSymbol>,
    nominal_types: &BTreeSet<&str>,
    state_effect: &StateEffectAnalysisModel,
    information_flow: &InformationFlowAnalysisModel,
    environmental: &EnvironmentalAnalysisModel,
) -> Result<(), BehaviorRealizationContractError> {
    if let Some(symbol_id) = anchor.symbol() {
        let symbol = symbols
            .get(symbol_id)
            .ok_or_else(|| BehaviorRealizationContractError::UnknownSymbol(symbol_id.into()))?;
        if !module_in_subtree(module_paths, feature_owner, symbol.fortress_module()) {
            return Err(BehaviorRealizationContractError::ForeignSymbol {
                feature: feature.into(),
                symbol: symbol_id.into(),
            });
        }
    }
    match anchor {
        BehaviorAnchor::SymbolEntry { .. } | BehaviorAnchor::SymbolReturn { .. } => {}
        BehaviorAnchor::StateTransition {
            nominal_type,
            symbol,
            from_states,
            to_states,
        } => {
            if !nominal_types.contains(nominal_type.as_str()) {
                return Err(BehaviorRealizationContractError::UnknownNominalType(
                    nominal_type.clone(),
                ));
            }
            if from_states.is_empty()
                || to_states.is_empty()
                || !is_sorted_unique(from_states)
                || !is_sorted_unique(to_states)
            {
                return Err(BehaviorRealizationContractError::InvalidStateTransition(
                    symbol.clone(),
                ));
            }
            let established = state_effect
                .summaries()
                .iter()
                .find(|summary| summary.symbol() == symbol)
                .is_some_and(|summary| {
                    classification_contains(summary.input_receiver_state(), from_states)
                        && classification_contains(summary.output_receiver_state(), to_states)
                });
            if !established {
                return Err(BehaviorRealizationContractError::UnknownStateTransition(
                    symbol.clone(),
                ));
            }
        }
        BehaviorAnchor::Effect { effect, symbol } => {
            let established = state_effect
                .summaries()
                .iter()
                .find(|summary| summary.symbol() == symbol)
                .is_some_and(|summary| summary.transitive_effects().contains(effect));
            if !established {
                return Err(BehaviorRealizationContractError::UnknownEffect {
                    symbol: symbol.clone(),
                    effect: *effect,
                });
            }
        }
        BehaviorAnchor::InformationTransition {
            transition,
            symbol,
            facet,
            from,
            to,
        } => {
            let established = information_flow
                .trusted_transition_diagnostics()
                .iter()
                .any(|diagnostic| {
                    diagnostic.kind() == *transition
                        && diagnostic.symbol() == symbol
                        && diagnostic.facet() == facet
                        && diagnostic.from() == from
                        && diagnostic.to() == to
                });
            if !established {
                return Err(
                    BehaviorRealizationContractError::UnknownInformationTransition(symbol.clone()),
                );
            }
        }
        BehaviorAnchor::EnvironmentOutcome { operation, outcome } => {
            let established = environmental.operations().iter().any(|summary| {
                summary.operation() == operation
                    && summary.outcomes().iter().any(|item| item.id() == outcome)
            });
            if !established {
                return Err(
                    BehaviorRealizationContractError::UnknownEnvironmentOutcome {
                        operation: operation.clone(),
                        outcome: outcome.clone(),
                    },
                );
            }
        }
    }
    Ok(())
}

fn classification_contains(
    classification: Option<&crate::state_effect_analysis::TypestateClassification>,
    expected: &[String],
) -> bool {
    match classification {
        Some(crate::state_effect_analysis::TypestateClassification::Exact { state }) => {
            expected.len() == 1 && expected[0] == *state
        }
        Some(crate::state_effect_analysis::TypestateClassification::Possible { states }) => {
            states == expected
        }
        _ => false,
    }
}

fn validate_module_in_subtree(
    module_paths: &BTreeMap<String, String>,
    owner: &str,
    module: &str,
    feature: &str,
) -> Result<(), BehaviorRealizationContractError> {
    if module_in_subtree(module_paths, owner, module) {
        Ok(())
    } else {
        Err(BehaviorRealizationContractError::ForeignContractOwner {
            feature: feature.into(),
            module: module.into(),
        })
    }
}

fn module_in_subtree(
    module_paths: &BTreeMap<String, String>,
    owner: &str,
    candidate: &str,
) -> bool {
    let Some(owner_path) = module_paths.get(owner) else {
        return false;
    };
    let Some(candidate_path) = module_paths.get(candidate) else {
        return false;
    };
    owner_path.is_empty()
        || candidate_path == owner_path
        || candidate_path.starts_with(&format!("{owner_path}/"))
}

fn ensure_sorted_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    location: &str,
) -> Result<(), BehaviorRealizationContractError> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(BehaviorRealizationContractError::NonCanonicalOrder(
            location.into(),
        ))
    }
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_document(
    document: &ContractDocument,
) -> Result<String, BehaviorRealizationContractError> {
    let mut output = serde_json::to_string_pretty(document)
        .map_err(|error| BehaviorRealizationContractError::Serialization(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

fn distributed_digest(sources: &[BehaviorRealizationContractSource]) -> String {
    let mut material = Vec::new();
    for source in sources {
        material.extend_from_slice(source.path.as_bytes());
        material.push(0);
        material.extend_from_slice(source.module_id.as_bytes());
        material.push(0);
        material.extend_from_slice(source.source.as_bytes());
        material.push(0xff);
    }
    format!("sha256:{:x}", Sha256::digest(material))
}

/// Canonicalizes one syntactically valid Behavior Realization Contract.
///
/// # Errors
///
/// Returns an error when typed decoding or serialization fails.
pub fn canonicalize_behavior_realization_contract_json(
    source: &str,
) -> Result<String, BehaviorRealizationContractError> {
    let document: ContractDocument = serde_json::from_str(source).map_err(|error| {
        BehaviorRealizationContractError::InvalidJson {
            path: "<memory>".into(),
            detail: error.to_string(),
        }
    })?;
    canonical_document(&document)
}
