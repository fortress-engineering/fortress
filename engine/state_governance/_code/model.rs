//! Versioned comparison inputs and derived outputs; no evaluator or workflow store.
use crate::state_view::StateView;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Independently compared governing dimension. A path can carry several roles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Axis {
    /// Observed software and content.
    Subject,
    /// Authored requirements and promises.
    Intent,
    /// Standard, profiles, interpretation and context authority.
    Authority,
    /// Baselines, exceptions and enforcement authority.
    Governance,
}

/// Closed comparison vocabulary; these labels never imply external approval.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Change {
    /// Exactly preserved under this comparison.
    Unchanged,
    /// A known item was introduced.
    Added,
    /// A known item was retired; absence alone is not a resolved finding.
    Removed,
    /// A supported descriptive difference, without a causal claim.
    Changed,
    /// Authored restrictions or unchanged conjunctive promises imply the prior promise.
    Strengthened,
    /// Authored restrictions or unchanged conjunctive promises relax the prior promise.
    Weakened,
    /// Opposing comparable restriction changes.
    Mixed,
    /// Required comparison premises differ or are absent.
    NotComparable,
    /// Upstream evaluation lacks sufficient support.
    NotEvaluable,
    /// No applicable upstream subject exists.
    NotApplicable,
    /// Missing information cannot establish equality or a direction.
    Unknown,
    /// The construct is outside the implemented finite semantics.
    Unsupported,
    /// An upstream claim becomes evaluable; no implementation regression is inferred.
    NewlyEvaluable,
    /// Previously evaluable support becomes unavailable.
    EvaluabilityLost,
    /// An identifier is absent without sufficient resolution evidence.
    NotObserved,
    /// The governing policy was retired.
    PolicyRetired,
    /// Visibility narrowed; a missing finding is not resolved.
    ScopeExcluded,
    /// Required authority or context cannot be compared.
    AuthorityIncomparable,
    /// Several occurrences share a proposed semantic identity.
    IdentityAmbiguous,
    /// Same semantic entity, different occurrence path.
    PlacementOnly,
    /// Nonrecursive evidence/output availability changed.
    StorageOnly,
    /// Source and permission relaxation changed together, without approval.
    CoMovingAuthorization,
}

/// One exact input with already-resolved, possibly overlapping authority roles.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AxisInput {
    /// Stable input identity; distinct from current placement.
    pub id: String,
    /// Portable repository-relative occurrence.
    pub path: String,
    /// Existing owner-resolved Module scopes; empty means unavailable ownership.
    #[serde(deserialize_with = "strict_set")]
    pub scope_refs: BTreeSet<String>,
    /// Exact observed bytes.
    pub content_ref: String,
    /// Role-specific canonical semantic identities, supplied by the owning producer.
    pub roles: BTreeMap<Axis, String>,
}

/// A stable authored or observed entity, paired before comparing content.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    /// Stable Module, guarantee, requirement or reference identity.
    pub id: String,
    /// Closed semantic namespace: module, guarantee, requirement, reference, observation.
    pub kind: String,
    /// Canonical meaning; excludes occurrence path and formatting.
    pub semantic_ref: String,
    /// Current repository-relative occurrence, if one exists.
    pub path: Option<String>,
    /// Conjunctive authored promise only; absent for derived observations.
    pub promise: Option<Promise>,
}

/// Supported authored guarantee algebra, without interpreting prose implications.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Promise {
    /// Same guaranteed subject and scope are required for implication.
    pub subject: String,
    /// Only ALL is supported; other quantifiers stay unsupported.
    pub quantifier: String,
    /// Requirement identities bound to their exact authored definitions.
    pub clauses: BTreeMap<String, String>,
}

/// A finite projection of an existing compiled effective policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinitePolicy {
    /// Stable policy slot, independent of disposition.
    pub id: String,
    /// Exact authored input bytes; must occur in the input manifest.
    pub origin_ref: String,
    /// AUTHORED permits the finite relation; observations cannot become promises.
    pub origin_kind: String,
    /// Exact pinned effect-vocabulary identity.
    pub vocabulary_ref: String,
    /// Explicit authored scope selector.
    pub scope: String,
    /// ALL is the supported quantifier.
    pub quantifier: String,
    /// Exact evaluator context, separate from source bytes.
    pub context_ref: String,
    /// Whether every authored target is represented by this pinned finite algebra.
    pub complete: bool,
    /// Entire registered target vocabulary; unlisted targets remain unconstrained.
    #[serde(deserialize_with = "strict_set")]
    pub universe: BTreeSet<String>,
    /// Effective prohibitions after owner-resolved precedence.
    #[serde(deserialize_with = "strict_set")]
    pub denied: BTreeSet<String>,
    /// Effective explicit permissions; observed use never populates this set.
    #[serde(deserialize_with = "strict_set")]
    pub allowed: BTreeSet<String>,
}

/// Explicit necessary authority and source assets for one exact endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateAssets {
    /// Exact source binding shared by the endpoint and all projections.
    pub subject_ref: String,
    /// Axes whose complete input inventory was supplied.
    #[serde(deserialize_with = "strict_set")]
    pub complete_axes: BTreeSet<Axis>,
    /// Role-resolved source and authority inventory.
    pub inputs: Vec<AxisInput>,
    /// Stable semantic identities, including ambiguous occurrences when present.
    pub entities: Vec<Entity>,
    /// Already compiled effective restrictions, not another policy evaluator.
    pub policies: Vec<FinitePolicy>,
    /// Exact Standard identity, edition and content digest as an opaque canonical ref.
    pub standard_ref: Option<String>,
    /// All selected profile references, including Module scope.
    #[serde(deserialize_with = "strict_set")]
    pub profile_refs: BTreeSet<String>,
    /// Exact semantic producer identity/version; no authenticity is inferred.
    pub evaluator_ref: Option<String>,
    /// Owner-resolved coverage/exclusion authority.
    pub exclusions_ref: Option<String>,
    /// Exact portable path-prefix exclusions, when their authority is available.
    #[serde(deserialize_with = "strict_optional_set")]
    pub exclusions: Option<BTreeSet<String>>,
    /// Existing semantic-reference facts independent of occurrence paths.
    #[serde(deserialize_with = "strict_optional_set")]
    pub reference_facts: Option<BTreeSet<String>>,
}

/// One explicitly identified immutable endpoint. Missing history remains representable.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonState {
    /// Versioned comparison-input schema.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact supported shape version.
    pub schema_version: u16,
    /// Known exact subject, or absent when historical bytes are unavailable.
    pub source_ref: Option<String>,
    /// Original declaration/assessment view, never rewritten under current authority.
    pub view: Option<StateView>,
    /// Original retained declaration/assessment pair when full `StateView` metadata is absent.
    pub retained_application: Option<crate::application::ApplicationAssessment>,
    /// Necessary owner-produced assets; absence disables affected comparisons.
    pub assets: Option<StateAssets>,
    /// Exact historical generation or source citation; excludes machine-local paths.
    pub origin_ref: Option<String>,
    /// Explicit unsupported or unavailable input conditions.
    pub limitations: Vec<String>,
}

/// Non-authoritative approval citation scoped to an exact comparison.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonContext {
    /// Caller-supplied approval citations; never validated as grants.
    #[serde(deserialize_with = "strict_set")]
    pub authorization_refs: BTreeSet<String>,
    /// Optional explicitly supplied four-cell study; no historical code executes.
    pub counterfactuals: Vec<Counterfactual>,
}

/// One already evaluated common-authority cell, admitted by its exact bindings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Counterfactual {
    /// Role-partitioned software subject, or original exact ref when assets are absent.
    pub subject_ref: String,
    /// Complete role-partitioned governing identity; original bindings stay in the view.
    pub authority_ref: String,
    /// Original immutable endpoint evaluated for this cell.
    pub view: StateView,
    /// Necessary original source/authority assets; absence withholds controlled attribution.
    pub assets: Option<StateAssets>,
}

/// One explainable difference with original evidence and uncertainty intact.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    /// semantic, policy, coverage, evidence, finding, entity, placement or storage.
    pub category: String,
    /// Stable paired identity or explicitly unmatched identity.
    pub id: String,
    /// Supported classification, never an overall improvement verdict.
    pub change: Change,
    /// Original before projection, without rewriting historical authority.
    pub before: Option<Value>,
    /// Original after projection.
    pub after: Option<Value>,
    /// Exact supported explanation or missing premise.
    pub reasons: Vec<String>,
}

/// One independently observed input-axis delta.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AxisDelta {
    /// Compared axis.
    pub axis: Axis,
    /// CHANGED, UNCHANGED or UNKNOWN with completeness made explicit.
    pub change: Change,
    /// IDs of role-bound inputs differing on this axis.
    pub input_ids: Vec<String>,
    /// Whether both inventories for this axis were supplied completely.
    pub complete: bool,
}

/// Exact base-bound reference for later authorization consumers, not a decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationReference {
    /// Changed protected dimension; no grant is inferred.
    pub axis: Axis,
    /// Original base authority, if available.
    pub base_authority_ref: Option<String>,
    /// Explicit owner citations, without trust inflation.
    #[serde(deserialize_with = "strict_set")]
    pub citations: BTreeSet<String>,
    /// Always `NOT_VALIDATED`; future host authority must validate independently.
    pub validation: String,
}

/// Derived reproducible comparison; no timestamp, cache path or workflow authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionAnalysis {
    /// Versioned transition schema.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Exact supported version.
    pub schema_version: u16,
    /// Deterministic comparator implementation version.
    pub semantic_version: String,
    /// Content digest of the exact admitted before input.
    pub from_state: String,
    /// Content digest of the exact admitted after input.
    pub to_state: String,
    /// Digest of the explicit comparison context.
    pub comparison_context: String,
    /// Four independent input dimensions, always all present.
    pub input_deltas: Vec<AxisDelta>,
    /// Descriptions of stable claim and authored policy differences.
    pub semantic_deltas: Vec<Delta>,
    /// Coverage and evaluability remain independent from truth.
    pub coverage_deltas: Vec<Delta>,
    /// Proof, obligation and assurance sufficiency differences.
    pub evidence_deltas: Vec<Delta>,
    /// Original finding identities and governance dispositions.
    pub finding_deltas: Vec<Delta>,
    /// Neutral finding-owner retirement observations, never baseline mutations.
    pub retirement_evidence: Vec<crate::finding_governance::RetirementEvidence>,
    /// Explicit finite authored relaxations only.
    pub weakenings: Vec<String>,
    /// Explicit finite authored strengthening only.
    pub strengthenings: Vec<String>,
    /// Missing, ambiguous and unsupported comparison premises.
    pub incomparabilities: Vec<String>,
    /// Base-bound citations only; no workflow or approval validation.
    pub required_authorizations: Vec<AuthorizationReference>,
    /// Limits on the conclusions, including lack of verdict-only causality.
    pub limitations: Vec<String>,
}

/// A separately labelled comparison to a merge base or parent.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParentComparison {
    /// base or parent identity supplied by the caller.
    pub label: String,
    /// Independent comparison to the same target.
    pub transition: TransitionAnalysis,
}

fn strict_set<'de, T: Deserialize<'de> + Ord, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<T>, D::Error> {
    let values = Vec::<T>::deserialize(deserializer)?;
    let length = values.len();
    let set = values.into_iter().collect::<BTreeSet<_>>();
    if set.len() != length {
        return Err(serde::de::Error::custom("duplicate semantic set member"));
    }
    Ok(set)
}
fn strict_optional_set<'de, T: Deserialize<'de> + Ord, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeSet<T>>, D::Error> {
    let values = Option::<Vec<T>>::deserialize(deserializer)?;
    values
        .map(|values| {
            let length = values.len();
            let set = values.into_iter().collect::<BTreeSet<_>>();
            if set.len() != length {
                return Err(serde::de::Error::custom("duplicate semantic set member"));
            }
            Ok(set)
        })
        .transpose()
}
