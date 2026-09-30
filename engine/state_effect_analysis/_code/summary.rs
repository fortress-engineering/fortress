//! Exact-context operation summaries with explicit effect and authority premises.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program_semantics::ContextKnowledge;
use crate::semantic_analysis::FunctionEffect;

/// Wire identity for installed operation-summary catalogs.
pub const OPERATION_SUMMARY_SCHEMA: &str = "urn:fortress:schema:v1:operation-summary-catalog";
/// First operation-summary catalog wire version.
pub const OPERATION_SUMMARY_SCHEMA_VERSION: u16 = 1;

/// Unknown is distinct from an established, possibly empty effect upper bound.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    content = "effects",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum SummaryEffectBound {
    /// No complete bound has been established.
    Unknown,
    /// Every effect lies within this canonical set.
    Known(Vec<FunctionEffect>),
}

/// Whether the summary accounts for the selected operation's whole effect boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SummaryCompleteness {
    /// Supported facts leave additional behavior opaque.
    Partial,
    /// All behavior is bounded conditional on the declared premises.
    Complete,
}

/// Provenance class, independent from the observed effect lower facts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SummaryAuthorityClass {
    /// Directly retained operational observations.
    Observed,
    /// Source-derived facts without complete qualification.
    Derived,
    /// An assumption accepted only by an explicit selected profile.
    Assumed,
    /// A reviewed and qualified bound under its exact context.
    Qualified,
}

/// Exact target alternatives and one exact feature set supported by a selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryTargetFeaturesConstraints {
    /// Canonical, nonempty exact target identities.
    pub targets: Vec<String>,
    /// Canonical exact features; an empty list means known absence of features.
    pub features: Vec<String>,
}

/// One installed summary and all the premises needed to instantiate its bound.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSummary {
    /// Stable catalog-local summary identity.
    pub id: String,
    /// One exact Program Semantics external operation identity.
    pub operation_selector: String,
    /// SHA-256 identity of the reviewed toolchain or package source bytes.
    pub toolchain_or_package_source_digest: String,
    /// Canonical exact supported version identities.
    pub supported_versions: Vec<String>,
    /// Exact configuration constraints.
    pub target_features_constraints: SummaryTargetFeaturesConstraints,
    /// Canonical exact type bindings required by this summary.
    pub type_constraints: Vec<String>,
    /// Positive operational facts; these do not imply a complete upper bound.
    pub observed_effects: Vec<FunctionEffect>,
    /// Conditional whole-operation effect bound.
    pub effect_upper_bound: SummaryEffectBound,
    /// Canonical premise keys for invoked callbacks or conversions.
    pub callback_dependencies: Vec<String>,
    /// Canonical premise keys for explicit or implicit destructor execution.
    pub destructor_dependencies: Vec<String>,
    /// Whether the bound covers the whole operation under its premises.
    pub completeness: SummaryCompleteness,
    /// Authority class of the bound, rather than its editable filename.
    pub authority_class: SummaryAuthorityClass,
    /// Canonical references to retained qualification evidence.
    pub qualification_refs: Vec<String>,
}

/// Exact facts supplied by the semantic producer or a trusted caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SummaryContext {
    /// Observed reviewed-source identity, never inferred from an operation name.
    pub source_digest: ContextKnowledge<String>,
    /// Exact dependency or toolchain version.
    pub version: ContextKnowledge<String>,
    /// Exact target platform identity.
    pub target: ContextKnowledge<String>,
    /// Exact selected features; unknown is distinct from a known empty set.
    pub features: ContextKnowledge<Vec<String>>,
    /// Exact actual type bindings; unknown is distinct from a known empty set.
    pub type_bindings: ContextKnowledge<Vec<String>>,
}

impl Default for SummaryContext {
    fn default() -> Self {
        Self {
            source_digest: ContextKnowledge::Unknown,
            version: ContextKnowledge::Unknown,
            target: ContextKnowledge::Unknown,
            features: ContextKnowledge::Unknown,
            type_bindings: ContextKnowledge::Unknown,
        }
    }
}

/// A callback or destructor bound supplied with evidence that supports it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SummaryPremise {
    /// All effects of this instantiated dependency, or explicit unknown.
    pub bound: SummaryEffectBound,
    /// Nonempty canonical evidence references justifying a known bound.
    pub refs: Vec<String>,
}

/// Explicit profile acceptance delivered by a trusted caller.
///
/// Parsing a repository catalog does not establish that this acceptance exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SummaryAcceptance {
    /// Exact content identity of the selected accepting profile.
    pub profile_digest: String,
    /// Canonical summary identities expressly accepted by that profile.
    pub accepted_summary_ids: Vec<String>,
}

/// Reviewable result of one exact operation-summary instantiation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SummaryOutcome {
    /// Summary selected by an exact context match, if one exists.
    pub selected_summary_id: Option<String>,
    /// Canonical installed catalog identity.
    pub catalog_digest: String,
    /// Selected authority class, including an unaccepted assumption.
    pub authority: Option<SummaryAuthorityClass>,
    /// Complete instantiated bound, or explicit unknown.
    pub upper_bound: SummaryEffectBound,
    /// Canonical evidence supporting qualification and all dependency premises.
    pub premise_refs: Vec<String>,
    /// Canonical disclosed assumption and accepting-profile references.
    pub assumption_refs: Vec<String>,
    /// Canonical reasons why a complete bound could not be established.
    pub reasons: Vec<String>,
}

impl SummaryOutcome {
    /// Returns whether the selected authority and premises establish an upper bound.
    #[must_use]
    pub const fn is_sufficient(&self) -> bool {
        matches!(self.upper_bound, SummaryEffectBound::Known(_))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    producer_version: String,
    summaries: Vec<OperationSummary>,
}

/// Validated catalog; trusted installation authority remains the caller's responsibility.
#[derive(Clone, Debug)]
pub struct OperationSummaryCatalog {
    document: CatalogDocument,
    digest: String,
}

impl OperationSummaryCatalog {
    /// Parses closed, duplicate-free records and rejects ambiguous selectors.
    ///
    /// # Errors
    /// Returns an error for malformed JSON, noncanonical sets, invalid identities,
    /// unsupported versions, or overlapping exact selectors.
    pub fn from_json_str(source: &str) -> Result<Self, OperationSummaryError> {
        let mut document: CatalogDocument = crate::wire::parse_public_json(source)
            .map_err(|error| OperationSummaryError::InvalidDocument(error.to_string()))?;
        if document.schema != OPERATION_SUMMARY_SCHEMA
            || document.schema_version != OPERATION_SUMMARY_SCHEMA_VERSION
        {
            return Err(OperationSummaryError::UnsupportedSchema);
        }
        validate_text(&document.id, "catalog id")?;
        validate_text(&document.producer_version, "producer version")?;
        document
            .summaries
            .sort_by(|left, right| left.id.cmp(&right.id));
        for pair in document.summaries.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(OperationSummaryError::DuplicateId(pair[0].id.clone()));
            }
        }
        for summary in &document.summaries {
            validate_summary(summary)?;
        }
        for (index, first) in document.summaries.iter().enumerate() {
            for second in &document.summaries[index + 1..] {
                if selectors_overlap(first, second) {
                    return Err(OperationSummaryError::SelectorConflict {
                        first: first.id.clone(),
                        second: second.id.clone(),
                    });
                }
            }
        }
        let bytes = serde_json_canonicalizer::to_vec(&document)
            .map_err(|error| OperationSummaryError::InvalidDocument(error.to_string()))?;
        Ok(Self {
            document,
            digest: format!("sha256:{:x}", Sha256::digest(bytes)),
        })
    }

    /// Adds project-local assumptions without promoting their editable authority.
    ///
    /// # Errors
    /// Returns an error for invalid catalogs, non-assumed records, positive facts,
    /// duplicate identities, or selectors that overlap existing authority.
    pub fn with_assumed_catalog(&self, source: &str) -> Result<Self, OperationSummaryError> {
        let extra = Self::from_json_str(source)?;
        for summary in extra.summaries() {
            if summary.authority_class != SummaryAuthorityClass::Assumed
                || !summary.observed_effects.is_empty()
            {
                return Err(OperationSummaryError::InvalidDocument(format!(
                    "project-local summary {} is not a fact-free explicit assumption",
                    summary.id
                )));
            }
        }
        let mut document = self.document.clone();
        document.summaries.extend(extra.document.summaries);
        let source = serde_json::to_string(&document)
            .map_err(|error| OperationSummaryError::InvalidDocument(error.to_string()))?;
        Self::from_json_str(&source)
    }

    /// Returns the catalog's exact canonical-byte SHA-256 identity.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the installed catalog identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.document.id
    }

    /// Returns the effect-summary producer semantic version.
    #[must_use]
    pub fn producer_version(&self) -> &str {
        &self.document.producer_version
    }

    /// Returns validated summaries in stable identity order.
    #[must_use]
    pub fn summaries(&self) -> &[OperationSummary] {
        &self.document.summaries
    }

    /// Returns retained positive lower facts without asserting whole-operation completeness.
    #[must_use]
    pub fn observed_effects(&self, operation: &str) -> Vec<FunctionEffect> {
        canonical_effects(
            self.document
                .summaries
                .iter()
                .filter(|summary| summary.operation_selector == operation)
                .flat_map(|summary| summary.observed_effects.iter().copied()),
        )
    }

    /// Resolves one operation under exact context and explicit effect premises.
    ///
    /// No call name, unknown configuration, or editable authority label provides
    /// missing premises. The caller must establish that this catalog is accepted
    /// installed authority before using the resulting bound in an assessment.
    #[must_use]
    pub fn resolve(
        &self,
        operation: &str,
        context: &SummaryContext,
        premises: &BTreeMap<String, SummaryPremise>,
        acceptance: Option<&SummaryAcceptance>,
    ) -> SummaryOutcome {
        let mut outcome = SummaryOutcome {
            selected_summary_id: None,
            catalog_digest: self.digest.clone(),
            authority: None,
            upper_bound: SummaryEffectBound::Unknown,
            premise_refs: Vec::new(),
            assumption_refs: Vec::new(),
            reasons: Vec::new(),
        };
        let candidates = self
            .document
            .summaries
            .iter()
            .filter(|summary| summary.operation_selector == operation)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            outcome.reasons.push("no_summary_for_operation".into());
            return outcome;
        }
        let mut mismatch_reasons = BTreeSet::new();
        let selected = candidates.into_iter().find(|summary| {
            let reasons = context_mismatches(summary, context);
            let matches = reasons.is_empty();
            mismatch_reasons.extend(reasons);
            matches
        });
        let Some(summary) = selected else {
            outcome.reasons = mismatch_reasons.into_iter().collect();
            return outcome;
        };
        instantiate_summary(summary, premises, acceptance, &mut outcome);
        outcome
    }
}

fn instantiate_summary(
    summary: &OperationSummary,
    premises: &BTreeMap<String, SummaryPremise>,
    acceptance: Option<&SummaryAcceptance>,
    outcome: &mut SummaryOutcome,
) {
    outcome.selected_summary_id = Some(summary.id.clone());
    outcome.authority = Some(summary.authority_class);
    let mut reasons = BTreeSet::new();
    let mut refs = summary
        .qualification_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if summary.completeness != SummaryCompleteness::Complete {
        reasons.insert("summary_incomplete".into());
    }
    match summary.authority_class {
        SummaryAuthorityClass::Qualified => {}
        SummaryAuthorityClass::Assumed => {
            outcome
                .assumption_refs
                .push(format!("operation_summary_assumption:{}", summary.id));
            if let Some(accepted) = acceptance.filter(|accepted| {
                is_digest(&accepted.profile_digest)
                    && is_canonical_text_set(&accepted.accepted_summary_ids)
                    && accepted
                        .accepted_summary_ids
                        .binary_search(&summary.id)
                        .is_ok()
            }) {
                outcome
                    .assumption_refs
                    .push(format!("accepted_profile:{}", accepted.profile_digest));
            } else {
                reasons.insert("summary_assumption_not_accepted".into());
            }
            outcome.assumption_refs.sort();
        }
        SummaryAuthorityClass::Observed | SummaryAuthorityClass::Derived => {
            reasons.insert("summary_authority_unqualified".into());
        }
    }
    let mut effects = match &summary.effect_upper_bound {
        SummaryEffectBound::Known(effects) => effects.clone(),
        SummaryEffectBound::Unknown => {
            reasons.insert("summary_upper_bound_unknown".into());
            Vec::new()
        }
    };
    for dependency in summary
        .callback_dependencies
        .iter()
        .chain(&summary.destructor_dependencies)
    {
        match premises.get(dependency) {
            Some(SummaryPremise {
                bound: SummaryEffectBound::Known(bound),
                refs: premise_refs,
            }) if !premise_refs.is_empty()
                && is_canonical_text_set(premise_refs)
                && is_canonical_effect_set(bound) =>
            {
                effects.extend(bound.iter().copied());
                refs.extend(premise_refs.iter().cloned());
            }
            _ => {
                reasons.insert(format!("summary_dependency_unresolved:{dependency}"));
            }
        }
    }
    outcome.premise_refs = refs.into_iter().collect();
    outcome.reasons = reasons.into_iter().collect();
    if outcome.reasons.is_empty() {
        outcome.upper_bound = SummaryEffectBound::Known(canonical_effects(effects));
    }
}

fn context_mismatches(summary: &OperationSummary, context: &SummaryContext) -> Vec<String> {
    let mut reasons = Vec::new();
    match &context.source_digest {
        ContextKnowledge::Unknown => reasons.push("summary_source_digest_unknown".into()),
        ContextKnowledge::Known(value) if value != &summary.toolchain_or_package_source_digest => {
            reasons.push("summary_source_digest_mismatch".into());
        }
        ContextKnowledge::Known(_) => {}
    }
    match &context.version {
        ContextKnowledge::Unknown => reasons.push("summary_version_unknown".into()),
        ContextKnowledge::Known(value)
            if summary.supported_versions.binary_search(value).is_err() =>
        {
            reasons.push("summary_version_mismatch".into());
        }
        ContextKnowledge::Known(_) => {}
    }
    match &context.target {
        ContextKnowledge::Unknown => reasons.push("summary_target_unknown".into()),
        ContextKnowledge::Known(value)
            if summary
                .target_features_constraints
                .targets
                .binary_search(value)
                .is_err() =>
        {
            reasons.push("summary_target_mismatch".into());
        }
        ContextKnowledge::Known(_) => {}
    }
    for (name, actual, expected) in [
        (
            "features",
            &context.features,
            &summary.target_features_constraints.features,
        ),
        (
            "type_bindings",
            &context.type_bindings,
            &summary.type_constraints,
        ),
    ] {
        match actual {
            ContextKnowledge::Unknown => reasons.push(format!("summary_{name}_unknown")),
            ContextKnowledge::Known(values) if values != expected => {
                reasons.push(format!("summary_{name}_mismatch"));
            }
            ContextKnowledge::Known(_) => {}
        }
    }
    reasons.sort();
    reasons
}

fn validate_summary(summary: &OperationSummary) -> Result<(), OperationSummaryError> {
    validate_text(&summary.id, "summary id")?;
    validate_text(&summary.operation_selector, "operation selector")?;
    if !is_digest(&summary.toolchain_or_package_source_digest) {
        return Err(OperationSummaryError::InvalidDocument(format!(
            "invalid source digest for {}",
            summary.id
        )));
    }
    if summary.supported_versions.is_empty()
        || summary.target_features_constraints.targets.is_empty()
    {
        return Err(OperationSummaryError::InvalidDocument(format!(
            "missing exact version or target for {}",
            summary.id
        )));
    }
    for (field, values) in [
        ("supported_versions", &summary.supported_versions),
        ("targets", &summary.target_features_constraints.targets),
        ("features", &summary.target_features_constraints.features),
        ("type_constraints", &summary.type_constraints),
        ("callback_dependencies", &summary.callback_dependencies),
        ("destructor_dependencies", &summary.destructor_dependencies),
        ("qualification_refs", &summary.qualification_refs),
    ] {
        if !is_canonical_text_set(values) {
            return Err(OperationSummaryError::NonCanonicalSet {
                summary: summary.id.clone(),
                field: field.into(),
            });
        }
    }
    if !is_canonical_effect_set(&summary.observed_effects) {
        return Err(OperationSummaryError::NonCanonicalSet {
            summary: summary.id.clone(),
            field: "observed_effects".into(),
        });
    }
    if let SummaryEffectBound::Known(effects) = &summary.effect_upper_bound {
        if !is_canonical_effect_set(effects) {
            return Err(OperationSummaryError::NonCanonicalSet {
                summary: summary.id.clone(),
                field: "effect_upper_bound".into(),
            });
        }
        if summary
            .observed_effects
            .iter()
            .any(|effect| !effects.contains(effect))
        {
            return Err(OperationSummaryError::InvalidDocument(format!(
                "observed effects exceed upper bound for {}",
                summary.id
            )));
        }
    }
    if summary.authority_class == SummaryAuthorityClass::Qualified
        && summary.qualification_refs.is_empty()
    {
        return Err(OperationSummaryError::InvalidDocument(format!(
            "missing qualification references for {}",
            summary.id
        )));
    }
    Ok(())
}

fn selectors_overlap(first: &OperationSummary, second: &OperationSummary) -> bool {
    first.operation_selector == second.operation_selector
        && first.toolchain_or_package_source_digest == second.toolchain_or_package_source_digest
        && first
            .supported_versions
            .iter()
            .any(|version| second.supported_versions.binary_search(version).is_ok())
        && first
            .target_features_constraints
            .targets
            .iter()
            .any(|target| {
                second
                    .target_features_constraints
                    .targets
                    .binary_search(target)
                    .is_ok()
            })
        && first.target_features_constraints.features == second.target_features_constraints.features
        && first.type_constraints == second.type_constraints
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_text(value: &str, field: &str) -> Result<(), OperationSummaryError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        Err(OperationSummaryError::InvalidDocument(format!(
            "invalid {field}"
        )))
    } else {
        Ok(())
    }
}

fn is_canonical_text_set(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| validate_text(value, "set member").is_ok())
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_canonical_effect_set(values: &[FunctionEffect]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].stable_id() < pair[1].stable_id())
}

fn canonical_effects(values: impl IntoIterator<Item = FunctionEffect>) -> Vec<FunctionEffect> {
    let mut effects = values.into_iter().collect::<Vec<_>>();
    effects.sort_by_key(|effect| effect.stable_id());
    effects.dedup();
    effects
}

/// Catalog validation failure; no malformed document is promoted to authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSummaryError {
    /// JSON shape, identity, or internal effect constraints are invalid.
    InvalidDocument(String),
    /// The mandatory schema family or version is unsupported.
    UnsupportedSchema,
    /// Two records declare the same stable identity.
    DuplicateId(String),
    /// A semantic set is not strictly sorted and unique.
    NonCanonicalSet {
        /// Stable identity of the invalid record.
        summary: String,
        /// Invalid semantic set field.
        field: String,
    },
    /// Two different records can match the same exact operation context.
    SelectorConflict {
        /// Lexically first stable identity.
        first: String,
        /// Lexically second stable identity.
        second: String,
    },
}

impl Display for OperationSummaryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid operation-summary catalog: {self:?}")
    }
}

impl Error for OperationSummaryError {}
