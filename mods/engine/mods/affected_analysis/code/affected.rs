//! Exact-snapshot affected dependency analysis and verified incremental reuse.
//!
//! This module identifies invalidation; it does not decide architectural truth.
//! Cache records are machine-local accelerators whose bytes and complete input
//! bindings are verified before reuse.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical affected-analysis document schema.
pub const AFFECTED_ANALYSIS_SCHEMA: &str = "urn:fortress:schema:v1:affected-analysis";
/// Canonical affected-analysis schema version.
pub const AFFECTED_ANALYSIS_SCHEMA_VERSION: u16 = 1;
/// Semantic implementation version for dependency and cache interpretation.
pub const AFFECTED_ANALYSIS_VERSION: &str = "1.0.0";
/// Stable affected dependency resolver identity.
pub const AFFECTED_ANALYZER_ID: &str = "fortress-affected-analysis";

/// Stable category of one authoritative repository input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityInputKind {
    /// Governed or observed source implementation.
    Source,
    /// Cargo manifest or lock authority.
    CargoAuthority,
    /// Project configuration, including logical path bindings.
    ProjectConfiguration,
    /// Canonical Module Contract authority.
    ModuleContract,
    /// Distributed Function Contract authority.
    FunctionContract,
    /// Authored finding baseline and exception authority.
    FindingGovernance,
    /// Standard rule, schema, manifest, or profile authority.
    StandardAuthority,
    /// Canonical source responsibility documentation.
    SourceResponsibility,
    /// State Contract authority.
    StateContract,
    /// Information-flow policy authority.
    InformationFlowPolicy,
    /// Environment Contract authority.
    EnvironmentContract,
    /// Behavioral Realization Contract authority.
    BehavioralRealizationContract,
    /// Other observed repository input with no narrower understood class.
    RepositoryInput,
}

/// Classifies one canonical repository-relative input without inferring intent.
#[must_use]
pub fn classify_authority_path(path: &str) -> AuthorityInputKind {
    let extension = Path::new(path).extension();
    if path == "data/project.json" {
        AuthorityInputKind::ProjectConfiguration
    } else if path == "data/finding_governance.json" {
        AuthorityInputKind::FindingGovernance
    } else if path == "contract.json" || path.ends_with("/contract.json") {
        AuthorityInputKind::ModuleContract
    } else if path == "data/function_contracts.json"
        || path.ends_with("/data/function_contracts.json")
    {
        AuthorityInputKind::FunctionContract
    } else if path == "data/state_contracts.json" || path.ends_with("/data/state_contracts.json") {
        AuthorityInputKind::StateContract
    } else if path == "data/information_flow_policy.json"
        || path.ends_with("/data/information_flow_policy.json")
    {
        AuthorityInputKind::InformationFlowPolicy
    } else if path == "data/environment_contracts.json"
        || path.ends_with("/data/environment_contracts.json")
    {
        AuthorityInputKind::EnvironmentContract
    } else if path == "data/behavior_realization_contracts.json"
        || path.ends_with("/data/behavior_realization_contracts.json")
    {
        AuthorityInputKind::BehavioralRealizationContract
    } else if path.ends_with("/docs/code_docs.md") || path == "docs/code_docs.md" {
        AuthorityInputKind::SourceResponsibility
    } else if path == "Cargo.toml"
        || path.ends_with("/Cargo.toml")
        || path == "Cargo.lock"
        || path.ends_with("/Cargo.lock")
    {
        AuthorityInputKind::CargoAuthority
    } else if extension
        .is_some_and(|value| value.eq_ignore_ascii_case("rs") || value.eq_ignore_ascii_case("py"))
    {
        AuthorityInputKind::Source
    } else if path.contains("/standard_registry/data/")
        || path.ends_with("_rule.json")
        || path.ends_with("_schema_v1.json")
        || path.ends_with("_schema_v2.json")
        || path.ends_with("_schema_v3.json")
    {
        AuthorityInputKind::StandardAuthority
    } else {
        AuthorityInputKind::RepositoryInput
    }
}

/// One exact repository input used by affected comparison.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AffectedInput {
    path: String,
    digest: String,
    bytes: u64,
    kind: AuthorityInputKind,
}

impl AffectedInput {
    /// Creates one canonical repository-relative input.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical path or malformed SHA-256 identity.
    pub fn new(
        path: impl Into<String>,
        digest: impl Into<String>,
        bytes: u64,
    ) -> Result<Self, AffectedAnalysisError> {
        let path = path.into();
        let digest = digest.into();
        validate_relative_path(&path)?;
        validate_digest(&digest)?;
        Ok(Self {
            kind: classify_authority_path(&path),
            path,
            digest,
            bytes,
        })
    }

    /// Returns the canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the input authority class.
    #[must_use]
    pub const fn kind(&self) -> AuthorityInputKind {
        self.kind
    }
}

/// Stable semantic unit category in the affected graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffectedUnitKind {
    /// Exact authoritative repository file.
    AuthorityInput,
    /// Observed source artifact and resolved ownership.
    SourceArtifact,
    /// Executable or nominal semantic symbol.
    Symbol,
    /// One supported or explicitly uncertain call relationship.
    CallRelationship,
    /// Authored Module semantic identity.
    Module,
    /// Direct or transitive effect consequence.
    Effect,
    /// Derived capability consequence.
    Capability,
    /// One authored-policy conformance claim.
    ConformanceClaim,
    /// Canonical finding identity.
    Finding,
    /// Evidence node or compact evidence aggregate.
    Evidence,
    /// Certification obligation.
    CertificationObligation,
    /// Canonical materialized projection.
    Projection,
}

/// One content-addressed unit and its complete direct semantic dependencies.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AffectedUnit {
    id: String,
    kind: AffectedUnitKind,
    digest: String,
    dependencies: Vec<String>,
}

impl AffectedUnit {
    /// Creates a canonical dependency unit.
    ///
    /// # Errors
    ///
    /// Returns an error for empty identity, malformed digest, self-dependency,
    /// or duplicate dependencies.
    pub fn new<I, S>(
        id: impl Into<String>,
        kind: AffectedUnitKind,
        digest: impl Into<String>,
        dependencies: I,
    ) -> Result<Self, AffectedAnalysisError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        if id.trim().is_empty() || id.contains('\0') {
            return Err(AffectedAnalysisError::InvalidUnitIdentity(id));
        }
        let digest = digest.into();
        validate_digest(&digest)?;
        let mut dependencies = dependencies.into_iter().map(Into::into).collect::<Vec<_>>();
        dependencies.sort();
        if dependencies.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AffectedAnalysisError::DuplicateDependency(id));
        }
        if dependencies.iter().any(|dependency| dependency == &id) {
            return Err(AffectedAnalysisError::SelfDependency(id));
        }
        Ok(Self {
            id,
            kind,
            digest,
            dependencies,
        })
    }

    /// Returns the stable semantic unit identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the semantic unit category.
    #[must_use]
    pub const fn kind(&self) -> AffectedUnitKind {
        self.kind
    }

    /// Returns the unit content/meaning digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns complete direct dependency identities.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }
}

/// Exact dependency snapshot for one observed repository state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AffectedSnapshot {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    source_fingerprint: String,
    inputs: Vec<AffectedInput>,
    units: Vec<AffectedUnit>,
}

impl AffectedSnapshot {
    /// Creates and validates one canonical exact-snapshot dependency graph.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate inputs/units or unresolved dependencies.
    pub fn new(
        source_fingerprint: impl Into<String>,
        mut inputs: Vec<AffectedInput>,
        mut units: Vec<AffectedUnit>,
    ) -> Result<Self, AffectedAnalysisError> {
        let source_fingerprint = source_fingerprint.into();
        validate_digest(&source_fingerprint)?;
        inputs.sort();
        units.sort_by(|left, right| left.id.cmp(&right.id));
        reject_duplicates(inputs.iter().map(|input| input.path.as_str()), "input")?;
        reject_duplicates(units.iter().map(|unit| unit.id.as_str()), "unit")?;
        let ids = units
            .iter()
            .map(|unit| unit.id.as_str())
            .collect::<BTreeSet<_>>();
        for unit in &units {
            for dependency in &unit.dependencies {
                if !ids.contains(dependency.as_str()) {
                    return Err(AffectedAnalysisError::UnresolvedDependency {
                        unit: unit.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        Ok(Self {
            schema: AFFECTED_ANALYSIS_SCHEMA.into(),
            schema_version: AFFECTED_ANALYSIS_SCHEMA_VERSION,
            semantic_version: AFFECTED_ANALYSIS_VERSION.into(),
            source_fingerprint,
            inputs,
            units,
        })
    }

    /// Returns the exact repository source fingerprint.
    #[must_use]
    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    /// Returns canonical repository inputs.
    #[must_use]
    pub fn inputs(&self) -> &[AffectedInput] {
        &self.inputs
    }

    /// Returns canonical dependency units.
    #[must_use]
    pub fn units(&self) -> &[AffectedUnit] {
        &self.units
    }

    /// Serializes canonical two-space UTF-8 JSON with one LF.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        canonical_json(self)
    }
}

/// Repository input change classification used only for invalidation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InputChangeKind {
    /// A new authoritative input exists.
    Added,
    /// A prior authoritative input no longer exists.
    Removed,
    /// Bytes changed at the same canonical path.
    Modified,
    /// Unique identical content moved between repository-relative paths.
    Relocated,
}

/// One exact authoritative-input delta.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct InputChange {
    kind: InputChangeKind,
    authority: AuthorityInputKind,
    previous_path: Option<String>,
    current_path: Option<String>,
    previous_digest: Option<String>,
    current_digest: Option<String>,
}

impl InputChange {
    /// Returns the change class.
    #[must_use]
    pub const fn kind(&self) -> InputChangeKind {
        self.kind
    }

    /// Returns the understood authority class.
    #[must_use]
    pub const fn authority(&self) -> AuthorityInputKind {
        self.authority
    }

    /// Returns the prior path when present.
    #[must_use]
    pub fn previous_path(&self) -> Option<&str> {
        self.previous_path.as_deref()
    }

    /// Returns the current path when present.
    #[must_use]
    pub fn current_path(&self) -> Option<&str> {
        self.current_path.as_deref()
    }
}

/// Why one semantic unit must be recomputed.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvalidationReason {
    /// The unit exists only in the current graph.
    UnitAdded,
    /// The prior unit no longer exists.
    UnitRemoved,
    /// The unit's own exact semantic digest changed.
    UnitDigestChanged,
    /// The direct dependency identity set changed.
    DependencySetChanged,
    /// A direct or transitive dependency is affected.
    UpstreamAffected {
        /// Stable affected dependency identity.
        dependency: String,
    },
}

/// Affected status for one semantic unit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffectedUnitState {
    /// The unit must be recomputed.
    Recompute,
    /// The unit was removed and prior material cannot be current.
    Removed,
}

/// One invalidated unit with complete deterministic reasons.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AffectedUnitResult {
    id: String,
    kind: AffectedUnitKind,
    state: AffectedUnitState,
    reasons: Vec<InvalidationReason>,
}

impl AffectedUnitResult {
    /// Returns the stable unit identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the unit class.
    #[must_use]
    pub const fn kind(&self) -> AffectedUnitKind {
        self.kind
    }

    /// Returns deterministic invalidation reasons.
    #[must_use]
    pub fn reasons(&self) -> &[InvalidationReason] {
        &self.reasons
    }
}

/// Aggregate affected/reuse counts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AffectedSummary {
    changed_inputs: usize,
    affected_units: usize,
    reusable_units: usize,
    removed_units: usize,
    recomputation_percent: u32,
}

impl AffectedSummary {
    /// Returns authoritative input change count.
    #[must_use]
    pub const fn changed_inputs(self) -> usize {
        self.changed_inputs
    }

    /// Returns current units requiring recomputation.
    #[must_use]
    pub const fn affected_units(self) -> usize {
        self.affected_units
    }

    /// Returns current units proven reusable.
    #[must_use]
    pub const fn reusable_units(self) -> usize {
        self.reusable_units
    }

    /// Returns integer recomputation percentage rounded up.
    #[must_use]
    pub const fn recomputation_percent(self) -> u32 {
        self.recomputation_percent
    }
}

/// Deterministic comparison and affected closure for two exact snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AffectedAnalysis {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    previous_source_fingerprint: String,
    current_source_fingerprint: String,
    input_changes: Vec<InputChange>,
    affected: Vec<AffectedUnitResult>,
    reusable: Vec<String>,
    affected_modules: Vec<String>,
    affected_projections: Vec<String>,
    summary: AffectedSummary,
}

impl AffectedAnalysis {
    /// Returns authoritative input changes.
    #[must_use]
    pub fn input_changes(&self) -> &[InputChange] {
        &self.input_changes
    }

    /// Returns affected dependency units.
    #[must_use]
    pub fn affected(&self) -> &[AffectedUnitResult] {
        &self.affected
    }

    /// Returns unit identities proven reusable.
    #[must_use]
    pub fn reusable(&self) -> &[String] {
        &self.reusable
    }

    /// Returns stable affected Module identities.
    #[must_use]
    pub fn affected_modules(&self) -> &[String] {
        &self.affected_modules
    }

    /// Returns affected canonical projection identities.
    #[must_use]
    pub fn affected_projections(&self) -> &[String] {
        &self.affected_projections
    }

    /// Returns aggregate affected/reuse counts.
    #[must_use]
    pub const fn summary(&self) -> AffectedSummary {
        self.summary
    }

    /// Serializes canonical two-space UTF-8 JSON with one LF.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        canonical_json(self)
    }

    /// Renders a deterministic developer explanation.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut output = format!(
            "Fortress Affected Analysis\nFrom: {}\nTo: {}\nChanged inputs: {}\nAffected units: {}\nReusable units: {}\nRecomputation: {}%\n\n",
            self.previous_source_fingerprint,
            self.current_source_fingerprint,
            self.summary.changed_inputs,
            self.summary.affected_units,
            self.summary.reusable_units,
            self.summary.recomputation_percent,
        );
        output.push_str("Input changes:\n");
        for change in &self.input_changes {
            let _ = writeln!(
                output,
                "  {:?} {:?}: {} -> {}",
                change.kind,
                change.authority,
                change.previous_path.as_deref().unwrap_or("-"),
                change.current_path.as_deref().unwrap_or("-"),
            );
        }
        output.push_str("\nAffected Modules:\n");
        for module in &self.affected_modules {
            let _ = writeln!(output, "  {module}");
        }
        output.push_str("\nAffected projections:\n");
        for projection in &self.affected_projections {
            let _ = writeln!(output, "  {projection}");
        }
        output
    }
}

/// Compares two exact dependency snapshots and computes conservative closure.
///
/// A unit is reusable only when its own digest, direct dependency identities,
/// and entire upstream closure are unchanged.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn analyze_affected(
    previous: &AffectedSnapshot,
    current: &AffectedSnapshot,
) -> AffectedAnalysis {
    let input_changes = compare_inputs(previous.inputs(), current.inputs());
    let previous_units = previous
        .units()
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    let current_units = current
        .units()
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    let mut reasons = BTreeMap::<String, BTreeSet<InvalidationReason>>::new();
    for (id, unit) in &current_units {
        match previous_units.get(id) {
            None => {
                reasons
                    .entry((*id).to_owned())
                    .or_default()
                    .insert(InvalidationReason::UnitAdded);
            }
            Some(previous_unit) => {
                if previous_unit.digest != unit.digest {
                    reasons
                        .entry((*id).to_owned())
                        .or_default()
                        .insert(InvalidationReason::UnitDigestChanged);
                }
                if previous_unit.dependencies != unit.dependencies {
                    reasons
                        .entry((*id).to_owned())
                        .or_default()
                        .insert(InvalidationReason::DependencySetChanged);
                }
            }
        }
    }
    let mut removed = Vec::new();
    for (id, unit) in &previous_units {
        if !current_units.contains_key(id) {
            removed.push(AffectedUnitResult {
                id: (*id).to_owned(),
                kind: unit.kind,
                state: AffectedUnitState::Removed,
                reasons: vec![InvalidationReason::UnitRemoved],
            });
        }
    }
    let mut reverse = BTreeMap::<&str, Vec<&str>>::new();
    for unit in current.units() {
        for dependency in unit.dependencies() {
            reverse
                .entry(dependency)
                .or_default()
                .push(unit.id.as_str());
        }
    }
    let mut queue = reasons.keys().cloned().collect::<VecDeque<_>>();
    while let Some(affected) = queue.pop_front() {
        for dependent in reverse.get(affected.as_str()).into_iter().flatten() {
            let reason = InvalidationReason::UpstreamAffected {
                dependency: affected.clone(),
            };
            let newly_affected = !reasons.contains_key(*dependent);
            reasons
                .entry((*dependent).to_owned())
                .or_default()
                .insert(reason);
            if newly_affected {
                queue.push_back((*dependent).to_owned());
            }
        }
    }
    let mut affected = reasons
        .into_iter()
        .filter_map(|(id, reasons)| {
            current_units
                .get(id.as_str())
                .map(|unit| AffectedUnitResult {
                    id,
                    kind: unit.kind,
                    state: AffectedUnitState::Recompute,
                    reasons: reasons.into_iter().collect(),
                })
        })
        .collect::<Vec<_>>();
    affected.extend(removed);
    affected.sort();
    let affected_ids = affected
        .iter()
        .filter(|unit| unit.state == AffectedUnitState::Recompute)
        .map(|unit| unit.id.as_str())
        .collect::<BTreeSet<_>>();
    let reusable = current
        .units()
        .iter()
        .filter(|unit| !affected_ids.contains(unit.id.as_str()))
        .map(|unit| unit.id.clone())
        .collect::<Vec<_>>();
    let affected_modules = affected
        .iter()
        .filter(|unit| unit.kind == AffectedUnitKind::Module)
        .map(|unit| {
            unit.id
                .strip_prefix("module:")
                .unwrap_or(&unit.id)
                .to_owned()
        })
        .collect::<Vec<_>>();
    let affected_projections = affected
        .iter()
        .filter(|unit| unit.kind == AffectedUnitKind::Projection)
        .map(|unit| {
            unit.id
                .strip_prefix("projection:")
                .unwrap_or(&unit.id)
                .to_owned()
        })
        .collect::<Vec<_>>();
    let current_affected = affected_ids.len();
    let changed_inputs = input_changes.len();
    let denominator = current.units().len().max(1);
    let recomputation_percent =
        u32::try_from(current_affected.saturating_mul(100).div_ceil(denominator)).unwrap_or(100);
    AffectedAnalysis {
        schema: AFFECTED_ANALYSIS_SCHEMA.into(),
        schema_version: AFFECTED_ANALYSIS_SCHEMA_VERSION,
        semantic_version: AFFECTED_ANALYSIS_VERSION.into(),
        previous_source_fingerprint: previous.source_fingerprint.clone(),
        current_source_fingerprint: current.source_fingerprint.clone(),
        input_changes,
        affected,
        reusable,
        affected_modules,
        affected_projections,
        summary: AffectedSummary {
            changed_inputs,
            affected_units: current_affected,
            reusable_units: current.units().len().saturating_sub(current_affected),
            removed_units: previous_units
                .keys()
                .filter(|id| !current_units.contains_key(**id))
                .count(),
            recomputation_percent,
        },
    }
}

fn compare_inputs(previous: &[AffectedInput], current: &[AffectedInput]) -> Vec<InputChange> {
    let previous_by_path = previous
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    let current_by_path = current
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    let mut removed = previous_by_path
        .iter()
        .filter(|(path, _)| !current_by_path.contains_key(**path))
        .map(|(_, input)| *input)
        .collect::<Vec<_>>();
    let mut added = current_by_path
        .iter()
        .filter(|(path, _)| !previous_by_path.contains_key(**path))
        .map(|(_, input)| *input)
        .collect::<Vec<_>>();
    let mut changes = Vec::new();
    for (path, before) in &previous_by_path {
        if let Some(after) = current_by_path.get(path)
            && (before.digest != after.digest || before.bytes != after.bytes)
        {
            changes.push(InputChange {
                kind: InputChangeKind::Modified,
                authority: after.kind,
                previous_path: Some((*path).to_owned()),
                current_path: Some((*path).to_owned()),
                previous_digest: Some(before.digest.clone()),
                current_digest: Some(after.digest.clone()),
            });
        }
    }
    let removed_keys = group_unique_content(&removed);
    let added_keys = group_unique_content(&added);
    let relocations = removed_keys
        .iter()
        .filter_map(|(key, before)| added_keys.get(key).map(|after| (*before, *after)))
        .collect::<Vec<_>>();
    let relocated_before = relocations
        .iter()
        .map(|(before, _)| before.path.clone())
        .collect::<BTreeSet<_>>();
    let relocated_after = relocations
        .iter()
        .map(|(_, after)| after.path.clone())
        .collect::<BTreeSet<_>>();
    for (before, after) in relocations {
        changes.push(InputChange {
            kind: InputChangeKind::Relocated,
            authority: after.kind,
            previous_path: Some(before.path.clone()),
            current_path: Some(after.path.clone()),
            previous_digest: Some(before.digest.clone()),
            current_digest: Some(after.digest.clone()),
        });
    }
    removed.retain(|input| !relocated_before.contains(&input.path));
    added.retain(|input| !relocated_after.contains(&input.path));
    changes.extend(removed.into_iter().map(|input| InputChange {
        kind: InputChangeKind::Removed,
        authority: input.kind,
        previous_path: Some(input.path.clone()),
        current_path: None,
        previous_digest: Some(input.digest.clone()),
        current_digest: None,
    }));
    changes.extend(added.into_iter().map(|input| InputChange {
        kind: InputChangeKind::Added,
        authority: input.kind,
        previous_path: None,
        current_path: Some(input.path.clone()),
        previous_digest: None,
        current_digest: Some(input.digest.clone()),
    }));
    changes.sort();
    changes
}

fn group_unique_content<'a>(
    inputs: &'a [&AffectedInput],
) -> BTreeMap<(&'a str, u64, AuthorityInputKind), &'a AffectedInput> {
    let mut grouped = BTreeMap::<_, Vec<_>>::new();
    for input in inputs {
        grouped
            .entry((input.digest.as_str(), input.bytes, input.kind))
            .or_default()
            .push(*input);
    }
    grouped
        .into_iter()
        .filter_map(|(key, values)| (values.len() == 1).then_some((key, values[0])))
        .collect()
}

/// Canonical projection kinds eligible for dependency-bound cache reuse.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionKind {
    /// Contract Coherency Graph.
    Ccg,
    /// Intended Behavioral Flow Graph.
    Bfg,
    /// Program Semantic Model.
    Psm,
    /// Function-domain semantic analysis.
    Semantic,
    /// State and Effect Analysis.
    StateEffect,
    /// Module semantic conformance.
    SemanticConformance,
    /// Information-flow analysis.
    InformationFlow,
    /// Environmental analysis.
    Environmental,
    /// Realized Behavioral Flow Graph.
    RealizedBfg,
    /// Component reference resolution.
    References,
    /// Source Artifact Model.
    SourceArtifacts,
    /// Raw repository audit.
    Audit,
}

impl ProjectionKind {
    /// Returns the stable command/cache identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ccg => "ccg",
            Self::Bfg => "bfg",
            Self::Psm => "psm",
            Self::Semantic => "semantic",
            Self::StateEffect => "state-effect",
            Self::SemanticConformance => "semantic-conformance",
            Self::InformationFlow => "information-flow",
            Self::Environmental => "environmental",
            Self::RealizedBfg => "realized-bfg",
            Self::References => "references",
            Self::SourceArtifacts => "source-artifacts",
            Self::Audit => "audit",
        }
    }
}

/// One exact input to a reusable projection unit.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProjectionDependency {
    id: String,
    digest: String,
}

impl ProjectionDependency {
    /// Creates one stable input binding.
    ///
    /// # Errors
    ///
    /// Returns an error for empty identity or malformed digest.
    pub fn new(
        id: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, AffectedAnalysisError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(AffectedAnalysisError::InvalidUnitIdentity(id));
        }
        let digest = digest.into();
        validate_digest(&digest)?;
        Ok(Self { id, digest })
    }

    /// Returns the stable dependency identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact dependency digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Complete cache identity for one canonical projection computation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionCacheKey {
    kind: ProjectionKind,
    generator: String,
    generator_version: String,
    dependencies: Vec<ProjectionDependency>,
    digest: String,
}

#[derive(Serialize)]
struct ProjectionKeyMaterial<'a> {
    kind: ProjectionKind,
    generator: &'a str,
    generator_version: &'a str,
    dependencies: &'a [ProjectionDependency],
}

impl ProjectionCacheKey {
    /// Creates a canonical key bound to every declared dependency.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate dependencies or serialization failure.
    pub fn new(
        kind: ProjectionKind,
        generator: impl Into<String>,
        generator_version: impl Into<String>,
        mut dependencies: Vec<ProjectionDependency>,
    ) -> Result<Self, AffectedAnalysisError> {
        dependencies.sort();
        reject_duplicates(
            dependencies.iter().map(|dependency| dependency.id.as_str()),
            "projection dependency",
        )?;
        let generator = generator.into();
        let generator_version = generator_version.into();
        let digest = sha256(
            &serde_json::to_vec(&ProjectionKeyMaterial {
                kind,
                generator: &generator,
                generator_version: &generator_version,
                dependencies: &dependencies,
            })
            .map_err(AffectedAnalysisError::Serialization)?,
        );
        Ok(Self {
            kind,
            generator,
            generator_version,
            dependencies,
            digest,
        })
    }

    /// Returns the projection kind.
    #[must_use]
    pub const fn kind(&self) -> ProjectionKind {
        self.kind
    }

    /// Returns the complete semantic dependency digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns exact dependency bindings.
    #[must_use]
    pub fn dependencies(&self) -> &[ProjectionDependency] {
        &self.dependencies
    }
}

/// Machine-local cache state for one requested dependency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncrementalCacheState {
    /// Exact dependency-bound bytes were verified.
    ReusableCurrent,
    /// A prior key exists but does not match current dependencies.
    Stale,
    /// No materialized unit exists.
    Missing,
    /// Materialized metadata or content failed verification.
    Invalid,
}

/// Verified cache lookup result.
#[derive(Debug, Eq, PartialEq)]
pub struct CachedProjection {
    state: IncrementalCacheState,
    content: Option<Vec<u8>>,
    exit_code: Option<u8>,
}

impl CachedProjection {
    /// Returns the truthful cache state.
    #[must_use]
    pub const fn state(&self) -> IncrementalCacheState {
        self.state
    }

    /// Returns verified canonical bytes only for a current entry.
    #[must_use]
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    /// Returns the original semantic command exit code when current.
    #[must_use]
    pub const fn exit_code(&self) -> Option<u8> {
        self.exit_code
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CacheDescriptor {
    schema_version: u16,
    key: ProjectionCacheKey,
    artifact_digest: String,
    bytes: u64,
    exit_code: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CacheIndex {
    schema_version: u16,
    latest_dependency_digest: String,
}

/// Verified machine-local content-addressed projection cache.
#[derive(Clone, Debug)]
pub struct IncrementalProjectionCache {
    base: PathBuf,
    project: String,
}

impl IncrementalProjectionCache {
    /// Resolves the existing Fortress derived-cache boundary for one project.
    ///
    /// `FORTRESS_DERIVED_CACHE_DIR` overrides the system temporary base. The
    /// resolved machine path never enters a cache key or semantic artifact.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe project cache segment.
    pub fn from_environment(project: impl Into<String>) -> Result<Self, AffectedAnalysisError> {
        let base = env::var_os("FORTRESS_DERIVED_CACHE_DIR")
            .map_or_else(|| env::temp_dir().join("fortress-derived"), PathBuf::from);
        Self::new(base, project)
    }

    /// Creates a cache rooted at an explicit execution-local directory.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe project cache segment.
    pub fn new(
        base: impl Into<PathBuf>,
        project: impl Into<String>,
    ) -> Result<Self, AffectedAnalysisError> {
        let project = project.into();
        if project.is_empty()
            || !project
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AffectedAnalysisError::InvalidCacheProject(project));
        }
        Ok(Self {
            base: base.into(),
            project,
        })
    }

    /// Loads and verifies one exact dependency-bound projection.
    ///
    /// # Errors
    ///
    /// Returns only machine I/O errors. Malformed entries are reported as
    /// [`IncrementalCacheState::Invalid`] rather than trusted.
    pub fn load(
        &self,
        key: &ProjectionCacheKey,
    ) -> Result<CachedProjection, AffectedAnalysisError> {
        let directory = self.key_directory(key);
        let descriptor_path = directory.join("descriptor.json");
        let content_path = directory.join("artifact.json");
        if !descriptor_path.is_file() || !content_path.is_file() {
            let state =
                self.latest_key(key.kind())
                    .map_or(IncrementalCacheState::Missing, |latest| {
                        if latest == key.digest {
                            IncrementalCacheState::Invalid
                        } else {
                            IncrementalCacheState::Stale
                        }
                    });
            return Ok(CachedProjection {
                state,
                content: None,
                exit_code: None,
            });
        }
        let descriptor_bytes =
            fs::read(&descriptor_path).map_err(|source| AffectedAnalysisError::Io {
                operation: "read cache descriptor",
                path: descriptor_path.clone(),
                source,
            })?;
        let descriptor = serde_json::from_slice::<CacheDescriptor>(&descriptor_bytes);
        let Ok(descriptor) = descriptor else {
            return Ok(invalid_cache());
        };
        let expected_descriptor = canonical_json(&descriptor)
            .map_err(AffectedAnalysisError::Serialization)?
            .into_bytes();
        if descriptor_bytes != expected_descriptor || descriptor.key != *key {
            return Ok(invalid_cache());
        }
        let content = fs::read(&content_path).map_err(|source| AffectedAnalysisError::Io {
            operation: "read cached projection",
            path: content_path,
            source,
        })?;
        if u64::try_from(content.len()).ok() != Some(descriptor.bytes)
            || sha256(&content) != descriptor.artifact_digest
        {
            return Ok(invalid_cache());
        }
        Ok(CachedProjection {
            state: IncrementalCacheState::ReusableCurrent,
            content: Some(content),
            exit_code: Some(descriptor.exit_code),
        })
    }

    /// Stores one canonical projection under its complete dependency key.
    ///
    /// # Errors
    ///
    /// Returns an error when machine-local materialization cannot be written.
    pub fn store(
        &self,
        key: &ProjectionCacheKey,
        content: &[u8],
        exit_code: u8,
    ) -> Result<(), AffectedAnalysisError> {
        let directory = self.key_directory(key);
        fs::create_dir_all(&directory).map_err(|source| AffectedAnalysisError::Io {
            operation: "create incremental cache directory",
            path: directory.clone(),
            source,
        })?;
        let descriptor = CacheDescriptor {
            schema_version: 1,
            key: key.clone(),
            artifact_digest: sha256(content),
            bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
            exit_code,
        };
        atomic_write(&directory.join("artifact.json"), content)?;
        atomic_write(
            &directory.join("descriptor.json"),
            canonical_json(&descriptor)
                .map_err(AffectedAnalysisError::Serialization)?
                .as_bytes(),
        )?;
        let index = CacheIndex {
            schema_version: 1,
            latest_dependency_digest: key.digest.clone(),
        };
        atomic_write(
            &self.kind_directory(key.kind()).join("current.json"),
            canonical_json(&index)
                .map_err(AffectedAnalysisError::Serialization)?
                .as_bytes(),
        )
    }

    fn project_directory(&self) -> PathBuf {
        self.base.join(&self.project).join("incremental-v1")
    }

    fn kind_directory(&self, kind: ProjectionKind) -> PathBuf {
        self.project_directory().join(kind.as_str())
    }

    fn key_directory(&self, key: &ProjectionCacheKey) -> PathBuf {
        self.kind_directory(key.kind())
            .join(key.digest.trim_start_matches("sha256:"))
    }

    fn latest_key(&self, kind: ProjectionKind) -> Option<String> {
        let bytes = fs::read(self.kind_directory(kind).join("current.json")).ok()?;
        let index: CacheIndex = serde_json::from_slice(&bytes).ok()?;
        (index.schema_version == 1).then_some(index.latest_dependency_digest)
    }
}

fn invalid_cache() -> CachedProjection {
    CachedProjection {
        state: IncrementalCacheState::Invalid,
        content: None,
        exit_code: None,
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), AffectedAnalysisError> {
    let parent = path
        .parent()
        .ok_or_else(|| AffectedAnalysisError::InvalidCachePath(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| AffectedAnalysisError::Io {
        operation: "create cache parent",
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = path.with_extension("pending");
    fs::write(&temporary, content).map_err(|source| AffectedAnalysisError::Io {
        operation: "write cache temporary",
        path: temporary.clone(),
        source,
    })?;
    if path.exists() {
        fs::remove_file(path).map_err(|source| AffectedAnalysisError::Io {
            operation: "replace cache entry",
            path: path.to_path_buf(),
            source,
        })?;
    }
    fs::rename(&temporary, path).map_err(|source| AffectedAnalysisError::Io {
        operation: "commit cache entry",
        path: path.to_path_buf(),
        source,
    })
}

fn reject_duplicates<'a>(
    values: impl IntoIterator<Item = &'a str>,
    class: &'static str,
) -> Result<(), AffectedAnalysisError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(AffectedAnalysisError::DuplicateIdentity {
                class,
                identity: value.to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), AffectedAnalysisError> {
    if path.is_empty()
        || path.contains('\\')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(AffectedAnalysisError::InvalidRepositoryPath(path.into()));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), AffectedAnalysisError> {
    let value = digest.strip_prefix("sha256:");
    if value.is_none_or(|value| {
        value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(AffectedAnalysisError::InvalidDigest(digest.into()));
    }
    Ok(())
}

fn canonical_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value).map(|mut output| {
        output.push('\n');
        output
    })
}

/// Computes canonical SHA-256 identity for exact bytes.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Affected-analysis or incremental-cache construction failure.
#[derive(Debug)]
pub enum AffectedAnalysisError {
    /// A repository path was not canonical and relative.
    InvalidRepositoryPath(String),
    /// A SHA-256 identity was malformed.
    InvalidDigest(String),
    /// A stable unit identity was empty or malformed.
    InvalidUnitIdentity(String),
    /// A unit depended on itself.
    SelfDependency(String),
    /// A unit repeated a direct dependency.
    DuplicateDependency(String),
    /// A canonical identity was duplicated.
    DuplicateIdentity {
        /// Identity class.
        class: &'static str,
        /// Repeated identity.
        identity: String,
    },
    /// A unit referenced an absent dependency.
    UnresolvedDependency {
        /// Dependent unit.
        unit: String,
        /// Missing dependency.
        dependency: String,
    },
    /// Project cache segment was unsafe.
    InvalidCacheProject(String),
    /// Cache path could not be safely resolved.
    InvalidCachePath(PathBuf),
    /// Canonical data could not be serialized.
    Serialization(serde_json::Error),
    /// Execution-local cache I/O failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Exact machine-local path, reported only at runtime.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

impl Display for AffectedAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRepositoryPath(path) => {
                write!(
                    formatter,
                    "repository path is not canonical and relative: {path}"
                )
            }
            Self::InvalidDigest(digest) => write!(formatter, "invalid SHA-256 identity: {digest}"),
            Self::InvalidUnitIdentity(identity) => {
                write!(formatter, "invalid affected unit identity: {identity}")
            }
            Self::SelfDependency(identity) => {
                write!(formatter, "affected unit depends on itself: {identity}")
            }
            Self::DuplicateDependency(identity) => {
                write!(formatter, "affected unit repeats a dependency: {identity}")
            }
            Self::DuplicateIdentity { class, identity } => {
                write!(formatter, "duplicate {class} identity: {identity}")
            }
            Self::UnresolvedDependency { unit, dependency } => {
                write!(
                    formatter,
                    "affected unit `{unit}` references absent `{dependency}`"
                )
            }
            Self::InvalidCacheProject(project) => {
                write!(
                    formatter,
                    "invalid incremental cache project segment: {project}"
                )
            }
            Self::InvalidCachePath(path) => {
                write!(
                    formatter,
                    "invalid incremental cache path: {}",
                    path.display()
                )
            }
            Self::Serialization(error) => {
                write!(formatter, "affected analysis serialization failed: {error}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} `{}` failed: {source}",
                path.display()
            ),
        }
    }
}

impl Error for AffectedAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
