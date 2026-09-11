//! Deterministic non-normative interpretation of coherent architecture facts.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::architecture_realization::{ArchitectureRealization, ReconciliationState};
use crate::contract_coherency::{
    CapabilityVisibility, ContractCoherencyGraph, ModuleRelationshipType,
};
use crate::implementation_observation::{
    ObservationIssueKind, ObservationProvenance, ObservedImplementation,
};

/// Structural interpretations implemented by Semantic Architecture Diagnostics v1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchitectureDiagnosticKind {
    /// A nested provider serves production consumers beyond its parent scope.
    CrossScopeProvider,
    /// A consumer directly couples to multiple descendants of one foreign composite.
    FragmentedForeignSurface,
    /// An internal provider currently has no governed production consumer.
    IsolatedInternalProvider,
    /// Current internal consumers share a scope narrower than the provider's parent.
    NarrowerConsumerScope,
}

impl ArchitectureDiagnosticKind {
    /// Returns the canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrossScopeProvider => "CROSS_SCOPE_PROVIDER",
            Self::FragmentedForeignSurface => "FRAGMENTED_FOREIGN_SURFACE",
            Self::IsolatedInternalProvider => "ISOLATED_INTERNAL_PROVIDER",
            Self::NarrowerConsumerScope => "NARROWER_CONSUMER_SCOPE",
        }
    }
}

/// Authority class behind one diagnostic source fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticAuthority {
    /// Authored Contract v2 fact.
    Contract,
    /// Physical recursive Module containment fact.
    Filesystem,
    /// Snapshot-bound implementation observation.
    Source,
}

/// Canonical source location contributing to a diagnostic conclusion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DiagnosticProvenance {
    authority: DiagnosticAuthority,
    path: String,
    location: String,
}

impl DiagnosticProvenance {
    fn contract(path: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            authority: DiagnosticAuthority::Contract,
            path: path.into(),
            location: pointer.into(),
        }
    }

    fn filesystem(path: impl Into<String>) -> Self {
        Self {
            authority: DiagnosticAuthority::Filesystem,
            path: path.into(),
            location: "module_containment".into(),
        }
    }

    fn source(evidence: &ObservationProvenance) -> Self {
        Self {
            authority: DiagnosticAuthority::Source,
            path: evidence.source_path().into(),
            location: format!(
                "line:{},column:{}",
                evidence.location().line(),
                evidence.location().column()
            ),
        }
    }

    /// Returns the governing authority class.
    #[must_use]
    pub const fn authority(&self) -> DiagnosticAuthority {
        self.authority
    }

    /// Returns the repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the JSON pointer or derived semantic source location.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }
}

/// Normalized authored evidence for one direct capability dependency.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeclaredDependencyEvidence {
    consumer: String,
    provider: String,
    capabilities: Vec<String>,
    provenance: Vec<DiagnosticProvenance>,
}

impl DeclaredDependencyEvidence {
    /// Returns the authored consumer Module.
    #[must_use]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    /// Returns the exact provider Module.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns every capability authorizing the normalized Module edge.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns exact contract source locations.
    #[must_use]
    pub fn provenance(&self) -> &[DiagnosticProvenance] {
        &self.provenance
    }
}

/// One capability included in a derived Module profile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProfileCapability {
    id: String,
    version: String,
    visibility: CapabilityVisibility,
}

impl ProfileCapability {
    /// Returns the capability identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns its exact provided version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns project or public visibility.
    #[must_use]
    pub const fn visibility(&self) -> CapabilityVisibility {
        self.visibility
    }
}

/// Deterministic production-only architecture profile for one Module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModuleArchitectureProfile {
    module_id: String,
    path: String,
    depth: usize,
    physical_parent: Option<String>,
    children: Vec<String>,
    descendants: Vec<String>,
    local_feature_count: usize,
    provided_capabilities: Vec<ProfileCapability>,
    declared_production_dependencies: Vec<String>,
    declared_production_consumers: Vec<String>,
    observed_production_dependencies: Vec<String>,
    observed_production_consumers: Vec<String>,
    direct_dependency_count: usize,
    direct_consumer_count: usize,
    transitive_reachability_count: usize,
    external_observation_count: usize,
    unresolved_or_unsupported_observation_count: usize,
    consumer_lowest_common_ancestor: Option<String>,
}

impl ModuleArchitectureProfile {
    /// Returns the profiled Module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the canonical Module path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns physical Module depth, where the repository root is zero.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the physical parent inferred from containment.
    #[must_use]
    pub fn physical_parent(&self) -> Option<&str> {
        self.physical_parent.as_deref()
    }

    /// Returns immediate production children, excluding Testing Modules.
    #[must_use]
    pub fn children(&self) -> &[String] {
        &self.children
    }

    /// Returns all production descendants, excluding Testing Modules.
    #[must_use]
    pub fn descendants(&self) -> &[String] {
        &self.descendants
    }

    /// Returns Features owned directly at this Module boundary.
    #[must_use]
    pub const fn local_feature_count(&self) -> usize {
        self.local_feature_count
    }

    /// Returns directly provided capabilities and visibility.
    #[must_use]
    pub fn provided_capabilities(&self) -> &[ProfileCapability] {
        &self.provided_capabilities
    }

    /// Returns declared direct production dependencies.
    #[must_use]
    pub fn declared_production_dependencies(&self) -> &[String] {
        &self.declared_production_dependencies
    }

    /// Returns declared direct production consumers.
    #[must_use]
    pub fn declared_production_consumers(&self) -> &[String] {
        &self.declared_production_consumers
    }

    /// Returns observed direct governed production dependencies.
    #[must_use]
    pub fn observed_production_dependencies(&self) -> &[String] {
        &self.observed_production_dependencies
    }

    /// Returns observed direct governed production consumers.
    #[must_use]
    pub fn observed_production_consumers(&self) -> &[String] {
        &self.observed_production_consumers
    }

    /// Returns the union count of declared and observed direct dependencies.
    #[must_use]
    pub const fn direct_dependency_count(&self) -> usize {
        self.direct_dependency_count
    }

    /// Returns the union count of declared and observed direct consumers.
    #[must_use]
    pub const fn direct_consumer_count(&self) -> usize {
        self.direct_consumer_count
    }

    /// Returns declared production dependency reachability count.
    #[must_use]
    pub const fn transitive_reachability_count(&self) -> usize {
        self.transitive_reachability_count
    }

    /// Returns normalized external targets observed from this Module.
    #[must_use]
    pub const fn external_observation_count(&self) -> usize {
        self.external_observation_count
    }

    /// Returns explicit unresolved references and unsupported analyzer issues.
    #[must_use]
    pub const fn unresolved_or_unsupported_observation_count(&self) -> usize {
        self.unresolved_or_unsupported_observation_count
    }

    /// Returns the LCA of all declared or observed production consumers.
    #[must_use]
    pub fn consumer_lowest_common_ancestor(&self) -> Option<&str> {
        self.consumer_lowest_common_ancestor.as_deref()
    }
}

/// One evidence-backed interpretation that is not a standard finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArchitectureDiagnostic {
    kind: ArchitectureDiagnosticKind,
    primary_module: String,
    related_modules: Vec<String>,
    summary: String,
    reasoning: Vec<String>,
    declared_evidence: Vec<DeclaredDependencyEvidence>,
    observed_evidence: Vec<ObservationProvenance>,
    candidate_structural_scope: Option<String>,
    provenance: Vec<DiagnosticProvenance>,
    fingerprint: String,
}

impl ArchitectureDiagnostic {
    /// Returns the diagnostic kind.
    #[must_use]
    pub const fn kind(&self) -> ArchitectureDiagnosticKind {
        self.kind
    }

    /// Returns its primary Module subject.
    #[must_use]
    pub fn primary_module(&self) -> &str {
        &self.primary_module
    }

    /// Returns other Module subjects in canonical order.
    #[must_use]
    pub fn related_modules(&self) -> &[String] {
        &self.related_modules
    }

    /// Returns the concise deterministic interpretation.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Returns the complete deterministic derivation chain.
    #[must_use]
    pub fn reasoning(&self) -> &[String] {
        &self.reasoning
    }

    /// Returns normalized authored dependency evidence.
    #[must_use]
    pub fn declared_evidence(&self) -> &[DeclaredDependencyEvidence] {
        &self.declared_evidence
    }

    /// Returns exact snapshot-bound source evidence.
    #[must_use]
    pub fn observed_evidence(&self) -> &[ObservationProvenance] {
        &self.observed_evidence
    }

    /// Returns an evidence-derived candidate scope, never a placement decision.
    #[must_use]
    pub fn candidate_structural_scope(&self) -> Option<&str> {
        self.candidate_structural_scope.as_deref()
    }

    /// Returns source-provenance closure for the conclusion.
    #[must_use]
    pub fn provenance(&self) -> &[DiagnosticProvenance] {
        &self.provenance
    }

    /// Returns the content-addressed diagnostic identity.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl Ord for ArchitectureDiagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.primary_module.cmp(&other.primary_module))
            .then_with(|| self.related_modules.cmp(&other.related_modules))
            .then_with(|| self.fingerprint.cmp(&other.fingerprint))
    }
}

impl PartialOrd for ArchitectureDiagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Profiles, diagnostics, Testing separation, and epistemic boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureDiagnostics {
    profiles: BTreeMap<String, ModuleArchitectureProfile>,
    diagnostics: Vec<ArchitectureDiagnostic>,
    testing_modules: Vec<String>,
    unsupported_analysis: Vec<String>,
}

impl ArchitectureDiagnostics {
    /// Returns production Module profiles keyed by identity.
    #[must_use]
    pub const fn profiles(&self) -> &BTreeMap<String, ModuleArchitectureProfile> {
        &self.profiles
    }

    /// Returns non-normative diagnostics in canonical order.
    #[must_use]
    pub fn diagnostics(&self) -> &[ArchitectureDiagnostic] {
        &self.diagnostics
    }

    /// Returns Modules excluded as verification topology.
    #[must_use]
    pub fn testing_modules(&self) -> &[String] {
        &self.testing_modules
    }

    /// Returns semantic conclusions deliberately unsupported by diagnostics v1.
    #[must_use]
    pub fn unsupported_analysis(&self) -> &[String] {
        &self.unsupported_analysis
    }
}

/// Error while content-addressing a deterministic diagnostic.
#[derive(Debug)]
pub struct ArchitectureDiagnosticError {
    source: serde_json::Error,
}

impl Display for ArchitectureDiagnosticError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "architecture diagnostic serialization failed: {}",
            self.source
        )
    }
}

impl Error for ArchitectureDiagnosticError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Returns the lowest common physical Module ancestor of a nonempty valid set.
///
/// Empty input or an unknown Module identity returns `None`.
#[must_use]
pub fn lowest_common_module_ancestor<'a>(
    ccg: &ContractCoherencyGraph,
    modules: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    let mut modules = modules.into_iter();
    let first = modules.next()?;
    let mut common = ancestor_chain(ccg, first)?;
    for module in modules {
        let chain = ancestor_chain(ccg, module)?;
        let shared = common
            .iter()
            .zip(&chain)
            .take_while(|(left, right)| left == right)
            .count();
        common.truncate(shared);
        if common.is_empty() {
            return None;
        }
    }
    common.last().cloned()
}

/// Derives production profiles and non-normative architecture diagnostics.
///
/// # Errors
///
/// Returns [`ArchitectureDiagnosticError`] if deterministic fingerprint input
/// cannot be serialized.
pub fn derive_architecture_diagnostics(
    ccg: &ContractCoherencyGraph,
    observed: &ObservedImplementation,
    realization: &ArchitectureRealization,
) -> Result<ArchitectureDiagnostics, ArchitectureDiagnosticError> {
    let context = DiagnosticContext::new(ccg, observed, realization);
    let profiles = build_profiles(&context);
    let mut diagnostics = Vec::new();
    diagnostics.extend(cross_scope_diagnostics(&context, &profiles)?);
    diagnostics.extend(fragmented_surface_diagnostics(&context, &profiles)?);
    diagnostics.extend(isolated_provider_diagnostics(&context, &profiles)?);
    diagnostics.extend(narrower_scope_diagnostics(&context, &profiles)?);
    diagnostics.sort();
    diagnostics.dedup();
    Ok(ArchitectureDiagnostics {
        profiles,
        diagnostics,
        testing_modules: context.testing.iter().cloned().collect(),
        unsupported_analysis: vec![
            "automatic_restructuring_correctness".into(),
            "capability_to_symbol_realization".into(),
            "external_consumer_completeness_for_public_capabilities".into(),
            "natural_language_architecture_semantics".into(),
        ],
    })
}

type EdgeMap = BTreeMap<String, BTreeSet<String>>;
type DeclaredEvidenceMap =
    BTreeMap<(String, String), (BTreeSet<String>, BTreeSet<DiagnosticProvenance>)>;
type ObservedEvidenceMap = BTreeMap<(String, String), Vec<ObservationProvenance>>;

struct DiagnosticContext<'a> {
    ccg: &'a ContractCoherencyGraph,
    observed: &'a ObservedImplementation,
    realization: &'a ArchitectureRealization,
    testing: BTreeSet<String>,
    production: BTreeSet<String>,
    declared_dependencies: EdgeMap,
    declared_consumers: EdgeMap,
    observed_dependencies: EdgeMap,
    observed_consumers: EdgeMap,
    declared_evidence: DeclaredEvidenceMap,
    observed_evidence: ObservedEvidenceMap,
}

impl<'a> DiagnosticContext<'a> {
    fn new(
        ccg: &'a ContractCoherencyGraph,
        observed: &'a ObservedImplementation,
        realization: &'a ArchitectureRealization,
    ) -> Self {
        let testing: BTreeSet<String> = ccg
            .relationships()
            .iter()
            .filter(|relationship| relationship.kind() == ModuleRelationshipType::Verifies)
            .map(|relationship| relationship.source().to_owned())
            .collect();
        let production: BTreeSet<String> = ccg
            .modules()
            .keys()
            .filter(|module| !testing.contains(module.as_str()))
            .cloned()
            .collect();
        let (declared_dependencies, declared_consumers, declared_evidence) =
            declared_topology(ccg, &production);
        let (observed_dependencies, observed_consumers, observed_evidence) =
            observed_topology(observed, &production);
        Self {
            ccg,
            observed,
            realization,
            testing,
            production,
            declared_dependencies,
            declared_consumers,
            observed_dependencies,
            observed_consumers,
            declared_evidence,
            observed_evidence,
        }
    }
}

fn declared_topology(
    ccg: &ContractCoherencyGraph,
    production: &BTreeSet<String>,
) -> (EdgeMap, EdgeMap, DeclaredEvidenceMap) {
    let mut dependencies = EdgeMap::new();
    let mut consumers = EdgeMap::new();
    let mut evidence = DeclaredEvidenceMap::new();
    for requirement in ccg.direct_requirements() {
        if !production.contains(requirement.consumer())
            || !production.contains(requirement.provider())
        {
            continue;
        }
        dependencies
            .entry(requirement.consumer().into())
            .or_default()
            .insert(requirement.provider().into());
        consumers
            .entry(requirement.provider().into())
            .or_default()
            .insert(requirement.consumer().into());
        let entry = evidence
            .entry((requirement.consumer().into(), requirement.provider().into()))
            .or_default();
        entry.0.insert(requirement.capability().into());
        entry.1.insert(DiagnosticProvenance::contract(
            requirement.provenance().contract_path(),
            requirement.provenance().pointer(),
        ));
    }
    (dependencies, consumers, evidence)
}

fn observed_topology(
    observed: &ObservedImplementation,
    production: &BTreeSet<String>,
) -> (EdgeMap, EdgeMap, ObservedEvidenceMap) {
    let mut dependencies = EdgeMap::new();
    let mut consumers = EdgeMap::new();
    let mut evidence = ObservedEvidenceMap::new();
    for dependency in observed.module_dependencies() {
        if !production.contains(dependency.source_module())
            || !production.contains(dependency.target_module())
        {
            continue;
        }
        dependencies
            .entry(dependency.source_module().into())
            .or_default()
            .insert(dependency.target_module().into());
        consumers
            .entry(dependency.target_module().into())
            .or_default()
            .insert(dependency.source_module().into());
        evidence.insert(
            (
                dependency.source_module().into(),
                dependency.target_module().into(),
            ),
            dependency.evidence().to_vec(),
        );
    }
    (dependencies, consumers, evidence)
}

fn build_profiles(context: &DiagnosticContext<'_>) -> BTreeMap<String, ModuleArchitectureProfile> {
    let coverage = coverage_counts(context);
    context
        .production
        .iter()
        .map(|module| {
            let declared_dependencies = edge_values(&context.declared_dependencies, module);
            let declared_consumers = edge_values(&context.declared_consumers, module);
            let observed_dependencies = edge_values(&context.observed_dependencies, module);
            let observed_consumers = edge_values(&context.observed_consumers, module);
            let all_dependencies = union(&declared_dependencies, &observed_dependencies);
            let all_consumers = union(&declared_consumers, &observed_consumers);
            let resolved = &context.ccg.modules()[module];
            let capabilities = resolved
                .contract()
                .provides()
                .iter()
                .map(|capability| ProfileCapability {
                    id: capability.id().into(),
                    version: capability.version().into(),
                    visibility: capability.visibility(),
                })
                .collect();
            let children: Vec<String> = context
                .production
                .iter()
                .filter(|candidate| {
                    context
                        .ccg
                        .containment()
                        .get(candidate.as_str())
                        .and_then(Option::as_deref)
                        == Some(module)
                })
                .cloned()
                .collect();
            let descendants: Vec<String> = context
                .production
                .iter()
                .filter(|candidate| {
                    candidate.as_str() != module
                        && is_descendant_or_same(context.ccg, candidate, module)
                })
                .cloned()
                .collect();
            let (external, unsupported) = coverage.get(module).copied().unwrap_or_default();
            let profile = ModuleArchitectureProfile {
                module_id: module.clone(),
                path: resolved.path().into(),
                depth: module_depth(context.ccg, module),
                physical_parent: resolved.parent_id().map(str::to_owned),
                children,
                descendants,
                local_feature_count: resolved.contract().features().len(),
                provided_capabilities: capabilities,
                declared_production_dependencies: declared_dependencies,
                declared_production_consumers: declared_consumers,
                observed_production_dependencies: observed_dependencies,
                observed_production_consumers: observed_consumers,
                direct_dependency_count: all_dependencies.len(),
                direct_consumer_count: all_consumers.len(),
                transitive_reachability_count: reachable_dependencies(
                    module,
                    &context.declared_dependencies,
                )
                .len(),
                external_observation_count: external,
                unresolved_or_unsupported_observation_count: unsupported,
                consumer_lowest_common_ancestor: lowest_common_module_ancestor(
                    context.ccg,
                    all_consumers.iter().map(String::as_str),
                ),
            };
            (module.clone(), profile)
        })
        .collect()
}

fn coverage_counts(context: &DiagnosticContext<'_>) -> BTreeMap<String, (usize, usize)> {
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for record in context.realization.records() {
        if !context.production.contains(record.source_module()) {
            continue;
        }
        let entry = counts.entry(record.source_module().into()).or_default();
        match record.state() {
            ReconciliationState::External => entry.0 += 1,
            ReconciliationState::Unresolved => entry.1 += 1,
            _ => {}
        }
    }
    for issue in context.observed.issues() {
        if issue.kind() != ObservationIssueKind::Unsupported {
            continue;
        }
        if let Some(owner) = source_owner(context, issue.source_path()) {
            counts.entry(owner).or_default().1 += 1;
        }
    }
    counts
}

fn source_owner(context: &DiagnosticContext<'_>, path: &str) -> Option<String> {
    context
        .production
        .iter()
        .filter_map(|module| {
            let module_path = context.ccg.modules()[module].path();
            contains_path(module_path, path).then_some((module_path.len(), module.clone()))
        })
        .max()
        .map(|(_, module)| module)
}

fn cross_scope_diagnostics(
    context: &DiagnosticContext<'_>,
    profiles: &BTreeMap<String, ModuleArchitectureProfile>,
) -> Result<Vec<ArchitectureDiagnostic>, ArchitectureDiagnosticError> {
    let mut output = Vec::new();
    for profile in profiles.values() {
        let Some(parent) = profile.physical_parent() else {
            continue;
        };
        if !profile
            .provided_capabilities()
            .iter()
            .any(|capability| capability.visibility() == CapabilityVisibility::Project)
        {
            continue;
        }
        let consumers = profile_consumers(profile);
        let outside: Vec<String> = consumers
            .iter()
            .filter(|consumer| !is_descendant_or_same(context.ccg, consumer, parent))
            .cloned()
            .collect();
        if outside.is_empty() {
            continue;
        }
        let lca = lowest_common_module_ancestor(
            context.ccg,
            std::iter::once(profile.module_id()).chain(consumers.iter().map(String::as_str)),
        );
        let mut related = outside.clone();
        related.push(parent.into());
        output.push(make_diagnostic(
            context,
            DiagnosticDraft {
                kind: ArchitectureDiagnosticKind::CrossScopeProvider,
                primary: profile.module_id().into(),
                related,
                summary: format!(
                    "Provider {} serves production consumers outside physical parent scope {}.",
                    profile.module_id(),
                    parent
                ),
                reasoning: vec![
                    format!(
                        "{} is physically contained by {}.",
                        profile.module_id(),
                        parent
                    ),
                    format!(
                        "Project-visible capabilities: {}.",
                        project_capabilities(profile).join(", ")
                    ),
                    format!("Outside production consumers: {}.", outside.join(", ")),
                    format!(
                        "The physical LCA of provider and all production consumers is {}.",
                        lca.as_deref().unwrap_or("unresolved")
                    ),
                ],
                declared_evidence: incoming_declared_evidence(
                    context,
                    profile.module_id(),
                    &outside,
                ),
                observed_evidence: incoming_observed_evidence(
                    context,
                    profile.module_id(),
                    &outside,
                ),
                candidate: lca,
                provenance: vec![containment_provenance(context, profile.module_id())],
                capability_modules: vec![profile.module_id().into()],
            },
        )?);
    }
    Ok(output)
}

fn narrower_scope_diagnostics(
    context: &DiagnosticContext<'_>,
    profiles: &BTreeMap<String, ModuleArchitectureProfile>,
) -> Result<Vec<ArchitectureDiagnostic>, ArchitectureDiagnosticError> {
    let mut output = Vec::new();
    for profile in profiles.values() {
        let Some(parent) = profile.physical_parent() else {
            continue;
        };
        if profile.provided_capabilities().is_empty()
            || profile
                .provided_capabilities()
                .iter()
                .any(|capability| capability.visibility() == CapabilityVisibility::Public)
        {
            continue;
        }
        let consumers = profile_consumers(profile);
        if consumers.is_empty()
            || consumers
                .iter()
                .any(|consumer| is_descendant_or_same(context.ccg, consumer, profile.module_id()))
        {
            continue;
        }
        let Some(candidate) =
            lowest_common_module_ancestor(context.ccg, consumers.iter().map(String::as_str))
        else {
            continue;
        };
        if module_depth(context.ccg, &candidate) <= module_depth(context.ccg, parent) {
            continue;
        }
        output.push(make_diagnostic(
            context,
            DiagnosticDraft {
                kind: ArchitectureDiagnosticKind::NarrowerConsumerScope,
                primary: profile.module_id().into(),
                related: consumers.clone(),
                summary: format!(
                    "Current internal consumers of {} share candidate structural scope {}.",
                    profile.module_id(), candidate
                ),
                reasoning: vec![
                    format!("Current physical parent scope: {parent}."),
                    format!("Production consumers: {}.", consumers.join(", ")),
                    format!("Their physical lowest common Module ancestor is {candidate}."),
                    "Every provided capability is project-visible; external consumers are not implied."
                        .into(),
                    "The candidate is evidence-derived and is not asserted to be the correct location."
                        .into(),
                ],
                declared_evidence: incoming_declared_evidence(
                    context,
                    profile.module_id(),
                    &consumers,
                ),
                observed_evidence: incoming_observed_evidence(
                    context,
                    profile.module_id(),
                    &consumers,
                ),
                candidate: Some(candidate),
                provenance: vec![containment_provenance(context, profile.module_id())],
                capability_modules: vec![profile.module_id().into()],
            },
        )?);
    }
    Ok(output)
}

fn isolated_provider_diagnostics(
    context: &DiagnosticContext<'_>,
    profiles: &BTreeMap<String, ModuleArchitectureProfile>,
) -> Result<Vec<ArchitectureDiagnostic>, ArchitectureDiagnosticError> {
    let mut output = Vec::new();
    for profile in profiles.values() {
        if profile.physical_parent().is_none()
            || profile.provided_capabilities().is_empty()
            || profile
                .provided_capabilities()
                .iter()
                .any(|capability| capability.visibility() == CapabilityVisibility::Public)
            || !profile_consumers(profile).is_empty()
        {
            continue;
        }
        output.push(make_diagnostic(
            context,
            DiagnosticDraft {
                kind: ArchitectureDiagnosticKind::IsolatedInternalProvider,
                primary: profile.module_id().into(),
                related: Vec::new(),
                summary: format!(
                    "Internal provider {} has no declared or observed governed production consumer.",
                    profile.module_id()
                ),
                reasoning: vec![
                    format!(
                        "Project-visible capabilities: {}.",
                        project_capabilities(profile).join(", ")
                    ),
                    "Declared production consumer count is zero.".into(),
                    "Observed governed production consumer count is zero.".into(),
                    "This may represent stale, premature, dormant, or self-contained responsibility; it is not a dead-code conclusion."
                        .into(),
                ],
                declared_evidence: Vec::new(),
                observed_evidence: Vec::new(),
                candidate: None,
                provenance: vec![containment_provenance(context, profile.module_id())],
                capability_modules: vec![profile.module_id().into()],
            },
        )?);
    }
    Ok(output)
}

fn fragmented_surface_diagnostics(
    context: &DiagnosticContext<'_>,
    profiles: &BTreeMap<String, ModuleArchitectureProfile>,
) -> Result<Vec<ArchitectureDiagnostic>, ArchitectureDiagnosticError> {
    let mut output = Vec::new();
    for consumer in profiles.values() {
        let providers = profile_dependencies(consumer);
        if providers.len() < 2 {
            continue;
        }
        for foreign in profiles.values() {
            if foreign.children().is_empty()
                || (foreign.provided_capabilities().is_empty()
                    && foreign.local_feature_count() == 0)
                || is_descendant_or_same(context.ccg, consumer.module_id(), foreign.module_id())
            {
                continue;
            }
            let foreign_providers: Vec<String> = providers
                .iter()
                .filter(|provider| {
                    provider.as_str() != foreign.module_id()
                        && is_descendant_or_same(context.ccg, provider, foreign.module_id())
                })
                .cloned()
                .collect();
            if foreign_providers.len() < 2
                || lowest_common_module_ancestor(
                    context.ccg,
                    foreign_providers.iter().map(String::as_str),
                )
                .as_deref()
                    != Some(foreign.module_id())
            {
                continue;
            }
            let mut related = foreign_providers.clone();
            related.push(foreign.module_id().into());
            output.push(make_diagnostic(
                context,
                DiagnosticDraft {
                    kind: ArchitectureDiagnosticKind::FragmentedForeignSurface,
                    primary: consumer.module_id().into(),
                    related,
                    summary: format!(
                        "Consumer {} directly uses multiple descendant surfaces of foreign composite {}.",
                        consumer.module_id(),
                        foreign.module_id()
                    ),
                    reasoning: vec![
                        format!(
                            "Directly consumed proper descendants: {}.",
                            foreign_providers.join(", ")
                        ),
                        format!(
                            "Their physical lowest common Module ancestor is {}.",
                            foreign.module_id()
                        ),
                        format!(
                            "{} is outside the {} subtree.",
                            consumer.module_id(),
                            foreign.module_id()
                        ),
                        "The composite owns a Feature or capability, so its boundary may be a meaningful facade surface; authorized access remains diagnostic rather than invalid."
                            .into(),
                    ],
                    declared_evidence: outgoing_declared_evidence(
                        context,
                        consumer.module_id(),
                        &foreign_providers,
                    ),
                    observed_evidence: outgoing_observed_evidence(
                        context,
                        consumer.module_id(),
                        &foreign_providers,
                    ),
                    candidate: None,
                    provenance: vec![containment_provenance(context, foreign.module_id())],
                    capability_modules: vec![foreign.module_id().into()],
                },
            )?);
        }
    }
    Ok(output)
}

struct DiagnosticDraft {
    kind: ArchitectureDiagnosticKind,
    primary: String,
    related: Vec<String>,
    summary: String,
    reasoning: Vec<String>,
    declared_evidence: Vec<DeclaredDependencyEvidence>,
    observed_evidence: Vec<ObservationProvenance>,
    candidate: Option<String>,
    provenance: Vec<DiagnosticProvenance>,
    capability_modules: Vec<String>,
}

fn make_diagnostic(
    context: &DiagnosticContext<'_>,
    mut draft: DiagnosticDraft,
) -> Result<ArchitectureDiagnostic, ArchitectureDiagnosticError> {
    draft.related.sort();
    draft.related.dedup();
    for module in std::iter::once(draft.primary.as_str())
        .chain(draft.related.iter().map(String::as_str))
        .chain(draft.candidate.iter().map(String::as_str))
    {
        if context.ccg.modules().contains_key(module) {
            draft
                .provenance
                .push(containment_provenance(context, module));
        }
    }
    draft.provenance.extend(
        draft
            .declared_evidence
            .iter()
            .flat_map(|evidence| evidence.provenance().iter().cloned()),
    );
    draft.provenance.extend(
        draft
            .observed_evidence
            .iter()
            .map(DiagnosticProvenance::source),
    );
    for module in &draft.capability_modules {
        draft
            .provenance
            .extend(capability_provenance(context, module));
    }
    draft.provenance.sort();
    draft.provenance.dedup();
    let mut diagnostic = ArchitectureDiagnostic {
        kind: draft.kind,
        primary_module: draft.primary,
        related_modules: draft.related,
        summary: draft.summary,
        reasoning: draft.reasoning,
        declared_evidence: draft.declared_evidence,
        observed_evidence: draft.observed_evidence,
        candidate_structural_scope: draft.candidate,
        provenance: draft.provenance,
        fingerprint: String::new(),
    };
    diagnostic.fingerprint = diagnostic_fingerprint(&diagnostic)?;
    Ok(diagnostic)
}

#[derive(Serialize)]
struct DiagnosticFingerprintInput<'a> {
    kind: ArchitectureDiagnosticKind,
    primary_module: &'a str,
    related_modules: &'a [String],
    summary: &'a str,
    reasoning: &'a [String],
    declared_evidence: &'a [DeclaredDependencyEvidence],
    observed_evidence: &'a [ObservationProvenance],
    candidate_structural_scope: &'a Option<String>,
    provenance: &'a [DiagnosticProvenance],
}

fn diagnostic_fingerprint(
    diagnostic: &ArchitectureDiagnostic,
) -> Result<String, ArchitectureDiagnosticError> {
    let input = DiagnosticFingerprintInput {
        kind: diagnostic.kind,
        primary_module: &diagnostic.primary_module,
        related_modules: &diagnostic.related_modules,
        summary: &diagnostic.summary,
        reasoning: &diagnostic.reasoning,
        declared_evidence: &diagnostic.declared_evidence,
        observed_evidence: &diagnostic.observed_evidence,
        candidate_structural_scope: &diagnostic.candidate_structural_scope,
        provenance: &diagnostic.provenance,
    };
    let bytes =
        serde_json::to_vec(&input).map_err(|source| ArchitectureDiagnosticError { source })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn outgoing_declared_evidence(
    context: &DiagnosticContext<'_>,
    source: &str,
    targets: &[String],
) -> Vec<DeclaredDependencyEvidence> {
    targets
        .iter()
        .filter_map(|target| {
            let (capabilities, provenance) = context
                .declared_evidence
                .get(&(source.into(), target.clone()))?;
            Some(DeclaredDependencyEvidence {
                consumer: source.into(),
                provider: target.clone(),
                capabilities: capabilities.iter().cloned().collect(),
                provenance: provenance.iter().cloned().collect(),
            })
        })
        .collect()
}

fn incoming_declared_evidence(
    context: &DiagnosticContext<'_>,
    provider: &str,
    consumers: &[String],
) -> Vec<DeclaredDependencyEvidence> {
    consumers
        .iter()
        .filter_map(|consumer| {
            let (capabilities, provenance) = context
                .declared_evidence
                .get(&(consumer.clone(), provider.into()))?;
            Some(DeclaredDependencyEvidence {
                consumer: consumer.clone(),
                provider: provider.into(),
                capabilities: capabilities.iter().cloned().collect(),
                provenance: provenance.iter().cloned().collect(),
            })
        })
        .collect()
}

fn outgoing_observed_evidence(
    context: &DiagnosticContext<'_>,
    source: &str,
    targets: &[String],
) -> Vec<ObservationProvenance> {
    let mut evidence: Vec<ObservationProvenance> = targets
        .iter()
        .filter_map(|target| {
            context
                .observed_evidence
                .get(&(source.into(), target.clone()))
        })
        .flatten()
        .cloned()
        .collect();
    evidence.sort();
    evidence.dedup();
    evidence
}

fn incoming_observed_evidence(
    context: &DiagnosticContext<'_>,
    provider: &str,
    consumers: &[String],
) -> Vec<ObservationProvenance> {
    let mut evidence: Vec<ObservationProvenance> = consumers
        .iter()
        .filter_map(|consumer| {
            context
                .observed_evidence
                .get(&(consumer.clone(), provider.into()))
        })
        .flatten()
        .cloned()
        .collect();
    evidence.sort();
    evidence.dedup();
    evidence
}

fn capability_provenance(
    context: &DiagnosticContext<'_>,
    module: &str,
) -> Vec<DiagnosticProvenance> {
    context.ccg.modules()[module]
        .contract()
        .provides()
        .iter()
        .filter_map(|provided| context.ccg.capabilities().get(provided.id()))
        .map(|capability| {
            DiagnosticProvenance::contract(
                capability.provenance().contract_path(),
                capability.provenance().pointer(),
            )
        })
        .collect()
}

fn containment_provenance(context: &DiagnosticContext<'_>, module: &str) -> DiagnosticProvenance {
    DiagnosticProvenance::filesystem(context.ccg.modules()[module].contract_path())
}

fn ancestor_chain(ccg: &ContractCoherencyGraph, module: &str) -> Option<Vec<String>> {
    if !ccg.modules().contains_key(module) {
        return None;
    }
    let mut chain = vec![module.to_owned()];
    let mut cursor = module;
    while let Some(parent) = ccg.containment().get(cursor)?.as_deref() {
        chain.push(parent.into());
        cursor = parent;
    }
    chain.reverse();
    Some(chain)
}

fn module_depth(ccg: &ContractCoherencyGraph, module: &str) -> usize {
    ancestor_chain(ccg, module).map_or(0, |chain| chain.len().saturating_sub(1))
}

fn is_descendant_or_same(ccg: &ContractCoherencyGraph, module: &str, ancestor: &str) -> bool {
    ancestor_chain(ccg, module)
        .is_some_and(|chain| chain.iter().any(|candidate| candidate == ancestor))
}

fn reachable_dependencies(source: &str, dependencies: &EdgeMap) -> BTreeSet<String> {
    let mut reached = BTreeSet::new();
    let mut queue: VecDeque<String> = dependencies
        .get(source)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    while let Some(module) = queue.pop_front() {
        if !reached.insert(module.clone()) {
            continue;
        }
        queue.extend(dependencies.get(&module).into_iter().flatten().cloned());
    }
    reached.remove(source);
    reached
}

fn edge_values(edges: &EdgeMap, module: &str) -> Vec<String> {
    edges.get(module).into_iter().flatten().cloned().collect()
}

fn union(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .chain(right)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn profile_consumers(profile: &ModuleArchitectureProfile) -> Vec<String> {
    union(
        profile.declared_production_consumers(),
        profile.observed_production_consumers(),
    )
}

fn profile_dependencies(profile: &ModuleArchitectureProfile) -> Vec<String> {
    union(
        profile.declared_production_dependencies(),
        profile.observed_production_dependencies(),
    )
}

fn project_capabilities(profile: &ModuleArchitectureProfile) -> Vec<String> {
    profile
        .provided_capabilities()
        .iter()
        .filter(|capability| capability.visibility() == CapabilityVisibility::Project)
        .map(|capability| capability.id().to_owned())
        .collect()
}

fn contains_path(module_path: &str, path: &str) -> bool {
    module_path.is_empty() || path == module_path || path.starts_with(&format!("{module_path}/"))
}
