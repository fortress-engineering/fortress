//! CCG-backed relocation-transparent reference resolution.
//!
//! Stable Fortress and ecosystem identities remain semantic authority. This
//! module derives current repository paths, validates the small set of formats
//! whose path semantics Fortress understands, and simulates physical moves
//! without changing architectural meaning.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::path::{Component, Path};

use pulldown_cmark::{Event, Parser, Tag};
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn::visit::Visit;
use syn::{Expr, Lit, LitStr, Meta};

use crate::contract_coherency::ContractCoherencyGraph;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of the relocation-transparent reference rule.
pub const REPO_REFERENCE_RULE_ID: &str = "REPO-REFERENCE-001";
/// Canonical resolution projection schema identity.
pub const RESOLUTION_INDEX_SCHEMA: &str = "urn:fortress:schema:v1:component-resolution-index";
/// Current resolution projection schema version.
pub const RESOLUTION_INDEX_SCHEMA_VERSION: u16 = 1;
/// Semantic version of the resolver's interpretation.
pub const REFERENCE_RESOLVER_SEMANTIC_VERSION: &str = "1.0.0";

const REMEDIATION: &str = "Replace cross-Module physical coupling with the target's stable Fortress identity or native package surface, keep unavoidable paths inside a registered resolution boundary, and regenerate derived navigation from the current CCG.";

/// Closed semantic classification of one reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceClass {
    /// Source and target share the same relocation boundary.
    Local,
    /// Stable governed identity is authoritative across Modules.
    Semantic,
    /// Physical path is a derived projection of semantic authority.
    PhysicalProjection,
    /// Another ecosystem owns the reference identity.
    External,
    /// Execution-local absolute filesystem location.
    MachineLocal,
}

/// Closed classification of legitimate physical resolution boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionBoundaryClass {
    /// Authored language/build configuration necessarily maps identity to location.
    AuthoredResolutionBoundary,
    /// A path rendered from stable identity for a path-only format.
    GeneratedProjection,
}

/// One stable semantic or physical projection reference.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReferenceFact {
    class: ReferenceClass,
    source_module: String,
    target_module: Option<String>,
    authority: String,
    projection: Option<String>,
    provenance: String,
}

/// Location-independent identity of one governed semantic relationship.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SemanticReferenceIdentity {
    source_module: String,
    target_module: String,
    authority: String,
}

impl SemanticReferenceIdentity {
    fn from_fact(fact: &ReferenceFact) -> Option<Self> {
        (fact.class == ReferenceClass::Semantic).then(|| Self {
            source_module: fact.source_module.clone(),
            target_module: fact.target_module.clone().unwrap_or_default(),
            authority: fact.authority.clone(),
        })
    }
}

/// Deterministic semantic delta between two resolution indexes.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SemanticReferenceDelta {
    added: Vec<SemanticReferenceIdentity>,
    removed: Vec<SemanticReferenceIdentity>,
}

impl SemanticReferenceDelta {
    /// Returns semantic relationships present only in the newer index.
    #[must_use]
    pub fn added(&self) -> &[SemanticReferenceIdentity] {
        &self.added
    }

    /// Returns semantic relationships absent from the newer index.
    #[must_use]
    pub fn removed(&self) -> &[SemanticReferenceIdentity] {
        &self.removed
    }

    /// Reports whether semantic authority is unchanged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl ReferenceFact {
    /// Constructs a deterministic reference fact for analyzers and fixtures.
    #[must_use]
    pub fn new(
        class: ReferenceClass,
        source_module: impl Into<String>,
        target_module: Option<String>,
        authority: impl Into<String>,
        projection: Option<String>,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            class,
            source_module: source_module.into(),
            target_module,
            authority: authority.into(),
            projection,
            provenance: provenance.into(),
        }
    }

    /// Returns the semantic reference class.
    #[must_use]
    pub const fn class(&self) -> ReferenceClass {
        self.class
    }

    /// Returns the source Module identity.
    #[must_use]
    pub fn source_module(&self) -> &str {
        &self.source_module
    }

    /// Returns the target Module identity when governed.
    #[must_use]
    pub fn target_module(&self) -> Option<&str> {
        self.target_module.as_deref()
    }

    /// Returns the stable semantic or ecosystem authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the path-only projection when one is required.
    #[must_use]
    pub fn projection(&self) -> Option<&str> {
        self.projection.as_deref()
    }
}

/// One legitimate location where repository placement must be mentioned.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ResolutionBoundary {
    class: ResolutionBoundaryClass,
    format: String,
    path: String,
    pointer: String,
    source_module: String,
    target_module: Option<String>,
    resolved_target: String,
}

impl ResolutionBoundary {
    /// Constructs a boundary for synthetic conformance fixtures.
    #[must_use]
    pub fn new(
        class: ResolutionBoundaryClass,
        format: impl Into<String>,
        path: impl Into<String>,
        pointer: impl Into<String>,
        source_module: impl Into<String>,
        target_module: Option<String>,
        resolved_target: impl Into<String>,
    ) -> Self {
        Self {
            class,
            format: format.into(),
            path: path.into(),
            pointer: pointer.into(),
            source_module: source_module.into(),
            target_module,
            resolved_target: resolved_target.into(),
        }
    }

    /// Returns the boundary class.
    #[must_use]
    pub const fn class(&self) -> ResolutionBoundaryClass {
        self.class
    }

    /// Returns the repository file containing the boundary.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the canonical resolved target without dot segments.
    #[must_use]
    pub fn resolved_target(&self) -> &str {
        &self.resolved_target
    }
}

/// Current physical projection for one stable Module identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ComponentResolution {
    module_id: String,
    module_path: String,
    contract_path: String,
    readme_path: String,
    parent_module: Option<String>,
    element_roots: Vec<String>,
}

impl ComponentResolution {
    /// Constructs a canonical component projection for fixtures.
    #[must_use]
    pub fn new(
        module_id: impl Into<String>,
        module_path: impl Into<String>,
        parent_module: Option<String>,
    ) -> Self {
        let module_path = module_path.into();
        Self {
            module_id: module_id.into(),
            contract_path: child_path(&module_path, "contract.json"),
            readme_path: child_path(&module_path, "README.md"),
            module_path,
            parent_module,
            element_roots: Vec::new(),
        }
    }

    /// Returns the stable Module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the current repository-relative Module location.
    #[must_use]
    pub fn module_path(&self) -> &str {
        &self.module_path
    }

    /// Returns the current canonical README location.
    #[must_use]
    pub fn readme_path(&self) -> &str {
        &self.readme_path
    }

    /// Returns the physical parent Module identity.
    #[must_use]
    pub fn parent_module(&self) -> Option<&str> {
        self.parent_module.as_deref()
    }
}

/// Deterministic summary of current reference resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceResolutionSummary {
    modules: usize,
    semantic_references: usize,
    local_references: usize,
    physical_projections: usize,
    external_references: usize,
    authored_resolution_boundaries: usize,
    generated_projections: usize,
    findings: usize,
}

impl ReferenceResolutionSummary {
    /// Returns the number of stable Module identities resolved.
    #[must_use]
    pub const fn modules(self) -> usize {
        self.modules
    }

    /// Returns cross-boundary semantic reference count.
    #[must_use]
    pub const fn semantic_references(self) -> usize {
        self.semantic_references
    }

    /// Returns same-boundary relative reference count.
    #[must_use]
    pub const fn local_references(self) -> usize {
        self.local_references
    }

    /// Returns generated path projection count.
    #[must_use]
    pub const fn physical_projections(self) -> usize {
        self.physical_projections
    }

    /// Returns authored resolution boundary count.
    #[must_use]
    pub const fn authored_resolution_boundaries(self) -> usize {
        self.authored_resolution_boundaries
    }

    /// Returns normative violation count.
    #[must_use]
    pub const fn findings(self) -> usize {
        self.findings
    }
}

/// Focused current-location projection derived from the CCG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComponentResolutionIndex {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    resolver_semantic_version: &'static str,
    project_id: String,
    source_ccg_digest: String,
    modules: Vec<ComponentResolution>,
    references: Vec<ReferenceFact>,
    resolution_boundaries: Vec<ResolutionBoundary>,
    summary: ReferenceResolutionSummary,
}

impl ComponentResolutionIndex {
    /// Constructs a deterministic synthetic index used by relocation fixtures.
    #[must_use]
    pub fn synthetic(
        project_id: impl Into<String>,
        source_ccg_digest: impl Into<String>,
        mut modules: Vec<ComponentResolution>,
        mut references: Vec<ReferenceFact>,
        mut boundaries: Vec<ResolutionBoundary>,
    ) -> Self {
        modules.sort();
        references.sort();
        references.dedup();
        boundaries.sort();
        boundaries.dedup();
        let summary = summarize(&modules, &references, &boundaries, 0);
        Self {
            schema: RESOLUTION_INDEX_SCHEMA,
            schema_version: RESOLUTION_INDEX_SCHEMA_VERSION,
            resolver_semantic_version: REFERENCE_RESOLVER_SEMANTIC_VERSION,
            project_id: project_id.into(),
            source_ccg_digest: source_ccg_digest.into(),
            modules,
            references,
            resolution_boundaries: boundaries,
            summary,
        }
    }

    /// Returns component projections sorted by stable identity.
    #[must_use]
    pub fn modules(&self) -> &[ComponentResolution] {
        &self.modules
    }

    /// Resolves one stable Module identity to current location.
    #[must_use]
    pub fn resolve_module(&self, id: &str) -> Option<&ComponentResolution> {
        self.modules
            .binary_search_by(|module| module.module_id.as_str().cmp(id))
            .ok()
            .map(|index| &self.modules[index])
    }

    /// Returns classified references in canonical order.
    #[must_use]
    pub fn references(&self) -> &[ReferenceFact] {
        &self.references
    }

    /// Returns registered physical resolution boundaries.
    #[must_use]
    pub fn resolution_boundaries(&self) -> &[ResolutionBoundary] {
        &self.resolution_boundaries
    }

    /// Returns deterministic summary counts.
    #[must_use]
    pub const fn summary(&self) -> ReferenceResolutionSummary {
        self.summary
    }

    /// Returns the exact source CCG digest.
    #[must_use]
    pub fn source_ccg_digest(&self) -> &str {
        &self.source_ccg_digest
    }

    /// Compares stable semantic relationships independently of physical placement.
    #[must_use]
    pub fn semantic_reference_delta(&self, newer: &Self) -> SemanticReferenceDelta {
        let before = self
            .references
            .iter()
            .filter_map(SemanticReferenceIdentity::from_fact)
            .collect::<BTreeSet<_>>();
        let after = newer
            .references
            .iter()
            .filter_map(SemanticReferenceIdentity::from_fact)
            .collect::<BTreeSet<_>>();
        SemanticReferenceDelta {
            added: after.difference(&before).cloned().collect(),
            removed: before.difference(&after).cloned().collect(),
        }
    }

    /// Serializes canonical UTF-8-compatible JSON with trailing LF.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the projection cannot be represented.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut value| {
            value.push('\n');
            value
        })
    }

    /// Computes SHA-256 over canonical projection bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if canonical bytes cannot be produced.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        self.to_canonical_json()
            .map(|value| format!("sha256:{:x}", Sha256::digest(value.as_bytes())))
    }

    /// Simulates moving a Module subtree beneath another current Module.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for unknown identities, root relocation,
    /// containment cycles, or a destination collision.
    pub fn preview_move(
        &self,
        module_id: &str,
        new_parent_id: &str,
    ) -> Result<RelocationPreview, RelocationError> {
        let module = self
            .resolve_module(module_id)
            .ok_or_else(|| RelocationError::UnknownModule(module_id.into()))?;
        let parent = self
            .resolve_module(new_parent_id)
            .ok_or_else(|| RelocationError::UnknownModule(new_parent_id.into()))?;
        if module.module_path.is_empty() {
            return Err(RelocationError::RootMove);
        }
        if parent.module_path == module.module_path
            || is_descendant(&parent.module_path, &module.module_path)
        {
            return Err(RelocationError::ContainmentCycle);
        }
        let leaf = module
            .module_path
            .rsplit('/')
            .next()
            .ok_or(RelocationError::RootMove)?;
        let destination = child_path(&child_path(&parent.module_path, "mods"), leaf);
        self.preview_move_to_path(module_id, &destination)
    }

    /// Simulates a move to an explicit canonical Module path.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for an invalid path or collision.
    pub fn preview_move_to_path(
        &self,
        module_id: &str,
        destination: &str,
    ) -> Result<RelocationPreview, RelocationError> {
        let module = self
            .resolve_module(module_id)
            .ok_or_else(|| RelocationError::UnknownModule(module_id.into()))?;
        if module.module_path.is_empty() {
            return Err(RelocationError::RootMove);
        }
        if !is_canonical_repository_path(destination) || destination.is_empty() {
            return Err(RelocationError::InvalidDestination(destination.into()));
        }
        let moved: BTreeSet<&str> = self
            .modules
            .iter()
            .filter(|candidate| {
                candidate.module_path == module.module_path
                    || is_descendant(&candidate.module_path, &module.module_path)
            })
            .map(|candidate| candidate.module_id.as_str())
            .collect();
        if self.modules.iter().any(|candidate| {
            !moved.contains(candidate.module_id.as_str())
                && (candidate.module_path == destination
                    || is_descendant(&candidate.module_path, destination))
        }) {
            return Err(RelocationError::DestinationCollision(destination.into()));
        }
        let moved_modules = moved.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
        let generated_projections_affected = self
            .references
            .iter()
            .filter(|reference| {
                reference.class == ReferenceClass::PhysicalProjection
                    && (moved.contains(reference.source_module.as_str())
                        || reference
                            .target_module
                            .as_deref()
                            .is_some_and(|target| moved.contains(target)))
            })
            .map(|reference| reference.provenance.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let authored_resolution_boundaries_affected = self
            .resolution_boundaries
            .iter()
            .filter(|boundary| {
                boundary.class == ResolutionBoundaryClass::AuthoredResolutionBoundary
                    && (moved.contains(boundary.source_module.as_str())
                        || boundary
                            .target_module
                            .as_deref()
                            .is_some_and(|target| moved.contains(target)))
            })
            .map(|boundary| format!("{}#{}", boundary.path, boundary.pointer))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let invalid_physical_couplings = self
            .references
            .iter()
            .filter(|reference| {
                reference.class == ReferenceClass::MachineLocal
                    || (reference.class == ReferenceClass::PhysicalProjection
                        && reference.authority == "unregistered-physical-reference")
            })
            .map(|reference| reference.provenance.clone())
            .collect();
        let semantic_references_preserved = self
            .references
            .iter()
            .filter(|reference| reference.class == ReferenceClass::Semantic)
            .count();
        let unrelated_modules_unaffected = self.modules.len() - moved.len();
        Ok(RelocationPreview {
            module_id: module_id.into(),
            from_path: module.module_path.clone(),
            to_path: destination.into(),
            moved_modules,
            semantic_references_preserved,
            required_semantic_reference_edits: 0,
            generated_projections_affected,
            authored_resolution_boundaries_affected,
            invalid_physical_couplings,
            unrelated_modules_unaffected,
        })
    }
}

/// Non-mutating impact of one pure physical Module relocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelocationPreview {
    module_id: String,
    from_path: String,
    to_path: String,
    moved_modules: Vec<String>,
    semantic_references_preserved: usize,
    required_semantic_reference_edits: usize,
    generated_projections_affected: Vec<String>,
    authored_resolution_boundaries_affected: Vec<String>,
    invalid_physical_couplings: Vec<String>,
    unrelated_modules_unaffected: usize,
}

impl RelocationPreview {
    /// Returns stable identities in the moved subtree.
    #[must_use]
    pub fn moved_modules(&self) -> &[String] {
        &self.moved_modules
    }

    /// Returns semantic-reference edit count; a pure move always yields zero.
    #[must_use]
    pub const fn required_semantic_reference_edits(&self) -> usize {
        self.required_semantic_reference_edits
    }

    /// Returns path-only generated projections affected by the move.
    #[must_use]
    pub fn generated_projections_affected(&self) -> &[String] {
        &self.generated_projections_affected
    }

    /// Returns authored physical resolution boundaries affected by the move.
    #[must_use]
    pub fn authored_resolution_boundaries_affected(&self) -> &[String] {
        &self.authored_resolution_boundaries_affected
    }

    /// Returns unrelated Module count remaining untouched.
    #[must_use]
    pub const fn unrelated_modules_unaffected(&self) -> usize {
        self.unrelated_modules_unaffected
    }

    /// Serializes deterministic pretty JSON with LF termination.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the preview cannot be represented.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut value| {
            value.push('\n');
            value
        })
    }
}

/// Complete resolver output plus normative rule findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceResolutionEvaluation {
    index: ComponentResolutionIndex,
    findings: Vec<CanonicalFinding>,
}

impl ReferenceResolutionEvaluation {
    /// Returns the derived current-location projection.
    #[must_use]
    pub const fn index(&self) -> &ComponentResolutionIndex {
        &self.index
    }

    /// Returns normalized `REPO-REFERENCE-001` findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Resolves stable identities and evaluates all supported persistent reference forms.
///
/// `files` must contain exact snapshot-bound repository-relative bytes.
///
/// # Errors
///
/// Returns an error only when canonical CCG serialization, understood source
/// parsing, or normalized finding construction fails. Semantic violations are
/// returned as findings.
pub fn evaluate_reference_resolution(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    standard_edition: &str,
) -> Result<ReferenceResolutionEvaluation, ReferenceResolutionError> {
    let mut findings = Vec::new();
    let mut references = semantic_references(ccg);
    let mut boundaries = Vec::new();
    let mut modules = ccg
        .modules()
        .iter()
        .map(|(id, module)| {
            let path = module.path().to_owned();
            let element_roots = ["code", "data", "info", "mods"]
                .into_iter()
                .map(|element| child_path(&path, element))
                .filter(|root| {
                    files
                        .keys()
                        .any(|file| file.starts_with(&format!("{root}/")))
                })
                .collect();
            ComponentResolution {
                module_id: id.clone(),
                contract_path: module.contract_path().into(),
                readme_path: child_path(&path, "README.md"),
                module_path: path,
                parent_module: module.parent_id().map(str::to_owned),
                element_roots,
            }
        })
        .collect::<Vec<_>>();
    modules.sort();

    inspect_markdown(
        ccg,
        files,
        standard_edition,
        &mut references,
        &mut boundaries,
        &mut findings,
    )?;
    let cargo_dependencies =
        inspect_cargo(ccg, files, standard_edition, &mut boundaries, &mut findings)?;
    inspect_registry_boundaries(ccg, files, standard_edition, &mut boundaries, &mut findings)?;
    inspect_rust_paths(
        ccg,
        files,
        standard_edition,
        &mut references,
        &mut boundaries,
        &mut findings,
        &cargo_dependencies,
    )?;
    references.sort();
    references.dedup();
    boundaries.sort();
    boundaries.dedup();
    findings.sort();
    let summary = summarize(&modules, &references, &boundaries, findings.len());
    let project_id = ccg.root().map_or_else(
        || "UNKNOWN-PROJECT".into(),
        |module| module.contract().id().to_owned(),
    );
    let index = ComponentResolutionIndex {
        schema: RESOLUTION_INDEX_SCHEMA,
        schema_version: RESOLUTION_INDEX_SCHEMA_VERSION,
        resolver_semantic_version: REFERENCE_RESOLVER_SEMANTIC_VERSION,
        project_id,
        source_ccg_digest: ccg.digest()?,
        modules,
        references,
        resolution_boundaries: boundaries,
        summary,
    };
    Ok(ReferenceResolutionEvaluation { index, findings })
}

fn semantic_references(ccg: &ContractCoherencyGraph) -> Vec<ReferenceFact> {
    let requirements = ccg.direct_requirements().iter().map(|requirement| {
        ReferenceFact::new(
            ReferenceClass::Semantic,
            requirement.consumer(),
            Some(requirement.provider().into()),
            requirement.capability(),
            None,
            format!(
                "{}#{}",
                requirement.provenance().contract_path(),
                requirement.provenance().pointer()
            ),
        )
    });
    let relationships = ccg.relationships().iter().map(|relationship| {
        ReferenceFact::new(
            ReferenceClass::Semantic,
            relationship.source(),
            Some(relationship.target().into()),
            relationship
                .subjects()
                .first()
                .map_or_else(|| relationship.target().to_owned(), Clone::clone),
            None,
            format!(
                "{}#{}",
                relationship.provenance().contract_path(),
                relationship.provenance().pointer()
            ),
        )
    });
    requirements.chain(relationships).collect()
}

fn inspect_markdown(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    edition: &str,
    references: &mut Vec<ReferenceFact>,
    boundaries: &mut Vec<ResolutionBoundary>,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), ReferenceResolutionError> {
    let expected_relationships: BTreeSet<(String, String)> = ccg
        .expected_readme_relationships()
        .iter()
        .flat_map(|(source, targets)| {
            targets
                .keys()
                .map(|target| (source.clone(), target.clone()))
        })
        .collect();
    MarkdownInspection {
        ccg,
        edition,
        expected_relationships: &expected_relationships,
        references,
        boundaries,
        findings,
    }
    .inspect(files)
}

struct MarkdownInspection<'a> {
    ccg: &'a ContractCoherencyGraph,
    edition: &'a str,
    expected_relationships: &'a BTreeSet<(String, String)>,
    references: &'a mut Vec<ReferenceFact>,
    boundaries: &'a mut Vec<ResolutionBoundary>,
    findings: &'a mut Vec<CanonicalFinding>,
}

impl MarkdownInspection<'_> {
    fn inspect(
        &mut self,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), ReferenceResolutionError> {
        for (path, bytes) in files.iter().filter(|(path, _)| {
            has_extension(path, "md") && is_governed_document_path(self.ccg, path)
        }) {
            self.inspect_document(path, bytes)?;
        }
        Ok(())
    }

    fn inspect_document(
        &mut self,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), ReferenceResolutionError> {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| ReferenceResolutionError::NonUtf8(path.to_owned()))?;
        let Some(source_owner) = deepest_owner(self.ccg, path) else {
            return Ok(());
        };
        for destination in markdown_links(source) {
            self.inspect_link(path, &source_owner, destination)?;
        }
        Ok(())
    }

    fn inspect_link(
        &mut self,
        path: &str,
        source_owner: &str,
        destination: String,
    ) -> Result<(), ReferenceResolutionError> {
        if destination.starts_with('#') || destination.is_empty() {
            return Ok(());
        }
        if is_external_reference(&destination) {
            self.references.push(ReferenceFact::new(
                ReferenceClass::External,
                source_owner,
                None,
                destination,
                None,
                path,
            ));
            return Ok(());
        }
        if is_machine_absolute(&destination) {
            self.references.push(ReferenceFact::new(
                ReferenceClass::MachineLocal,
                source_owner,
                None,
                "machine-filesystem",
                Some(destination.clone()),
                path,
            ));
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned()],
                path,
                format!("Markdown link persists machine-local absolute path `{destination}`."),
            )?);
            return Ok(());
        }
        let clean = destination
            .split(['#', '?'])
            .next()
            .unwrap_or(destination.as_str());
        let Some(resolved) = resolve_relative_path(path, clean) else {
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned()],
                path,
                format!("Markdown link `{destination}` escapes the repository root."),
            )?);
            return Ok(());
        };
        match deepest_owner(self.ccg, &resolved) {
            Some(target) if target == source_owner => self.references.push(ReferenceFact::new(
                ReferenceClass::Local,
                source_owner,
                Some(target),
                "repository-relative-local",
                Some(destination),
                path,
            )),
            Some(target) => {
                self.inspect_cross_module(path, source_owner, target, &destination, resolved)?;
            }
            None => {}
        }
        Ok(())
    }

    fn inspect_cross_module(
        &mut self,
        path: &str,
        source_owner: &str,
        target: String,
        destination: &str,
        resolved: String,
    ) -> Result<(), ReferenceResolutionError> {
        let relationship_projection = path.ends_with("README.md")
            && self
                .expected_relationships
                .contains(&(source_owner.to_owned(), target.clone()));
        let child_catalog_projection = path.ends_with("docs/mods_docs.md")
            && self
                .ccg
                .modules()
                .get(&target)
                .and_then(|module| module.parent_id())
                == Some(source_owner);
        if !(relationship_projection || child_catalog_projection) {
            self.references.push(ReferenceFact::new(
                ReferenceClass::PhysicalProjection,
                source_owner,
                Some(target.clone()),
                "unregistered-physical-reference",
                Some(destination.to_owned()),
                path,
            ));
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned(), target],
                path,
                format!("Cross-Module Markdown path `{destination}` is outside a registered generated projection boundary."),
            )?);
            return Ok(());
        }
        let canonical_target = self
            .ccg
            .modules()
            .get(&target)
            .map_or_else(|| resolved, |module| child_path(module.path(), "README.md"));
        let expected = relative_navigation(path, &canonical_target);
        self.references.push(ReferenceFact::new(
            ReferenceClass::PhysicalProjection,
            source_owner,
            Some(target.clone()),
            if relationship_projection {
                target.clone()
            } else {
                format!("containment:{target}")
            },
            Some(destination.to_owned()),
            path,
        ));
        self.boundaries.push(ResolutionBoundary::new(
            ResolutionBoundaryClass::GeneratedProjection,
            "markdown",
            path,
            destination.to_owned(),
            source_owner,
            Some(target.clone()),
            canonical_target,
        ));
        if destination != expected {
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned(), target],
                path,
                format!("Markdown navigation `{destination}` is stale; stable identity projects to `{expected}` at the current CCG locations."),
            )?);
        }
        Ok(())
    }
}

fn inspect_cargo(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    edition: &str,
    boundaries: &mut Vec<ResolutionBoundary>,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<BTreeMap<String, CargoDependencyIdentity>, ReferenceResolutionError> {
    let mut dependencies: BTreeMap<String, CargoDependencyIdentity> = BTreeMap::new();
    for (path, bytes) in files.iter().filter(|(path, _)| {
        path.ends_with("Cargo.toml") && is_governed_element_path(ccg, path, "data")
    }) {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| ReferenceResolutionError::NonUtf8(path.clone()))?;
        let value: toml::Value =
            toml::from_str(source).map_err(|source| ReferenceResolutionError::Cargo {
                path: path.clone(),
                source,
            })?;
        let source_owner = deepest_owner(ccg, path).unwrap_or_else(|| {
            ccg.root().map_or_else(
                || "UNKNOWN-PROJECT".into(),
                |root| root.contract().id().into(),
            )
        });
        for (name, package, raw_path) in cargo_dependencies(&value) {
            let target = raw_path
                .as_deref()
                .and_then(|raw| resolve_relative_path(path, raw))
                .and_then(|resolved| deepest_owner(ccg, &resolved));
            let crate_name = name.replace('-', "_");
            dependencies
                .entry(crate_name)
                .and_modify(|current| {
                    if current.target_module.is_none() {
                        current.target_module.clone_from(&target);
                    }
                })
                .or_insert(CargoDependencyIdentity {
                    package,
                    target_module: target,
                });
        }
        for (pointer, raw) in cargo_paths(&value) {
            if is_machine_absolute(&raw) {
                findings.push(reference_finding(
                    edition,
                    vec![source_owner.clone()],
                    path,
                    format!("Cargo resolution boundary `{pointer}` persists machine-local absolute path `{raw}`."),
                )?);
                continue;
            }
            let Some(resolved) = resolve_relative_path(path, &raw) else {
                findings.push(reference_finding(
                    edition,
                    vec![source_owner.clone()],
                    path,
                    format!("Cargo resolution boundary `{pointer}` escapes the repository root."),
                )?);
                continue;
            };
            boundaries.push(ResolutionBoundary::new(
                ResolutionBoundaryClass::AuthoredResolutionBoundary,
                "cargo",
                path,
                pointer,
                &source_owner,
                deepest_owner(ccg, &resolved),
                resolved,
            ));
        }
    }
    Ok(dependencies)
}

fn inspect_registry_boundaries(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    edition: &str,
    boundaries: &mut Vec<ResolutionBoundary>,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), ReferenceResolutionError> {
    for (path, field, format) in [
        (
            "mods/engine/mods/standard_registry/data/standard_manifest.json",
            "rules",
            "standard-registry",
        ),
        (
            "mods/engine/mods/standard_registry/data/schema_manifest.json",
            "schemas",
            "schema-registry",
        ),
    ] {
        let Some(bytes) = files.get(path) else {
            continue;
        };
        let document: serde_json::Value = serde_json::from_slice(bytes)?;
        let source_owner = deepest_owner(ccg, path).unwrap_or_default();
        for (index, value) in document[field].as_array().into_iter().flatten().enumerate() {
            let Some(raw) = value.as_str() else {
                continue;
            };
            if is_machine_absolute(raw) {
                findings.push(reference_finding(
                    edition,
                    vec![source_owner.clone()],
                    path,
                    format!("Registry resolution boundary `/{field}/{index}` persists machine-local absolute path `{raw}`."),
                )?);
                continue;
            }
            if !is_canonical_repository_path(raw) {
                findings.push(reference_finding(
                    edition,
                    vec![source_owner.clone()],
                    path,
                    format!("Registry resolution boundary `/{field}/{index}` is not a canonical repository-relative path: `{raw}`."),
                )?);
                continue;
            }
            boundaries.push(ResolutionBoundary::new(
                ResolutionBoundaryClass::AuthoredResolutionBoundary,
                format,
                path,
                format!("/{field}/{index}"),
                &source_owner,
                deepest_owner(ccg, raw),
                raw,
            ));
        }
    }
    Ok(())
}

fn inspect_rust_paths(
    ccg: &ContractCoherencyGraph,
    files: &BTreeMap<String, Vec<u8>>,
    edition: &str,
    references: &mut Vec<ReferenceFact>,
    boundaries: &mut Vec<ResolutionBoundary>,
    findings: &mut Vec<CanonicalFinding>,
    cargo_dependencies: &BTreeMap<String, CargoDependencyIdentity>,
) -> Result<(), ReferenceResolutionError> {
    RustInspection {
        ccg,
        edition,
        references,
        boundaries,
        findings,
        cargo_dependencies,
    }
    .inspect(files)
}

struct RustInspection<'a> {
    ccg: &'a ContractCoherencyGraph,
    edition: &'a str,
    references: &'a mut Vec<ReferenceFact>,
    boundaries: &'a mut Vec<ResolutionBoundary>,
    findings: &'a mut Vec<CanonicalFinding>,
    cargo_dependencies: &'a BTreeMap<String, CargoDependencyIdentity>,
}

impl RustInspection<'_> {
    fn inspect(
        &mut self,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), ReferenceResolutionError> {
        for (path, bytes) in files.iter().filter(|(path, _)| {
            has_extension(path, "rs") && is_governed_element_path(self.ccg, path, "code")
        }) {
            self.inspect_file(path, bytes)?;
        }
        Ok(())
    }

    fn inspect_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), ReferenceResolutionError> {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| ReferenceResolutionError::NonUtf8(path.to_owned()))?;
        let syntax = syn::parse_file(source).map_err(|source| ReferenceResolutionError::Rust {
            path: path.to_owned(),
            source,
        })?;
        let source_owner = deepest_owner(self.ccg, path).unwrap_or_default();
        let mut visitor = RustPhysicalPathVisitor::default();
        visitor.visit_file(&syntax);
        for import in visitor.imports {
            self.inspect_import(path, &source_owner, &import);
        }
        for occurrence in visitor.paths {
            self.inspect_occurrence(path, &source_owner, occurrence)?;
        }
        Ok(())
    }

    fn inspect_import(&mut self, path: &str, source_owner: &str, import: &str) {
        let resolved_import = match import {
            "crate" | "self" | "super" => Some((
                ReferenceClass::Local,
                Some(source_owner.to_owned()),
                "rust-crate-module".to_owned(),
            )),
            "std" | "core" | "alloc" => Some((ReferenceClass::External, None, import.to_owned())),
            _ => self.cargo_dependencies.get(import).map(|dependency| {
                (
                    ReferenceClass::External,
                    dependency.target_module.clone(),
                    dependency.package.clone(),
                )
            }),
        };
        if let Some((class, target, authority)) = resolved_import {
            self.references.push(ReferenceFact::new(
                class,
                source_owner,
                target,
                authority,
                None,
                path,
            ));
        }
    }

    fn inspect_occurrence(
        &mut self,
        path: &str,
        source_owner: &str,
        occurrence: RustPathOccurrence,
    ) -> Result<(), ReferenceResolutionError> {
        if is_machine_absolute(&occurrence.value) {
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned()],
                path,
                format!(
                    "Rust `{}` persists machine-local absolute path `{}`.",
                    occurrence.kind, occurrence.value
                ),
            )?);
            return Ok(());
        }
        let Some(resolved) = resolve_relative_path(path, &occurrence.value) else {
            self.findings.push(reference_finding(
                self.edition,
                vec![source_owner.to_owned()],
                path,
                format!(
                    "Rust `{}` path `{}` escapes the repository root.",
                    occurrence.kind, occurrence.value
                ),
            )?);
            return Ok(());
        };
        let target_owner = deepest_owner(self.ccg, &resolved);
        let crosses = target_owner
            .as_deref()
            .is_some_and(|target| target != source_owner);
        let crate_root_boundary = occurrence.kind == "path_attribute"
            && (path.ends_with("/code/lib.rs")
                || path.ends_with("/code/main.rs")
                || path == "code/lib.rs"
                || path == "code/main.rs");
        if crosses && !crate_root_boundary {
            self.references.push(ReferenceFact::new(
                ReferenceClass::PhysicalProjection,
                source_owner,
                target_owner.clone(),
                "unregistered-physical-reference",
                Some(occurrence.value.clone()),
                path,
            ));
            let mut entities = vec![source_owner.to_owned()];
            if let Some(target) = target_owner {
                entities.push(target);
            }
            self.findings.push(reference_finding(
                self.edition,
                entities,
                path,
                format!("Rust `{}` directly traverses a cross-Module filesystem path `{}` outside a crate-root resolution boundary.", occurrence.kind, occurrence.value),
            )?);
        } else if crate_root_boundary {
            self.boundaries.push(ResolutionBoundary::new(
                ResolutionBoundaryClass::AuthoredResolutionBoundary,
                "rust-module",
                path,
                occurrence.value,
                source_owner,
                target_owner,
                resolved,
            ));
        } else {
            self.references.push(ReferenceFact::new(
                ReferenceClass::Local,
                source_owner,
                target_owner,
                "rust-local-path",
                Some(occurrence.value),
                path,
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct RustPhysicalPathVisitor {
    paths: Vec<RustPathOccurrence>,
    imports: Vec<String>,
}

struct RustPathOccurrence {
    kind: &'static str,
    value: String,
}

impl<'ast> Visit<'ast> for RustPhysicalPathVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        rust_use_roots(&node.tree, &mut self.imports);
        syn::visit::visit_item_use(self, node);
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if attribute.path().is_ident("path")
            && let Meta::NameValue(name_value) = &attribute.meta
            && let Expr::Lit(expression) = &name_value.value
            && let Lit::Str(value) = &expression.lit
        {
            self.paths.push(RustPathOccurrence {
                kind: "path_attribute",
                value: value.value(),
            });
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let kind = if node.path.is_ident("include") {
            Some("include")
        } else if node.path.is_ident("include_str") {
            Some("include_str")
        } else if node.path.is_ident("include_bytes") {
            Some("include_bytes")
        } else {
            None
        };
        if let Some(kind) = kind
            && let Ok(value) = syn::parse2::<LitStr>(node.tokens.clone())
        {
            self.paths.push(RustPathOccurrence {
                kind,
                value: value.value(),
            });
        }
        syn::visit::visit_macro(self, node);
    }
}

fn rust_use_roots(tree: &syn::UseTree, roots: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => roots.push(path.ident.to_string()),
        syn::UseTree::Name(name) => roots.push(name.ident.to_string()),
        syn::UseTree::Rename(rename) => roots.push(rename.ident.to_string()),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                rust_use_roots(item, roots);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn cargo_paths(value: &toml::Value) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    if let Some(workspace) = value.get("workspace").and_then(toml::Value::as_table) {
        for key in ["members", "exclude"] {
            if let Some(values) = workspace.get(key).and_then(toml::Value::as_array) {
                for (index, value) in values.iter().enumerate() {
                    if let Some(path) = value.as_str() {
                        paths.push((format!("workspace.{key}[{index}]"), path.into()));
                    }
                }
            }
        }
    }
    if let Some(table) = value.as_table() {
        collect_manifest_targets(table, "", &mut paths);
        collect_dependency_paths(table, "", &mut paths);
        if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
            for (target, value) in targets {
                if let Some(table) = value.as_table() {
                    collect_dependency_paths(table, &format!("target.{target}."), &mut paths);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

#[derive(Clone, Debug)]
struct CargoDependencyIdentity {
    package: String,
    target_module: Option<String>,
}

fn cargo_dependencies(value: &toml::Value) -> Vec<(String, String, Option<String>)> {
    let mut dependencies = Vec::new();
    if let Some(table) = value.as_table() {
        collect_dependency_identities(table, &mut dependencies);
        if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
            for value in targets.values() {
                if let Some(table) = value.as_table() {
                    collect_dependency_identities(table, &mut dependencies);
                }
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn collect_dependency_identities(
    table: &toml::map::Map<String, toml::Value>,
    output: &mut Vec<(String, String, Option<String>)>,
) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = table.get(key).and_then(toml::Value::as_table) {
            for (name, dependency) in dependencies {
                let package = dependency
                    .as_table()
                    .and_then(|table| table.get("package"))
                    .and_then(toml::Value::as_str)
                    .unwrap_or(name);
                let path = dependency
                    .as_table()
                    .and_then(|table| table.get("path"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned);
                output.push((name.to_owned(), package.to_owned(), path));
            }
        }
    }
}

fn collect_manifest_targets(
    table: &toml::map::Map<String, toml::Value>,
    prefix: &str,
    paths: &mut Vec<(String, String)>,
) {
    for key in ["lib", "package"] {
        if let Some(path) = table
            .get(key)
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get("path"))
            .and_then(toml::Value::as_str)
        {
            paths.push((format!("{prefix}{key}.path"), path.into()));
        }
    }
    for key in ["bin", "test", "bench", "example"] {
        if let Some(targets) = table.get(key).and_then(toml::Value::as_array) {
            for (index, target) in targets.iter().enumerate() {
                if let Some(path) = target
                    .as_table()
                    .and_then(|table| table.get("path"))
                    .and_then(toml::Value::as_str)
                {
                    paths.push((format!("{prefix}{key}[{index}].path"), path.into()));
                }
            }
        }
    }
}

fn collect_dependency_paths(
    table: &toml::map::Map<String, toml::Value>,
    prefix: &str,
    paths: &mut Vec<(String, String)>,
) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = table.get(key).and_then(toml::Value::as_table) {
            for (name, dependency) in dependencies {
                if let Some(path) = dependency
                    .as_table()
                    .and_then(|table| table.get("path"))
                    .and_then(toml::Value::as_str)
                {
                    paths.push((format!("{prefix}{key}.{name}.path"), path.into()));
                }
            }
        }
    }
}

fn markdown_links(source: &str) -> Vec<String> {
    Parser::new(source)
        .filter_map(|event| match event {
            Event::Start(Tag::Link { dest_url, .. }) => Some(dest_url.into_string()),
            _ => None,
        })
        .collect()
}

/// Regenerates only cross-Module README relationship link destinations.
///
/// Non-generated prose and same-Module links are preserved byte-for-byte.
///
/// # Errors
///
/// Returns an error for an unknown Module identity, ambiguous display name, or
/// malformed canonical relationship heading.
pub fn project_readme_relationships(
    ccg: &ContractCoherencyGraph,
    source_module: &str,
    readme: &str,
) -> Result<String, ProjectionError> {
    let source = ccg
        .modules()
        .get(source_module)
        .ok_or_else(|| ProjectionError::UnknownModule(source_module.into()))?;
    let expected = ccg
        .expected_readme_relationships()
        .get(source_module)
        .cloned()
        .unwrap_or_default();
    let names: BTreeMap<&str, Vec<&str>> = expected.keys().fold(BTreeMap::new(), |mut map, id| {
        if let Some(target) = ccg.modules().get(id) {
            map.entry(target.contract().display_name())
                .or_default()
                .push(id);
        }
        map
    });
    let source_readme = child_path(source.path(), "README.md");
    let mut in_relationships = false;
    let mut output = String::with_capacity(readme.len());
    for line in readme.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body == "## Relationships" {
            in_relationships = true;
        } else if body.starts_with("## ") {
            in_relationships = false;
        }
        if in_relationships && body.starts_with("### [") {
            let Some((name, _destination)) = parse_markdown_heading_link(body) else {
                return Err(ProjectionError::MalformedHeading(body.into()));
            };
            let ids = names.get(name.as_str()).cloned().unwrap_or_default();
            if ids.len() > 1 {
                return Err(ProjectionError::AmbiguousDisplayName(name));
            }
            if let Some(target_id) = ids.first()
                && let Some(target) = ccg.modules().get(*target_id)
            {
                let target_readme = child_path(target.path(), "README.md");
                let destination = relative_navigation(&source_readme, &target_readme);
                write!(output, "### [{name}]({destination})")
                    .expect("writing to a String cannot fail");
                if line.ends_with('\n') {
                    output.push('\n');
                }
                continue;
            }
        }
        output.push_str(line);
    }
    Ok(output)
}

fn parse_markdown_heading_link(line: &str) -> Option<(String, String)> {
    let body = line.strip_prefix("### [")?;
    let (name, destination) = body.split_once("](")?;
    Some((name.into(), destination.strip_suffix(')')?.into()))
}

/// Returns the portable relative navigation from one repository file to another.
#[must_use]
pub fn relative_navigation(source_file: &str, target_file: &str) -> String {
    let mut source: Vec<&str> = source_file.split('/').collect();
    source.pop();
    let target: Vec<&str> = target_file.split('/').collect();
    let common = source
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts = vec![".."; source.len() - common];
    parts.extend_from_slice(&target[common..]);
    if parts.is_empty() {
        target.last().copied().unwrap_or(".").into()
    } else {
        parts.join("/")
    }
}

fn resolve_relative_path(source_file: &str, target: &str) -> Option<String> {
    let target = target.replace('\\', "/");
    if target.starts_with('/') || is_machine_absolute(&target) {
        return None;
    }
    let parent = source_file
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let combined = if parent.is_empty() {
        target
    } else {
        format!("{parent}/{target}")
    };
    normalize_relative(&combined)
}

fn normalize_relative(path: &str) -> Option<String> {
    let mut output = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(value) => output.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(output.join("/"))
}

fn is_machine_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('/')
        || value.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

fn is_external_reference(value: &str) -> bool {
    value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("mailto:")
        || value.starts_with("urn:")
}

fn is_canonical_repository_path(path: &str) -> bool {
    !is_machine_absolute(path)
        && !path.contains('\\')
        && !path.is_empty()
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn deepest_owner(ccg: &ContractCoherencyGraph, path: &str) -> Option<String> {
    ccg.module_paths()
        .iter()
        .filter(|(_, module_path)| {
            module_path.is_empty()
                || path == module_path.as_str()
                || path.starts_with(&format!("{module_path}/"))
        })
        .max_by_key(|(_, module_path)| module_path.len())
        .map(|(id, _)| id.clone())
}

fn is_governed_element_path(ccg: &ContractCoherencyGraph, path: &str, element: &str) -> bool {
    deepest_owner(ccg, path)
        .and_then(|owner| ccg.modules().get(&owner))
        .is_some_and(|module| {
            let root = child_path(module.path(), element);
            path.starts_with(&format!("{root}/"))
        })
}

fn has_extension(path: &str, expected: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn is_governed_document_path(ccg: &ContractCoherencyGraph, path: &str) -> bool {
    deepest_owner(ccg, path)
        .and_then(|owner| ccg.modules().get(&owner))
        .is_some_and(|module| {
            path == child_path(module.path(), "README.md")
                || path.starts_with(&format!("{}/", child_path(module.path(), "docs")))
        })
}

fn summarize(
    modules: &[ComponentResolution],
    references: &[ReferenceFact],
    boundaries: &[ResolutionBoundary],
    findings: usize,
) -> ReferenceResolutionSummary {
    ReferenceResolutionSummary {
        modules: modules.len(),
        semantic_references: references
            .iter()
            .filter(|reference| reference.class == ReferenceClass::Semantic)
            .count(),
        local_references: references
            .iter()
            .filter(|reference| reference.class == ReferenceClass::Local)
            .count(),
        physical_projections: references
            .iter()
            .filter(|reference| reference.class == ReferenceClass::PhysicalProjection)
            .count(),
        external_references: references
            .iter()
            .filter(|reference| reference.class == ReferenceClass::External)
            .count(),
        authored_resolution_boundaries: boundaries
            .iter()
            .filter(|boundary| {
                boundary.class == ResolutionBoundaryClass::AuthoredResolutionBoundary
            })
            .count(),
        generated_projections: boundaries
            .iter()
            .filter(|boundary| boundary.class == ResolutionBoundaryClass::GeneratedProjection)
            .count(),
        findings,
    }
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}

fn is_descendant(path: &str, parent: &str) -> bool {
    !parent.is_empty() && path.starts_with(&format!("{parent}/"))
}

fn reference_finding(
    edition: &str,
    entities: Vec<String>,
    path: &str,
    message: String,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            REPO_REFERENCE_RULE_ID,
            1,
            FindingCategory::Repository,
            REMEDIATION,
        )?,
        FindingOccurrence::new(entities, FindingLocation::at_path(path)?, message)?,
        EvaluatorProvenance::new(
            "fortress-core/reference-resolution",
            REFERENCE_RESOLVER_SEMANTIC_VERSION,
        )?,
        edition,
        None,
    )
}

/// Reference-resolution failure distinct from normative findings.
#[derive(Debug)]
pub enum ReferenceResolutionError {
    /// CCG or projection serialization failed.
    Json(serde_json::Error),
    /// Understood Markdown or source bytes were not UTF-8.
    NonUtf8(String),
    /// Cargo resolution input could not be parsed structurally.
    Cargo {
        /// Repository-relative Cargo manifest.
        path: String,
        /// Parser failure.
        source: toml::de::Error,
    },
    /// Rust source could not be parsed structurally.
    Rust {
        /// Repository-relative source path.
        path: String,
        /// Parser failure.
        source: syn::Error,
    },
    /// Finding normalization failed.
    Finding(FindingError),
}

impl Display for ReferenceResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "resolution serialization failed: {source}"),
            Self::NonUtf8(path) => write!(
                formatter,
                "understood reference source `{path}` is not UTF-8"
            ),
            Self::Cargo { path, source } => write!(
                formatter,
                "Cargo resolution source `{path}` is invalid: {source}"
            ),
            Self::Rust { path, source } => write!(
                formatter,
                "Rust reference source `{path}` is invalid: {source}"
            ),
            Self::Finding(source) => write!(
                formatter,
                "reference finding normalization failed: {source}"
            ),
        }
    }
}

impl Error for ReferenceResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(source) => Some(source),
            Self::Cargo { source, .. } => Some(source),
            Self::Rust { source, .. } => Some(source),
            Self::Finding(source) => Some(source),
            Self::NonUtf8(_) => None,
        }
    }
}

impl From<serde_json::Error> for ReferenceResolutionError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<FindingError> for ReferenceResolutionError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}

/// Invalid relocation preview request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelocationError {
    /// Stable Module identity is absent.
    UnknownModule(String),
    /// Root Module cannot move beneath itself.
    RootMove,
    /// Destination would place a Module beneath its own subtree.
    ContainmentCycle,
    /// Destination is not canonical repository-relative form.
    InvalidDestination(String),
    /// Destination overlaps a different current Module.
    DestinationCollision(String),
}

impl Display for RelocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownModule(id) => write!(formatter, "unknown Module identity `{id}`"),
            Self::RootMove => formatter.write_str("the repository root Module cannot be relocated"),
            Self::ContainmentCycle => {
                formatter.write_str("relocation would create a containment cycle")
            }
            Self::InvalidDestination(path) => write!(
                formatter,
                "relocation destination `{path}` is not canonical"
            ),
            Self::DestinationCollision(path) => write!(
                formatter,
                "relocation destination `{path}` collides with an unaffected Module"
            ),
        }
    }
}

impl Error for RelocationError {}

/// README projection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Stable Module identity is absent.
    UnknownModule(String),
    /// More than one relationship target has the same display name.
    AmbiguousDisplayName(String),
    /// Canonical relationship heading could not be interpreted.
    MalformedHeading(String),
}

impl Display for ProjectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownModule(id) => write!(formatter, "unknown Module identity `{id}`"),
            Self::AmbiguousDisplayName(name) => {
                write!(formatter, "relationship display name `{name}` is ambiguous")
            }
            Self::MalformedHeading(value) => {
                write!(formatter, "malformed relationship heading `{value}`")
            }
        }
    }
}

impl Error for ProjectionError {}
