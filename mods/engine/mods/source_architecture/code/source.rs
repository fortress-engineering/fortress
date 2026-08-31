//! Language-neutral governed source-artifact architecture.
//!
//! This module composes Project Filing membership, canonical authored file
//! responsibilities, optional language-profile observations, and stable
//! references to richer program semantics. Registered adapters may project
//! language syntax into structural facts; this module does not perform deep
//! program semantics or define universal language idioms.

#[path = "rust.rs"]
mod rust;

pub use rust::{RustProfileError, observe_rust_source_profile};

pub(crate) const SOURCE_PROFILE_RULE_SOURCE: &str =
    include_str!("../data/source_profile_rule.json");
pub(crate) const SOURCE_ARTIFACT_RULE_SOURCE: &str =
    include_str!("../data/source_artifact_rule.json");

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::program_semantics::{ProgramSemanticModel, SymbolVisibility};

/// Standard Rust Source Profile identity.
pub const RUST_SOURCE_PROFILE_ID: &str = "FORTRESS-SOURCE-RUST";
/// Standard Rust Source Profile semantic version.
pub const RUST_SOURCE_PROFILE_VERSION: &str = "1.0.0";

/// Universal source-profile conformance rule.
pub const SOURCE_PROFILE_RULE_ID: &str = "SOURCE-PROFILE-001";
/// Governed source-artifact coherence rule.
pub const SOURCE_ARTIFACT_RULE_ID: &str = "SOURCE-ARTIFACT-001";
/// Source Artifact Model schema identity.
pub const SOURCE_ARTIFACT_MODEL_SCHEMA: &str = "urn:fortress:schema:v1:source-artifact-model";
/// Source Profile registry schema identity.
pub const SOURCE_PROFILE_SCHEMA: &str = "urn:fortress:schema:v1:source-profiles";
/// Source Artifact Model schema version.
pub const SOURCE_ARTIFACT_MODEL_SCHEMA_VERSION: u16 = 1;
/// Source Profile schema version.
pub const SOURCE_PROFILE_SCHEMA_VERSION: u16 = 1;

/// One authored direct-Code-file responsibility projected by the canonical
/// `code_docs.md` parser owned by Snapshot Governance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CodeFileResponsibility {
    source_path: String,
    module_id: String,
    documentation_path: String,
    responsibility: String,
}

impl CodeFileResponsibility {
    /// Creates one responsibility projection from parsed canonical Markdown.
    #[must_use]
    pub fn new(
        source_path: impl Into<String>,
        module_id: impl Into<String>,
        documentation_path: impl Into<String>,
        responsibility: impl Into<String>,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            module_id: module_id.into(),
            documentation_path: documentation_path.into(),
            responsibility: responsibility.into(),
        }
    }

    /// Returns the exact repository-relative governed source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns the stable owning Module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the canonical Markdown authority path.
    #[must_use]
    pub fn documentation_path(&self) -> &str {
        &self.documentation_path
    }

    /// Returns the substantive authored architectural responsibility.
    #[must_use]
    pub fn responsibility(&self) -> &str {
        &self.responsibility
    }
}
/// Semantic implementation version of Source Architecture.
pub const SOURCE_ARCHITECTURE_SEMANTIC_VERSION: &str = "1.1.0";

const PROFILE_REMEDIATION: &str = "Correct the registered language profile so its identity, adapter, extensions, semantic-region mapping, archetypes, composition constraints, and coverage limitations conform to Source Profile v1.";
const ARTIFACT_REMEDIATION: &str = "Document the file's single architectural responsibility in canonical code_docs.md, register or correct the applicable language profile, and align observed composition with exactly one permitted archetype without suppressing unsupported coverage.";

/// Closed language-neutral semantic concern vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticRegion {
    /// Stable artifact identity, ownership, and authored responsibility.
    IdentityResponsibility,
    /// Governed or external semantic dependencies.
    Dependencies,
    /// Language declarations observed in the artifact.
    Declarations,
    /// State-bearing declarations or accesses.
    State,
    /// Initialization semantics.
    Initialization,
    /// Publicly visible source surface.
    PublicInterface,
    /// Executable or otherwise concrete implementation.
    Implementation,
    /// Failure-bearing interfaces and mechanics.
    FailureSemantics,
    /// Proven externally meaningful effects.
    Effects,
    /// Authored human explanation of architectural intent.
    DocumentationIntent,
    /// Stable references to authoritative verification relationships.
    VerificationRelationships,
}

/// Canonical ordered semantic region vocabulary.
pub const SEMANTIC_REGIONS: [SemanticRegion; 11] = [
    SemanticRegion::IdentityResponsibility,
    SemanticRegion::Dependencies,
    SemanticRegion::Declarations,
    SemanticRegion::State,
    SemanticRegion::Initialization,
    SemanticRegion::PublicInterface,
    SemanticRegion::Implementation,
    SemanticRegion::FailureSemantics,
    SemanticRegion::Effects,
    SemanticRegion::DocumentationIntent,
    SemanticRegion::VerificationRelationships,
];

/// Epistemic state for one semantic concern.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegionCoverage {
    /// Supported semantic facts were observed.
    Observed,
    /// A supporting adapter established absence.
    Absent,
    /// The available analyzer cannot establish presence or absence.
    Unsupported,
    /// The concern does not apply under the resolved archetype.
    NotApplicable,
}

/// Human-authored versus generated source provenance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceProvenanceKind {
    /// Project-authored source.
    Human,
    /// Machine-produced compiled source.
    Generated,
}

/// Stable profile/archetype resolution state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchetypeResolution {
    /// No language identity was supplied by an observation adapter.
    LanguageUnknown,
    /// Language is known but no Source Profile is registered yet.
    ProfileNotRegistered,
    /// A registered profile's observation adapter is unavailable.
    ProfileUnsupported,
    /// Exactly one applicable archetype was proven.
    Resolved,
    /// No archetype accepts the supported observed composition.
    Missing,
    /// More than one archetype accepts the supported observed composition.
    Ambiguous,
}

/// Canonical Source Architecture finding vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceFindingKind {
    /// A Source Profile violates its universal contract.
    SourceProfileInvalid,
    /// A registered profile's required adapter is unavailable.
    SourceProfileUnsupported,
    /// No profile archetype accepts one applicable artifact.
    SourceArchetypeMissing,
    /// Multiple profile archetypes accept one artifact.
    SourceArchetypeAmbiguous,
    /// Canonical `code_docs.md` supplies no responsibility.
    SourceResponsibilityMissing,
    /// An archetype-required semantic concern is supported and absent.
    SourceRequiredRegionMissing,
    /// A forbidden semantic concern is present.
    SourceForbiddenRegionPresent,
    /// Observed declarations fall outside the archetype composition.
    SourceDeclarationCompositionInvalid,
    /// Generated source lacks exact generator provenance.
    SourceGeneratedProvenanceMissing,
    /// Required profile observation is outside current adapter support.
    SourceObservationUnsupported,
}

impl SourceFindingKind {
    /// Returns the canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceProfileInvalid => "SOURCE_PROFILE_INVALID",
            Self::SourceProfileUnsupported => "SOURCE_PROFILE_UNSUPPORTED",
            Self::SourceArchetypeMissing => "SOURCE_ARCHETYPE_MISSING",
            Self::SourceArchetypeAmbiguous => "SOURCE_ARCHETYPE_AMBIGUOUS",
            Self::SourceResponsibilityMissing => "SOURCE_RESPONSIBILITY_MISSING",
            Self::SourceRequiredRegionMissing => "SOURCE_REQUIRED_REGION_MISSING",
            Self::SourceForbiddenRegionPresent => "SOURCE_FORBIDDEN_REGION_PRESENT",
            Self::SourceDeclarationCompositionInvalid => "SOURCE_DECLARATION_COMPOSITION_INVALID",
            Self::SourceGeneratedProvenanceMissing => "SOURCE_GENERATED_PROVENANCE_MISSING",
            Self::SourceObservationUnsupported => "SOURCE_OBSERVATION_UNSUPPORTED",
        }
    }
}

/// Standard-owned registry of language-specific Source Profiles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceProfileRegistry {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    profiles: Vec<SourceProfile>,
}

/// One language-native realization of universal source architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceProfile {
    id: String,
    language: String,
    version: String,
    extensions: Vec<String>,
    generated_source_recognition: String,
    observation_adapter: String,
    archetypes: Vec<SourceArchetype>,
    semantic_region_mapping: Vec<SemanticRegionMapping>,
    visibility_mapping: Vec<VisibilityMapping>,
    responsibility_required: bool,
    coverage_limitations: Vec<String>,
}

/// Profile mapping from one adapter-native fact to a universal concern.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticRegionMapping {
    fact: String,
    region: SemanticRegion,
}

/// Profile mapping from language-native visibility to universal publicness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VisibilityMapping {
    native: String,
    public: bool,
}

/// One profile-owned coherent source-file composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceArchetype {
    id: String,
    required_regions: Vec<SemanticRegion>,
    allowed_regions: Vec<SemanticRegion>,
    forbidden_regions: Vec<SemanticRegion>,
}

impl SourceProfileRegistry {
    /// Parses and validates one Source Profile registry.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid JSON or universal profile invariants.
    pub fn from_json_str(source: &str) -> Result<Self, SourceProfileError> {
        let registry: Self = serde_json::from_str(source).map_err(SourceProfileError::Json)?;
        registry.validate()?;
        Ok(registry)
    }

    /// Loads the Standard-owned profile registry. It intentionally contains no
    /// Rust content profile until that separately governed milestone exists.
    ///
    /// # Panics
    ///
    /// Panics only when the embedded, repository-reviewed registry violates its
    /// own universal Source Profile contract.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_json_str(include_str!("../data/source_profiles.json"))
            .expect("embedded Source Profile registry must validate")
    }

    /// Returns registered profiles.
    #[must_use]
    pub fn profiles(&self) -> &[SourceProfile] {
        &self.profiles
    }

    fn validate(&self) -> Result<(), SourceProfileError> {
        if self.schema != SOURCE_PROFILE_SCHEMA {
            return Err(SourceProfileError::Model(
                "unsupported schema identity".into(),
            ));
        }
        if self.schema_version != SOURCE_PROFILE_SCHEMA_VERSION {
            return Err(SourceProfileError::Model(
                "unsupported Source Profile schema version".into(),
            ));
        }
        let mut profile_ids = BTreeSet::new();
        let mut language_extensions = BTreeSet::new();
        for profile in &self.profiles {
            if profile.id.trim().is_empty() || !profile_ids.insert(profile.id.as_str()) {
                return Err(SourceProfileError::Model(
                    "profile identities must be nonempty and unique".into(),
                ));
            }
            if profile.language.trim().is_empty()
                || profile.version.trim().is_empty()
                || profile.observation_adapter.trim().is_empty()
                || profile.generated_source_recognition.trim().is_empty()
                || profile.extensions.is_empty()
                || profile.archetypes.is_empty()
            {
                return Err(SourceProfileError::Model(
                    "profile language, version, extensions, generator recognition, adapter, and archetypes are required".into(),
                ));
            }
            let mut extensions = BTreeSet::new();
            for extension in &profile.extensions {
                if extension.is_empty()
                    || extension.starts_with('.')
                    || extension.contains(['/', '\\'])
                    || !extensions.insert(extension.as_str())
                    || !language_extensions.insert((profile.language.as_str(), extension.as_str()))
                {
                    return Err(SourceProfileError::Model(
                        "profile extensions must be unique canonical suffixes per language".into(),
                    ));
                }
            }
            let mut archetypes = BTreeSet::new();
            for archetype in &profile.archetypes {
                if archetype.id.trim().is_empty() || !archetypes.insert(archetype.id.as_str()) {
                    return Err(SourceProfileError::Model(
                        "archetype identities must be nonempty and profile-unique".into(),
                    ));
                }
                let required = ordered_unique(&archetype.required_regions)?;
                let allowed = ordered_unique(&archetype.allowed_regions)?;
                let forbidden = ordered_unique(&archetype.forbidden_regions)?;
                if !required.is_disjoint(&forbidden) || !allowed.is_disjoint(&forbidden) {
                    return Err(SourceProfileError::Model(
                        "an archetype cannot both permit and forbid one semantic region".into(),
                    ));
                }
            }
            let mut mapped_facts = BTreeSet::new();
            for mapping in &profile.semantic_region_mapping {
                if mapping.fact.trim().is_empty() || !mapped_facts.insert(mapping.fact.as_str()) {
                    return Err(SourceProfileError::Model(
                        "semantic-region mapping facts must be nonempty and unique".into(),
                    ));
                }
            }
            let mut visibility = BTreeSet::new();
            for mapping in &profile.visibility_mapping {
                if mapping.native.trim().is_empty() || !visibility.insert(mapping.native.as_str()) {
                    return Err(SourceProfileError::Model(
                        "visibility mappings must be nonempty and unique".into(),
                    ));
                }
                let _ = mapping.public;
            }
            if profile
                .coverage_limitations
                .iter()
                .any(|value| value.trim().is_empty())
            {
                return Err(SourceProfileError::Model(
                    "coverage limitations must be substantive".into(),
                ));
            }
        }
        Ok(())
    }
}

fn ordered_unique(
    values: &[SemanticRegion],
) -> Result<BTreeSet<SemanticRegion>, SourceProfileError> {
    let set = values.iter().copied().collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err(SourceProfileError::Model(
            "semantic-region lists cannot contain duplicates".into(),
        ));
    }
    Ok(set)
}

/// Source Profile loading failure.
#[derive(Debug)]
pub enum SourceProfileError {
    /// JSON syntax or typed shape was invalid.
    Json(serde_json::Error),
    /// Universal Source Profile invariant failed.
    Model(Box<str>),
}

impl Display for SourceProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "Source Profile JSON is invalid: {error}"),
            Self::Model(message) => write!(formatter, "Source Profile is invalid: {message}"),
        }
    }
}

impl Error for SourceProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Model(_) => None,
        }
    }
}

/// Adapter-supplied language identity independent from profile registration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LanguageAssignment {
    extension: String,
    language: String,
    analyzer: String,
}

impl LanguageAssignment {
    /// Creates one extension-to-language observation.
    #[must_use]
    pub fn new(
        extension: impl Into<String>,
        language: impl Into<String>,
        analyzer: impl Into<String>,
    ) -> Self {
        Self {
            extension: extension.into(),
            language: language.into(),
            analyzer: analyzer.into(),
        }
    }
}

/// One language-neutral source observation emitted by an adapter or reused
/// semantic model.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceObservation {
    path: String,
    region: SemanticRegion,
    coverage: RegionCoverage,
    analyzer: String,
    source_reference: String,
    start_line: Option<u32>,
}

/// Profile adapter conclusion about the native role of one source artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceArchetypeObservation {
    path: String,
    profile_id: String,
    candidates: Vec<String>,
    analyzer: String,
    source_reference: String,
}

impl SourceArchetypeObservation {
    /// Creates one deterministic profile-scoped archetype observation.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        profile_id: impl Into<String>,
        candidates: impl IntoIterator<Item = impl Into<String>>,
        analyzer: impl Into<String>,
        source_reference: impl Into<String>,
    ) -> Self {
        let mut candidates = candidates.into_iter().map(Into::into).collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        Self {
            path: path.into(),
            profile_id: profile_id.into(),
            candidates,
            analyzer: analyzer.into(),
            source_reference: source_reference.into(),
        }
    }

    /// Returns the repository-relative artifact path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns deterministic candidate archetypes established by the adapter.
    #[must_use]
    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }
}

/// One language-native structural fact retained inside a profile conclusion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceProfileFact {
    profile_id: String,
    kind: String,
    name: Option<String>,
    visibility: Option<String>,
    coverage: RegionCoverage,
    source_reference: String,
    start_line: Option<u32>,
}

impl SourceProfileFact {
    /// Creates one deterministic profile-scoped structural fact.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: impl Into<String>,
        kind: impl Into<String>,
        name: Option<String>,
        visibility: Option<String>,
        coverage: RegionCoverage,
        source_reference: impl Into<String>,
        start_line: Option<u32>,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            kind: kind.into(),
            name,
            visibility,
            coverage,
            source_reference: source_reference.into(),
            start_line,
        }
    }

    /// Returns the profile-native fact kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the observed native visibility, when applicable.
    #[must_use]
    pub fn visibility(&self) -> Option<&str> {
        self.visibility.as_deref()
    }

    /// Returns truthful coverage for this native structural concern.
    #[must_use]
    pub const fn coverage(&self) -> RegionCoverage {
        self.coverage
    }
}

impl SourceObservation {
    /// Creates one deterministic observation fact.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        region: SemanticRegion,
        coverage: RegionCoverage,
        analyzer: impl Into<String>,
        source_reference: impl Into<String>,
        start_line: Option<u32>,
    ) -> Self {
        Self {
            path: path.into(),
            region,
            coverage,
            analyzer: analyzer.into(),
            source_reference: source_reference.into(),
            start_line,
        }
    }
}

/// Explicit generated-source provenance supplied by a supported generator or
/// filing/profile adapter.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneratedSource {
    path: String,
    generator: Option<String>,
}

impl GeneratedSource {
    /// Creates a generated-source declaration.
    #[must_use]
    pub fn new(path: impl Into<String>, generator: Option<String>) -> Self {
        Self {
            path: path.into(),
            generator,
        }
    }
}

/// Stable verification authority projected onto one source artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceVerificationRelationship {
    path: String,
    feature: String,
    requirement: String,
    test: String,
}

impl SourceVerificationRelationship {
    /// Creates one existing Feature/Requirement/Test projection.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        feature: impl Into<String>,
        requirement: impl Into<String>,
        test: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            feature: feature.into(),
            requirement: requirement.into(),
            test: test.into(),
        }
    }
}

/// One region conclusion with exact evidence references and epistemic state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceRegion {
    region: SemanticRegion,
    coverage: RegionCoverage,
    evidence: Vec<SourceRegionEvidence>,
}

impl SourceRegion {
    /// Returns the universal semantic concern.
    #[must_use]
    pub const fn region(&self) -> SemanticRegion {
        self.region
    }

    /// Returns explicit epistemic coverage.
    #[must_use]
    pub const fn coverage(&self) -> RegionCoverage {
        self.coverage
    }
}

/// Provenance for one region observation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceRegionEvidence {
    analyzer: String,
    source_reference: String,
    start_line: Option<u32>,
}

/// Source provenance retained independently from source content.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceProvenance {
    kind: SourceProvenanceKind,
    generator: Option<String>,
}

/// Authored responsibility and its canonical Markdown provenance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AuthoredResponsibility {
    text: String,
    authority: String,
}

/// Profile/archetype conclusion for one artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceProfileEvaluation {
    status: ArchetypeResolution,
    profile_id: Option<String>,
    profile_version: Option<String>,
    archetype_id: Option<String>,
    candidate_archetypes: Vec<String>,
    coverage_limitations: Vec<String>,
    structural_facts: Vec<SourceProfileFact>,
}

impl SourceProfileEvaluation {
    /// Returns the profile/archetype resolution state.
    #[must_use]
    pub const fn status(&self) -> ArchetypeResolution {
        self.status
    }

    /// Returns the uniquely resolved archetype identity.
    #[must_use]
    pub fn archetype_id(&self) -> Option<&str> {
        self.archetype_id.as_deref()
    }

    /// Returns every matching archetype identity.
    #[must_use]
    pub fn candidate_archetypes(&self) -> &[String] {
        &self.candidate_archetypes
    }

    /// Returns native structural facts retained by the resolved profile.
    #[must_use]
    pub fn structural_facts(&self) -> &[SourceProfileFact] {
        &self.structural_facts
    }
}

/// Authority establishing source ownership independently from current placement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceArtifactOwnershipAuthority {
    /// Authored Fortress Module authority.
    DeclaredModule,
    /// Mechanical Cargo analysis territory.
    CargoAnalysisTerritory,
}

impl SourceArtifactOwnershipAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredModule => "DECLARED_MODULE",
            Self::CargoAnalysisTerritory => "CARGO_ANALYSIS_TERRITORY",
        }
    }
}

/// One normalized structural conclusion serialized in the derived model.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceConclusion {
    kind: SourceFindingKind,
    rule_id: String,
    artifact_id: String,
    path: String,
    message: String,
}

impl SourceConclusion {
    /// Returns the normalized conclusion kind.
    #[must_use]
    pub const fn kind(&self) -> SourceFindingKind {
        self.kind
    }
}

/// One language-neutral governed source artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceArtifact {
    id: String,
    path: String,
    module_id: String,
    module_relative_path: String,
    ownership_authority: SourceArtifactOwnershipAuthority,
    content_digest: String,
    provenance: SourceProvenance,
    authored_responsibility: Option<AuthoredResponsibility>,
    language: Option<String>,
    language_authority: Option<String>,
    profile: SourceProfileEvaluation,
    semantic_regions: Vec<SourceRegion>,
    structural_observations: Vec<String>,
    verification_relationships: Vec<SourceVerificationRelationship>,
    conclusions: Vec<SourceConclusion>,
}

impl SourceArtifact {
    /// Returns the location-stable semantic artifact identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns current repository-relative placement.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns stable owning Module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns whether ownership is authored Module authority or analysis-only Cargo authority.
    #[must_use]
    pub const fn ownership_authority(&self) -> SourceArtifactOwnershipAuthority {
        self.ownership_authority
    }

    /// Returns exact source content digest.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns profile/archetype resolution.
    #[must_use]
    pub const fn profile(&self) -> &SourceProfileEvaluation {
        &self.profile
    }

    /// Returns all universal semantic concern conclusions.
    #[must_use]
    pub fn semantic_regions(&self) -> &[SourceRegion] {
        &self.semantic_regions
    }

    /// Returns structural conclusions attached to this artifact.
    #[must_use]
    pub fn conclusions(&self) -> &[SourceConclusion] {
        &self.conclusions
    }

    /// Returns authored versus generated source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }
}

impl SourceProvenance {
    /// Returns whether source is human-authored or generated.
    #[must_use]
    pub const fn kind(&self) -> SourceProvenanceKind {
        self.kind
    }

    /// Returns exact generator identity when known.
    #[must_use]
    pub fn generator(&self) -> Option<&str> {
        self.generator.as_deref()
    }
}

/// Aggregate deterministic self/model counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SourceArtifactSummary {
    artifacts: usize,
    documented_responsibilities: usize,
    generated_artifacts: usize,
    profile_not_registered: usize,
    profile_resolved: usize,
    profile_missing: usize,
    profile_ambiguous: usize,
    observed_regions: usize,
    unsupported_regions: usize,
    verification_relationships: usize,
    findings: usize,
}

impl SourceArtifactSummary {
    /// Returns total governed Code artifacts.
    #[must_use]
    pub const fn artifacts(self) -> usize {
        self.artifacts
    }

    /// Returns artifacts with canonical authored responsibility.
    #[must_use]
    pub const fn documented_responsibilities(self) -> usize {
        self.documented_responsibilities
    }

    /// Returns artifacts whose language is known but profile is intentionally absent.
    #[must_use]
    pub const fn profile_not_registered(self) -> usize {
        self.profile_not_registered
    }

    /// Returns structural finding count.
    #[must_use]
    pub const fn findings(self) -> usize {
        self.findings
    }
}

/// Provenance envelope for the derived Source Artifact Model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceModelProvenance {
    responsibility_authority: String,
    project_model_authority: String,
    observation_authorities: Vec<String>,
    psm_digest: Option<String>,
}

/// Canonical derived Source Artifact Model v1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceArtifactModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: Option<String>,
    source_identity: String,
    universal_regions: Vec<SemanticRegion>,
    registered_profiles: Vec<String>,
    artifacts: Vec<SourceArtifact>,
    summary: SourceArtifactSummary,
    unsupported_semantics: Vec<String>,
    provenance: SourceModelProvenance,
}

/// One source artifact admitted by the shared observation/ownership boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceArtifactInput {
    path: String,
    owner: String,
    owner_relative_path: String,
    ownership_authority: SourceArtifactOwnershipAuthority,
}

impl SourceArtifactInput {
    /// Creates one explicit source-artifact membership relation.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        owner: impl Into<String>,
        owner_relative_path: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            owner: owner.into(),
            owner_relative_path: owner_relative_path.into(),
            ownership_authority: SourceArtifactOwnershipAuthority::DeclaredModule,
        }
    }

    /// Creates one artifact membership with explicit ownership authority.
    #[must_use]
    pub fn with_ownership_authority(
        path: impl Into<String>,
        owner: impl Into<String>,
        owner_relative_path: impl Into<String>,
        ownership_authority: SourceArtifactOwnershipAuthority,
    ) -> Self {
        Self {
            path: path.into(),
            owner: owner.into(),
            owner_relative_path: owner_relative_path.into(),
            ownership_authority,
        }
    }
}

impl SourceArtifactModel {
    /// Returns all governed source artifacts in canonical order.
    #[must_use]
    pub fn artifacts(&self) -> &[SourceArtifact] {
        &self.artifacts
    }

    /// Returns aggregate counts.
    #[must_use]
    pub const fn summary(&self) -> SourceArtifactSummary {
        self.summary
    }

    /// Returns exact model input identity.
    #[must_use]
    pub fn source_identity(&self) -> &str {
        &self.source_identity
    }

    /// Returns explicitly unsupported universal/source-profile semantics.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[String] {
        &self.unsupported_semantics
    }

    /// Serializes canonical UTF-8 pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the deterministic model is not representable.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut value| {
            value.push('\n');
            value
        })
    }

    /// Renders a deterministic profile-oriented human summary.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut output = format!(
            "Source Artifact Model\nArtifacts: {}\nRegistered profiles: {}\n\n",
            self.summary.artifacts,
            self.registered_profiles.join(", ")
        );
        for artifact in &self.artifacts {
            let profile = artifact
                .profile
                .profile_id
                .as_deref()
                .unwrap_or("UNREGISTERED");
            let archetype = artifact
                .profile
                .archetype_id
                .as_deref()
                .unwrap_or("UNRESOLVED");
            let responsibility = artifact
                .authored_responsibility
                .as_ref()
                .map_or("ABSENT", |value| value.text.as_str());
            let mut coverage = BTreeMap::<RegionCoverage, usize>::new();
            for region in &artifact.semantic_regions {
                *coverage.entry(region.coverage).or_default() += 1;
            }
            let mut visibility = BTreeMap::<&str, usize>::new();
            for fact in &artifact.profile.structural_facts {
                if let Some(native) = fact.visibility.as_deref() {
                    *visibility.entry(native).or_default() += 1;
                }
            }
            let _ = writeln!(
                output,
                "{}\n  profile: {} ({:?})\n  archetype: {}\n  owner: {} {}\n  responsibility: {}\n  provenance: {:?}{}\n  regions: {:?}\n  visibility: {:?}\n  limitations: {}\n",
                artifact.path,
                profile,
                artifact.profile.status,
                archetype,
                artifact.ownership_authority.as_str(),
                artifact.module_id,
                responsibility,
                artifact.provenance.kind,
                artifact
                    .provenance
                    .generator
                    .as_deref()
                    .map_or(String::new(), |generator| format!(" ({generator})")),
                coverage,
                visibility,
                artifact.profile.coverage_limitations.join("; ")
            );
        }
        output
    }
}

/// Rule-facing Source Architecture result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceArchitectureEvaluation {
    model: SourceArtifactModel,
    findings: Vec<CanonicalFinding>,
}

impl SourceArchitectureEvaluation {
    /// Returns the derived model.
    #[must_use]
    pub const fn model(&self) -> &SourceArtifactModel {
        &self.model
    }

    /// Returns normalized Standard findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Complete language-neutral compilation input.
pub struct SourceArchitectureInput<'a> {
    /// Stable project identity when authored authority exists.
    pub project_id: Option<&'a str>,
    /// Snapshot/content identity of exact input bytes.
    pub source_identity: &'a str,
    /// Source files admitted by the shared observation/ownership relation.
    pub artifacts: &'a [SourceArtifactInput],
    /// Authority used to resolve source membership and ownership.
    pub project_model_authority: &'a str,
    /// Exact repository file bytes.
    pub files: &'a BTreeMap<String, Vec<u8>>,
    /// Canonical `code_docs.md` responsibility projection.
    pub responsibilities: &'a [CodeFileResponsibility],
    /// Validated language-profile registry.
    pub profiles: &'a SourceProfileRegistry,
    /// Language assignments supplied by observation adapters.
    pub languages: &'a [LanguageAssignment],
    /// Universal observations supplied by adapters or semantic reuse.
    pub observations: &'a [SourceObservation],
    /// Profile-native archetype observations supplied by registered adapters.
    pub archetype_observations: &'a [SourceArchetypeObservation],
    /// Profile-native structural facts supplied by registered adapters.
    pub profile_facts: &'a BTreeMap<String, Vec<SourceProfileFact>>,
    /// Explicit generated source records.
    pub generated_sources: &'a [GeneratedSource],
    /// Existing authoritative verification relationships.
    pub verification_relationships: &'a [SourceVerificationRelationship],
    /// Adapter identities available for this compilation.
    pub available_adapters: &'a BTreeSet<String>,
    /// Digest of reused PSM facts, without copying the graph.
    pub psm_digest: Option<&'a str>,
    /// Applicable Standard edition.
    pub standard_edition: &'a str,
}

/// Compiles and evaluates Source Artifact Model v1 from already parsed Markdown
/// authority and adapter-supplied structural observations.
///
/// # Errors
///
/// Returns a normalized finding construction error when input paths cannot be
/// represented by the shared Finding Model.
#[allow(clippy::too_many_lines)]
pub fn evaluate_source_architecture(
    input: &SourceArchitectureInput<'_>,
) -> Result<SourceArchitectureEvaluation, FindingError> {
    let responsibilities = input
        .responsibilities
        .iter()
        .map(|entry| (entry.source_path(), entry))
        .collect::<BTreeMap<_, _>>();
    let generated = input
        .generated_sources
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let observations = group_observations(input.observations);
    let archetype_observations = group_archetype_observations(input.archetype_observations);
    let verifications = group_verification(input.verification_relationships);
    let language_map = input
        .languages
        .iter()
        .map(|entry| (entry.extension.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut artifacts = Vec::new();
    let mut conclusions = Vec::new();
    let mut source_inputs = input.artifacts.to_vec();
    source_inputs.sort();
    source_inputs.dedup();
    for entry in &source_inputs {
        let path = entry.path.as_str();
        let module_id = entry.owner.as_str();
        let module_relative_path = entry.owner_relative_path.as_str();
        let artifact_id = artifact_identity(module_id, module_relative_path);
        let bytes = input.files.get(path).map_or(&[][..], Vec::as_slice);
        let authored_responsibility =
            responsibilities
                .get(path)
                .map(|entry| AuthoredResponsibility {
                    text: entry.responsibility().to_owned(),
                    authority: entry.documentation_path().to_owned(),
                });
        let extension = path.rsplit_once('.').map_or("", |(_, value)| value);
        let language_assignment = language_map.get(extension).copied();
        let language = language_assignment.map(|entry| entry.language.clone());
        let language_authority = language_assignment.map(|entry| entry.analyzer.clone());
        let artifact_observations = observations.get(path).cloned().unwrap_or_default();
        let mut regions = compile_regions(
            &artifact_observations,
            authored_responsibility.is_some(),
            verifications
                .get(path)
                .is_some_and(|values| !values.is_empty()),
        );
        let source_provenance = generated.get(path).map_or(
            SourceProvenance {
                kind: SourceProvenanceKind::Human,
                generator: None,
            },
            |record| SourceProvenance {
                kind: SourceProvenanceKind::Generated,
                generator: record.generator.clone(),
            },
        );
        if source_provenance.kind == SourceProvenanceKind::Generated
            && source_provenance.generator.is_none()
        {
            push_conclusion(
                &mut conclusions,
                SourceFindingKind::SourceGeneratedProvenanceMissing,
                SOURCE_ARTIFACT_RULE_ID,
                &artifact_id,
                path,
                "Generated source has no exact generator identity.",
            );
        }
        let profile = resolve_profile(
            input,
            path,
            &artifact_id,
            language.as_deref(),
            extension,
            authored_responsibility.is_some(),
            source_provenance.kind,
            archetype_observations.get(path).map_or(&[], Vec::as_slice),
            input.profile_facts.get(path).map_or(&[], Vec::as_slice),
            &mut regions,
            &mut conclusions,
        );
        let artifact_conclusions = conclusions
            .iter()
            .filter(|conclusion| conclusion.artifact_id == artifact_id)
            .cloned()
            .collect();
        let mut structural_observations = artifact_observations
            .iter()
            .map(|observation| observation.source_reference.clone())
            .collect::<Vec<_>>();
        structural_observations.sort();
        structural_observations.dedup();
        artifacts.push(SourceArtifact {
            id: artifact_id,
            path: path.to_owned(),
            module_id: module_id.to_owned(),
            module_relative_path: module_relative_path.to_owned(),
            ownership_authority: entry.ownership_authority,
            content_digest: sha256(bytes),
            provenance: source_provenance,
            authored_responsibility,
            language,
            language_authority,
            profile,
            semantic_regions: regions,
            structural_observations,
            verification_relationships: verifications.get(path).cloned().unwrap_or_default(),
            conclusions: artifact_conclusions,
        });
    }
    artifacts.sort();
    conclusions.sort();
    conclusions.dedup();
    let findings = canonical_findings(&conclusions, input.standard_edition)?;
    let summary = summarize(&artifacts, findings.len());
    let mut registered_profiles = input
        .profiles
        .profiles
        .iter()
        .map(|profile| format!("{}@{}", profile.id, profile.version))
        .collect::<Vec<_>>();
    registered_profiles.sort();
    let mut observation_authorities = input
        .observations
        .iter()
        .map(|fact| fact.analyzer.clone())
        .chain(input.languages.iter().map(|fact| fact.analyzer.clone()))
        .collect::<Vec<_>>();
    observation_authorities.sort();
    observation_authorities.dedup();
    Ok(SourceArchitectureEvaluation {
        model: SourceArtifactModel {
            schema: SOURCE_ARTIFACT_MODEL_SCHEMA.into(),
            schema_version: SOURCE_ARTIFACT_MODEL_SCHEMA_VERSION,
            semantic_version: SOURCE_ARCHITECTURE_SEMANTIC_VERSION.into(),
            project_id: input.project_id.map(str::to_owned),
            source_identity: input.source_identity.into(),
            universal_regions: SEMANTIC_REGIONS.to_vec(),
            registered_profiles,
            artifacts,
            summary,
            unsupported_semantics: vec![
                "language-specific source-file idioms without a registered Source Profile".into(),
                "semantic natural-language responsibility-to-code matching".into(),
                "universal textual source ordering".into(),
                "automatic source splitting or rewriting".into(),
                "deep program correctness beyond referenced semantic analyzers".into(),
            ],
            provenance: SourceModelProvenance {
                responsibility_authority: "snapshot-governance/canonical-code-docs-v1".into(),
                project_model_authority: input.project_model_authority.into(),
                observation_authorities,
                psm_digest: input.psm_digest.map(str::to_owned),
            },
        },
        findings,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn resolve_profile(
    input: &SourceArchitectureInput<'_>,
    path: &str,
    artifact_id: &str,
    language: Option<&str>,
    extension: &str,
    has_responsibility: bool,
    provenance: SourceProvenanceKind,
    archetype_observations: &[SourceArchetypeObservation],
    profile_facts: &[SourceProfileFact],
    regions: &mut [SourceRegion],
    conclusions: &mut Vec<SourceConclusion>,
) -> SourceProfileEvaluation {
    let Some(language) = language else {
        return unresolved_profile(ArchetypeResolution::LanguageUnknown);
    };
    let candidates = input
        .profiles
        .profiles
        .iter()
        .filter(|profile| {
            profile.language == language
                && profile.extensions.iter().any(|value| value == extension)
        })
        .collect::<Vec<_>>();
    let Some(profile) = candidates.first().copied() else {
        return unresolved_profile(ArchetypeResolution::ProfileNotRegistered);
    };
    if !input
        .available_adapters
        .contains(&profile.observation_adapter)
    {
        push_conclusion(
            conclusions,
            SourceFindingKind::SourceProfileUnsupported,
            SOURCE_PROFILE_RULE_ID,
            artifact_id,
            path,
            format!(
                "Profile `{}` requires unavailable observation adapter `{}`.",
                profile.id, profile.observation_adapter
            ),
        );
        return SourceProfileEvaluation {
            status: ArchetypeResolution::ProfileUnsupported,
            profile_id: Some(profile.id.clone()),
            profile_version: Some(profile.version.clone()),
            archetype_id: None,
            candidate_archetypes: Vec::new(),
            coverage_limitations: profile.coverage_limitations.clone(),
            structural_facts: profile_facts
                .iter()
                .filter(|fact| fact.profile_id == profile.id)
                .cloned()
                .collect(),
        };
    }
    if profile.responsibility_required && !has_responsibility {
        push_conclusion(
            conclusions,
            SourceFindingKind::SourceResponsibilityMissing,
            SOURCE_ARTIFACT_RULE_ID,
            artifact_id,
            path,
            "Canonical code_docs.md contains no substantive responsibility for this source artifact.",
        );
    }
    let coverage = regions
        .iter()
        .map(|region| (region.region, region.coverage))
        .collect::<BTreeMap<_, _>>();
    let mut assigned = archetype_observations
        .iter()
        .filter(|observation| observation.profile_id == profile.id)
        .flat_map(|observation| observation.candidates.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if provenance == SourceProvenanceKind::Generated && profile.id == RUST_SOURCE_PROFILE_ID {
        assigned = vec!["RUST_GENERATED_SOURCE"];
    }
    assigned.sort_unstable();
    assigned.dedup();
    let matching = if assigned.is_empty() {
        profile
            .archetypes
            .iter()
            .filter(|archetype| archetype_matches(archetype, &coverage))
            .collect::<Vec<_>>()
    } else {
        assigned
            .iter()
            .filter_map(|candidate| {
                profile
                    .archetypes
                    .iter()
                    .find(|archetype| archetype.id == *candidate)
            })
            .collect::<Vec<_>>()
    };
    let status = match matching.len() {
        0 => ArchetypeResolution::Missing,
        1 => ArchetypeResolution::Resolved,
        _ => ArchetypeResolution::Ambiguous,
    };
    if status == ArchetypeResolution::Missing {
        push_conclusion(
            conclusions,
            SourceFindingKind::SourceArchetypeMissing,
            SOURCE_ARTIFACT_RULE_ID,
            artifact_id,
            path,
            format!(
                "No `{}` profile archetype accepts the supported observed composition.",
                profile.id
            ),
        );
        for archetype in &profile.archetypes {
            for required in &archetype.required_regions {
                match coverage.get(required) {
                    Some(RegionCoverage::Absent) => push_conclusion(
                        conclusions,
                        SourceFindingKind::SourceRequiredRegionMissing,
                        SOURCE_ARTIFACT_RULE_ID,
                        artifact_id,
                        path,
                        format!(
                            "Archetype `{}` requires absent region `{required:?}`.",
                            archetype.id
                        ),
                    ),
                    Some(RegionCoverage::Unsupported) | None => push_conclusion(
                        conclusions,
                        SourceFindingKind::SourceObservationUnsupported,
                        SOURCE_ARTIFACT_RULE_ID,
                        artifact_id,
                        path,
                        format!(
                            "Archetype `{}` requires unsupported observation for `{required:?}`.",
                            archetype.id
                        ),
                    ),
                    _ => {}
                }
            }
            for forbidden in &archetype.forbidden_regions {
                if coverage.get(forbidden) == Some(&RegionCoverage::Observed) {
                    push_conclusion(
                        conclusions,
                        SourceFindingKind::SourceForbiddenRegionPresent,
                        SOURCE_ARTIFACT_RULE_ID,
                        artifact_id,
                        path,
                        format!(
                            "Archetype `{}` forbids observed region `{forbidden:?}`.",
                            archetype.id
                        ),
                    );
                }
            }
        }
    } else if status == ArchetypeResolution::Resolved {
        let archetype = matching[0];
        let allowed = archetype
            .required_regions
            .iter()
            .chain(&archetype.allowed_regions)
            .copied()
            .collect::<BTreeSet<_>>();
        if !allowed.is_empty() {
            for region in regions.iter().filter(|region| {
                region.coverage == RegionCoverage::Observed
                    && !allowed.contains(&region.region)
                    && !matches!(
                        region.region,
                        SemanticRegion::IdentityResponsibility
                            | SemanticRegion::DocumentationIntent
                            | SemanticRegion::VerificationRelationships
                    )
            }) {
                push_conclusion(
                    conclusions,
                    SourceFindingKind::SourceDeclarationCompositionInvalid,
                    SOURCE_ARTIFACT_RULE_ID,
                    artifact_id,
                    path,
                    format!(
                        "Archetype `{}` does not permit observed region `{:?}`.",
                        archetype.id, region.region
                    ),
                );
            }
        }
        for region in regions.iter_mut().filter(|region| {
            region.coverage == RegionCoverage::Unsupported
                && !allowed.contains(&region.region)
                && !archetype.forbidden_regions.contains(&region.region)
        }) {
            region.coverage = RegionCoverage::NotApplicable;
        }
    }
    SourceProfileEvaluation {
        status,
        profile_id: Some(profile.id.clone()),
        profile_version: Some(profile.version.clone()),
        archetype_id: (matching.len() == 1).then(|| matching[0].id.clone()),
        candidate_archetypes: matching.iter().map(|item| item.id.clone()).collect(),
        coverage_limitations: profile.coverage_limitations.clone(),
        structural_facts: profile_facts
            .iter()
            .filter(|fact| fact.profile_id == profile.id)
            .cloned()
            .collect(),
    }
}

fn unresolved_profile(status: ArchetypeResolution) -> SourceProfileEvaluation {
    SourceProfileEvaluation {
        status,
        profile_id: None,
        profile_version: None,
        archetype_id: None,
        candidate_archetypes: Vec::new(),
        coverage_limitations: vec![
            "language-specific archetype classification is not registered".into(),
        ],
        structural_facts: Vec::new(),
    }
}

fn group_archetype_observations(
    observations: &[SourceArchetypeObservation],
) -> BTreeMap<&str, Vec<SourceArchetypeObservation>> {
    let mut grouped = BTreeMap::<&str, Vec<SourceArchetypeObservation>>::new();
    for observation in observations {
        grouped
            .entry(observation.path.as_str())
            .or_default()
            .push(observation.clone());
    }
    for values in grouped.values_mut() {
        values.sort();
        values.dedup();
    }
    grouped
}

fn archetype_matches(
    archetype: &SourceArchetype,
    coverage: &BTreeMap<SemanticRegion, RegionCoverage>,
) -> bool {
    archetype
        .required_regions
        .iter()
        .all(|region| coverage.get(region) == Some(&RegionCoverage::Observed))
        && archetype
            .forbidden_regions
            .iter()
            .all(|region| coverage.get(region) != Some(&RegionCoverage::Observed))
}

fn compile_regions(
    observations: &[SourceObservation],
    has_responsibility: bool,
    has_verification: bool,
) -> Vec<SourceRegion> {
    SEMANTIC_REGIONS
        .iter()
        .copied()
        .map(|region| {
            let relevant = observations
                .iter()
                .filter(|observation| observation.region == region)
                .collect::<Vec<_>>();
            let implicit = match region {
                SemanticRegion::IdentityResponsibility => Some(RegionCoverage::Observed),
                SemanticRegion::DocumentationIntent if has_responsibility => {
                    Some(RegionCoverage::Observed)
                }
                SemanticRegion::VerificationRelationships => Some(if has_verification {
                    RegionCoverage::Observed
                } else {
                    RegionCoverage::Absent
                }),
                _ => None,
            };
            let coverage = implicit.unwrap_or_else(|| join_coverage(&relevant));
            let mut evidence = relevant
                .iter()
                .map(|observation| SourceRegionEvidence {
                    analyzer: observation.analyzer.clone(),
                    source_reference: observation.source_reference.clone(),
                    start_line: observation.start_line,
                })
                .collect::<Vec<_>>();
            if implicit.is_some() && evidence.is_empty() {
                evidence.push(SourceRegionEvidence {
                    analyzer: if region == SemanticRegion::VerificationRelationships {
                        "contract-coherency/test-traceability".into()
                    } else {
                        "snapshot-governance/canonical-code-docs-v1".into()
                    },
                    source_reference: if region == SemanticRegion::VerificationRelationships {
                        "stable Feature/Requirement/Test identity".into()
                    } else {
                        "docs/code_docs.md#Files".into()
                    },
                    start_line: None,
                });
            }
            evidence.sort();
            evidence.dedup();
            SourceRegion {
                region,
                coverage,
                evidence,
            }
        })
        .collect()
}

fn join_coverage(observations: &[&SourceObservation]) -> RegionCoverage {
    if observations
        .iter()
        .any(|observation| observation.coverage == RegionCoverage::Observed)
    {
        RegionCoverage::Observed
    } else if observations
        .iter()
        .any(|observation| observation.coverage == RegionCoverage::Unsupported)
    {
        RegionCoverage::Unsupported
    } else if observations
        .iter()
        .any(|observation| observation.coverage == RegionCoverage::Absent)
    {
        RegionCoverage::Absent
    } else if observations
        .iter()
        .any(|observation| observation.coverage == RegionCoverage::NotApplicable)
    {
        RegionCoverage::NotApplicable
    } else {
        RegionCoverage::Unsupported
    }
}

fn group_observations(
    observations: &[SourceObservation],
) -> BTreeMap<&str, Vec<SourceObservation>> {
    let mut grouped = BTreeMap::<&str, Vec<SourceObservation>>::new();
    for observation in observations {
        grouped
            .entry(observation.path.as_str())
            .or_default()
            .push(observation.clone());
    }
    for values in grouped.values_mut() {
        values.sort();
        values.dedup();
    }
    grouped
}

fn group_verification(
    relationships: &[SourceVerificationRelationship],
) -> BTreeMap<&str, Vec<SourceVerificationRelationship>> {
    let mut grouped = BTreeMap::<&str, Vec<SourceVerificationRelationship>>::new();
    for relationship in relationships {
        grouped
            .entry(relationship.path.as_str())
            .or_default()
            .push(relationship.clone());
    }
    for values in grouped.values_mut() {
        values.sort();
        values.dedup();
    }
    grouped
}

fn push_conclusion(
    conclusions: &mut Vec<SourceConclusion>,
    kind: SourceFindingKind,
    rule_id: &str,
    artifact_id: &str,
    path: &str,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    conclusions.push(SourceConclusion {
        kind,
        rule_id: rule_id.into(),
        artifact_id: artifact_id.into(),
        path: path.into(),
        message: format!("{}: {detail}", kind.as_str()),
    });
}

fn canonical_findings(
    conclusions: &[SourceConclusion],
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let evaluator = EvaluatorProvenance::new(
        "fortress-core/source-architecture",
        SOURCE_ARCHITECTURE_SEMANTIC_VERSION,
    )?;
    let mut findings = Vec::new();
    for conclusion in conclusions {
        let definition = RuleFindingDefinition::new(
            &conclusion.rule_id,
            1,
            FindingCategory::Source,
            if conclusion.rule_id == SOURCE_PROFILE_RULE_ID {
                PROFILE_REMEDIATION
            } else {
                ARTIFACT_REMEDIATION
            },
        )?;
        findings.push(CanonicalFinding::failure(
            definition,
            FindingOccurrence::new(
                Vec::new(),
                FindingLocation::at_path(&conclusion.path)?,
                conclusion.message.clone(),
            )?,
            evaluator.clone(),
            standard_edition,
        )?);
    }
    findings.sort();
    findings.dedup();
    Ok(findings)
}

fn summarize(artifacts: &[SourceArtifact], findings: usize) -> SourceArtifactSummary {
    let mut summary = SourceArtifactSummary {
        artifacts: artifacts.len(),
        findings,
        ..SourceArtifactSummary::default()
    };
    for artifact in artifacts {
        summary.documented_responsibilities +=
            usize::from(artifact.authored_responsibility.is_some());
        summary.generated_artifacts +=
            usize::from(artifact.provenance.kind == SourceProvenanceKind::Generated);
        match artifact.profile.status {
            ArchetypeResolution::ProfileNotRegistered => summary.profile_not_registered += 1,
            ArchetypeResolution::Resolved => summary.profile_resolved += 1,
            ArchetypeResolution::Missing => summary.profile_missing += 1,
            ArchetypeResolution::Ambiguous => summary.profile_ambiguous += 1,
            ArchetypeResolution::LanguageUnknown | ArchetypeResolution::ProfileUnsupported => {}
        }
        summary.verification_relationships += artifact.verification_relationships.len();
        summary.observed_regions += artifact
            .semantic_regions
            .iter()
            .filter(|region| region.coverage == RegionCoverage::Observed)
            .count();
        summary.unsupported_regions += artifact
            .semantic_regions
            .iter()
            .filter(|region| region.coverage == RegionCoverage::Unsupported)
            .count();
    }
    summary
}

fn artifact_identity(module_id: &str, module_relative_path: &str) -> String {
    sha256(format!(
        "source-artifact-v1\0{module_id}\0{module_relative_path}"
    ))
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes.as_ref()))
}

/// Projects existing PSM structure into lightweight universal observations.
///
/// The projection references stable PSM symbol/type identities and never copies
/// executable bodies or reconstructs language syntax.
#[must_use]
pub fn observations_from_psm(psm: &ProgramSemanticModel) -> Vec<SourceObservation> {
    let mut observations = Vec::new();
    let symbol_paths = psm
        .symbols()
        .iter()
        .map(|symbol| (symbol.id(), symbol.source_path()))
        .collect::<BTreeMap<_, _>>();
    for symbol in psm.symbols() {
        observations.push(SourceObservation::new(
            symbol.source_path(),
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            "fortress-core/program-semantics-v3",
            format!("symbol:{}", symbol.id()),
            Some(symbol.provenance().location().line()),
        ));
        if symbol.has_body() {
            observations.push(SourceObservation::new(
                symbol.source_path(),
                SemanticRegion::Implementation,
                RegionCoverage::Observed,
                "fortress-core/program-semantics-v3",
                format!("symbol-body:{}", symbol.id()),
                Some(symbol.provenance().location().line()),
            ));
        }
        if symbol.visibility() == &SymbolVisibility::Public {
            observations.push(SourceObservation::new(
                symbol.source_path(),
                SemanticRegion::PublicInterface,
                RegionCoverage::Observed,
                "fortress-core/program-semantics-v3",
                format!("public-symbol:{}", symbol.id()),
                Some(symbol.provenance().location().line()),
            ));
        }
    }
    for nominal in psm.nominal_types() {
        observations.push(SourceObservation::new(
            nominal.provenance().path(),
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            "fortress-core/program-semantics-v3",
            format!("nominal-type:{}", nominal.id()),
            Some(nominal.provenance().location().line()),
        ));
    }
    for call in psm.calls() {
        if let Some(path) = symbol_paths.get(call.caller()) {
            observations.push(SourceObservation::new(
                *path,
                SemanticRegion::Dependencies,
                RegionCoverage::Observed,
                "fortress-core/program-semantics-v3",
                call.callee().map_or_else(
                    || format!("call:{:?}", call.state()),
                    |callee| format!("callee:{callee}"),
                ),
                call.evidence()
                    .first()
                    .map(|evidence| evidence.provenance().location().line()),
            ));
        }
    }
    for read in psm.state_reads() {
        observations.push(SourceObservation::new(
            read.provenance().path(),
            SemanticRegion::State,
            RegionCoverage::Observed,
            "fortress-core/program-semantics-v3",
            format!("state-read:{}", read.symbol()),
            Some(read.provenance().location().line()),
        ));
    }
    for mutation in psm.mutations() {
        observations.push(SourceObservation::new(
            mutation.provenance().path(),
            SemanticRegion::State,
            RegionCoverage::Observed,
            "fortress-core/program-semantics-v3",
            format!("mutation:{}", mutation.symbol()),
            Some(mutation.provenance().location().line()),
        ));
    }
    observations.sort();
    observations.dedup();
    observations
}
