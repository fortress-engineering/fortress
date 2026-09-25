//! Immutable governance and assurance profile resolution.
//!
//! Profile definitions belong to the Standard. Projects select exact
//! id/version/digest references through the existing project configuration.
//! Resolution composes requirements without array-order precedence and keeps
//! missing assurance evidence separate from semantic truth verdicts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::standard::StandardBundle;

const INSTALLED_PROFILES: &str = include_str!("../_data/governance_profiles_v1.json");

/// Native governance profile used by legacy project configurations that have
/// not yet authored explicit v4 selection authority.
pub const NATIVE_GOVERNANCE_PROFILE_ID: &str = "GOV-FORTRESS-NATIVE";
/// Strict canonical Project Filing governance profile.
pub const CANONICAL_GOVERNANCE_PROFILE_ID: &str = "GOV-FORTRESS-CANONICAL";
/// Standard assurance profile requiring explicit semantic evaluability evidence.
pub const EVALUABILITY_ASSURANCE_PROFILE_ID: &str = "ASSURE-SEMANTIC-EVALUABILITY";

/// Exact project-authored profile reference presented to the Standard resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileReferenceInput {
    id: String,
    version: String,
    digest: String,
}

impl ProfileReferenceInput {
    /// Creates one already shape-validated project reference.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            digest: digest.into(),
        }
    }
}

/// Stable Module-scoped project selection presented to the resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleProfileSelectionInput {
    module: String,
    selected_profiles: Vec<ProfileReferenceInput>,
    assurance_profiles: Vec<ProfileReferenceInput>,
}

impl ModuleProfileSelectionInput {
    /// Creates one stable-ID Module selection without accepting a physical path.
    #[must_use]
    pub fn new(
        module: impl Into<String>,
        selected_profiles: Vec<ProfileReferenceInput>,
        assurance_profiles: Vec<ProfileReferenceInput>,
    ) -> Self {
        Self {
            module: module.into(),
            selected_profiles,
            assurance_profiles,
        }
    }
}

/// Complete Project Model output consumed by profile resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSelectionInput {
    default_layout: String,
    selected_profiles: Vec<ProfileReferenceInput>,
    module_overrides: Vec<ModuleProfileSelectionInput>,
    assurance_profiles: Vec<ProfileReferenceInput>,
}

impl ProfileSelectionInput {
    /// Creates one validated project selection boundary value.
    #[must_use]
    pub fn new(
        default_layout: impl Into<String>,
        selected_profiles: Vec<ProfileReferenceInput>,
        module_overrides: Vec<ModuleProfileSelectionInput>,
        assurance_profiles: Vec<ProfileReferenceInput>,
    ) -> Self {
        Self {
            default_layout: default_layout.into(),
            selected_profiles,
            module_overrides,
            assurance_profiles,
        }
    }
}

/// Closed profile purpose vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProfileKind {
    /// Selects rule applicability, layout interpretation, and semantic scope.
    Governance,
    /// Adds evidence requirements without changing semantic verdicts.
    Assurance,
}

/// One Standard-owned required evidence descriptor.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEvidenceDescriptor {
    id: String,
    semantic_scope: String,
    evidence_class: RequiredEvidenceClass,
}

/// Closed evidence class vocabulary that profiles may require.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredEvidenceClass {
    /// Current deterministic evaluator proof.
    StaticProof,
    /// Current executed test evidence.
    ExecutedTest,
    /// Current executed scenario evidence.
    ExecutedScenario,
    /// Current authored or derived authority evidence.
    Authority,
}

impl RequiredEvidenceDescriptor {
    /// Returns the stable evidence requirement identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the semantic scope whose evaluability is required.
    #[must_use]
    pub fn semantic_scope(&self) -> &str {
        &self.semantic_scope
    }

    /// Returns the required evidence class.
    #[must_use]
    pub const fn evidence_class(&self) -> RequiredEvidenceClass {
        self.evidence_class
    }
}

/// Installed immutable profile registry document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    profiles: Vec<ProfileDefinition>,
}

/// One content-addressed profile definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileDefinition {
    id: String,
    version: String,
    digest: String,
    kind: ProfileKind,
    layout_id: Option<String>,
    active_rules: Vec<String>,
    semantic_scopes: Vec<String>,
    required_evidence: Vec<RequiredEvidenceDescriptor>,
    conflicts: Vec<String>,
}

#[derive(Serialize)]
struct ProfileDefinitionBody<'a> {
    id: &'a str,
    version: &'a str,
    kind: ProfileKind,
    layout_id: Option<&'a str>,
    active_rules: &'a [String],
    semantic_scopes: &'a [String],
    required_evidence: &'a [RequiredEvidenceDescriptor],
    conflicts: &'a [String],
}

impl ProfileDefinition {
    fn computed_digest(&self) -> Result<String, ProfileResolutionError> {
        let bytes = serde_json_canonicalizer::to_vec(&ProfileDefinitionBody {
            id: &self.id,
            version: &self.version,
            kind: self.kind,
            layout_id: self.layout_id.as_deref(),
            active_rules: &self.active_rules,
            semantic_scopes: &self.semantic_scopes,
            required_evidence: &self.required_evidence,
            conflicts: &self.conflicts,
        })
        .map_err(|error| ProfileResolutionError::Serialization(error.to_string().into()))?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

/// One resolved Module-scoped composition keyed only by stable Module ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedModuleProfiles {
    active_rules: BTreeSet<String>,
    required_evidence: Vec<RequiredEvidenceDescriptor>,
}

impl ResolvedModuleProfiles {
    /// Returns whether a Standard rule applies to this Module.
    #[must_use]
    pub fn rule_applicable(&self, rule_id: &str) -> bool {
        self.active_rules.contains(rule_id)
    }

    /// Returns the exact Module-scoped evidence requirement manifest.
    #[must_use]
    pub fn required_evidence(&self) -> &[RequiredEvidenceDescriptor] {
        &self.required_evidence
    }
}

/// Deterministic effective project policy produced from Standard definitions
/// and one project selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProfiles {
    layout_id: String,
    selected_profiles: Vec<String>,
    authority_digests: Vec<String>,
    active_rules: BTreeSet<String>,
    semantic_scopes: BTreeSet<String>,
    required_evidence: Vec<RequiredEvidenceDescriptor>,
    module_overrides: BTreeMap<String, ResolvedModuleProfiles>,
}

impl ResolvedProfiles {
    /// Returns the effective repository layout interpretation.
    #[must_use]
    pub fn layout_id(&self) -> &str {
        &self.layout_id
    }

    /// Returns selected profile identities in canonical order.
    #[must_use]
    pub fn selected_profiles(&self) -> &[String] {
        &self.selected_profiles
    }

    /// Returns exact profile definition digests for evaluation authority binding.
    #[must_use]
    pub fn authority_digests(&self) -> &[String] {
        &self.authority_digests
    }

    /// Returns whether a Standard rule is active for the repository scope.
    #[must_use]
    pub fn rule_applicable(&self, rule_id: &str) -> bool {
        self.active_rules.contains(rule_id)
    }

    /// Returns composed semantic scopes.
    #[must_use]
    pub const fn semantic_scopes(&self) -> &BTreeSet<String> {
        &self.semantic_scopes
    }

    /// Returns the exact project assurance requirement manifest.
    #[must_use]
    pub fn required_evidence(&self) -> &[RequiredEvidenceDescriptor] {
        &self.required_evidence
    }

    /// Returns a stable Module-scoped override, if selected.
    #[must_use]
    pub fn module(&self, module_id: &str) -> Option<&ResolvedModuleProfiles> {
        self.module_overrides.get(module_id)
    }

    /// Evaluates only presence of required evidence. Semantic outcomes are not
    /// inputs and therefore cannot be rewritten by an assurance profile.
    #[must_use]
    pub fn assess_required_evidence(
        &self,
        available_evidence: &BTreeSet<String>,
    ) -> Vec<AssuranceAssessment> {
        self.required_evidence
            .iter()
            .map(|requirement| AssuranceAssessment {
                requirement: requirement.id.clone(),
                outcome: if available_evidence.contains(requirement.id()) {
                    AssuranceOutcome::Satisfied
                } else {
                    AssuranceOutcome::RequiredEvidenceMissing
                },
            })
            .collect()
    }
}

/// Assurance-only evidence availability result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceAssessment {
    requirement: String,
    outcome: AssuranceOutcome,
}

impl AssuranceAssessment {
    /// Returns the required evidence descriptor identity.
    #[must_use]
    pub fn requirement(&self) -> &str {
        &self.requirement
    }

    /// Returns evidence availability without changing any semantic verdict.
    #[must_use]
    pub const fn outcome(&self) -> AssuranceOutcome {
        self.outcome
    }
}

/// Closed assurance evidence availability vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceOutcome {
    /// The selected evidence descriptor is satisfied.
    Satisfied,
    /// The profile requires evidence that is absent.
    RequiredEvidenceMissing,
}

/// Resolves the installed Standard profile definitions against project
/// selection and the CCG's stable Module identity index.
///
/// # Errors
///
/// Returns [`ProfileResolutionError`] for invalid installed data, stale or
/// unknown references, incompatible composition, unknown rules, or unknown
/// Module scope.
pub fn resolve_profiles(
    standard: &StandardBundle,
    selection: Option<&ProfileSelectionInput>,
    module_ids: &BTreeSet<String>,
) -> Result<ResolvedProfiles, ProfileResolutionError> {
    let registry = load_registry(standard)?;
    let governance_definitions = if let Some(selection) = selection {
        resolve_references(
            &registry,
            &selection.selected_profiles,
            ProfileKind::Governance,
        )?
    } else {
        vec![
            registry
                .values()
                .find(|profile| profile.id == NATIVE_GOVERNANCE_PROFILE_ID)
                .ok_or_else(|| {
                    ProfileResolutionError::MissingDefaultProfile(
                        NATIVE_GOVERNANCE_PROFILE_ID.into(),
                    )
                })?,
        ]
    };
    let assurances = resolve_references(
        &registry,
        selection.map_or(&[], |selection| selection.assurance_profiles.as_slice()),
        ProfileKind::Assurance,
    )?;
    let mut resolved = compose_profiles(&governance_definitions, &assurances)?;
    if let Some(selection) = selection {
        if resolved.layout_id != selection.default_layout {
            return Err(ProfileResolutionError::LayoutSelectionMismatch {
                selected: selection.default_layout.clone(),
                resolved: resolved.layout_id,
            });
        }
        for profile_override in &selection.module_overrides {
            if !module_ids.contains(&profile_override.module) {
                return Err(ProfileResolutionError::UnknownModule(
                    profile_override.module.clone().into(),
                ));
            }
            let mut module_governance = governance_definitions.clone();
            module_governance.extend(resolve_references(
                &registry,
                &profile_override.selected_profiles,
                ProfileKind::Governance,
            )?);
            let mut module_assurance = assurances.clone();
            module_assurance.extend(resolve_references(
                &registry,
                &profile_override.assurance_profiles,
                ProfileKind::Assurance,
            )?);
            let module = compose_profiles(&module_governance, &module_assurance)?;
            resolved.authority_digests.extend(module.authority_digests);
            resolved.selected_profiles.extend(module.selected_profiles);
            resolved.module_overrides.insert(
                profile_override.module.clone(),
                ResolvedModuleProfiles {
                    active_rules: module.active_rules,
                    required_evidence: module.required_evidence,
                },
            );
        }
    }
    resolved.authority_digests.sort();
    resolved.authority_digests.dedup();
    resolved.selected_profiles.sort();
    resolved.selected_profiles.dedup();
    Ok(resolved)
}

fn load_registry(
    standard: &StandardBundle,
) -> Result<BTreeMap<(String, String), ProfileDefinition>, ProfileResolutionError> {
    crate::wire::reject_duplicate_json_keys(INSTALLED_PROFILES)
        .map_err(ProfileResolutionError::Json)?;
    let document: ProfileDocument =
        serde_json::from_str(INSTALLED_PROFILES).map_err(ProfileResolutionError::Json)?;
    if document.schema != "urn:fortress:schema:v1:governance-profiles"
        || document.schema_version != 1
    {
        return Err(ProfileResolutionError::UnsupportedRegistry);
    }
    let standard_rules = standard
        .rules()
        .iter()
        .map(super::standard::StandardRule::id)
        .collect::<BTreeSet<_>>();
    let mut registry = BTreeMap::new();
    for profile in document.profiles {
        if profile.computed_digest()? != profile.digest {
            return Err(ProfileResolutionError::DefinitionDigestMismatch(
                profile.id.into(),
            ));
        }
        reject_noncanonical_list(&profile.active_rules, &profile.id)?;
        reject_noncanonical_list(&profile.semantic_scopes, &profile.id)?;
        reject_noncanonical_list(&profile.conflicts, &profile.id)?;
        for rule in &profile.active_rules {
            if !standard_rules.contains(rule.as_str()) {
                return Err(ProfileResolutionError::UnknownRule(rule.clone().into()));
            }
        }
        let key = (profile.id.clone(), profile.version.clone());
        if registry.insert(key, profile).is_some() {
            return Err(ProfileResolutionError::DuplicateDefinition);
        }
    }
    Ok(registry)
}

fn reject_noncanonical_list(
    values: &[String],
    profile: &str,
) -> Result<(), ProfileResolutionError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProfileResolutionError::NoncanonicalDefinition(
            profile.into(),
        ));
    }
    Ok(())
}

fn resolve_references<'a>(
    registry: &'a BTreeMap<(String, String), ProfileDefinition>,
    references: &[ProfileReferenceInput],
    expected_kind: ProfileKind,
) -> Result<Vec<&'a ProfileDefinition>, ProfileResolutionError> {
    let mut resolved = Vec::with_capacity(references.len());
    for reference in references {
        let key = (reference.id.clone(), reference.version.clone());
        let profile = registry.get(&key).ok_or_else(|| {
            ProfileResolutionError::UnknownProfile(
                format!("{}@{}", reference.id, reference.version).into(),
            )
        })?;
        if profile.kind != expected_kind {
            return Err(ProfileResolutionError::WrongProfileKind(
                reference.id.clone().into(),
            ));
        }
        if profile.digest != reference.digest {
            return Err(ProfileResolutionError::ReferenceDigestMismatch(
                reference.id.clone().into(),
            ));
        }
        resolved.push(profile);
    }
    resolved.sort_by(|left, right| (&left.id, &left.version).cmp(&(&right.id, &right.version)));
    Ok(resolved)
}

fn compose_profiles(
    governance: &[&ProfileDefinition],
    assurances: &[&ProfileDefinition],
) -> Result<ResolvedProfiles, ProfileResolutionError> {
    if governance.is_empty() {
        return Err(ProfileResolutionError::MissingGovernanceProfile);
    }
    let all = governance
        .iter()
        .chain(assurances.iter())
        .copied()
        .collect::<Vec<_>>();
    let selected_ids = all
        .iter()
        .map(|profile| profile.id.as_str())
        .collect::<BTreeSet<_>>();
    for profile in &all {
        if let Some(conflict) = profile
            .conflicts
            .iter()
            .find(|conflict| selected_ids.contains(conflict.as_str()))
        {
            return Err(ProfileResolutionError::ConflictingProfiles {
                left: profile.id.clone(),
                right: conflict.clone(),
            });
        }
    }
    let layouts = governance
        .iter()
        .filter_map(|profile| profile.layout_id.as_deref())
        .collect::<BTreeSet<_>>();
    if layouts.len() != 1 {
        return Err(ProfileResolutionError::IncompatibleLayouts);
    }
    let mut active_rules = BTreeSet::new();
    let mut semantic_scopes = BTreeSet::new();
    let mut required_evidence = BTreeSet::new();
    let mut authority_digests = Vec::new();
    let mut selected_profiles = Vec::new();
    for profile in all {
        active_rules.extend(profile.active_rules.iter().cloned());
        semantic_scopes.extend(profile.semantic_scopes.iter().cloned());
        required_evidence.extend(profile.required_evidence.iter().cloned());
        authority_digests.push(profile.digest.clone());
        selected_profiles.push(format!("{}@{}", profile.id, profile.version));
    }
    // Stable identity validation is an invariant of every evaluation and cannot
    // be disabled by profile composition.
    active_rules.insert("STD-ID-001".into());
    authority_digests.sort();
    authority_digests.dedup();
    selected_profiles.sort();
    selected_profiles.dedup();
    Ok(ResolvedProfiles {
        layout_id: layouts.into_iter().next().expect("one layout").into(),
        selected_profiles,
        authority_digests,
        active_rules,
        semantic_scopes,
        required_evidence: required_evidence.into_iter().collect(),
        module_overrides: BTreeMap::new(),
    })
}

/// Explains why profile authority could not be resolved.
#[derive(Debug)]
pub enum ProfileResolutionError {
    /// Installed JSON was malformed.
    Json(serde_json::Error),
    /// Installed schema identity or version is unsupported.
    UnsupportedRegistry,
    /// Canonical profile serialization failed.
    Serialization(Box<str>),
    /// An installed definition's digest did not match its body.
    DefinitionDigestMismatch(Box<str>),
    /// An installed definition list was not strictly sorted and unique.
    NoncanonicalDefinition(Box<str>),
    /// An installed rule identity is absent from the selected Standard.
    UnknownRule(Box<str>),
    /// Two installed definitions have the same identity and version.
    DuplicateDefinition,
    /// The native default profile is absent.
    MissingDefaultProfile(Box<str>),
    /// A selected identity/version does not exist.
    UnknownProfile(Box<str>),
    /// Governance and assurance references were placed in the wrong field.
    WrongProfileKind(Box<str>),
    /// A selected reference digest is stale or false.
    ReferenceDigestMismatch(Box<str>),
    /// No governance profile was selected.
    MissingGovernanceProfile,
    /// Selected profiles explicitly conflict.
    ConflictingProfiles {
        /// First conflicting identity.
        left: String,
        /// Second conflicting identity.
        right: String,
    },
    /// Selected governance profiles require different layouts.
    IncompatibleLayouts,
    /// Authored default layout disagrees with composed profile authority.
    LayoutSelectionMismatch {
        /// Project-selected layout.
        selected: String,
        /// Standard-resolved layout.
        resolved: String,
    },
    /// A Module override references no CCG Module identity.
    UnknownModule(Box<str>),
}

impl Display for ProfileResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "profile registry JSON is invalid: {error}"),
            Self::UnsupportedRegistry => {
                formatter.write_str("profile registry schema is unsupported")
            }
            Self::Serialization(error) => write!(
                formatter,
                "profile definition cannot be canonicalized: {error}"
            ),
            Self::DefinitionDigestMismatch(id) => write!(
                formatter,
                "profile definition `{id}` digest does not match its canonical body"
            ),
            Self::NoncanonicalDefinition(id) => write!(
                formatter,
                "profile definition `{id}` lists must be strictly sorted and unique"
            ),
            Self::UnknownRule(id) => {
                write!(formatter, "profile references unknown Standard rule `{id}`")
            }
            Self::DuplicateDefinition => {
                formatter.write_str("profile identity and version are duplicated")
            }
            Self::MissingDefaultProfile(id) => {
                write!(formatter, "native default profile `{id}` is absent")
            }
            Self::UnknownProfile(id) => write!(formatter, "selected profile `{id}` is unknown"),
            Self::WrongProfileKind(id) => write!(
                formatter,
                "selected profile `{id}` has the wrong profile kind"
            ),
            Self::ReferenceDigestMismatch(id) => write!(
                formatter,
                "selected profile `{id}` digest does not match Standard authority"
            ),
            Self::MissingGovernanceProfile => {
                formatter.write_str("profile composition has no governance profile")
            }
            Self::ConflictingProfiles { left, right } => {
                write!(formatter, "profiles `{left}` and `{right}` conflict")
            }
            Self::IncompatibleLayouts => {
                formatter.write_str("selected governance profiles require incompatible layouts")
            }
            Self::LayoutSelectionMismatch { selected, resolved } => write!(
                formatter,
                "selected layout `{selected}` disagrees with resolved layout `{resolved}`"
            ),
            Self::UnknownModule(id) => write!(
                formatter,
                "profile override references unknown Module `{id}`"
            ),
        }
    }
}

impl Error for ProfileResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}
