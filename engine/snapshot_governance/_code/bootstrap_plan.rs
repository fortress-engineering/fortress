//! Exact reviewed repository adoption over the existing candidate and migration owners.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    BootstrapError, BootstrapGovernanceState, BootstrapUnresolvedChoice, ProposedAuthorityArtifact,
    installed_standard_binding, observe_governance, observed_source, sha256_bytes,
    snapshot_bound_files,
};
use crate::candidate::{
    CandidateRequest, CandidateWorkspace, HypotheticalEvaluation, NoActualExecution,
};
use crate::control_layout::{ControlLayout, ControlRole};
use crate::finding::FindingIdentityEligibility;
use crate::finding_governance::FindingGovernanceDocument;
use crate::migration_adapter::CanonicalMigrationEvaluator;
use crate::migration_governance::{
    MigrationAuthority, MigrationEvaluation, MigrationEvaluator, MigrationOperation,
    MigrationOptions, MigrationPlan, MigrationServices, MigrationValidation, NoMutationFaults,
    OperationGraph, apply_migration, preview_migration,
};
use crate::observation::{CandidateChangeSet, SourceView};
use crate::project::{ProjectConfiguration, SourcePathBinding};
use crate::state_governance::ComparisonContext;

/// Current versioned reviewed repository-adoption record.
pub const ONBOARDING_PROPOSAL_SCHEMA: &str = "urn:fortress:schema:v2:repository-bootstrap-proposal";
/// Maximum admitted reviewed record; actual source and mutation limits remain owner-enforced.
pub const MAX_ONBOARDING_PROPOSAL_BYTES: usize = 64 * 1024 * 1024;

/// Loads an explicitly selected bounded UTF-8 review using the shared link-safe read boundary.
/// # Errors
/// Refuses links/reparse escapes, nonregular files, invalid UTF-8 and excessive records.
pub fn load_onboarding_record(path: &Path) -> Result<String, BootstrapError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(invalid)?.join(path)
    };
    let anchor = absolute
        .ancestors()
        .last()
        .ok_or_else(|| invalid("UNSAFE_PATH: input anchor unavailable"))?;
    let bytes = crate::query::safe_read(anchor, &absolute, 64 * 1024 * 1024).map_err(invalid)?;
    String::from_utf8(bytes).map_err(invalid)
}

fn invalid(e: impl std::fmt::Display) -> BootstrapError {
    BootstrapError::InvalidProposal(e.to_string().into())
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, BootstrapError> {
    crate::declaration::canonical(v).map_err(invalid)
}
fn digest<T: Serialize>(v: &T) -> Result<String, BootstrapError> {
    Ok(sha256_bytes(&canonical(v)?))
}
fn one() -> u16 {
    1
}
fn proposed_only<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    if bool::deserialize(d)? {
        return Err(serde::de::Error::custom(
            "a repository-adoption proposal cannot assert actual_state",
        ));
    }
    Ok(false)
}

/// Independent filing interpretation; native adoption preserves application placement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OnboardingMode {
    /// Existing application source and Cargo inputs remain byte-exact.
    #[default]
    Native,
    /// The full current canonical filing and documentation constraints apply.
    Canonical,
}

/// Exact caller-authored authority content. Its presence is a proposal, not a grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingAuthorityFile {
    /// Repository-relative application contract or registered governance path.
    pub path: String,
    /// Reviewed UTF-8 bytes; defaults never infer permissions from observations.
    pub content: String,
}

/// Explicit identity and membership choice using the existing logical binding vocabulary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingModuleChoice {
    /// Stable authored Module identity.
    pub module: String,
    /// Readable human name, independent of incidental source placement.
    pub display_name: String,
    /// Application-owned contract location; never placed in the control namespace.
    pub contract: String,
    /// Stable semantic parent identity; empty only for the project Module.
    pub parent: String,
    /// Existing Project Model selectors; a file does not claim its parent directory.
    pub bindings: Vec<SourcePathBinding>,
}

/// Exact selection against the pre-admission target; an empty list admits no findings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingBaselineReview {
    /// Exact evaluated target before adding the baseline authority.
    pub evaluated_state_ref: String,
    /// Sorted explicitly reviewed stable finding identities.
    pub finding_ids: Vec<String>,
}

/// Versioned caller inputs. Defaults introduce no effect policy, assurance claim or baseline.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingOptions {
    #[serde(default = "one")]
    schema_version: u16,
    #[serde(default)]
    mode: OnboardingMode,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    governance_profiles: Vec<String>,
    #[serde(default)]
    assurance_profiles: Vec<String>,
    #[serde(default)]
    module_choices: Option<Vec<OnboardingModuleChoice>>,
    #[serde(default)]
    authority_files: Vec<OnboardingAuthorityFile>,
    #[serde(default)]
    source_operations: Vec<MigrationOperation>,
    #[serde(default)]
    repair: bool,
    #[serde(default)]
    baseline_review: Option<OnboardingBaselineReview>,
}
impl Default for OnboardingOptions {
    fn default() -> Self {
        Self::new(None, None)
    }
}
impl OnboardingOptions {
    fn validate(&self) -> Result<(), BootstrapError> {
        if self.schema_version != 1 {
            return Err(invalid("UNSUPPORTED_VERSION: adoption request"));
        }
        if self.mode == OnboardingMode::Native && !self.source_operations.is_empty() {
            return Err(invalid(
                "NATIVE_SOURCE_PRESERVATION: native requests cannot alter application source",
            ));
        }
        if self.module_choices.as_ref().is_some_and(|m| m.len() > 1024)
            || self.authority_files.len() > 1024
            || self.source_operations.len() > 1024
            || self.governance_profiles.len() > 64
            || self.assurance_profiles.len() > 64
            || self
                .baseline_review
                .as_ref()
                .is_some_and(|r| r.finding_ids.len() > 50_000)
        {
            return Err(invalid(
                "RESOURCE_LIMIT: onboarding request exceeds owner admission",
            ));
        }
        Ok(())
    }
    /// Creates explicit identity choices with the native, non-permissive default.
    #[must_use]
    pub fn new(project_id: Option<String>, display_name: Option<String>) -> Self {
        Self {
            schema_version: 1,
            mode: OnboardingMode::Native,
            project_id,
            display_name,
            governance_profiles: vec![],
            assurance_profiles: vec![],
            module_choices: None,
            authority_files: vec![],
            source_operations: vec![],
            repair: false,
            baseline_review: None,
        }
    }
    /// Selects strict canonical filing or native/logical placement without changing intent semantics.
    #[must_use]
    pub const fn with_mode(mut self, mode: OnboardingMode) -> Self {
        self.mode = mode;
        self
    }
    /// Selects installed profile identities; exact immutable versions/digests are resolved by the owner.
    #[must_use]
    pub fn with_profiles(mut self, governance: Vec<String>, assurance: Vec<String>) -> Self {
        self.governance_profiles = governance;
        self.assurance_profiles = assurance;
        self
    }
    /// Replaces mechanical suggestions with explicit reviewed Module identities and memberships.
    #[must_use]
    pub fn with_modules(mut self, modules: Vec<OnboardingModuleChoice>) -> Self {
        self.module_choices = Some(modules);
        self
    }
    /// Supplies exact authored contracts or configuration; observed behavior is never converted to ALLOW.
    #[must_use]
    pub fn with_authority_files(mut self, files: Vec<OnboardingAuthorityFile>) -> Self {
        self.authority_files = files;
        self
    }
    /// Supplies explicit canonical relocation/repair operations using the existing migration vocabulary.
    #[must_use]
    pub fn with_source_operations(mut self, operations: Vec<MigrationOperation>) -> Self {
        self.source_operations = operations;
        self
    }
    /// Requests a repair proposal. This never authorizes replacement of existing protected inputs.
    #[must_use]
    pub const fn with_repair(mut self, repair: bool) -> Self {
        self.repair = repair;
        self
    }
    /// Reads bounded typed authoring inputs without accepting any asserted approval.
    /// # Errors
    /// Refuses duplicate fields, unsupported versions and resource exhaustion.
    pub fn from_json_str(source: &str) -> Result<Self, BootstrapError> {
        if source.len() > MAX_ONBOARDING_PROPOSAL_BYTES {
            return Err(invalid("RESOURCE_LIMIT: adoption request is too large"));
        }
        let v: Self = crate::wire::parse_public_json(source).map_err(invalid)?;
        v.validate()?;
        Ok(v)
    }
}

/// Mechanically proposed boundary; it becomes authored intent only through explicit reviewed application.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingModuleCandidate {
    /// Exact proposed identity/membership choice.
    pub choice: OnboardingModuleChoice,
    /// Readable qualified selector; ambiguous alternatives require explicit identity selection.
    pub selector: String,
    /// Existing observation or caller-authored basis.
    pub basis: String,
    /// Why this boundary was offered, not proof of intended behavior.
    pub rationale: String,
    /// Material limits on the mechanical suggestion.
    pub uncertainty: Vec<String>,
}

/// Exact observed regular-file inventory; semantic interpretation remains with existing owners.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingSourceEntry {
    /// Portable repository-relative name.
    pub path: String,
    /// SHA-256 of the original bytes.
    pub content_digest: String,
    /// Original byte count.
    pub byte_count: usize,
}

/// Immutable current proposal. Historical bootstrap v1 records keep their own reader and meaning.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingProposal {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    state: String,
    #[serde(deserialize_with = "proposed_only")]
    actual_state: bool,
    proposal_digest: String,
    mode: OnboardingMode,
    base_source_ref: String,
    source_fingerprint: String,
    context_ref: Option<String>,
    base_state_ref: Option<String>,
    trusted_base_authority_ref: Option<String>,
    reviewed_intent_ref: Option<String>,
    source_inventory: Vec<OnboardingSourceEntry>,
    observed_facts: Value,
    observed_program_context: Option<Value>,
    existing_contracts: Vec<Value>,
    candidate_modules: Vec<OnboardingModuleCandidate>,
    selected_profiles: Value,
    proposed_authority: Vec<ProposedAuthorityArtifact>,
    operations: Vec<MigrationOperation>,
    baseline_review: Option<OnboardingBaselineReview>,
    baseline_origin_assessment: Option<HypotheticalEvaluation>,
    predicted_findings: Vec<Value>,
    residue_summary: Value,
    assessment: Option<HypotheticalEvaluation>,
    migration_plan: Option<MigrationPlan>,
    unresolved_choices: Vec<BootstrapUnresolvedChoice>,
    request: OnboardingOptions,
    limitations: Vec<String>,
}

struct PreviewEndpoints<'a> {
    base_source: &'a SourceView,
    target_source: &'a SourceView,
    base: &'a MigrationEvaluation,
    target: &'a MigrationEvaluation,
}
impl MigrationEvaluator for PreviewEndpoints<'_> {
    fn evaluate(
        &self,
        source: &SourceView,
    ) -> Result<MigrationEvaluation, crate::migration_governance::MigrationError> {
        if source == self.base_source {
            Ok(self.base.clone())
        } else if source == self.target_source {
            Ok(self.target.clone())
        } else {
            CanonicalMigrationEvaluator.evaluate(source)
        }
    }
    fn observe(
        &self,
        root: &Path,
    ) -> Result<SourceView, crate::migration_governance::MigrationError> {
        CanonicalMigrationEvaluator.observe(root)
    }
}

struct OnboardingAuthority<'a> {
    intent_ref: String,
    canonical: bool,
    external: Option<&'a dyn MigrationAuthority>,
}
impl MigrationAuthority for OnboardingAuthority<'_> {
    fn preview(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        before: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<
        crate::development_governance::ApplicationAuthorityRecord,
        crate::migration_governance::MigrationError,
    > {
        if base
            .state
            .governing_identity()
            .map_err(authority_transition_error)?
            .is_some()
            && !changes.operations().is_empty()
        {
            return self.external.ok_or_else(||migration_error("TRUSTED_BASE_POLICY_REQUIRED: existing authority needs the original trusted AUTHORITY boundary"))?.preview(base,target,before,changes,context);
        }
        self.authorize(base, target, before, changes, context)
            .map(|p| p.record().clone())
    }
    fn authorize(
        &self,
        base: &MigrationEvaluation,
        target: &MigrationEvaluation,
        before: &SourceView,
        changes: &CandidateChangeSet,
        context: &ComparisonContext,
    ) -> Result<
        crate::development_governance::ApplicationAuthorization,
        crate::migration_governance::MigrationError,
    > {
        if changes.operations().is_empty() {
            return crate::development_governance::authorize_no_source_change(
                &base.state,
                &target.state,
                context,
                before,
                changes,
            )
            .map_err(authority_transition_error);
        }
        if base
            .state
            .governing_identity()
            .map_err(authority_transition_error)?
            .is_some()
        {
            return self.external.ok_or_else(||migration_error("TRUSTED_BASE_POLICY_REQUIRED: existing authority needs independently validated authorization"))?.authorize(base,target,before,changes,context);
        }
        crate::development_governance::authorize_reviewed_initial_establishment(
            &base.state,
            &target.state,
            context,
            before,
            changes,
            &self.intent_ref,
            self.canonical,
        )
        .map_err(authority_transition_error)
    }
}
fn authority_transition_error(
    error: crate::state_governance::TransitionError,
) -> crate::migration_governance::MigrationError {
    crate::migration_governance::MigrationError {
        code: error.code,
        message: error.message,
        transaction_ref: None,
    }
}
fn migration_error(e: impl std::fmt::Display) -> crate::migration_governance::MigrationError {
    crate::migration_governance::MigrationError {
        code: "INITIAL_AUTHORITY".into(),
        message: e.to_string(),
        transaction_ref: None,
    }
}
impl OnboardingProposal {
    /// Exact JCS content identity, including the complete reviewed operation/evidence inventory.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.proposal_digest
    }
    /// Whether this exact review has a valid executable plan and no unresolved owner choices.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.unresolved_choices.is_empty() && self.migration_plan.is_some()
    }
    /// Existing immutable proposed assessment; never current certification or approval.
    #[must_use]
    pub fn assessment(&self) -> Option<&HypotheticalEvaluation> {
        self.assessment.as_ref()
    }
    /// Exact original request for deliberate revision; no implicit widening occurs.
    #[must_use]
    pub const fn request(&self) -> &OnboardingOptions {
        &self.request
    }
    /// Resolves a stable identity or readable selector without choosing an ambiguous first match.
    /// # Errors
    /// Reports unavailable or ambiguous selectors explicitly.
    pub fn resolve_module(
        &self,
        selector: &str,
    ) -> Result<&OnboardingModuleChoice, BootstrapError> {
        let matches: Vec<_> = self
            .candidate_modules
            .iter()
            .filter(|m| {
                m.choice.module == selector
                    || m.selector == selector
                    || m.choice.display_name == selector
            })
            .collect();
        match matches.as_slice() {
            [module] => Ok(&module.choice),
            [] => Err(invalid(
                "IDENTITY_UNRESOLVED: no proposed Module matches the selector",
            )),
            _ => Err(invalid(
                "IDENTITY_AMBIGUOUS: qualify the Module selector or use its stable identity",
            )),
        }
    }
    /// Formats only already-loaded observations; no analysis or source mutation occurs.
    #[must_use]
    pub fn to_human(&self) -> String {
        let summary = json!({
            "status":"PROPOSED",
            "proposal_ref":self.digest(),
            "mode":self.mode,
            "base_source_ref":self.base_source_ref,
            "plan_ready_for_explicit_application":self.is_ready(),
            "raw_finding_count":self.assessment.as_ref().map(|_|self.predicted_findings.len()),
            "enforcement_residue":self.residue_summary,
            "governance_selection":self.selected_profiles.get("governance"),
            "assurance_selection":self.selected_profiles.get("assurance_profiles"),
            "observed_coverage":self.observed_facts.get("semantic_observation"),
            "modules":self.candidate_modules.iter().map(|m|json!({"selector":m.selector,"identity":m.choice.module,"contract":m.choice.contract,"rationale":m.rationale,"uncertainty":m.uncertainty})).collect::<Vec<_>>(),
            "unresolved_choices":self.unresolved_choices,
            "actual_certification":"NOT_ESTABLISHED",
            "permission":"A reviewed proposal is not an external grant or authorization to change existing protected authority."
        });
        match serde_json::to_value(self) {
            Ok(value) => format!(
                "Repository onboarding: {}\n{}\nFull immutable review record:\n{}",
                self.digest(),
                crate::query::render_inspection_value(&summary),
                crate::query::render_inspection_value(&value)
            ),
            Err(error) => format!("Onboarding inspection UNAVAILABLE: {error}\n"),
        }
    }
    /// Serializes the versioned canonical proposal with one terminating newline.
    /// # Errors
    /// Refuses invalid bindings or an oversized complete record.
    pub fn to_canonical_json(&self) -> Result<String, BootstrapError> {
        self.validate()?;
        let mut bytes = canonical(self)?;
        if bytes.len() > MAX_ONBOARDING_PROPOSAL_BYTES {
            return Err(invalid(
                "RESOURCE_LIMIT: complete adoption proposal is too large",
            ));
        }
        bytes.push(b'\n');
        String::from_utf8(bytes).map_err(invalid)
    }
    /// Reads immutable evidence without interpreting repository-authored assertions as permission.
    /// # Errors
    /// Refuses tampering, duplicate fields, unsupported versions and invalid contained owner records.
    pub fn from_json_str(source: &str) -> Result<Self, BootstrapError> {
        if source.len() > MAX_ONBOARDING_PROPOSAL_BYTES {
            return Err(invalid("RESOURCE_LIMIT: adoption proposal"));
        }
        let v: Self = crate::wire::parse_public_json(source).map_err(invalid)?;
        v.validate()?;
        Ok(v)
    }
    fn identity(&self) -> Result<String, BootstrapError> {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        digest(&copy)
    }
    fn validate(&self) -> Result<(), BootstrapError> {
        if self.schema != ONBOARDING_PROPOSAL_SCHEMA
            || self.schema_version != 2
            || self.semantic_version != "2.0.0"
            || self.state != "PROPOSED"
            || self.actual_state
        {
            return Err(invalid(
                "UNSUPPORTED_VERSION: expected a proposed adoption record v2",
            ));
        }
        if self.identity()? != self.proposal_digest {
            return Err(invalid(
                "proposal digest does not match exact reviewed content",
            ));
        }
        self.request.validate()?;
        validate_configuration_mode(&self.selected_profiles, self.mode)?;
        if self.mode != self.request.mode {
            return Err(invalid(
                "UNSUPPORTED_VERSION: inconsistent request or filing mode",
            ));
        }
        validate_module_choices(&self.candidate_modules, &self.request)?;
        if self.source_inventory.len() > 50_000
            || self.operations.len() > 1024
            || self.candidate_modules.len() > 1024
            || self.proposed_authority.len() > 1024
        {
            return Err(invalid(
                "RESOURCE_LIMIT: source inventory or operation count",
            ));
        }
        if self
            .source_inventory
            .windows(2)
            .any(|p| p[0].path >= p[1].path)
        {
            return Err(invalid("source inventory is not uniquely ordered"));
        }
        validate_reviewed_operations(&self.proposed_authority, &self.operations, self.mode)?;
        if let Some(artifact) = self
            .proposed_authority
            .iter()
            .find(|a| a.authority_kind == "PROJECT_CONFIGURATION")
            && serde_json::from_str::<Value>(&artifact.content).map_err(invalid)?
                != self.selected_profiles
        {
            return Err(invalid(
                "BINDING_MISMATCH: reported configuration differs from the exact reviewed artifact",
            ));
        }
        if let Some(a) = &self.assessment {
            if self.context_ref.as_deref() != Some(a.context_ref()) {
                return Err(invalid(
                    "BINDING_MISMATCH: proposal and assessment contexts differ",
                ));
            }
            HypotheticalEvaluation::from_json_str(
                &String::from_utf8(a.to_canonical_bytes().map_err(invalid)?).map_err(invalid)?,
            )
            .map_err(invalid)?;
        }
        if let Some(p) = &self.migration_plan {
            MigrationPlan::from_json_str(
                &String::from_utf8(p.to_canonical_bytes().map_err(invalid)?).map_err(invalid)?,
            )
            .map_err(invalid)?;
            if p.base_source_ref() != self.base_source_ref
                || self.base_state_ref.as_deref() != Some(p.base_state_ref())
                || canonical(&self.operations)? != canonical(&p.operations())?
                || self.assessment.as_ref().is_none_or(|a| {
                    a.predicted_state().digest().ok().as_deref() != Some(p.target_state_ref())
                })
            {
                return Err(invalid(
                    "BINDING_MISMATCH: migration and hypothetical state identities differ",
                ));
            }
        }
        if self.baseline_review.is_some() != self.baseline_origin_assessment.is_some() {
            return Err(invalid(
                "INCOMPLETE_REVIEW: original residue assessment is required",
            ));
        }
        if let (Some(review), Some(origin)) =
            (&self.baseline_review, &self.baseline_origin_assessment)
            && origin.predicted_state().digest().map_err(invalid)? != review.evaluated_state_ref
        {
            return Err(invalid(
                "BINDING_MISMATCH: reviewed residue and original evaluated target differ",
            ));
        }
        Ok(())
    }
}

fn validate_reviewed_operations(
    proposed_authority: &[ProposedAuthorityArtifact],
    operations: &[MigrationOperation],
    mode: OnboardingMode,
) -> Result<(), BootstrapError> {
    let mut artifacts = BTreeMap::new();
    for artifact in proposed_authority {
        if sha256_bytes(artifact.content.as_bytes()) != artifact.content_digest {
            return Err(invalid("authority artifact digest mismatch"));
        }
        validate_reviewed_artifact(artifact, mode)?;
        if artifacts.insert(artifact.path.as_str(), artifact).is_some() {
            return Err(invalid(
                "IDENTITY_AMBIGUOUS: duplicate reviewed authority path",
            ));
        }
    }
    if mode == OnboardingMode::Native {
        for operation in operations {
            let (MigrationOperation::CreateFile { path, postimage }
            | MigrationOperation::ReplaceFile {
                path, postimage, ..
            }) = operation
            else {
                return Err(invalid(
                    "NATIVE_SOURCE_PRESERVATION: native records cannot relocate or delete application source",
                ));
            };
            if artifacts
                .get(path.as_str())
                .is_none_or(|a| a.content.as_bytes() != postimage)
            {
                return Err(invalid(
                    "BINDING_MISMATCH: native operation is not an exact reviewed authority artifact",
                ));
            }
        }
    }
    Ok(())
}

fn validate_reviewed_artifact(
    artifact: &ProposedAuthorityArtifact,
    mode: OnboardingMode,
) -> Result<(), BootstrapError> {
    SourceView::from_bytes(BTreeMap::from([(artifact.path.clone(), Vec::new())]))
        .map_err(invalid)?;
    let layout = ControlLayout::standard();
    match artifact.authority_kind.as_str() {
        "MODULE_CONTRACT"
            if !artifact.path.starts_with("__fortress/")
                && (artifact.path == "contract.json"
                    || artifact.path.ends_with("/contract.json")) =>
        {
            crate::contract_coherency::ModuleContract::from_json_str(&artifact.content)
                .map_err(invalid)?;
        }
        "PROJECT_CONFIGURATION"
            if layout.role_path(ControlRole::ProjectConfiguration)
                == Some(artifact.path.as_str()) =>
        {
            ProjectConfiguration::from_json_str(&artifact.content).map_err(invalid)?;
        }
        "FINDING_GOVERNANCE"
            if layout.role_path(ControlRole::FindingGovernance) == Some(artifact.path.as_str()) =>
        {
            FindingGovernanceDocument::from_json_str(&artifact.content).map_err(invalid)?;
        }
        "CANONICAL_DOCUMENTATION"
            if mode == OnboardingMode::Canonical
                && (artifact.path == "README.md"
                    || artifact.path.ends_with("/README.md")
                    || [
                        "code_docs.md",
                        "data_docs.md",
                        "info_docs.md",
                        "modules_docs.md",
                    ]
                    .iter()
                    .any(|name| {
                        artifact.path == format!("_docs/{name}")
                            || artifact.path.ends_with(&format!("/_docs/{name}"))
                    })) => {}
        _ => {
            return Err(invalid(
                "UNSUPPORTED_ARTIFACT: reviewed authority kind and registered location disagree",
            ));
        }
    }
    Ok(())
}

fn validate_configuration_mode(
    configuration: &Value,
    mode: OnboardingMode,
) -> Result<(), BootstrapError> {
    ProjectConfiguration::from_json_str(&configuration.to_string()).map_err(invalid)?;
    if mode == OnboardingMode::Canonical
        && configuration["logical_modules"]
            .as_array()
            .is_some_and(|modules| !modules.is_empty())
    {
        return Err(invalid(
            "PROFILE_MODE_CONFLICT: strict canonical adoption requires physical Module containment; logical bindings use native mode",
        ));
    }
    let (layout, profile) = match mode {
        OnboardingMode::Native => (
            "native-logical-v1",
            crate::profile::NATIVE_GOVERNANCE_PROFILE_ID,
        ),
        OnboardingMode::Canonical => (
            "canonical-filing-v1",
            crate::profile::CANONICAL_GOVERNANCE_PROFILE_ID,
        ),
    };
    if configuration["governance"]["default_layout"]
        .as_str()
        .unwrap_or("native-logical-v1")
        != layout
        || configuration
            .get("governance")
            .filter(|g| !g.is_null())
            .is_some_and(|g| {
                !g["selected_profiles"]
                    .as_array()
                    .is_some_and(|profiles| profiles.iter().any(|p| p["id"] == profile))
            })
    {
        return Err(invalid(
            "PROFILE_MODE_CONFLICT: reviewed configuration selects a different filing interpretation",
        ));
    }
    Ok(())
}

/// Actual observed governance after shared transactional application; runtime certification is separate.
#[derive(Clone, Debug, Serialize)]
pub struct OnboardingApplyResult {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    proposal_digest: String,
    migration_plan_ref: String,
    migration_receipt_ref: String,
    migration_record_path: String,
    proposal_record_path: String,
    actual_source_ref: String,
    actual_state_ref: String,
    reconciliation: Value,
    actual_governance: Value,
    inspection: Value,
    certification: String,
}
impl OnboardingApplyResult {
    /// Serializes exact actual observations without manufacturing actual execution evidence.
    /// # Errors
    /// Refuses serialization failures.
    pub fn to_canonical_json(&self) -> Result<String, BootstrapError> {
        let mut b = canonical(self)?;
        b.push(b'\n');
        String::from_utf8(b).map_err(invalid)
    }
}

fn choice(code: &str, detail: impl Into<String>) -> BootstrapUnresolvedChoice {
    BootstrapUnresolvedChoice {
        code: code.into(),
        detail: detail.into(),
    }
}
fn sibling(parent: &str, file: &str) -> String {
    if parent.is_empty() {
        file.into()
    } else {
        format!("{parent}/{file}")
    }
}
fn component_id(value: &str) -> String {
    let mut result = String::new();
    for c in value.chars() {
        let c = c.to_ascii_uppercase();
        if c.is_ascii_alphanumeric() {
            result.push(c);
        } else if !result.ends_with('-') {
            result.push('-');
        }
    }
    result.trim_matches('-').into()
}
fn source_binding(kind: &str, path: &str) -> Result<SourcePathBinding, BootstrapError> {
    serde_json::from_value(json!({"kind":kind,"path":path})).map_err(invalid)
}

fn proposed_modules(
    files: &BTreeMap<String, Vec<u8>>,
    options: &OnboardingOptions,
    facts: &[crate::implementation_observation::CargoAnalysisTerritoryObservation],
) -> Result<Vec<OnboardingModuleCandidate>, BootstrapError> {
    let Some(id) = &options.project_id else {
        return Ok(vec![]);
    };
    let Some(name) = &options.display_name else {
        return Ok(vec![]);
    };
    if let Some(modules) = &options.module_choices {
        return modules.iter().map(|m|Ok(OnboardingModuleCandidate{choice:m.clone(),selector:format!("{name}::{}",m.display_name),basis:"EXPLICIT_REVIEW_CHOICE".into(),rationale:"The caller supplied this identity, contract location, parent and membership for review.".into(),uncertainty:vec!["A reviewed boundary declares ownership; it proves neither behavior nor permission.".into()]})).collect();
    }
    let mut modules = vec![OnboardingModuleCandidate {
        choice: OnboardingModuleChoice {
            module: id.clone(),
            display_name: name.clone(),
            contract: "contract.json".into(),
            parent: String::new(),
            bindings: vec![],
        },
        selector: name.clone(),
        basis: "EXPLICIT_PROJECT_IDENTITY".into(),
        rationale: "The owner supplied the project identity and display name.".into(),
        uncertainty: vec![
            "No architectural or behavioral promises are inferred from the source.".into(),
        ],
    }];
    let mut boundaries = BTreeMap::<String, (String, String)>::new();
    if options.mode == OnboardingMode::Native {
        for package in facts {
            let directory = package.manifest_path().rsplit_once('/').map_or("", |p| p.0);
            if !directory.is_empty() {
                boundaries.insert(
                    directory.into(),
                    (package.package_name().into(), package.identity().into()),
                );
            }
        }
    } else {
        for path in files.keys() {
            let parts = path.split('/').collect::<Vec<_>>();
            if let Some(element) = parts
                .iter()
                .position(|p| crate::module_index::RESERVED_STRUCTURAL_DIRECTORIES.contains(p))
            {
                for length in 1..=element {
                    let directory = parts[..length].join("/");
                    if parts[..length]
                        .iter()
                        .all(|part| crate::module_index::is_module_name(part))
                    {
                        boundaries.insert(directory.clone(), (parts[length - 1].into(), directory));
                    }
                }
            }
        }
    }
    let mut ids = BTreeSet::from([id.clone()]);
    for (path, (display, identity)) in boundaries {
        let mut module = format!("{id}-{}", component_id(&display));
        if !ids.insert(module.clone()) {
            module = format!(
                "{module}-{}",
                sha256_bytes(identity.as_bytes())[7..15].to_ascii_uppercase()
            );
            if !ids.insert(module.clone()) {
                return Err(invalid(
                    "IDENTITY_AMBIGUOUS: mechanically suggested Module identity",
                ));
            }
        }
        modules.push(OnboardingModuleCandidate{choice:OnboardingModuleChoice{module,display_name:display.clone(),contract:sibling(&path,"contract.json"),parent:id.clone(),bindings:if options.mode==OnboardingMode::Native{vec![source_binding("directory",&path)?]}else{vec![]}},selector:format!("{name}::{display}@{path}"),basis:if options.mode==OnboardingMode::Native{"OBSERVED_CARGO_BOUNDARY"}else{"OBSERVED_CANONICAL_ELEMENT_BOUNDARY"}.into(),rationale:if options.mode==OnboardingMode::Native{format!("Cargo declares an observed package at `{path}`. This offers a reviewable logical boundary without moving source or changing Cargo.")}else{format!("Source already uses a reserved Element below `{path}`; the proposal adds its missing canonical Module intent.")},uncertainty:vec!["A build or filesystem boundary does not establish the intended architectural responsibility or authorize observed dependencies.".into()]});
    }
    let parents = modules
        .iter()
        .map(|m| {
            (
                m.choice
                    .contract
                    .strip_suffix("/contract.json")
                    .unwrap_or("")
                    .to_owned(),
                m.choice.module.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for module in &mut modules {
        let path = module
            .choice
            .contract
            .strip_suffix("/contract.json")
            .unwrap_or("");
        if !path.is_empty() {
            module.choice.parent = parents
                .iter()
                .filter(|(p, _)| !p.is_empty() && path.starts_with(&format!("{p}/")))
                .max_by_key(|(p, _)| p.len())
                .map_or_else(|| id.clone(), |(_, id)| id.clone());
        }
    }
    modules.sort_by(|a, b| a.choice.module.cmp(&b.choice.module));
    Ok(modules)
}

fn module_contract(
    module: &OnboardingModuleChoice,
    standard: &super::BootstrapStandardBinding,
) -> Result<String, BootstrapError> {
    let mut value = json!({"$schema":"urn:fortress:schema:v3:module-contract","schema_version":3,"id":module.module,"display_name":module.display_name,"provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[],"semantic_policy":{"default":"UNDECLARED","capabilities":{"allow":[],"deny":[]},"effects":{"allow":[],"deny":[]}}});
    if module.parent.is_empty() {
        value["ecosystem"] = json!({"repository_grammar":1,"standard":{"id":standard.id,"edition":standard.edition}});
    }
    let contract: crate::contract_coherency::ModuleContract =
        serde_json::from_value(value).map_err(invalid)?;
    let text = contract.to_canonical_json().map_err(invalid)?;
    crate::contract_coherency::ModuleContract::from_json_str(&text).map_err(invalid)?;
    Ok(text)
}

fn validate_module_choices(
    modules: &[OnboardingModuleCandidate],
    options: &OnboardingOptions,
) -> Result<(), BootstrapError> {
    let mut ids = BTreeSet::new();
    let mut contracts = BTreeSet::new();
    let mut roots = 0;
    for module in modules {
        let m = &module.choice;
        if options.mode == OnboardingMode::Canonical && !m.bindings.is_empty() {
            return Err(invalid(
                "PROFILE_MODE_CONFLICT: logical implementation bindings require native mode",
            ));
        }
        if !ids.insert(m.module.clone()) || !contracts.insert(m.contract.to_lowercase()) {
            return Err(invalid(
                "IDENTITY_AMBIGUOUS: duplicate Module identity or case-colliding contract path",
            ));
        }
        if m.parent.is_empty() {
            roots += 1;
            if m.contract != "contract.json" || options.project_id.as_ref() != Some(&m.module) {
                return Err(invalid(
                    "ROOT_IDENTITY_CONFLICT: the root Module must match the reviewed project identity",
                ));
            }
        }
    }
    if modules.is_empty() && (options.project_id.is_none() || options.display_name.is_none()) {
        return Ok(());
    }
    if roots != 1 {
        return Err(invalid(
            "IDENTITY_AMBIGUOUS: exactly one root Module is required",
        ));
    }
    if options.mode == OnboardingMode::Canonical {
        let placements: BTreeMap<_, _> = modules
            .iter()
            .map(|m| {
                (
                    m.choice
                        .contract
                        .strip_suffix("/contract.json")
                        .unwrap_or(""),
                    m.choice.module.as_str(),
                )
            })
            .collect();
        for module in modules.iter().filter(|m| !m.choice.parent.is_empty()) {
            let directory = module
                .choice
                .contract
                .strip_suffix("/contract.json")
                .ok_or_else(|| {
                    invalid("CANONICAL_PLACEMENT: each child owns its direct contract.json")
                })?;
            let parent = directory.rsplit_once('/').map_or("", |p| p.0);
            if !directory
                .split('/')
                .all(crate::module_index::is_module_name)
                || placements.get(parent).copied() != Some(module.choice.parent.as_str())
            {
                return Err(invalid(
                    "CANONICAL_PLACEMENT: reviewed Module parentage must match direct lowercase snake_case physical containment",
                ));
            }
        }
    }
    let parents: BTreeMap<_, _> = modules
        .iter()
        .map(|m| (&m.choice.module, &m.choice.parent))
        .collect();
    for module in modules {
        let mut seen = BTreeSet::new();
        let mut cursor = &module.choice.module;
        while let Some(parent) = parents.get(cursor) {
            if !seen.insert(cursor) {
                return Err(invalid("IDENTITY_AMBIGUOUS: cyclic Module parentage"));
            }
            if parent.is_empty() {
                break;
            }
            if !parents.contains_key(parent) {
                return Err(invalid("IDENTITY_UNRESOLVED: Module parent is unavailable"));
            }
            cursor = parent;
        }
    }
    Ok(())
}

fn profile_selection(
    options: &OnboardingOptions,
    modules: &[OnboardingModuleCandidate],
) -> Result<Value, BootstrapError> {
    let required = match options.mode {
        OnboardingMode::Native => crate::profile::NATIVE_GOVERNANCE_PROFILE_ID,
        OnboardingMode::Canonical => crate::profile::CANONICAL_GOVERNANCE_PROFILE_ID,
    };
    let ids = if options.governance_profiles.is_empty() {
        vec![required.into()]
    } else {
        options.governance_profiles.clone()
    };
    if !ids.iter().any(|id| id == required) {
        return Err(invalid(
            "PROFILE_MODE_CONFLICT: the selected filing mode requires its installed governance profile",
        ));
    }
    let resolve = |ids: &[String]| -> Result<Vec<Value>, BootstrapError> {
        let mut unique = BTreeSet::new();
        let mut refs = vec![];
        for id in ids {
            if !unique.insert(id) {
                return Err(invalid("IDENTITY_AMBIGUOUS: duplicate selected profile"));
            }
            let r = crate::profile::installed_profile_reference(id, "1.0.0")
                .map_err(invalid)?
                .ok_or_else(|| invalid(format!("UNSUPPORTED_PROFILE: {id}")))?;
            refs.push(serde_json::to_value(r).map_err(invalid)?);
        }
        refs.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(refs)
    };
    let logical = if options.mode == OnboardingMode::Native {
        modules.iter().filter(|m|!m.choice.parent.is_empty()).map(|m|json!({"module":m.choice.module,"contract":m.choice.contract,"parent":m.choice.parent,"bindings":m.choice.bindings})).collect::<Vec<_>>()
    } else {
        vec![]
    };
    let configuration = json!({"$schema":"urn:fortress:schema:v4:project-configuration","schema_version":4,"observation_exclusions":[".git"],"logical_modules":logical,"governance":{"default_layout":match options.mode{OnboardingMode::Native=>"native-logical-v1",OnboardingMode::Canonical=>"canonical-filing-v1"},"selected_profiles":resolve(&ids)?,"module_overrides":[]},"assurance_profiles":resolve(&options.assurance_profiles)?});
    ProjectConfiguration::from_json_str(&configuration.to_string()).map_err(invalid)?;
    Ok(configuration)
}

fn authority_artifacts(
    files: &BTreeMap<String, Vec<u8>>,
    options: &OnboardingOptions,
    modules: &[OnboardingModuleCandidate],
    configuration: &Value,
) -> Result<Vec<ProposedAuthorityArtifact>, BootstrapError> {
    let layout = ControlLayout::standard();
    let config = layout
        .role_path(ControlRole::ProjectConfiguration)
        .ok_or_else(|| invalid("configuration role unavailable"))?;
    let governance = layout
        .role_path(ControlRole::FindingGovernance)
        .ok_or_else(|| invalid("finding governance role unavailable"))?;
    let standard = installed_standard_binding()?;
    let mut artifacts = BTreeMap::<String, ProposedAuthorityArtifact>::new();
    if !options.repair {
        for module in modules {
            artifacts.insert(
                module.choice.contract.clone(),
                ProposedAuthorityArtifact::new(
                    &module.choice.contract,
                    "MODULE_CONTRACT",
                    module_contract(&module.choice, &standard)?,
                ),
            );
        }
        artifacts.insert(
            config.into(),
            ProposedAuthorityArtifact::new(
                config,
                "PROJECT_CONFIGURATION",
                serde_json::to_string_pretty(configuration).map_err(invalid)? + "\n",
            ),
        );
        artifacts.insert(
            governance.into(),
            ProposedAuthorityArtifact::new(
                governance,
                "FINDING_GOVERNANCE",
                FindingGovernanceDocument::empty_current()
                    .to_canonical_json()
                    .map_err(invalid)?,
            ),
        );
    }
    let mut supplied = BTreeSet::new();
    for file in &options.authority_files {
        if !supplied.insert(&file.path) {
            return Err(invalid(
                "IDENTITY_AMBIGUOUS: duplicate reviewed authority artifact",
            ));
        }
        let kind = if file.path == config {
            "PROJECT_CONFIGURATION"
        } else if file.path == governance {
            "FINDING_GOVERNANCE"
        } else if file.path == "contract.json" || file.path.ends_with("/contract.json") {
            "MODULE_CONTRACT"
        } else {
            return Err(invalid(
                "reviewed authority files must use registered governance or application Module contract locations; source edits use migration operations",
            ));
        };
        if kind == "MODULE_CONTRACT" {
            crate::contract_coherency::ModuleContract::from_json_str(&file.content)
                .map_err(invalid)?;
        }
        if kind == "PROJECT_CONFIGURATION" {
            ProjectConfiguration::from_json_str(&file.content).map_err(invalid)?;
        }
        if kind == "FINDING_GOVERNANCE" && !files.contains_key(governance) {
            let parsed =
                FindingGovernanceDocument::from_json_str(&file.content).map_err(invalid)?;
            let value = serde_json::to_value(&parsed).map_err(invalid)?;
            if value["schema_version"] != 2
                || !parsed.exceptions().is_empty()
                || value["baseline"] != Value::Null
                || parsed.lifecycle().is_some_and(|l| {
                    !l.anchors.is_empty()
                        || !l.retirements.is_empty()
                        || !l.exception_reviews.is_empty()
                })
            {
                return Err(invalid(
                    "INITIAL_BASELINE_REVIEW_REQUIRED: initial residue must be selected from the exact evaluated target; exceptions require the existing lifecycle authority",
                ));
            }
        }
        artifacts.insert(
            file.path.clone(),
            ProposedAuthorityArtifact::new(&file.path, kind, file.content.clone()),
        );
    }
    Ok(artifacts.into_values().collect())
}

fn artifact_operations(
    source: &SourceView,
    artifacts: &[ProposedAuthorityArtifact],
    repair: bool,
) -> Result<Vec<MigrationOperation>, BootstrapError> {
    artifacts
        .iter()
        .map(|artifact| match source.bytes(&artifact.path) {
            None => Ok(MigrationOperation::CreateFile {
                path: artifact.path.clone(),
                postimage: artifact.bytes(),
            }),
            Some(before) if before == artifact.content.as_bytes() => {
                Ok(MigrationOperation::ReplaceFile {
                    path: artifact.path.clone(),
                    preimage: before.to_vec(),
                    postimage: artifact.bytes(),
                })
            }
            Some(before) if repair => Ok(MigrationOperation::ReplaceFile {
                path: artifact.path.clone(),
                preimage: before.to_vec(),
                postimage: artifact.bytes(),
            }),
            Some(_) => Err(BootstrapError::AuthorityConflict(
                format!(
                    "existing `{}` requires an explicit repair proposal",
                    artifact.path
                )
                .into(),
            )),
        })
        .collect()
}

/// Discovers complete observed inputs and evaluates a review-only adoption target.
/// This never executes project code, writes source, repairs authority, or admits findings implicitly.
/// # Errors
/// Refuses unsafe/unstable source, unsupported requests, conflicting operations and exhausted limits.
pub fn discover_repository_onboarding(
    root: impl AsRef<Path>,
    options: &OnboardingOptions,
) -> Result<OnboardingProposal, BootstrapError> {
    build_proposal(root.as_ref(), options, None)
}

/// Uses an explicitly trusted original-policy port for a protected repair preview.
/// Repository-authored references cannot create this process-local boundary.
/// # Errors
/// Retains the ordinary discovery errors and original-authority refusals.
pub fn discover_repository_onboarding_with_authority(
    root: impl AsRef<Path>,
    options: &OnboardingOptions,
    authority: &dyn MigrationAuthority,
) -> Result<OnboardingProposal, BootstrapError> {
    build_proposal(root.as_ref(), options, Some(authority))
}

#[allow(clippy::too_many_lines)]
fn build_proposal(
    root: &Path,
    options: &OnboardingOptions,
    external: Option<&dyn MigrationAuthority>,
) -> Result<OnboardingProposal, BootstrapError> {
    options.validate()?;
    if options.mode == OnboardingMode::Native && !options.source_operations.is_empty() {
        return Err(invalid(
            "NATIVE_SOURCE_PRESERVATION: native adoption cannot alter application source or Cargo inputs",
        ));
    }
    let (files, fingerprint) = observed_source(root)?;
    let source = SourceView::from_bytes(files.clone()).map_err(invalid)?;
    let mut options = options.clone();
    options.governance_profiles.sort();
    options.assurance_profiles.sort();
    options.authority_files.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(choices) = &mut options.module_choices {
        choices.sort_by(|a, b| a.module.cmp(&b.module));
    }
    if let Some(review) = &mut options.baseline_review {
        review.finding_ids.sort();
        if review.finding_ids.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid(
                "IDENTITY_AMBIGUOUS: duplicate initial finding selection",
            ));
        }
    }
    let input = crate::implementation_observation::ImplementationObservationInput::new(
        &fingerprint,
        snapshot_bound_files(&files),
        vec![],
    );
    let cargo = crate::implementation_observation::observe_cargo_analysis_territories(&input)
        .map_err(invalid)?;
    let mut limitations=vec!["Proposed architectural boundaries and contracts require explicit review; observation never creates permission or intended behavior.".into(),"Native adoption preserves every existing application and Cargo byte. Canonical source operations are explicit exact-preimage migration operations.".into(),"Raw conformance, progressive enforcement, assurance, source coverage, external authorization and actual execution remain independent.".into(),"The CLI supplies no production grant or actual-execution validator. Unsigned proposals and receipts remain unauthenticated.".into()];
    let (test_observation, program_context, semantic_observation, observation_limits) =
        observe_discovery_context(root, &files)?;
    limitations.extend(observation_limits);
    let boundary_view = CandidateChangeSet::new_simultaneous(
        &source,
        "onboarding-boundary-preview-v1",
        "unbound-proposed-authority",
        options
            .source_operations
            .iter()
            .map(MigrationOperation::neutral),
    )
    .map_err(invalid)?;
    let mut modules = proposed_modules(boundary_view.view().files(), &options, &cargo)?;
    if options.mode == OnboardingMode::Canonical && !options.source_operations.is_empty() {
        for module in &mut modules {
            if module.basis == "OBSERVED_CANONICAL_ELEMENT_BOUNDARY" {
                module.basis = "PROPOSED_CANONICAL_ELEMENT_BOUNDARY".into();
                module.rationale = format!(
                    "The exact proposed source view contains this reserved-Element boundary at `{}`. It remains a suggestion requiring review, not an observation of the current repository.",
                    module.choice.contract
                );
            }
        }
    }
    validate_module_choices(&modules, &options)?;
    let mut configuration = profile_selection(&options, &modules)?;
    let existing = existing_contract_observations(&files);
    let mut unresolved = vec![];
    if options.project_id.is_none() {
        unresolved.push(choice(
            "PROJECT_ID_REQUIRED",
            "An explicit stable project identity is required; no hash extraction is needed.",
        ));
    }
    if options.display_name.is_none() {
        unresolved.push(choice(
            "DISPLAY_NAME_REQUIRED",
            "An explicit readable project name is required.",
        ));
    }
    let governance = observe_governance(&files);
    if !options.repair
        && (governance.0 != BootstrapGovernanceState::Absent
            || !existing.is_empty()
            || files.contains_key(crate::finding_governance::FINDING_GOVERNANCE_PATH))
    {
        unresolved.push(choice("EXISTING_AUTHORITY_REQUIRES_REPAIR","Existing, partial or competing authority is preserved. Supply an explicit repair and the original trusted authorization boundary; initialization cannot overwrite it."));
    }
    let artifacts = authority_artifacts(&files, &options, &modules, &configuration)?;
    if let Some(artifact) = artifacts
        .iter()
        .find(|a| a.authority_kind == "PROJECT_CONFIGURATION")
    {
        configuration = serde_json::from_str(&artifact.content).map_err(invalid)?;
    } else if let Some(bytes) = files.get(crate::control_layout::PROJECT_CONFIGURATION_PATH) {
        let content = std::str::from_utf8(bytes).map_err(invalid)?;
        ProjectConfiguration::from_json_str(content).map_err(invalid)?;
        configuration = serde_json::from_str(content).map_err(invalid)?;
    }
    validate_configuration_mode(&configuration, options.mode)?;
    let mut operations = options.source_operations.clone();
    match artifact_operations(&source, &artifacts, options.repair) {
        Ok(ops) => operations.extend(ops),
        Err(e) => unresolved.push(choice("AUTHORITY_PATH_CONFLICT", e.to_string())),
    }
    let mut body = OnboardingProposal {
        schema: ONBOARDING_PROPOSAL_SCHEMA.into(),
        schema_version: 2,
        semantic_version: "2.0.0".into(),
        state: "PROPOSED".into(),
        actual_state: false,
        proposal_digest: String::new(),
        mode: options.mode,
        base_source_ref: source.digest().into(),
        source_fingerprint: fingerprint,
        context_ref: None,
        base_state_ref: None,
        trusted_base_authority_ref: None,
        reviewed_intent_ref: None,
        source_inventory: files
            .iter()
            .map(|(path, b)| OnboardingSourceEntry {
                path: path.clone(),
                content_digest: sha256_bytes(b),
                byte_count: b.len(),
            })
            .collect(),
        observed_facts: json!({"repository_files":files.len(),"rust_source_files":files.keys().filter(|p| Path::new(p).extension().is_some_and(|extension| extension == "rs")).count(),"cargo_territories":cargo.iter().cloned().map(super::BootstrapCargoTerritory::from).collect::<Vec<_>>(),"tests":test_observation,"semantic_observation":semantic_observation,"governance_state":governance.0,"governance_detail":governance.1,"permissions_inferred":false,"project_code_execution":"NOT_RUN"}),
        observed_program_context: program_context,
        existing_contracts: existing,
        candidate_modules: modules,
        selected_profiles: configuration,
        proposed_authority: artifacts,
        operations,
        baseline_review: options.baseline_review.clone(),
        baseline_origin_assessment: None,
        predicted_findings: vec![],
        residue_summary: json!({"state":"NOT_EVALUATED"}),
        assessment: None,
        migration_plan: None,
        unresolved_choices: unresolved,
        request: options,
        limitations,
    };
    if !body.unresolved_choices.is_empty() {
        return finish_proposal(body, root, &source);
    }
    let mut work = match CandidateWorkspace::open_cold(root) {
        Ok(w) => w,
        Err(e) => {
            body.unresolved_choices
                .push(choice("BASE_AUTHORITY_UNRESOLVED", e.to_string()));
            return finish_proposal(body, root, &source);
        }
    };
    if work.physical_source() != &source {
        return Err(BootstrapError::StaleProposal {
            expected: source.digest().into(),
            actual: work.base_source_ref().into(),
        });
    }
    body.context_ref = Some(work.context_ref().into());
    body.base_state_ref = Some(work.base_state().digest().map_err(invalid)?);
    body.trusted_base_authority_ref = work.base_state().governing_identity().map_err(invalid)?;
    let mut graph = OperationGraph::compile(
        &source,
        body.operations.clone(),
        &work.base_endpoint().ownership,
    )
    .map_err(BootstrapError::Migration)?;
    if body.mode == OnboardingMode::Canonical && !body.request.repair {
        let docs = crate::documentation::propose_canonical_documentation(graph.target().files())
            .map_err(invalid)?;
        for (path, content) in docs {
            body.proposed_authority.push(ProposedAuthorityArtifact::new(
                &path,
                "CANONICAL_DOCUMENTATION",
                content.clone(),
            ));
            body.operations.push(MigrationOperation::CreateFile {
                path,
                postimage: content.into_bytes(),
            });
        }
        graph = OperationGraph::compile(
            &source,
            body.operations.clone(),
            &work.base_endpoint().ownership,
        )
        .map_err(BootstrapError::Migration)?;
    }
    body.operations = graph.operations().to_vec();
    let mut intent = digest(&(
        "reviewed-initial-intent-v1",
        source.digest(),
        graph.target().digest(),
        body.mode,
        &body.selected_profiles,
    ))?;
    let mut authority = OnboardingAuthority {
        intent_ref: intent.clone(),
        canonical: body.mode == OnboardingMode::Canonical,
        external,
    };
    let request = CandidateRequest {
        schema_version: 1,
        base_source_ref: work.base_source_ref().into(),
        context_ref: work.context_ref().into(),
        operations: body.operations.clone(),
        comparison_context: ComparisonContext::default(),
    };
    let (mut assessment, mut facts) = match work.evaluate_detailed(
        "adoption",
        "unadmitted",
        request,
        &authority,
        &AtomicBool::new(false),
    ) {
        Ok(value) => value,
        Err(e) => {
            body.unresolved_choices
                .push(choice("TARGET_EVALUATION_FAILED", e.to_string()));
            return finish_proposal(body, root, &source);
        }
    };
    let mut endpoint_key = "unadmitted";
    if let Some(review) = &body.baseline_review {
        if !body.request.source_operations.is_empty() {
            return Err(invalid(
                "INITIAL_BASELINE_MIXED_SOURCE: source changes require a separate reviewed transition before initial residue admission",
            ));
        }
        if assessment.predicted_state().digest().map_err(invalid)? != review.evaluated_state_ref {
            return Err(invalid(
                "STALE_BASELINE_TARGET: reviewed findings belong to another exact target",
            ));
        }
        let original = facts
            .as_ref()
            .ok_or_else(|| invalid("NOT_EVALUABLE: initial finding inventory is unavailable"))?;
        let mut identities = BTreeMap::new();
        for finding in &original.findings {
            let entry = identities
                .entry(finding.finding_id())
                .or_insert((0usize, finding));
            entry.0 = entry.0.saturating_add(1);
        }
        let selected = review
            .finding_ids
            .iter()
            .map(|id| {
                let Some((1, found)) = identities.get(id.as_str()) else {
                    return Err(invalid(format!(
                        "IDENTITY_AMBIGUOUS: reviewed finding `{id}` does not uniquely exist"
                    )));
                };
                if found.identity_eligibility() != FindingIdentityEligibility::Eligible {
                    return Err(invalid(format!("BASELINE_INELIGIBLE: {id}")));
                }
                Ok((*found).clone())
            })
            .collect::<Result<Vec<_>, BootstrapError>>()?;
        let standard = installed_standard_binding()?;
        let admission = crate::lifecycle_load::propose_baseline(
            &FindingGovernanceDocument::empty_current(),
            assessment.predicted_state(),
            &selected,
            &standard.id,
            &standard.edition,
        )
        .map_err(invalid)?;
        let layout = ControlLayout::standard();
        let path = layout
            .role_path(ControlRole::FindingGovernance)
            .ok_or_else(|| invalid("finding governance role unavailable"))?;
        if source.bytes(path).is_some() {
            return Err(invalid(
                "BASELINE_ALREADY_EXISTS: finding maintenance must use its existing owner and original authorization",
            ));
        }
        let content = admission
            .proposed_governance()
            .to_canonical_json()
            .map_err(invalid)?;
        let artifact = body
            .proposed_authority
            .iter_mut()
            .find(|a| a.path == path)
            .ok_or_else(|| invalid("initial finding authority is absent"))?;
        *artifact = ProposedAuthorityArtifact::new(path, "FINDING_GOVERNANCE", content.clone());
        let op = body
            .operations
            .iter_mut()
            .find(|op| matches!(op,MigrationOperation::CreateFile{path:p,..} if p==path))
            .ok_or_else(|| invalid("initial finding creation operation is absent"))?;
        *op = MigrationOperation::CreateFile {
            path: path.into(),
            postimage: content.into_bytes(),
        };
        body.baseline_origin_assessment = Some(assessment);
        graph = OperationGraph::compile(
            &source,
            body.operations.clone(),
            &work.base_endpoint().ownership,
        )
        .map_err(BootstrapError::Migration)?;
        body.operations = graph.operations().to_vec();
        intent = digest(&(
            "reviewed-initial-intent-v1",
            source.digest(),
            graph.target().digest(),
            body.mode,
            &body.selected_profiles,
        ))?;
        authority = OnboardingAuthority {
            intent_ref: intent.clone(),
            canonical: body.mode == OnboardingMode::Canonical,
            external,
        };
        let request = CandidateRequest {
            schema_version: 1,
            base_source_ref: work.base_source_ref().into(),
            context_ref: work.context_ref().into(),
            operations: body.operations.clone(),
            comparison_context: ComparisonContext::default(),
        };
        (assessment, facts) = work
            .evaluate_detailed(
                "adoption",
                "admitted",
                request,
                &authority,
                &AtomicBool::new(false),
            )
            .map_err(BootstrapError::Migration)?;
        endpoint_key = "admitted";
    }
    body.reviewed_intent_ref = Some(intent.clone());
    if let Some(facts) = &facts {
        body.predicted_findings = facts
            .findings
            .iter()
            .map(|f| serde_json::to_value(f).map_err(invalid))
            .collect::<Result<_, _>>()?;
        body.residue_summary = serde_json::to_value(facts.governance.summary()).map_err(invalid)?;
        if body.mode == OnboardingMode::Canonical
            && facts
                .findings
                .iter()
                .any(|f| matches!(f.rule_id(), "REPO-MODULE-001" | "REPO-DOCS-001"))
        {
            body.unresolved_choices.push(choice("CANONICAL_FILING_REQUIRED","The proposed target violates mandatory current filing or documentation constraints. Review exact relocations or documents; baselines cannot waive strict canonical structure."));
        }
    } else {
        body.unresolved_choices.push(choice("TARGET_AUTHORITY_INVALID","The existing owners could not establish usable target authority; no absence of findings is conformance evidence."));
    }
    body.assessment = Some(assessment);
    if body.unresolved_choices.is_empty() {
        let target = work
            .candidate_endpoint("adoption", endpoint_key)
            .ok_or_else(|| invalid("evaluated target endpoint unavailable"))?;
        let preview_evaluator = PreviewEndpoints {
            base_source: &source,
            target_source: graph.target(),
            base: work.base_endpoint(),
            target,
        };
        let mut options = MigrationOptions::default();
        options
            .validation_requirements
            .insert(MigrationValidation::GovernanceDeclared);
        match preview_migration(
            &preview_evaluator,
            &authority,
            &source,
            body.operations.clone(),
            options,
        ) {
            Ok(preview) => {
                if !preview.plan.validations_satisfied() {
                    body.unresolved_choices.push(choice(
                        "APPLICATION_VALIDATION_UNRESOLVED",
                        "An existing owner did not satisfy a required migration validation.",
                    ));
                }
                let record = serde_json::to_value(preview.plan.authorization()).map_err(invalid)?;
                if record["governed_decision"].is_object()
                    && record["governed_decision"]["disposition"] != "PERMIT"
                {
                    body.unresolved_choices.push(choice("EXTERNAL_AUTHORIZATION_REQUIRED","The original-policy boundary must independently validate all required external grants on explicit application."));
                }
                body.migration_plan = Some(preview.plan);
            }
            Err(e) => body
                .unresolved_choices
                .push(choice("APPLICATION_REQUIREMENT_UNRESOLVED", e.to_string())),
        }
    }
    finish_proposal(body, root, &source)
}

fn existing_contract_observations(files: &BTreeMap<String, Vec<u8>>) -> Vec<Value> {
    let layout = ControlLayout::standard();
    files.iter().filter_map(|(path, bytes)| {
        let text = std::str::from_utf8(bytes).ok();
        let value = text.and_then(|s| crate::wire::parse_public_json::<Value>(s).ok());
        let schema = value.as_ref().and_then(|v| v["$schema"].as_str());
        let roles = crate::authority_roles::protected_input_roles(&layout, path, schema);
        if path != "contract.json" && !path.ends_with("/contract.json")
            && !roles.contains(&crate::authority_roles::ProtectedClass::ModuleIntent) {
            return None;
        }
        Some(match text.and_then(|s| crate::contract_coherency::ModuleContract::from_json_str(s).ok()) {
            Some(c) => json!({"path":path,"content_digest":sha256_bytes(bytes),"module":c.id(),"schema":schema,"state":"EXISTING_AUTHORED_INTENT","provides":c.provides(),"requires":c.requires(),"relationships":c.relationships(),"permission_inferred":false}),
            None => json!({"path":path,"content_digest":sha256_bytes(bytes),"module":null,"schema":schema,"state":"UNVERIFIED_DECLARATION_OCCURRENCE","protected_roles":roles,"permission_inferred":false}),
        })
    }).collect()
}

fn semantic_discovery_projection(psm: &crate::program_semantics::ProgramSemanticModel) -> Value {
    let relationships = psm.calls().iter().take(1024).map(|call| json!({"id":call.id(),"caller":call.caller(),"callee":call.callee(),"external_target":call.external_target(),"state":call.state(),"reason":call.reason()})).collect::<Vec<_>>();
    json!({"coverage":psm.coverage(),"unsupported_semantics":psm.unsupported_semantics(),"execution":"NOT_RUN","relationships":{"kind":"OBSERVED_CALLS","total":psm.calls().len(),"included":relationships,"truncated":psm.calls().len()>1024,"permission_inferred":false,"limitation":"Bounded observation preview; not authored intent, full call coverage, or permission. Exact source and context remain available to the canonical query owner."}})
}

type DiscoveryProjection = (Value, Option<Value>, Value, Vec<String>);
fn observe_discovery_context(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<DiscoveryProjection, BootstrapError> {
    std::thread::scope(|scope| {
        std::thread::Builder::new().name("fortress-adoption-observation".into()).spawn_scoped(scope,||{
            let mut limits=vec![];
            let tests=match crate::rust_test_analyzer::observe_observed_rust_tests(files.iter().map(|(p,b)|(p.as_str(),b.as_slice()))){
                Ok(t)=>json!({"supported_observed":t.len(),"without_stable_identity":t.iter().filter(|x|!x.is_governed()).count(),"completeness":"SUPPORTED_SYNTAX_ONLY","execution":"NOT_RUN"}),
                Err(e)=>{limits.push(format!("Test inventory is incomplete: {e}"));json!({"supported_observed":null,"without_stable_identity":null,"completeness":"NOT_EVALUABLE","execution":"NOT_RUN","reason":e.to_string()})},
            };
            let (context,semantic)=match crate::audit::compile_repository_psm(root){
                Ok(psm)=>(Some(crate::wire::parse_public_json::<Value>(&psm.program_context().to_canonical_json()).map_err(invalid)?),semantic_discovery_projection(&psm)),
                Err(e)=>{limits.push(format!("Semantic observation is unavailable: {e}"));(None,json!({"coverage":null,"unsupported_semantics":[e.to_string()],"execution":"NOT_RUN"}))},
            };
            Ok((tests,context,semantic,limits))
        }).map_err(invalid)?.join().map_err(|_|invalid("observation worker failed; no proposal or source change was published"))?
    })
}

fn finish_proposal(
    mut body: OnboardingProposal,
    root: &Path,
    source: &SourceView,
) -> Result<OnboardingProposal, BootstrapError> {
    if CanonicalMigrationEvaluator
        .observe(root)
        .map_err(BootstrapError::Migration)?
        != *source
    {
        return Err(invalid(
            "STALE_BASE: repository changed during read-only discovery",
        ));
    }
    body.proposed_authority.sort_by(|a, b| a.path.cmp(&b.path));
    body.unresolved_choices.sort();
    body.unresolved_choices.dedup();
    body.limitations.sort();
    body.limitations.dedup();
    body.proposal_digest = body.identity()?;
    body.to_canonical_json()?;
    Ok(body)
}

/// Selects only exact eligible findings from an already reviewed evaluated target.
/// # Errors
/// Refuses stale targets, unknown/ambiguous/ineligible identities, existing baseline replacement,
/// or source changes mixed with introduction of authority. Discovery remains read-only.
pub fn review_onboarding_baseline(
    root: impl AsRef<Path>,
    proposal: &OnboardingProposal,
    evaluated_state_ref: &str,
    finding_ids: &[String],
) -> Result<OnboardingProposal, BootstrapError> {
    proposal.validate()?;
    let source = CanonicalMigrationEvaluator
        .observe(root.as_ref())
        .map_err(BootstrapError::Migration)?;
    if source.digest() != proposal.base_source_ref {
        return Err(invalid("STALE_BASE: reviewed original source changed"));
    }
    let assessment = proposal.assessment.as_ref().ok_or_else(|| {
        invalid("NOT_EVALUABLE: no complete target assessment is available for baseline review")
    })?;
    if assessment.predicted_state().digest().map_err(invalid)? != evaluated_state_ref {
        return Err(invalid(
            "STALE_TARGET: baseline review does not name the evaluated target",
        ));
    }
    let mut request = proposal.request.clone();
    request.baseline_review = Some(OnboardingBaselineReview {
        evaluated_state_ref: evaluated_state_ref.into(),
        finding_ids: finding_ids.to_vec(),
    });
    build_proposal(root.as_ref(), &request, None)
}

/// Applies exactly one reviewed proposal using the shared migration engine and read-only reconciliation.
/// # Errors
/// Refuses stale/incomplete reviews, changed predictions and missing original-state authorization.
pub fn apply_repository_onboarding(
    root: impl AsRef<Path>,
    proposal: &OnboardingProposal,
) -> Result<OnboardingApplyResult, BootstrapError> {
    apply_repository_onboarding_inner(root.as_ref(), proposal, None)
}
/// Supplies the existing trusted external authorization port for explicitly reviewed protected repair.
/// # Errors
/// Retains exact source/target checks; unverified references still confer no permission.
pub fn apply_repository_onboarding_with_authority(
    root: impl AsRef<Path>,
    proposal: &OnboardingProposal,
    authority: &dyn MigrationAuthority,
) -> Result<OnboardingApplyResult, BootstrapError> {
    apply_repository_onboarding_inner(root.as_ref(), proposal, Some(authority))
}
fn apply_repository_onboarding_inner(
    root: &Path,
    proposal: &OnboardingProposal,
    external: Option<&dyn MigrationAuthority>,
) -> Result<OnboardingApplyResult, BootstrapError> {
    let storage =
        crate::migration_adapter::default_migration_storage().map_err(BootstrapError::Migration)?;
    apply_repository_onboarding_with_ports(root, proposal, external, &storage, &NoMutationFaults)
}

/// Applies through the existing migration resource and fault-observation ports.
/// This boundary supports cancellation and recovery testing without a second writer.
/// # Errors
/// Preserves the shared engine's transaction reference and all recoverable journal material.
pub fn apply_repository_onboarding_with_ports<
    R: crate::migration_governance::ResourceLeasePort,
    O: crate::migration_governance::MutationObserver,
>(
    root: &Path,
    proposal: &OnboardingProposal,
    external: Option<&dyn MigrationAuthority>,
    storage: &R,
    observer: &O,
) -> Result<OnboardingApplyResult, BootstrapError> {
    let rebuilt = validate_current_review(root, proposal, external)?;
    let plan = rebuilt
        .migration_plan
        .as_ref()
        .ok_or(BootstrapError::UnresolvedProposal)?;
    let intent = rebuilt
        .reviewed_intent_ref
        .as_deref()
        .ok_or(BootstrapError::UnresolvedProposal)?;
    let authority = OnboardingAuthority {
        intent_ref: intent.into(),
        canonical: rebuilt.mode == OnboardingMode::Canonical,
        external,
    };
    let mut workspace = CandidateWorkspace::open_cold(root).map_err(BootstrapError::Migration)?;
    let request = CandidateRequest {
        schema_version: 1,
        base_source_ref: workspace.base_source_ref().into(),
        context_ref: workspace.context_ref().into(),
        operations: rebuilt.operations.clone(),
        comparison_context: ComparisonContext::default(),
    };
    let predicted = workspace
        .evaluate(
            "adoption",
            "apply",
            request,
            &authority,
            &AtomicBool::new(false),
        )
        .map_err(BootstrapError::Migration)?;
    if predicted.predicted_state().digest().map_err(invalid)? != plan.target_state_ref() {
        return Err(invalid(
            "PREDICTION_CHANGED: migration and candidate target differ",
        ));
    }
    let permit = workspace
        .authorize_before_write("adoption", "apply", &authority, &AtomicBool::new(false))
        .map_err(BootstrapError::Migration)?;
    let applied = apply_migration(
        root,
        plan,
        &MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &authority,
            resources: storage,
            observer,
        },
    )
    .map_err(BootstrapError::Migration)?;
    let reconciliation = workspace
        .reconcile(
            "adoption",
            "apply",
            Some(&permit),
            &authority,
            &NoActualExecution,
            &AtomicBool::new(false),
        )
        .map_err(BootstrapError::Migration)?;
    if reconciliation.status() != "EXACT_MATCH_UNVERIFIED" && !reconciliation.actual_state() {
        return Err(invalid(format!(
            "POST_WRITE_DIVERGENCE: receipt {} is historical; actual state requires reassessment",
            applied.receipt.digest()
        )));
    }
    let (actual, evaluated) = observe_onboarding_target(root, plan, applied.receipt.digest())?;
    let proposal_record_path = retain_onboarding_proposal(
        root,
        proposal,
        applied.receipt.digest(),
        &applied.transaction_ref,
    )?;
    let inspection = onboarding_actual_inspection(root)?;
    if CanonicalMigrationEvaluator
        .observe(root)
        .map_err(BootstrapError::Migration)?
        != actual
    {
        return Err(invalid(format!(
            "POST_WRITE_DIVERGENCE: source changed during final inspection; receipt {} is historical",
            applied.receipt.digest()
        )));
    }
    Ok(OnboardingApplyResult {
        schema: "urn:fortress:derived:v1:repository-onboarding-result".into(),
        schema_version: 1,
        proposal_digest: proposal.digest().into(),
        migration_plan_ref: plan.digest().into(),
        migration_receipt_ref: applied.receipt.digest().into(),
        migration_record_path: applied.record_path,
        proposal_record_path,
        actual_source_ref: actual.digest().into(),
        actual_state_ref: evaluated.state.digest().map_err(invalid)?,
        reconciliation: serde_json::to_value(reconciliation).map_err(invalid)?,
        actual_governance: serde_json::to_value(evaluated.state.view).map_err(invalid)?,
        inspection,
        certification: "NOT_ESTABLISHED".into(),
    })
}

/// Recovers the exact reviewed plan using exclusively the Migration Governance journal owner.
/// # Errors
/// Refuses mismatched plans, forged authorization, independent edits and ambiguous ownership.
pub fn recover_repository_onboarding<
    R: crate::migration_governance::ResourceLeasePort,
    O: crate::migration_governance::MutationObserver,
>(
    root: &Path,
    proposal: &OnboardingProposal,
    transaction_ref: &str,
    mode: crate::migration_governance::MigrationRecoveryMode,
    external: Option<&dyn MigrationAuthority>,
    storage: &R,
    observer: &O,
) -> Result<crate::migration_governance::MigrationRecovery, BootstrapError> {
    proposal.validate()?;
    let plan = proposal
        .migration_plan
        .as_ref()
        .ok_or(BootstrapError::UnresolvedProposal)?;
    let authority = OnboardingAuthority {
        intent_ref: proposal
            .reviewed_intent_ref
            .clone()
            .ok_or(BootstrapError::UnresolvedProposal)?,
        canonical: proposal.mode == OnboardingMode::Canonical,
        external,
    };
    let recovered = crate::migration_governance::recover_migration(
        root,
        plan,
        transaction_ref,
        mode,
        &MigrationServices {
            evaluator: &CanonicalMigrationEvaluator,
            authority: &authority,
            resources: storage,
            observer,
        },
    )
    .map_err(BootstrapError::Migration)?;
    if recovered.receipt.is_some() {
        let assessment = proposal
            .assessment
            .as_ref()
            .ok_or(BootstrapError::UnresolvedProposal)?;
        let reconciliation =
            crate::candidate::inspect_post_write(root, assessment, &AtomicBool::new(false))
                .map_err(BootstrapError::Migration)?;
        if reconciliation.status() != "EXACT_MATCH_UNVERIFIED" {
            return Err(invalid(
                "POST_WRITE_DIVERGENCE: recovery receipt is historical; the actual repository requires reassessment",
            ));
        }
        let path = ControlLayout::standard()
            .onboarding_proposal_path(proposal.digest())
            .ok_or_else(|| invalid("UNAVAILABLE_ROLE: reviewed onboarding proposal"))?;
        crate::migration_governance::export_proposal_record(
            root,
            path,
            proposal.to_canonical_json()?.as_bytes(),
        )
        .map_err(BootstrapError::Migration)?;
    }
    Ok(recovered)
}

fn observe_onboarding_target(
    root: &Path,
    plan: &MigrationPlan,
    receipt_ref: &str,
) -> Result<(SourceView, MigrationEvaluation), BootstrapError> {
    let actual = CanonicalMigrationEvaluator
        .observe(root)
        .map_err(BootstrapError::Migration)?;
    let evaluated = CanonicalMigrationEvaluator
        .evaluate(&actual)
        .map_err(BootstrapError::Migration)?;
    if actual.digest() != plan.target_source_ref()
        || evaluated.state.digest().map_err(invalid)? != plan.target_state_ref()
    {
        return Err(invalid(format!(
            "POST_WRITE_DIVERGENCE: actual repository differs from receipt {receipt_ref}"
        )));
    }
    Ok((actual, evaluated))
}
fn onboarding_actual_inspection(root: &Path) -> Result<Value, BootstrapError> {
    Ok(
        match crate::query::load_repository_query(root, &crate::query::QueryLoadOptions::default())
        {
            Ok(service) => {
                let response = |method: &str| -> Result<Value, BootstrapError> {
                    serde_json::to_value(service.execute(
                        &crate::query::QueryRequest {
                            protocol_version: 5,
                            request_id: format!("adoption-{method}"),
                            method: method.into(),
                            state_ref: None,
                            context_ref: None,
                            parameters: json!({}),
                        },
                        &AtomicBool::new(false),
                    ))
                    .map_err(invalid)
                };
                json!({"status":response("status")?,"doctor":response("doctor")?,"guidance":"Use status, doctor and explain against the actual repository. Retained historical certificates do not certify the newly established source."})
            }
            Err(error) => json!({"state":"UNAVAILABLE","error":error}),
        },
    )
}
fn retain_onboarding_proposal(
    root: &Path,
    proposal: &OnboardingProposal,
    receipt_ref: &str,
    transaction_ref: &str,
) -> Result<String, BootstrapError> {
    let path = ControlLayout::standard()
        .onboarding_proposal_path(proposal.digest())
        .ok_or_else(|| invalid("UNAVAILABLE_ROLE: reviewed onboarding proposal"))?;
    crate::migration_governance::export_proposal_record(root,path,proposal.to_canonical_json()?.as_bytes())
        .map_err(|error| BootstrapError::Migration(crate::migration_governance::MigrationError {
            code: "APPLIED_REVIEW_RECORD_UNAVAILABLE".into(),
            message: format!("Actual source was applied and verified. Receipt {receipt_ref} is retained; review-record export failed: {error}"),
            transaction_ref: Some(transaction_ref.into()),
        }))
}

fn validate_current_review(
    root: &Path,
    proposal: &OnboardingProposal,
    external: Option<&dyn MigrationAuthority>,
) -> Result<OnboardingProposal, BootstrapError> {
    proposal.validate()?;
    let current = CanonicalMigrationEvaluator
        .observe(root)
        .map_err(BootstrapError::Migration)?;
    if current.digest() != proposal.base_source_ref {
        return Err(BootstrapError::StaleProposal {
            expected: proposal.base_source_ref.clone().into(),
            actual: current.digest().into(),
        });
    }
    let rebuilt = build_proposal(root, &proposal.request, external)?;
    if rebuilt.digest() != proposal.digest() {
        return Err(invalid(
            "PREDICTION_CHANGED: exact reviewed proposal no longer matches the canonical owners",
        ));
    }
    if !(rebuilt.is_ready()
        || (external.is_some()
            && rebuilt.migration_plan.is_some()
            && rebuilt
                .unresolved_choices
                .iter()
                .all(|c| c.code == "EXTERNAL_AUTHORIZATION_REQUIRED")))
    {
        return Err(BootstrapError::UnresolvedProposal);
    }
    Ok(rebuilt)
}
