//! Read-only repository discovery and explicit snapshot-bound governance adoption.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::audit_repository;
use crate::certification::certification_source_digest;
use crate::contract_coherency::ModuleContract;
use crate::finding_governance::{FINDING_GOVERNANCE_PATH, FindingGovernanceDocument};
use crate::implementation_observation::{
    CargoAnalysisTerritoryObservation, ImplementationObservationInput, SnapshotBoundFile,
    observe_cargo_analysis_territories,
};
use crate::observation::ObservationPolicy;
use crate::project::ProjectConfiguration;
use crate::rust_test_analyzer::observe_observed_rust_tests;
use crate::snapshot::observe_repository_stably;
use crate::standard::installed_standard_manifest;

/// Canonical discovery-proposal schema identity.
pub const BOOTSTRAP_PROPOSAL_SCHEMA: &str = "urn:fortress:schema:v1:repository-bootstrap-proposal";
/// Canonical discovery-proposal schema version.
pub const BOOTSTRAP_PROPOSAL_SCHEMA_VERSION: u16 = 1;
/// Semantic version of proposal discovery and application behavior.
pub const BOOTSTRAP_SEMANTIC_VERSION: &str = "1.0.0";

static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(1);

/// Explicit caller-supplied architectural choices used during discovery.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootstrapDiscoveryOptions {
    project_id: Option<String>,
    display_name: Option<String>,
}

impl BootstrapDiscoveryOptions {
    /// Creates optional explicit project identity inputs.
    #[must_use]
    pub fn new(project_id: Option<String>, display_name: Option<String>) -> Self {
        Self {
            project_id,
            display_name,
        }
    }
}

/// Current authored-governance state observed without manufacturing authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BootstrapGovernanceState {
    /// No operational project authority exists.
    Absent,
    /// Valid project and root Module authority already exist.
    Declared,
    /// Project or root Module authority exists but is invalid or incomplete.
    Invalid,
}

/// Whether reviewed authority is complete enough for explicit application.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProposedAuthorityState {
    /// Every required owner choice is explicit and all artifact bytes are present.
    Ready,
    /// Human choices or authority conflicts prevent application.
    Unresolved,
}

/// One mechanically observed Cargo package, never an authored Fortress Module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootstrapCargoTerritory {
    analysis_identity: String,
    package_name: String,
    manifest_path: String,
    target_roots: Vec<String>,
}

impl From<CargoAnalysisTerritoryObservation> for BootstrapCargoTerritory {
    fn from(value: CargoAnalysisTerritoryObservation) -> Self {
        Self {
            analysis_identity: value.identity().into(),
            package_name: value.package_name().into(),
            manifest_path: value.manifest_path().into(),
            target_roots: value.target_roots().to_vec(),
        }
    }
}

/// Mechanically observed facts separated from proposed owner intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootstrapObservedFacts {
    repository_files: usize,
    rust_source_files: usize,
    rust_tests: usize,
    rust_tests_without_stable_identity: usize,
    cargo_territories: Vec<BootstrapCargoTerritory>,
}

impl BootstrapObservedFacts {
    /// Returns mechanically observed Cargo analysis territories.
    #[must_use]
    pub fn cargo_territories(&self) -> &[BootstrapCargoTerritory] {
        &self.cargo_territories
    }

    /// Returns the count of observed tests lacking stable Fortress identity.
    #[must_use]
    pub const fn rust_tests_without_stable_identity(&self) -> usize {
        self.rust_tests_without_stable_identity
    }
}

/// Exact installed Standard authority selected by the proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootstrapStandardBinding {
    id: String,
    edition: String,
}

/// One explicit unresolved owner decision or adoption conflict.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BootstrapUnresolvedChoice {
    code: String,
    detail: String,
}

/// One exact reviewed authored document that application may create.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposedAuthorityArtifact {
    path: String,
    authority_kind: String,
    content_digest: String,
    content: String,
}

impl ProposedAuthorityArtifact {
    fn new(path: &str, authority_kind: &str, content: String) -> Self {
        let bytes = content.as_bytes();
        Self {
            path: path.into(),
            authority_kind: authority_kind.into(),
            content_digest: sha256_bytes(bytes),
            content,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.content.as_bytes().to_vec()
    }
}

/// Reviewed authored content, distinct from observed facts and proposal state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposedBootstrapAuthority {
    state: ProposedAuthorityState,
    artifacts: Vec<ProposedAuthorityArtifact>,
}

/// Truthful prediction boundary for legacy finding residue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictedLegacyResidue {
    status: String,
    detail: String,
}

/// Canonical, immutable, source-bound initialization proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapProposal {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    state: String,
    proposal_digest: String,
    source_fingerprint: String,
    governance_state: BootstrapGovernanceState,
    governance_detail: Option<String>,
    installed_standard: BootstrapStandardBinding,
    observed_facts: BootstrapObservedFacts,
    proposed_authority: ProposedBootstrapAuthority,
    unresolved_choices: Vec<BootstrapUnresolvedChoice>,
    predicted_legacy_residue: PredictedLegacyResidue,
}

impl BootstrapProposal {
    /// Parses, validates, and byte-checks a canonical proposal.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or digest-invalid content.
    pub fn from_json_str(source: &str) -> Result<Self, BootstrapError> {
        let proposal: Self = serde_json::from_str(source)
            .map_err(|error| BootstrapError::InvalidProposal(error.to_string().into()))?;
        proposal.validate()?;
        if proposal.to_canonical_json()?.as_bytes() != source.as_bytes() {
            return Err(BootstrapError::InvalidProposal(
                "proposal serialization is not canonical".into(),
            ));
        }
        Ok(proposal)
    }

    /// Serializes canonical deterministic JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, BootstrapError> {
        let mut output = serde_json::to_string_pretty(self)
            .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
        output.push('\n');
        Ok(output)
    }

    /// Returns the exact source identity captured by discovery.
    #[must_use]
    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    /// Returns whether explicit reviewed authority is ready to apply.
    #[must_use]
    pub const fn authority_state(&self) -> ProposedAuthorityState {
        self.proposed_authority.state
    }

    /// Returns unresolved owner choices and conflicts.
    #[must_use]
    pub fn unresolved_choices(&self) -> &[BootstrapUnresolvedChoice] {
        &self.unresolved_choices
    }

    /// Returns mechanically observed repository facts.
    #[must_use]
    pub const fn observed_facts(&self) -> &BootstrapObservedFacts {
        &self.observed_facts
    }

    /// Returns the content-addressed proposal identity.
    #[must_use]
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }

    fn validate(&self) -> Result<(), BootstrapError> {
        if self.schema != BOOTSTRAP_PROPOSAL_SCHEMA
            || self.schema_version != BOOTSTRAP_PROPOSAL_SCHEMA_VERSION
            || self.semantic_version != BOOTSTRAP_SEMANTIC_VERSION
            || self.state != "PROPOSED"
        {
            return Err(BootstrapError::InvalidProposal(
                "proposal schema, version, semantic version, or state is unsupported".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        for artifact in &self.proposed_authority.artifacts {
            if !is_canonical_relative_path(&artifact.path) || !paths.insert(&artifact.path) {
                return Err(BootstrapError::InvalidProposal(
                    format!(
                        "proposed authority path `{}` is invalid or duplicated",
                        artifact.path
                    )
                    .into(),
                ));
            }
            if sha256_bytes(&artifact.bytes()) != artifact.content_digest {
                return Err(BootstrapError::InvalidProposal(
                    format!("proposed authority digest mismatch at `{}`", artifact.path).into(),
                ));
            }
        }
        if self.proposed_authority.state == ProposedAuthorityState::Ready
            && (!self.unresolved_choices.is_empty() || self.proposed_authority.artifacts.len() != 3)
        {
            return Err(BootstrapError::InvalidProposal(
                "ready authority must contain exactly three artifacts and no unresolved choices"
                    .into(),
            ));
        }
        if self.identity_digest()? != self.proposal_digest {
            return Err(BootstrapError::InvalidProposal(
                "proposal digest does not match canonical content".into(),
            ));
        }
        Ok(())
    }

    fn identity_digest(&self) -> Result<String, BootstrapError> {
        let material = BootstrapProposalIdentityMaterial {
            schema: &self.schema,
            schema_version: self.schema_version,
            semantic_version: &self.semantic_version,
            state: &self.state,
            source_fingerprint: &self.source_fingerprint,
            governance_state: self.governance_state,
            governance_detail: self.governance_detail.as_deref(),
            installed_standard: &self.installed_standard,
            observed_facts: &self.observed_facts,
            proposed_authority: &self.proposed_authority,
            unresolved_choices: &self.unresolved_choices,
            predicted_legacy_residue: &self.predicted_legacy_residue,
        };
        let bytes = serde_json::to_vec(&material)
            .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
        Ok(sha256_bytes(&bytes))
    }
}

#[derive(Serialize)]
struct BootstrapProposalIdentityMaterial<'a> {
    schema: &'a str,
    schema_version: u16,
    semantic_version: &'a str,
    state: &'a str,
    source_fingerprint: &'a str,
    governance_state: BootstrapGovernanceState,
    governance_detail: Option<&'a str>,
    installed_standard: &'a BootstrapStandardBinding,
    observed_facts: &'a BootstrapObservedFacts,
    proposed_authority: &'a ProposedBootstrapAuthority,
    unresolved_choices: &'a [BootstrapUnresolvedChoice],
    predicted_legacy_residue: &'a PredictedLegacyResidue,
}

/// Result of one explicit transactional adoption operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BootstrapApplyResult {
    proposal_digest: String,
    source_fingerprint: String,
    created_files: Vec<String>,
    baseline_created: bool,
    raw_findings: Option<usize>,
    baselined_findings: Option<usize>,
    baseline_ineligible_findings: Option<usize>,
    blocking_findings: Option<usize>,
    strict_conformance: String,
    progressive_enforcement: String,
}

impl BootstrapApplyResult {
    /// Serializes a canonical apply report.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, BootstrapError> {
        let mut output = serde_json::to_string_pretty(self)
            .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
        output.push('\n');
        Ok(output)
    }
}

/// Performs read-only discovery and constructs a reviewed authority proposal.
///
/// # Errors
///
/// Returns an error when observation, Cargo/test parsing, or explicit owner
/// input validation fails. The subject repository is never modified.
pub fn discover_repository_bootstrap(
    root: impl AsRef<Path>,
    options: &BootstrapDiscoveryOptions,
) -> Result<BootstrapProposal, BootstrapError> {
    let root = root.as_ref();
    let (files, source_fingerprint) = observed_source(root)?;
    let installed_standard = installed_standard_binding()?;
    let governance = observe_governance(&files);
    let snapshot_files = snapshot_bound_files(&files);
    let observation_input =
        ImplementationObservationInput::new(&source_fingerprint, snapshot_files, Vec::new());
    let cargo_territories = observe_cargo_analysis_territories(&observation_input)
        .map_err(|error| BootstrapError::Observation(error.to_string().into()))?
        .into_iter()
        .map(BootstrapCargoTerritory::from)
        .collect();
    let rust_tests = observe_observed_rust_tests(
        files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    )
    .map_err(|error| BootstrapError::Observation(error.to_string().into()))?;
    let observed_facts = BootstrapObservedFacts {
        repository_files: files.len(),
        rust_source_files: files
            .keys()
            .filter(|path| {
                Path::new(path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            })
            .count(),
        rust_tests: rust_tests.len(),
        rust_tests_without_stable_identity: rust_tests
            .iter()
            .filter(|test| !test.is_governed())
            .count(),
        cargo_territories,
    };
    let mut unresolved_choices = Vec::new();
    if governance.0 != BootstrapGovernanceState::Absent {
        unresolved_choices.push(BootstrapUnresolvedChoice {
            code: "EXISTING_GOVERNANCE".into(),
            detail: "initialization cannot overwrite or repair existing project authority".into(),
        });
    }
    if files.contains_key("contract.json") || files.contains_key(FINDING_GOVERNANCE_PATH) {
        unresolved_choices.push(BootstrapUnresolvedChoice {
            code: "AUTHORITY_PATH_CONFLICT".into(),
            detail: "a bootstrap-owned authority path already exists".into(),
        });
    }
    if options.project_id.is_none() {
        unresolved_choices.push(BootstrapUnresolvedChoice {
            code: "PROJECT_ID_REQUIRED".into(),
            detail: "a stable project/root Module identity must be supplied by the owner".into(),
        });
    }
    if options.display_name.is_none() {
        unresolved_choices.push(BootstrapUnresolvedChoice {
            code: "DISPLAY_NAME_REQUIRED".into(),
            detail: "a project display name must be supplied by the owner".into(),
        });
    }
    unresolved_choices.sort();
    unresolved_choices.dedup();
    let artifacts = match (&options.project_id, &options.display_name) {
        (Some(project_id), Some(display_name)) if unresolved_choices.is_empty() => {
            proposed_artifacts(project_id, display_name, &installed_standard)?
        }
        _ => Vec::new(),
    };
    let proposed_authority = ProposedBootstrapAuthority {
        state: if artifacts.is_empty() {
            ProposedAuthorityState::Unresolved
        } else {
            ProposedAuthorityState::Ready
        },
        artifacts,
    };
    let mut proposal = BootstrapProposal {
        schema: BOOTSTRAP_PROPOSAL_SCHEMA.into(),
        schema_version: BOOTSTRAP_PROPOSAL_SCHEMA_VERSION,
        semantic_version: BOOTSTRAP_SEMANTIC_VERSION.into(),
        state: "PROPOSED".into(),
        proposal_digest: String::new(),
        source_fingerprint,
        governance_state: governance.0,
        governance_detail: governance.1,
        installed_standard,
        observed_facts,
        proposed_authority,
        unresolved_choices,
        predicted_legacy_residue: PredictedLegacyResidue {
            status: "EVALUATED_DURING_EXPLICIT_APPLY".into(),
            detail: "Raw governed findings are intentionally not inferred from unapproved authority; --baseline-current evaluates them only after the reviewed authority is materialized.".into(),
        },
    };
    proposal.proposal_digest = proposal.identity_digest()?;
    proposal.validate()?;
    Ok(proposal)
}

/// Applies reviewed authority transactionally and optionally creates the initial baseline.
///
/// # Errors
///
/// Returns an error without retained mutation for stale proposals, conflicts,
/// invalid authority, governed-evaluation failures, or baseline-ineligible residue.
pub fn apply_repository_bootstrap(
    root: impl AsRef<Path>,
    proposal: &BootstrapProposal,
    baseline_current: bool,
) -> Result<BootstrapApplyResult, BootstrapError> {
    proposal.validate()?;
    if proposal.authority_state() != ProposedAuthorityState::Ready {
        return Err(BootstrapError::UnresolvedProposal);
    }
    let root = root.as_ref();
    let (current_files, current_fingerprint) = observed_source(root)?;
    if current_fingerprint != proposal.source_fingerprint {
        return Err(BootstrapError::StaleProposal {
            expected: proposal.source_fingerprint.clone().into(),
            actual: current_fingerprint.into(),
        });
    }
    if observe_governance(&current_files).0 != BootstrapGovernanceState::Absent {
        return Err(BootstrapError::ExistingGovernance);
    }
    if current_files
        .keys()
        .any(|path| path == "contract.json" || path.ends_with("/contract.json"))
    {
        return Err(BootstrapError::AuthorityConflict(
            "an existing contract.json would compete with reviewed bootstrap authority".into(),
        ));
    }
    validate_reviewed_artifacts(proposal)?;
    for artifact in &proposal.proposed_authority.artifacts {
        if root.join(&artifact.path).exists() {
            return Err(BootstrapError::AuthorityConflict(
                format!("refusing to overwrite `{}`", artifact.path).into(),
            ));
        }
    }

    let mut transaction =
        BootstrapTransaction::stage(root, &proposal.proposed_authority.artifacts)?;
    transaction.commit()?;
    let result = if baseline_current {
        bootstrap_baseline(root, proposal, &mut transaction)
    } else {
        Ok(BootstrapApplyResult {
            proposal_digest: proposal.proposal_digest.clone(),
            source_fingerprint: proposal.source_fingerprint.clone(),
            created_files: transaction.final_paths(),
            baseline_created: false,
            raw_findings: None,
            baselined_findings: None,
            baseline_ineligible_findings: None,
            blocking_findings: None,
            strict_conformance: "NOT_EVALUATED".into(),
            progressive_enforcement: "NOT_EVALUATED".into(),
        })
    };
    match result {
        Ok(value) => {
            transaction.finish();
            Ok(value)
        }
        Err(error) => {
            transaction.rollback();
            Err(error)
        }
    }
}

fn bootstrap_baseline(
    root: &Path,
    proposal: &BootstrapProposal,
    transaction: &mut BootstrapTransaction,
) -> Result<BootstrapApplyResult, BootstrapError> {
    let audit = audit_repository(root)
        .map_err(|error| BootstrapError::GovernedEvaluation(error.to_string().into()))?;
    if !audit.is_governed() {
        return Err(BootstrapError::GovernedEvaluation(
            "reviewed authority did not establish governed project state".into(),
        ));
    }
    let mut authority = FindingGovernanceDocument::empty();
    let mutation = authority
        .create_baseline(
            audit.standard_id(),
            audit.standard_edition(),
            audit.findings(),
        )
        .map_err(|error| BootstrapError::GovernedEvaluation(error.to_string().into()))?;
    if mutation.ineligible > 0 {
        return Err(BootstrapError::BaselineIneligible(mutation.ineligible));
    }
    transaction.replace_committed(
        FINDING_GOVERNANCE_PATH,
        authority
            .to_canonical_json()
            .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?
            .as_bytes(),
    )?;
    let classified = audit_repository(root)
        .map_err(|error| BootstrapError::GovernedEvaluation(error.to_string().into()))?;
    let summary = classified.finding_governance().summary();
    if !classified.enforcement_success() {
        return Err(BootstrapError::BlockingFindings(summary.new_blocking));
    }
    Ok(BootstrapApplyResult {
        proposal_digest: proposal.proposal_digest.clone(),
        source_fingerprint: proposal.source_fingerprint.clone(),
        created_files: transaction.final_paths(),
        baseline_created: true,
        raw_findings: Some(classified.findings().len()),
        baselined_findings: Some(summary.baselined_non_blocking),
        baseline_ineligible_findings: Some(summary.baseline_ineligible),
        blocking_findings: Some(summary.new_blocking),
        strict_conformance: if classified.is_success() {
            "PASS"
        } else {
            "FAIL"
        }
        .into(),
        progressive_enforcement: "PASS".into(),
    })
}

fn proposed_artifacts(
    project_id: &str,
    display_name: &str,
    standard: &BootstrapStandardBinding,
) -> Result<Vec<ProposedAuthorityArtifact>, BootstrapError> {
    let project_id = serde_json::to_string(project_id)
        .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
    let display_name = serde_json::to_string(display_name)
        .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
    let standard_id = serde_json::to_string(&standard.id)
        .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
    let standard_edition = serde_json::to_string(&standard.edition)
        .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
    let contract = format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v2:module-contract\",\n  \"schema_version\": 2,\n  \"id\": {project_id},\n  \"display_name\": {display_name},\n  \"ecosystem\": {{\n    \"repository_grammar\": 1,\n    \"standard\": {{\n      \"id\": {standard_id},\n      \"edition\": {standard_edition}\n    }}\n  }},\n  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n  \"constraints\": [],\n  \"guarantees\": [],\n  \"features\": [],\n  \"behavior\": []\n}}\n"
    );
    let project = "{\n  \"$schema\": \"urn:fortress:schema:v2:project-configuration\",\n  \"schema_version\": 2,\n  \"observation_exclusions\": [\n    \".git\"\n  ]\n}\n".to_owned();
    let governance = FindingGovernanceDocument::empty()
        .to_canonical_json()
        .map_err(|error| BootstrapError::Serialization(error.to_string().into()))?;
    let mut artifacts = vec![
        ProposedAuthorityArtifact::new("contract.json", "ROOT_MODULE_CONTRACT", contract),
        ProposedAuthorityArtifact::new("data/project.json", "PROJECT_CONFIGURATION", project),
        ProposedAuthorityArtifact::new(FINDING_GOVERNANCE_PATH, "FINDING_GOVERNANCE", governance),
    ];
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(artifacts)
}

fn validate_reviewed_artifacts(proposal: &BootstrapProposal) -> Result<(), BootstrapError> {
    let by_path = proposal
        .proposed_authority
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let contract = by_path
        .get("contract.json")
        .ok_or_else(|| BootstrapError::InvalidProposal("root contract is absent".into()))?;
    let contract_bytes = contract.bytes();
    let contract_source = std::str::from_utf8(&contract_bytes)
        .map_err(|_| BootstrapError::InvalidProposal("root contract is not UTF-8".into()))?;
    let contract_model = ModuleContract::from_json_str(contract_source)
        .map_err(|error| BootstrapError::InvalidProposal(error.to_string().into()))?;
    let ecosystem = contract_model.ecosystem().ok_or_else(|| {
        BootstrapError::InvalidProposal("root ecosystem binding is absent".into())
    })?;
    if ecosystem.standard().id() != proposal.installed_standard.id
        || ecosystem.standard().edition() != proposal.installed_standard.edition
    {
        return Err(BootstrapError::InvalidProposal(
            "reviewed Standard binding differs from the installed authority".into(),
        ));
    }
    let project = by_path
        .get("data/project.json")
        .ok_or_else(|| BootstrapError::InvalidProposal("project configuration is absent".into()))?;
    let project_bytes = project.bytes();
    ProjectConfiguration::from_json_str(std::str::from_utf8(&project_bytes).map_err(|_| {
        BootstrapError::InvalidProposal("project configuration is not UTF-8".into())
    })?)
    .map_err(|error| BootstrapError::InvalidProposal(error.to_string().into()))?;
    let finding = by_path.get(FINDING_GOVERNANCE_PATH).ok_or_else(|| {
        BootstrapError::InvalidProposal("finding governance authority is absent".into())
    })?;
    let finding_bytes = finding.bytes();
    FindingGovernanceDocument::from_json_str(
        std::str::from_utf8(&finding_bytes).map_err(|_| {
            BootstrapError::InvalidProposal("finding governance is not UTF-8".into())
        })?,
    )
    .map_err(|error| BootstrapError::InvalidProposal(error.to_string().into()))?;
    Ok(())
}

fn observed_source(root: &Path) -> Result<(BTreeMap<String, Vec<u8>>, String), BootstrapError> {
    let policy = ObservationPolicy::new([".git"])
        .map_err(|error| BootstrapError::Observation(error.to_string().into()))?;
    let observation = observe_repository_stably(root, &policy)
        .map_err(|error| BootstrapError::Observation(error.to_string().into()))?;
    let files = observation
        .files()
        .iter()
        .map(|file| {
            fs::read(root.join(file.path()))
                .map(|bytes| (file.path().to_owned(), bytes))
                .map_err(|error| BootstrapError::Io {
                    path: file.path().into(),
                    detail: error.to_string().into(),
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let digest = certification_source_digest(&files);
    Ok((files, digest))
}

fn snapshot_bound_files(files: &BTreeMap<String, Vec<u8>>) -> Vec<SnapshotBoundFile> {
    files
        .iter()
        .map(|(path, bytes)| SnapshotBoundFile::from_bytes(path, bytes.clone()))
        .collect()
}

fn observe_governance(
    files: &BTreeMap<String, Vec<u8>>,
) -> (BootstrapGovernanceState, Option<String>) {
    let Some(project) = files.get("data/project.json") else {
        return (
            BootstrapGovernanceState::Absent,
            Some("data/project.json is absent".into()),
        );
    };
    let parsed_project = std::str::from_utf8(project)
        .map_err(|_| "data/project.json is not UTF-8".to_owned())
        .and_then(|source| ProjectConfiguration::from_json_str(source).map_err(|e| e.to_string()));
    let parsed_contract = files
        .get("contract.json")
        .ok_or_else(|| "root contract.json is absent".to_owned())
        .and_then(|bytes| {
            std::str::from_utf8(bytes)
                .map_err(|_| "contract.json is not UTF-8".to_owned())
                .and_then(|source| ModuleContract::from_json_str(source).map_err(|e| e.to_string()))
        });
    match (parsed_project, parsed_contract) {
        (Ok(_), Ok(_)) => (BootstrapGovernanceState::Declared, None),
        (project, contract) => (
            BootstrapGovernanceState::Invalid,
            Some(
                [project.err(), contract.err()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        ),
    }
}

#[derive(Deserialize)]
struct InstalledStandardManifest {
    id: String,
    edition: String,
}

fn installed_standard_binding() -> Result<BootstrapStandardBinding, BootstrapError> {
    let manifest: InstalledStandardManifest =
        serde_json::from_str(installed_standard_manifest())
            .map_err(|error| BootstrapError::InvalidProposal(error.to_string().into()))?;
    if manifest.id.is_empty() || manifest.edition.is_empty() {
        return Err(BootstrapError::InvalidProposal(
            "installed Standard identity is incomplete".into(),
        ));
    }
    Ok(BootstrapStandardBinding {
        id: manifest.id,
        edition: manifest.edition,
    })
}

struct StagedArtifact {
    relative: String,
    temporary: PathBuf,
    final_path: PathBuf,
}

struct BootstrapTransaction {
    staged: Vec<StagedArtifact>,
    created_directories: Vec<PathBuf>,
    committed: bool,
}

impl BootstrapTransaction {
    fn stage(root: &Path, artifacts: &[ProposedAuthorityArtifact]) -> Result<Self, BootstrapError> {
        let identity = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
        let mut transaction = Self {
            staged: Vec::new(),
            created_directories: Vec::new(),
            committed: false,
        };
        for artifact in artifacts {
            let final_path = root.join(&artifact.path);
            let parent = final_path.parent().ok_or_else(|| {
                BootstrapError::InvalidProposal("authority path has no parent".into())
            })?;
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|error| BootstrapError::Io {
                    path: artifact.path.clone().into(),
                    detail: error.to_string().into(),
                })?;
                transaction.created_directories.push(parent.to_path_buf());
            }
            let file_name = final_path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| BootstrapError::InvalidProposal("invalid authority name".into()))?;
            let temporary = parent.join(format!(
                ".{file_name}.fortress-init-{}-{identity}.tmp",
                std::process::id()
            ));
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| BootstrapError::Io {
                    path: artifact.path.clone().into(),
                    detail: error.to_string().into(),
                })?;
            file.write_all(&artifact.bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| BootstrapError::Io {
                    path: artifact.path.clone().into(),
                    detail: error.to_string().into(),
                })?;
            transaction.staged.push(StagedArtifact {
                relative: artifact.path.clone(),
                temporary,
                final_path,
            });
        }
        Ok(transaction)
    }

    fn commit(&mut self) -> Result<(), BootstrapError> {
        for artifact in &self.staged {
            fs::rename(&artifact.temporary, &artifact.final_path).map_err(|error| {
                BootstrapError::Io {
                    path: artifact.relative.clone().into(),
                    detail: error.to_string().into(),
                }
            })?;
        }
        self.committed = true;
        Ok(())
    }

    fn replace_committed(&mut self, relative: &str, bytes: &[u8]) -> Result<(), BootstrapError> {
        let artifact = self
            .staged
            .iter()
            .find(|artifact| artifact.relative == relative)
            .ok_or_else(|| BootstrapError::InvalidProposal("replacement target absent".into()))?;
        fs::write(&artifact.final_path, bytes).map_err(|error| BootstrapError::Io {
            path: relative.into(),
            detail: error.to_string().into(),
        })?;
        Ok(())
    }

    fn final_paths(&self) -> Vec<String> {
        self.staged
            .iter()
            .map(|artifact| artifact.relative.clone())
            .collect()
    }

    fn finish(&mut self) {
        self.committed = false;
        self.staged.clear();
        self.created_directories.clear();
    }

    fn rollback(&mut self) {
        for artifact in self.staged.iter().rev() {
            let _ = fs::remove_file(&artifact.temporary);
            let _ = fs::remove_file(&artifact.final_path);
        }
        for directory in self.created_directories.iter().rev() {
            let _ = fs::remove_dir(directory);
        }
        self.committed = false;
    }
}

impl Drop for BootstrapTransaction {
    fn drop(&mut self) {
        if !self.staged.is_empty() {
            self.rollback();
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.ends_with('/')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Explains why discovery or explicit application could not complete.
#[derive(Debug)]
pub enum BootstrapError {
    /// Repository observation or supported Cargo/test extraction failed.
    Observation(Box<str>),
    /// Proposal JSON, digest, or reviewed content is invalid.
    InvalidProposal(Box<str>),
    /// Proposal still contains choices requiring owner review.
    UnresolvedProposal,
    /// The repository changed after discovery.
    StaleProposal {
        /// Fingerprint reviewed by the owner.
        expected: Box<str>,
        /// Current repository fingerprint.
        actual: Box<str>,
    },
    /// Valid project governance already exists.
    ExistingGovernance,
    /// Existing repository content conflicts with proposed authority.
    AuthorityConflict(Box<str>),
    /// Governed evaluation required for baseline bootstrap failed.
    GovernedEvaluation(Box<str>),
    /// Some current findings cannot safely enter a legacy baseline.
    BaselineIneligible(usize),
    /// Blocking findings remain after attempted baseline creation.
    BlockingFindings(usize),
    /// Canonical serialization failed.
    Serialization(Box<str>),
    /// Filesystem mutation or read failed.
    Io {
        /// Repository-relative affected path where known.
        path: Box<str>,
        /// Operating-system failure detail.
        detail: Box<str>,
    },
}

impl Display for BootstrapError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observation(detail) => write!(formatter, "repository discovery failed: {detail}"),
            Self::InvalidProposal(detail) => write!(formatter, "bootstrap proposal is invalid: {detail}"),
            Self::UnresolvedProposal => formatter.write_str(
                "bootstrap proposal has unresolved owner choices and cannot be applied",
            ),
            Self::StaleProposal { expected, actual } => write!(
                formatter,
                "bootstrap proposal is stale: reviewed source `{expected}`, current source `{actual}`; regenerate and review the proposal"
            ),
            Self::ExistingGovernance => formatter.write_str(
                "repository already has project governance; initialization never overwrites or migrates it",
            ),
            Self::AuthorityConflict(detail) => write!(formatter, "authority conflict: {detail}"),
            Self::GovernedEvaluation(detail) => write!(formatter, "governed evaluation failed: {detail}"),
            Self::BaselineIneligible(count) => write!(
                formatter,
                "{count} current finding(s) lack safe stable identity; zero-new-red bootstrap was rolled back"
            ),
            Self::BlockingFindings(count) => write!(
                formatter,
                "{count} blocking finding(s) remain after baseline creation; bootstrap was rolled back"
            ),
            Self::Serialization(detail) => write!(formatter, "canonical serialization failed: {detail}"),
            Self::Io { path, detail } => write!(formatter, "repository I/O failed at `{path}`: {detail}"),
        }
    }
}

impl Error for BootstrapError {}
