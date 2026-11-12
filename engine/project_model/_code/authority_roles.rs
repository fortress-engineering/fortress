//! Protected input roles resolved independently of a candidate's permission claims.
use crate::control_layout::{ControlLayout, ControlRole};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Versioned protected governance surface vocabulary; ordinary source is absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedClass {
    /// Authored Module promises and requirements.
    ModuleIntent,
    /// Standard interpretation and installed rules.
    Standard,
    /// Profile selection, composition and applicability.
    Profile,
    /// Ownership, exclusions and visibility.
    OwnershipScope,
    /// Baselines, exceptions and enforcement dispositions.
    FindingGovernance,
    /// Required evidence and verification selectors.
    RequiredEvidence,
    /// Stable identity migrations.
    IdentityMigration,
    /// Assessor implementation, qualification and verification trust.
    AssessorTrust,
    /// External observation admission trust.
    ProviderTrust,
    /// Schema meaning and compatibility commitments.
    SchemaCompatibility,
    /// Active operational configuration.
    ProtectedConfiguration,
    /// Selected immutable evidence generation.
    EvidenceSelection,
    /// Evidence publication and retained history integrity.
    EvidencePublication,
    /// Release and publication policy.
    ReleasePolicy,
    /// Unrecognized control input; never silently ordinary source.
    UnknownControl,
}
impl ProtectedClass {
    /// Returns the complete installed vocabulary in stable order.
    #[must_use]
    pub fn all() -> Vec<Self> {
        use ProtectedClass::{
            AssessorTrust, EvidencePublication, EvidenceSelection, FindingGovernance,
            IdentityMigration, ModuleIntent, OwnershipScope, Profile, ProtectedConfiguration,
            ProviderTrust, ReleasePolicy, RequiredEvidence, SchemaCompatibility, Standard,
            UnknownControl,
        };
        vec![
            ModuleIntent,
            Standard,
            Profile,
            OwnershipScope,
            FindingGovernance,
            RequiredEvidence,
            IdentityMigration,
            AssessorTrust,
            ProviderTrust,
            SchemaCompatibility,
            ProtectedConfiguration,
            EvidenceSelection,
            EvidencePublication,
            ReleasePolicy,
            UnknownControl,
        ]
    }
}
/// Resolves installed CONTROL roles and declared schema meaning, irrespective of filename.
/// Additional protected owner/closure scopes are supplied by trusted base authority.
#[must_use]
pub fn protected_input_roles(
    layout: &ControlLayout,
    path: &str,
    schema: Option<&str>,
) -> BTreeSet<ProtectedClass> {
    use ProtectedClass::{
        AssessorTrust, EvidencePublication, EvidenceSelection, FindingGovernance,
        IdentityMigration, ModuleIntent, OwnershipScope, Profile, ProtectedConfiguration,
        ProviderTrust, ReleasePolicy, RequiredEvidence, SchemaCompatibility, Standard,
        UnknownControl,
    };
    let mut roles = BTreeSet::new();
    if let Some(entry) = layout.resolve(path) {
        match entry.role() {
            ControlRole::ProjectConfiguration => {
                roles.extend([ProtectedConfiguration, Profile, OwnershipScope]);
            }
            ControlRole::FindingGovernance => {
                roles.insert(FindingGovernance);
            }
            ControlRole::GlobalInformationFlowPolicy => {
                roles.insert(ModuleIntent);
            }
            ControlRole::EffectSummaryAuthority => {
                roles.insert(Standard);
            }
            ControlRole::VerificationBindings => {
                roles.insert(RequiredEvidence);
            }
            ControlRole::AssessmentSelectionIndex => {
                roles.insert(EvidenceSelection);
            }
            ControlRole::ProviderEnvelope
            | ControlRole::HypotheticalProposal
            | ControlRole::OnboardingProposal
            | ControlRole::ReviewedMigrationPlan
            | ControlRole::MigrationReceipt
            | ControlRole::ProviderPayload
            | ControlRole::GenerationManifest
            | ControlRole::GeneratedAssessmentPayload => {
                roles.insert(EvidencePublication);
            }
            ControlRole::Unrecognized => {
                roles.insert(UnknownControl);
            }
        }
    }
    if let Some(schema) = schema.filter(|s| s.starts_with("urn:fortress:schema:")) {
        // Schema identities are registered semantic types, not incidental file paths.
        let kind = schema.rsplit(':').next().unwrap_or_default();
        let class = match kind {
            "module-contract"
            | "function-contract"
            | "state-contract"
            | "information-flow-contract"
            | "behavior-contract"
            | "environment-contract" => ModuleIntent,
            "project" | "project-manifest" | "project-configuration" => ProtectedConfiguration,
            "identity-migration" => IdentityMigration,
            "finding-governance" => FindingGovernance,
            "verification-bindings" => RequiredEvidence,
            "governance-profiles" | "profile-catalog" => Profile,
            "provider-policy" | "provider-admission-policy" => ProviderTrust,
            "rule" | "standard-manifest" => Standard,
            "schema-manifest" | "compatibility-catalog" => SchemaCompatibility,
            "release-policy" | "publication-policy" => ReleasePolicy,
            "authorization-policy" | "assessor-policy" => AssessorTrust,
            _ => UnknownControl,
        };
        roles.insert(class);
    }
    roles
}

/// Installed assessor responsibility identities, independent of repository placement.
/// A trusted host may protect further scopes; candidate ownership edits cannot remove base roles.
#[must_use]
pub fn protected_owner_roles(owner: &str) -> BTreeSet<ProtectedClass> {
    let mut roles = BTreeSet::new();
    if let Some(parent) = owner.strip_prefix("TEST-") {
        roles.extend(protected_owner_roles(&format!("AF-{parent}")));
    }
    if matches!(
        owner,
        "PF-FORTRESS"
            | "TEST-FORTRESS-0001"
            | "AF-SEMANTIC-ORACLE-0001"
            | "AF-STANDARD-REGISTRY-0001"
            | "AF-CERTIFICATION-0001"
            | "AF-MIGRATION-GOVERNANCE-0001"
            | "AF-SNAPSHOT-GOVERNANCE-0001"
            | "AF-STATE-GOVERNANCE-0001"
            | "AF-DEVELOPMENT-GOVERNANCE-0001"
            | "AF-PROJECT-MODEL-0001"
            | "AF-REPOSITORY-OBSERVATION-0001"
            | "AF-ARCHITECTURE-EVALUATION-0001"
            | "AF-BEHAVIORAL-REALIZATION-0001"
            | "AF-BEHAVIORAL-SEMANTICS-0001"
            | "AF-CONTRACT-COHERENCY-0001"
            | "AF-ENVIRONMENTAL-SEMANTICS-0001"
            | "AF-FINDING-MODEL-0001"
            | "AF-IMPLEMENTATION-OBSERVATION-0001"
            | "AF-INFORMATION-FLOW-0001"
            | "AF-PROGRAM-SEMANTICS-0001"
            | "AF-REFERENCE-RESOLUTION-0001"
            | "AF-SEMANTIC-ANALYSIS-0001"
            | "AF-SOURCE-ARCHITECTURE-0001"
            | "AF-STATE-EFFECT-ANALYSIS-0001"
            | "AF-AFFECTED-ANALYSIS-0001"
            | "AF-CORE-0001"
            | "TF-CLI-0001"
    ) {
        roles.insert(ProtectedClass::AssessorTrust);
    }
    roles
}
