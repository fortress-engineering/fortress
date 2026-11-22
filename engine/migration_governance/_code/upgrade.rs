//! Reviewable edition changes built on the canonical migration and comparison owners.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::control_layout::{ControlLayout, ControlRole};
use crate::observation::SourceView;
use crate::profile::{NATIVE_GOVERNANCE_PROFILE_ID, installed_profile_reference};
use crate::project::{PROJECT_CONFIGURATION_SCHEMA, ProjectConfiguration};
use crate::standard::StandardBundle;
use crate::standard::compatibility::{
    CompatibilityEntry, installed_compatibility, installed_compatibility_source,
};
use crate::state_governance::TransitionAnalysis;

use super::{
    MigrationError, MigrationEvaluation, MigrationOperation, MigrationPlan, MigrationPreview,
    canonical, content_digest, fail,
};

const CONFIG_V2: &str = "urn:fortress:schema:v2:project-configuration";
const CONFIG_V3: &str = "urn:fortress:schema:v3:project-configuration";
const EDITION_UPGRADE_SCHEMA: &str = "urn:fortress:derived:v1:edition-upgrade";
const MAX_CONFIGURATION_BYTES: usize = 1024 * 1024;

/// Exact relationship between declared representation capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Compatibility {
    /// The installed runtime declares a reader for this exact original shape.
    DirectlyCompatible,
    /// A specifically implemented version transformation is required.
    MigrationRequired,
    /// The installed runtime does not implement this route.
    Unsupported,
    /// Both endpoints are readable, with no established equivalence between them.
    Incomparable,
    /// One of the requested identities is malformed.
    Invalid,
}

/// Compatibility of two exact requested schema identities.
#[derive(Debug, Serialize)]
pub struct CompatibilityAssessment {
    /// Original registered entry, if present.
    pub original: Option<CompatibilityEntry>,
    /// Target registered entry, if present.
    pub target: Option<CompatibilityEntry>,
    /// Capability relationship, independent of the validity of any record.
    pub status: Compatibility,
    /// Exact supported transformation, when one exists.
    pub transform: Option<&'static str>,
}

fn configuration_route(from: &str, to: &str) -> bool {
    matches!(from, CONFIG_V2 | CONFIG_V3) && to == PROJECT_CONFIGURATION_SCHEMA
}

/// Discovers installed capabilities and explicit routes without executing a reader.
///
/// # Errors
/// Refuses invalid installed compatibility authority.
pub fn compatibility(from: &str, to: &str) -> Result<CompatibilityAssessment, MigrationError> {
    let mut entries = installed_compatibility().map_err(invalid)?;
    let pop = |entries: &mut Vec<CompatibilityEntry>, id: &str| {
        entries
            .iter()
            .position(|entry| entry.schema_id == id)
            .map(|i| entries.swap_remove(i))
    };
    let original = pop(&mut entries, from);
    let target = if from == to {
        original.clone()
    } else {
        pop(&mut entries, to)
    };
    let valid = |id: &str| {
        id.len() <= 256
            && id.starts_with("urn:fortress:")
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":-_.".contains(&b))
    };
    let status = if !valid(from) || !valid(to) {
        Compatibility::Invalid
    } else if !original
        .as_ref()
        .is_some_and(CompatibilityEntry::has_runtime_reader)
        || !target
            .as_ref()
            .is_some_and(CompatibilityEntry::has_runtime_reader)
        || from.rsplit(':').next() != to.rsplit(':').next()
        || from == PROJECT_CONFIGURATION_SCHEMA && to != PROJECT_CONFIGURATION_SCHEMA
    {
        Compatibility::Unsupported
    } else if from == to {
        Compatibility::DirectlyCompatible
    } else if configuration_route(from, to) {
        Compatibility::MigrationRequired
    } else {
        Compatibility::Incomparable
    };
    Ok(CompatibilityAssessment {
        original,
        target,
        status,
        transform: (status == Compatibility::MigrationRequired)
            .then_some("explicit-native-configuration-v1"),
    })
}

/// Produces the original legacy native default as an explicit current selection.
/// Existing exclusions, contracts and logical bindings are retained exactly in meaning.
///
/// # Errors
/// Rejects malformed, oversized or unregistered inputs and unsupported routes.
pub fn explicit_native_configuration(original: &[u8]) -> Result<Vec<u8>, MigrationError> {
    if original.len() > MAX_CONFIGURATION_BYTES {
        return Err(fail(
            "RESOURCE_LIMIT",
            "project configuration exceeds admission",
        ));
    }
    let text = std::str::from_utf8(original).map_err(invalid)?;
    let original = ProjectConfiguration::from_json_str(text).map_err(invalid)?;
    let mut target: Value = crate::wire::parse_public_json(text).map_err(invalid)?;
    let fields = target
        .as_object()
        .ok_or_else(|| invalid("configuration is not an object"))?;
    match target["$schema"].as_str() {
        Some(CONFIG_V2) if fields.len() == 3 => {}
        Some(CONFIG_V3) if fields.len() == 4 && target["logical_modules"].is_array() => {}
        Some(CONFIG_V2 | CONFIG_V3) => {
            return Err(invalid(
                "legacy configuration violates its original field inventory",
            ));
        }
        _ => {
            return Err(fail(
                "UNSUPPORTED_UPGRADE_ROUTE",
                "only legacy v2 or v3 native configuration can use this transformation",
            ));
        }
    }
    let profile = installed_profile_reference(NATIVE_GOVERNANCE_PROFILE_ID, "1.0.0")
        .map_err(invalid)?
        .ok_or_else(|| {
            fail(
                "UNSUPPORTED_UPGRADE_ROUTE",
                "the original native profile is unavailable",
            )
        })?;
    target["$schema"] = json!(PROJECT_CONFIGURATION_SCHEMA);
    target["schema_version"] = json!(4);
    let logical_modules = target
        .get("logical_modules")
        .cloned()
        .unwrap_or_else(|| json!([]));
    target["logical_modules"] = logical_modules;
    target["governance"] = json!({
        "default_layout": "native-logical-v1",
        "selected_profiles": [profile],
        "module_overrides": []
    });
    target["assurance_profiles"] = json!([]);
    let bytes = canonical(&target)?;
    let transformed =
        ProjectConfiguration::from_json_str(std::str::from_utf8(&bytes).map_err(invalid)?)
            .map_err(invalid)?;
    if transformed.observation_exclusions() != original.observation_exclusions()
        || transformed.logical_modules() != original.logical_modules()
    {
        return Err(fail(
            "UPGRADE_EQUIVALENCE_UNAVAILABLE",
            "authored source placement changed",
        ));
    }
    Ok(bytes)
}

/// Prepares an exact replacement for the registered configuration role.
///
/// # Errors
/// Refuses missing configurations, retired control roots and unsupported shapes.
pub fn configuration_upgrade_operation(
    base: &SourceView,
) -> Result<MigrationOperation, MigrationError> {
    let layout = ControlLayout::standard();
    let path = layout
        .role_path(ControlRole::ProjectConfiguration)
        .ok_or_else(|| {
            fail(
                "UNSUPPORTED_UPGRADE_ROUTE",
                "configuration role unavailable",
            )
        })?;
    let original = base.bytes(path).ok_or_else(|| {
        fail(
            "MISSING_ORIGINAL_AUTHORITY",
            "registered configuration is missing",
        )
    })?;
    Ok(MigrationOperation::ReplaceFile {
        path: path.into(),
        preimage: original.to_vec(),
        postimage: explicit_native_configuration(original)?,
    })
}

/// Independently pinned exact authority of a selected Standard edition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditionPin {
    /// Stable Standard identity.
    pub standard_id: String,
    /// Exact authored edition name.
    pub edition: String,
    /// Existing Standard Registry digest over original manifest and rule bytes.
    pub release_digest: String,
}

impl EditionPin {
    /// Projects an original validated Standard bundle into its trusted pin.
    #[must_use]
    pub fn for_standard(bundle: &StandardBundle) -> Self {
        Self {
            standard_id: bundle.id().into(),
            edition: bundle.edition().into(),
            release_digest: bundle.digest().into(),
        }
    }

    /// Validates an offline manifest plus rule bytes using the existing Standard reader.
    ///
    /// # Errors
    /// Refuses unavailable, excessive, malformed or mismatched authority bytes.
    pub fn resolve(
        &self,
        manifest: &str,
        rules: &[(&str, &str)],
    ) -> Result<StandardBundle, MigrationError> {
        if rules.len() > 1024
            || rules
                .iter()
                .try_fold(manifest.len(), |bytes, (path, rule)| {
                    bytes.checked_add(path.len())?.checked_add(rule.len())
                })
                .is_none_or(|bytes| bytes > super::MAX_MIGRATION_BYTES)
        {
            return Err(fail(
                "RESOURCE_LIMIT",
                "offline edition input exceeds admission",
            ));
        }
        require_schema(manifest, "urn:fortress:schema:v1:standard-manifest")?;
        for (_, source) in rules {
            require_schema(source, "urn:fortress:schema:v1:rule")?;
        }
        let bundle = StandardBundle::from_json_documents(manifest, rules).map_err(invalid)?;
        self.verify(&bundle)?;
        Ok(bundle)
    }

    fn verify(&self, bundle: &StandardBundle) -> Result<(), MigrationError> {
        if *self != Self::for_standard(bundle) {
            return Err(fail(
                "EDITION_PIN_MISMATCH",
                "Standard identity, edition and original bytes must match the exact pin",
            ));
        }
        Ok(())
    }
}

fn require_schema(source: &str, schema: &str) -> Result<(), MigrationError> {
    let record: Value = crate::wire::parse_public_json(source).map_err(invalid)?;
    if record["$schema"].as_str() != Some(schema) {
        return Err(fail(
            "UNSUPPORTED_UPGRADE_ROUTE",
            "offline edition document does not use the registered reader schema",
        ));
    }
    Ok(())
}

/// Exact intended edition endpoints. The selection is review input, never a grant.
#[derive(Clone, Debug, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeAdapter {
    /// Independently selected original edition.
    pub from_bundle: EditionPin,
    /// Explicitly selected proposed edition.
    pub to_bundle: EditionPin,
    /// Request a separate canonical admission assessment for this exact operation set.
    #[serde(default)]
    pub preview_admission: bool,
}

/// Resolved endpoint with original qualified assessment and separately identified pinned inputs.
#[derive(Serialize)]
pub struct EditionBundle {
    /// Exact Standard pin, validated against the canonical endpoint.
    #[serde(flatten)]
    pub pin: EditionPin,
    /// Existing Standard's exact rule document digests, keyed by rule identity.
    pub rules: BTreeMap<String, String>,
    /// Exact CONTROL and selected configuration representation identities.
    pub schemas: BTreeMap<&'static str, String>,
    /// Existing canonical typed profile references with scope.
    pub profiles: Value,
    /// Installed reader capabilities, kept separate from semantic equality.
    pub supported_reader_manifest: String,
    /// Identity and content algorithms qualified for these configuration schemas.
    pub identity_algorithms: BTreeMap<String, String>,
    /// Original canonical declaration and assurance assessment, if produced.
    pub application: Option<crate::application::ApplicationAssessment>,
}

/// One independently named rule document change.
///
/// Neither removal nor changing prose infers an implication or retires a finding.
#[derive(Clone, Debug, Serialize)]
pub struct RuleChange {
    /// Exact authored Standard rule identity.
    pub id: String,
    /// Previous exact document digest, when present.
    pub before: Option<String>,
    /// Proposed exact document digest, when present.
    pub after: Option<String>,
    /// Formal implication or conflict edges differ for a retained rule.
    pub logic_changed: bool,
    /// Newly authored implication targets.
    pub implies_added: Vec<String>,
    /// Removed implication targets.
    pub implies_removed: Vec<String>,
    /// Newly authored conflict targets.
    pub conflicts_added: Vec<String>,
    /// Removed conflict targets.
    pub conflicts_removed: Vec<String>,
    /// Endpoint change classification.
    pub change: &'static str,
}

/// Versioned canonical proposal retaining the original comparison and sole-writer plan.
#[derive(Serialize)]
pub struct EditionUpgrade {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    disposition: &'static str,
    adapter_version: &'static str,
    /// Exact original declared authority and meanings.
    pub original: EditionBundle,
    /// Independently evaluated proposed authority and meanings.
    pub target: EditionBundle,
    /// Canonical state-axis, obligation, finding, evidence and policy changes.
    pub transition: TransitionAnalysis,
    /// Registered rule document changes without invented semantic implications.
    pub rules: Vec<RuleChange>,
    /// Compatibility of the observed original and proposed configuration representations.
    pub configuration_compatibility: Option<CompatibilityAssessment>,
    /// Existing admission owner's proposal, if explicitly requested.
    pub admission: Option<crate::finding_governance::AdmissionAssessment>,
    /// Existing identity owner's exact mapping and original physical binding.
    pub identity_migration: Option<Value>,
    /// Exact reviewed operations and protection requirements from the canonical preview.
    pub proposal_plan_ref: String,
    /// Exact operations even when the applicable writer plan must be withheld.
    pub operations: Vec<MigrationOperation>,
    /// Original-policy requirements supplied by the existing authorization preview.
    pub required_authorization: Vec<crate::development_governance::AuthorizationRequirement>,
    /// Existing exact writer plan where the edition route is supported.
    pub plan: Option<MigrationPlan>,
    /// Explicit route limits that prevent the proposal from yielding an applicable plan.
    pub limitations: Vec<&'static str>,
    /// Stable public proposal reference. It confers no permission.
    pub digest: String,
}

impl EditionUpgrade {
    /// Returns canonical bounded JSON. Existing certificate and historical wire digests are untouched.
    ///
    /// # Errors
    /// Refuses serialization outside public resource limits.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        canonical(self)
    }

    pub(crate) fn bind_admission(
        &mut self,
        assessment: crate::finding_governance::AdmissionAssessment,
    ) -> Result<(), MigrationError> {
        self.admission = Some(assessment);
        self.bind_digest()
    }

    pub(crate) fn bind_identity(&mut self, plan: &impl Serialize) -> Result<(), MigrationError> {
        self.identity_migration = Some(serde_json::to_value(plan).map_err(invalid)?);
        self.bind_digest()
    }

    fn bind_digest(&mut self) -> Result<(), MigrationError> {
        self.digest.clear();
        self.digest = content_digest(&self.to_canonical_bytes()?);
        Ok(())
    }
}

/// Projects the result of canonical MIGRATE planning; never runs an evaluator or writer.
///
/// # Errors
/// Refuses missing authority, edition reuse with changed bytes or mismatched endpoint pins.
pub fn assess_upgrade(
    adapter: &UpgradeAdapter,
    from: &StandardBundle,
    to: &StandardBundle,
    preview: MigrationPreview,
) -> Result<EditionUpgrade, MigrationError> {
    adapter.from_bundle.verify(from)?;
    adapter.to_bundle.verify(to)?;
    if from.id() != to.id() {
        return Err(fail(
            "UNSUPPORTED_UPGRADE_ROUTE",
            "no installed bridge connects different Standard identities",
        ));
    }
    if from.edition() == to.edition() && from.digest() != to.digest() {
        return Err(fail(
            "EDITION_IDENTITY_REUSED",
            "changed Standard bytes require a distinct edition identity",
        ));
    }
    let original = endpoint(from, &preview.base)?;
    let target = endpoint(to, &preview.target)?;
    let configuration_compatibility = original
        .schemas
        .get("configuration")
        .zip(target.schemas.get("configuration"))
        .map(|(from, to)| compatibility(from, to))
        .transpose()?;
    if let Some(compatibility) = &configuration_compatibility {
        match compatibility.status {
            Compatibility::DirectlyCompatible => {}
            Compatibility::MigrationRequired => {
                let expected = configuration_upgrade_operation(&preview.base.evaluated_source)?;
                if !preview.plan.operations().contains(&expected) {
                    return Err(fail(
                        "UNSUPPORTED_UPGRADE_ROUTE",
                        "configuration shape migration must preserve the exact original native selection and authored bindings",
                    ));
                }
            }
            _ => {
                return Err(fail(
                    "UNSUPPORTED_UPGRADE_ROUTE",
                    "no qualified direct configuration transformation",
                ));
            }
        }
    }
    let rules = compare_rules(from, to);
    let mut limitations = Vec::new();
    if !rules.is_empty() {
        limitations.push("CHANGED_RULE_MEANING_REQUIRES_QUALIFIED_EVALUATOR");
    }
    if original.application.is_none() || target.application.is_none() {
        limitations.push("DECLARED_ENDPOINT_ASSESSMENT_UNAVAILABLE");
    }
    let mut proposal = EditionUpgrade {
        schema: EDITION_UPGRADE_SCHEMA,
        schema_version: 1,
        disposition: "PROPOSED",
        adapter_version: "1.0.0",
        original,
        target,
        transition: preview.transition,
        rules,
        configuration_compatibility,
        admission: None,
        identity_migration: None,
        proposal_plan_ref: preview.plan.digest().into(),
        operations: preview.plan.operations().to_vec(),
        required_authorization: preview.plan.authorization().requirements().to_vec(),
        plan: limitations.is_empty().then_some(preview.plan),
        limitations,
        digest: String::new(),
    };
    proposal.bind_digest()?;
    Ok(proposal)
}

fn endpoint(
    bundle: &StandardBundle,
    evaluated: &MigrationEvaluation,
) -> Result<EditionBundle, MigrationError> {
    if evaluated
        .state
        .assets
        .as_ref()
        .and_then(|asset| asset.standard_ref.as_deref())
        != Some(bundle.digest())
    {
        return Err(fail(
            "EDITION_ENDPOINT_MISMATCH",
            "edition is not the exact canonically evaluated authority",
        ));
    }
    let layout = ControlLayout::standard();
    let layout_document: Value =
        crate::wire::parse_public_json(layout.authority_source()).map_err(invalid)?;
    let layout_schema = layout_document["$schema"].as_str().ok_or_else(|| {
        fail(
            "INVALID_UPGRADE_INPUT",
            "installed layout has no schema identity",
        )
    })?;
    let mut schemas = BTreeMap::from([
        ("control_layout", layout_schema.into()),
        ("control_layout_content", layout.digest()),
        (
            "installed_generation_locator",
            crate::control_manifest::GENERATION_MANIFEST_SCHEMA.into(),
        ),
        (
            "installed_selection_locator",
            crate::control_manifest::SELECTION_INDEX_SCHEMA.into(),
        ),
    ]);
    let config_path = layout.role_path(ControlRole::ProjectConfiguration);
    if let Some(bytes) = config_path.and_then(|path| evaluated.evaluated_source.bytes(path)) {
        let config: Value =
            crate::wire::parse_public_json(std::str::from_utf8(bytes).map_err(invalid)?)
                .map_err(invalid)?;
        if let Some(schema) = config["$schema"].as_str() {
            schemas.insert("configuration", schema.into());
        }
    }
    let application = evaluated
        .state
        .view
        .as_ref()
        .and_then(|view| view.application.clone());
    let profiles = application.as_ref().map_or(Value::Null, |a| {
        json!(a.declaration.required_dimension_manifest)
    });
    let catalog = installed_compatibility().map_err(invalid)?;
    let identity_algorithms = catalog
        .iter()
        .filter(|entry| schemas.values().any(|id| id == &entry.schema_id))
        .map(|entry| (entry.schema_id.clone(), entry.identity_algorithm.id.clone()))
        .collect();
    Ok(EditionBundle {
        pin: EditionPin::for_standard(bundle),
        rules: bundle
            .rules()
            .iter()
            .map(|rule| (rule.id().into(), rule.source_digest().into()))
            .collect(),
        schemas,
        profiles,
        supported_reader_manifest: content_digest(installed_compatibility_source().as_bytes()),
        identity_algorithms,
        application,
    })
}

fn compare_rules(from: &StandardBundle, to: &StandardBundle) -> Vec<RuleChange> {
    let before = from
        .rules()
        .iter()
        .map(|rule| (rule.id(), rule))
        .collect::<BTreeMap<_, _>>();
    let after = to
        .rules()
        .iter()
        .map(|rule| (rule.id(), rule))
        .collect::<BTreeMap<_, _>>();
    before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|id| {
            let original = before.get(id);
            let target = after.get(id);
            let old = original.map(|rule| rule.source_digest());
            let new = target.map(|rule| rule.source_digest());
            let old_implies = original.map_or(&[][..], |rule| rule.logic().implies());
            let new_implies = target.map_or(&[][..], |rule| rule.logic().implies());
            let old_conflicts = original.map_or(&[][..], |rule| rule.logic().conflicts_with());
            let new_conflicts = target.map_or(&[][..], |rule| rule.logic().conflicts_with());
            (old != new).then(|| RuleChange {
                id: id.into(),
                before: old.map(str::to_owned),
                after: new.map(str::to_owned),
                logic_changed: original
                    .zip(target)
                    .is_some_and(|(a, b)| a.logic() != b.logic()),
                implies_added: difference(new_implies, old_implies),
                implies_removed: difference(old_implies, new_implies),
                conflicts_added: difference(new_conflicts, old_conflicts),
                conflicts_removed: difference(old_conflicts, new_conflicts),
                change: match (old, new) {
                    (None, _) => "INTRODUCED",
                    (_, None) => "REMOVED_FROM_EDITION",
                    _ => "MODIFIED",
                },
            })
        })
        .collect()
}

fn difference(left: &[String], right: &[String]) -> Vec<String> {
    let excluded = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|value| !excluded.contains(value))
        .cloned()
        .collect()
}

fn invalid(error: impl std::fmt::Display) -> MigrationError {
    fail("INVALID_UPGRADE_INPUT", error.to_string())
}
