//! Registered edition compatibility and exact transformation controls.

use fortress_core::migration_governance::upgrade::{
    Compatibility, compatibility, explicit_native_configuration,
};
use fortress_core::project::ProjectConfiguration;

const V2: &str = "urn:fortress:schema:v2:project-configuration";
const V3: &str = "urn:fortress:schema:v3:project-configuration";
const V4: &str = "urn:fortress:schema:v4:project-configuration";

/// `T-AF-MIGRATION-GOVERNANCE-0001-R08-001`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R08
#[test]
fn upgrade_readers_do_not_imply_undeclared_migration_routes() {
    assert_eq!(
        compatibility(V3, V3).unwrap().status,
        Compatibility::DirectlyCompatible
    );
    assert_eq!(
        compatibility(V3, V4).unwrap().status,
        Compatibility::MigrationRequired
    );
    assert_eq!(
        compatibility(V4, V3).unwrap().status,
        Compatibility::Unsupported
    );
    assert_eq!(
        compatibility("urn:fortress:schema:v99:project-configuration", V4)
            .unwrap()
            .status,
        Compatibility::Unsupported
    );
    assert_eq!(
        compatibility(
            "urn:fortress:schema:v1:identity-migration",
            "urn:fortress:schema:v2:identity-migration"
        )
        .unwrap()
        .status,
        Compatibility::Unsupported
    );
    assert_eq!(
        compatibility(
            "urn:fortress:schema:v7:control-layout",
            "urn:fortress:schema:v8:control-layout"
        )
        .unwrap()
        .status,
        Compatibility::Incomparable
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R08-002`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R08
#[test]
fn native_config_upgrade_retains_authored_inputs_and_requires_exact_shape() {
    for (schema, version) in [(V2, 2), (V3, 3)] {
        let modules = if version == 3 {
            r#","logical_modules":[]"#
        } else {
            ""
        };
        let original = format!(
            r#"{{"$schema":"{schema}","schema_version":{version},"observation_exclusions":["vendor"]{modules}}}"#
        );
        let proposed = explicit_native_configuration(original.as_bytes()).unwrap();
        let after =
            ProjectConfiguration::from_json_str(std::str::from_utf8(&proposed).unwrap()).unwrap();
        assert_eq!(after.observation_exclusions(), ["vendor"]);
        assert!(after.assurance_profiles().is_empty());
        assert_eq!(
            after.governance().unwrap().selected_profiles()[0].id(),
            "GOV-FORTRESS-NATIVE"
        );
        assert_eq!(
            proposed,
            explicit_native_configuration(original.as_bytes()).unwrap()
        );
        let duplicate = original.replace(
            r#""observation_exclusions":"#,
            r#""observation_exclusions":[],"observation_exclusions":"#,
        );
        assert!(explicit_native_configuration(duplicate.as_bytes()).is_err());
        assert!(explicit_native_configuration(&proposed).is_err());
    }
}

fn installed_rule_documents() -> (String, Vec<(String, String)>) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = fortress_core::standard::installed_standard_manifest().to_owned();
    let document: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let rules = document["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| {
            let path = path.as_str().unwrap();
            (
                path.to_owned(),
                std::fs::read_to_string(root.join(path)).unwrap(),
            )
        })
        .collect();
    (manifest, rules)
}

fn parsed_standard(
    manifest: &str,
    rules: &[(String, String)],
) -> fortress_core::standard::StandardBundle {
    let documents = rules
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    fortress_core::standard::StandardBundle::from_json_documents(manifest, &documents).unwrap()
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R08-003`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R08
#[test]
fn bundle_digest_pins_rule_meaning_in_offline_upgrade() {
    use fortress_core::migration_governance::upgrade::EditionPin;
    let (manifest, rules) = installed_rule_documents();
    let pin = EditionPin::for_standard(&parsed_standard(&manifest, &rules));
    let sources = rules
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        pin.resolve(&manifest, &sources).unwrap().digest(),
        pin.release_digest
    );
    assert!(pin.resolve(&manifest, &sources[1..]).is_err());
    let (path, text) = sources[0];
    let mut changed = serde_json::from_str::<serde_json::Value>(text).unwrap();
    changed["statement"] = serde_json::json!("A meaning the pinned version never authored.");
    let change = changed.to_string();
    let mut candidates = sources.clone();
    candidates[0] = (path, &change);
    let error = pin.resolve(&manifest, &candidates).unwrap_err();
    assert_eq!(error.code, "EDITION_PIN_MISMATCH");
    candidates[0] = ("../unsafe.json", text);
    assert!(pin.resolve(&manifest, &candidates).is_err());
    assert!(
        pin.resolve(
            &manifest.replace("v1:standard-manifest", "v9:standard-manifest"),
            &sources
        )
        .is_err()
    );
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R08-004`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R08
#[test]
fn draft_upgrade_does_not_install_changed_rule_meaning_without_support() {
    use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
    use fortress_core::migration_adapter::{
        CanonicalMigrationAuthority, CanonicalMigrationEvaluator,
    };
    use fortress_core::migration_governance::upgrade::{EditionPin, UpgradeAdapter};
    use fortress_core::migration_governance::{MigrationEvaluator, MigrationOperation};
    use fortress_core::upgrade_load::{UpgradeOperations, preview_repository_upgrade};
    use std::fs;
    let fixture = super::adopted();
    let (manifest, mut rules) = installed_rule_documents();
    fs::write(fixture.root.join("standard_manifest.json"), &manifest).unwrap();
    for (path, bytes) in &rules {
        let file = fixture.root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    let evaluator = CanonicalMigrationEvaluator;
    let physical = evaluator.observe(&fixture.root).unwrap();
    let base = evaluator.evaluate(&physical).unwrap();
    let policy = super::trusted_policy(&base);
    let authority = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let original = EditionPin::for_standard(&parsed_standard(&manifest, &rules));
    let new_manifest = manifest.replace("1.0.0-draft.2", "1.0.0-rehearsal.3");
    let manifest_operation = MigrationOperation::ReplaceFile {
        path: "standard_manifest.json".into(),
        preimage: manifest.into_bytes(),
        postimage: new_manifest.as_bytes().to_vec(),
    };
    let first_target = EditionPin::for_standard(&parsed_standard(&new_manifest, &rules));
    let contract_path = "contract.json";
    let original_contract = physical.bytes(contract_path).unwrap();
    let contract: serde_json::Value = serde_json::from_slice(original_contract).unwrap();
    assert_eq!(
        contract["ecosystem"]["standard"]["edition"],
        original.edition
    );
    let original_contract_text = std::str::from_utf8(original_contract).unwrap();
    assert_eq!(original_contract_text.matches(&original.edition).count(), 1);
    let proposed_contract =
        original_contract_text.replace(&original.edition, &first_target.edition);
    fortress_core::contract_coherency::ModuleContract::from_json_str(&proposed_contract).unwrap();
    let contract_operation = MigrationOperation::ReplaceFile {
        path: contract_path.into(),
        preimage: original_contract.to_vec(),
        postimage: proposed_contract.into_bytes(),
    };
    let edition_selection = UpgradeAdapter {
        from_bundle: original.clone(),
        to_bundle: first_target.clone(),
        preview_admission: false,
    };
    assert!(
        preview_repository_upgrade(
            &fixture.root,
            &edition_selection,
            UpgradeOperations::Explicit(vec![manifest_operation.clone()]),
            &authority
        )
        .is_err()
    );
    let direct = preview_repository_upgrade(
        &fixture.root,
        &edition_selection,
        UpgradeOperations::Explicit(vec![manifest_operation.clone(), contract_operation.clone()]),
        &authority,
    )
    .unwrap();
    assert!(direct.plan.is_some());
    validate_proposal_schema(&direct);
    assert!(direct.rules.is_empty());
    assert_eq!(direct.target.pin, first_target);
    let (path, original_rule) = rules[0].clone();
    let mut change: serde_json::Value = serde_json::from_str(&original_rule).unwrap();
    change["statement"] =
        serde_json::json!("A distinct rule statement whose implication has not been established.");
    let change = change.to_string();
    rules[0].1.clone_from(&change);
    let changed = preview_repository_upgrade(
        &fixture.root,
        &UpgradeAdapter {
            from_bundle: original,
            to_bundle: EditionPin::for_standard(&parsed_standard(&new_manifest, &rules)),
            preview_admission: false,
        },
        UpgradeOperations::Explicit(vec![
            manifest_operation,
            contract_operation,
            MigrationOperation::ReplaceFile {
                path,
                preimage: original_rule.into_bytes(),
                postimage: change.into_bytes(),
            },
        ]),
        &authority,
    )
    .unwrap();
    assert!(changed.plan.is_none());
    validate_proposal_schema(&changed);
    assert_eq!(changed.rules.len(), 1);
    assert_eq!(changed.rules[0].change, "MODIFIED");
    assert!(
        changed
            .limitations
            .contains(&"CHANGED_RULE_MEANING_REQUIRES_QUALIFIED_EVALUATOR")
    );
    assert_eq!(evaluator.observe(&fixture.root).unwrap(), physical);
}

fn validate_proposal_schema(record: &fortress_core::migration_governance::upgrade::EditionUpgrade) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("engine/standard_registry/_data/schema_manifest.json")).unwrap(),
    )
    .unwrap();
    let mut options = jsonschema::draft202012::options();
    let mut edition_schema = None;
    for deployed in manifest["schemas"].as_array().unwrap() {
        let asset: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(deployed.as_str().unwrap())).unwrap())
                .unwrap();
        let id = asset["$id"].as_str().unwrap();
        if id == "urn:fortress:derived:v1:edition-upgrade" {
            edition_schema = Some(asset.clone());
        }
        options = options.with_resource(
            id,
            jsonschema::Resource::from_contents(asset.clone()).unwrap(),
        );
    }
    let schema = edition_schema.unwrap();
    let validator = options.build(&schema).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&record.to_canonical_bytes().unwrap()).unwrap();
    if let Err(error) = validator.validate(&payload) {
        panic!("edition upgrade does not match its registered schema: {error}");
    }
    let digest = payload["digest"].as_str().unwrap().to_owned();
    let mut body = payload;
    body["digest"] = serde_json::json!("");
    let jcs = serde_json_canonicalizer::to_vec(&body).unwrap();
    use sha2::Digest;
    assert_eq!(digest, format!("sha256:{:x}", sha2::Sha256::digest(jcs)));
}

/// `T-AF-MIGRATION-GOVERNANCE-0001-R08-005`
/// Fortress requirement: AF-MIGRATION-GOVERNANCE-0001-R08
#[test]
fn profile_upgrade_keeps_original_evidence_and_reports_missing_target_scope() {
    use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
    use fortress_core::migration_adapter::{
        CanonicalMigrationAuthority, CanonicalMigrationEvaluator,
    };
    use fortress_core::migration_governance::upgrade::UpgradeAdapter;
    use fortress_core::migration_governance::{MigrationEvaluator, MigrationOperation};
    use fortress_core::profile::installed_profile_reference;
    use fortress_core::upgrade_load::{
        UpgradeOperations, inspect_upgrade_base, preview_repository_upgrade,
    };
    let fixture = super::adopted();
    let evaluator = CanonicalMigrationEvaluator;
    let source = evaluator.observe(&fixture.root).unwrap();
    let original = evaluator.evaluate(&source).unwrap();
    let policy = super::trusted_policy(&original);
    let authority = CanonicalMigrationAuthority {
        policy: Some(&policy),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let pin = inspect_upgrade_base(&fixture.root).unwrap().edition;
    let adapter = UpgradeAdapter {
        from_bundle: pin.clone(),
        to_bundle: pin,
        preview_admission: true,
    };
    let path = "__fortress/.fsconfig";
    let bytes = source.bytes(path).unwrap();
    let mut config: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let profile = installed_profile_reference("ASSURE-SEMANTIC-EVALUABILITY", "1.0.0")
        .unwrap()
        .unwrap();
    config["assurance_profiles"] = serde_json::json!([profile]);
    let make_preview = |postimage| {
        preview_repository_upgrade(
            &fixture.root,
            &adapter,
            UpgradeOperations::Explicit(vec![MigrationOperation::ReplaceFile {
                path: path.into(),
                preimage: bytes.to_vec(),
                postimage,
            }]),
            &authority,
        )
    };
    let evaluated = make_preview(serde_json::to_vec(&config).unwrap()).unwrap();
    let original = evaluated.original.application.as_ref().unwrap();
    let target = evaluated.target.application.as_ref().unwrap();
    assert_ne!(
        original.declaration.binding.authority_ref,
        target.declaration.binding.authority_ref
    );
    assert!(
        !original
            .declaration
            .required_dimension_manifest
            .profiles
            .iter()
            .any(|reference| reference.id == profile.id)
    );
    assert!(
        target
            .declaration
            .required_dimension_manifest
            .profiles
            .iter()
            .any(|reference| reference.digest == profile.digest)
    );
    assert!(!evaluated.required_authorization.is_empty());
    assert!(evaluated.admission.is_some());
    config["assurance_profiles"][0]["digest"] =
        serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    assert!(make_preview(serde_json::to_vec(&config).unwrap()).is_err());
    assert_eq!(evaluator.observe(&fixture.root).unwrap(), source);
}
