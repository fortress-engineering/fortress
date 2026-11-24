//! End-to-end self-application evidence for the Snapshot Governance audit.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fortress_core::affected_analysis::{
    AFFECTED_ANALYSIS_VERSION, IncrementalCacheState, IncrementalProjectionCache,
    ProjectionCacheKey, ProjectionKind,
};
use fortress_core::audit::{
    AUDIT_RESULT_SCHEMA_VERSION, audit_repository, compile_repository_environmental_analysis,
    compile_repository_information_flow_analysis, compile_repository_psm,
    compile_repository_realized_bfg, compile_repository_semantic_analysis,
    compile_repository_semantic_conformance, compile_repository_source_artifact_model,
    compile_repository_state_effect_analysis, inspect_repository_modules,
    prepare_repository_projection_cache,
};
use fortress_core::environmental_semantics::canonicalize_environment_contract_json;
use fortress_core::evaluation::RuleExecutionState;
use fortress_core::program_semantics::ExecutableSymbol;
use fortress_core::semantic_analysis::canonicalize_function_contract_json;
use fortress_core::semantic_conformance::SemanticConformanceState;

static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(0);

struct TestRepository(PathBuf);

impl TestRepository {
    fn new(name: &str) -> Self {
        let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fortress-observation-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test repository must be created");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent must be created");
        }
        fs::write(path, contents).expect("test file must be written");
    }
}

fn minimal_contract(id: &str, name: &str, root: bool) -> String {
    let ecosystem = if root {
        ",\n  \"ecosystem\": {\n    \"repository_grammar\": 1,\n    \"standard\": {\n      \"id\": \"STD-FORTRESS-ENGINEERING\",\n      \"edition\": \"1.0.0-draft.2\"\n    }\n  }"
    } else {
        ""
    };
    format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v2:module-contract\",\n  \"schema_version\": 2,\n  \"id\": \"{id}\",\n  \"display_name\": \"{name}\"{ecosystem},\n  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n  \"constraints\": [],\n  \"guarantees\": [],\n  \"features\": [],\n  \"behavior\": []\n}}\n"
    )
}

fn semantic_contract(id: &str) -> String {
    format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v3:module-contract\",\n  \"schema_version\": 3,\n  \"id\": \"{id}\",\n  \"display_name\": \"{id}\",\n  \"provides\": [],\n  \"requires\": [],\n  \"relationships\": [],\n  \"constraints\": [],\n  \"guarantees\": [],\n  \"features\": [],\n  \"behavior\": [],\n  \"semantic_policy\": {{\n    \"default\": \"UNDECLARED\",\n    \"capabilities\": {{\n      \"allow\": [],\n      \"deny\": []\n    }},\n    \"effects\": {{\n      \"allow\": [],\n      \"deny\": [\n        \"filesystem.write\"\n      ]\n    }}\n  }}\n}}\n"
    )
}

fn assert_native_profile_has_no_filing_noise(repository: &Path) {
    let audit = audit_repository(repository).expect("native logical audit completes");
    for rule_id in [
        "REPO-DOCS-001",
        "REPO-MODULE-001",
        "TEST-BOUNDARY-001",
        "TEST-TRACEABILITY-001",
    ] {
        let execution = audit
            .rules()
            .iter()
            .find(|execution| execution.rule_id() == rule_id)
            .expect("Standard rule remains declared");
        assert!(!execution.applicable());
        assert_eq!(
            execution.applicability_reason(),
            Some("UNSELECTED_BY_GOVERNANCE_PROFILE")
        );
        assert!(
            audit
                .findings()
                .iter()
                .all(|finding| finding.rule_id() != rule_id)
        );
    }
}

/// `T-AUDIT-CACHE-SEMANTIC-PRODUCER-001`
/// Fortress classification: infrastructure
#[test]
fn audit_rejects_cache_entries_without_a_semantic_producer_binding() {
    let repository = TestRepository::new("audit-cache-producer");
    repository.write("src/lib.rs", "pub fn value() {}\n");
    let current = prepare_repository_projection_cache(repository.path(), ProjectionKind::Audit)
        .expect("current audit key");
    let legacy = format!("{AFFECTED_ANALYSIS_VERSION}+audit-v{AUDIT_RESULT_SCHEMA_VERSION}");
    let semantic_only = format!(
        "{legacy}+semantic-{}",
        fortress_core::semantic_analysis::SEMANTIC_ANALYSIS_VERSION
    );
    let storage = TestRepository::new("audit-cache-storage");
    let cache = IncrementalProjectionCache::new(storage.path(), "cache-producer-fixture")
        .expect("independent cache");
    for version in [&legacy, &semantic_only] {
        let prior = ProjectionCacheKey::new(
            ProjectionKind::Audit,
            "fortress-core/audit",
            version,
            current.key().dependencies().to_vec(),
        )
        .expect("prior audit key");
        cache.store(&prior, b"{}\n", 1).expect("retain prior audit");
        assert_eq!(
            cache.load(&prior).expect("load prior audit").state(),
            IncrementalCacheState::ReusableCurrent
        );
        assert_eq!(
            cache
                .load(current.key())
                .expect("load current audit")
                .state(),
            IncrementalCacheState::Stale
        );
    }
    let encoded = serde_json::to_value(current.key()).expect("serialize current key");
    let version = format!(
        "{semantic_only}+source-{}",
        fortress_core::source_architecture::SOURCE_ARCHITECTURE_SEMANTIC_VERSION
    );
    assert_eq!(encoded["generator_version"], version);
}

/// `T-LOGICAL-MODULE-INTEGRATION-001`
/// Fortress classification: infrastructure
#[test]
fn logical_contracts_and_native_paths_feed_one_semantic_ownership_relation() {
    let repository = TestRepository::new("logical-module");
    repository.write(
        "Cargo.toml",
        "[package]\nname='native'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    );
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "__fortress/.fsconfig",
        "{\n  \"$schema\": \"urn:fortress:schema:v3:project-configuration\",\n  \"schema_version\": 3,\n  \"observation_exclusions\": [\n    \".git\"\n  ],\n  \"logical_modules\": [\n    {\n      \"module\": \"AF-API-0001\",\n      \"contract\": \"_data/logical_modules/api/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/api\"\n        }\n      ]\n    },\n    {\n      \"module\": \"AF-CORE-0001\",\n      \"contract\": \"_data/logical_modules/core/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/core\"\n        }\n      ]\n    }\n  ]\n}\n",
    );
    repository.write(
        "_data/logical_modules/api/contract.json",
        &semantic_contract("AF-API-0001"),
    );
    repository.write(
        "_data/logical_modules/core/contract.json",
        &minimal_contract("AF-CORE-0001", "Core", false),
    );
    repository.write(
        "src/lib.rs",
        "pub mod api;\npub mod core;\npub mod utility;\n",
    );
    repository.write(
        "src/api/mod.rs",
        "pub fn submit() { std::fs::write(\"receipt.txt\", b\"ok\").unwrap(); }\n",
    );
    repository.write("src/core/mod.rs", "pub fn calculate() {}\n");
    repository.write("src/utility.rs", "pub fn utility() {}\n");

    let inspection = inspect_repository_modules(repository.path()).expect("Modules inspect");
    assert_eq!(
        inspection.modules().len(),
        3,
        "governance detail: {:?}",
        inspection.governance_detail()
    );
    assert_eq!(
        inspection
            .modules()
            .iter()
            .find(|module| module.module() == "AF-API-0001")
            .expect("API Module")
            .observed_sources(),
        1
    );
    assert_eq!(inspection.analysis_territories().len(), 1);
    assert_eq!(inspection.analysis_territories()[0].observed_sources(), 2);

    let psm = compile_repository_psm(repository.path()).expect("logical PSM compiles");
    let owners = psm
        .symbols()
        .iter()
        .map(ExecutableSymbol::fortress_module)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(owners.contains("AF-API-0001"));
    assert!(owners.contains("AF-CORE-0001"));
    assert!(
        owners
            .iter()
            .any(|owner| owner.starts_with("SRC-ANALYSIS-CARGO-"))
    );

    let source = compile_repository_source_artifact_model(repository.path())
        .expect("logical Source Artifact Model compiles");
    let document: serde_json::Value = serde_json::from_str(
        &source
            .to_canonical_json()
            .expect("Source Artifact Model serializes"),
    )
    .expect("Source Artifact Model parses");
    assert!(document["artifacts"].as_array().is_some_and(|artifacts| {
        artifacts
            .iter()
            .any(|artifact| artifact["module_id"] == "AF-API-0001")
            && artifacts
                .iter()
                .any(|artifact| artifact["module_id"] == "AF-CORE-0001")
    }));

    let conformance = compile_repository_semantic_conformance(repository.path())
        .expect("logical semantic conformance compiles");
    let api = conformance
        .model()
        .module("AF-API-0001")
        .expect("API semantic policy conclusion");
    assert_eq!(api.state(), SemanticConformanceState::SupportedViolation);
    assert!(api.observations().iter().any(|observation| {
        observation.operation() == "std::fs::write" && observation.policy_disposition().is_some()
    }));

    assert_native_profile_has_no_filing_noise(repository.path());
}

fn mixed_native_artifact_repository(conflicting_binding: bool) -> TestRepository {
    let repository = TestRepository::new("mixed-native-artifacts");
    let mut declarations = vec![serde_json::json!({
        "module": "AF-NATIVE-0001", "parent": "PF-FIXTURE",
        "contract": "_data/logical_modules/native/contract.json",
        "bindings": [
            {"kind":"file","path":"left/guard.go"},
            {"kind":"directory","path":"pytools"},
            {"kind":"file","path":"right/guard.go"}
        ]
    })];
    if conflicting_binding {
        declarations.push(serde_json::json!({
            "module":"AF-OTHER-0001", "parent":"PF-FIXTURE",
            "contract":"_data/logical_modules/other/contract.json",
            "bindings":[{"kind":"file","path":"left/guard.go"}]
        }));
        repository.write(
            "_data/logical_modules/other/contract.json",
            &minimal_contract("AF-OTHER-0001", "Other", false),
        );
    }
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "_data/logical_modules/native/contract.json",
        &minimal_contract("AF-NATIVE-0001", "Native", false),
    );
    repository.write(
        "__fortress/.fsconfig",
        &serde_json::to_string(&serde_json::json!({
            "$schema":"urn:fortress:schema:v3:project-configuration", "schema_version":3,
            "observation_exclusions":[".git"], "logical_modules": declarations
        }))
        .unwrap(),
    );
    repository.write(
        "left/guard.go",
        "package left\nfunc Allow() bool { return true }\n",
    );
    repository.write(
        "right/guard.go",
        "package right\nfunc Allow() bool { return false }\n",
    );
    repository.write("pytools/guard.py", "def allow():\n    return True\n");
    repository.write("outside/guard.py", "def allow():\n    return False\n");
    repository.write("scratch.rs", "pub fn scratch() {}\n");
    repository
}

/// `T-NATIVE-ARTIFACT-BOUND-OWNERSHIP-001`
/// Fortress classification: infrastructure
#[test]
fn logical_go_and_python_artifacts_keep_exact_paths_and_unsupported_profiles() {
    use fortress_core::source_architecture::{
        ArchetypeResolution, SourceArtifactOwnershipAuthority,
    };
    use sha2::{Digest, Sha256};

    let repository = mixed_native_artifact_repository(false);
    let inspection = inspect_repository_modules(repository.path()).expect("inspect declarations");
    let owner = inspection
        .modules()
        .iter()
        .find(|module| module.module() == "AF-NATIVE-0001")
        .unwrap_or_else(|| {
            panic!(
                "declared owner unavailable: {:?}",
                inspection.governance_detail()
            )
        });
    assert_eq!(owner.observed_sources(), 3);
    assert!(inspection.ownership_diagnostics().is_empty());
    let model = compile_repository_source_artifact_model(repository.path())
        .expect("compile source artifacts");
    assert_eq!(model.artifacts().len(), 3);
    let json: serde_json::Value =
        serde_json::from_str(&model.to_canonical_json().unwrap()).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    for (path, language) in [
        ("left/guard.go", "go"),
        ("right/guard.go", "go"),
        ("pytools/guard.py", "python"),
    ] {
        let artifact = model
            .artifacts()
            .iter()
            .find(|artifact| artifact.path() == path)
            .expect("bound artifact");
        assert_eq!(artifact.module_id(), "AF-NATIVE-0001");
        assert_eq!(
            artifact.ownership_authority(),
            SourceArtifactOwnershipAuthority::DeclaredModule
        );
        assert!(
            ids.insert(artifact.id()),
            "exact native paths must disambiguate same-name artifacts"
        );
        assert_eq!(
            artifact.content_digest(),
            format!(
                "sha256:{:x}",
                Sha256::digest(fs::read(repository.path().join(path)).unwrap())
            )
        );
        assert_eq!(
            artifact.profile().status(),
            ArchetypeResolution::ProfileNotRegistered
        );
        let row = json["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(row["language"], language);
        assert_eq!(row["module_relative_path"], path);
        assert_eq!(row["structural_observations"], serde_json::json!([]));
        assert_eq!(row["verification_relationships"], serde_json::json!([]));
    }
    let audit = audit_repository(repository.path()).expect("audit completes");
    let audit_json: serde_json::Value =
        serde_json::from_str(&audit.to_json_pretty().unwrap()).unwrap();
    assert_eq!(audit_json["governance"]["declared_source_owners"], 3);
    assert_eq!(audit_json["governance"]["analysis_source_owners"], 0);
    assert_eq!(audit_json["governance"]["project_authority"], "DECLARED");
}

/// `T-NATIVE-ARTIFACT-AMBIGUITY-001`
/// Fortress classification: infrastructure
#[test]
fn conflicting_native_file_claims_have_no_artifact_owner() {
    let repository = mixed_native_artifact_repository(true);
    let inspection =
        inspect_repository_modules(repository.path()).expect("inspect conflicting declarations");
    assert_eq!(inspection.project_authority_state(), "INVALID");
    assert!(
        inspection
            .governance_detail()
            .is_some_and(|detail| detail.contains("left/guard.go"))
    );
    let model = compile_repository_source_artifact_model(repository.path())
        .expect("incomplete source model remains inspectable");
    assert!(model.artifacts().is_empty());
}

/// `T-NATIVE-ARTIFACT-AFFECTED-001`
/// Fortress classification: infrastructure
#[test]
fn a_go_edit_invalidates_the_artifact_projection_without_entering_rust_inputs() {
    let repository = mixed_native_artifact_repository(false);
    let key = |kind| {
        prepare_repository_projection_cache(repository.path(), kind)
            .unwrap()
            .key()
            .digest()
            .to_owned()
    };
    let artifact_key = key(ProjectionKind::SourceArtifacts);
    let psm_key = key(ProjectionKind::Psm);
    let affected =
        fortress_core::audit::compile_repository_affected_snapshot(repository.path()).unwrap();
    let dependencies = |id| {
        affected
            .units()
            .iter()
            .find(|unit| unit.id() == id)
            .unwrap()
            .dependencies()
    };
    assert!(
        dependencies("projection:source-artifacts").contains(&"source:left/guard.go".to_owned())
    );
    assert!(!dependencies("projection:psm").contains(&"source:left/guard.go".to_owned()));
    assert!(
        dependencies("source:left/guard.go").contains(&"authority:__fortress/.fsconfig".to_owned())
    );
    repository.write(
        "left/guard.go",
        "package left\nfunc Allow() bool { return false }\n",
    );
    assert_ne!(key(ProjectionKind::SourceArtifacts), artifact_key);
    assert_eq!(key(ProjectionKind::Psm), psm_key);
}

/// `T-NATIVE-PHYSICAL-OWNERSHIP-001`
/// Fortress classification: infrastructure
#[test]
fn physical_native_code_ownership_is_independent_of_responsibility_docs() {
    let repository = TestRepository::new("physical-native-ownership");
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "native/contract.json",
        &minimal_contract("AF-NATIVE-0001", "Native", false),
    );
    repository.write("native/_code/check.go", "package native\n");
    repository.write("native/_code/check.py", "enabled = True\n");
    repository.write("outside/unowned.go", "package outside\n");
    repository.write("native/_data/unowned.py", "ignored = True\n");
    let undeclared = inspect_repository_modules(repository.path()).unwrap();
    assert_eq!(undeclared.project_authority_state(), "MISSING");
    assert!(
        undeclared
            .modules()
            .iter()
            .all(|module| module.observed_sources() == 0)
    );
    repository.write(
        "__fortress/.fsconfig",
        r#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":[],"logical_modules":[]}"#,
    );
    let inspection = inspect_repository_modules(repository.path()).unwrap();
    assert_eq!(inspection.project_authority_state(), "DECLARED");
    let module = inspection
        .modules()
        .iter()
        .find(|module| module.module() == "AF-NATIVE-0001")
        .unwrap();
    assert_eq!(module.observed_sources(), 2);
    let inspect = || compile_repository_source_artifact_model(repository.path()).unwrap();
    let expected = ["native/_code/check.go", "native/_code/check.py"];
    let ownership = |model: &fortress_core::source_architecture::SourceArtifactModel| {
        let mut ids = Vec::new();
        for path in expected {
            let artifact = model
                .artifacts()
                .iter()
                .find(|row| row.path() == path)
                .unwrap();
            assert_eq!(artifact.module_id(), "AF-NATIVE-0001");
            ids.push(artifact.id().to_owned());
        }
        assert_eq!(model.artifacts().len(), expected.len());
        ids
    };
    let undocumented = ownership(&inspect());
    repository.write(
        "native/_docs/code_docs.md",
        "# Code\n\n## Files\n\n### `check.go`\n\nDeclares the native Go fixture package.\n\n### `check.py`\n\nDefines the flag used by the native Python fixture.\n",
    );
    assert_eq!(ownership(&inspect()), undocumented);
    let affected =
        fortress_core::audit::compile_repository_affected_snapshot(repository.path()).unwrap();
    for path in expected {
        let source = affected
            .units()
            .iter()
            .find(|unit| unit.id() == format!("source:{path}"))
            .unwrap();
        assert!(
            source
                .dependencies()
                .contains(&"authority:native/contract.json".to_owned())
        );
        assert!(
            source
                .dependencies()
                .contains(&"authority:__fortress/.fsconfig".to_owned())
        );
    }
}

fn write_nested_native_bindings(repository: &TestRepository, exact: &str) {
    let modules = [
        ("AF-BASE-0001", "PF-FIXTURE", "base", "directory", "src"),
        (
            "AF-DETAIL-0001",
            "AF-BASE-0001",
            "detail",
            "directory",
            "src/core",
        ),
        ("AF-EXACT-0001", "AF-DETAIL-0001", "exact", "file", exact),
    ];
    let declarations = modules.map(|(id, parent, directory, kind, path)| {
        let contract = format!("_data/logical_modules/{directory}/contract.json");
        repository.write(&contract, &minimal_contract(id, directory, false));
        serde_json::json!({
            "module":id,"parent":parent,"contract":contract,
            "bindings":[{"kind":kind,"path":path}]
        })
    });
    let configuration = serde_json::json!({
        "$schema":"urn:fortress:schema:v3:project-configuration",
        "schema_version":3,"observation_exclusions":[".git"],"logical_modules":declarations
    });
    repository.write("__fortress/.fsconfig", &configuration.to_string());
}

/// `T-NATIVE-OWNERSHIP-EXACT-PRECEDENCE-001`
/// Fortress classification: infrastructure
#[test]
fn native_owner_precedence_and_module_identity_survive_explicit_relocation() {
    for (suffix, bytes) in [("go", "package fixture\n"), ("py", "value = 1\n")] {
        let repository = TestRepository::new("nested-native-ownership");
        repository.write(
            "contract.json",
            &minimal_contract("PF-FIXTURE", "Fixture", true),
        );
        let general = format!("src/general.{suffix}");
        let nested = format!("src/core/nested.{suffix}");
        let exact = format!("src/core/exact.{suffix}");
        let moved = format!("src/core/relocated.{suffix}");
        let unowned = format!("outside/unowned.{suffix}");
        for path in [&general, &nested, &exact, &unowned] {
            repository.write(path, bytes);
        }
        write_nested_native_bindings(&repository, &exact);
        let original = compile_repository_source_artifact_model(repository.path()).unwrap();
        let original_exact = original
            .artifacts()
            .iter()
            .find(|row| row.path() == exact)
            .unwrap();
        fs::rename(
            repository.path().join(&exact),
            repository.path().join(&moved),
        )
        .unwrap();
        write_nested_native_bindings(&repository, &moved);
        let relocated = compile_repository_source_artifact_model(repository.path()).unwrap();
        let owners = |report: &fortress_core::source_architecture::SourceArtifactModel| {
            report
                .artifacts()
                .iter()
                .map(|artifact| (artifact.path().to_owned(), artifact.module_id().to_owned()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        for (candidate, observed) in [(&exact, &original), (&moved, &relocated)] {
            let expected = [
                (general.clone(), "AF-BASE-0001".to_owned()),
                (nested.clone(), "AF-DETAIL-0001".to_owned()),
                (candidate.clone(), "AF-EXACT-0001".to_owned()),
            ]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(owners(observed), expected);
        }
        let relocated_exact = relocated
            .artifacts()
            .iter()
            .find(|row| row.path() == moved)
            .unwrap();
        assert_ne!(original_exact.id(), relocated_exact.id());
        assert_eq!(
            original_exact.content_digest(),
            relocated_exact.content_digest()
        );
    }
}

/// `T-DISTRIBUTED-CONTRACT-LOGICAL-LOADERS-001`
/// Fortress classification: infrastructure
#[test]
fn all_distributed_contract_loaders_accept_one_logical_module_territory() {
    let repository = TestRepository::new("logical-distributed-contracts");
    repository.write(
        "Cargo.toml",
        "[package]\nname='native'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='native/lib.rs'\n",
    );
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "__fortress/.fsconfig",
        "{\n  \"$schema\": \"urn:fortress:schema:v3:project-configuration\",\n  \"schema_version\": 3,\n  \"observation_exclusions\": [\n    \".git\"\n  ],\n  \"logical_modules\": [\n    {\n      \"module\": \"AF-NATIVE-0001\",\n      \"contract\": \"_data/logical_modules/native/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"native\"\n        }\n      ]\n    }\n  ]\n}\n",
    );
    repository.write(
        "_data/logical_modules/native/contract.json",
        &minimal_contract("AF-NATIVE-0001", "Native", false),
    );
    repository.write(
        "native/lib.rs",
        "pub fn governed(value: bool) -> bool { !value }\n",
    );

    let psm = compile_repository_psm(repository.path()).expect("logical PSM compiles");
    let symbol = psm
        .symbols()
        .iter()
        .find(|symbol| {
            symbol.fortress_module() == "AF-NATIVE-0001"
                && symbol.qualified_name().ends_with("::governed")
        })
        .expect("logical Module symbol exists")
        .id();
    let authored = format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v4:function-contracts\",\n  \"schema_version\": 4,\n  \"functions\": [\n    {{\n      \"symbol\": \"{symbol}\",\n      \"requires\": [],\n      \"ensures\": [],\n      \"state_requires\": [],\n      \"state_ensures\": [],\n      \"effects\": null\n    }}\n  ]\n}}\n"
    );
    let function_contract =
        canonicalize_function_contract_json("native/data/function_contracts.json", &authored)
            .expect("Function Contract canonicalizes");
    repository.write("native/data/function_contracts.json", &function_contract);
    repository.write(
        "native/data/state_contracts.json",
        "{\n  \"$schema\": \"urn:fortress:schema:v1:state-contracts\",\n  \"schema_version\": 1,\n  \"types\": []\n}\n",
    );
    let environment_contract = format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v1:environment-contracts\",\n  \"schema_version\": 1,\n  \"operations\": [\n    {{\n      \"id\": \"EX-NATIVE-READ\",\n      \"actor\": \"ENV-NATIVE\",\n      \"boundary\": \"{symbol}\",\n      \"retry_policy\": \"NEVER\",\n      \"retryable_outcomes\": [],\n      \"idempotency\": \"IDEMPOTENT\",\n      \"idempotency_key_parameter\": null,\n      \"delivery\": \"AT_MOST_ONCE\",\n      \"interruption_sensitive\": false,\n      \"atomicity\": \"UNKNOWN\",\n      \"effect_steps\": [],\n      \"recovery\": null,\n      \"outcomes\": [\n        {{\n          \"id\": \"EX-NATIVE-READ-SUCCESS\",\n          \"completion\": \"COMPLETED\",\n          \"response\": \"ONE_RESPONSE\",\n          \"timing\": \"UNBOUNDED\",\n          \"result\": \"SUCCESS\",\n          \"domain\": null,\n          \"information_flow\": [],\n          \"state\": null,\n          \"forbidden_effects\": [],\n          \"resource\": null,\n          \"handling\": null\n        }}\n      ]\n    }}\n  ]\n}}\n"
    );
    repository.write(
        "native/data/environment_contracts.json",
        &canonicalize_environment_contract_json(
            "native/data/environment_contracts.json",
            &environment_contract,
        )
        .expect("Environment Contract canonicalizes"),
    );
    repository.write(
        "native/data/behavior_realization_contracts.json",
        "{\n  \"$schema\": \"urn:fortress:schema:v1:behavior-realization-contracts\",\n  \"schema_version\": 1,\n  \"features\": []\n}\n",
    );

    let ccg = fortress_core::audit::compile_repository_ccg(repository.path())
        .expect("logical CCG compiles");
    for path in [
        "native/data/behavior_realization_contracts.json",
        "native/data/environment_contracts.json",
        "native/data/function_contracts.json",
        "native/data/state_contracts.json",
    ] {
        assert_eq!(
            ccg.governance_territories()
                .resolve(path)
                .expect("distributed contract resolves"),
            "AF-NATIVE-0001"
        );
    }
    let semantic = compile_repository_semantic_analysis(repository.path())
        .expect("logical Function Contract loads");
    assert_eq!(semantic.model().coverage().function_contracts(), 1);
    compile_repository_state_effect_analysis(repository.path())
        .expect("logical State Contract loads");
    compile_repository_information_flow_analysis(repository.path())
        .expect("logical Function Contract reaches Information Flow");
    compile_repository_environmental_analysis(repository.path())
        .expect("logical Environment Contract loads");
    compile_repository_realized_bfg(repository.path())
        .expect("logical Behavior-Realization Contract loads");
}

/// `T-DISTRIBUTED-CONTRACT-TARGET-OWNERSHIP-001`
/// Fortress classification: infrastructure
#[test]
fn logical_function_contract_rejects_a_foreign_module_target() {
    let repository = TestRepository::new("logical-contract-foreign-target");
    repository.write(
        "Cargo.toml",
        "[package]\nname='native'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    );
    repository.write(
        "contract.json",
        &minimal_contract("PF-FIXTURE", "Fixture", true),
    );
    repository.write(
        "__fortress/.fsconfig",
        "{\n  \"$schema\": \"urn:fortress:schema:v3:project-configuration\",\n  \"schema_version\": 3,\n  \"observation_exclusions\": [\n    \".git\"\n  ],\n  \"logical_modules\": [\n    {\n      \"module\": \"AF-ALPHA-0001\",\n      \"contract\": \"_data/logical_modules/alpha/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/alpha\"\n        }\n      ]\n    },\n    {\n      \"module\": \"AF-BETA-0001\",\n      \"contract\": \"_data/logical_modules/beta/contract.json\",\n      \"parent\": \"PF-FIXTURE\",\n      \"bindings\": [\n        {\n          \"kind\": \"directory\",\n          \"path\": \"src/beta\"\n        }\n      ]\n    }\n  ]\n}\n",
    );
    repository.write(
        "_data/logical_modules/alpha/contract.json",
        &minimal_contract("AF-ALPHA-0001", "Alpha", false),
    );
    repository.write(
        "_data/logical_modules/beta/contract.json",
        &minimal_contract("AF-BETA-0001", "Beta", false),
    );
    repository.write("src/lib.rs", "pub mod alpha;\npub mod beta;\n");
    repository.write("src/alpha/mod.rs", "pub fn alpha() {}\n");
    repository.write("src/beta/mod.rs", "pub fn beta() {}\n");
    let psm = compile_repository_psm(repository.path()).expect("logical PSM compiles");
    let beta = psm
        .symbols()
        .iter()
        .find(|symbol| {
            symbol.fortress_module() == "AF-BETA-0001"
                && symbol.qualified_name().ends_with("::beta")
        })
        .expect("beta symbol exists")
        .id();
    let authored = format!(
        "{{\n  \"$schema\": \"urn:fortress:schema:v4:function-contracts\",\n  \"schema_version\": 4,\n  \"functions\": [\n    {{\n      \"symbol\": \"{beta}\",\n      \"requires\": [],\n      \"ensures\": [],\n      \"state_requires\": [],\n      \"state_ensures\": [],\n      \"effects\": null\n    }}\n  ]\n}}\n"
    );
    repository.write(
        "src/alpha/data/function_contracts.json",
        &canonicalize_function_contract_json("src/alpha/data/function_contracts.json", &authored)
            .expect("Function Contract canonicalizes"),
    );
    let error = compile_repository_semantic_analysis(repository.path())
        .expect_err("cross-Module target must fail")
        .to_string();
    assert!(error.contains("in `AF-ALPHA-0001`"));
    assert!(error.contains("owned by `AF-BETA-0001`"));
}

impl Drop for TestRepository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("test repository must be removed");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R08-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R08
#[test]
fn fortress_self_audit_distinguishes_evaluated_and_nonapplicable_rules() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    assert!(result.is_success());
    assert_eq!(result.rules().len(), 23);
    assert_eq!(result.summary().rules_evaluated(), 22);
    assert_eq!(result.summary().passed(), 22);
    assert_eq!(result.summary().not_applicable(), 1);
    let nonapplicable = result
        .rules()
        .iter()
        .filter(|rule| !rule.applicable())
        .collect::<Vec<_>>();
    assert_eq!(nonapplicable.len(), 1);
    assert_eq!(nonapplicable[0].rule_id(), "PROGRAM-INFOFLOW-001");
    assert_eq!(nonapplicable[0].state(), RuleExecutionState::NotApplicable);
    assert_eq!(
        nonapplicable[0].applicability_reason(),
        Some("NO_SELECTED_DECLARED_FLOW_SINKS")
    );
    assert_eq!(result.summary().failed(), 0);
    assert_eq!(result.summary().unsupported(), 0);
    assert!(result.findings().is_empty());
    assert!(
        result
            .unsupported_analysis()
            .contains(&"capability_to_symbol_realization".to_owned())
    );
    assert_eq!(result.is_success(), result.findings().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R14-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R14
#[test]
fn filesystem_boundary_success_and_failure_scenarios_are_current() {
    let evaluation = compile_repository_environmental_analysis(repository_root())
        .expect("self environmental analysis compiles");
    let ids = evaluation
        .model()
        .failure_test_obligations()
        .iter()
        .map(|obligation| {
            serde_json::to_value(obligation).expect("obligation serializes")["id"]
                .as_str()
                .expect("obligation ID")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["SCN-5A016EDD618E626E", "SCN-E881A0DBF2A76CE4"]);
    assert!(evaluation.environment_findings().is_empty());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R13-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R13
#[test]
fn self_audit_reuses_one_applicable_intended_behavior_evaluation() {
    let result = audit_repository(repository_root()).expect("Fortress self-audit completes");
    let executions = result
        .rules()
        .iter()
        .filter(|rule| rule.rule_id() == "BEHAVIOR-FLOW-001")
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 1);
    assert!(executions[0].applicable());
    assert_eq!(executions[0].finding_count(), 0);
    assert!(executions[0].detail().contains("1 modeled Feature"));
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R08-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R08
#[test]
fn ungoverned_cargo_repository_reaches_semantic_observation_without_admission_files() {
    let repository = TestRepository::new("ungoverned-cargo");
    repository.write(
        "Cargo.toml",
        "[package]\nname='ordinary'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/lib.rs'\n",
    );
    repository.write(
        "src/lib.rs",
        "pub mod runtime;\npub fn run(value: bool) -> bool { runtime::flip(value) }\n",
    );
    repository.write(
        "src/runtime/mod.rs",
        "pub fn flip(value: bool) -> bool { !value }\n",
    );
    repository.write("tests/plain.rs", "#[test]\nfn ordinary_test() {}\n");

    let psm =
        compile_repository_psm(repository.path()).expect("PSM observes ordinary Cargo layout");
    assert_eq!(psm.project_id(), None);
    let psm_json: serde_json::Value =
        serde_json::from_str(&psm.to_canonical_json().expect("PSM serializes"))
            .expect("PSM JSON parses");
    assert_eq!(psm_json["coverage"]["source_files"], 3);
    assert_eq!(psm_json["coverage"]["test_only_symbols"], 1);
    assert!(
        psm.symbols()
            .iter()
            .any(|symbol| symbol.qualified_name().ends_with("::flip"))
    );
    assert!(
        psm.symbols()
            .iter()
            .all(|symbol| symbol.fortress_module().starts_with("SRC-ANALYSIS-CARGO-"))
    );

    let source = compile_repository_source_artifact_model(repository.path())
        .expect("Source Architecture observes ordinary Cargo layout");
    let source_json: serde_json::Value =
        serde_json::from_str(&source.to_canonical_json().expect("source model serializes"))
            .expect("source model JSON parses");
    assert!(source_json["project_id"].is_null());
    assert_eq!(
        source_json["artifacts"]
            .as_array()
            .expect("artifacts")
            .len(),
        3
    );

    let state = compile_repository_state_effect_analysis(repository.path())
        .expect("State/Effect analysis consumes the observation-only PSM");
    assert!(state.model().coverage().functions() >= 2);

    let audit = audit_repository(repository.path())
        .expect("audit reports missing governance after semantic observation");
    assert!(!audit.is_success());
    let audit_json: serde_json::Value =
        serde_json::from_str(&audit.to_json_pretty().expect("audit serializes"))
            .expect("audit JSON parses");
    assert_eq!(audit_json["outcome"], "MISSING");
    assert_eq!(audit_json["governance"]["project_authority"], "ABSENT");
    assert_eq!(
        audit_json["governance"]["standard_authority"],
        "INSTALLED_UNBOUND"
    );
    assert_eq!(audit_json["governance"]["tests_missing_stable_id"], 1);
    assert!(
        audit_json["observation"]["psm_symbols"]
            .as_u64()
            .is_some_and(|count| count >= 2)
    );
}
