//! Seeded whole-artifact comparisons through the resident and cold production ports.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
};
use fortress_core::certification::{EvidenceGraph, RustSuiteExecution};
use fortress_core::contract_coherency::ModuleContract;
use fortress_core::control_manifest::AssessmentGenerationManifest;
use fortress_core::finding_governance::FindingGovernanceDocument;
use fortress_core::information_flow::{
    InformationFlowPolicySource, canonicalize_information_flow_policy_json,
    load_information_flow_policy,
};
use fortress_core::observation::{ChangeOperation, SourceView};
use fortress_core::project::{ProjectConfiguration, SourcePathBindingKind};
use fortress_core::runtime_storage::StoragePolicy;
use fortress_core::semantic_analysis::{
    FunctionContractError, FunctionContractSource, canonicalize_function_contract_json,
    load_function_contracts,
};
use fortress_core::session::{
    Generation, Session, SessionDisposition, SessionErrorKind, SessionOptions, SessionUpdate,
    SessionWork, SourceDelta,
};
use fortress_core::state_effect_analysis::OperationSummaryCatalog;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REGISTRY: &str = include_str!("../_data/resident_mutations_v1.json");
const BASELINE_GENERATION: &str =
    "b1badab7905a8134b57cd9ec931a5d8c95f3c6028f94d680f35726cca0ac3217";
const PROFILE_PATH: &str = "engine/standard_registry/_data/cert_full_snapshot_v1.json";
const ROOT_ID: &str = "PF-RESIDENT-CORPUS";
const CODE_MODULE_ID: &str = "AF-RESIDENT-CODE-0001";
const CODE_CONTRACT_PATH: &str = "_data/logical_modules/code/contract.json";
const REQUIREMENT: &str = "AF-RESIDENT-CORPUS-0001-R01";
const MAX_RETAINED_REPORT_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIXTURE_CLAIM_ATTEMPTS: usize = 64;
static NEXT: AtomicU64 = AtomicU64::new(0);

const ARTIFACT_PATHS: [&str; 14] = [
    "_info/behavioral_flow_graph.json",
    "_info/certification.json",
    "_info/component_resolution_index.json",
    "_info/contract_coherency_graph.json",
    "_info/environmental_analysis.json",
    "_info/evidence_graph.json",
    "_info/information_flow_analysis.json",
    "_info/program_semantic_model.json",
    "_info/realized_behavioral_flow_graph.json",
    "_info/semantic_analysis.json",
    "_info/semantic_conformance.json",
    "_info/source_artifact_model.json",
    "_info/state_effect_analysis.json",
    "_info/verified_behavioral_flow_graph.json",
];

const LIBRARY: &str = concat!(
    "pub mod leaf;\npub mod movable;\npub fn stable() -> u32 { 9 }\npub fn changed() -> u32 { 1 }\npub fn caller() -> u32 { leaf::provider() }\npub fn unresolved() -> u32 { future() }\npub fn left() -> u32 { 1 }\npub fn right() -> u32 { left() }\npub struct State { pub value: u32 }\nimpl State { pub fn read(&self) -> u32 { self.value } pub fn write(&mut self, value: u32) { self.value = value; } }\n",
    "/// `T-AF-RESIDENT-CORPUS-0001-R01-001`\n",
    "/// Fortress requirement: AF-RESIDENT-CORPUS-0001-R01\n",
    "#[test]\nfn observed_fixture_requirement_has_a_real_assertion() { assert_eq!(stable(), 9); }\n",
);
const LEAF: &str = "pub fn provider() -> u32 { 1 }\npub fn effect() { let _ = std::fs::read(\"fixture\"); }\npub fn stable() -> bool { true }\n";
const MOVABLE: &str = "pub fn located() -> u32 { 3 }\n";
const MANIFEST: &str = "[package]\nname = \"resident_corpus\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[features]\ndefault = []\nmode = []\n";

#[derive(Deserialize)]
struct Registry {
    generator: String,
    seed: String,
    successful_comparisons: usize,
    classes: Vec<MutationClass>,
    cases: Vec<MutationCase>,
}

#[derive(Deserialize)]
struct MutationClass {
    id: String,
    count: usize,
}

#[derive(Deserialize)]
struct MutationCase {
    id: String,
    class: String,
    ordinal: usize,
    seed: String,
    input_role: String,
}

struct ComparedWarm {
    generation: std::sync::Arc<Generation>,
    work: SessionWork,
    disposition: SessionDisposition,
    reasons: Vec<String>,
    availability_changes: Vec<String>,
}

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    storage: PathBuf,
}

fn fixture_candidate(parent: &Path, process_id: u32, ordinal: u64) -> PathBuf {
    parent.join(format!("fortress-resident-corpus-{process_id}-{ordinal}"))
}

fn claim_fixture_base(parent: &Path, process_id: u32, next: &AtomicU64) -> io::Result<PathBuf> {
    for _ in 0..MAX_FIXTURE_CLAIM_ATTEMPTS {
        let candidate = fixture_candidate(parent, process_id, next.fetch_add(1, Ordering::Relaxed));
        // create_dir claims one new incarnation atomically. Existing files,
        // directories and links are collisions; never inspect or reuse them.
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "bounded fresh fixture directory claims exhausted",
    ))
}

fn create_retained_report(path: &Path) -> io::Result<File> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "retained report has no parent")
    })?;
    fs::create_dir_all(parent)?;
    OpenOptions::new().write(true).create_new(true).open(path)
}

impl Fixture {
    fn new() -> Self {
        let base = claim_fixture_base(&std::env::temp_dir(), std::process::id(), &NEXT)
            .expect("fresh native fixture incarnation");
        let root = base.join("repository");
        let storage = base.join("storage");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(&storage).expect("external storage directory");
        write(&root, "Cargo.toml", MANIFEST.as_bytes());
        write(&root, "src/lib.rs", LIBRARY.as_bytes());
        write(&root, "src/leaf.rs", LEAF.as_bytes());
        write(&root, "src/movable.rs", MOVABLE.as_bytes());
        let proposal = discover_repository_bootstrap(
            &root,
            &BootstrapDiscoveryOptions::new(Some(ROOT_ID.into()), Some("Resident Corpus".into())),
        )
        .expect("native fixture discovery");
        apply_repository_bootstrap(&root, &proposal, false).expect("native fixture authority");
        let mut contract = module_contract_value(&fs::read(root.join("contract.json")).unwrap());
        contract["features"] = json!([{
            "id": "AF-RESIDENT-CORPUS-0001", "version": "0.1.0", "requirements": [{
                "id": REQUIREMENT, "statement": "The fixture requires genuine current execution evidence.",
                "tests": ["T-AF-RESIDENT-CORPUS-0001-R01-001"]
            }]
        }]);
        write(&root, "contract.json", &module_contract_bytes(&contract));
        // Native Cargo analysis territories are observed ownership, not authored
        // Module authority. Declare the existing source directory explicitly so
        // distributed function contracts have a real shared declaring owner.
        let mut code_contract = contract.clone();
        code_contract["id"] = json!(CODE_MODULE_ID);
        code_contract["display_name"] = json!("Resident Code");
        code_contract.as_object_mut().unwrap().remove("ecosystem");
        code_contract["features"] = json!([]);
        write(
            &root,
            CODE_CONTRACT_PATH,
            &module_contract_bytes(&code_contract),
        );
        let mut configuration: Value =
            serde_json::from_slice(&fs::read(root.join("__fortress/.fsconfig")).unwrap()).unwrap();
        configuration["logical_modules"] = json!([{
            "module": CODE_MODULE_ID, "contract": CODE_CONTRACT_PATH, "parent": ROOT_ID,
            "bindings": [{"kind":"directory", "path":"src"}]
        }]);
        let configuration_bytes = project_configuration_bytes(&configuration);
        write(&root, "__fortress/.fsconfig", &configuration_bytes);
        // Copy the actual installed mandatory full profile, with every flag intact.
        write(
            &root,
            PROFILE_PATH,
            &fs::read(repository().join(PROFILE_PATH)).expect("tracked full profile"),
        );
        Self {
            base,
            root,
            storage,
        }
    }

    fn open(&self, suite: &RustSuiteExecution) -> Session {
        Session::open(
            &self.root,
            &self.storage,
            SessionOptions {
                storage_policy: StoragePolicy {
                    reserve_bytes: 0,
                    retain_shared_compiler: false,
                    ..StoragePolicy::default()
                },
                suite_execution: Some(suite.clone()),
                ..SessionOptions::default()
            },
        )
        .expect("governed session opens")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The exact owned fixture goes away. Qualification records and completed
        // runtime journals deliberately survive outside source and disposable work.
        if self.root.starts_with(&self.base) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn repository() -> PathBuf {
    // This test belongs to engine/_data/Cargo.toml; accepted control authority
    // and the tracked mandatory profile belong to the repository two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository above engine manifest")
        .to_path_buf()
}

fn write(root: &Path, path: &str, bytes: &[u8]) {
    let destination = root.join(path);
    fs::create_dir_all(destination.parent().expect("parent")).expect("owned parent");
    fs::write(destination, bytes).expect("fixture bytes");
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).expect("fixture JSON")
}

fn project_configuration_bytes(value: &Value) -> Vec<u8> {
    let bytes = json_bytes(value);
    ProjectConfiguration::from_json_str(std::str::from_utf8(&bytes).unwrap())
        .expect("authored project configuration satisfies its owning model");
    bytes
}

fn information_flow_policy_bytes(value: &Value) -> Vec<u8> {
    let path = "__fortress/governance/information_flow_policy.json";
    let source = canonicalize_information_flow_policy_json(
        path,
        &serde_json::to_string(value).expect("authored information-flow policy JSON"),
    )
    .expect("authoritative information-flow policy canonicalization");
    load_information_flow_policy(vec![InformationFlowPolicySource::new(
        path,
        source.as_str(),
    )])
    .expect("authored information-flow facets satisfy their owning model");
    source.into_bytes()
}

fn finding_governance_bytes(value: &Value) -> Vec<u8> {
    FindingGovernanceDocument::from_json_str(
        &serde_json::to_string(value).expect("authored finding governance JSON"),
    )
    .expect("authored finding governance satisfies its owning model")
    .to_canonical_json()
    .expect("authoritative finding governance canonicalization")
    .into_bytes()
}

fn assumed_catalog_bytes(value: &Value) -> Vec<u8> {
    let bytes = json_bytes(value);
    OperationSummaryCatalog::from_json_str(fortress_core::standard::installed_operation_summaries())
        .expect("installed summary authority")
        .with_assumed_catalog(std::str::from_utf8(&bytes).unwrap())
        .expect("authored catalog is a valid fact-free local assumption");
    bytes
}

fn module_contract_value(source: &[u8]) -> Value {
    let contract = ModuleContract::from_json_str(std::str::from_utf8(source).unwrap())
        .expect("observed fixture Module Contract is canonical and valid");
    serde_json::to_value(contract).expect("validated Module Contract authoring view")
}

fn module_contract_bytes(value: &Value) -> Vec<u8> {
    let contract: ModuleContract =
        serde_json::from_value(value.clone()).expect("authored Module Contract wire shape");
    let source = contract
        .to_canonical_json()
        .expect("typed canonical Module Contract serialization");
    ModuleContract::from_json_str(&source)
        .expect("authored contract satisfies the selected schema and local semantics");
    source.into_bytes()
}

fn function_contract_bytes(path: &str, value: &Value) -> Vec<u8> {
    canonicalize_function_contract_json(
        path,
        &serde_json::to_string(value).expect("authored function contract JSON"),
    )
    .expect("authoritative function contract canonicalization")
    .into_bytes()
}

fn function_contract_mutation(base: &Generation, n: u32) -> ChangeOperation {
    let symbol = base
        .psm()
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::changed"))
        .expect("actual target symbol");
    let configuration = ProjectConfiguration::from_json_str(
        std::str::from_utf8(base.source_view().bytes("__fortress/.fsconfig").unwrap()).unwrap(),
    )
    .expect("actual baseline configuration");
    let owner = configuration
        .logical_modules()
        .iter()
        .find(|module| module.module() == symbol.fortress_module())
        .expect("target belongs to an authored Module rather than a mechanical Cargo territory");
    let binding = owner
        .bindings()
        .iter()
        .filter(|binding| {
            binding.kind() == SourcePathBindingKind::Directory
                && binding.matches(symbol.source_path())
        })
        .max_by_key(|binding| binding.path().len())
        .expect("actual declaring directory also owns the executable source");
    let ccg: Value =
        serde_json::from_str(&base.canonical_artifacts()["_info/contract_coherency_graph.json"])
            .unwrap();
    let compiled_owner = ccg["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["id"] == owner.module())
        .expect("declaring owner exists in the actual compiled CCG");
    assert_eq!(compiled_owner["contract_source"], owner.contract());
    let path = format!("{}/data/function_contracts.json", binding.path());
    assert!(!base.source_view().contains_key(&path));
    let document = json!({
        "$schema": "urn:fortress:schema:v5:function-contracts", "schema_version": 5,
        "functions": [{"symbol":symbol.id(), "requires":[], "ensures":[{"return":true,
            "domain":{"kind":"integer_interval", "min":n, "max":n + 2, "exclude":[]}}],
            "state_requires":[], "state_ensures":[], "effects":null}]
    });
    let candidate_bytes = function_contract_bytes(&path, &document);
    ChangeOperation::Create {
        path,
        candidate_bytes,
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn file_digest(path: &Path) -> String {
    let mut file = File::open(path).expect("binding file");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).expect("binding bytes");
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn actual_suite() -> (RustSuiteExecution, String) {
    let path = repository()
        .join("__fortress/evidence/generations")
        .join(BASELINE_GENERATION)
        .join("evidence_graph.json");
    let bytes = fs::read(path).expect("immutable accepted evidence graph remains available");
    let accepted: EvidenceGraph =
        serde_json::from_slice(&bytes).expect("accepted typed evidence graph");
    accepted
        .validate()
        .expect("accepted content identities and evidence DAG validate");
    let manifest_source = fs::read_to_string(
        repository()
            .join("__fortress/evidence/generations")
            .join(BASELINE_GENERATION)
            .join("manifest.json"),
    )
    .expect("accepted generation manifest");
    let manifest = AssessmentGenerationManifest::from_json_str(&manifest_source)
        .expect("accepted manifest validates");
    assert_eq!(
        manifest.generation_digest().unwrap(),
        format!("sha256:{BASELINE_GENERATION}")
    );
    let manifest_json: Value = serde_json::from_str(&manifest_source).unwrap();
    let descriptor = manifest_json["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["id"] == "evidence-graph")
        .expect("accepted graph descriptor");
    assert_eq!(descriptor["content_digest"], digest(&bytes));
    assert_eq!(descriptor["byte_count"], json!(bytes.len()));
    let graph: Value = serde_json::from_slice(&bytes).expect("accepted graph JSON");
    let nodes = graph["nodes"].as_array().expect("accepted nodes");
    let matching = nodes
        .iter()
        .filter(|node| node["kind"] == "rust_workspace_suite_execution")
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "one actual baseline execution record");
    let node = matching[0];
    assert_eq!(node["result"], "PASS");
    assert_eq!(node["evidence_class"], "EXECUTED_TEST");
    let payload = &node["payload"];
    let suite = RustSuiteExecution {
        executor: node["producer"].as_str().unwrap().into(),
        executor_version: node["producer_semantic_version"].as_str().unwrap().into(),
        toolchain: payload["toolchain"].as_str().unwrap().into(),
        certification_source_digest: payload["certification_source_digest"]
            .as_str()
            .unwrap()
            .into(),
        test_inventory_digest: payload["test_inventory_digest"].as_str().unwrap().into(),
        canonical_unfiltered: payload["canonical_unfiltered"].as_bool().unwrap(),
        passed: node["result"] == "PASS",
        eligible_test_ids: serde_json::from_value(payload["eligible_test_ids"].clone()).unwrap(),
        ignored_test_ids: serde_json::from_value(payload["ignored_test_ids"].clone()).unwrap(),
    };
    suite
        .validate()
        .expect("actual baseline inventory validates");
    assert!(suite.canonical_unfiltered);
    (suite, digest(&bytes))
}

fn assert_stale_execution(generation: &Generation, suite: &RustSuiteExecution) {
    let members = generation.canonical_artifacts();
    assert_eq!(
        members.len(),
        14,
        "all eleven semantic and three certification members"
    );
    assert_eq!(
        members.keys().map(String::as_str).collect::<Vec<_>>(),
        ARTIFACT_PATHS
    );
    let graph: Value = serde_json::from_str(&members["_info/evidence_graph.json"]).unwrap();
    let node = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["kind"] == "rust_workspace_suite_execution")
        .unwrap();
    assert_eq!(
        node["payload"]["certification_source_digest"],
        suite.certification_source_digest
    );
    assert_eq!(
        node["payload"]["test_inventory_digest"],
        suite.test_inventory_digest
    );
    assert_eq!(
        node["payload"]["eligible_test_ids"],
        json!(suite.eligible_test_ids)
    );
    assert_eq!(
        node["payload"]["ignored_test_ids"],
        json!(suite.ignored_test_ids)
    );
    assert_eq!(node["payload"]["toolchain"], suite.toolchain);
    assert_eq!(
        node["payload"]["canonical_unfiltered"],
        suite.canonical_unfiltered
    );
    assert_eq!(node["producer"], suite.executor);
    assert_eq!(node["producer_semantic_version"], suite.executor_version);
    assert_eq!(
        node["result"], "PASS",
        "historical execution outcome remains historical"
    );
    let certification: Value = serde_json::from_str(&members["_info/certification.json"]).unwrap();
    let obligation = certification["obligations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["subject"] == REQUIREMENT)
        .expect("fixture execution obligation");
    assert_eq!(
        obligation["status"], "STALE",
        "old execution must not qualify changed fixture bytes"
    );
}

fn replace(view: &SourceView, path: &str, bytes: Vec<u8>) -> ChangeOperation {
    ChangeOperation::Replace {
        path: path.into(),
        base_bytes: view.bytes(path).expect("base path").to_vec(),
        candidate_bytes: bytes,
    }
}

fn library(view: &SourceView) -> String {
    String::from_utf8(view.bytes("src/lib.rs").unwrap().to_vec()).unwrap()
}

fn mutation(case: &MutationCase, base: &Generation) -> Vec<ChangeOperation> {
    let case_number = case
        .id
        .rsplit('-')
        .next()
        .unwrap()
        .parse::<u32>()
        .expect("registered case number");
    let n = case_number * 1_000_000
        + 2
        + u32::try_from(
            u64::from_str_radix(&case.seed, 16).expect("registered generator value") % 1_000_000,
        )
        .expect("bounded mutation value");
    match case.class.as_str() {
        "trivia" | "body_domain" | "callee_effects" => {
            content_mutation(case, base.source_view(), n)
        }
        "edges_scc" | "add_delete_readd" | "unresolved" | "imports" => {
            linkage_mutation(case, base.source_view(), n)
        }
        "types_impl_drop" | "file_moves" | "cargo_cfg_target" | "valid_unsupported" => {
            syntax_mutation(case, base.source_view(), n)
        }
        "contracts" | "policy_profile" | "ownership_config" | "finding_governance" => {
            authority_mutation(case, base, n)
        }
        "control_history" => control_mutation(case, n),
        unknown => panic!("unregistered mutation class {unknown}"),
    }
}

fn content_mutation(case: &MutationCase, view: &SourceView, n: u32) -> Vec<ChangeOperation> {
    let source = library(view);
    let changed = |replacement: String| replace(view, "src/lib.rs", replacement.into_bytes());
    match case.class.as_str() {
        "trivia" => vec![changed(format!(
            "// seed {} case {}\n{}\n",
            case.seed, case.id, source
        ))],
        "body_domain" => {
            let expression = match case.ordinal % 4 {
                0 => n.to_string(),
                1 => format!("if {n} > 2 {{ {n} }} else {{ 0 }}"),
                2 => format!("{{ let value = {n}; value + 1 }}"),
                _ => format!("match {n} {{ 0 => 0, value => value }}"),
            };
            vec![changed(source.replace(
                "changed() -> u32 { 1 }",
                &format!("changed() -> u32 {{ {expression} }}"),
            ))]
        }
        "callee_effects" => {
            let operation = match case.ordinal % 4 {
                0 => format!("let _ = std::fs::read(\"input-{n}\");"),
                1 => format!("let _ = std::fs::write(\"output-{n}\", b\"value\");"),
                2 => format!("let _ = std::env::var(\"KEY_{n}\");"),
                _ => "let _ = std::time::SystemTime::now();".into(),
            };
            vec![replace(
                view,
                "src/leaf.rs",
                LEAF.replace(
                    "provider() -> u32 { 1 }",
                    &format!("provider() -> u32 {{ {operation} {n} }}"),
                )
                .into_bytes(),
            )]
        }
        unknown => panic!("unregistered mutation class {unknown}"),
    }
}

fn linkage_mutation(case: &MutationCase, view: &SourceView, n: u32) -> Vec<ChangeOperation> {
    let source = library(view);
    let changed = |replacement: String| replace(view, "src/lib.rs", replacement.into_bytes());
    match case.class.as_str() {
        "edges_scc" => {
            let tail = match case.ordinal % 4 {
                0 => format!("pub fn edge_{n}() -> u32 {{ right() }}\n"),
                1 => format!("pub fn edge_{n}() -> u32 {{ leaf::provider() + left() }}\n"),
                2 => format!(
                    "pub fn edge_{n}() -> u32 {{ edge_other_{n}() }}\npub fn edge_other_{n}() -> u32 {{ edge_{n}() }}\n"
                ),
                _ => format!("pub fn edge_{n}() -> u32 {{ left() + right() + caller() }}\n"),
            };
            vec![changed(format!("{source}{tail}"))]
        }
        "add_delete_readd" => match case.ordinal % 3 {
            0 => vec![
                changed(format!("{source}pub mod added_{n};\n")),
                ChangeOperation::Create {
                    path: format!("src/added_{n}.rs"),
                    candidate_bytes: format!("pub fn added() -> u32 {{ {n} }}\n").into_bytes(),
                },
            ],
            1 => vec![
                changed(source.replace("pub mod movable;\n", "").replace(
                    "changed() -> u32 { 1 }",
                    &format!("changed() -> u32 {{ {n} }}"),
                )),
                ChangeOperation::Delete {
                    path: "src/movable.rs".into(),
                    base_bytes: view.bytes("src/movable.rs").unwrap().to_vec(),
                },
            ],
            _ => vec![changed(format!(
                "{source}pub fn future() -> u32 {{ {n} }}\n"
            ))],
        },
        "unresolved" => {
            let replacement = match case.ordinal % 3 {
                0 => format!("{source}pub fn future() -> u32 {{ {n} }}\n"),
                1 => source.replace("future()", &format!("missing_{n}()")),
                _ => format!(
                    "{}pub fn future() -> u32 {{ leaf::provider() }}\n",
                    source.replace(
                        "left() -> u32 { 1 }",
                        &format!("left() -> u32 {{ missing_{n}() }}")
                    )
                ),
            };
            vec![changed(replacement)]
        }
        "imports" => {
            let replacement = match case.ordinal % 3 {
                0 => format!(
                    "use leaf::provider as selected_{n};\n{}",
                    source.replace("{ leaf::provider() }", &format!("{{ selected_{n}() }}"))
                ),
                1 => format!(
                    "pub use leaf::provider as export_{n};\n{source}pub fn import_{n}() -> u32 {{ export_{n}() }}\n"
                ),
                _ => {
                    format!("use movable::*;\n{source}pub fn import_{n}() -> u32 {{ located() }}\n")
                }
            };
            vec![changed(replacement)]
        }
        unknown => panic!("unregistered mutation class {unknown}"),
    }
}

fn syntax_mutation(case: &MutationCase, view: &SourceView, n: u32) -> Vec<ChangeOperation> {
    let source = library(view);
    let changed = |replacement: String| replace(view, "src/lib.rs", replacement.into_bytes());
    match case.class.as_str() {
        "types_impl_drop" => {
            let tail = match case.ordinal % 3 {
                0 => format!(
                    "pub struct Local{n} {{ pub value: u64 }}\nimpl Local{n} {{ pub fn read(&self) -> u64 {{ self.value }} }}\n"
                ),
                1 => format!(
                    "pub struct Local{n}(pub u32);\nimpl Drop for Local{n} {{ fn drop(&mut self) {{ let _ = std::fs::read(\"drop-{n}\"); }} }}\n"
                ),
                _ => format!(
                    "pub enum Local{n} {{ One(u32), Empty }}\npub fn typed_{n}(value: Local{n}) -> u32 {{ match value {{ Local{n}::One(v) => v, Local{n}::Empty => 0 }} }}\n"
                ),
            };
            vec![changed(format!("{source}{tail}"))]
        }
        "file_moves" => vec![
            ChangeOperation::Move {
                source: "src/movable.rs".into(),
                destination: format!("src/relocated/location_{n}.rs"),
                base_bytes: view.bytes("src/movable.rs").unwrap().to_vec(),
            },
            changed(source.replace(
                "pub mod movable;",
                &format!("#[path = \"relocated/location_{n}.rs\"]\npub mod movable;"),
            )),
        ],
        "cargo_cfg_target" => match case.ordinal % 3 {
            0 => vec![replace(
                view,
                "Cargo.toml",
                MANIFEST
                    .replace("version = \"0.1.0\"", &format!("version = \"0.1.{n}\""))
                    .replace("default = []", "default = [\"mode\"]")
                    .into_bytes(),
            )],
            1 => vec![changed(format!(
                "{source}#[cfg(feature = \"mode\")]\npub fn selected_{n}() -> u32 {{ {n} }}\n#[cfg(not(feature = \"mode\"))]\npub fn absent_{n}() -> u32 {{ 0 }}\n"
            ))],
            _ => vec![ChangeOperation::Create {
                path: ".cargo/config.toml".into(),
                candidate_bytes: format!(
                    "[build]\ntarget = \"{}\"\nrustflags = [\"--cfg\", \"resident_case_{n}\"]\n",
                    if case.ordinal.is_multiple_of(2) {
                        "x86_64-unknown-linux-gnu"
                    } else {
                        "x86_64-pc-windows-msvc"
                    }
                )
                .into_bytes(),
            }],
        },
        "valid_unsupported" => {
            let tail = match case.ordinal % 4 {
                0 => format!("pub fn unsupported_{n}() {{ unknown_macro_{n}!(); }}\n"),
                1 => format!("pub fn unsupported_{n}(target: fn() -> u32) -> u32 {{ target() }}\n"),
                2 => format!(
                    "pub async fn unsupported_{n}() -> u32 {{ future_async_{n}().await }}\n"
                ),
                _ => format!(
                    "pub fn unsupported_{n}() -> u32 {{ let callback = || {n}; callback() }}\n"
                ),
            };
            vec![changed(format!("{source}{tail}"))]
        }
        unknown => panic!("unregistered mutation class {unknown}"),
    }
}

fn authority_mutation(case: &MutationCase, base: &Generation, n: u32) -> Vec<ChangeOperation> {
    let view = base.source_view();
    match case.class.as_str() {
        "contracts" => {
            if case.ordinal.is_multiple_of(3) {
                let mut contract = module_contract_value(view.bytes("contract.json").unwrap());
                contract["display_name"] = json!(format!("Resident Corpus {n}"));
                contract["features"][0]["requirements"][0]["statement"] = json!(format!(
                    "Current execution evidence is required for case {n}."
                ));
                vec![replace(
                    view,
                    "contract.json",
                    module_contract_bytes(&contract),
                )]
            } else {
                vec![function_contract_mutation(base, n)]
            }
        }
        "policy_profile" => {
            if case.ordinal.is_multiple_of(2) {
                vec![ChangeOperation::Create {
                    path: "__fortress/governance/information_flow_policy.json".into(),
                    candidate_bytes: information_flow_policy_bytes(&json!({
                        "$schema":"urn:fortress:schema:v1:information-flow-policy", "schema_version":1,
                        "facets":[{"id":format!("FLOW-CONFIDENTIALITY-{n}"), "direction":"higher_is_more_restricted", "levels":["PUBLIC","PRIVATE"]}]
                    })),
                }]
            } else {
                let mut config: Value =
                    serde_json::from_slice(view.bytes("__fortress/.fsconfig").unwrap()).unwrap();
                config["assurance_profiles"] = json!([{"id":"ASSURE-SEMANTIC-EVALUABILITY", "version":"1.0.0",
                    "digest":"sha256:590aa518f3ea324d396877362e6a68c98febf297990810e46523729aa35786c8"}]);
                config["governance"]["coverage_floor"] = json!({"minimum_semantic_functions": n,
                    "minimum_evaluable_basis_points": n % 10_001});
                vec![replace(
                    view,
                    "__fortress/.fsconfig",
                    project_configuration_bytes(&config),
                )]
            }
        }
        "ownership_config" => {
            let mut config: Value =
                serde_json::from_slice(view.bytes("__fortress/.fsconfig").unwrap()).unwrap();
            let id = format!("AF-RESIDENT-OWNER-{n}");
            let path = format!("_data/logical_modules/owner_{n}/contract.json");
            config["logical_modules"].as_array_mut().unwrap().push(json!({
                "module":id, "contract":path, "parent":ROOT_ID,
                "bindings":[{"kind":"file", "path":if case.ordinal.is_multiple_of(2) { "src/leaf.rs" } else { "src/movable.rs" }}]
            }));
            let mut contract = module_contract_value(view.bytes("contract.json").unwrap());
            contract["id"] = json!(id);
            contract["display_name"] = json!(format!("Logical owner {n}"));
            contract.as_object_mut().unwrap().remove("ecosystem");
            contract["features"] = json!([]);
            vec![
                replace(
                    view,
                    "__fortress/.fsconfig",
                    project_configuration_bytes(&config),
                ),
                ChangeOperation::Create {
                    path,
                    candidate_bytes: module_contract_bytes(&contract),
                },
            ]
        }
        "finding_governance" => {
            let mut governance: Value = serde_json::from_slice(
                view.bytes("__fortress/governance/finding_governance.json")
                    .unwrap(),
            )
            .unwrap();
            governance["exceptions"] = json!([{"id":format!("EX-RESIDENT-{n}"), "finding_id":digest(case.id.as_bytes()),
                "rule_id":"REPO-DOCS-001", "authority":"fixture owner", "rationale":format!("Retired fixture review {n}"),
                "review_condition":null, "state":"RETIRED"}]);
            vec![replace(
                view,
                "__fortress/governance/finding_governance.json",
                finding_governance_bytes(&governance),
            )]
        }
        unknown => panic!("unregistered mutation class {unknown}"),
    }
}

fn control_mutation(case: &MutationCase, n: u32) -> Vec<ChangeOperation> {
    if case.ordinal.is_multiple_of(2) {
        let mut catalog: Value =
            serde_json::from_str(fortress_core::standard::installed_operation_summaries()).unwrap();
        let mut summary = catalog["summaries"][0].clone();
        summary["id"] = json!(format!("resident_unrelated_assumption_{n}"));
        summary["operation_selector"] = json!(format!("external::unrelated_{n}"));
        summary["observed_effects"] = json!([]);
        summary["authority_class"] = json!("ASSUMED");
        catalog["summaries"] = json!([summary]);
        vec![ChangeOperation::Create {
            path: "__fortress/governance/effect_summaries/catalog.json".into(),
            candidate_bytes: assumed_catalog_bytes(&catalog),
        }]
    } else {
        let member = [
            "manifest.json",
            "certification.json",
            "evidence_graph.json",
            "verified_behavioral_flow_graph.json",
            "quality_certificate.json",
        ][case.ordinal / 2];
        let path = format!("__fortress/evidence/generations/{BASELINE_GENERATION}/{member}");
        vec![ChangeOperation::Create {
            candidate_bytes: fs::read(repository().join(&path))
                .expect("unchanged genuine retained evidence member"),
            path,
        }]
    }
}

fn operations_json(operations: &[ChangeOperation]) -> Value {
    json!(operations.iter().map(|operation| match operation {
        ChangeOperation::Create { path, candidate_bytes } => json!({"operation":"CREATE", "path":path,
            "preimage":null, "candidate_utf8":std::str::from_utf8(candidate_bytes).unwrap(), "candidate_digest":digest(candidate_bytes)}),
        ChangeOperation::Replace { path, base_bytes, candidate_bytes } => json!({"operation":"REPLACE", "path":path,
            "preimage_utf8":std::str::from_utf8(base_bytes).unwrap(), "preimage_digest":digest(base_bytes),
            "candidate_utf8":std::str::from_utf8(candidate_bytes).unwrap(), "candidate_digest":digest(candidate_bytes)}),
        ChangeOperation::Delete { path, base_bytes } => json!({"operation":"DELETE", "path":path,
            "preimage_utf8":std::str::from_utf8(base_bytes).unwrap(), "preimage_digest":digest(base_bytes)}),
        ChangeOperation::Move { source, destination, base_bytes } => json!({"operation":"MOVE", "source":source,
            "destination":destination, "preimage_utf8":std::str::from_utf8(base_bytes).unwrap(), "preimage_digest":digest(base_bytes)}),
    }).collect::<Vec<_>>())
}

fn work_json(work: &SessionWork) -> Value {
    json!({"program":{
        "parsed_files":work.program.parsed_files, "reused_parse_files":work.program.reused_parse_files,
        "rebuilt_declaration_files":work.program.rebuilt_declaration_files, "reused_declaration_files":work.program.reused_declaration_files,
        "analyzed_bodies":work.program.analyzed_bodies, "reused_bodies":work.program.reused_bodies,
        "rebuilt_callers":work.program.rebuilt_callers, "reused_callers":work.program.reused_callers,
        "recomputed_components":work.program.recomputed_components, "reused_components":work.program.reused_components,
        "type_fixed_point_rounds":work.program.type_fixed_point_rounds},
        "semantic":work.semantic, "state_effect":work.state_effect,
        "parser":{"tokenizations":work.tokenizations,"input_bytes_tokenized":work.input_bytes_tokenized,
        "admission_bytes_added":work.parser_admission_bytes_added,"epoch_rotated":work.parser_epoch_rotated,
        "discarded_tokenizations":work.discarded_tokenizations,"discarded_input_bytes":work.discarded_input_bytes,
        "discarded_admission_bytes":work.discarded_parser_bytes,"retained_admission_bytes":work.retained_parser_bytes,
        "retained_input_bytes":work.retained_parser_input_bytes,"retained_tokenizations":work.retained_parser_tokenizations,
        "retained_allocation_charge":work.retained_parser_charge},"prepared_units":work.prepared_units})
}

fn member_hashes(generation: &Generation) -> BTreeMap<String, String> {
    generation
        .canonical_artifacts()
        .iter()
        .map(|(path, bytes)| (path.clone(), digest(bytes.as_bytes())))
        .collect()
}

struct Retention {
    file: File,
    path: PathBuf,
    bytes: usize,
}

impl Retention {
    fn new(
        fixture: &Fixture,
        suite: &RustSuiteExecution,
        graph_digest: &str,
        base: &Generation,
    ) -> Self {
        let path = fixture
            .storage
            .join("qualification/resident-differential-v1/cases.jsonl");
        let file = create_retained_report(&path).expect("exclusive durable records");
        let mut retention = Self {
            file,
            path,
            bytes: 0,
        };
        retention.record(&json!({"record":"RUN_BINDING", "registry_digest":digest(REGISTRY.as_bytes()),
            "baseline_generation":BASELINE_GENERATION, "baseline_evidence_graph_digest":graph_digest,
            "suite_execution":suite, "fixture_input_revision":base.input_revision(), "context_digest":base.context_digest(),
            "authority_digest":base.authority_digest(), "profile_digest":digest(base.source_view().bytes(PROFILE_PATH).unwrap()),
            "executable_digest":file_digest(&std::env::current_exe().unwrap()), "operating_system":std::env::consts::OS,
            "architecture":std::env::consts::ARCH, "baseline_files":base.source_view().files(),
            "timing_scope":"API call; independent cold oracle measured separately; tiny fixture only",
            "memory_scope":"owner conservative work/accounting; no RSS claim"}));
        retention
    }

    fn record(&mut self, record: &Value) {
        let bytes = serde_json::to_vec(record).expect("qualification record");
        self.bytes = self
            .bytes
            .checked_add(bytes.len() + 1)
            .expect("report accounting");
        assert!(
            self.bytes <= MAX_RETAINED_REPORT_BYTES,
            "bounded retained corpus report"
        );
        self.file.write_all(&bytes).expect("retain record");
        self.file.write_all(b"\n").expect("retain record separator");
        self.file.sync_data().expect("durable qualification record");
    }
}

fn registered_corpus() -> Registry {
    let registry: Registry = serde_json::from_str(REGISTRY).expect("registered mutation corpus");
    assert_eq!(registry.successful_comparisons, 1000);
    assert_eq!(registry.cases.len(), 1000);
    assert_eq!(
        registry
            .classes
            .iter()
            .map(|class| class.count)
            .sum::<usize>(),
        1000
    );
    assert_eq!(
        registry
            .cases
            .iter()
            .map(|case| &case.id)
            .collect::<BTreeSet<_>>()
            .len(),
        1000
    );
    let mut generator_state = u64::from_str_radix(&registry.seed, 16).expect("generator seed");
    for case in &registry.cases {
        generator_state ^= generator_state.wrapping_shl(13);
        generator_state ^= generator_state.wrapping_shr(7);
        generator_state ^= generator_state.wrapping_shl(17);
        assert_eq!(
            case.seed,
            format!("{generator_state:016x}"),
            "registered generator trajectory"
        );
    }
    for class in &registry.classes {
        assert_eq!(
            registry
                .cases
                .iter()
                .filter(|case| case.class == class.id)
                .count(),
            class.count
        );
    }
    registry
}

#[derive(Default)]
struct ReuseTotals {
    successful: usize,
    parse_files: usize,
    bodies: usize,
    callers: usize,
    components: usize,
    domain_rounds: usize,
    direct_units: usize,
    closure_rounds: usize,
}

impl ReuseTotals {
    fn add(&mut self, work: &SessionWork) {
        self.parse_files += work.program.reused_parse_files;
        self.bodies += work.program.reused_bodies;
        self.callers += work.program.reused_callers;
        self.components += work.program.reused_components;
        self.domain_rounds += work.semantic.reused_domain_rounds;
        self.direct_units += work.state_effect.reused_direct_units;
        self.closure_rounds += work.state_effect.reused_closure_rounds;
        self.successful += 1;
    }

    fn assert_complete(&self) {
        assert_eq!(
            self.successful, 1000,
            "only successful full canonical comparisons count"
        );
        assert!(self.parse_files > 0, "actual parse reuse");
        assert!(self.bodies > 0, "actual unchanged-file body reuse");
        assert!(self.callers > 0, "actual caller reuse");
        assert!(self.components > 0, "actual weak-component graph reuse");
        assert!(
            self.domain_rounds > 0,
            "actual synchronous domain-round reuse"
        );
        assert!(self.direct_units > 0, "actual direct-effect seed reuse");
        assert!(
            self.closure_rounds > 0,
            "actual synchronous effect-round reuse"
        );
    }
}

struct CaseComparison {
    warm: ComparedWarm,
    cold: SessionUpdate,
    operations: Value,
    history: bool,
    warm_ns: u128,
    cold_ns: u128,
}

impl CaseComparison {
    fn canonical_equal(&self) -> bool {
        self.warm.generation.canonical_artifacts() == self.cold.generation.canonical_artifacts()
            && self.warm.generation.audit() == self.cold.generation.audit()
    }

    fn assert_equivalent(&self, case: &MutationCase, retention: &Retention) {
        assert_eq!(
            self.warm.generation.context_digest(),
            self.cold.generation.context_digest(),
            "{} context",
            case.id
        );
        assert_eq!(
            self.warm.generation.authority_digest(),
            self.cold.generation.authority_digest(),
            "{} authority",
            case.id
        );
        assert_eq!(
            self.warm.generation.input_revision(),
            self.cold.generation.input_revision(),
            "{} input",
            case.id
        );
        assert!(
            self.canonical_equal(),
            "{} {} differs across whole canonical bundle; retained at {}",
            case.id,
            case.class,
            retention.path.display()
        );
    }

    fn assert_history(&self, base: &Generation) {
        if !self.history {
            return;
        }
        assert_eq!(
            self.warm.generation.input_revision(),
            base.input_revision(),
            "retained history leaves source revision unchanged"
        );
        assert_eq!(
            self.warm.generation.context_digest(),
            base.context_digest(),
            "retained history leaves context unchanged"
        );
        assert_eq!(
            self.warm.generation.authority_digest(),
            base.authority_digest(),
            "retained history leaves selected authority unchanged"
        );
        assert_eq!(
            self.warm.generation.canonical_artifacts(),
            base.canonical_artifacts(),
            "availability is outside all 14 semantic hashes"
        );
        let path = self.operations[0]["path"].as_str().unwrap();
        assert!(
            self.warm
                .availability_changes
                .iter()
                .any(|changed| changed == path),
            "actual retained member availability is observed"
        );
    }
}

fn assert_cold_preparation(work: &SessionWork) {
    assert_eq!(
        work.program.reused_parse_files, 0,
        "fresh cold parse preparation"
    );
    assert_eq!(work.program.reused_bodies, 0, "fresh cold body preparation");
    assert_eq!(
        work.program.reused_callers, 0,
        "fresh cold caller preparation"
    );
    assert_eq!(
        work.program.reused_components, 0,
        "fresh cold graph preparation"
    );
    assert_eq!(
        work.semantic.reused_domain_rounds, 0,
        "fresh cold domain preparation"
    );
    assert_eq!(
        work.state_effect.reused_direct_units, 0,
        "fresh cold effect preparation"
    );
    assert_eq!(
        work.state_effect.reused_closure_rounds, 0,
        "fresh cold closure preparation"
    );
}

fn apply_actual_history(fixture: &Fixture, operations: &[ChangeOperation]) {
    for operation in operations {
        let ChangeOperation::Create {
            path,
            candidate_bytes,
        } = operation
        else {
            panic!("registered availability case creates one genuine retained member");
        };
        let preimage = fs::symlink_metadata(fixture.root.join(path))
            .expect_err("exact physical history preimage is absent");
        assert_eq!(preimage.kind(), std::io::ErrorKind::NotFound);
        write(&fixture.root, path, candidate_bytes);
        assert_eq!(fs::read(fixture.root.join(path)).unwrap(), *candidate_bytes);
    }
}

struct CorpusRun<'a> {
    fixture: &'a Fixture,
    suite: &'a RustSuiteExecution,
    registry: &'a Registry,
    base: &'a Generation,
    retention: Retention,
    totals: ReuseTotals,
    operation_identities: BTreeSet<String>,
}

impl CorpusRun<'_> {
    fn evaluate_warm(
        &mut self,
        session: &mut Session,
        case: &MutationCase,
        operations: Vec<ChangeOperation>,
        operations_record: &Value,
        history: bool,
    ) -> ComparedWarm {
        let result = if history {
            session
                .refresh(&SourceDelta::default())
                .map(|update| ComparedWarm {
                    generation: update.generation,
                    work: update.work,
                    disposition: update.disposition,
                    reasons: update.reasons,
                    availability_changes: update.availability_changes,
                })
        } else {
            session
                .evaluate_delta(&case.id, self.base.input_revision(), operations)
                .map(|candidate| ComparedWarm {
                    generation: candidate.generation,
                    work: candidate.work,
                    disposition: candidate.disposition,
                    reasons: candidate.reasons,
                    availability_changes: Vec::new(),
                })
        };
        match result {
            Ok(warm) => warm,
            Err(error) => {
                self.retention.record(&json!({"record":"FAILED_CASE", "id":case.id, "class":case.class,
                    "seed":case.seed, "stage":"WARM_EVALUATION", "operations":operations_record,
                    "error_kind":format!("{:?}",error.kind()), "error":error.detail(), "successful_comparison":false}));
                panic!(
                    "{} {} warm evaluation: {error}; retained at {}",
                    case.id,
                    case.class,
                    self.retention.path.display()
                );
            }
        }
    }

    fn evaluate_cold(
        &mut self,
        session: &mut Session,
        case: &MutationCase,
        warm: &ComparedWarm,
        operations_record: &Value,
    ) -> SessionUpdate {
        match session.evaluate_view_cold(warm.generation.source_view().clone()) {
            Ok(cold) => cold,
            Err(error) => {
                self.retention.record(&json!({"record":"FAILED_CASE", "id":case.id, "class":case.class,
                    "seed":case.seed, "stage":"COLD_EVALUATION", "operations":operations_record,
                    "warm_member_hashes":member_hashes(&warm.generation), "warm_work":work_json(&warm.work),
                    "error_kind":format!("{:?}",error.kind()), "error":error.detail(), "successful_comparison":false}));
                panic!(
                    "{} {} cold evaluation: {error}; retained at {}",
                    case.id,
                    case.class,
                    self.retention.path.display()
                );
            }
        }
    }

    fn retain_case(&mut self, case: &MutationCase, comparison: &CaseComparison) {
        let warm = &comparison.warm;
        let cold = &comparison.cold;
        self.retention.record(&json!({"record":"CASE", "id":case.id, "class":case.class, "ordinal":case.ordinal,
            "input_role":case.input_role,
            "availability_changes":warm.availability_changes,
            "seed":case.seed, "generator":self.registry.generator, "base_input_revision":self.base.input_revision(),
            "candidate_input_revision":warm.generation.input_revision(), "context_digest":warm.generation.context_digest(),
            "authority_digest":warm.generation.authority_digest(), "operations":comparison.operations,
            "warm_member_hashes":member_hashes(&warm.generation), "cold_member_hashes":member_hashes(&cold.generation),
            "warm_work":work_json(&warm.work), "cold_work":work_json(&cold.work),
            "warm_output_effect_witness_records":warm.generation.state_effect().model().summaries().iter()
                .map(|summary| summary.effect_evidence().len()).sum::<usize>(),
            "cold_output_effect_witness_records":cold.generation.state_effect().model().summaries().iter()
                .map(|summary| summary.effect_evidence().len()).sum::<usize>(),
            "warm_disposition":format!("{:?}",warm.disposition), "warm_reasons":warm.reasons,
            "warm_api_nanoseconds":comparison.warm_ns.to_string(), "cold_oracle_nanoseconds":comparison.cold_ns.to_string(),
            "canonical_equal":comparison.canonical_equal()}));
    }

    fn compare(&mut self, session: &mut Session, case: &MutationCase) {
        let operations = mutation(case, self.base);
        let operations_record = operations_json(&operations);
        assert!(
            self.operation_identities
                .insert(digest(&json_bytes(&operations_record))),
            "distinct registered mutation {}",
            case.id
        );
        let history = case.class == "control_history" && case.ordinal % 2 == 1;
        assert_eq!(
            case.input_role,
            if history {
                "ACTUAL_NONRECURSIVE_AVAILABILITY"
            } else {
                "CANDIDATE_SOURCE_OR_AUTHORITY"
            }
        );
        if history {
            apply_actual_history(self.fixture, &operations);
        }
        let started = Instant::now();
        let warm = self.evaluate_warm(session, case, operations, &operations_record, history);
        let warm_ns = started.elapsed().as_nanos();
        let cold_started = Instant::now();
        let cold = self.evaluate_cold(session, case, &warm, &operations_record);
        let cold_ns = cold_started.elapsed().as_nanos();
        let comparison = CaseComparison {
            warm,
            cold,
            operations: operations_record,
            history,
            warm_ns,
            cold_ns,
        };
        self.retain_case(case, &comparison);
        comparison.assert_equivalent(case, &self.retention);
        comparison.assert_history(self.base);
        assert_stale_execution(&comparison.warm.generation, self.suite);
        assert_stale_execution(&comparison.cold.generation, self.suite);
        assert_cold_preparation(&comparison.cold.work);
        self.totals.add(&comparison.warm.work);
        if !history {
            session.release_candidate(&case.id);
        }
        drop(comparison.cold);
        drop(comparison.warm);
    }

    fn record_completion(&mut self) {
        self.retention.record(&json!({"record":"COMPLETE", "successful_comparisons":self.totals.successful,
            "generator":self.registry.generator, "seed":self.registry.seed,
            "reused_parse_files":self.totals.parse_files, "reused_bodies":self.totals.bodies,
            "reused_callers":self.totals.callers, "reused_graph_components":self.totals.components,
            "reused_domain_rounds":self.totals.domain_rounds, "reused_direct_effect_units":self.totals.direct_units,
            "reused_effect_closure_rounds":self.totals.closure_rounds,
            "canonical_members_per_case":14, "retained_bytes_before_final_record":self.retention.bytes}));
        eprintln!(
            "Resident differential qualification: {} ({} bytes)",
            self.retention.path.display(),
            self.retention.bytes
        );
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn incremental_equals_clean_for_registered_mutations() {
    let registry = registered_corpus();
    let (suite, graph_digest) = actual_suite();
    let fixture = Fixture::new();
    let mut session = fixture.open(&suite);
    let base = session.acquire_generation().expect("immutable actual base");
    assert_stale_execution(&base, &suite);
    let physical_source = fs::read(fixture.root.join("src/lib.rs")).unwrap();
    let retention = Retention::new(&fixture, &suite, &graph_digest, &base);
    let mut run = CorpusRun {
        fixture: &fixture,
        suite: &suite,
        registry: &registry,
        base: &base,
        retention,
        totals: ReuseTotals::default(),
        operation_identities: BTreeSet::new(),
    };
    for case in &registry.cases {
        run.compare(&mut session, case);
    }
    run.totals.assert_complete();
    assert_eq!(
        fs::read(fixture.root.join("src/lib.rs")).unwrap(),
        physical_source
    );
    assert_eq!(
        session.acquire_generation().unwrap().input_revision(),
        base.input_revision()
    );
    session
        .close()
        .expect("close releases owned operational work");
    run.record_completion();
}

fn assert_actual_matches_cold(
    session: &mut Session,
    suite: &RustSuiteExecution,
) -> std::sync::Arc<Generation> {
    let warm = session
        .refresh(&SourceDelta::default())
        .expect("whole-input refresh");
    let cold = session
        .evaluate_view_cold(warm.generation.source_view().clone())
        .expect("fresh cold oracle");
    assert_eq!(
        warm.generation.canonical_artifacts(),
        cold.generation.canonical_artifacts()
    );
    assert_eq!(warm.generation.audit(), cold.generation.audit());
    assert_stale_execution(&warm.generation, suite);
    warm.generation
}

fn assert_function_contract_ownership(
    session: &mut Session,
    baseline: &Generation,
    suite: &RustSuiteExecution,
) {
    // A real contract target remains owned by its declared logical territory.
    // Both the focused owner loader and the complete resident API must reject
    // the same canonical contract when declared under the unrelated root.
    let operation = function_contract_mutation(baseline, 2);
    let ChangeOperation::Create {
        path,
        candidate_bytes,
    } = &operation
    else {
        unreachable!();
    };
    let source = std::str::from_utf8(candidate_bytes).unwrap();
    let mismatch = load_function_contracts(
        baseline.psm(),
        vec![FunctionContractSource::new(
            ROOT_ID,
            "_data/function_contracts.json",
            source,
        )],
    )
    .expect_err("canonical bytes cannot grant foreign target ownership");
    assert!(matches!(mismatch, FunctionContractError::ForeignSymbol {
        owner, declaring_module, ..
    } if owner == CODE_MODULE_ID && declaring_module == ROOT_ID));
    let valid = load_function_contracts(
        baseline.psm(),
        vec![FunctionContractSource::new(
            CODE_MODULE_ID,
            path.as_str(),
            source,
        )],
    )
    .expect("actual declaring territory admits its target");
    assert_eq!(valid.len(), 1);
    let rejected = session
        .evaluate_delta(
            "foreign_contract",
            baseline.input_revision(),
            vec![ChangeOperation::Create {
                path: "_data/function_contracts.json".into(),
                candidate_bytes: candidate_bytes.clone(),
            }],
        )
        .expect_err("the actual distributed loader rejects root declaration");
    assert_eq!(rejected.kind(), SessionErrorKind::Evaluation);
    assert!(
        rejected
            .detail()
            .contains(&format!("owned by `{CODE_MODULE_ID}`"))
    );
    let contracted = session
        .evaluate_delta("owned_contract", baseline.input_revision(), vec![operation])
        .expect("authored logical data path follows actual loader ownership");
    let cold = session
        .evaluate_view_cold(contracted.generation.source_view().clone())
        .expect("fresh whole-bundle contract oracle");
    assert_eq!(
        contracted.generation.canonical_artifacts(),
        cold.generation.canonical_artifacts()
    );
    assert_eq!(contracted.generation.audit(), cold.generation.audit());
    assert_eq!(
        contracted
            .generation
            .semantic()
            .model()
            .coverage()
            .function_contracts(),
        1
    );
    assert_stale_execution(&contracted.generation, suite);
    assert_stale_execution(&cold.generation, suite);
    session.release_candidate("owned_contract");
}

fn assert_remaining_payload_variants(
    fixture: &Fixture,
    session: &mut Session,
    base: &Generation,
    suite: &RustSuiteExecution,
) {
    let registry = registered_corpus();
    let variants: [(&str, &[usize]); 5] = [
        ("policy_profile", &[0, 1]),
        ("ownership_config", &[0, 1]),
        ("finding_governance", &[0]),
        ("valid_unsupported", &[0, 1, 2, 3]),
        ("control_history", &[0, 1, 3, 5, 7, 9]),
    ];
    for (class, ordinals) in variants {
        for ordinal in ordinals {
            let case = registry
                .cases
                .iter()
                .find(|case| case.class == class && case.ordinal == *ordinal)
                .expect("every payload smoke variant belongs to the unchanged registry");
            assert_remaining_payload_case(fixture, session, base, suite, case);
        }
    }
}

fn assert_remaining_payload_case(
    fixture: &Fixture,
    session: &mut Session,
    base: &Generation,
    suite: &RustSuiteExecution,
    case: &MutationCase,
) {
    let operations = mutation(case, base);
    let history = case.class == "control_history" && case.ordinal % 2 == 1;
    let expected_availability = if history {
        let ChangeOperation::Create { path, .. } = &operations[0] else {
            unreachable!("registered history payload creates one genuine member");
        };
        vec![path.clone()]
    } else {
        Vec::new()
    };
    let prior = session.acquire_generation().expect("actual smoke base");
    let (warm, availability_changes) = if history {
        apply_actual_history(fixture, &operations);
        let update = session
            .refresh(&SourceDelta::for_base(base.input_revision()))
            .unwrap_or_else(|error| panic!("{} {} actual refresh: {error}", case.id, case.class));
        (update.generation, update.availability_changes)
    } else {
        let candidate = session
            .evaluate_delta(&case.id, base.input_revision(), operations)
            .unwrap_or_else(|error| panic!("{} {} candidate: {error}", case.id, case.class));
        (candidate.generation, Vec::new())
    };
    let cold = session
        .evaluate_view_cold(warm.source_view().clone())
        .unwrap_or_else(|error| panic!("{} {} cold oracle: {error}", case.id, case.class));
    assert_eq!(
        warm.source_view(),
        cold.generation.source_view(),
        "{}",
        case.id,
    );
    assert_eq!(
        warm.context_digest(),
        cold.generation.context_digest(),
        "{}",
        case.id,
    );
    assert_eq!(
        warm.authority_digest(),
        cold.generation.authority_digest(),
        "{}",
        case.id,
    );
    assert_eq!(
        warm.canonical_artifacts(),
        cold.generation.canonical_artifacts(),
        "{}",
        case.id,
    );
    assert_eq!(warm.audit(), cold.generation.audit(), "{}", case.id);
    assert_stale_execution(&warm, suite);
    assert_stale_execution(&cold.generation, suite);
    assert_cold_preparation(&cold.work);
    if history {
        assert_eq!(warm.input_revision(), base.input_revision());
        assert_eq!(warm.context_digest(), base.context_digest());
        assert_eq!(warm.authority_digest(), base.authority_digest());
        assert_eq!(warm.canonical_artifacts(), base.canonical_artifacts());
        assert_eq!(availability_changes, expected_availability);
        assert_eq!(
            session.acquire_generation().unwrap().generation_id(),
            warm.generation_id(),
        );
    } else {
        assert_eq!(
            session.acquire_generation().unwrap().generation_id(),
            prior.generation_id(),
            "candidate smoke leaves the actual head unchanged",
        );
        session.release_candidate(&case.id);
    }
    eprintln!("Resident payload smoke: {} {}", case.id, case.class);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn new_declaration_invalidates_unresolved_lookup_in_actual_refresh() {
    let (suite, _) = actual_suite();
    let fixture = Fixture::new();
    let mut session = fixture.open(&suite);
    let before = session.acquire_generation().unwrap();
    let before_psm = before.psm().to_canonical_json().unwrap();
    write(
        &fixture.root,
        "src/lib.rs",
        format!("{LIBRARY}pub fn future() -> u32 {{ 17 }}\n").as_bytes(),
    );
    let after = assert_actual_matches_cold(&mut session, &suite);
    assert_ne!(before_psm, after.psm().to_canonical_json().unwrap());
    let future = after
        .psm()
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::future"))
        .unwrap()
        .id();
    assert!(
        after
            .psm()
            .calls()
            .iter()
            .any(|call| call.callee() == Some(future)),
        "new declaration resolves prior missing target"
    );
    session.close().unwrap();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn delete_and_readd_symbol_rebuilds_scc_without_ghost_facts() {
    let (suite, _) = actual_suite();
    let fixture = Fixture::new();
    let mut session = fixture.open(&suite);
    let original = session.acquire_generation().unwrap();
    let original_artifacts = original.canonical_artifacts().clone();
    let deleted = LIBRARY.replace("pub fn left() -> u32 { 1 }\n", "");
    write(&fixture.root, "src/lib.rs", deleted.as_bytes());
    let without = assert_actual_matches_cold(&mut session, &suite);
    assert!(
        !without
            .psm()
            .symbols()
            .iter()
            .any(|symbol| symbol.qualified_name().ends_with("::left"))
    );
    drop(without);
    write(&fixture.root, "src/lib.rs", LIBRARY.as_bytes());
    let restored = assert_actual_matches_cold(&mut session, &suite);
    assert_eq!(
        restored.canonical_artifacts(),
        &original_artifacts,
        "readdition reconstructs exact original facts and provenance"
    );
    session.close().unwrap();
}

fn assert_fixture_collisions_preserve_existing_paths(parent: &Path) -> PathBuf {
    let process_id = std::process::id();
    let directory = fixture_candidate(parent, process_id, 0);
    fs::create_dir(&directory).unwrap();
    let historical = directory.join("retained-history.json");
    let historical_bytes = b"exact retained prior incarnation\n";
    fs::write(&historical, historical_bytes).unwrap();
    let file = fixture_candidate(parent, process_id, 1);
    let foreign_bytes = b"existing file must survive a directory claim\n";
    fs::write(&file, foreign_bytes).unwrap();
    let next = AtomicU64::new(0);
    let fresh = claim_fixture_base(parent, process_id, &next).unwrap();
    assert_eq!(fresh, fixture_candidate(parent, process_id, 2));
    assert_eq!(fs::read(&historical).unwrap(), historical_bytes);
    assert_eq!(fs::read(&file).unwrap(), foreign_bytes);
    for ordinal in 3..MAX_FIXTURE_CLAIM_ATTEMPTS {
        fs::create_dir(fixture_candidate(parent, process_id, ordinal as u64)).unwrap();
    }
    let exhausted = claim_fixture_base(parent, process_id, &AtomicU64::new(0)).unwrap_err();
    assert_eq!(exhausted.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&historical).unwrap(), historical_bytes);
    assert_eq!(fs::read(&file).unwrap(), foreign_bytes);
    let invalid_parent = parent.join("existing-parent-file");
    fs::write(&invalid_parent, foreign_bytes).unwrap();
    let denied = claim_fixture_base(&invalid_parent, process_id, &AtomicU64::new(0)).unwrap_err();
    assert_ne!(denied.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&invalid_parent).unwrap(), foreign_bytes);
    fresh
}

fn assert_retained_report_creation_preserves_preimage(fresh: &Path) {
    let path = fresh.join("storage/qualification/resident-differential-v1/cases.jsonl");
    let historical = b"{\"record\":\"retained prior report sentinel\"}\n";
    let mut report = create_retained_report(&path).unwrap();
    report.write_all(historical).unwrap();
    report.sync_all().unwrap();
    drop(report);
    let denied = create_retained_report(&path).unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), historical);
}

fn assert_fixture_retention_preserves_prior_incarnations() {
    let parent = claim_fixture_base(&std::env::temp_dir(), std::process::id(), &NEXT).unwrap();
    let fresh = assert_fixture_collisions_preserve_existing_paths(&parent);
    assert_retained_report_creation_preserves_preimage(&fresh);
    // This exact test parent was freshly claimed above. All collision sentinels
    // were authored within it; no pre-existing external incarnation is removed.
    fs::remove_dir_all(&parent).unwrap();
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R19-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R19
#[test]
fn cache_eviction_changes_actual_work_only_for_whole_bundle() {
    assert_fixture_retention_preserves_prior_incarnations();
    let (suite, _) = actual_suite();
    let fixture = Fixture::new();
    let mut session = fixture.open(&suite);
    let unchanged = session.refresh(&SourceDelta::default()).unwrap();
    assert!(unchanged.work.program.reused_parse_files > 0);
    session.evict_preparation().expect("evict preparation");
    let evicted = session.refresh(&SourceDelta::default()).unwrap();
    let cold = session
        .evaluate_view_cold(evicted.generation.source_view().clone())
        .unwrap();
    assert_eq!(
        unchanged.generation.canonical_artifacts(),
        evicted.generation.canonical_artifacts()
    );
    assert_eq!(
        evicted.generation.canonical_artifacts(),
        cold.generation.canonical_artifacts()
    );
    assert_eq!(evicted.work.program.reused_parse_files, 0);
    assert_eq!(evicted.work.semantic.reused_domain_rounds, 0);
    assert_eq!(evicted.work.state_effect.reused_direct_units, 0);
    assert_stale_execution(&evicted.generation, &suite);
    drop(unchanged);
    drop(cold);
    assert_function_contract_ownership(&mut session, &evicted.generation, &suite);
    assert_remaining_payload_variants(&fixture, &mut session, &evicted.generation, &suite);
    session.close().unwrap();
}
