//! Explicit bounded read-only CONTROL loading, separate from warm queries.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{QueryError, QueryInput, QueryService};
use crate::control_layout::{ControlLayout, ControlRole};
use crate::control_manifest::{
    ArtifactStorage, AssessmentGenerationManifest, AssessmentSelectionIndex,
};

const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LOADED_BYTES: u64 = 128 * 1024 * 1024;

/// Explicit cold-load selection and operational source admission.
#[derive(Clone, Debug)]
pub struct QueryLoadOptions {
    /// Exact CONTROL selection key; omission is allowed only for zero or one selection.
    pub selection_key: Option<String>,
    /// Explicit already-produced `StateView`, read without regeneration.
    pub state_path: Option<PathBuf>,
    /// Maximum authoritative source bytes admitted before whole-file retention.
    pub max_source_bytes: usize,
    /// Maximum source inventory entries.
    pub max_files: usize,
}

impl Default for QueryLoadOptions {
    fn default() -> Self {
        Self {
            selection_key: None,
            state_path: None,
            max_source_bytes: 128 * 1024 * 1024,
            max_files: 50_000,
        }
    }
}

/// Loads source/authority and selected immutable results, never project execution.
///
/// All semantic products must already exist. Missing/corrupt selections become
/// visible diagnostic states; unsafe paths and resource failures are not repaired.
///
/// # Errors
/// Returns an error if actual source observation or immutable index admission fails.
pub fn load_repository_query(
    root: &Path,
    options: &QueryLoadOptions,
) -> Result<QueryService, QueryError> {
    let mut input =
        crate::audit::prepare_query_input(root, options.max_source_bytes, options.max_files)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
    let layout = ControlLayout::standard();
    input.availability["configuration_path"] =
        json!(layout.role_path(ControlRole::ProjectConfiguration));
    input.availability["active_governance"] = json!([ControlRole::FindingGovernance,ControlRole::GlobalInformationFlowPolicy,ControlRole::EffectSummaryAuthority,ControlRole::VerificationBindings].into_iter().filter_map(|role|layout.role_path(role)).map(|path|json!({"path":path,"state":match safe_read(root,&root.join(path),MAX_FILE_BYTES) {Ok(_)=>"AVAILABLE",Err(error) if error.code == "MISSING"=>"MISSING",Err(_)=>"UNAVAILABLE"}})).collect::<Vec<_>>());
    let mut budget = 0;
    if let Err(error) = load_selection(root, &layout, options, &mut input, &mut budget) {
        input.availability["evidence_state"] = json!(if error.code == "MISSING" {
            "MISSING"
        } else if error.code == "AMBIGUOUS_SELECTION" {
            "AMBIGUOUS"
        } else {
            "UNAVAILABLE"
        });
        input.availability["selection_error"] = json!(error);
        input.retained_application = None;
        input.evidence_nodes.clear();
        input.findings.clear();
        input.defeaters.clear();
        input.observed_routes.clear();
        input.limitations.push("Selected evidence could not be fully admitted; historical PASS is not current repository proof.".into());
    }
    if let Some(path) = &options.state_path {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            root.join(path)
        };
        // An explicit host-supplied StateView may be external to the repository.
        let anchor = absolute
            .ancestors()
            .last()
            .ok_or_else(|| QueryError::new("UNSAFE_PATH", "state path has no root"))?;
        let bytes = safe_read(anchor, &absolute, MAX_FILE_BYTES)?;
        charge(&mut budget, bytes.len())?;
        let view = crate::audit::StateView::from_json_str(text(&bytes)?)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        input.retained_application = None;
        input.evidence_nodes.clear();
        input.findings.clear();
        input.defeaters.clear();
        input.observed_routes.clear();
        input.availability["control_generation_applicability"] = json!("HISTORY_ONLY");
        input.state_view = Some(view);
        retain_state_graph(&mut input)?;
        input.availability["selection_source"] = json!("EXPLICIT_STATE_VIEW");
        input.availability["evidence_state"] = json!("SELECTED");
        input.availability["proof_metadata"] = json!("COMPLETE_STATE_VIEW");
    }
    let selected_source = input
        .state_view
        .as_ref()
        .map(|view| view.source_ref.as_str())
        .or_else(|| {
            input
                .retained_application
                .as_ref()
                .map(|app| app.declaration.binding.subject_ref.as_str())
        });
    input.availability["authority_freshness"] = json!(selected_source.map_or(
        "UNAVAILABLE",
        |source| if source == input.source_ref {
            "SOURCE_BOUND"
        } else {
            "STALE"
        }
    ));
    input.availability["actual_context_freshness"] = json!("NOT_REEVALUATED");
    input.availability["evidence_freshness"] =
        json!(
            selected_source.map_or("MISSING", |source| if source == input.source_ref {
                "FRESH"
            } else {
                "STALE"
            })
        );
    input.diagnostics["environment"] = json!({"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"project_commands_executed":false});
    if !input.diagnostics["toolchain"].is_object() {
        input.diagnostics["toolchain"] = json!({});
    }
    input.diagnostics["toolchain"]["availability"] = json!("NOT_EXECUTED");
    input.diagnostics["toolchain"]["reason"] =
        json!("Doctor reads declared inputs; compiler and project hooks are never launched.");
    input.diagnostics["storage"] = json!({"repository_read_only_attribute":fs::metadata(root).ok().map(|metadata|metadata.permissions().readonly()),"writeability":"NOT_PROBED","loaded_evidence_bytes":budget,"max_loaded_evidence_bytes":MAX_LOADED_BYTES,"repairs_performed":false});
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = disks
        .iter()
        .filter(|disk| root.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len());
    input.diagnostics["storage"]["available_disk_bytes"] =
        json!(disk.map(sysinfo::Disk::available_space));
    input.diagnostics["storage"]["disk_read_only"] = json!(disk.map(sysinfo::Disk::is_read_only));
    input.diagnostics["evidence"] = input.availability.clone();
    QueryService::new(input)
}

fn load_selection(
    root: &Path,
    layout: &ControlLayout,
    options: &QueryLoadOptions,
    input: &mut QueryInput,
    budget: &mut u64,
) -> Result<(), QueryError> {
    let path = layout
        .role_path(ControlRole::AssessmentSelectionIndex)
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "selection role is not registered"))?;
    let bytes = safe_read(root, &root.join(path), MAX_FILE_BYTES)?;
    charge(budget, bytes.len())?;
    let index = AssessmentSelectionIndex::from_json_str(text(&bytes)?)
        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
    let selections = index.selections().collect::<Vec<_>>();
    if selections.len() > 128 {
        return Err(QueryError::new(
            "RESOURCE_LIMIT",
            "selection count exceeds 128",
        ));
    }
    let selection =
        if let Some(key) = &options.selection_key {
            index
                .generation(key)
                .map(|generation| (key.as_str(), generation))
                .ok_or_else(|| QueryError::new("MISSING", "requested selection is absent"))?
        } else {
            match selections.as_slice() {
                [selection] => *selection,
                [] => {
                    return Err(QueryError::new(
                        "MISSING",
                        "no evidence generation is selected",
                    ));
                }
                _ => return Err(QueryError {
                    code: "AMBIGUOUS_SELECTION".into(),
                    message:
                        "choose an exact selection_key; no latest or first generation is inferred"
                            .into(),
                    candidates: selections.iter().map(|(key, _)| (*key).into()).collect(),
                }),
            }
        };
    input.availability["selection_key"] = json!(selection.0);
    input.availability["generation_digest"] = json!(selection.1);
    let manifest_path = layout
        .generation_path(selection.1, None)
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "unregistered manifest path"))?;
    let bytes = safe_read(root, &root.join(&manifest_path), MAX_FILE_BYTES)?;
    charge(budget, bytes.len())?;
    let manifest = AssessmentGenerationManifest::from_json_str(text(&bytes)?)
        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
    if manifest
        .generation_digest()
        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?
        != selection.1
    {
        return Err(QueryError::new(
            "INTEGRITY_ERROR",
            "selected manifest digest does not match its generation",
        ));
    }
    let (payloads, materialization) =
        load_artifacts(root, layout, &manifest, selection.1, input, budget)?;
    input.availability["history"] = probe_history(root, layout, &manifest_path);
    input.availability["local_materialization"] = json!(materialization);
    input.availability["evidence_state"] = json!("SELECTED");
    input.availability["authenticity"] = json!("UNVERIFIED");
    input.availability["generation_source_ref"] = json!(manifest.source_ref());
    load_retained_products(input, &payloads)
}

fn load_retained_products(
    input: &mut QueryInput,
    payloads: &ArtifactPayloads,
) -> Result<(), QueryError> {
    if let (Some(declaration), Some(assessment)) = (
        payloads.get("conformance-declaration"),
        payloads.get("profile-assessment"),
    ) {
        let declaration =
            crate::declaration::ConformanceDeclaration::from_json_str(text(declaration)?)
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        let assessment = crate::assessment::ProfileAssessment::from_json_str(text(assessment)?)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        input.retained_application = Some(crate::application::ApplicationAssessment {
            portable_replay: None,
            project: "retained-generation".into(),
            declaration,
            assessment,
            evidence: Vec::new(),
            obligations: Vec::new(),
            evidence_inputs: None,
            provider_requirements: Vec::new(),
        });
        input.availability["proof_metadata"] = json!("PARTIAL_RETAINED_PAIR");
    }
    if let Some(bytes) = payloads.get("evidence-graph") {
        let graph: Value = crate::wire::parse_public_json(text(bytes)?)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        if graph["$schema"] != "urn:fortress:schema:v2:evidence-graph"
            || graph["schema_version"] != 2
        {
            return Err(QueryError::new(
                "UNSUPPORTED_SEMANTICS",
                "unsupported evidence graph projection version",
            ));
        }
        if let Some(nodes) = graph["nodes"].as_array() {
            input.evidence_nodes.clone_from(nodes);
        }
        retain_replay_records(input, &graph)?;
    }
    if input
        .retained_application
        .as_ref()
        .is_some_and(|a| a.portable_replay.is_none())
    {
        input.limitations.push("This generation retains declaration/assessment results but not the complete StateView evidence-admission and obligation manifest. Explanations disclose unresolved references. Supply an existing --state StateView for complete recorded metadata.".into());
    }
    Ok(())
}

fn retain_replay_records(input: &mut QueryInput, graph: &Value) -> Result<(), QueryError> {
    let validated: crate::certification::EvidenceGraph = serde_json::from_value(graph.clone())
        .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
    validated
        .validate()
        .map_err(|e| QueryError::new("INTEGRITY_ERROR", e.to_string()))?;
    let nodes = graph["nodes"]
        .as_array()
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "evidence nodes absent"))?;
    let replays = nodes
        .iter()
        .filter(|n| n["kind"] == "assessment_replay")
        .collect::<Vec<_>>();
    let [node] = replays.as_slice() else {
        return if replays.is_empty() {
            Ok(())
        } else {
            Err(QueryError::new(
                "INVALID_INPUT",
                "ambiguous replay observations",
            ))
        };
    };
    let replay = &node["payload"]["replay"];
    let app = if let Some(app) = input.retained_application.as_mut() {
        app
    } else if let Some(app) = input
        .state_view
        .as_mut()
        .and_then(|v| v.application.as_mut())
    {
        app
    } else {
        return Err(QueryError::new(
            "INVALID_INPUT",
            "replay has no retained declaration",
        ));
    };
    let hash = |v: &Value| -> Result<String, QueryError> {
        crate::portable::canonical(v)
            .map(|b| crate::portable::digest(&b))
            .map_err(|e| QueryError::new(&e.code, e.message))
    };
    if replay["schema_version"] != 1
        || replay["expected"]["binding"]
            != serde_json::to_value(&app.declaration.binding)
                .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?
        || hash(&replay["expected"]["obligations"])? != app.assessment.obligation_manifest_digest
        || hash(&replay["acceptance"])? != app.assessment.acceptance_policy_digest
    {
        return Err(QueryError::new(
            "INTEGRITY_ERROR",
            "retained replay differs from original assessment",
        ));
    }
    app.evidence = serde_json::from_value(replay["evidence"].clone())
        .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
    app.obligations = serde_json::from_value(replay["expected"]["obligations"].clone())
        .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
    app.evidence_inputs = serde_json::from_value(replay["evidence_inputs"].clone())
        .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
    app.portable_replay = Some(replay.clone());
    if let Some(findings) = node["payload"]["audit"]["findings"].as_array() {
        input.findings.clone_from(findings);
    }
    input.evidence_nodes.clone_from(nodes);
    input.availability["proof_metadata"] = json!("RETAINED_REPLAY_INPUTS");
    Ok(())
}

type ArtifactPayloads = BTreeMap<String, Vec<u8>>;

fn load_artifacts(
    root: &Path,
    layout: &ControlLayout,
    manifest: &AssessmentGenerationManifest,
    generation: &str,
    input: &mut QueryInput,
    budget: &mut u64,
) -> Result<(ArtifactPayloads, Vec<Value>), QueryError> {
    let mut payloads = BTreeMap::new();
    let mut materialization = Vec::new();
    for artifact in manifest.artifacts() {
        match artifact.storage() {
            ArtifactStorage::Included { member_name } => {
                let registered = layout
                    .generation_path(generation, Some(artifact.id()))
                    .ok_or_else(|| {
                        QueryError::new("INVALID_INPUT", "unregistered included artifact")
                    })?;
                if Path::new(&registered)
                    .file_name()
                    .and_then(|value| value.to_str())
                    != Some(member_name)
                {
                    return Err(QueryError::new(
                        "INVALID_INPUT",
                        "artifact member disagrees with registered role",
                    ));
                }
                let bytes = safe_read(root, &root.join(&registered), MAX_FILE_BYTES)?;
                charge(budget, bytes.len())?;
                if bytes.len() as u64 != artifact.byte_count()
                    || format!("sha256:{:x}", Sha256::digest(&bytes)) != artifact.content_digest()
                {
                    return Err(QueryError::new(
                        "INTEGRITY_ERROR",
                        "selected artifact bytes differ from their manifest",
                    ));
                }
                payloads.insert(artifact.id().to_owned(), bytes);
                materialization.push(json!({"id":artifact.id(),"availability":"AVAILABLE","integrity":"VERIFIED_DIGEST","authenticity":"UNVERIFIED"}));
            }
            ArtifactStorage::ExternalMaterialization { .. } => {
                let cached = read_cached(root, layout, manifest, artifact.id(), budget);
                match cached {
                    Ok(bytes) if bytes.len() as u64 == artifact.byte_count() && format!("sha256:{:x}",Sha256::digest(&bytes)) == artifact.content_digest() => {
                        materialization.push(json!({"id":artifact.id(),"availability":"AVAILABLE","integrity":"VERIFIED_DIGEST","authenticity":"UNVERIFIED","subject":"SELECTED_GENERATION"}));
                        if artifact.id() == "semantic-conformance" {load_semantic_projection(input,&bytes)?;}
                    },
                    Ok(_) => materialization.push(json!({"id":artifact.id(),"availability":"INVALID","reason":"Materialized bytes differ from selected immutable identity."})),
                    Err(error) => materialization.push(json!({"id":artifact.id(),"availability":if error.code == "MISSING" {"MISSING"} else {"UNAVAILABLE"},"reason":error.message,"required_digest":artifact.content_digest()})),
                }
            }
        }
    }
    Ok((payloads, materialization))
}

fn read_cached(
    root: &Path,
    layout: &ControlLayout,
    manifest: &AssessmentGenerationManifest,
    id: &str,
    budget: &mut u64,
) -> Result<Vec<u8>, QueryError> {
    let project = manifest.project();
    if project.is_empty()
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(QueryError::new(
            "UNSAFE_PATH",
            "project cache identity is not a safe segment",
        ));
    }
    let base = std::env::var_os("FORTRESS_DERIVED_CACHE_DIR").map_or_else(
        || std::env::temp_dir().join("fortress-derived"),
        PathBuf::from,
    );
    let base = if base.is_absolute() {
        base
    } else {
        root.join(base)
    };
    if base.starts_with(root) {
        return Err(QueryError::new(
            "UNSAFE_PATH",
            "materialization cache must remain outside the repository",
        ));
    }
    let logical = layout
        .artifact_logical_path(id)
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "unregistered cache artifact"))?;
    let member = Path::new(logical)
        .file_name()
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "registered artifact has no member"))?;
    let subject = manifest
        .source_ref()
        .strip_prefix("sha256:")
        .ok_or_else(|| QueryError::new("INVALID_INPUT", "invalid cache subject"))?;
    let path = base.join(project).join(subject).join(member);
    let anchor = path
        .ancestors()
        .last()
        .ok_or_else(|| QueryError::new("UNSAFE_PATH", "cache has no absolute root"))?;
    let bytes = safe_read(anchor, &path, MAX_FILE_BYTES)?;
    charge(budget, bytes.len())?;
    Ok(bytes)
}

fn load_semantic_projection(input: &mut QueryInput, bytes: &[u8]) -> Result<(), QueryError> {
    let projection: Value = crate::wire::parse_public_json(text(bytes)?)
        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
    if projection["$schema"] != "urn:fortress:schema:v7:semantic-conformance"
        || projection["schema_version"] != 7
    {
        return Err(QueryError::new(
            "UNSUPPORTED_SEMANTICS",
            "unsupported semantic-conformance projection version",
        ));
    }
    // Preserve only existing owner-produced records. There is no inference from
    // the names or content of observations into permissions or proof sufficiency.
    if let Some(values) = projection["findings"].as_array() {
        input.findings.extend(
            values
                .iter()
                .filter(|value| value["finding_id"].is_string())
                .cloned(),
        );
    }
    if let Some(values) = projection["defeaters"].as_array() {
        input.defeaters.extend(values.clone());
    }
    Ok(())
}

fn text(bytes: &[u8]) -> Result<&str, QueryError> {
    std::str::from_utf8(bytes).map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))
}

fn charge(budget: &mut u64, bytes: usize) -> Result<(), QueryError> {
    *budget = budget
        .checked_add(bytes as u64)
        .filter(|total| *total <= MAX_LOADED_BYTES)
        .ok_or_else(|| {
            QueryError::new("RESOURCE_LIMIT", "aggregate evidence byte limit reached")
        })?;
    Ok(())
}

// Inspect every existing path component before opening, including Windows
// junction/reparse boundaries. This is an optimistic read protocol, not a host lock.
pub(crate) fn safe_read(root: &Path, path: &Path, maximum: u64) -> Result<Vec<u8>, QueryError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| QueryError::new("UNSAFE_PATH", "path escapes its supplied root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(QueryError::new(
                "UNSAFE_PATH",
                "noncanonical path component",
            ));
        }
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| read_error(&error))?;
        if linked(&metadata) {
            return Err(QueryError::new(
                "UNSAFE_PATH",
                "linked or reparse evidence paths are unsupported",
            ));
        }
    }
    let mut file = File::open(path).map_err(|error| read_error(&error))?;
    let before = file.metadata().map_err(|error| read_error(&error))?;
    if !before.is_file() {
        return Err(QueryError::new(
            "UNSAFE_PATH",
            "evidence input is not an ordinary file",
        ));
    }
    if before.len() > maximum {
        return Err(QueryError::new(
            "RESOURCE_LIMIT",
            "evidence file exceeds byte limit",
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| read_error(&error))?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != before.len()
        || file.metadata().map_err(|error| read_error(&error))?.len() != before.len()
    {
        return Err(QueryError::new(
            "RESOURCE_LIMIT",
            "evidence file changed size or exceeded admission",
        ));
    }
    Ok(bytes)
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn read_error(error: &io::Error) -> QueryError {
    QueryError::new(
        if error.kind() == io::ErrorKind::NotFound {
            "MISSING"
        } else {
            "UNAVAILABLE"
        },
        error.to_string(),
    )
}

fn probe_history(root: &Path, layout: &ControlLayout, selected_manifest: &str) -> Value {
    let Some(directory) = Path::new(selected_manifest).parent().and_then(Path::parent) else {
        return json!({"availability":"UNAVAILABLE"});
    };
    let entries = match fs::read_dir(root.join(directory)) {
        Ok(entries) => entries,
        Err(error) => return json!({"availability":"UNAVAILABLE","reason":error.to_string()}),
    };
    let mut generations = Vec::new();
    for entry in entries {
        if generations.len() >= 256 {
            return json!({"availability":"UNAVAILABLE","reason":"history inventory exceeds 256 generation entries","retention":"UNCHANGED"});
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return json!({"availability":"UNAVAILABLE","reason":error.to_string()}),
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return json!({"availability":"UNAVAILABLE","reason":"nonportable generation name"});
        };
        let digest = format!("sha256:{name}");
        let Some(path) = layout.generation_path(&digest, None) else {
            return json!({"availability":"INVALID","reason":"unregistered history directory"});
        };
        let directory_metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => return json!({"availability":"UNAVAILABLE","reason":error.to_string()}),
        };
        if linked(&directory_metadata) || !directory_metadata.is_dir() {
            return json!({"availability":"INVALID","reason":"history generation is linked or not a directory"});
        }
        let availability = match fs::symlink_metadata(root.join(path)) {
            Ok(metadata) if !linked(&metadata) && metadata.is_file() => "AVAILABLE",
            Ok(_) => "INVALID",
            Err(error) if error.kind() == io::ErrorKind::NotFound => "MISSING",
            Err(_) => "UNAVAILABLE",
        };
        generations.push(json!({"generation_digest":digest,"manifest_availability":availability,"integrity":"NOT_CHECKED_FOR_UNSELECTED_HISTORY"}));
    }
    generations.sort_by(|left, right| {
        left["generation_digest"]
            .as_str()
            .cmp(&right["generation_digest"].as_str())
    });
    json!({"selected_generation":"AVAILABLE","selected_manifest":selected_manifest,"retained_generations":generations,"retention":"UNCHANGED"})
}

fn retain_state_graph(input: &mut QueryInput) -> Result<(), QueryError> {
    if let Some(graph) = input
        .state_view
        .as_ref()
        .and_then(|v| v.portable_evidence_graph.as_ref())
    {
        let graph = serde_json::to_value(graph)
            .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
        retain_replay_records(input, &graph)?;
    }
    Ok(())
}
