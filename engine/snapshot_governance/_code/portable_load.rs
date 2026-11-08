//! Explicit registered-generation loading and safe portable directory publication.

use crate::bundle::PortableBundle;
use crate::control_layout::{ControlLayout, ControlRole};
use crate::control_manifest::{
    ArtifactStorage, AssessmentGenerationManifest, AssessmentSelectionIndex,
};
use crate::portable::{PortableError, digest, failure};
use std::collections::BTreeMap;
use std::path::Path;

/// Admits an explicitly supplied immutable JSON report without analysis.
/// # Errors
/// Rejects unsafe paths, invalid public JSON and resource excess.
pub fn load_portable_json(root: &Path, path: &Path) -> Result<serde_json::Value, PortableError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| failure("IO_ERROR", e.to_string()))?
            .join(root)
            .join(path)
    };
    let anchor = absolute
        .ancestors()
        .last()
        .ok_or_else(|| failure("UNSAFE_PATH", "input root missing"))?;
    let bytes = crate::query::safe_read(anchor, &absolute, 32 * 1024 * 1024)
        .map_err(|e| failure(&e.code, e.message))?;
    crate::portable::parse(&bytes)
}

/// Admits an explicit captured neutral endpoint without reconstructing its past.
/// # Errors
/// Rejects unsafe files, historical missing replay, corruption and limits.
pub fn load_portable_state(
    root: &Path,
    path: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, PortableError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let absolute = if absolute.is_absolute() {
        absolute
    } else {
        std::env::current_dir()
            .map_err(|e| failure("IO_ERROR", e.to_string()))?
            .join(absolute)
    };
    let anchor = absolute
        .ancestors()
        .last()
        .ok_or_else(|| failure("UNSAFE_PATH", "state root missing"))?;
    let bytes = crate::query::safe_read(anchor, &absolute, 32 * 1024 * 1024)
        .map_err(|e| failure(&e.code, e.message))?;
    let view = crate::state_view::StateView::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| failure("INVALID_JSON", e.to_string()))?,
    )
    .map_err(|e| failure("INVALID_STATE", e.to_string()))?;
    let application = view
        .application
        .as_ref()
        .ok_or_else(|| failure("UNAVAILABLE", "endpoint has no usable application"))?;
    let graph = view.portable_evidence_graph.as_ref().ok_or_else(|| {
        failure(
            "UNAVAILABLE",
            "historical endpoint did not retain a portable graph",
        )
    })?;
    let mut artifacts = BTreeMap::from([
        ("state-view".into(), bytes),
        (
            "conformance-declaration".into(),
            application
                .declaration
                .to_canonical_bytes()
                .map_err(|e| failure("INVALID_DECLARATION", e.to_string()))?,
        ),
        (
            "profile-assessment".into(),
            application
                .assessment
                .to_canonical_bytes()
                .map_err(|e| failure("INVALID_ASSESSMENT", e.to_string()))?,
        ),
        (
            "evidence-graph".into(),
            graph
                .to_json_pretty()
                .map_err(|e| failure("INVALID_GRAPH", e.to_string()))?
                .into_bytes(),
        ),
    ]);
    load_provider_payloads(root, &ControlLayout::standard(), &mut artifacts)?;
    Ok(artifacts)
}

/// Loads compact retained products without analysis, execution or cache repair.
/// Exact generation references preserve historical authority and source meaning.
/// # Errors
/// Rejects ambiguity, missing members, corrupt digests, unsafe paths and limits.
pub fn load_portable_artifacts(
    root: &Path,
    generation: Option<&str>,
    selection: Option<&str>,
) -> Result<(String, BTreeMap<String, Vec<u8>>), PortableError> {
    let layout = ControlLayout::standard();
    let generation = match generation {
        Some(g) if selection.is_none() => g.to_owned(),
        Some(_) => {
            return Err(failure(
                "INVALID_PARAMETERS",
                "generation and selection are exclusive",
            ));
        }
        None => selected(root, &layout, selection)?,
    };
    let path = layout
        .generation_path(&generation, None)
        .ok_or_else(|| failure("INVALID_REFERENCE", "unregistered generation reference"))?;
    let bytes = read(root, &path)?;
    let manifest = AssessmentGenerationManifest::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| failure("INVALID_JSON", e.to_string()))?,
    )
    .map_err(|e| failure("INVALID_MANIFEST", e.to_string()))?;
    if manifest
        .generation_digest()
        .map_err(|e| failure("INVALID_MANIFEST", e.to_string()))?
        != generation
    {
        return Err(failure("INTEGRITY_ERROR", "generation digest mismatch"));
    }
    let roles = [
        "conformance-declaration",
        "profile-assessment",
        "evidence-graph",
        "certification",
    ];
    let mut artifacts = BTreeMap::new();
    let mut total = 0usize;
    if manifest.artifacts().len() > 256 {
        return Err(failure(
            "RESOURCE_LIMIT",
            "generation inventory exceeds 256",
        ));
    }
    for artifact in manifest
        .artifacts()
        .iter()
        .filter(|a| roles.contains(&a.id()))
    {
        let ArtifactStorage::Included { member_name } = artifact.storage() else {
            continue;
        };
        let path = layout
            .generation_path(&generation, Some(artifact.id()))
            .ok_or_else(|| failure("INVALID_REFERENCE", "unregistered artifact role"))?;
        if Path::new(&path).file_name().and_then(|n| n.to_str()) != Some(member_name) {
            return Err(failure(
                "UNSAFE_PATH",
                "member does not match registered role",
            ));
        }
        let bytes = read(root, &path)?;
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= 128 * 1024 * 1024)
            .ok_or_else(|| failure("RESOURCE_LIMIT", "generation exceeds 128 MiB"))?;
        if digest(&bytes) != artifact.content_digest()
            || bytes.len() as u64 != artifact.byte_count()
        {
            return Err(failure(
                "INTEGRITY_ERROR",
                format!("artifact {} differs", artifact.id()),
            ));
        }
        artifacts.insert(artifact.id().into(), bytes);
    }
    artifacts.insert("control-generation".into(), bytes);
    load_provider_payloads(root, &layout, &mut artifacts)?;
    Ok((generation, artifacts))
}

fn load_provider_payloads(
    root: &Path,
    layout: &ControlLayout,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), PortableError> {
    let Some(graph) = artifacts.get("evidence-graph") else {
        return Ok(());
    };
    let graph = crate::portable::parse(graph)?;
    let Some(nodes) = graph["nodes"].as_array() else {
        return Err(failure("INVALID_GRAPH", "nodes missing"));
    };
    let mut selected = BTreeMap::new();
    for node in nodes.iter().filter(|n| n["kind"] == "assessment_replay") {
        if let Some(inputs) = node["payload"]["replay"]["evidence_inputs"]["selected"].as_array() {
            for input in inputs {
                let id = input["envelope_digest"].as_str().ok_or_else(|| {
                    failure("INVALID_IDENTITY", "provider envelope identity missing")
                })?;
                selected.insert(id.to_owned(), input["payload_digest"].clone());
            }
        }
    }
    let mut total = artifacts.values().map(Vec::len).sum::<usize>();
    for (id, payload_digest) in selected {
        for (role, label) in [
            (ControlRole::ProviderEnvelope, "provider-envelope"),
            (ControlRole::ProviderPayload, "provider-payload"),
        ] {
            let path = layout
                .provider_path(&id, role)
                .ok_or_else(|| failure("UNSAFE_PATH", "unregistered provider import"))?;
            let bytes = match read(root, &path) {
                Ok(b) => b,
                Err(e) if e.code == "MISSING" => continue,
                Err(e) => return Err(e),
            };
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= 128 * 1024 * 1024)
                .ok_or_else(|| {
                    failure(
                        "RESOURCE_LIMIT",
                        "provider closure exceeds bundle admission",
                    )
                })?;
            let identity = if role == ControlRole::ProviderEnvelope {
                let value = crate::portable::parse(&bytes)?;
                crate::portable::digest(&crate::portable::canonical(&value)?)
            } else {
                digest(&bytes)
            };
            let expected = if role == ControlRole::ProviderEnvelope {
                id.as_str()
            } else {
                payload_digest
                    .as_str()
                    .ok_or_else(|| failure("INVALID_IDENTITY", "payload identity missing"))?
            };
            if identity != expected {
                return Err(failure("DIGEST_MISMATCH", "selected provider bytes differ"));
            }
            artifacts.insert(format!("{label}:{identity}"), bytes);
        }
    }
    Ok(())
}

fn read(root: &Path, path: &str) -> Result<Vec<u8>, PortableError> {
    crate::query::safe_read(root, &root.join(path), 32 * 1024 * 1024)
        .map_err(|e| failure(&e.code, e.message))
}

fn selected(
    root: &Path,
    layout: &ControlLayout,
    key: Option<&str>,
) -> Result<String, PortableError> {
    let path = layout
        .role_path(ControlRole::AssessmentSelectionIndex)
        .ok_or_else(|| failure("INVALID_REFERENCE", "selection role absent"))?;
    let bytes = read(root, path)?;
    let index = AssessmentSelectionIndex::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| failure("INVALID_JSON", e.to_string()))?,
    )
    .map_err(|e| failure("INVALID_MANIFEST", e.to_string()))?;
    if let Some(key) = key {
        return index
            .generation(key)
            .map(str::to_owned)
            .ok_or_else(|| failure("MISSING", "exact selection absent"));
    }
    let selections = index.selections().take(129).collect::<Vec<_>>();
    match selections.as_slice() {
        [(_, generation)] => Ok((*generation).into()),
        [] => Err(failure("MISSING", "no selected evidence")),
        _ => Err(failure(
            "AMBIGUOUS_SELECTION",
            "choose an exact selection; no latest or first candidate is inferred",
        )),
    }
}

/// Writes an already assembled bundle into a new directory only.
/// Existing output and either compared state are never modified or repaired.
/// # Errors
/// Rejects existing destinations, unsafe members, links and filesystem failures.
pub fn write_portable_bundle(
    bundle: &PortableBundle,
    destination: &Path,
) -> Result<(), PortableError> {
    let io = |e: std::io::Error| failure("IO_ERROR", e.to_string());
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Preserve the supplied components until shared path admission has checked
    // every ancestor; canonicalize would conceal a link or junction here.
    let absolute_parent = std::path::absolute(parent).map_err(io)?;
    let anchor = absolute_parent
        .ancestors()
        .last()
        .ok_or_else(|| failure("UNSAFE_PATH", "destination root missing"))?;
    // The existing shared reader rejects ancestor links/reparse points even for
    // a missing leaf. A missing result is expected for a new destination.
    let name = destination
        .file_name()
        .ok_or_else(|| failure("UNSAFE_PATH", "destination must name a new directory"))?;
    let destination = absolute_parent.join(name);
    if destination.symlink_metadata().is_ok() {
        return Err(failure("OUTPUT_EXISTS", "destination already exists"));
    }
    if let Err(e) = crate::query::safe_read(anchor, &destination, 1)
        && e.code != "MISSING"
    {
        return Err(failure(&e.code, e.message));
    }
    for member in bundle.members.keys() {
        let bytes = member.as_bytes();
        let artifact = bytes.len() >= 78
            && bytes.starts_with(b"artifacts/")
            && bytes[10..74]
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && (bytes[74..] == *b".json" || bytes[74..] == *b".bin");
        if !(member == "manifest.json" || member == "statement.json" || artifact) {
            return Err(failure("UNSAFE_PATH", "invalid bundle member"));
        }
    }
    std::fs::create_dir(&destination).map_err(io)?;
    std::fs::create_dir(destination.join("artifacts")).map_err(io)?;
    for (member, bytes) in &bundle.members {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(member))
            .map_err(io)?;
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
    }
    Ok(())
}
