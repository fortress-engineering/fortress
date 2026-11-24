//! Exact-source Go workspace declarations from an explicitly selected host reader.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::affected_analysis::sha256;
use crate::native_observation::{NativeSource, NativeSourceError};
use crate::observation::{SourceView, is_canonical_relative_path};
use crate::wire::{JsonAdmissionLimits, admit_json, parse_public_json};

const SCHEMA: &str = "urn:fortress:derived:v1:go-workspace-observation";
const MAX_MEMBERS: usize = 256;
const MAX_MANIFEST_BYTES: usize = 128 << 10;
const MAX_PATH_BYTES: usize = 4096;

/// Pinned Go reader outcome for the provided workspace bytes.
pub enum GoWorkspaceReaderReply {
    /// The bounded Go work editor reported an invalid workspace file.
    Invalid,
    /// Pinning, parsing or resource requirements could not be established.
    Unavailable,
    /// Read-only JSON and formatted text outputs from the same pinned Go reader.
    Parsed {
        /// Exact JSON from the Go workspace editor.
        json: Vec<u8>,
        /// Exact printed Go workspace text.
        formatted: Vec<u8>,
        /// Exact host executable identity.
        executable_ref: String,
        /// The actual Go version used to read the manifest.
        version: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct NativeWorkFile {
    #[serde(default)]
    go: Option<String>,
    #[serde(rename = "Use")]
    members: Option<Vec<NativeUse>>,
    #[serde(rename = "Replace")]
    replacements: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct NativeUse {
    disk_path: String,
    #[serde(rename = "ModPath")]
    _module_path: Option<String>,
}

#[derive(Serialize)]
struct FileBinding {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum WorkspaceMember {
    Observed {
        module: FileBinding,
        sum: Option<FileBinding>,
    },
    MissingModule {
        path: String,
    },
    Ambiguous {
        path: String,
    },
    UnresolvedPath {
        declared_path_ref: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum WorkspaceMetadata {
    Missing,
    Invalid,
    Unavailable {
        reason: &'static str,
    },
    Declared {
        go_version: Option<String>,
        toolchain_directive: Option<String>,
        reader_version: String,
        reader_executable_ref: String,
        workspace_membership: Vec<WorkspaceMember>,
        replacement_count: usize,
    },
}

/// Selected Go workspace declarations linked to exact physical source.
#[derive(Serialize)]
pub struct GoWorkspaceObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    scope: &'static str,
    source_fingerprint: String,
    source_view_digest: String,
    source_manifest_digest: String,
    authority_digest: String,
    manifest_path: String,
    manifest_sha256: Option<String>,
    workspace_sum: Option<FileBinding>,
    metadata: WorkspaceMetadata,
    effective_workspace: &'static str,
}

/// An observation could not be bound to an ordinary, unchanged source inventory.
#[derive(Debug)]
pub enum GoWorkspaceObservationError {
    /// The selected path is not a portable repository-relative go.work.
    InvalidManifestPath,
    /// Physical observation or original authority is unavailable.
    SourceUnavailable(String),
    /// Exact source or directory identity changed before publication.
    SourceChanged,
}

impl std::fmt::Display for GoWorkspaceObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifestPath => formatter.write_str("INVALID_GO_WORKSPACE_MANIFEST_PATH"),
            Self::SourceUnavailable(detail) => {
                write!(formatter, "GO_WORKSPACE_SOURCE_UNAVAILABLE: {detail}")
            }
            Self::SourceChanged => formatter.write_str("GO_WORKSPACE_SOURCE_CHANGED"),
        }
    }
}

impl std::error::Error for GoWorkspaceObservationError {}

impl From<NativeSourceError> for GoWorkspaceObservationError {
    fn from(error: NativeSourceError) -> Self {
        match error {
            NativeSourceError::Unavailable(detail) => Self::SourceUnavailable(detail),
            NativeSourceError::Changed => Self::SourceChanged,
        }
    }
}

/// Observes selected workspace declarations and ordinary module metadata bytes.
///
/// The host reader sees only the exact, bounded manifest bytes. It supplies no
/// source authority or effective workspace selection. Manifest paths are
/// normalized only within the closed lexical scope, and file bytes come
/// exclusively from the admitted immutable view.
///
/// # Errors
/// Refuses nonportable manifest paths, unavailable physical source or authority,
/// and changes to the exact source or its underlying directory identity.
pub fn observe_go_workspace(
    root: &Path,
    manifest_path: &str,
    read: impl FnOnce(&[u8]) -> GoWorkspaceReaderReply,
) -> Result<GoWorkspaceObservation, GoWorkspaceObservationError> {
    let directory = manifest_path
        .strip_suffix("go.work")
        .filter(|directory| directory.is_empty() || directory.ends_with('/'))
        .filter(|_| {
            manifest_path.len() <= MAX_PATH_BYTES && is_canonical_relative_path(manifest_path)
        })
        .ok_or(GoWorkspaceObservationError::InvalidManifestPath)?;
    let source = NativeSource::capture(root, "Go")?;
    let selected = source.view.bytes(manifest_path);
    let metadata = match selected {
        None => WorkspaceMetadata::Missing,
        Some(bytes) if bytes.len() > MAX_MANIFEST_BYTES => unavailable("RESOURCE_LIMIT"),
        Some(bytes) => inspect_reply(read(bytes), &source.view, directory),
    };
    let observation = GoWorkspaceObservation {
        schema: SCHEMA,
        schema_version: 1,
        scope: "STATIC_WORKSPACE_DECLARATIONS_ONLY",
        source_fingerprint: source.binding.source_fingerprint.clone(),
        source_view_digest: source.view.digest().to_owned(),
        source_manifest_digest: source.binding.source_manifest_digest.clone(),
        authority_digest: source.binding.authority_digest.clone(),
        manifest_path: manifest_path.to_owned(),
        manifest_sha256: selected.map(sha256),
        workspace_sum: bind_file(&source.view, format!("{directory}go.work.sum")),
        metadata,
        effective_workspace: "UNESTABLISHED",
    };
    source.revalidate()?;
    Ok(observation)
}

const fn unavailable(reason: &'static str) -> WorkspaceMetadata {
    WorkspaceMetadata::Unavailable { reason }
}

fn inspect_reply(
    reply: GoWorkspaceReaderReply,
    view: &SourceView,
    directory: &str,
) -> WorkspaceMetadata {
    let (json, formatted, executable_ref, version) = match reply {
        GoWorkspaceReaderReply::Invalid => return WorkspaceMetadata::Invalid,
        GoWorkspaceReaderReply::Unavailable => return unavailable("PINNED_READER_UNAVAILABLE"),
        GoWorkspaceReaderReply::Parsed {
            json,
            formatted,
            executable_ref,
            version,
        } => (json, formatted, executable_ref, version),
    };
    if !is_digest(&executable_ref) || !matches!(version.as_str(), "go1.22.2" | "go1.22.12") {
        return unavailable("INVALID_READER_OBSERVATION");
    }
    let limits = JsonAdmissionLimits {
        bytes: MAX_MANIFEST_BYTES,
        depth: 12,
        nodes: 8192,
        token_bytes: MAX_PATH_BYTES + 32,
    };
    if admit_json(&json, limits).is_err() || formatted.len() > MAX_MANIFEST_BYTES {
        return unavailable("RESOURCE_OR_READER_OUTPUT_LIMIT");
    }
    let Some(file) = std::str::from_utf8(&json)
        .ok()
        .and_then(|text| parse_public_json::<NativeWorkFile>(text).ok())
    else {
        return unavailable("INVALID_READER_OBSERVATION");
    };
    let Ok(toolchain_directive) = printed_toolchain(&formatted) else {
        return unavailable("INVALID_READER_OBSERVATION");
    };
    if file.go.as_deref().is_some_and(|go| !version_text(go)) {
        return unavailable("INVALID_READER_OBSERVATION");
    }
    let members = file.members.unwrap_or_default();
    let replacement_count = file.replacements.as_ref().map_or(0, Vec::len);
    if members.len() > MAX_MEMBERS || replacement_count > MAX_MEMBERS {
        return unavailable("RESOURCE_OR_READER_OUTPUT_LIMIT");
    }
    let workspace_membership = project_members(&members, view, directory);
    WorkspaceMetadata::Declared {
        go_version: file.go,
        toolchain_directive,
        reader_version: version,
        reader_executable_ref: executable_ref,
        workspace_membership,
        replacement_count,
    }
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|body| {
        body.len() == 64
            && body
                .bytes()
                .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(&character))
    })
}

fn version_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|part| part.is_ascii_alphanumeric() || matches!(part, b'.' | b'-' | b'_'))
}

fn printed_toolchain(formatted: &[u8]) -> Result<Option<String>, ()> {
    let text = std::str::from_utf8(formatted).map_err(|_| ())?;
    let mut selected = None;
    for line in text.lines() {
        if let Some(tail) = line.strip_prefix("toolchain") {
            let directive = tail.split_once("//").map_or(tail, |(before, _)| before);
            let fields = directive.split_whitespace().collect::<Vec<_>>();
            let [value] = fields.as_slice() else {
                return Err(());
            };
            if !tail.starts_with(char::is_whitespace) || !version_text(value) || selected.is_some()
            {
                return Err(());
            }
            selected = Some((*value).to_owned());
        }
    }
    Ok(selected)
}

fn bind_file(view: &SourceView, path: String) -> Option<FileBinding> {
    view.bytes(&path).map(|bytes| FileBinding {
        sha256: sha256(bytes),
        path,
    })
}

fn local_path(directory: &str, declared: &str) -> Option<String> {
    let portable = if declared == "." {
        ""
    } else {
        let relative = declared.strip_prefix("./").unwrap_or(declared);
        if !is_canonical_relative_path(relative) {
            return None;
        }
        relative
    };
    let name = if portable.is_empty() {
        format!("{directory}go.mod")
    } else {
        format!("{directory}{portable}/go.mod")
    };
    (name.len() <= MAX_PATH_BYTES).then_some(name)
}

fn project_members(
    members: &[NativeUse],
    view: &SourceView,
    directory: &str,
) -> Vec<WorkspaceMember> {
    let mut scoped = BTreeMap::<String, usize>::new();
    let mut unavailable = BTreeMap::new();
    for member in members {
        if let Some(path) = local_path(directory, &member.disk_path) {
            *scoped.entry(path).or_default() += 1;
        } else {
            let reference = sha256(member.disk_path.as_bytes());
            unavailable
                .entry(reference.clone())
                .or_insert(WorkspaceMember::UnresolvedPath {
                    declared_path_ref: reference,
                });
        }
    }
    scoped
        .into_iter()
        .map(|(path, count)| {
            if count != 1 {
                return WorkspaceMember::Ambiguous { path };
            }
            let sum_path = format!(
                "{}go.sum",
                path.strip_suffix("go.mod").expect("selected module path")
            );
            match bind_file(view, path.clone()) {
                Some(module) => WorkspaceMember::Observed {
                    module,
                    sum: bind_file(view, sum_path),
                },
                None => WorkspaceMember::MissingModule { path },
            }
        })
        .chain(unavailable.into_values())
        .collect()
}
