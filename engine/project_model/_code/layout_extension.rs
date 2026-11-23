//! Explicitly selected native layout observations over the existing Project Filing model.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::wire::{JsonAdmissionLimits, admit_json, parse_public_json};

use super::{
    FILING_MODEL_SEMANTIC_VERSION, FilingSystemProfiles, RootEntryKind, is_portable_repository_path,
};

const ROLE: crate::control_layout::ExtensionInputRole =
    crate::control_layout::ExtensionInputRole::NativeLayout;
const REPORT: &str = "urn:fortress:schema:v1:layout-extension-report";

/// One immutable analysis-only profile definition loaded from an explicit digest pin.
#[derive(Debug)]
pub struct LayoutExtension {
    definition: Definition,
    digest: String,
}

/// Transport-neutral path observation supplied by the existing physical observer.
pub struct ObservedLayoutPath<'a> {
    /// Exact portable observed path.
    pub path: &'a str,
    /// Explicit barrier when the observer could not inspect ordinary bytes.
    pub limitation: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    id: String,
    version: String,
    filing_model: String,
    mode: String,
    ecosystem: String,
    marker: String,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    kind: RootEntryKind,
    role: NativeRole,
    opaque: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum NativeRole {
    Source,
    Configuration,
    Documentation,
    Test,
    Asset,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

fn version(value: &str) -> bool {
    value.split('.').count() == 3
        && value
            .split('.')
            .all(|part| part.parse::<u16>().is_ok_and(|n| n.to_string() == part))
}

impl LayoutExtension {
    /// Admits exact pinned bytes rather than discovering extension files in the candidate.
    ///
    /// # Errors
    ///
    /// Refuses unsupported versions, capabilities, unsafe names, and invalid pins.
    pub fn from_pinned_bytes(bytes: &[u8], expected: &str) -> Result<Self, String> {
        admit_json(
            bytes,
            JsonAdmissionLimits {
                bytes: ROLE.definition_bytes(),
                depth: 8,
                nodes: 4096,
                token_bytes: 256,
            },
        )
        .map_err(|error| error.to_string())?;
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        if expected != digest {
            return Err("LAYOUT_EXTENSION_DIGEST_MISMATCH".into());
        }
        let source = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let definition: Definition = parse_public_json(source).map_err(|e| e.to_string())?;
        definition.validate()?;
        Ok(Self { definition, digest })
    }
}

impl Definition {
    fn validate(&self) -> Result<(), String> {
        if self.schema != ROLE.schema()
            || self.schema_version != 1
            || self.filing_model != FILING_MODEL_SEMANTIC_VERSION
            || self.mode != "NATIVE_ANALYSIS"
        {
            return Err("UNSUPPORTED_LAYOUT_EXTENSION: schema, filing model or mode".into());
        }
        if !label(&self.id) || !label(&self.ecosystem) || !version(&self.version) {
            return Err("INVALID_LAYOUT_IDENTITY".into());
        }
        if self.entries.is_empty() || self.entries.len() > 128 {
            return Err("INVALID_LAYOUT_ENTRY_COUNT".into());
        }
        let standard = FilingSystemProfiles::standard();
        let protected = standard
            .profiles()
            .iter()
            .flat_map(|p| &p.root_entries)
            .map(|entry| entry.path.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let mut entries = BTreeSet::new();
        for entry in &self.entries {
            let folded = entry.path.to_ascii_lowercase();
            if !entry.path.is_ascii()
                || !is_portable_repository_path(&entry.path)
                || entry.path.contains('/')
                || entry.path.starts_with('_')
                || protected.contains(&folded)
                || matches!(folded.as_str(), ".git" | "readme.md" | "contract.json")
                || entry.opaque != (entry.kind == RootEntryKind::Directory)
            {
                return Err(format!(
                    "INVALID_LAYOUT_ENTRY: {}",
                    crate::wire::readable_text(&entry.path)
                ));
            }
            if !entries.insert(folded) {
                return Err("CONFLICTING_LAYOUT_ENTRY".into());
            }
        }
        if !self
            .entries
            .iter()
            .any(|e| e.path == self.marker && e.kind == RootEntryKind::File)
        {
            return Err("INVALID_LAYOUT_MARKER".into());
        }
        Ok(())
    }
}

/// Reports explicitly selected native roles against immutable physical observation.
///
/// The projection preserves the Standard-owned Module index and does not modify
/// source admission, authored bindings, canonical filing, or certification.
///
/// # Errors
///
/// Refuses colliding identities, overlapping entries and canonical Module shadows.
pub fn inspect_layout_extensions(
    observation: &[ObservedLayoutPath<'_>],
    observation_digest: &str,
    profiles: &[LayoutExtension],
) -> Result<Value, String> {
    if profiles.is_empty() || profiles.len() > 16 {
        return Err("INVALID_LAYOUT_SELECTION_COUNT".into());
    }
    let mut selected = BTreeMap::new();
    let mut entries = BTreeMap::new();
    let mut folded = BTreeSet::new();
    for profile in profiles {
        let def = &profile.definition;
        if selected.insert(def.id.as_str(), profile).is_some() {
            return Err("DUPLICATE_LAYOUT_ID".into());
        }
        for entry in &def.entries {
            if !folded.insert(entry.path.to_ascii_lowercase()) {
                return Err("CONFLICTING_LAYOUT_ENTRY".into());
            }
            entries.insert(entry.path.as_str(), (def, entry));
        }
    }
    let paths = observation
        .iter()
        .filter(|entry| entry.limitation.is_none())
        .map(|entry| entry.path)
        .collect::<BTreeSet<_>>();
    let standard = FilingSystemProfiles::standard();
    let modules = crate::module_index::CanonicalModuleIndex::from_paths(
        paths.iter().copied(),
        |module, name| standard.registered_directory(module, name),
    );
    if modules.entries().keys().any(|module| {
        module
            .split('/')
            .next()
            .is_some_and(|part| folded.contains(&part.to_ascii_lowercase()))
    }) {
        return Err("LAYOUT_SHADOWS_CANONICAL_MODULE".into());
    }
    let profiles = selected.values().map(|profile| {
        let def = &profile.definition;
        json!({
            "id": def.id, "version": def.version, "digest": profile.digest,
            "ecosystem": def.ecosystem, "marker": def.marker,
            "applicability": if paths.contains(def.marker.as_str()) { "OBSERVED_MARKER" } else { "UNESTABLISHED_MARKER" }
        })
    }).collect::<Vec<_>>();
    let mut rows = Vec::new();
    for observed in observation {
        let path = observed.path;
        let (root, nested) = path
            .split_once('/')
            .map_or((path, false), |(root, _)| (root, true));
        let mut state = "UNCLASSIFIED";
        let (mut profile_id, mut role) = (None, None);
        if observed.limitation.is_some() {
            state = "NOT_OBSERVED";
        } else if let Some((profile, entry)) = entries.get(root) {
            profile_id = Some(profile.id.as_str());
            if !paths.contains(profile.marker.as_str()) {
                state = "UNESTABLISHED_MARKER";
            } else if nested == (entry.kind == RootEntryKind::Directory) {
                state = "CLASSIFIED";
                role = Some(entry.role);
            } else {
                state = "UNSUPPORTED_ENTRY_KIND";
            }
        }
        rows.push(json!({
            "path": path, "state": state, "profile": profile_id, "role": role,
            "observation_limitation": observed.limitation
        }));
    }
    Ok(json!({
        "$schema": REPORT, "schema_version": 1, "authority": ROLE.authority(),
        "observation_digest": observation_digest,
        "canonical_module_paths": modules.entries().keys().collect::<Vec<_>>(),
        "profiles": profiles, "entries": rows
    }))
}
