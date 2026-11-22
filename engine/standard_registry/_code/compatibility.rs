//! Exact declared reader capabilities, independently installed with this runtime.

use serde::{Deserialize, Serialize};

use crate::wire::{WireError, parse_public_json};

const CATALOG: &str = include_str!("../_data/compatibility_catalog_v1.json");

/// Exact bytes of the installed catalog whose capabilities are reported.
#[must_use]
pub const fn installed_compatibility_source() -> &'static str {
    CATALOG
}

/// Declared capability state of an exact installed edition of a wire shape.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReaderStatus {
    /// A currently active installed reader.
    Active,
    /// A real installed reader was catalogued.
    Supported,
    /// Shape validation exists, but no qualifying runtime reader is claimed.
    SchemaOnly,
    /// Only test consumers are known.
    TestOnly,
    /// Interpretation by this runtime is unavailable.
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Capability<T> {
    status: T,
    source: Option<String>,
}

/// Installed historical identity or content-hash algorithm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Algorithm {
    /// Exact algorithm name recorded by the owner.
    pub id: String,
    /// Existing implementation authority when available.
    pub source: Option<String>,
}

/// One exact schema declaration and its installed capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEntry {
    /// Exact named schema. Edition numbers do not imply compatibility.
    pub schema_id: String,
    /// Canonical schema authority path in the installed inventory.
    pub schema_path: String,
    /// Shape version declared in the installed compatibility catalog.
    pub version: u16,
    writer: Capability<String>,
    reader: Capability<ReaderStatus>,
    migration: String,
    /// Original identity algorithm, kept independent from current serialization.
    pub identity_algorithm: Algorithm,
    /// Exact content-hash algorithm applicable to the historical record.
    pub content_hash_algorithm: Algorithm,
}

impl CompatibilityEntry {
    /// Returns the installed reader classification.
    #[must_use]
    pub const fn reader_status(&self) -> ReaderStatus {
        self.reader.status
    }

    /// A runtime reader is declared for this exact shape.
    #[must_use]
    pub const fn has_runtime_reader(&self) -> bool {
        matches!(
            self.reader_status(),
            ReaderStatus::Active | ReaderStatus::Supported
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    entries: Vec<CompatibilityEntry>,
}

/// Parses the installed compatibility authority. Project-supplied copies cannot select capabilities.
///
/// # Errors
/// Reports invalid installed authority bytes, unknown reader status or duplicate identities.
pub fn installed_compatibility() -> Result<Vec<CompatibilityEntry>, WireError> {
    let catalog: Catalog = parse_public_json(CATALOG)?;
    if catalog.schema != "urn:fortress:schema:v1:compatibility-catalog"
        || catalog.schema_version != 1
        || has_duplicate_entries(&catalog.entries)
    {
        return Err(WireError::Canonical(
            "invalid installed compatibility catalog".into(),
        ));
    }
    Ok(catalog.entries)
}

fn has_duplicate_entries(entries: &[CompatibilityEntry]) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    entries.iter().any(|entry| !ids.insert(&entry.schema_id))
}
