//! Source Architecture's shared projection of verified native file observations.

use serde::Serialize;
use serde_json::Value;

use super::{SourceObservation, SourceRegion, compile_regions_with};

const SCHEMA: &str = "urn:fortress:derived:v1:native-source-regions";

/// Availability of the selected native observation, independent of region coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeRegionAvailability {
    /// The selected compiler reported scoped observations.
    Observed,
    /// The selected compiler reported observations with limited scope.
    Partial,
    /// The selected parser reported syntax alone.
    SyntaxOnly,
    /// The admitted compiler rejected the selected input.
    InvalidSource,
    /// The selected observation scope is unsupported.
    Unsupported,
    /// The host or another necessary observation premise was unavailable.
    Unavailable,
    /// The compiler reported a bounded resource refusal.
    ResourceLimit,
}

/// Optional analysis-only annotation from the selected native layout extension.
#[derive(Debug, Serialize)]
pub struct NativeRegionLayout {
    pub(crate) layout_report_ref: String,
    pub(crate) authority: &'static str,
    pub(crate) entry: Value,
    pub(crate) selected_profile: Option<Value>,
}

/// Source and receipt identities independently captured by Snapshot Governance.
pub(crate) struct NativeRegionBinding<'a> {
    pub(crate) language: &'static str,
    pub(crate) path: &'a str,
    pub(crate) source_ref: String,
    pub(crate) source_view_ref: &'a str,
    pub(crate) source_manifest_ref: &'a str,
    pub(crate) original_authority_ref: &'a str,
    pub(crate) native_receipt_ref: String,
}

/// Source-semantic regions for one exact ordinary file and one admitted native receipt.
///
/// This observational projection supplies no ownership, profile selection,
/// finding, enforcement or certification authority.
#[derive(Debug, Serialize)]
pub struct NativeSourceRegions {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    language: &'static str,
    path: String,
    source_ref: String,
    source_view_ref: String,
    source_manifest_ref: String,
    original_authority_ref: String,
    native_receipt_ref: String,
    availability: NativeRegionAvailability,
    regions: Vec<SourceRegion>,
    layout: Option<NativeRegionLayout>,
}

impl NativeSourceRegions {
    pub(crate) fn project(
        binding: NativeRegionBinding<'_>,
        availability: NativeRegionAvailability,
        observations: &[SourceObservation],
        layout: Option<NativeRegionLayout>,
    ) -> Self {
        Self {
            schema: SCHEMA,
            schema_version: 1,
            language: binding.language,
            path: binding.path.to_owned(),
            source_ref: binding.source_ref,
            source_view_ref: binding.source_view_ref.to_owned(),
            source_manifest_ref: binding.source_manifest_ref.to_owned(),
            original_authority_ref: binding.original_authority_ref.to_owned(),
            native_receipt_ref: binding.native_receipt_ref,
            availability,
            // Authored responsibility, ownership and verification require separate
            // premises. This observation is deliberately independent of them.
            regions: compile_regions_with(observations, |_| None),
            layout,
        }
    }

    /// Returns only the compiler's admitted observation availability.
    #[must_use]
    pub const fn availability(&self) -> NativeRegionAvailability {
        self.availability
    }

    /// Returns region coverage with references into the exact input receipt.
    #[must_use]
    pub fn regions(&self) -> &[SourceRegion] {
        &self.regions
    }
}

/// Returns the registered schema for the scoped native region observation.
#[must_use]
pub const fn native_source_region_schema() -> &'static str {
    include_str!("../_data/native_region_schema_v1.json")
}
