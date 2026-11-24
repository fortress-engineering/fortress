//! Scoped native filesystem lower facts using exact Operation Summary matching.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    OperationSummaryCatalog, OperationSummaryError, SummaryAuthorityClass, SummaryCompleteness,
    SummaryContext, SummaryEffectBound,
};
use crate::finding::FindingLocation;
use crate::program_semantics::ContextKnowledge;
use crate::semantic_analysis::FunctionEffect;

const CATALOG: &str = include_str!("../_data/native_filesystem_catalog_v1.json");
const MAX_SOURCE: usize = 64 << 10;
const MAX_SITES: usize = 64;
const MAX_METADATA: usize = 240;

/// Identity of the installed bytes that can affect native operation selection.
pub(crate) fn native_filesystem_catalog_source_ref() -> String {
    format!("sha256:{:x}", Sha256::digest(CATALOG.as_bytes()))
}

/// Native language associated with already verified call evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFilesystemLanguage {
    /// Exact Go source and selected standard-library declaration.
    Go,
    /// Exact `CPython` source and independently bound standard-library receiver.
    Python,
}

impl NativeFilesystemLanguage {
    fn extension(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "py",
        }
    }
}

/// Closed supported native declaration identity from a trusted observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFilesystemOperation {
    /// Native compiler resolved the actual standard Go os.WriteFile function.
    GoOsWriteFile,
    /// Exact Python pathlib declaration and concrete standard receiver are bound.
    PythonPathWriteBytes,
}

impl NativeFilesystemOperation {
    fn language(self) -> NativeFilesystemLanguage {
        match self {
            Self::GoOsWriteFile => NativeFilesystemLanguage::Go,
            Self::PythonPathWriteBytes => NativeFilesystemLanguage::Python,
        }
    }

    fn selector(self) -> &'static str {
        match self {
            Self::GoOsWriteFile => "go_stdlib::os::WriteFile",
            Self::PythonPathWriteBytes => "python_stdlib::pathlib::Path::write_bytes",
        }
    }
}

/// Exact context of the source-side call observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFilesystemBinding<'a> {
    /// Stabilized complete snapshot fingerprint.
    pub snapshot_fingerprint: &'a str,
    /// Exact selected immutable source-view digest.
    pub source_view_sha256: &'a str,
    /// Exact original governing authority digest.
    pub authority_sha256: &'a str,
    /// Exact selected evaluation and native compiler context digest.
    pub evaluation_sha256: &'a str,
    /// Exact repository-relative source artifact.
    pub source_path: &'a str,
    /// Exact source artifact bytes used by the observed positions.
    pub source_sha256: &'a str,
}

/// Native call classification established separately from filesystem effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemCallee<'a> {
    /// An exact, independently resolved standard declaration with scoped context.
    ResolvedStandardLibrary {
        /// Identity established from the native binding rather than source spelling.
        operation: NativeFilesystemOperation,
        /// Retained immutable declaration and target binding evidence.
        declaration_sha256: &'a str,
        /// Exact package source, toolchain, target, feature and type premises.
        summary_context: &'a SummaryContext,
    },
    /// A source-local declaration or a shadowed name with no catalog credit.
    LocalOrShadowed,
    /// An indirect or dynamic callee whose standard identity is unestablished.
    Unresolved,
}

/// One already admitted physical call site within its exact source buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFilesystemCall<'a> {
    /// Inclusive UTF-8 byte offset, relative to the exact source file.
    pub start_byte: usize,
    /// Exclusive UTF-8 byte offset, relative to the exact source file.
    pub end_byte: usize,
    /// Already admitted callee identity facts or an explicit unresolved state.
    pub callee: NativeFilesystemCallee<'a>,
}

/// Source-bound input supplied by the exact native observation owner.
///
/// This port accepts typed already admitted observations. Native call
/// binding, declarations and standard-library ownership remain with their
/// respective observers. This is not a wire parser for unauthenticated data.
pub struct NativeFilesystemBatch<'a> {
    /// Native language and observer family.
    pub language: NativeFilesystemLanguage,
    /// Exact immutable source and authority admitted by the caller.
    pub binding: NativeFilesystemBinding<'a>,
    /// Exact native observation receipt identity.
    pub observation_sha256: &'a str,
    /// Bounded call observations within the single selected artifact.
    pub calls: &'a [NativeFilesystemCall<'a>],
}

/// Disposition of one source-level effect observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeFilesystemDisposition<'a> {
    /// One exact catalog row establishes a scoped positive operation effect.
    ModeledOperation {
        /// Exact reviewed operation-context identity.
        operation: NativeFilesystemOperation,
        /// Digest of the native declaration binding evidence.
        declaration_sha256: &'a str,
        /// Actual observed context selecting the one catalog row.
        context: &'a SummaryContext,
        /// Selected row in the reviewed scoped catalog.
        summary_id: String,
        /// Positive lower facts conditional on the actual operation taking place.
        effects: Vec<FunctionEffect>,
        /// Source-bound reviewed qualification references.
        qualification_refs: Vec<String>,
    },
    /// The exact standard operation did not match any supported context.
    ContextUnavailable {
        /// Standard declaration under evaluation.
        operation: NativeFilesystemOperation,
        /// Exact retained declaration evidence for this unresolved context.
        declaration_sha256: &'a str,
        /// Actual presented context, including independent unknown premises.
        context: &'a SummaryContext,
        /// Existing catalog reasons for failing to select a row.
        reasons: Vec<String>,
    },
    /// A distinct local or shadowed binding.
    LocalOrShadowed,
    /// Native call resolution could not establish a target.
    Unresolved,
}

/// Scoped filesystem effect receipt at a physical source occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFilesystemSite<'a> {
    start_byte: usize,
    end_byte: usize,
    disposition: NativeFilesystemDisposition<'a>,
}

impl<'a> NativeFilesystemSite<'a> {
    /// Returns the independently scoped effect disposition.
    #[must_use]
    pub const fn disposition(&self) -> &NativeFilesystemDisposition<'a> {
        &self.disposition
    }

    /// Returns the exact physical UTF-8 byte range.
    #[must_use]
    pub fn byte_range(&self) -> std::ops::Range<usize> {
        self.start_byte..self.end_byte
    }
}

/// Standalone positive-operation sidecar, independent of state/effect enforcement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFilesystemProjection<'a> {
    adapter_version: u16,
    binding: NativeFilesystemBinding<'a>,
    language: NativeFilesystemLanguage,
    observation_sha256: &'a str,
    catalog_sha256: String,
    upper_bound: SummaryEffectBound,
    scope: &'static str,
    sites: Vec<NativeFilesystemSite<'a>>,
}

impl<'a> NativeFilesystemProjection<'a> {
    /// Returns all bounded sites in exact source order.
    #[must_use]
    pub fn sites(&self) -> &[NativeFilesystemSite<'a>] {
        &self.sites
    }

    /// Returns the independent source, context, and original authority binding.
    #[must_use]
    pub const fn binding(&self) -> NativeFilesystemBinding<'a> {
        self.binding
    }

    /// Returns the whole-operation bound, conservatively unknown.
    #[must_use]
    pub const fn upper_bound(&self) -> &SummaryEffectBound {
        &self.upper_bound
    }
}

/// One admitted call shape under an explicitly selected hypothetical `CPython` model.
///
/// Snapshot Governance supplies the exact original source, authority, and scope.
/// A trusted host separately supplies exact isolated installed origin and
/// startup assumptions. A receipt, digest, or source-only observation cannot
/// establish these premises. This input has no actual callee or write authority.
#[derive(Clone, Copy, Debug)]
pub struct HypotheticalPythonFilesystemCall<'a> {
    /// Exact independently observed original source endpoint.
    pub binding: NativeFilesystemBinding<'a>,
    /// Receipt for the source-bearing compile-only observation.
    pub source_observation_sha256: &'a str,
    /// Explicit ordered original import scope, after checking for local alternatives.
    pub source_scope_sha256: &'a str,
    /// Independently observed isolated installed import origin.
    pub installed_origin_sha256: &'a str,
    /// Explicit independently selected closed startup and invocation assumptions.
    pub startup_assumptions_sha256: &'a str,
    /// Exact installed declaration and concrete receiver evidence.
    pub declaration_sha256: &'a str,
    /// Existing exact package, toolchain, target, feature, and receiver premises.
    pub summary_context: &'a SummaryContext,
    /// Inclusive and exclusive UTF-8 byte offsets of the exact observed call.
    pub site: [usize; 2],
}

/// Conditional catalog evidence for the selected closed model only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HypotheticalPythonFilesystemProjection<'a> {
    model_version: u16,
    scope: &'static str,
    condition: &'static str,
    binding: NativeFilesystemBinding<'a>,
    source_observation_sha256: &'a str,
    source_scope_sha256: &'a str,
    installed_origin_sha256: &'a str,
    startup_assumptions_sha256: &'a str,
    site: [usize; 2],
    catalog_sha256: String,
    catalog_disposition: NativeFilesystemDisposition<'a>,
    actual_project_binding: &'static str,
    execution: &'static str,
    filesystem_result: &'static str,
    authorization: &'static str,
    upper_bound: SummaryEffectBound,
}

impl<'a> HypotheticalPythonFilesystemProjection<'a> {
    /// Original UTF-8 byte extent of the method call under the closed model.
    #[must_use]
    pub const fn site(&self) -> [usize; 2] {
        self.site
    }

    /// Existing catalog resolution under the independently selected assumptions.
    #[must_use]
    pub const fn catalog_disposition(&self) -> &NativeFilesystemDisposition<'a> {
        &self.catalog_disposition
    }
}

/// Failure at the narrow native effect observation boundary.
#[derive(Debug)]
pub enum NativeFilesystemError {
    /// Exact source, authority, or evaluation identities do not agree.
    BindingMismatch,
    /// Immutable source bytes do not match the admitted digest.
    SourceMismatch,
    /// A source site or typed declaration context is malformed.
    InvalidObservation,
    /// The input exceeds a fixed source or observation bound.
    ResourceLimit,
    /// The compiled scoped catalog fails the existing catalog reader.
    Catalog(OperationSummaryError),
    /// The reviewed scoped row would exceed the adapter's observation authority.
    CatalogScope,
}

impl std::fmt::Display for NativeFilesystemError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingMismatch => formatter.write_str("native filesystem binding mismatch"),
            Self::SourceMismatch => formatter.write_str("native filesystem source digest mismatch"),
            Self::InvalidObservation => {
                formatter.write_str("malformed native filesystem observation")
            }
            Self::ResourceLimit => formatter.write_str("native filesystem resource limit"),
            Self::Catalog(error) => write!(formatter, "invalid native operation catalog: {error}"),
            Self::CatalogScope => {
                formatter.write_str("native operation catalog exceeds scoped authority")
            }
        }
    }
}

impl std::error::Error for NativeFilesystemError {}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn bounded_string(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_METADATA
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn context_shape(context: &SummaryContext) -> bool {
    (match &context.source_digest {
        ContextKnowledge::Known(value) => digest(value),
        ContextKnowledge::Unknown => true,
    }) && [&context.version, &context.target]
        .into_iter()
        .all(|input| match input {
            ContextKnowledge::Known(value) => bounded_string(value),
            ContextKnowledge::Unknown => true,
        })
        && [&context.features, &context.type_bindings]
            .into_iter()
            .all(|input| match input {
                ContextKnowledge::Known(values) => {
                    values.len() <= 8
                        && values.iter().all(|value| bounded_string(value))
                        && values.windows(2).all(|pair| pair[0] < pair[1])
                }
                ContextKnowledge::Unknown => true,
            })
}

fn validate_source<'a>(
    expected: NativeFilesystemBinding<'_>,
    admitted: &NativeFilesystemBatch<'_>,
    source: &'a [u8],
) -> Result<&'a str, NativeFilesystemError> {
    if expected != admitted.binding
        || ![
            expected.snapshot_fingerprint,
            expected.source_view_sha256,
            expected.authority_sha256,
            expected.evaluation_sha256,
            expected.source_sha256,
            admitted.observation_sha256,
        ]
        .into_iter()
        .all(digest)
    {
        return Err(NativeFilesystemError::BindingMismatch);
    }
    if source.len() > MAX_SOURCE || admitted.calls.len() > MAX_SITES {
        return Err(NativeFilesystemError::ResourceLimit);
    }
    if expected.source_path.len() > MAX_METADATA
        || Path::new(expected.source_path).extension()
            != Some(OsStr::new(admitted.language.extension()))
        || FindingLocation::at_path(expected.source_path).is_err()
    {
        return Err(NativeFilesystemError::InvalidObservation);
    }
    if format!("sha256:{:x}", Sha256::digest(source)) != expected.source_sha256 {
        return Err(NativeFilesystemError::SourceMismatch);
    }
    std::str::from_utf8(source).map_err(|_| NativeFilesystemError::InvalidObservation)
}

fn classify<'a>(
    language: NativeFilesystemLanguage,
    catalog: &OperationSummaryCatalog,
    callee: NativeFilesystemCallee<'a>,
) -> Result<NativeFilesystemDisposition<'a>, NativeFilesystemError> {
    let (operation, declaration_sha256, context) = match callee {
        NativeFilesystemCallee::ResolvedStandardLibrary {
            operation,
            declaration_sha256,
            summary_context,
        } => (operation, declaration_sha256, summary_context),
        NativeFilesystemCallee::LocalOrShadowed => {
            return Ok(NativeFilesystemDisposition::LocalOrShadowed);
        }
        NativeFilesystemCallee::Unresolved => return Ok(NativeFilesystemDisposition::Unresolved),
    };
    classify_standard(language, catalog, operation, declaration_sha256, context)
}

fn classify_standard<'a>(
    language: NativeFilesystemLanguage,
    catalog: &OperationSummaryCatalog,
    operation: NativeFilesystemOperation,
    declaration_sha256: &'a str,
    context: &'a SummaryContext,
) -> Result<NativeFilesystemDisposition<'a>, NativeFilesystemError> {
    if language != operation.language() || !digest(declaration_sha256) || !context_shape(context) {
        return Err(NativeFilesystemError::InvalidObservation);
    }
    let identity = operation.selector();
    // The general observed_effects selector unions all rows with that name.
    // This projection needs precisely the row selected under exact premises.
    let decision = catalog.resolve(identity, context, &BTreeMap::new(), None);
    let Some(summary_id) = decision.selected_summary_id else {
        return Ok(NativeFilesystemDisposition::ContextUnavailable {
            operation,
            declaration_sha256,
            context,
            reasons: decision.reasons,
        });
    };
    let chosen = catalog
        .summaries()
        .iter()
        .find(|row| row.id == summary_id)
        .ok_or(NativeFilesystemError::CatalogScope)?;
    if chosen.operation_selector != identity
        || chosen.authority_class != SummaryAuthorityClass::Observed
        || chosen.completeness != SummaryCompleteness::Partial
        || chosen.effect_upper_bound != SummaryEffectBound::Unknown
        || decision.upper_bound != SummaryEffectBound::Unknown
        || chosen.observed_effects != [FunctionEffect::FilesystemWrite]
        || chosen.qualification_refs.is_empty()
    {
        return Err(NativeFilesystemError::CatalogScope);
    }
    Ok(NativeFilesystemDisposition::ModeledOperation {
        operation,
        declaration_sha256,
        context,
        summary_id,
        effects: chosen.observed_effects.clone(),
        qualification_refs: chosen.qualification_refs.clone(),
    })
}

/// Selects the existing exact Python operation summary under a hypothetical model.
///
/// Invoking the exact bound function and reaching the call with its independently
/// selected startup assumptions are conditions of the observation. Neither the
/// call nor any project code executes here. This projection does not produce an
/// actual call site, a write result, or authority. Ordinary source-only
/// observation cannot supply the independently admitted inputs.
///
/// # Errors
/// Refuses malformed premise identities, source, ranges, or catalog entries.
pub fn project_hypothetical_python_filesystem<'a>(
    expected: NativeFilesystemBinding<'_>,
    source: &[u8],
    proposed: &HypotheticalPythonFilesystemCall<'a>,
) -> Result<HypotheticalPythonFilesystemProjection<'a>, NativeFilesystemError> {
    let language = NativeFilesystemLanguage::Python;
    // Reuse exact source admission. No actual callee or actual site is formed.
    let batch = NativeFilesystemBatch {
        language,
        binding: proposed.binding,
        observation_sha256: proposed.source_observation_sha256,
        calls: &[],
    };
    let text = validate_source(expected, &batch, source)?;
    if ![
        proposed.source_scope_sha256,
        proposed.installed_origin_sha256,
        proposed.startup_assumptions_sha256,
    ]
    .into_iter()
    .all(digest)
        || text
            .get(proposed.site[0]..proposed.site[1])
            .is_none_or(str::is_empty)
    {
        return Err(NativeFilesystemError::InvalidObservation);
    }
    let catalog =
        OperationSummaryCatalog::from_json_str(CATALOG).map_err(NativeFilesystemError::Catalog)?;
    let disposition = classify_standard(
        language,
        &catalog,
        NativeFilesystemOperation::PythonPathWriteBytes,
        proposed.declaration_sha256,
        proposed.summary_context,
    )?;
    Ok(HypotheticalPythonFilesystemProjection {
        model_version: 1,
        scope: "HYPOTHETICAL_CLOSED_REFERENCE_ONLY",
        condition: "BOUND_FUNCTION_INVOKED_UNDER_CLOSED_ASSUMPTIONS_AND_REACHES_METHOD_CALL",
        binding: proposed.binding,
        source_observation_sha256: proposed.source_observation_sha256,
        source_scope_sha256: proposed.source_scope_sha256,
        installed_origin_sha256: proposed.installed_origin_sha256,
        startup_assumptions_sha256: proposed.startup_assumptions_sha256,
        site: proposed.site,
        catalog_sha256: catalog.digest().into(),
        catalog_disposition: disposition,
        actual_project_binding: "UNESTABLISHED",
        execution: "NOT_RUN_BY_ANALYSIS",
        filesystem_result: "UNESTABLISHED",
        authorization: "NOT_ESTABLISHED",
        upper_bound: SummaryEffectBound::Unknown,
    })
}

/// Projects exact native filesystem operation evidence through the reviewed scoped catalog.
///
/// There is no runtime or whole-operation claim. Empty and unknown results
/// convey no negative filesystem conclusion. Ordinary canonical effect
/// analysis continues to use its independently installed catalog.
///
/// # Errors
///
/// Refuses inexact source and authority, malformed or excessive input,
/// and catalogs or records outside the positive-only observation scope.
pub fn project_native_filesystem_effects<'a>(
    expected: NativeFilesystemBinding<'_>,
    source: &[u8],
    admitted: &NativeFilesystemBatch<'a>,
) -> Result<NativeFilesystemProjection<'a>, NativeFilesystemError> {
    let text = validate_source(expected, admitted, source)?;
    let catalog =
        OperationSummaryCatalog::from_json_str(CATALOG).map_err(NativeFilesystemError::Catalog)?;
    let mut sites = Vec::with_capacity(admitted.calls.len());
    let mut seen = BTreeSet::new();
    for call in admitted.calls {
        if text
            .get(call.start_byte..call.end_byte)
            .is_none_or(str::is_empty)
            || !seen.insert((call.start_byte, call.end_byte))
        {
            return Err(NativeFilesystemError::InvalidObservation);
        }
        let disposition = classify(admitted.language, &catalog, call.callee)?;
        sites.push(NativeFilesystemSite {
            start_byte: call.start_byte,
            end_byte: call.end_byte,
            disposition,
        });
    }
    sites.sort_unstable_by_key(|site| (site.start_byte, site.end_byte));
    Ok(NativeFilesystemProjection {
        adapter_version: 1,
        binding: admitted.binding,
        language: admitted.language,
        observation_sha256: admitted.observation_sha256,
        catalog_sha256: catalog.digest().into(),
        upper_bound: SummaryEffectBound::Unknown,
        scope: "scoped_positive_operation_only_execution_and_absence_unestablished",
        sites,
    })
}
