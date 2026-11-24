//! Exact current-source projection of previously admitted Go and Python receipts.

use std::path::Path;

use crate::affected_analysis::sha256;
use crate::filing::{LayoutExtension, ObservedLayoutPath, inspect_layout_extensions};
use crate::go_observation::{GoNativeModuleObservation, GoNativeObservation};
use crate::native_observation::{NativeSource, NativeSourceError};
use crate::observation::is_canonical_relative_path;
use crate::program_semantics::go_observation::Status as GoStatus;
use crate::python_observation::{ActualPythonLexicalObservation, PythonLexicalOutcome};
use crate::source_architecture::native_regions::{NativeRegionBinding, NativeRegionLayout};
use crate::source_architecture::{RegionCoverage, SemanticRegion, SourceObservation};

pub use crate::source_architecture::native_regions::{
    NativeRegionAvailability, NativeSourceRegions,
};

const GO_ANALYZER: &str = "fortress-core/go-declaration-regions-v1";
const PYTHON_ANALYZER: &str = "fortress-core/python-lexical-regions-v1";

/// Independently admitted actual-state receipt selected for a source region projection.
#[derive(Clone, Copy)]
pub enum NativeRegionInput<'a> {
    /// The closed Go declaration and call observation.
    Go(&'a GoNativeObservation),
    /// Exact selected declarations and import sites of the admitted native Go module.
    GoModule(&'a GoNativeModuleObservation),
    /// The admitted Python compile-only observation.
    Python(&'a ActualPythonLexicalObservation),
}

impl NativeRegionInput<'_> {
    const fn language(self) -> &'static str {
        match self {
            Self::Go(_) | Self::GoModule(_) => "go",
            Self::Python(_) => "python",
        }
    }
}

/// Failure to project one exact current source file.
#[derive(Debug)]
pub enum NativeRegionError {
    /// The selected file path could not identify one safe physical source entry.
    InvalidPath,
    /// The selected path did not have ordinary source bytes in the current view.
    MissingSource,
    /// The selected file is outside the admitted receipt's subject or language.
    SubjectMismatch,
    /// The retained receipt refers to a different original source or authority.
    StaleReceipt,
    /// Physical source or original authority could not be captured.
    SourceUnavailable(String),
    /// The selected analysis-only layout could not be resolved.
    LayoutUnavailable(String),
    /// The verified receipt or output identity could not be encoded.
    Encoding(serde_json::Error),
}

impl From<NativeSourceError> for NativeRegionError {
    fn from(error: NativeSourceError) -> Self {
        match error {
            NativeSourceError::Unavailable(detail) => Self::SourceUnavailable(detail),
            NativeSourceError::Changed => Self::StaleReceipt,
        }
    }
}

impl std::fmt::Display for NativeRegionError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => {
                output.write_str("expected canonical repository-relative source path")
            }
            Self::MissingSource => output.write_str("selected source bytes are missing"),
            Self::SubjectMismatch => {
                output.write_str("selected source is outside the admitted native receipt")
            }
            Self::StaleReceipt => {
                output.write_str("native receipt or captured source is no longer current")
            }
            Self::SourceUnavailable(detail) | Self::LayoutUnavailable(detail) => {
                output.write_str(detail)
            }
            Self::Encoding(error) => error.fmt(output),
        }
    }
}

impl std::error::Error for NativeRegionError {}

/// Reports source region coverage for a previously admitted actual native receipt.
///
/// This projection reobserves the exact original physical source and authority.
/// Optional layout roles come from the explicitly supplied pinned profiles and
/// remain analysis-only. This workflow performs no compiler invocation, policy
/// selection, ownership inference, certification or source mutation.
///
/// # Errors
/// Refuses unavailable or stale inputs, mismatched subjects, invalid layout
/// selection and serialization failures.
pub fn project_native_source_regions(
    project_root: &Path,
    source_path: &str,
    input: NativeRegionInput<'_>,
    layouts: &[LayoutExtension],
) -> Result<NativeSourceRegions, NativeRegionError> {
    if !is_canonical_relative_path(source_path) {
        return Err(NativeRegionError::InvalidPath);
    }
    let source = NativeSource::capture(project_root, input.language())?;
    let bytes = source
        .view
        .bytes(source_path)
        .ok_or(NativeRegionError::MissingSource)?;
    let source_ref = sha256(bytes);
    let (availability, receipt, observations) = match input {
        NativeRegionInput::Go(admitted) => go_regions(&source, source_path, &source_ref, admitted)?,
        NativeRegionInput::GoModule(admitted) => {
            go_module_regions(&source, source_path, &source_ref, admitted)?
        }
        NativeRegionInput::Python(admitted) => {
            python_regions(&source, source_path, &source_ref, admitted)?
        }
    };
    let layout = resolve_layout(&source, source_path, layouts)?;
    let projection = NativeSourceRegions::project(
        NativeRegionBinding {
            language: input.language(),
            path: source_path,
            source_ref,
            source_view_ref: source.view.digest(),
            source_manifest_ref: &source.binding.source_manifest_digest,
            original_authority_ref: &source.binding.authority_digest,
            native_receipt_ref: receipt,
        },
        availability,
        &observations,
        layout,
    );
    source.revalidate()?;
    Ok(projection)
}

type Regions = (NativeRegionAvailability, String, Vec<SourceObservation>);

fn go_regions(
    source: &NativeSource<'_>,
    path: &str,
    source_ref: &str,
    admitted: &GoNativeObservation,
) -> Result<Regions, NativeRegionError> {
    let selected = admitted
        .source_digest(path)
        .ok_or(NativeRegionError::SubjectMismatch)?;
    if selected != source_ref
        || !admitted.matches_actual_source(source.view.digest(), &source.binding.authority_digest)
    {
        return Err(NativeRegionError::StaleReceipt);
    }
    let availability = go_availability(admitted.status())?;
    let receipt = hash_receipt(admitted)?;
    let observations = go_declarations(
        path,
        admitted
            .declaration_regions(path)
            .map(|(index, line, has_body)| {
                (
                    format!("{receipt}#/observation/declarations/{index}"),
                    line,
                    has_body,
                )
            }),
    );
    Ok((availability, receipt, observations))
}

fn go_module_regions(
    source: &NativeSource<'_>,
    path: &str,
    source_ref: &str,
    admitted: &GoNativeModuleObservation,
) -> Result<Regions, NativeRegionError> {
    let (received, selected) = admitted
        .region_source(path)
        .ok_or(NativeRegionError::SubjectMismatch)?;
    if received != source_ref
        || !admitted.matches_actual_source(source.view.digest(), &source.binding.authority_digest)
    {
        return Err(NativeRegionError::StaleReceipt);
    }
    let receipt = hash_receipt(admitted)?;
    let availability = go_availability(admitted.status())?;
    if !selected || availability != NativeRegionAvailability::Observed {
        let unavailable = if availability == NativeRegionAvailability::Observed {
            NativeRegionAvailability::Unsupported
        } else {
            availability
        };
        return Ok((unavailable, receipt, Vec::new()));
    }
    let mut observations = go_declarations(
        path,
        admitted
            .declaration_regions(path)
            .map(|(package, index, line, has_body)| {
                (
                    format!(
                        "{receipt}#/observation/observed_packages/{package}/declarations/{index}"
                    ),
                    line,
                    has_body,
                )
            }),
    );
    observations.extend(admitted.import_regions(path).map(|(package, index, line)| {
        SourceObservation::new(
            path,
            SemanticRegion::Dependencies,
            RegionCoverage::Observed,
            GO_ANALYZER,
            format!("{receipt}#/observation/observed_packages/{package}/imports/{index}"),
            u32::try_from(line).ok(),
        )
    }));
    Ok((availability, receipt, observations))
}

fn go_availability(status: &GoStatus) -> Result<NativeRegionAvailability, NativeRegionError> {
    Ok(match status {
        GoStatus::Observed => NativeRegionAvailability::Observed,
        GoStatus::InvalidSource => NativeRegionAvailability::InvalidSource,
        GoStatus::Unsupported => NativeRegionAvailability::Unsupported,
        GoStatus::ResourceLimit => NativeRegionAvailability::ResourceLimit,
        GoStatus::InvalidRequest => return Err(NativeRegionError::SubjectMismatch),
    })
}

fn hash_receipt<T: serde::Serialize>(value: &T) -> Result<String, NativeRegionError> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(NativeRegionError::Encoding)?;
    Ok(sha256(&bytes))
}

fn go_declarations(
    path: &str,
    declarations: impl Iterator<Item = (String, usize, bool)>,
) -> Vec<SourceObservation> {
    let mut observations = Vec::new();
    for (reference, line, has_body) in declarations {
        observations.push(SourceObservation::new(
            path,
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            GO_ANALYZER,
            &reference,
            u32::try_from(line).ok(),
        ));
        if has_body {
            observations.push(SourceObservation::new(
                path,
                SemanticRegion::Implementation,
                RegionCoverage::Observed,
                GO_ANALYZER,
                reference,
                u32::try_from(line).ok(),
            ));
        }
    }
    observations
}

fn python_regions(
    source: &NativeSource<'_>,
    path: &str,
    source_ref: &str,
    admitted: &ActualPythonLexicalObservation,
) -> Result<Regions, NativeRegionError> {
    let observation = admitted.observation();
    if observation.selected_source_path() != path {
        return Err(NativeRegionError::SubjectMismatch);
    }
    let evaluation = admitted.evaluation_key();
    if !observation.matches_source(source.view.digest(), source_ref)
        || evaluation.source_manifest_digest() != source.binding.source_manifest_digest
        || evaluation.authority_binding_digest() != source.binding.authority_digest
    {
        return Err(NativeRegionError::StaleReceipt);
    }
    let availability = match observation.outcome() {
        PythonLexicalOutcome::Lexical => NativeRegionAvailability::Observed,
        PythonLexicalOutcome::Partial => NativeRegionAvailability::Partial,
        PythonLexicalOutcome::SyntaxOnly => NativeRegionAvailability::SyntaxOnly,
        PythonLexicalOutcome::InvalidSource => NativeRegionAvailability::InvalidSource,
        PythonLexicalOutcome::Unsupported => NativeRegionAvailability::Unsupported,
        PythonLexicalOutcome::Unavailable => NativeRegionAvailability::Unavailable,
    };
    let receipt = observation
        .to_canonical_json()
        .map_err(NativeRegionError::Encoding)?;
    let receipt = sha256(&receipt);
    let mut observations = Vec::new();
    for (index, line) in observation.function_regions() {
        observations.push(SourceObservation::new(
            path,
            SemanticRegion::Declarations,
            RegionCoverage::Observed,
            PYTHON_ANALYZER,
            format!("{receipt}#/report/observations/scopes/{index}"),
            u32::try_from(line).ok(),
        ));
    }
    for (index, line) in observation.unresolved_import_regions() {
        observations.push(SourceObservation::new(
            path,
            SemanticRegion::Dependencies,
            RegionCoverage::Unsupported,
            PYTHON_ANALYZER,
            format!("{receipt}#/report/observations/imports/{index}"),
            u32::try_from(line).ok(),
        ));
    }
    Ok((availability, receipt, observations))
}

fn resolve_layout(
    source: &NativeSource<'_>,
    path: &str,
    layouts: &[LayoutExtension],
) -> Result<Option<NativeRegionLayout>, NativeRegionError> {
    if layouts.is_empty() {
        return Ok(None);
    }
    let paths = source
        .view
        .files()
        .keys()
        .map(|path| ObservedLayoutPath {
            path,
            limitation: None,
        })
        .collect::<Vec<_>>();
    let report = inspect_layout_extensions(&paths, &source.binding.source_manifest_digest, layouts)
        .map_err(NativeRegionError::LayoutUnavailable)?;
    if report["authority"] != "ANALYSIS_ONLY" {
        return Err(NativeRegionError::LayoutUnavailable(
            "unexpected layout authority".into(),
        ));
    }
    let entry = report["entries"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["path"] == path))
        .ok_or_else(|| {
            NativeRegionError::LayoutUnavailable(
                "selected source omitted by layout observer".into(),
            )
        })?;
    let selected_profile = entry["profile"].as_str().and_then(|profile| {
        report["profiles"]
            .as_array()?
            .iter()
            .find(|row| row["id"] == profile)
            .cloned()
    });
    let layout_report =
        serde_json_canonicalizer::to_vec(&report).map_err(NativeRegionError::Encoding)?;
    Ok(Some(NativeRegionLayout {
        layout_report_ref: sha256(&layout_report),
        authority: "ANALYSIS_ONLY",
        entry: entry.clone(),
        selected_profile,
    }))
}
