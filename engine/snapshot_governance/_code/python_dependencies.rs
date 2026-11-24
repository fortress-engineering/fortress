//! Scoped dependency evidence from admitted actual Python static imports.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::{
    ActualPythonStaticImportObservation, PythonImportScope, PythonLexicalError,
    PythonLexicalProducer, PythonLexicalRequest, PythonObservationError,
    PythonStaticImportLimitation, PythonStaticImportObservation, PythonStaticImportOutcome,
    collect_static_imports,
};
use crate::affected_analysis::sha256;
use crate::audit::NativeAuthorityScope;
use crate::implementation_observation::{
    NativeDependencyAdapterError, NativeDependencyBatch, NativeDependencyContext,
    NativeDependencyEndpoint, NativeDependencyFile, NativeDependencyLanguage,
    NativeDependencyOccurrence, NativeDependencyTarget, NativeDependencyUnresolved,
    adapt_native_dependencies,
};
use crate::native_observation::NativeSource;
use crate::project::EvaluationKey;
use crate::source_architecture::python_lexical::python_static_imports::PythonStaticImportTarget;

/// Actual static imports and their separately bound scoped dependency evidence.
#[derive(Debug)]
pub struct ActualPythonStaticDependencyObservation {
    imports: ActualPythonStaticImportObservation,
    dependencies: PythonStaticDependencyOutcome,
    intent: Option<Value>,
}

impl ActualPythonStaticDependencyObservation {
    /// Returns the original admitted lexical and static import observations.
    #[must_use]
    pub const fn imports(&self) -> &ActualPythonStaticImportObservation {
        &self.imports
    }

    /// Returns source dependency evidence or the upstream reason it is unavailable.
    #[must_use]
    pub const fn dependencies(&self) -> &PythonStaticDependencyOutcome {
        &self.dependencies
    }

    /// Returns the explicit observed-edge comparison when independently requested.
    #[must_use]
    pub const fn intent(&self) -> Option<&Value> {
        self.intent.as_ref()
    }
}

/// Scoped dependency evidence or an explicitly unavailable observation.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonStaticDependencyOutcome {
    /// Scoped evidence from admitted static lookup and original authored ownership.
    Observed {
        /// Digest of the independently resolved endpoint ownership and diagnostics.
        ownership_ref: String,
        /// Ownership diagnostics from the original authority.
        ownership_diagnostics: Vec<crate::implementation_observation::SourceOwnershipDiagnostic>,
        /// Bounded native source adapter output, separate from canonical model input.
        projection: Value,
    },
    /// The preceding scoped import lookup could not produce a usable observation.
    Unavailable {
        /// Scoped reason the import observation or adapter was unavailable.
        reason: PythonStaticImportLimitation,
    },
}

/// Projects admitted static origins under the independently selected original authority.
///
/// `receive` uses the existing trusted lexical transport. It cannot supply source
/// ownership, executable bindings, runtime resolution, or analysis completeness.
/// The result never enters the canonical Program Semantic Model or assessment.
///
/// # Errors
/// Refuses unsafe or stale physical inputs, invalid host or adapter replies, and
/// source/context/authority mismatches. Retains bounded unsupported lookup states.
pub fn observe_python_static_dependencies(
    project_root: &Path,
    source_path: &str,
    producer: &PythonLexicalProducer,
    scope: &PythonImportScope,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonStaticDependencyObservation, PythonObservationError> {
    collect_dependencies(project_root, source_path, producer, scope, receive, false)
}

/// Compares positive source dependency edges with independently captured intent.
/// Runtime import execution and absence of dependencies remain unproven.
///
/// # Errors
/// Returns the same source, transport, and output errors as dependency inspection.
pub fn observe_python_static_dependency_intent(
    project_root: &Path,
    source_path: &str,
    producer: &PythonLexicalProducer,
    scope: &PythonImportScope,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonStaticDependencyObservation, PythonObservationError> {
    collect_dependencies(project_root, source_path, producer, scope, receive, true)
}

fn collect_dependencies(
    project_root: &Path,
    source_path: &str,
    producer: &PythonLexicalProducer,
    scope: &PythonImportScope,
    receive: impl FnOnce(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
    with_intent: bool,
) -> Result<ActualPythonStaticDependencyObservation, PythonObservationError> {
    let authority = if with_intent {
        NativeAuthorityScope::DependenciesWithIntent
    } else {
        NativeAuthorityScope::Dependencies
    };
    let source = NativeSource::capture_with(project_root, "Python", authority)?;
    let imports = collect_static_imports(&source, source_path, producer, scope, receive)?;
    let mut intent = None;
    let dependencies = match imports.outcome() {
        PythonStaticImportOutcome::Unavailable { reason } => {
            PythonStaticDependencyOutcome::Unavailable { reason: *reason }
        }
        PythonStaticImportOutcome::Observed { observation } => {
            match project_dependencies(&source, imports.evaluation_key(), observation, |observed| {
                if with_intent {
                    intent = Some(encode_intent(&source, Some(observed))?);
                }
                Ok(())
            }) {
                Ok(report) => report,
                Err(PythonObservationError::StaticDependencies(
                    NativeDependencyAdapterError::ResourceLimit,
                )) => PythonStaticDependencyOutcome::Unavailable {
                    reason: PythonStaticImportLimitation::ResourceLimit,
                },
                Err(error) => return Err(error),
            }
        }
    };
    if with_intent && intent.is_none() {
        intent = Some(encode_intent(&source, None)?);
    }
    source.revalidate()?;
    Ok(ActualPythonStaticDependencyObservation {
        imports,
        dependencies,
        intent,
    })
}

fn encode_intent(
    source: &NativeSource<'_>,
    observed: Option<&crate::implementation_observation::ObservedImplementation>,
) -> Result<Value, PythonObservationError> {
    source
        .compare_dependency_intent(observed)
        .and_then(serde_json::to_value)
        .map_err(|error| PythonLexicalError::Encoding(error).into())
}

fn project_dependencies(
    source: &NativeSource<'_>,
    evaluation: &EvaluationKey,
    observation: &PythonStaticImportObservation,
    inspect: impl FnOnce(
        &crate::implementation_observation::ObservedImplementation,
    ) -> Result<(), PythonObservationError>,
) -> Result<PythonStaticDependencyOutcome, PythonObservationError> {
    let expected = NativeDependencyContext {
        snapshot_fingerprint: &source.binding.source_fingerprint,
        source_view_sha256: source.view.digest(),
        authority_sha256: &source.binding.authority_digest,
        context_sha256: evaluation.program_context_digest(),
    };
    if evaluation.source_manifest_digest() != source.binding.source_manifest_digest
        || evaluation.authority_binding_digest() != expected.authority_sha256
        || observation.evaluation_ref() != evaluation.digest()
        || observation.source_view_ref() != expected.source_view_sha256
    {
        return Err(PythonObservationError::StaticDependencies(
            NativeDependencyAdapterError::BindingMismatch,
        ));
    }
    let source_path = observation.source_path();
    let original = source
        .view
        .bytes(source_path)
        .ok_or(PythonObservationError::Lexical(
            super::PythonLexicalError::MissingSource,
        ))?;
    let physical = PhysicalLines::new(original)?;
    let references = import_references(observation, &physical)?;
    let file = NativeDependencyFile {
        path: source_path,
        sha256: observation.source_ref(),
    };
    let mut paths = BTreeSet::from([source_path]);
    let endpoints: Vec<_> = references
        .iter()
        .map(|row| NativeDependencyEndpoint {
            occurrence: NativeDependencyOccurrence {
                file,
                start_byte: row.start,
                end_byte: row.end,
                reference: &row.spelling,
            },
            target: static_target(row.target, &mut paths),
        })
        .collect();
    let (input, diagnostics) = source.dependency_input(paths)?;
    let ownership_bytes = serde_json_canonicalizer::to_vec(&(input.ownerships(), diagnostics))
        .map_err(super::PythonLexicalError::Encoding)?;
    let observation_ref = sha256(&observation.to_canonical_json()?);
    let admitted = NativeDependencyBatch {
        language: NativeDependencyLanguage::Python,
        context: NativeDependencyContext {
            source_view_sha256: observation.source_view_ref(),
            ..expected
        },
        observation_sha256: &observation_ref,
        endpoints: &endpoints,
    };
    let projected = adapt_native_dependencies(&input, expected, &admitted)
        .map_err(PythonObservationError::StaticDependencies)?;
    inspect(projected.observation())?;
    Ok(PythonStaticDependencyOutcome::Observed {
        ownership_ref: sha256(&ownership_bytes),
        ownership_diagnostics: diagnostics.to_vec(),
        projection: serde_json::to_value(projected).map_err(super::PythonLexicalError::Encoding)?,
    })
}

struct ImportReference<'a> {
    start: usize,
    end: usize,
    spelling: String,
    target: &'a PythonStaticImportTarget,
}

fn import_references<'a>(
    observation: &'a PythonStaticImportObservation,
    physical: &PhysicalLines<'_>,
) -> Result<Vec<ImportReference<'a>>, PythonObservationError> {
    let mut references = Vec::new();
    for row in observation.imports() {
        let [start_line, start_column, end_line, end_column] = row.source_span();
        let start = physical.offset(start_line, start_column)?;
        let end = physical.offset(end_line, end_column)?;
        for (index, target) in row.static_targets().iter().enumerate() {
            let spelling =
                row.lookup_spelling(index)
                    .ok_or(PythonObservationError::StaticDependencies(
                        NativeDependencyAdapterError::ResourceLimit,
                    ))?;
            references.push(ImportReference {
                start,
                end,
                spelling,
                target,
            });
        }
    }
    Ok(references)
}

fn static_target<'a>(
    target: &'a PythonStaticImportTarget,
    paths: &mut BTreeSet<&'a str>,
) -> NativeDependencyTarget<'a> {
    use NativeDependencyUnresolved as Unresolved;
    match target {
        PythonStaticImportTarget::FileStatic {
            path, source_ref, ..
        } => {
            paths.insert(path);
            NativeDependencyTarget::PythonStaticOrigin(NativeDependencyFile {
                path,
                sha256: source_ref,
            })
        }
        PythonStaticImportTarget::NamespaceStatic { .. } => {
            NativeDependencyTarget::Unresolved(Unresolved::NamespaceOnly)
        }
        PythonStaticImportTarget::MissingFromAdmittedRoots { .. } => {
            NativeDependencyTarget::Unresolved(Unresolved::MissingFromAdmittedScope)
        }
        PythonStaticImportTarget::NonPackagePrefix { .. }
        | PythonStaticImportTarget::UnsupportedModuleSpelling
        | PythonStaticImportTarget::OriginContextUnavailable
        | PythonStaticImportTarget::RelativeAboveTopLevel => {
            NativeDependencyTarget::Unresolved(Unresolved::UnsupportedContext)
        }
    }
}

struct PhysicalLines<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> PhysicalLines<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, PythonObservationError> {
        let text = std::str::from_utf8(bytes).map_err(|_| Self::invalid())?;
        let starts = std::iter::once(0)
            .chain(
                bytes
                    .iter()
                    .enumerate()
                    .filter_map(|(index, byte)| (*byte == b'\n').then_some(index + 1)),
            )
            .collect();
        Ok(Self { text, starts })
    }

    fn offset(&self, line: usize, column: usize) -> Result<usize, PythonObservationError> {
        let line_index = line.checked_sub(1).ok_or_else(Self::invalid)?;
        let start = *self.starts.get(line_index).ok_or_else(Self::invalid)?;
        let end = self.starts.get(line).copied().unwrap_or(self.text.len());
        let content = self.text[start..end].trim_end_matches(['\r', '\n']);
        if column > content.len() || !content.is_char_boundary(column) {
            return Err(Self::invalid());
        }
        Ok(start + column)
    }

    fn invalid() -> PythonObservationError {
        PythonObservationError::StaticDependencies(NativeDependencyAdapterError::InvalidEndpoint)
    }
}
