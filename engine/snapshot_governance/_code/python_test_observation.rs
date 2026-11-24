//! Exact compile-only pytest naming observations for explicitly selected roots.

use std::path::Path;

use serde::Serialize;

use super::{
    PythonLexicalError, PythonLexicalMode, PythonLexicalOutcome, PythonLexicalProducer,
    PythonLexicalRequest, PythonObservationError, collect_lexical,
};
use crate::affected_analysis::sha256;
use crate::native_observation::NativeSource;
use crate::observation::{SourceView, is_canonical_relative_path};
use crate::project::EvaluationKey;
use crate::source_architecture::python_lexical::{
    MAX_SOURCE_BYTES, python_test_declarations::PythonTestDeclarations,
};

const PROFILE: &str = "PYTEST_DEFAULT_FILE_AND_FUNCTION_NAMES_V1";
const MAX_ROOTS: usize = 16;
const MAX_FILES: usize = 16;
const MAX_TEST_BYTES: usize = 512 * 1024;
const MAX_MARKERS: usize = 64;
const LIMITATIONS: [&str; 5] = [
    "PHYSICAL_FILENAME_AND_MODULE_LEXICAL_DECLARATIONS_ONLY",
    "IMPORTABILITY_AND_RUNNER_COLLECTION_UNESTABLISHED",
    "DECORATORS_REBINDING_CLASSES_AND_DYNAMIC_TESTS_UNRESOLVED",
    "CUSTOM_DISCOVERY_PLUGINS_CONFIG_AND_DIRECTORY_POLICY_UNINTERPRETED",
    "NO_EXECUTION_COVERAGE_OR_VERIFICATION_RELATIONSHIPS",
];

/// Exact original-source test naming observations for a bounded Python scope.
#[derive(Serialize)]
pub struct ActualPythonTestObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    profile: &'static str,
    evaluation_key: EvaluationKey,
    source_view_ref: String,
    producer: PythonLexicalProducer,
    roots: Vec<TestRoot>,
    discovery_markers: Vec<DiscoveryMarker>,
    files: Vec<TestFile>,
    runner_collection: &'static str,
    limitations: [&'static str; 5],
}

#[derive(Serialize)]
struct TestRoot {
    path: String,
    ordinary_entries: usize,
    naming_matches: usize,
    state: RootState,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RootState {
    SourceUnestablished,
    NoNamingMatches,
    NamingMatchesObserved,
}

#[derive(Serialize)]
struct DiscoveryMarker {
    path: String,
    source_ref: String,
    interpretation: &'static str,
}

#[derive(Serialize)]
struct TestFile {
    path: String,
    source_ref: String,
    lexical_receipt_ref: String,
    lexical_outcome: PythonLexicalOutcome,
    #[serde(flatten)]
    facts: PythonTestDeclarations,
}

struct Scope<'a> {
    roots: Vec<TestRoot>,
    markers: Vec<DiscoveryMarker>,
    files: Vec<&'a str>,
}

/// Observes the fixed pytest default naming convention over explicit test roots.
///
/// This uses the existing compile-only lexical worker for selected ordinary
/// files. Root selection and collection markers are independent of ownership,
/// runner behavior and test outcomes. The original physical source and
/// governing authority are revalidated before publication.
///
/// # Errors
/// Refuses invalid or excessive scope, mismatched worker responses and changes
/// to the captured source or governing inputs.
pub fn observe_python_tests(
    project_root: &Path,
    roots: &[&str],
    producer: &PythonLexicalProducer,
    mut receive: impl FnMut(&PythonLexicalRequest, &[u8]) -> Result<Vec<u8>, PythonObservationError>,
) -> Result<ActualPythonTestObservation, PythonObservationError> {
    let source = NativeSource::capture(project_root, "Python")?;
    let scope = select(&source.view, roots)?;
    let context = serde_json_canonicalizer::to_vec(&(
        "fortress-python-test-declaration-context-v1",
        PROFILE,
        scope
            .roots
            .iter()
            .map(|root| root.path.as_str())
            .collect::<Vec<_>>(),
        producer,
    ))
    .map_err(PythonLexicalError::Encoding)?;
    let evaluation_key = EvaluationKey::new(
        &source.binding.source_manifest_digest,
        sha256(&context),
        &source.binding.authority_digest,
    );
    let mut files = Vec::with_capacity(scope.files.len());
    for path in scope.files {
        let observation = collect_lexical(
            &source,
            &evaluation_key,
            path,
            PythonLexicalMode::Lexical,
            producer,
            &mut receive,
        )?;
        let receipt = observation
            .to_canonical_json()
            .map_err(PythonLexicalError::Encoding)?;
        let bytes = source
            .view
            .bytes(path)
            .ok_or(PythonLexicalError::MissingSource)?;
        files.push(TestFile {
            path: path.to_owned(),
            source_ref: sha256(bytes),
            lexical_receipt_ref: sha256(&receipt),
            lexical_outcome: observation.outcome(),
            facts: observation.test_declarations(),
        });
    }
    source.revalidate()?;
    Ok(ActualPythonTestObservation {
        schema: "urn:fortress:derived:v1:python-test-declarations",
        schema_version: 1,
        profile: PROFILE,
        evaluation_key,
        source_view_ref: source.view.digest().to_owned(),
        producer: producer.clone(),
        roots: scope.roots,
        discovery_markers: scope.markers,
        files,
        runner_collection: "UNESTABLISHED",
        limitations: LIMITATIONS,
    })
}

fn select<'a>(source: &'a SourceView, roots: &[&str]) -> Result<Scope<'a>, PythonObservationError> {
    if roots.len() > MAX_ROOTS {
        return Err(PythonObservationError::TestScopeLimit);
    }
    if roots.is_empty() {
        return Err(PythonObservationError::InvalidTestRoots);
    }
    let mut ordered = roots.to_vec();
    ordered.sort_unstable();
    for (index, root) in ordered.iter().enumerate() {
        let folded = root.to_ascii_lowercase();
        if root.len() > 240
            || (*root != "." && !is_canonical_relative_path(root))
            || source.bytes(root).is_some()
            || ordered[..index].iter().any(|ancestor| {
                let earlier = ancestor.to_ascii_lowercase();
                earlier == folded || below(&folded, &earlier) || below(&earlier, &folded)
            })
        {
            return Err(PythonObservationError::InvalidTestRoots);
        }
    }
    let mut roots = ordered
        .into_iter()
        .map(|path| TestRoot {
            path: path.to_owned(),
            ordinary_entries: 0,
            naming_matches: 0,
            state: RootState::SourceUnestablished,
        })
        .collect::<Vec<_>>();
    let mut files = Vec::new();
    let mut markers = Vec::new();
    let mut bytes = 0;
    for (path, source_bytes) in source.files() {
        if let Some(root) = roots.iter_mut().find(|root| below(path, &root.path)) {
            root.ordinary_entries += 1;
            if matches_filename(path) {
                bytes += source_bytes.len();
                if files.len() == MAX_FILES
                    || source_bytes.len() > MAX_SOURCE_BYTES
                    || bytes > MAX_TEST_BYTES
                {
                    return Err(PythonObservationError::TestScopeLimit);
                }
                root.naming_matches += 1;
                files.push(path.as_str());
            }
        }
        if marker_in_scope(path, &roots) {
            if markers.len() == MAX_MARKERS {
                return Err(PythonObservationError::TestScopeLimit);
            }
            markers.push(DiscoveryMarker {
                path: path.clone(),
                source_ref: sha256(source_bytes),
                interpretation: "CONFIGURATION_OR_HOOK_UNINTERPRETED",
            });
        }
    }
    for root in &mut roots {
        root.state = match (root.ordinary_entries, root.naming_matches) {
            (0, _) => RootState::SourceUnestablished,
            (_, 0) => RootState::NoNamingMatches,
            _ => RootState::NamingMatchesObserved,
        };
    }
    Ok(Scope {
        roots,
        markers,
        files,
    })
}

fn below(path: &str, root: &str) -> bool {
    root == "."
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn matches_filename(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or_default();
    // The Python collector accepts the literal lowercase suffix on both hosts.
    let Some((stem, "py")) = name.rsplit_once('.') else {
        return false;
    };
    stem.starts_with("test_") || stem.ends_with("_test")
}

fn marker_in_scope(path: &str, roots: &[TestRoot]) -> bool {
    let (dir, name) = path.rsplit_once('/').unwrap_or((".", path));
    matches!(
        name,
        "conftest.py"
            | "pytest.ini"
            | ".pytest.ini"
            | "pytest.toml"
            | ".pytest.toml"
            | "pyproject.toml"
            | "setup.cfg"
            | "tox.ini"
    ) && roots
        .iter()
        .any(|root| dir == root.path || below(dir, &root.path) || below(&root.path, dir))
}
