//! Static source candidates for admitted Python import declarations.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::control_layout::CONTROL_ROOT;
use crate::observation::{SourceView, is_canonical_relative_path};
use crate::project::EvaluationKey;
use crate::wire::{JsonAdmissionLimits, admit_json, reject_duplicate_json_keys_bytes};

use super::{
    Import, ImportForm, PythonLexicalObservation, PythonLexicalOutcome, PythonLexicalRequest,
    Unresolved, digest, is_digest,
};

const ROOTS_SCHEMA: &str = "fortress:python:static-import-roots:1";
const OBSERVATION_SCHEMA: &str = "fortress:python:static-import-observation:1";
const MAX_ROOTS: usize = 4;
const MAX_PATH_BYTES: usize = 240;
const MAX_COMPONENTS: usize = 12;
const MAX_FILES: usize = 4096;
const MAX_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_IMPORTS: usize = 256;
const MAX_NAMES: usize = 512;
const MAX_NAME_BYTES: usize = 256;
const MAX_REPORT_BYTES: usize = 512 * 1024;
const ROOTS_LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 8192,
    depth: 4,
    nodes: 64,
    token_bytes: 1536,
};

/// Explicit ordered root scope selected by a trusted caller.
///
/// This is a scoped analysis input. Matching a digest authenticates neither a
/// configuration author nor a claim that a physical inventory is complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonImportRoots {
    configuration_ref: String,
    configuration: RootConfiguration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RootConfiguration {
    schema: String,
    source_view_ref: String,
    evaluation_ref: String,
    inventory: Inventory,
    roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Inventory {
    CompleteSourceOnly,
    Incomplete,
}

impl PythonImportRoots {
    /// Admits an independently selected canonical configuration digest.
    ///
    /// The caller must select the pin outside subject and candidate authority,
    /// and supply a complete ordinary-file inventory for the selected roots.
    /// Root order is explicit and significant. No roots are inferred from the
    /// project, environment, Python runtime or the current working directory.
    ///
    /// # Errors
    /// Rejects malformed, unsupported, unpinned, incomplete or ambiguous roots.
    pub fn admit(bytes: &[u8], expected_ref: &str) -> Result<Self, PythonStaticImportError> {
        admit_json(bytes, ROOTS_LIMITS).map_err(|_| PythonStaticImportError::ResourceLimit)?;
        reject_duplicate_json_keys_bytes(bytes).map_err(PythonStaticImportError::Encoding)?;
        let configuration: RootConfiguration =
            serde_json::from_slice(bytes).map_err(PythonStaticImportError::Encoding)?;
        if configuration.schema != ROOTS_SCHEMA {
            return Err(PythonStaticImportError::UnsupportedConfiguration);
        }
        let canonical = serde_json_canonicalizer::to_vec(&configuration)
            .map_err(PythonStaticImportError::Encoding)?;
        if digest(&canonical) != expected_ref
            || !is_digest(&configuration.source_view_ref)
            || !is_digest(&configuration.evaluation_ref)
        {
            return Err(PythonStaticImportError::InvalidBinding);
        }
        if configuration.inventory != Inventory::CompleteSourceOnly {
            return Err(PythonStaticImportError::IncompleteInventory);
        }
        validate_roots(&configuration.roots)?;
        Ok(Self {
            configuration_ref: expected_ref.to_owned(),
            configuration,
        })
    }

    /// Returns the JCS/SHA-256 identity of the exact ordered scope.
    #[must_use]
    pub fn configuration_ref(&self) -> &str {
        &self.configuration_ref
    }
}

/// Independently pinned, ordered source-root selection for analysis only.
///
/// The original physical snapshot owner binds this scope to one evaluation.
/// The selection supplies no repository governance or runtime import authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonImportScope {
    scope_ref: String,
    selection: ScopeSelection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeSelection {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    inventory: Inventory,
    roots: Vec<String>,
}

impl PythonImportScope {
    /// Admits an independently selected canonical root-scope digest.
    ///
    /// # Errors
    /// Refuses malformed documents, invalid identities, unsupported versions,
    /// incomplete inventories, and invalid or overlapping root paths.
    pub fn admit(bytes: &[u8], expected_ref: &str) -> Result<Self, PythonStaticImportError> {
        admit_json(bytes, ROOTS_LIMITS).map_err(|_| PythonStaticImportError::ResourceLimit)?;
        reject_duplicate_json_keys_bytes(bytes).map_err(PythonStaticImportError::Encoding)?;
        let selection: ScopeSelection =
            serde_json::from_slice(bytes).map_err(PythonStaticImportError::Encoding)?;
        if selection.schema != "urn:fortress:host:v1:python-static-import-scope"
            || selection.schema_version != 1
        {
            return Err(PythonStaticImportError::UnsupportedConfiguration);
        }
        let canonical = serde_json_canonicalizer::to_vec(&selection)
            .map_err(PythonStaticImportError::Encoding)?;
        if digest(&canonical) != expected_ref {
            return Err(PythonStaticImportError::InvalidBinding);
        }
        if selection.inventory != Inventory::CompleteSourceOnly {
            return Err(PythonStaticImportError::IncompleteInventory);
        }
        validate_roots(&selection.roots)?;
        Ok(Self {
            scope_ref: expected_ref.to_owned(),
            selection,
        })
    }

    /// Returns the independently selected JCS/SHA-256 scope identity.
    #[must_use]
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }

    pub(crate) fn bind(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
    ) -> Result<PythonImportRoots, PythonStaticImportError> {
        let configuration = RootConfiguration {
            schema: ROOTS_SCHEMA.into(),
            source_view_ref: view.digest().into(),
            evaluation_ref: evaluation.digest(),
            inventory: self.selection.inventory,
            roots: self.selection.roots.clone(),
        };
        let canonical = serde_json_canonicalizer::to_vec(&configuration)
            .map_err(PythonStaticImportError::Encoding)?;
        Ok(PythonImportRoots {
            configuration_ref: digest(&canonical),
            configuration,
        })
    }
}

fn validate_roots(roots: &[String]) -> Result<(), PythonStaticImportError> {
    if roots.is_empty() || roots.len() > MAX_ROOTS || roots.iter().any(|root| !admitted_path(root))
    {
        return Err(PythonStaticImportError::InvalidRootPath);
    }
    let folded = roots
        .iter()
        .map(|root| root.to_ascii_lowercase())
        .collect::<Vec<_>>();
    for (index, left) in folded.iter().enumerate() {
        if folded[index + 1..]
            .iter()
            .any(|right| left == right || under(left, right) || under(right, left))
        {
            return Err(PythonStaticImportError::AmbiguousRoots);
        }
    }
    Ok(())
}

fn admitted_path(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or_default();
    path.is_ascii()
        && path.len() <= MAX_PATH_BYTES
        && is_canonical_relative_path(path)
        && !first.eq_ignore_ascii_case(CONTROL_ROOT)
        && !first.eq_ignore_ascii_case(".git")
}

fn under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn source_file(relative: &str) -> bool {
    relative.strip_suffix(".py").is_some_and(|stem| {
        stem.split('/').count() <= MAX_COMPONENTS && stem.split('/').all(identifier)
    })
}

/// Exact scoped disposition of one static module lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonStaticImportTarget {
    /// A regular package initializer or module is selected in the scope.
    FileStatic {
        /// Canonical absolute Python module spelling.
        module: String,
        /// Exact repository-relative source path.
        path: String,
        /// SHA-256 of the selected source bytes.
        source_ref: String,
    },
    /// A namespace has ordered directory portions represented by source files.
    NamespaceStatic {
        /// Canonical absolute Python module spelling.
        module: String,
        /// Ordered repository-relative namespace directories.
        portions: Vec<String>,
    },
    /// The scope has no file match or namespace represented by its files.
    MissingFromAdmittedRoots {
        /// Canonical absolute Python module spelling.
        module: String,
    },
    /// The selected non-final prefix is a source module, rather than a package.
    NonPackagePrefix {
        /// Canonical absolute Python module spelling.
        module: String,
    },
    /// The request falls outside the bounded ASCII dotted spelling policy.
    UnsupportedModuleSpelling,
    /// The importing source has no independently established package context.
    OriginContextUnavailable,
    /// The relative import exceeds the established package depth.
    RelativeAboveTopLevel,
}

/// One admitted import declaration and its evaluated static lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonStaticImport {
    occurrence: Import,
    static_targets: Vec<PythonStaticImportTarget>,
    member_resolution: MemberResolution,
    runtime_resolution: Unresolved,
}

impl PythonStaticImport {
    /// Returns the exact original lexical scope identity for the occurrence.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.occurrence.scope
    }

    /// Returns start line, start UTF-8 byte column, end line and end column.
    ///
    /// Lines are one-based. Columns are zero-based offsets in the source bytes.
    #[must_use]
    pub const fn source_span(&self) -> [usize; 4] {
        let super::Span(start_line, start_column, end_line, end_column) = self.occurrence.span;
        [start_line, start_column, end_line, end_column]
    }

    /// Returns the bounded declared spelling for one static lookup in original order.
    pub(crate) fn lookup_spelling(&self, index: usize) -> Option<String> {
        match self.occurrence.form {
            ImportForm::Import => self
                .occurrence
                .names
                .get(index)
                .map(|(name, _)| name.clone()),
            ImportForm::From if index == 0 => {
                let level = self.occurrence.level?;
                let module = self.occurrence.module.as_deref().unwrap_or_default();
                if level > MAX_NAME_BYTES {
                    return None;
                }
                Some(format!("{}{module}", ".".repeat(level)))
            }
            ImportForm::From => None,
        }
    }

    /// Returns one lookup for a from-import base or one per plain import name.
    #[must_use]
    pub fn static_targets(&self) -> &[PythonStaticImportTarget] {
        &self.static_targets
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MemberResolution {
    NoMember,
    UnresolvedAttributeOrSubmodule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DirectoryCoverage {
    ImpliedByAdmittedSourceFiles,
}

/// Source-only Python import candidates tied to one admitted lexical result.
///
/// This projection makes no runtime import, reachability, ownership or
/// certification claims and leaves earlier lexical response bytes unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonStaticImportObservation {
    schema: &'static str,
    lexical_request: PythonLexicalRequest,
    lexical_outcome: PythonLexicalOutcome,
    roots: PythonImportRoots,
    directory_coverage: DirectoryCoverage,
    imports: Vec<PythonStaticImport>,
}

impl PythonStaticImportObservation {
    /// Returns the exact originating repository-relative source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.lexical_request.source_path
    }

    /// Returns the exact originating source bytes' SHA-256 reference.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.lexical_request.source_ref
    }

    /// Returns the original complete immutable view identity.
    #[must_use]
    pub fn source_view_ref(&self) -> &str {
        &self.lexical_request.source_view_ref
    }

    /// Returns the exact selected evaluation context and authority binding.
    #[must_use]
    pub fn evaluation_ref(&self) -> &str {
        &self.lexical_request.evaluation_ref
    }

    /// Returns the scoped, content-addressed root configuration identity.
    #[must_use]
    pub fn roots_ref(&self) -> &str {
        self.roots.configuration_ref()
    }

    /// Evaluates the admitted import declarations within explicitly selected roots.
    ///
    /// Only ordinary source files from the immutable view can contribute. A
    /// represented directory is a source path prefix. Empty directories,
    /// installed dependencies and runtime search configuration remain unknown.
    ///
    /// # Errors
    /// Rejects stale bindings, unavailable lexical facts, unsupported or
    /// ambiguous inventories, and applicable resource-limit failures.
    pub fn evaluate(
        lexical: &PythonLexicalObservation,
        view: &SourceView,
        evaluation: &EvaluationKey,
        roots: &PythonImportRoots,
    ) -> Result<Self, PythonStaticImportError> {
        let request = &lexical.request;
        let input = &roots.configuration;
        if view.digest() != input.source_view_ref
            || request.source_view_ref != input.source_view_ref
            || evaluation.digest() != input.evaluation_ref
            || request.evaluation_ref != input.evaluation_ref
        {
            return Err(PythonStaticImportError::StaleInput);
        }
        let facts = lexical
            .report
            .observations
            .as_ref()
            .ok_or(PythonStaticImportError::LexicalUnavailable)?;
        bound_imports(&facts.imports)?;
        let index = Index::new(view, &input.roots)?;
        let origin = index.origin_package(&request.source_path);
        let imports = facts
            .imports
            .iter()
            .map(|row| index.resolve(row, origin.as_deref()))
            .collect();
        let result = Self {
            schema: OBSERVATION_SCHEMA,
            lexical_request: request.clone(),
            lexical_outcome: lexical.report.outcome,
            roots: roots.clone(),
            directory_coverage: DirectoryCoverage::ImpliedByAdmittedSourceFiles,
            imports,
        };
        result.to_canonical_json()?;
        Ok(result)
    }

    /// Returns the admitted declarations with their static dispositions.
    #[must_use]
    pub fn imports(&self) -> &[PythonStaticImport] {
        &self.imports
    }

    /// Returns deterministic bounded JSON for this independent sidecar.
    ///
    /// # Errors
    /// Returns an error if serialization fails or exceeds the byte bound.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, PythonStaticImportError> {
        let bytes =
            serde_json_canonicalizer::to_vec(self).map_err(PythonStaticImportError::Encoding)?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(PythonStaticImportError::ResourceLimit);
        }
        Ok(bytes)
    }
}

fn bound_imports(imports: &[Import]) -> Result<(), PythonStaticImportError> {
    if imports.len() > MAX_IMPORTS
        || imports.iter().map(|row| row.names.len()).sum::<usize>() > MAX_NAMES
        || imports.iter().any(|row| {
            row.module
                .as_ref()
                .is_some_and(|module| module.len() > MAX_NAME_BYTES)
                || row.names.iter().any(|(name, alias)| {
                    name.len() > MAX_NAME_BYTES
                        || alias
                            .as_ref()
                            .is_some_and(|alias| alias.len() > MAX_NAME_BYTES)
                })
        })
    {
        return Err(PythonStaticImportError::ResourceLimit);
    }
    Ok(())
}

struct Index<'a> {
    roots: &'a [String],
    directories: BTreeSet<&'a str>,
    files: BTreeMap<&'a str, String>,
}

enum Selected<'a> {
    File {
        path: &'a str,
        prefix: Option<&'a str>,
    },
    Namespace(Vec<&'a str>),
    Missing,
    NonPackage,
}

impl<'a> Index<'a> {
    fn new(view: &'a SourceView, roots: &'a [String]) -> Result<Self, PythonStaticImportError> {
        let mut index = Self {
            roots,
            directories: BTreeSet::new(),
            files: BTreeMap::new(),
        };
        let mut folded = BTreeMap::new();
        let mut input_bytes = 0;
        for root in roots {
            if view.bytes(root).is_some() {
                return Err(PythonStaticImportError::AmbiguousInventory);
            }
            let prefix = format!("{root}/");
            let mut found = false;
            for (path, bytes) in view
                .files()
                .range(prefix.clone()..)
                .take_while(|(path, _)| path.starts_with(&prefix))
            {
                found = true;
                input_bytes = bytes.len().saturating_add(input_bytes);
                if index.files.len() == MAX_FILES || input_bytes > MAX_INVENTORY_BYTES {
                    return Err(PythonStaticImportError::ResourceLimit);
                }
                let relative = &path[prefix.len()..];
                if !admitted_path(path) || !source_file(relative) {
                    return Err(PythonStaticImportError::UnsupportedRootContent);
                }
                for (boundary, _) in path.match_indices('/') {
                    let directory = &path[..boundary];
                    if view.bytes(directory).is_some() {
                        return Err(PythonStaticImportError::AmbiguousInventory);
                    }
                    record_spelling(&mut folded, directory)?;
                    index.directories.insert(directory);
                }
                record_spelling(&mut folded, path)?;
                index.files.insert(path.as_str(), digest(bytes));
            }
            if !found {
                return Err(PythonStaticImportError::RootUnavailable);
            }
        }
        Ok(index)
    }

    fn find_component(&self, locations: &[&'a str], component: &str) -> Selected<'a> {
        let mut portions = Vec::new();
        for location in locations {
            let directory = format!("{location}/{component}");
            let initializer = format!("{directory}/__init__.py");
            if let Some((&path, _)) = self.files.get_key_value(initializer.as_str()) {
                return Selected::File {
                    path,
                    prefix: self.directories.get(directory.as_str()).copied(),
                };
            }
            let module = format!("{directory}.py");
            if let Some((&path, _)) = self.files.get_key_value(module.as_str()) {
                return Selected::File { path, prefix: None };
            }
            if let Some(&portion) = self.directories.get(directory.as_str()) {
                portions.push(portion);
            }
        }
        if portions.is_empty() {
            Selected::Missing
        } else {
            Selected::Namespace(portions)
        }
    }

    fn select(&self, absolute: &str) -> Selected<'a> {
        let mut locations = self.roots.iter().map(String::as_str).collect::<Vec<_>>();
        let mut parts = absolute.split('.').peekable();
        while let Some(part) = parts.next() {
            let selected = self.find_component(&locations, part);
            if parts.peek().is_none() {
                return selected;
            }
            locations = match selected {
                Selected::File {
                    prefix: Some(directory),
                    ..
                } => vec![directory],
                Selected::Namespace(portions) => portions,
                Selected::File { prefix: None, .. } => return Selected::NonPackage,
                Selected::Missing | Selected::NonPackage => return Selected::Missing,
            };
        }
        Selected::Missing
    }

    fn lookup(&self, absolute: &str) -> PythonStaticImportTarget {
        if absolute.len() > MAX_NAME_BYTES
            || absolute.split('.').count() > MAX_COMPONENTS
            || !absolute.split('.').all(identifier)
        {
            return PythonStaticImportTarget::UnsupportedModuleSpelling;
        }
        let module = absolute.to_owned();
        match self.select(absolute) {
            Selected::File { path, .. } => PythonStaticImportTarget::FileStatic {
                module,
                path: path.to_owned(),
                source_ref: self.files[path].clone(),
            },
            Selected::Namespace(portions) => PythonStaticImportTarget::NamespaceStatic {
                module,
                portions: portions.into_iter().map(str::to_owned).collect(),
            },
            Selected::Missing => PythonStaticImportTarget::MissingFromAdmittedRoots { module },
            Selected::NonPackage => PythonStaticImportTarget::NonPackagePrefix { module },
        }
    }

    fn origin_package(&self, path: &str) -> Option<String> {
        let relative = self.roots.iter().find_map(|root| {
            path.strip_prefix(root)
                .and_then(|suffix| suffix.strip_prefix('/'))
        })?;
        let (parent, name) = relative.rsplit_once('/')?;
        let package = parent.replace('/', ".");
        let absolute = if name == "__init__.py" {
            package.clone()
        } else {
            format!("{package}.{}", name.strip_suffix(".py")?)
        };
        if matches!(self.select(&absolute), Selected::File { path: selected, .. } if selected == path)
        {
            Some(package)
        } else {
            None
        }
    }

    fn resolve(&self, row: &Import, origin: Option<&str>) -> PythonStaticImport {
        let (static_targets, member_resolution) = match row.form {
            ImportForm::Import => (
                row.names
                    .iter()
                    .map(|(name, _)| self.lookup(name))
                    .collect(),
                MemberResolution::NoMember,
            ),
            ImportForm::From => (
                vec![self.resolve_from(row, origin)],
                MemberResolution::UnresolvedAttributeOrSubmodule,
            ),
        };
        PythonStaticImport {
            occurrence: row.clone(),
            static_targets,
            member_resolution,
            runtime_resolution: Unresolved::Unresolved,
        }
    }

    fn resolve_from(&self, row: &Import, origin: Option<&str>) -> PythonStaticImportTarget {
        let module = row.module.as_deref().unwrap_or_default();
        let level = row.level.unwrap_or_default();
        if level == 0 {
            return self.lookup(module);
        }
        let Some(package) = origin else {
            return PythonStaticImportTarget::OriginContextUnavailable;
        };
        let mut prefix = package;
        for _ in 1..level {
            let Some((parent, _)) = prefix.rsplit_once('.') else {
                return PythonStaticImportTarget::RelativeAboveTopLevel;
            };
            prefix = parent;
        }
        if module.is_empty() {
            self.lookup(prefix)
        } else {
            self.lookup(&format!("{prefix}.{module}"))
        }
    }
}

fn record_spelling<'a>(
    folded: &mut BTreeMap<String, &'a str>,
    path: &'a str,
) -> Result<(), PythonStaticImportError> {
    if *folded.entry(path.to_ascii_lowercase()).or_insert(path) != path {
        return Err(PythonStaticImportError::AmbiguousInventory);
    }
    Ok(())
}

/// Failure to establish a bounded, source-scoped static import projection.
#[derive(Debug)]
pub enum PythonStaticImportError {
    /// A configured input or output limit was exceeded.
    ResourceLimit,
    /// The registration changed or contains invalid exact identities.
    InvalidBinding,
    /// The lexical report, root configuration, source or evaluation changed.
    StaleInput,
    /// The import root configuration edition is unsupported.
    UnsupportedConfiguration,
    /// The source inventory was not established as complete for selected roots.
    IncompleteInventory,
    /// Roots include a noncanonical or protected path.
    InvalidRootPath,
    /// Roots overlap or are duplicated.
    AmbiguousRoots,
    /// A root is absent or has no represented source inventory.
    RootUnavailable,
    /// Root contents include unsupported artifact types, shapes or names.
    UnsupportedRootContent,
    /// Root contents have conflicting case or file and directory spellings.
    AmbiguousInventory,
    /// No lexical occurrence facts were available.
    LexicalUnavailable,
    /// Strict JSON decoding or canonical serialization failed.
    Encoding(serde_json::Error),
}

impl Display for PythonStaticImportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResourceLimit => "Python static import resource limit exceeded",
            Self::InvalidBinding => "invalid Python import root binding",
            Self::StaleInput => "stale Python import analysis input",
            Self::UnsupportedConfiguration => "unsupported Python import root configuration",
            Self::IncompleteInventory => "Python roots have incomplete source inventory",
            Self::InvalidRootPath => "invalid Python import root path",
            Self::AmbiguousRoots => "overlapping or duplicate Python import roots",
            Self::RootUnavailable => "Python import root unavailable in source inventory",
            Self::UnsupportedRootContent => "unsupported Python import root content",
            Self::AmbiguousInventory => "ambiguous spelling in Python import inventory",
            Self::LexicalUnavailable => "admitted Python lexical occurrences unavailable",
            Self::Encoding(_) => "invalid Python static import JSON",
        })
    }
}

impl Error for PythonStaticImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}
