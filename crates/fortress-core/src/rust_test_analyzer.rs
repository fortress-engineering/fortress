//! Structured Rust test fact extraction subordinate to Fortress rule semantics.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::visit::Visit;
use syn::{Attribute, Expr, ItemFn, Lit, Meta};

use crate::identity::StableId;
use crate::snapshot::RepositorySnapshot;

/// Rule-relevant classification of one registered Rust test.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RustTestClassification {
    /// Product or feature behavior requiring a valid requirement mapping.
    Behavioral,
    /// Specification-authored conformance behavior requiring a mapping.
    Conformance,
    /// Implementation-only evidence that may intentionally lack a requirement mapping.
    Infrastructure,
}

impl RustTestClassification {
    /// Returns the canonical serialized classification spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Behavioral => "behavioral",
            Self::Conformance => "conformance",
            Self::Infrastructure => "infrastructure",
        }
    }
}

/// One deterministic analyzer-observed Rust test fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RustTestFact {
    id: String,
    path: String,
    symbol: String,
    classification: RustTestClassification,
    declared_requirement: Option<String>,
}

impl RustTestFact {
    /// Creates a validated analyzer fact, also used by rule conformance fixtures.
    ///
    /// # Errors
    ///
    /// Returns [`RustAnalyzerError`] for invalid test/requirement identities,
    /// paths, or empty symbols.
    pub fn new(
        id: impl Into<String>,
        path: impl Into<String>,
        symbol: impl Into<String>,
        classification: RustTestClassification,
        declared_requirement: Option<String>,
    ) -> Result<Self, RustAnalyzerError> {
        let id = id.into();
        validate_test_id(&id)?;
        let path = path.into();
        if !is_canonical_relative_path(&path) {
            return Err(RustAnalyzerError::InvalidPath(path.into()));
        }
        let symbol = symbol.into();
        if symbol.is_empty() {
            return Err(RustAnalyzerError::EmptySymbol);
        }
        if let Some(requirement) = &declared_requirement {
            StableId::parse(requirement).map_err(|error| {
                RustAnalyzerError::InvalidRequirementId {
                    value: requirement.clone().into(),
                    detail: error.to_string().into(),
                }
            })?;
        }
        Ok(Self {
            id,
            path,
            symbol,
            classification,
            declared_requirement,
        })
    }

    /// Returns the stable test identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the canonical source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the Rust function symbol.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the analyzer classification.
    #[must_use]
    pub const fn classification(&self) -> RustTestClassification {
        self.classification
    }

    /// Returns an explicit source-declared requirement when present.
    #[must_use]
    pub fn declared_requirement(&self) -> Option<&str> {
        self.declared_requirement.as_deref()
    }
}

/// Analyzes all Rust source files whose exact content is bound into a snapshot.
///
/// Each file is re-read and compared with the snapshot byte size and SHA-256
/// before parsing. Mutation after snapshot construction is rejected rather than
/// allowing analyzer facts to refer to different bytes.
///
/// # Errors
///
/// Returns [`RustAnalyzerError`] for I/O, snapshot-content mismatch, invalid
/// Rust syntax, or malformed Fortress test metadata.
pub fn analyze_snapshot_rust_tests(
    root: impl AsRef<Path>,
    snapshot: &RepositorySnapshot,
) -> Result<Vec<RustTestFact>, RustAnalyzerError> {
    let root = root.as_ref();
    let mut facts = Vec::new();
    for file in snapshot.files().iter().filter(|file| {
        Path::new(file.path())
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
    }) {
        let absolute = root.join(file.path());
        let bytes = fs::read(&absolute).map_err(|source| RustAnalyzerError::Io {
            path: absolute.clone(),
            source,
        })?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if u64::try_from(bytes.len()).ok() != Some(file.size()) || digest != file.sha256() {
            return Err(RustAnalyzerError::SnapshotContentMismatch(
                file.path().into(),
            ));
        }
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| RustAnalyzerError::NonUtf8(file.path().into()))?;
        facts.extend(analyze_rust_source(file.path(), source)?);
    }
    facts.sort();
    Ok(facts)
}

/// Extracts deterministic test facts from one Rust source document.
///
/// # Errors
///
/// Returns [`RustAnalyzerError`] for invalid syntax or test metadata.
pub fn analyze_rust_source(
    path: &str,
    source: &str,
) -> Result<Vec<RustTestFact>, RustAnalyzerError> {
    if !is_canonical_relative_path(path) {
        return Err(RustAnalyzerError::InvalidPath(path.into()));
    }
    let syntax = syn::parse_file(source).map_err(|error| RustAnalyzerError::Parse {
        path: path.into(),
        detail: error.to_string().into(),
    })?;
    let mut visitor = TestVisitor {
        path,
        facts: Vec::new(),
        error: None,
    };
    visitor.visit_file(&syntax);
    if let Some(error) = visitor.error {
        return Err(error);
    }
    visitor.facts.sort();
    Ok(visitor.facts)
}

struct TestVisitor<'a> {
    path: &'a str,
    facts: Vec<RustTestFact>,
    error: Option<RustAnalyzerError>,
}

impl<'ast> Visit<'ast> for TestVisitor<'_> {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        if self.error.is_some() {
            return;
        }
        if function
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        {
            let symbol = function.sig.ident.to_string();
            match metadata_from_attributes(&function.attrs, &symbol).and_then(
                |(id, classification, requirement)| {
                    RustTestFact::new(id, self.path, symbol, classification, requirement)
                },
            ) {
                Ok(fact) => self.facts.push(fact),
                Err(error) => self.error = Some(error),
            }
        }
        syn::visit::visit_item_fn(self, function);
    }
}

fn metadata_from_attributes(
    attributes: &[Attribute],
    symbol: &str,
) -> Result<(String, RustTestClassification, Option<String>), RustAnalyzerError> {
    let docs: Vec<String> = attributes.iter().filter_map(doc_attribute).collect();
    let mut ids: Vec<String> = docs
        .iter()
        .flat_map(|line| backtick_values(line))
        .filter(|value| value.starts_with("T-"))
        .collect();
    ids.sort();
    ids.dedup();
    let id = match ids.as_slice() {
        [] => return Err(RustAnalyzerError::MissingTestId(symbol.into())),
        [id] => id.clone(),
        _ => return Err(RustAnalyzerError::MultipleTestIds(symbol.into())),
    };
    let classification = if docs
        .iter()
        .any(|line| line.trim() == "Fortress classification: infrastructure")
    {
        RustTestClassification::Infrastructure
    } else if id.starts_with("T-ARCH-")
        || id.starts_with("T-DEP-")
        || id.starts_with("T-CONTRACT-")
        || id.starts_with("T-REPO-")
        || id.starts_with("T-STD-")
        || id.starts_with("T-TEST-")
    {
        RustTestClassification::Conformance
    } else {
        RustTestClassification::Behavioral
    };
    let requirements: Vec<String> = docs
        .iter()
        .filter_map(|line| line.trim().strip_prefix("Fortress requirement: "))
        .map(str::to_owned)
        .collect();
    let requirement = match requirements.as_slice() {
        [] => None,
        [requirement] => Some(requirement.clone()),
        _ => return Err(RustAnalyzerError::MultipleRequirementMarkers(symbol.into())),
    };
    Ok((id, classification, requirement))
}

fn doc_attribute(attribute: &Attribute) -> Option<String> {
    if !attribute.path().is_ident("doc") {
        return None;
    }
    let Meta::NameValue(name_value) = &attribute.meta else {
        return None;
    };
    let Expr::Lit(expression) = &name_value.value else {
        return None;
    };
    let Lit::Str(value) = &expression.lit else {
        return None;
    };
    Some(value.value())
}

fn backtick_values(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, value)| value.to_owned())
}

fn validate_test_id(id: &str) -> Result<(), RustAnalyzerError> {
    if !id.starts_with("T-") {
        return Err(RustAnalyzerError::InvalidTestId {
            value: id.into(),
            detail: "test IDs must use the T namespace".into(),
        });
    }
    StableId::parse(id).map_err(|error| RustAnalyzerError::InvalidTestId {
        value: id.into(),
        detail: error.to_string().into(),
    })?;
    Ok(())
}

/// Explains why deterministic Rust test analysis failed.
#[derive(Debug)]
pub enum RustAnalyzerError {
    /// Source path is not canonical and repository-relative.
    InvalidPath(Box<str>),
    /// Test ID is not canonical.
    InvalidTestId {
        /// Invalid serialized test identity.
        value: Box<str>,
        /// Stable identity validation detail.
        detail: Box<str>,
    },
    /// Explicit requirement identity is invalid.
    InvalidRequirementId {
        /// Invalid serialized requirement identity.
        value: Box<str>,
        /// Stable identity validation detail.
        detail: Box<str>,
    },
    /// Test symbol was empty.
    EmptySymbol,
    /// A test lacked its stable doc-comment identity.
    MissingTestId(Box<str>),
    /// A test declared multiple stable identities.
    MultipleTestIds(Box<str>),
    /// A test declared multiple requirement markers.
    MultipleRequirementMarkers(Box<str>),
    /// Snapshot-bound bytes changed before analysis.
    SnapshotContentMismatch(Box<str>),
    /// Rust source was not UTF-8.
    NonUtf8(Box<str>),
    /// Rust source could not be parsed.
    Parse {
        /// Canonical source path.
        path: Box<str>,
        /// Parser diagnostic.
        detail: Box<str>,
    },
    /// Snapshot-bound source could not be read.
    Io {
        /// Filesystem path used for the read.
        path: PathBuf,
        /// Underlying read failure.
        source: std::io::Error,
    },
}

impl Display for RustAnalyzerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => {
                write!(formatter, "Rust test source path `{path}` is invalid")
            }
            Self::InvalidTestId { value, detail } => {
                write!(formatter, "Rust test ID `{value}` is invalid: {detail}")
            }
            Self::InvalidRequirementId { value, detail } => write!(
                formatter,
                "Rust test requirement `{value}` is invalid: {detail}"
            ),
            Self::EmptySymbol => formatter.write_str("Rust test symbol is empty"),
            Self::MissingTestId(symbol) => write!(
                formatter,
                "Rust test `{symbol}` has no stable test ID doc comment"
            ),
            Self::MultipleTestIds(symbol) => write!(
                formatter,
                "Rust test `{symbol}` declares multiple stable test IDs"
            ),
            Self::MultipleRequirementMarkers(symbol) => write!(
                formatter,
                "Rust test `{symbol}` declares multiple requirement markers"
            ),
            Self::SnapshotContentMismatch(path) => write!(
                formatter,
                "Rust test source `{path}` differs from the stabilized snapshot"
            ),
            Self::NonUtf8(path) => write!(formatter, "Rust test source `{path}` is not UTF-8"),
            Self::Parse { path, detail } => write!(
                formatter,
                "Rust test source `{path}` is invalid Rust: {detail}"
            ),
            Self::Io { path, source } => write!(
                formatter,
                "failed to read Rust test source {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for RustAnalyzerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn is_canonical_relative_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_path = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !value.is_empty()
        && !drive_path
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::{RustAnalyzerError, RustTestClassification, analyze_rust_source};

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-001`
    #[test]
    fn structured_analyzer_extracts_identity_classification_and_requirement() {
        let source = r"
            /// `T-AF-SAMPLE-0001-R01-001`
            /// Fortress requirement: AF-SAMPLE-0001-R01
            #[test]
            fn behavior() {}

            /// `T-AF-SAMPLE-0001-INFRA-001`
            /// Fortress classification: infrastructure
            #[test]
            fn helper() {}
        ";
        let facts = analyze_rust_source("tests/sample.rs", source).expect("source analyzes");
        assert_eq!(facts.len(), 2);
        assert_eq!(
            facts[0].classification(),
            RustTestClassification::Infrastructure
        );
        assert_eq!(facts[1].declared_requirement(), Some("AF-SAMPLE-0001-R01"));
    }

    /// `T-AF-SNAPSHOT-GOVERNANCE-0001-R06-002`
    #[test]
    fn structured_analyzer_rejects_unidentified_behavior_test() {
        let error = analyze_rust_source("tests/sample.rs", "#[test]\nfn missing_identity() {}")
            .expect_err("missing identity must fail");
        assert!(matches!(error, RustAnalyzerError::MissingTestId(_)));
    }
}
