//! Explicit migration of legacy Rust symbol and semantic-finding references.
//!
//! Migration is exact-snapshot work. Ordinary analysis resolves unambiguous
//! aliases without rewriting authored authority; this module is the only path
//! that writes canonical current identities back to repository files.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::audit::{audit_repository, compile_repository_psm};
use crate::behavioral_realization::canonicalize_behavior_realization_contract_json;
use crate::environmental_semantics::canonicalize_environment_contract_json;
use crate::finding::CanonicalFinding;
use crate::finding_governance::FindingGovernanceDocument;
use crate::program_semantics::{
    ProgramSemanticModel, RUST_SYMBOL_IDENTITY_ALGORITHM, RUST_SYMBOL_IDENTITY_VERSION,
};
use crate::semantic_analysis::canonicalize_function_contract_json;

/// Canonical identity-migration plan schema.
pub const IDENTITY_MIGRATION_SCHEMA: &str = "urn:fortress:schema:v1:identity-migration";
/// Canonical identity-migration plan schema version.
pub const IDENTITY_MIGRATION_SCHEMA_VERSION: u16 = 1;

const FUNCTION_CONTRACT_FILE: &str = "function_contracts.json";
const ENVIRONMENT_CONTRACT_FILE: &str = "environment_contracts.json";
const REALIZATION_CONTRACT_FILE: &str = "behavior_realization_contracts.json";
const FINDING_GOVERNANCE_FILE: &str = "finding_governance.json";

/// Kind of authored legacy identity rewritten by a migration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityReferenceKind {
    /// An authored target using the legacy Rust symbol namespace.
    RustSymbol,
    /// An authored baseline or exception using a legacy semantic-finding ID.
    SemanticFinding,
}

/// One unambiguous authored-reference replacement.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct IdentityReferenceMigration {
    kind: IdentityReferenceKind,
    authored_reference: String,
    canonical_reference: String,
    occurrences: usize,
}

impl IdentityReferenceMigration {
    fn new(kind: IdentityReferenceKind, authored: &str, canonical: &str) -> Self {
        Self {
            kind,
            authored_reference: authored.into(),
            canonical_reference: canonical.into(),
            occurrences: 1,
        }
    }

    /// Returns the reference family being migrated.
    #[must_use]
    pub const fn kind(&self) -> IdentityReferenceKind {
        self.kind
    }

    /// Returns the exact authored legacy reference.
    #[must_use]
    pub fn authored_reference(&self) -> &str {
        &self.authored_reference
    }

    /// Returns the exact current canonical reference.
    #[must_use]
    pub fn canonical_reference(&self) -> &str {
        &self.canonical_reference
    }

    /// Returns how many exact occurrences carry this replacement in the file.
    #[must_use]
    pub const fn occurrences(&self) -> usize {
        self.occurrences
    }
}

/// One repository authority file changed by an identity migration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityMigrationFile {
    path: String,
    before_digest: String,
    after_digest: String,
    replacements: Vec<IdentityReferenceMigration>,
    #[serde(skip)]
    content: Vec<u8>,
}

impl IdentityMigrationFile {
    /// Returns the canonical repository-relative authority path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the digest whose bytes must still exist before application.
    #[must_use]
    pub fn before_digest(&self) -> &str {
        &self.before_digest
    }

    /// Returns the digest of canonical migrated bytes.
    #[must_use]
    pub fn after_digest(&self) -> &str {
        &self.after_digest
    }

    /// Returns exact unambiguous replacements in this authority file.
    #[must_use]
    pub fn replacements(&self) -> &[IdentityReferenceMigration] {
        &self.replacements
    }
}

/// Reviewable exact-snapshot identity migration plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityMigrationPlan {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    symbol_identity_algorithm: String,
    symbol_identity_version: u16,
    files: Vec<IdentityMigrationFile>,
    symbol_references: usize,
    semantic_finding_references: usize,
}

impl IdentityMigrationPlan {
    /// Returns files whose canonical bytes would change.
    #[must_use]
    pub fn files(&self) -> &[IdentityMigrationFile] {
        &self.files
    }

    /// Returns the number of legacy Rust symbol references mapped.
    #[must_use]
    pub const fn symbol_references(&self) -> usize {
        self.symbol_references
    }

    /// Returns the number of legacy semantic-finding references mapped.
    #[must_use]
    pub const fn semantic_finding_references(&self) -> usize {
        self.semantic_finding_references
    }

    /// Serializes canonical deterministic plan JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the plan cannot be encoded.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }

    /// Renders a concise human review surface.
    #[must_use]
    pub fn to_human(&self) -> String {
        let mut output = String::from("Semantic identity migration: PREVIEW\n");
        writeln!(output, "Files: {}", self.files.len()).expect("writing to a String cannot fail");
        writeln!(
            output,
            "Legacy symbol references: {}\nLegacy semantic finding references: {}",
            self.symbol_references, self.semantic_finding_references
        )
        .expect("writing to a String cannot fail");
        for file in &self.files {
            writeln!(output, "\n{}", file.path).expect("writing to a String cannot fail");
            for replacement in &file.replacements {
                writeln!(
                    output,
                    "  {:?} ({} occurrence(s)): {} -> {}",
                    replacement.kind,
                    replacement.occurrences,
                    replacement.authored_reference,
                    replacement.canonical_reference
                )
                .expect("writing to a String cannot fail");
            }
        }
        output
    }
}

/// Summary returned after an explicit migration was applied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityMigrationApplication {
    files_written: usize,
    symbol_references: usize,
    semantic_finding_references: usize,
}

impl IdentityMigrationApplication {
    /// Returns the number of authority files written.
    #[must_use]
    pub const fn files_written(&self) -> usize {
        self.files_written
    }

    /// Serializes a deterministic application summary.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the summary cannot be encoded.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }

    /// Returns a concise human application summary.
    #[must_use]
    pub fn to_human(&self) -> String {
        format!(
            "Semantic identity migration: APPLIED\nFiles written: {}\nLegacy symbol references: {}\nLegacy semantic finding references: {}\n",
            self.files_written, self.symbol_references, self.semantic_finding_references
        )
    }
}

/// Builds an exact-snapshot migration plan without changing repository authority.
///
/// # Errors
///
/// Returns an error when analysis fails, a legacy reference is ambiguous or
/// missing, authority is malformed, or a candidate path escapes the repository.
pub fn plan_repository_identity_migration(
    root: impl AsRef<Path>,
) -> Result<IdentityMigrationPlan, IdentityMigrationError> {
    let root = root.as_ref();
    let model = compile_repository_psm(root)
        .map_err(|error| IdentityMigrationError::Analysis(error.to_string()))?;
    let contract_plan = plan_identity_migration(root, &model, &[])?;
    if contract_plan.symbol_references > 0
        || contract_plan
            .files
            .iter()
            .any(|file| !file.path.ends_with(FINDING_GOVERNANCE_FILE))
    {
        return Ok(contract_plan);
    }
    let audit = audit_repository(root)
        .map_err(|error| IdentityMigrationError::Analysis(error.to_string()))?;
    plan_identity_migration(root, &model, audit.findings())
}

/// Applies a previously reviewed plan only while all source digests remain exact.
///
/// # Errors
///
/// Returns an error when authority changed after planning or a write fails. If a
/// write fails, already written files are restored from their exact prior bytes.
pub fn apply_repository_identity_migration(
    root: impl AsRef<Path>,
    plan: &IdentityMigrationPlan,
) -> Result<IdentityMigrationApplication, IdentityMigrationError> {
    let root = root.as_ref();
    let mut prior = Vec::new();
    for file in &plan.files {
        let path = repository_path(root, &file.path)?;
        let bytes = fs::read(&path).map_err(|source| IdentityMigrationError::Io {
            path: file.path.clone(),
            source,
        })?;
        if content_digest(&bytes) != file.before_digest {
            return Err(IdentityMigrationError::StalePlan(file.path.clone()));
        }
        prior.push((path, file.path.clone(), bytes));
    }
    for (index, file) in plan.files.iter().enumerate() {
        let path = &prior[index].0;
        if let Err(source) = fs::write(path, &file.content) {
            for (rollback_path, _, bytes) in prior.iter().take(index + 1) {
                let _ = fs::write(rollback_path, bytes);
            }
            return Err(IdentityMigrationError::Io {
                path: file.path.clone(),
                source,
            });
        }
    }
    Ok(IdentityMigrationApplication {
        files_written: plan.files.len(),
        symbol_references: plan.symbol_references,
        semantic_finding_references: plan.semantic_finding_references,
    })
}

fn plan_identity_migration(
    root: &Path,
    model: &ProgramSemanticModel,
    findings: &[CanonicalFinding],
) -> Result<IdentityMigrationPlan, IdentityMigrationError> {
    let symbols = symbol_aliases(model)?;
    let finding_aliases = finding_aliases(findings)?;
    let mut paths = Vec::new();
    collect_authority_files(root, root, &mut paths)?;
    paths.sort();
    let mut files = Vec::new();
    let mut symbol_references = 0;
    let mut semantic_finding_references = 0;
    for path in paths {
        let relative = normalized_relative(root, &path)?;
        let bytes = fs::read(&path).map_err(|source| IdentityMigrationError::Io {
            path: relative.clone(),
            source,
        })?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| IdentityMigrationError::InvalidUtf8(relative.clone()))?;
        let mut document: Value =
            serde_json::from_str(source).map_err(|error| IdentityMigrationError::InvalidJson {
                path: relative.clone(),
                detail: error.to_string(),
            })?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let mut replacements = Vec::new();
        if filename == FINDING_GOVERNANCE_FILE {
            migrate_finding_governance(&mut document, &finding_aliases, &mut replacements)?;
        } else {
            migrate_symbol_fields(&mut document, None, &symbols, &mut replacements)?;
            upgrade_contract_schema(filename, &mut document);
        }
        replacements = consolidate_replacements(replacements);
        let draft = format!(
            "{}\n",
            serde_json::to_string_pretty(&document)
                .map_err(IdentityMigrationError::Serialization)?
        );
        let content = canonical_migrated_document(filename, &relative, &draft)?.into_bytes();
        if replacements.is_empty() && content == bytes {
            continue;
        }
        symbol_references += replacements
            .iter()
            .filter(|replacement| replacement.kind == IdentityReferenceKind::RustSymbol)
            .map(|replacement| replacement.occurrences)
            .sum::<usize>();
        semantic_finding_references += replacements
            .iter()
            .filter(|replacement| replacement.kind == IdentityReferenceKind::SemanticFinding)
            .map(|replacement| replacement.occurrences)
            .sum::<usize>();
        files.push(IdentityMigrationFile {
            path: relative,
            before_digest: content_digest(&bytes),
            after_digest: content_digest(&content),
            replacements,
            content,
        });
    }
    Ok(IdentityMigrationPlan {
        schema: IDENTITY_MIGRATION_SCHEMA.into(),
        schema_version: IDENTITY_MIGRATION_SCHEMA_VERSION,
        symbol_identity_algorithm: RUST_SYMBOL_IDENTITY_ALGORITHM.into(),
        symbol_identity_version: RUST_SYMBOL_IDENTITY_VERSION,
        files,
        symbol_references,
        semantic_finding_references,
    })
}

fn consolidate_replacements(
    replacements: Vec<IdentityReferenceMigration>,
) -> Vec<IdentityReferenceMigration> {
    let mut counts = BTreeMap::new();
    for replacement in replacements {
        *counts
            .entry((
                replacement.kind,
                replacement.authored_reference,
                replacement.canonical_reference,
            ))
            .or_insert(0_usize) += replacement.occurrences;
    }
    counts
        .into_iter()
        .map(
            |((kind, authored_reference, canonical_reference), occurrences)| {
                IdentityReferenceMigration {
                    kind,
                    authored_reference,
                    canonical_reference,
                    occurrences,
                }
            },
        )
        .collect()
}

fn canonical_migrated_document(
    filename: &str,
    path: &str,
    draft: &str,
) -> Result<String, IdentityMigrationError> {
    match filename {
        FUNCTION_CONTRACT_FILE => canonicalize_function_contract_json(path, draft)
            .map_err(|error| IdentityMigrationError::InvalidMigratedContract(error.to_string())),
        ENVIRONMENT_CONTRACT_FILE => canonicalize_environment_contract_json(path, draft)
            .map_err(|error| IdentityMigrationError::InvalidMigratedContract(error.to_string())),
        REALIZATION_CONTRACT_FILE => canonicalize_behavior_realization_contract_json(draft)
            .map_err(|error| IdentityMigrationError::InvalidMigratedContract(error.to_string())),
        FINDING_GOVERNANCE_FILE => {
            let authority = FindingGovernanceDocument::from_json_str(draft).map_err(|error| {
                IdentityMigrationError::InvalidMigratedGovernance(error.to_string())
            })?;
            authority
                .to_canonical_json()
                .map_err(IdentityMigrationError::Serialization)
        }
        _ => Ok(draft.into()),
    }
}

fn symbol_aliases(
    model: &ProgramSemanticModel,
) -> Result<BTreeMap<String, String>, IdentityMigrationError> {
    let mut candidates = BTreeMap::<String, BTreeSet<String>>::new();
    for symbol in model.symbols() {
        for legacy in symbol.legacy_ids() {
            candidates
                .entry(legacy.clone())
                .or_default()
                .insert(symbol.id().into());
        }
    }
    resolve_unique_aliases(candidates, "Rust symbol")
}

fn finding_aliases(
    findings: &[CanonicalFinding],
) -> Result<BTreeMap<String, CanonicalFinding>, IdentityMigrationError> {
    let mut result = BTreeMap::new();
    for finding in findings {
        for legacy in finding.legacy_finding_ids() {
            if let Some(previous) = result.insert(legacy.clone(), finding.clone())
                && previous.finding_id() != finding.finding_id()
            {
                return Err(IdentityMigrationError::AmbiguousReference {
                    kind: "semantic finding".into(),
                    reference: legacy.clone(),
                });
            }
        }
    }
    Ok(result)
}

fn resolve_unique_aliases(
    candidates: BTreeMap<String, BTreeSet<String>>,
    kind: &str,
) -> Result<BTreeMap<String, String>, IdentityMigrationError> {
    candidates
        .into_iter()
        .map(|(legacy, current)| {
            if current.len() != 1 {
                return Err(IdentityMigrationError::AmbiguousReference {
                    kind: kind.into(),
                    reference: legacy,
                });
            }
            Ok((legacy, current.into_iter().next().expect("one candidate")))
        })
        .collect()
}

fn migrate_symbol_fields(
    value: &mut Value,
    key: Option<&str>,
    aliases: &BTreeMap<String, String>,
    replacements: &mut Vec<IdentityReferenceMigration>,
) -> Result<(), IdentityMigrationError> {
    match value {
        Value::Object(object) => {
            for (field, child) in object {
                migrate_symbol_fields(child, Some(field), aliases, replacements)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                migrate_symbol_fields(child, key, aliases, replacements)?;
            }
        }
        Value::String(reference)
            if matches!(
                key,
                Some("symbol" | "boundary" | "continuation" | "handler")
            ) && reference.starts_with("rust_symbol:sha256:") =>
        {
            let current = aliases
                .get(reference)
                .ok_or_else(|| IdentityMigrationError::MissingLegacyReference(reference.clone()))?;
            replacements.push(IdentityReferenceMigration::new(
                IdentityReferenceKind::RustSymbol,
                reference,
                current,
            ));
            *reference = current.clone();
        }
        _ => {}
    }
    Ok(())
}

fn migrate_finding_governance(
    document: &mut Value,
    aliases: &BTreeMap<String, CanonicalFinding>,
    replacements: &mut Vec<IdentityReferenceMigration>,
) -> Result<(), IdentityMigrationError> {
    let Some(object) = document.as_object_mut() else {
        return Err(IdentityMigrationError::InvalidMigratedGovernance(
            "root must be an object".into(),
        ));
    };
    if let Some(baseline) = object.get_mut("baseline").and_then(Value::as_object_mut) {
        if let Some(entries) = baseline
            .get_mut("active_entries")
            .and_then(Value::as_array_mut)
        {
            for entry in entries.iter_mut() {
                migrate_baseline_entry(entry, aliases, replacements)?;
            }
            entries.sort_by_key(|entry| {
                entry
                    .get("finding_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            });
            let mut ids = BTreeSet::new();
            if entries.iter().any(|entry| {
                !ids.insert(
                    entry
                        .get("finding_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
            }) {
                return Err(IdentityMigrationError::AmbiguousGovernanceMigration);
            }
        }
        if let Some(entries) = baseline
            .get_mut("retired_entries")
            .and_then(Value::as_array_mut)
        {
            for entry in entries.iter_mut() {
                migrate_finding_reference(entry, aliases, replacements, false)?;
            }
            entries.sort_by_key(|entry| {
                entry
                    .get("finding_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            });
        }
    }
    if let Some(exceptions) = object.get_mut("exceptions").and_then(Value::as_array_mut) {
        for exception in exceptions.iter_mut() {
            migrate_finding_reference(exception, aliases, replacements, false)?;
        }
        exceptions.sort_by_key(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        });
    }
    Ok(())
}

fn migrate_baseline_entry(
    entry: &mut Value,
    aliases: &BTreeMap<String, CanonicalFinding>,
    replacements: &mut Vec<IdentityReferenceMigration>,
) -> Result<(), IdentityMigrationError> {
    let Some(reference) = entry.get("finding_id").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(finding) = aliases.get(reference) else {
        return Ok(());
    };
    let authored = reference.to_owned();
    verify_finding_authority(entry, finding)?;
    let object = entry
        .as_object_mut()
        .expect("baseline entry with finding_id is an object");
    object.insert(
        "finding_id".into(),
        Value::String(finding.finding_id().into()),
    );
    object.insert(
        "violation_discriminator".into(),
        Value::String(
            finding
                .violation_discriminator()
                .unwrap_or("VIOLATION")
                .into(),
        ),
    );
    replacements.push(IdentityReferenceMigration::new(
        IdentityReferenceKind::SemanticFinding,
        &authored,
        finding.finding_id(),
    ));
    Ok(())
}

fn migrate_finding_reference(
    entry: &mut Value,
    aliases: &BTreeMap<String, CanonicalFinding>,
    replacements: &mut Vec<IdentityReferenceMigration>,
    verify_subjects: bool,
) -> Result<(), IdentityMigrationError> {
    let Some(reference) = entry.get("finding_id").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(finding) = aliases.get(reference) else {
        return Ok(());
    };
    let authored = reference.to_owned();
    if verify_subjects {
        verify_finding_authority(entry, finding)?;
    } else if entry.get("rule_id").and_then(Value::as_str) != Some(finding.rule_id()) {
        return Err(IdentityMigrationError::FindingAuthorityMismatch(authored));
    }
    entry
        .as_object_mut()
        .expect("finding reference entry is an object")
        .insert(
            "finding_id".into(),
            Value::String(finding.finding_id().into()),
        );
    replacements.push(IdentityReferenceMigration::new(
        IdentityReferenceKind::SemanticFinding,
        &authored,
        finding.finding_id(),
    ));
    Ok(())
}

fn verify_finding_authority(
    entry: &Value,
    finding: &CanonicalFinding,
) -> Result<(), IdentityMigrationError> {
    let rule_matches = entry.get("rule_id").and_then(Value::as_str) == Some(finding.rule_id());
    let subjects_match = entry
        .get("subjects")
        .and_then(Value::as_array)
        .is_some_and(|subjects| {
            subjects
                .iter()
                .filter_map(Value::as_str)
                .eq(finding.entities().iter().map(String::as_str))
        });
    if rule_matches && subjects_match {
        Ok(())
    } else {
        Err(IdentityMigrationError::FindingAuthorityMismatch(
            entry
                .get("finding_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
        ))
    }
}

fn upgrade_contract_schema(filename: &str, document: &mut Value) {
    let Some(object) = document.as_object_mut() else {
        return;
    };
    let (schema, version) = match filename {
        FUNCTION_CONTRACT_FILE => ("urn:fortress:schema:v5:function-contracts", 5),
        ENVIRONMENT_CONTRACT_FILE => ("urn:fortress:schema:v2:environment-contracts", 2),
        REALIZATION_CONTRACT_FILE => ("urn:fortress:schema:v2:behavior-realization-contracts", 2),
        _ => return,
    };
    object.insert("$schema".into(), Value::String(schema.into()));
    object.insert("schema_version".into(), Value::from(version));
}

fn collect_authority_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), IdentityMigrationError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| IdentityMigrationError::Io {
            path: normalized_relative(root, directory).unwrap_or_else(|_| ".".into()),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| IdentityMigrationError::Io {
            path: normalized_relative(root, directory).unwrap_or_else(|_| ".".into()),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|source| IdentityMigrationError::Io {
                path: normalized_relative(root, &path).unwrap_or_default(),
                source,
            })?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if entry.file_name() != ".git" && entry.file_name() != "target" {
                collect_authority_files(root, &path, output)?;
            }
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(
            name.as_ref(),
            FUNCTION_CONTRACT_FILE
                | ENVIRONMENT_CONTRACT_FILE
                | REALIZATION_CONTRACT_FILE
                | FINDING_GOVERNANCE_FILE
        ) {
            output.push(path);
        }
    }
    Ok(())
}

fn normalized_relative(root: &Path, path: &Path) -> Result<String, IdentityMigrationError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| IdentityMigrationError::PathEscape(path.display().to_string()))?;
    let normalized = relative.to_string_lossy().replace('\\', "/");
    if normalized.split('/').any(|segment| segment == "..") {
        return Err(IdentityMigrationError::PathEscape(normalized));
    }
    Ok(if normalized.is_empty() {
        ".".into()
    } else {
        normalized
    })
}

fn repository_path(root: &Path, relative: &str) -> Result<PathBuf, IdentityMigrationError> {
    if relative.starts_with('/')
        || relative.contains('\\')
        || relative.split('/').any(|segment| segment == "..")
    {
        return Err(IdentityMigrationError::PathEscape(relative.into()));
    }
    Ok(root.join(relative))
}

fn content_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Identity migration failure.
#[derive(Debug)]
pub enum IdentityMigrationError {
    /// Snapshot analysis could not establish exact current mappings.
    Analysis(String),
    /// Repository I/O failed.
    Io {
        /// Repository-relative path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A candidate authority file was not UTF-8.
    InvalidUtf8(String),
    /// A candidate authority document was malformed JSON.
    InvalidJson {
        /// Repository-relative path.
        path: String,
        /// Parser detail.
        detail: String,
    },
    /// A legacy reference maps to multiple current entities.
    AmbiguousReference {
        /// Reference family.
        kind: String,
        /// Ambiguous legacy identity.
        reference: String,
    },
    /// A legacy symbol reference has no exact current-snapshot target.
    MissingLegacyReference(String),
    /// Finding rule or subject authority does not match the mapped finding.
    FindingAuthorityMismatch(String),
    /// Multiple baseline entries collapse to one current finding.
    AmbiguousGovernanceMigration,
    /// Migrated finding governance does not validate canonically.
    InvalidMigratedGovernance(String),
    /// Migrated distributed-contract authority does not validate canonically.
    InvalidMigratedContract(String),
    /// A reviewed plan no longer matches current authority bytes.
    StalePlan(String),
    /// A candidate path was not repository relative.
    PathEscape(String),
    /// Canonical JSON serialization failed.
    Serialization(serde_json::Error),
}

impl Display for IdentityMigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analysis(detail) => write!(formatter, "snapshot analysis failed: {detail}"),
            Self::Io { path, source } => write!(formatter, "I/O failed for `{path}`: {source}"),
            Self::InvalidUtf8(path) => write!(formatter, "`{path}` is not UTF-8"),
            Self::InvalidJson { path, detail } => {
                write!(formatter, "invalid JSON in `{path}`: {detail}")
            }
            Self::AmbiguousReference { kind, reference } => {
                write!(formatter, "ambiguous {kind} legacy reference `{reference}`")
            }
            Self::MissingLegacyReference(reference) => {
                write!(
                    formatter,
                    "legacy symbol reference `{reference}` has no current target"
                )
            }
            Self::FindingAuthorityMismatch(reference) => write!(
                formatter,
                "legacy finding `{reference}` does not match current rule and subject authority"
            ),
            Self::AmbiguousGovernanceMigration => write!(
                formatter,
                "multiple governed entries map to one current finding; migration requires review"
            ),
            Self::InvalidMigratedGovernance(detail) => {
                write!(
                    formatter,
                    "migrated finding governance is invalid: {detail}"
                )
            }
            Self::InvalidMigratedContract(detail) => {
                write!(
                    formatter,
                    "migrated distributed contract is invalid: {detail}"
                )
            }
            Self::StalePlan(path) => {
                write!(formatter, "migration plan is stale for `{path}`")
            }
            Self::PathEscape(path) => {
                write!(
                    formatter,
                    "migration path is not repository relative: `{path}`"
                )
            }
            Self::Serialization(source) => write!(formatter, "migration JSON failed: {source}"),
        }
    }
}

impl Error for IdentityMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialization(source) => Some(source),
            _ => None,
        }
    }
}
