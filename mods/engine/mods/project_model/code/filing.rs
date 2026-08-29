//! Canonical, language-neutral Project Filing System model.
//!
//! The model separates recursive Fortress Module structure from registered
//! ecosystem-required paths. It inventories every observed leaf file while
//! retaining only Module/Element/role/collection/partition aggregates as
//! project structure; leaf files never become CCG nodes.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version-one filing profile schema identity.
pub const FILING_PROFILE_SCHEMA: &str = "urn:fortress:schema:v1:filing-system-profiles";
/// Current filing profile schema version.
pub const FILING_PROFILE_SCHEMA_VERSION: u16 = 1;
/// Current deterministic filing-model semantic version.
pub const FILING_MODEL_SEMANTIC_VERSION: &str = "1.0.0";

/// Closed universal Data role vocabulary for the current Standard edition.
pub const DATA_ROLES: [&str; 10] = [
    "config",
    "dataset",
    "fixture",
    "migration",
    "policy",
    "reference",
    "resource",
    "schema",
    "seed",
    "template",
];

/// Closed universal Info role vocabulary for the current Standard edition.
pub const INFO_ROLES: [&str; 8] = [
    "evidence", "graph", "index", "log", "manifest", "metric", "report", "snapshot",
];

const CANONICAL_ELEMENTS: [&str; 5] = ["code", "data", "docs", "info", "mods"];
const CANONICAL_DOCS: [&str; 4] = [
    "code_docs.md",
    "data_docs.md",
    "info_docs.md",
    "mods_docs.md",
];

/// Standard-owned registry of ecosystem-required repository surfaces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilingSystemProfiles {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    profiles: Vec<EcosystemFilingProfile>,
}

/// One ecosystem's explicit filesystem resolution boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EcosystemFilingProfile {
    id: String,
    root_entries: Vec<RegisteredRootEntry>,
    element_files: Vec<RegisteredElementFile>,
    mechanical_code_structures: Vec<MechanicalCodeStructure>,
}

/// A registered non-Fortress root entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredRootEntry {
    path: String,
    kind: RootEntryKind,
    classification: RootEntryClassification,
}

/// Whether a registered root path is a file or opaque ecosystem directory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootEntryKind {
    /// One exact root file.
    File,
    /// One exact root directory whose descendants belong to the ecosystem.
    Directory,
}

/// Universal classification of one direct repository-root entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootEntryClassification {
    /// README, contract, or a canonical Module Element.
    FortressCanonical,
    /// A validated external ecosystem requires the entry.
    EcosystemRequired,
    /// A validated generator owns the persisted root projection.
    GeneratedAllowed,
    /// No canonical or registered authority admits the entry.
    Invalid,
}

/// One ecosystem-owned filename valid in Data or Info.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredElementFile {
    element: String,
    filename: String,
}

/// One explicit mechanical namespace tree permitted beneath `code/`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MechanicalCodeStructure {
    path: String,
    allow_descendants: bool,
}

impl FilingSystemProfiles {
    /// Parses and validates an ecosystem profile registry.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid JSON, schema identity, duplicate
    /// registrations, noncanonical paths, or unsupported element names.
    pub fn from_json_str(source: &str) -> Result<Self, FilingProfileError> {
        let profiles: Self = serde_json::from_str(source).map_err(FilingProfileError::Json)?;
        profiles.validate()?;
        Ok(profiles)
    }

    /// Loads the canonical Standard-owned profiles embedded with the engine.
    ///
    /// # Panics
    ///
    /// Panics only when the engine's compile-time profile document violates its
    /// own validated schema, which is an internal release-integrity defect.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_json_str(include_str!("../data/filing_system_profiles.json"))
            .expect("embedded filing-system profiles must validate")
    }

    /// Builds a registry for conformance fixtures and future language profiles.
    ///
    /// # Errors
    ///
    /// Returns a typed profile error when the supplied document is invalid.
    pub fn from_profiles(
        profiles: Vec<EcosystemFilingProfile>,
    ) -> Result<Self, FilingProfileError> {
        let registry = Self {
            schema: FILING_PROFILE_SCHEMA.into(),
            schema_version: FILING_PROFILE_SCHEMA_VERSION,
            profiles,
        };
        registry.validate()?;
        Ok(registry)
    }

    /// Returns registered profile records.
    #[must_use]
    pub fn profiles(&self) -> &[EcosystemFilingProfile] {
        &self.profiles
    }

    fn validate(&self) -> Result<(), FilingProfileError> {
        if self.schema != FILING_PROFILE_SCHEMA {
            return Err(FilingProfileError::InvalidSchema(
                self.schema.clone().into(),
            ));
        }
        if self.schema_version != FILING_PROFILE_SCHEMA_VERSION {
            return Err(FilingProfileError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        let mut profile_ids = BTreeSet::new();
        let mut root_entries = BTreeSet::new();
        let mut element_files = BTreeSet::new();
        let mut structures = BTreeSet::new();
        for profile in &self.profiles {
            if profile.id.trim().is_empty() || !profile_ids.insert(profile.id.as_str()) {
                return Err(FilingProfileError::DuplicateOrEmptyProfile(
                    profile.id.clone().into(),
                ));
            }
            for entry in &profile.root_entries {
                if !is_single_root_entry(&entry.path) {
                    return Err(FilingProfileError::InvalidRootEntry(
                        entry.path.clone().into(),
                    ));
                }
                if !root_entries.insert((entry.path.as_str(), entry.kind)) {
                    return Err(FilingProfileError::DuplicateRootEntry(
                        entry.path.clone().into(),
                    ));
                }
                if !matches!(
                    entry.classification,
                    RootEntryClassification::EcosystemRequired
                        | RootEntryClassification::GeneratedAllowed
                ) {
                    return Err(FilingProfileError::InvalidRootEntry(
                        entry.path.clone().into(),
                    ));
                }
            }
            for entry in &profile.element_files {
                if !matches!(entry.element.as_str(), "data" | "info")
                    || entry.filename.is_empty()
                    || entry.filename.contains(['/', '\\'])
                {
                    return Err(FilingProfileError::InvalidElementFile(
                        format!("{}/{}", entry.element, entry.filename).into(),
                    ));
                }
                if !element_files.insert((entry.element.as_str(), entry.filename.as_str())) {
                    return Err(FilingProfileError::DuplicateElementFile(
                        format!("{}/{}", entry.element, entry.filename).into(),
                    ));
                }
            }
            for structure in &profile.mechanical_code_structures {
                if !is_canonical_relative_path(&structure.path) {
                    return Err(FilingProfileError::InvalidCodeStructure(
                        structure.path.clone().into(),
                    ));
                }
                if !structures.insert(structure.path.as_str()) {
                    return Err(FilingProfileError::DuplicateCodeStructure(
                        structure.path.clone().into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn root_classification(
        &self,
        path: &str,
        kind: RootEntryKind,
    ) -> Option<RootEntryClassification> {
        self.profiles.iter().find_map(|profile| {
            profile
                .root_entries
                .iter()
                .find(|entry| entry.path == path && entry.kind == kind)
                .map(|entry| entry.classification)
        })
    }

    fn registered_element_file(&self, element: &str, filename: &str) -> bool {
        self.profiles.iter().any(|profile| {
            profile
                .element_files
                .iter()
                .any(|entry| entry.element == element && entry.filename == filename)
        })
    }

    fn code_structure_registered(&self, relative: &str) -> bool {
        self.profiles.iter().any(|profile| {
            profile.mechanical_code_structures.iter().any(|entry| {
                relative == entry.path
                    || entry.allow_descendants
                        && relative
                            .strip_prefix(&entry.path)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                    || entry
                        .path
                        .strip_prefix(relative)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        })
    }

    fn has_code_structures(&self) -> bool {
        self.profiles
            .iter()
            .any(|profile| !profile.mechanical_code_structures.is_empty())
    }
}

impl EcosystemFilingProfile {
    /// Creates one explicit ecosystem profile for tests or registered adapters.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        root_entries: Vec<RegisteredRootEntry>,
        element_files: Vec<RegisteredElementFile>,
        mechanical_code_structures: Vec<MechanicalCodeStructure>,
    ) -> Self {
        Self {
            id: id.into(),
            root_entries,
            element_files,
            mechanical_code_structures,
        }
    }
}

impl RegisteredRootEntry {
    /// Creates a registered ecosystem root entry.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        kind: RootEntryKind,
        classification: RootEntryClassification,
    ) -> Self {
        Self {
            path: path.into(),
            kind,
            classification,
        }
    }
}

impl RegisteredElementFile {
    /// Creates a registered ecosystem-owned Data/Info filename.
    #[must_use]
    pub fn new(element: impl Into<String>, filename: impl Into<String>) -> Self {
        Self {
            element: element.into(),
            filename: filename.into(),
        }
    }
}

impl MechanicalCodeStructure {
    /// Creates a mechanical namespace registration relative to `code/`.
    #[must_use]
    pub fn new(path: impl Into<String>, allow_descendants: bool) -> Self {
        Self {
            path: path.into(),
            allow_descendants,
        }
    }
}

/// Deterministic structural model of one observed repository.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectFilingModel {
    schema: String,
    schema_version: u16,
    semantic_version: String,
    root_entries: Vec<ClassifiedRootEntry>,
    modules: Vec<FilingModule>,
    collections: Vec<ElementCollection>,
    inventory: FilingInventory,
    violations: Vec<FilingSystemViolation>,
}

impl ProjectFilingModel {
    /// Returns every direct repository-root entry and its authority class.
    #[must_use]
    pub fn root_entries(&self) -> &[ClassifiedRootEntry] {
        &self.root_entries
    }

    /// Returns discovered recursive Modules.
    #[must_use]
    pub fn modules(&self) -> &[FilingModule] {
        &self.modules
    }

    /// Returns Data/Info flat surfaces and structured collections.
    #[must_use]
    pub fn collections(&self) -> &[ElementCollection] {
        &self.collections
    }

    /// Returns the complete deterministic machine inventory.
    #[must_use]
    pub const fn inventory(&self) -> &FilingInventory {
        &self.inventory
    }

    /// Returns normalized filing-system violations.
    #[must_use]
    pub fn violations(&self) -> &[FilingSystemViolation] {
        &self.violations
    }

    /// Returns whether the complete modeled structure is canonical.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// One direct root file/directory with its canonical authority classification.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClassifiedRootEntry {
    path: String,
    kind: RootEntryKind,
    classification: RootEntryClassification,
}

impl ClassifiedRootEntry {
    /// Returns the exact root name.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the authority classification.
    #[must_use]
    pub const fn classification(&self) -> RootEntryClassification {
        self.classification
    }
}

/// One discovered Module and the canonical Elements physically present.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FilingModule {
    path: String,
    elements: Vec<String>,
}

impl FilingModule {
    /// Returns the repository-relative Module path; the root is `.`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns present canonical Elements.
    #[must_use]
    pub fn elements(&self) -> &[String] {
        &self.elements
    }
}

/// One flat Element or structured Data/Info collection aggregate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ElementCollection {
    module: String,
    element: String,
    role: Option<String>,
    collection: Option<String>,
    partitions: usize,
    files: usize,
}

impl ElementCollection {
    /// Returns owning Module path.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns `data` or `info`.
    #[must_use]
    pub fn element(&self) -> &str {
        &self.element
    }

    /// Returns canonical role when structured.
    #[must_use]
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    /// Returns project collection when present.
    #[must_use]
    pub fn collection(&self) -> Option<&str> {
        self.collection.as_deref()
    }

    /// Returns mechanical partition count.
    #[must_use]
    pub const fn partitions(&self) -> usize {
        self.partitions
    }

    /// Returns complete leaf-file count beneath this aggregate.
    #[must_use]
    pub const fn files(&self) -> usize {
        self.files
    }
}

/// Complete leaf inventory kept outside the CCG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilingInventory {
    digest: String,
    entries: Vec<FilingInventoryEntry>,
}

impl FilingInventory {
    /// Returns a digest over sorted repository-relative paths.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns every observed file exactly once.
    #[must_use]
    pub fn entries(&self) -> &[FilingInventoryEntry] {
        &self.entries
    }
}

/// Machine classification of one leaf file.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FilingInventoryEntry {
    path: String,
    module: String,
    element: String,
    role: Option<String>,
    collection: Option<String>,
    partition: Option<String>,
}

impl FilingInventoryEntry {
    /// Returns canonical repository-relative file path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Stable normalized filing-system diagnostic kinds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilingViolationKind {
    /// Module root contains a noncanonical file or directory.
    UnknownModuleRootEntry,
    /// A present Element lacks its canonical companion document.
    MissingRequiredElementDoc,
    /// `docs/` contains a noncanonical file.
    UnrecognizedDocFile,
    /// `docs/` contains a subdirectory.
    DocSubdirectoryForbidden,
    /// `code/` contains unregistered project-semantic grouping.
    CodeSemanticSubdirectory,
    /// A claimed mechanical code structure is absent from the profile registry.
    UnregisteredCodeStructure,
    /// Structured Data begins with an unknown role.
    UnknownDataRole,
    /// Structured Info begins with an unknown role.
    UnknownInfoRole,
    /// Data/Info has more semantic levels than role + collection.
    ExcessiveCollectionDepth,
    /// A mechanical partition name is invalid.
    InvalidPartition,
    /// A partition contains a directory.
    PartitionRecursion,
    /// A directory contributes no recognized structural information.
    RedundantDirectoryLevel,
    /// Direct files and structured role directories coexist.
    MixedFlatAndStructuredElement,
    /// A version suffix is malformed or redundantly duplicated.
    InvalidVersionSuffix,
    /// A collection violates the canonical lexical grammar.
    InvalidCollectionName,
    /// Module lacks README, contract, or code/mods realization.
    MissingModuleRequirement,
    /// `mods/` contains a loose file.
    LooseModsEntry,
    /// A Fortress-controlled filename violates canonical grammar.
    InvalidFilename,
}

impl FilingViolationKind {
    /// Returns the stable machine vocabulary spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownModuleRootEntry => "UNKNOWN_MODULE_ROOT_ENTRY",
            Self::MissingRequiredElementDoc => "MISSING_REQUIRED_ELEMENT_DOC",
            Self::UnrecognizedDocFile => "UNRECOGNIZED_DOC_FILE",
            Self::DocSubdirectoryForbidden => "DOC_SUBDIRECTORY_FORBIDDEN",
            Self::CodeSemanticSubdirectory => "CODE_SEMANTIC_SUBDIRECTORY",
            Self::UnregisteredCodeStructure => "UNREGISTERED_CODE_STRUCTURE",
            Self::UnknownDataRole => "UNKNOWN_DATA_ROLE",
            Self::UnknownInfoRole => "UNKNOWN_INFO_ROLE",
            Self::ExcessiveCollectionDepth => "EXCESSIVE_COLLECTION_DEPTH",
            Self::InvalidPartition => "INVALID_PARTITION",
            Self::PartitionRecursion => "PARTITION_RECURSION",
            Self::RedundantDirectoryLevel => "REDUNDANT_DIRECTORY_LEVEL",
            Self::MixedFlatAndStructuredElement => "MIXED_FLAT_AND_STRUCTURED_ELEMENT",
            Self::InvalidVersionSuffix => "INVALID_VERSION_SUFFIX",
            Self::InvalidCollectionName => "INVALID_COLLECTION_NAME",
            Self::MissingModuleRequirement => "MISSING_MODULE_REQUIREMENT",
            Self::LooseModsEntry => "LOOSE_MODS_ENTRY",
            Self::InvalidFilename => "INVALID_FILENAME",
        }
    }
}

/// One explainable structural violation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FilingSystemViolation {
    kind: FilingViolationKind,
    module: String,
    element: String,
    path: String,
    law: String,
    expected: String,
}

impl FilingSystemViolation {
    /// Returns stable violation kind.
    #[must_use]
    pub const fn kind(&self) -> FilingViolationKind {
        self.kind
    }

    /// Returns owning Module path.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns affected canonical Element or `module`/`ecosystem`.
    #[must_use]
    pub fn element(&self) -> &str {
        &self.element
    }

    /// Returns offending repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the violated structural law.
    #[must_use]
    pub fn law(&self) -> &str {
        &self.law
    }

    /// Returns a canonical alternative where determinable.
    #[must_use]
    pub fn expected(&self) -> &str {
        &self.expected
    }

    /// Returns a deterministic human explanation.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "{}: Module `{}` Element `{}` path `{}` violates {}; expected {}.",
            self.kind.as_str(),
            self.module,
            self.element,
            self.path,
            self.law,
            self.expected
        )
    }
}

/// Compiles the canonical filing model from a sorted or unsorted file inventory.
#[must_use]
pub fn analyze_project_filing_system(
    observed_paths: &[String],
    profiles: &FilingSystemProfiles,
) -> ProjectFilingModel {
    let files: BTreeSet<String> = observed_paths.iter().cloned().collect();
    let directories = observed_directories(&files);
    let modules = discover_modules(&directories);
    let mut violations = Vec::new();

    evaluate_root(&files, &directories, profiles, &mut violations);
    for module in &modules {
        evaluate_module(
            module,
            &files,
            &directories,
            &modules,
            profiles,
            &mut violations,
        );
    }
    violations.sort();
    violations.dedup();

    let module_records = modules
        .iter()
        .map(|module| FilingModule {
            path: module_label(module),
            elements: CANONICAL_ELEMENTS
                .iter()
                .filter(|element| directories.contains(&child_path(module, element)))
                .map(ToString::to_string)
                .collect(),
        })
        .collect();
    let inventory_entries = build_inventory(&files, &modules);
    let inventory_digest = inventory_digest(&inventory_entries);
    let collections = build_collections(&inventory_entries);

    ProjectFilingModel {
        schema: "urn:fortress:model:v1:project-filing-system".into(),
        schema_version: 1,
        semantic_version: FILING_MODEL_SEMANTIC_VERSION.into(),
        root_entries: build_root_entries(&files, &directories, profiles),
        modules: module_records,
        collections,
        inventory: FilingInventory {
            digest: inventory_digest,
            entries: inventory_entries,
        },
        violations,
    }
}

fn evaluate_root(
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    for directory in directories
        .iter()
        .filter(|directory| parent_path(directory).is_none())
    {
        if CANONICAL_ELEMENTS.contains(&directory.as_str())
            || profiles
                .root_classification(directory, RootEntryKind::Directory)
                .is_some()
        {
            continue;
        }
        violation(
            violations,
            FilingViolationKind::UnknownModuleRootEntry,
            "",
            "module",
            directory,
            "the closed root Module grammar",
            "a canonical Module Element or registered ecosystem root directory",
        );
    }
    for file in files.iter().filter(|path| !path.contains('/')) {
        if matches!(file.as_str(), "README.md" | "contract.json")
            || profiles
                .root_classification(file, RootEntryKind::File)
                .is_some()
        {
            continue;
        }
        violation(
            violations,
            FilingViolationKind::UnknownModuleRootEntry,
            "",
            "module",
            file,
            "the closed root Module grammar",
            "README.md, contract.json, or a registered ecosystem root file",
        );
    }
}

fn evaluate_module(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    modules: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    evaluate_module_root(module, files, directories, violations);
    evaluate_module_realization(module, files, directories, modules, violations);
    evaluate_code(module, files, directories, profiles, violations);
    evaluate_docs(module, files, directories, violations);
    evaluate_element(module, "data", files, directories, profiles, violations);
    evaluate_element(module, "info", files, directories, profiles, violations);
    evaluate_companion_docs(module, files, directories, violations);
}

fn evaluate_module_root(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    violations: &mut Vec<FilingSystemViolation>,
) {
    for required in ["README.md", "contract.json"] {
        let path = child_path(module, required);
        if !files.contains(&path) {
            violation(
                violations,
                FilingViolationKind::MissingModuleRequirement,
                module,
                "module",
                &path,
                "every Module contains README.md and contract.json",
                required,
            );
        }
    }

    if !module.is_empty() {
        for directory in directories
            .iter()
            .filter(|directory| parent_path(directory) == Some(module))
        {
            let name = file_name(directory);
            if !CANONICAL_ELEMENTS.contains(&name) {
                violation(
                    violations,
                    FilingViolationKind::UnknownModuleRootEntry,
                    module,
                    "module",
                    directory,
                    "a Module root admits only canonical Elements",
                    "code/, data/, info/, docs/, or mods/",
                );
            }
        }
        for file in files
            .iter()
            .filter(|file| parent_path(file) == Some(module))
        {
            if !matches!(file_name(file), "README.md" | "contract.json") {
                violation(
                    violations,
                    FilingViolationKind::UnknownModuleRootEntry,
                    module,
                    "module",
                    file,
                    "a Module root admits no loose files",
                    "placement beneath an applicable canonical Element",
                );
            }
        }
        if !is_lexical_name(file_name(module), false) {
            violation(
                violations,
                FilingViolationKind::InvalidFilename,
                module,
                "module",
                module,
                "canonical Module naming",
                "one to three lowercase ASCII words separated by single underscores",
            );
        }
    }
}

fn evaluate_module_realization(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    modules: &BTreeSet<String>,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let code = child_path(module, "code");
    let mods = child_path(module, "mods");
    let has_code = directories.contains(&code);
    let has_child = modules
        .iter()
        .any(|candidate| parent_path(candidate) == Some(mods.as_str()));
    if !has_code && !has_child {
        violation(
            violations,
            FilingViolationKind::MissingModuleRequirement,
            module,
            "module",
            &child_path(module, "README.md"),
            "every Module owns code or child Modules",
            "code/ for an atomic Module or at least one child beneath mods/",
        );
    }

    for file in files
        .iter()
        .filter(|file| parent_path(file) == Some(mods.as_str()))
    {
        violation(
            violations,
            FilingViolationKind::LooseModsEntry,
            module,
            "mods",
            file,
            "mods contains Module directories only",
            "an immediate child Module directory",
        );
    }
}

fn evaluate_companion_docs(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    violations: &mut Vec<FilingSystemViolation>,
) {
    for (element, document) in [
        ("code", "code_docs.md"),
        ("data", "data_docs.md"),
        ("info", "info_docs.md"),
        ("mods", "mods_docs.md"),
    ] {
        let element_path = child_path(module, element);
        let document_path = child_path(&child_path(module, "docs"), document);
        let element_exists = directories.contains(&element_path);
        let document_exists = files.contains(&document_path);
        if element_exists && !document_exists {
            violation(
                violations,
                FilingViolationKind::MissingRequiredElementDoc,
                module,
                "docs",
                &document_path,
                "every present Element has its canonical companion document",
                &format!("docs/{document}"),
            );
        } else if !element_exists && document_exists {
            violation(
                violations,
                FilingViolationKind::UnrecognizedDocFile,
                module,
                "docs",
                &document_path,
                "companion documents exist only for present Elements",
                &format!("remove docs/{document} or add {element}/"),
            );
        }
    }
}

fn evaluate_code(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let root = child_path(module, "code");
    for directory in directories.iter().filter(|path| is_descendant(path, &root)) {
        let relative = directory
            .strip_prefix(&format!("{root}/"))
            .unwrap_or(directory);
        if !profiles.code_structure_registered(relative) {
            violation(
                violations,
                if profiles.has_code_structures() {
                    FilingViolationKind::UnregisteredCodeStructure
                } else {
                    FilingViolationKind::CodeSemanticSubdirectory
                },
                module,
                "code",
                directory,
                "code is a flat project-owned source surface unless an ecosystem profile owns the mechanical namespace",
                "a direct source file or registered mechanical code structure",
            );
        }
    }
    for file in files.iter().filter(|path| is_descendant(path, &root)) {
        let name = file_name(file);
        if !is_lexical_name(name, true) {
            violation(
                violations,
                FilingViolationKind::InvalidFilename,
                module,
                "code",
                file,
                "canonical source filename grammar",
                "one to three lowercase ASCII words with optional extension and canonical _vN suffix",
            );
        }
    }
}

fn evaluate_docs(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let root = child_path(module, "docs");
    for directory in directories.iter().filter(|path| is_descendant(path, &root)) {
        violation(
            violations,
            FilingViolationKind::DocSubdirectoryForbidden,
            module,
            "docs",
            directory,
            "docs is a closed flat canonical documentation set",
            "one of the four direct canonical companion documents",
        );
    }
    for file in files
        .iter()
        .filter(|path| parent_path(path) == Some(root.as_str()))
    {
        if !CANONICAL_DOCS.contains(&file_name(file)) {
            violation(
                violations,
                FilingViolationKind::UnrecognizedDocFile,
                module,
                "docs",
                file,
                "docs admits only canonical companion files",
                "code_docs.md, data_docs.md, info_docs.md, or mods_docs.md",
            );
        }
    }
}

fn evaluate_element(
    module: &str,
    element: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let root = child_path(module, element);
    let direct_files: Vec<&String> = files
        .iter()
        .filter(|path| parent_path(path) == Some(root.as_str()))
        .collect();
    let role_directories: Vec<&String> = directories
        .iter()
        .filter(|path| parent_path(path) == Some(root.as_str()))
        .collect();
    if !direct_files.is_empty() && !role_directories.is_empty() {
        violation(
            violations,
            FilingViolationKind::MixedFlatAndStructuredElement,
            module,
            element,
            &root,
            "an Element is either flat or role-structured",
            "all direct files or all canonical role directories",
        );
    }
    for file in direct_files {
        let name = file_name(file);
        if !is_lexical_name(name, true) && !profiles.registered_element_file(element, name) {
            violation(
                violations,
                FilingViolationKind::InvalidFilename,
                module,
                element,
                file,
                "canonical persisted-artifact filename grammar",
                "one to three lowercase ASCII words, a canonical _vN suffix, or a registered ecosystem filename",
            );
        }
    }
    for role_path in role_directories {
        evaluate_role(
            module,
            element,
            role_path,
            files,
            directories,
            profiles,
            violations,
        );
    }
}

fn evaluate_role(
    module: &str,
    element: &str,
    role_path: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let role_name = file_name(role_path);
    let role_parse = parse_versioned_name(role_name);
    let roles = if element == "data" {
        &DATA_ROLES[..]
    } else {
        &INFO_ROLES[..]
    };
    let Some((role, role_version)) = role_parse else {
        violation(
            violations,
            FilingViolationKind::InvalidVersionSuffix,
            module,
            element,
            role_path,
            "version suffixes use _v followed by a positive canonical integer",
            "<canonical_role> or <canonical_role>_vN",
        );
        return;
    };
    if !roles.contains(&role.as_str()) {
        violation(
            violations,
            if element == "data" {
                FilingViolationKind::UnknownDataRole
            } else {
                FilingViolationKind::UnknownInfoRole
            },
            module,
            element,
            role_path,
            "structured Elements begin with a frozen canonical role",
            if element == "data" {
                "config/schema/policy/reference/fixture/seed/template/migration/resource/dataset"
            } else {
                "report/snapshot/graph/index/manifest/evidence/metric/log"
            },
        );
        return;
    }

    for file in files
        .iter()
        .filter(|path| parent_path(path) == Some(role_path))
    {
        validate_leaf_filename(module, element, file, profiles, violations);
    }
    let collection_dirs: Vec<&String> = directories
        .iter()
        .filter(|path| parent_path(path) == Some(role_path))
        .collect();
    for collection_path in collection_dirs {
        evaluate_role_collection(
            module,
            element,
            &role,
            role_version,
            collection_path,
            files,
            directories,
            profiles,
            violations,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_role_collection(
    module: &str,
    element: &str,
    role: &str,
    role_version: Option<u64>,
    collection_path: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let collection_name = file_name(collection_path);
    let Some((collection, collection_version)) = parse_versioned_name(collection_name) else {
        violation(
            violations,
            FilingViolationKind::InvalidVersionSuffix,
            module,
            element,
            collection_path,
            "version suffixes use _v followed by a positive canonical integer",
            "<collection> or <collection>_vN",
        );
        return;
    };
    if !is_collection_name(&collection) {
        violation(
            violations,
            FilingViolationKind::InvalidCollectionName,
            module,
            element,
            collection_path,
            "collection names contain one to three lowercase ASCII semantic words",
            "lowercase words separated by single underscores with optional _vN",
        );
        return;
    }
    if is_redundant_collection(role, &collection) {
        violation(
            violations,
            FilingViolationKind::RedundantDirectoryLevel,
            module,
            element,
            collection_path,
            "every directory contributes recognized new structural information",
            "files directly beneath the role or a nonredundant project collection",
        );
    }
    if role_version.is_some() && role_version == collection_version {
        violation(
            violations,
            FilingViolationKind::InvalidVersionSuffix,
            module,
            element,
            collection_path,
            "the narrowest independently versioned semantic unit owns the version",
            "one nonduplicated role or collection _vN suffix",
        );
    }
    evaluate_collection(
        module,
        element,
        collection_path,
        files,
        directories,
        profiles,
        violations,
    );
}

fn evaluate_collection(
    module: &str,
    element: &str,
    collection_path: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    for file in files
        .iter()
        .filter(|path| parent_path(path) == Some(collection_path))
    {
        validate_leaf_filename(module, element, file, profiles, violations);
    }
    let partition_dirs: Vec<&String> = directories
        .iter()
        .filter(|path| parent_path(path) == Some(collection_path))
        .collect();
    for partition in partition_dirs {
        if !is_partition_name(file_name(partition)) {
            violation(
                violations,
                FilingViolationKind::InvalidPartition,
                module,
                element,
                partition,
                "the sole physical partition level is mechanically named",
                "part_ followed by exactly six decimal digits from 000001",
            );
        }
        for nested in directories
            .iter()
            .filter(|path| parent_path(path) == Some(partition.as_str()))
        {
            violation(
                violations,
                FilingViolationKind::PartitionRecursion,
                module,
                element,
                nested,
                "mechanical partitions never recurse",
                "leaf files directly beneath one part_000001-style directory",
            );
            violation(
                violations,
                FilingViolationKind::ExcessiveCollectionDepth,
                module,
                element,
                nested,
                "Data/Info depth is role + collection + one nonrecursive partition",
                "remove arbitrary recursive semantic nesting or introduce a truthful Module boundary",
            );
        }
        for file in files
            .iter()
            .filter(|path| parent_path(path) == Some(partition.as_str()))
        {
            validate_leaf_filename(module, element, file, profiles, violations);
        }
    }
    let prefix = format!("{collection_path}/");
    for directory in directories.iter().filter(|path| {
        path.starts_with(&prefix)
            && parent_path(path).is_some_and(|parent| parent != collection_path)
            && parent_path(path).is_some_and(|parent| {
                parent_path(parent).is_some_and(|grandparent| grandparent != collection_path)
            })
    }) {
        violation(
            violations,
            FilingViolationKind::ExcessiveCollectionDepth,
            module,
            element,
            directory,
            "Data/Info depth is role + collection + one nonrecursive partition",
            "remove arbitrary recursive semantic nesting or introduce a truthful Module boundary",
        );
    }
}

fn validate_leaf_filename(
    module: &str,
    element: &str,
    file: &str,
    profiles: &FilingSystemProfiles,
    violations: &mut Vec<FilingSystemViolation>,
) {
    let name = file_name(file);
    if !is_lexical_name(name, true) && !profiles.registered_element_file(element, name) {
        violation(
            violations,
            FilingViolationKind::InvalidFilename,
            module,
            element,
            file,
            "canonical persisted-artifact filename grammar",
            "one to three lowercase ASCII words with an optional canonical _vN suffix",
        );
    }
}

fn build_root_entries(
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    profiles: &FilingSystemProfiles,
) -> Vec<ClassifiedRootEntry> {
    let mut entries = Vec::new();
    for path in directories
        .iter()
        .filter(|path| parent_path(path).is_none())
    {
        let classification = if CANONICAL_ELEMENTS.contains(&path.as_str()) {
            RootEntryClassification::FortressCanonical
        } else {
            profiles
                .root_classification(path, RootEntryKind::Directory)
                .unwrap_or(RootEntryClassification::Invalid)
        };
        entries.push(ClassifiedRootEntry {
            path: path.clone(),
            kind: RootEntryKind::Directory,
            classification,
        });
    }
    for path in files.iter().filter(|path| !path.contains('/')) {
        let classification = if matches!(path.as_str(), "README.md" | "contract.json") {
            RootEntryClassification::FortressCanonical
        } else {
            profiles
                .root_classification(path, RootEntryKind::File)
                .unwrap_or(RootEntryClassification::Invalid)
        };
        entries.push(ClassifiedRootEntry {
            path: path.clone(),
            kind: RootEntryKind::File,
            classification,
        });
    }
    entries.sort();
    entries
}

fn build_inventory(
    files: &BTreeSet<String>,
    modules: &BTreeSet<String>,
) -> Vec<FilingInventoryEntry> {
    files
        .iter()
        .map(|path| {
            let module = owning_module(path, modules);
            let relative = if module.is_empty() {
                path.as_str()
            } else {
                path.strip_prefix(&format!("{module}/")).unwrap_or(path)
            };
            let segments: Vec<&str> = relative.split('/').collect();
            let element = match segments.first().copied() {
                Some(value) if CANONICAL_ELEMENTS.contains(&value) => value,
                Some("README.md" | "contract.json") => "module",
                _ => "ecosystem",
            };
            let (role, collection, partition) = if matches!(element, "data" | "info") {
                (
                    (segments.len() >= 3).then(|| segments[1].to_owned()),
                    (segments.len() >= 4).then(|| segments[2].to_owned()),
                    segments
                        .get(3)
                        .filter(|value| is_partition_name(value))
                        .map(|value| (*value).to_owned()),
                )
            } else {
                (None, None, None)
            };
            FilingInventoryEntry {
                path: path.clone(),
                module: module_label(module),
                element: element.into(),
                role,
                collection,
                partition,
            }
        })
        .collect()
}

fn build_collections(entries: &[FilingInventoryEntry]) -> Vec<ElementCollection> {
    let mut aggregates = BTreeMap::<
        (String, String, Option<String>, Option<String>),
        (BTreeSet<String>, usize),
    >::new();
    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.element.as_str(), "data" | "info"))
    {
        let key = (
            entry.module.clone(),
            entry.element.clone(),
            entry.role.clone(),
            entry.collection.clone(),
        );
        let aggregate = aggregates.entry(key).or_default();
        if let Some(partition) = &entry.partition {
            aggregate.0.insert(partition.clone());
        }
        aggregate.1 += 1;
    }
    aggregates
        .into_iter()
        .map(
            |((module, element, role, collection), (partitions, files))| ElementCollection {
                module,
                element,
                role,
                collection,
                partitions: partitions.len(),
                files,
            },
        )
        .collect()
}

fn inventory_digest(entries: &[FilingInventoryEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn observed_directories(files: &BTreeSet<String>) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for path in files {
        let segments: Vec<&str> = path.split('/').collect();
        for end in 1..segments.len() {
            directories.insert(segments[..end].join("/"));
        }
    }
    directories
}

fn discover_modules(directories: &BTreeSet<String>) -> BTreeSet<String> {
    let mut modules = BTreeSet::from([String::new()]);
    loop {
        let previous = modules.len();
        let candidates: Vec<String> = modules
            .iter()
            .flat_map(|module| {
                let mods = child_path(module, "mods");
                directories
                    .iter()
                    .filter(move |directory| parent_path(directory) == Some(mods.as_str()))
                    .cloned()
            })
            .collect();
        modules.extend(candidates);
        if modules.len() == previous {
            break;
        }
    }
    modules
}

fn owning_module<'a>(path: &str, modules: &'a BTreeSet<String>) -> &'a str {
    let mut cursor = parent_path(path);
    while let Some(candidate) = cursor {
        if let Some(module) = modules.get(candidate) {
            return module;
        }
        cursor = parent_path(candidate);
    }
    modules.get("").map_or("", String::as_str)
}

fn violation(
    violations: &mut Vec<FilingSystemViolation>,
    kind: FilingViolationKind,
    module: &str,
    element: &str,
    path: &str,
    law: &str,
    expected: &str,
) {
    violations.push(FilingSystemViolation {
        kind,
        module: module_label(module),
        element: element.into(),
        path: path.into(),
        law: law.into(),
        expected: expected.into(),
    });
}

fn parse_versioned_name(value: &str) -> Option<(String, Option<u64>)> {
    if let Some(index) = value.rfind("_v") {
        let base = &value[..index];
        let version = &value[index + 2..];
        if version.is_empty() || version.as_bytes()[0].is_ascii_digit() {
            if version.is_empty()
                || version.starts_with('0')
                || !version.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let number = version.parse().ok()?;
            return Some((base.into(), Some(number)));
        }
    }
    if value.contains("-v")
        || value.ends_with("_latest")
        || value.ends_with("_new")
        || value.bytes().any(|byte| byte == b'V')
    {
        return None;
    }
    Some((value.into(), None))
}

fn is_redundant_collection(role: &str, collection: &str) -> bool {
    collection == role
        || collection == format!("{role}s")
        || matches!(
            collection,
            "file" | "files" | "output" | "outputs" | "final" | "current"
        )
}

fn is_collection_name(value: &str) -> bool {
    is_lexical_name(value, false)
}

fn is_partition_name(value: &str) -> bool {
    value.strip_prefix("part_").is_some_and(|digits| {
        digits.len() == 6 && digits.bytes().all(|byte| byte.is_ascii_digit()) && digits != "000000"
    })
}

/// Returns whether a Fortress-controlled name satisfies canonical lexical law.
#[must_use]
pub fn is_lexical_name(name: &str, allow_extension: bool) -> bool {
    let (stem, extension) = if allow_extension {
        name.rsplit_once('.')
            .map_or((name, None), |(stem, extension)| (stem, Some(extension)))
    } else {
        (name, None)
    };
    if extension.is_some_and(|value| {
        value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return false;
    }
    let Some((semantic, _)) = parse_versioned_name(stem) else {
        return false;
    };
    let words: Vec<&str> = semantic.split('_').collect();
    !words.is_empty()
        && words.len() <= 3
        && words.iter().all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn is_single_root_entry(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['/', '\\'])
        && path != "."
        && path != ".."
        && !CANONICAL_ELEMENTS.contains(&path)
        && !matches!(path, "README.md" | "contract.json")
}

fn is_canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn module_label(module: &str) -> String {
    if module.is_empty() {
        ".".into()
    } else {
        module.into()
    }
}

fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}

fn is_descendant(path: &str, directory: &str) -> bool {
    path.strip_prefix(directory)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Explains invalid ecosystem filing-profile authority.
#[derive(Debug)]
pub enum FilingProfileError {
    /// JSON syntax or typed shape is invalid.
    Json(serde_json::Error),
    /// Schema identity is unsupported.
    InvalidSchema(Box<str>),
    /// Schema version is unsupported.
    UnsupportedSchemaVersion(u16),
    /// Profile ID is empty or duplicated.
    DuplicateOrEmptyProfile(Box<str>),
    /// Root entry is not one canonical root segment.
    InvalidRootEntry(Box<str>),
    /// Root entry is duplicated.
    DuplicateRootEntry(Box<str>),
    /// Ecosystem Element filename registration is invalid.
    InvalidElementFile(Box<str>),
    /// Ecosystem Element filename registration is duplicated.
    DuplicateElementFile(Box<str>),
    /// Mechanical Code structure is not canonical and relative.
    InvalidCodeStructure(Box<str>),
    /// Mechanical Code structure is duplicated.
    DuplicateCodeStructure(Box<str>),
}

impl Display for FilingProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "filing profile JSON is invalid: {error}"),
            Self::InvalidSchema(value) => write!(
                formatter,
                "filing profile schema `{value}` is unsupported; `{FILING_PROFILE_SCHEMA}` is required"
            ),
            Self::UnsupportedSchemaVersion(version) => write!(
                formatter,
                "filing profile schema version {version} is unsupported"
            ),
            Self::DuplicateOrEmptyProfile(value) => {
                write!(
                    formatter,
                    "filing profile identity `{value}` is empty or duplicated"
                )
            }
            Self::InvalidRootEntry(value) => {
                write!(
                    formatter,
                    "registered root entry `{value}` is not canonical"
                )
            }
            Self::DuplicateRootEntry(value) => {
                write!(formatter, "registered root entry `{value}` is duplicated")
            }
            Self::InvalidElementFile(value) => {
                write!(formatter, "registered Element file `{value}` is invalid")
            }
            Self::DuplicateElementFile(value) => {
                write!(formatter, "registered Element file `{value}` is duplicated")
            }
            Self::InvalidCodeStructure(value) => write!(
                formatter,
                "mechanical Code structure `{value}` is not canonical"
            ),
            Self::DuplicateCodeStructure(value) => write!(
                formatter,
                "mechanical Code structure `{value}` is duplicated"
            ),
        }
    }
}

impl Error for FilingProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::InvalidSchema(_)
            | Self::UnsupportedSchemaVersion(_)
            | Self::DuplicateOrEmptyProfile(_)
            | Self::InvalidRootEntry(_)
            | Self::DuplicateRootEntry(_)
            | Self::InvalidElementFile(_)
            | Self::DuplicateElementFile(_)
            | Self::InvalidCodeStructure(_)
            | Self::DuplicateCodeStructure(_) => None,
        }
    }
}
