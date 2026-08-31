//! Canonical Module documentation and contract synchronization evaluation.
//!
//! Markdown is parsed through `pulldown-cmark` events into a structural model.
//! The evaluator never treats line-oriented regular expressions as Markdown
//! authority. Filesystem membership, Module contracts, and human projections
//! remain distinct inputs whose required bijections are checked explicitly.

pub(crate) const DOCUMENTATION_RULE_SOURCE: &str = include_str!("../data/documentation_rule.json");

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};

use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contract_coherency::{ContractCoherencyGraph, ModuleContract, ResolvedRelationshipType};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::snapshot::RepositorySnapshot;
use crate::source_architecture::CodeFileResponsibility;

/// Stable identity of canonical Module documentation synchronization.
pub const REPO_DOCS_RULE_ID: &str = "REPO-DOCS-001";

const REMEDIATION: &str = "Converge the Module contract and canonical Markdown to the documented grammar, restore exact filesystem catalogs and child catalogs, resolve every relative link, and make README relationship projections exactly match typed outbound contract relationships.";
const CANONICAL_DOCS: [&str; 4] = [
    "code_docs.md",
    "data_docs.md",
    "info_docs.md",
    "mods_docs.md",
];
const PLACEHOLDERS: [&str; 7] = [
    "todo",
    "tbd",
    "fixme",
    "coming soon",
    "to be determined",
    "to be decided",
    "placeholder",
];

/// Extracts the canonical direct-Code-file responsibility catalog using the
/// same structural `CommonMark` model as documentation conformance.
///
/// Source Architecture consumes this projection instead of parsing Markdown or
/// introducing another responsibility manifest. Repository documentation
/// conformance remains responsible for the catalog/filesystem bijection.
///
/// # Errors
///
/// Returns the offending documentation path when canonical Markdown is not
/// UTF-8. Structural invalidity is reported by [`evaluate_repository_documentation`].
pub fn code_file_responsibilities(
    files: &BTreeMap<String, Vec<u8>>,
    ccg: &ContractCoherencyGraph,
) -> Result<Vec<CodeFileResponsibility>, String> {
    let mut entries = Vec::new();
    for (module_id, module) in ccg.modules() {
        let module_path = module.path();
        let documentation_path = child_path(&child_path(module_path, "docs"), "code_docs.md");
        let Some(bytes) = files.get(&documentation_path) else {
            continue;
        };
        let source = std::str::from_utf8(bytes)
            .map_err(|_| format!("canonical Markdown `{documentation_path}` is not UTF-8"))?;
        let document = MarkdownDocument::parse(source);
        for heading in document
            .headings
            .iter()
            .filter(|heading| heading.level == 3 && heading.parent_h2.as_deref() == Some("Files"))
        {
            let responsibility = document
                .paragraphs_for_h3(heading.index)
                .iter()
                .map(|paragraph| paragraph.text.trim())
                .filter(|text| is_substantive(text))
                .collect::<Vec<_>>()
                .join("\n\n");
            entries.push(CodeFileResponsibility::new(
                child_path(&child_path(module_path, "code"), &heading.text),
                module_id,
                &documentation_path,
                responsibility,
            ));
        }
    }
    entries.sort();
    entries.dedup();
    Ok(entries)
}

/// Deterministic machine-readable documentation-conformance report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DocumentationConformanceReport {
    schema_version: u16,
    rule_id: String,
    outcome: DocumentationOutcome,
    summary: DocumentationSummary,
    findings: Vec<CanonicalFinding>,
}

impl DocumentationConformanceReport {
    /// Returns whether every implemented documentation check passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome == DocumentationOutcome::Pass
    }

    /// Returns deterministic conformance metrics.
    #[must_use]
    pub const fn summary(&self) -> &DocumentationSummary {
        &self.summary
    }

    /// Returns canonical findings in deterministic order.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Serializes the report as stable pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the version-one report cannot be represented.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Returns the deterministic rule-execution detail used by snapshot audit.
    #[must_use]
    pub fn execution_detail(&self) -> String {
        format!(
            "Evaluator inspected {} Modules and {} canonical Markdown files; filesystem/documentation entries code {}/{}, data {}/{}, info {}/{}, modules {}/{}; relationship/documentation entries {}/{}; broken or stale links {}; structural Markdown violations {}; unexpected docs files {}; missing canonical docs {}; findings {}.",
            self.summary.modules_inspected,
            self.summary.markdown_files_inspected,
            self.summary.documented_code_elements,
            self.summary.physical_code_elements,
            self.summary.documented_data_elements,
            self.summary.physical_data_elements,
            self.summary.documented_info_elements,
            self.summary.physical_info_elements,
            self.summary.documented_child_modules,
            self.summary.physical_child_modules,
            self.summary.documented_relationships,
            self.summary.contract_relationships,
            self.summary.broken_or_stale_links,
            self.summary.structural_markdown_violations,
            self.summary.unexpected_docs_files,
            self.summary.missing_canonical_docs,
            self.findings.len(),
        )
    }
}

/// Implemented documentation-conformance result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DocumentationOutcome {
    Pass,
    Fail,
}

/// Exact deterministic counts produced by documentation evaluation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DocumentationSummary {
    modules_inspected: usize,
    markdown_files_inspected: usize,
    physical_code_elements: usize,
    documented_code_elements: usize,
    physical_data_elements: usize,
    documented_data_elements: usize,
    physical_info_elements: usize,
    documented_info_elements: usize,
    physical_child_modules: usize,
    documented_child_modules: usize,
    contract_relationships: usize,
    documented_relationships: usize,
    relationship_violations: usize,
    broken_or_stale_links: usize,
    structural_markdown_violations: usize,
    unexpected_docs_files: usize,
    missing_canonical_docs: usize,
}

impl DocumentationSummary {
    /// Returns the number of physical Modules inspected.
    #[must_use]
    pub const fn modules_inspected(&self) -> usize {
        self.modules_inspected
    }

    /// Returns the number of present canonical Markdown files parsed.
    #[must_use]
    pub const fn markdown_files_inspected(&self) -> usize {
        self.markdown_files_inspected
    }

    /// Returns physical and documented direct Code element counts.
    #[must_use]
    pub const fn code_bijection(&self) -> (usize, usize) {
        (self.physical_code_elements, self.documented_code_elements)
    }

    /// Returns physical and documented direct Data element counts.
    #[must_use]
    pub const fn data_bijection(&self) -> (usize, usize) {
        (self.physical_data_elements, self.documented_data_elements)
    }

    /// Returns physical and documented direct Info element counts.
    #[must_use]
    pub const fn info_bijection(&self) -> (usize, usize) {
        (self.physical_info_elements, self.documented_info_elements)
    }

    /// Returns physical and documented immediate child Module counts.
    #[must_use]
    pub const fn module_bijection(&self) -> (usize, usize) {
        (self.physical_child_modules, self.documented_child_modules)
    }

    /// Returns authoritative and documented outbound relationship target counts.
    #[must_use]
    pub const fn relationship_bijection(&self) -> (usize, usize) {
        (self.contract_relationships, self.documented_relationships)
    }

    /// Returns README/contract relationship synchronization violations.
    #[must_use]
    pub const fn relationship_violations(&self) -> usize {
        self.relationship_violations
    }

    /// Returns broken or stale relative-link count.
    #[must_use]
    pub const fn broken_or_stale_links(&self) -> usize {
        self.broken_or_stale_links
    }

    /// Returns structural Markdown violation count.
    #[must_use]
    pub const fn structural_markdown_violations(&self) -> usize {
        self.structural_markdown_violations
    }

    /// Returns unexpected `docs/` file count.
    #[must_use]
    pub const fn unexpected_docs_files(&self) -> usize {
        self.unexpected_docs_files
    }

    /// Returns missing canonical Markdown file count.
    #[must_use]
    pub const fn missing_canonical_docs(&self) -> usize {
        self.missing_canonical_docs
    }
}

/// Reads a stabilized repository and evaluates its canonical Module documentation.
///
/// Every byte is checked against the supplied snapshot before evaluation, so a
/// post-snapshot repository mutation becomes an error rather than new evidence.
///
/// # Errors
///
/// Returns [`DocumentationEvaluationError`] for I/O, snapshot mismatch, or
/// canonical finding construction failure.
pub fn evaluate_repository_documentation(
    root: impl AsRef<Path>,
    snapshot: &RepositorySnapshot,
    ccg: &ContractCoherencyGraph,
    standard_edition: &str,
) -> Result<DocumentationConformanceReport, DocumentationEvaluationError> {
    let root = root.as_ref();
    let mut files = BTreeMap::new();
    for observed in snapshot.files() {
        let absolute = root.join(observed.path());
        let bytes = fs::read(&absolute).map_err(|source| DocumentationEvaluationError::Io {
            path: absolute,
            source,
        })?;
        let size = u64::try_from(bytes.len())
            .map_err(|_| DocumentationEvaluationError::SnapshotMismatch(observed.path().into()))?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if size != observed.size() || digest != observed.sha256() {
            return Err(DocumentationEvaluationError::SnapshotMismatch(
                observed.path().into(),
            ));
        }
        files.insert(observed.path().to_owned(), bytes);
    }
    evaluate_documentation_files_with_ccg(&files, standard_edition, Some(ccg))
        .map_err(DocumentationEvaluationError::Finding)
}

/// Evaluates an in-memory repository file inventory.
///
/// This boundary supports specification-authored conformance fixtures without
/// assigning temporary filesystem behavior normative meaning.
///
/// # Errors
///
/// Returns [`FindingError`] if canonical finding construction fails.
pub fn evaluate_documentation_files(
    files: &BTreeMap<String, Vec<u8>>,
    standard_edition: &str,
) -> Result<DocumentationConformanceReport, FindingError> {
    evaluate_documentation_files_with_ccg(files, standard_edition, None)
}

fn evaluate_documentation_files_with_ccg(
    files: &BTreeMap<String, Vec<u8>>,
    standard_edition: &str,
    ccg: Option<&ContractCoherencyGraph>,
) -> Result<DocumentationConformanceReport, FindingError> {
    let definition = RuleFindingDefinition::new(
        REPO_DOCS_RULE_ID,
        1,
        FindingCategory::Documentation,
        REMEDIATION,
    )?;
    let evaluator =
        EvaluatorProvenance::new("fortress-core/documentation", env!("CARGO_PKG_VERSION"))?;
    let paths: BTreeSet<String> = files.keys().cloned().collect();
    let modules = discover_modules(&paths);
    let mut context = EvaluationContext {
        files,
        paths: &paths,
        modules: &modules,
        definition: &definition,
        evaluator: &evaluator,
        standard_edition,
        findings: Vec::new(),
        summary: DocumentationSummary {
            modules_inspected: modules.len(),
            ..DocumentationSummary::default()
        },
        parsed: BTreeMap::new(),
        contracts: BTreeMap::new(),
        contract_paths: BTreeMap::new(),
        ccg,
    };

    context.validate_structural_surfaces()?;
    context.load_contracts()?;
    context.validate_contract_graph()?;
    context.parse_markdown()?;
    context.validate_markdown_documents()?;
    context.validate_all_links()?;

    context.findings.sort();
    context.findings.dedup();
    Ok(DocumentationConformanceReport {
        schema_version: 1,
        rule_id: REPO_DOCS_RULE_ID.into(),
        outcome: if context.findings.is_empty() {
            DocumentationOutcome::Pass
        } else {
            DocumentationOutcome::Fail
        },
        summary: context.summary,
        findings: context.findings,
    })
}

struct EvaluationContext<'a> {
    files: &'a BTreeMap<String, Vec<u8>>,
    paths: &'a BTreeSet<String>,
    modules: &'a BTreeSet<String>,
    definition: &'a RuleFindingDefinition,
    evaluator: &'a EvaluatorProvenance,
    standard_edition: &'a str,
    findings: Vec<CanonicalFinding>,
    summary: DocumentationSummary,
    parsed: BTreeMap<String, MarkdownDocument>,
    contracts: BTreeMap<String, ModuleContract>,
    contract_paths: BTreeMap<String, String>,
    ccg: Option<&'a ContractCoherencyGraph>,
}

impl EvaluationContext<'_> {
    fn validate_structural_surfaces(&mut self) -> Result<(), FindingError> {
        for module in self.modules {
            let readme = child_path(module, "README.md");
            if !self.paths.contains(&readme) {
                self.summary.missing_canonical_docs += 1;
                self.structural_finding(
                    &readme,
                    "MISSING_README",
                    format!(
                        "Module `{}` is missing canonical `README.md`.",
                        module_name(module)
                    ),
                )?;
            }
            let contract = child_path(module, "contract.json");
            if !self.paths.contains(&contract) {
                self.structural_finding(
                    &contract,
                    "MISSING_CONTRACT",
                    format!(
                        "Module `{}` is missing canonical `contract.json`.",
                        module_name(module)
                    ),
                )?;
            }

            for (attribute, documentation) in [
                ("code", "code_docs.md"),
                ("data", "data_docs.md"),
                ("info", "info_docs.md"),
                ("mods", "mods_docs.md"),
            ] {
                let attribute_exists = has_descendant(self.paths, &child_path(module, attribute));
                let documentation_path = child_path(&child_path(module, "docs"), documentation);
                let documentation_exists = self.paths.contains(&documentation_path);
                if attribute_exists && !documentation_exists {
                    self.summary.missing_canonical_docs += 1;
                    self.structural_finding(
                        &documentation_path,
                        "MISSING_ELEMENT_DOCUMENTATION",
                        format!(
                            "Module `{}` has `{attribute}/` but is missing `docs/{documentation}`.",
                            module_name(module)
                        ),
                    )?;
                } else if !attribute_exists && documentation_exists {
                    self.structural_finding(
                        &documentation_path,
                        "ORPHAN_ELEMENT_DOCUMENTATION",
                        format!(
                            "Module `{}` has `docs/{documentation}` without `{attribute}/`.",
                            module_name(module)
                        ),
                    )?;
                }
            }

            let docs = child_path(module, "docs");
            for path in self.paths.iter().filter(|path| is_descendant(path, &docs)) {
                let relative = path.strip_prefix(&format!("{docs}/")).unwrap_or(path);
                if relative.contains('/') || !CANONICAL_DOCS.contains(&relative) {
                    self.summary.unexpected_docs_files += 1;
                    self.structural_finding(
                        path,
                        "UNEXPECTED_DOCUMENTATION_PATH",
                        format!("Documentation path `{path}` is not an applicable direct canonical Module documentation file."),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn load_contracts(&mut self) -> Result<(), FindingError> {
        if let Some(ccg) = self.ccg {
            for module in ccg.modules().values() {
                self.contract_paths.insert(
                    module.contract().id().to_owned(),
                    module.contract_path().to_owned(),
                );
                self.contracts
                    .insert(module.path().to_owned(), module.contract().clone());
            }
            self.summary.contract_relationships = ccg
                .expected_readme_relationships()
                .values()
                .map(BTreeMap::len)
                .sum();
            return Ok(());
        }
        for module in self.modules {
            let path = child_path(module, "contract.json");
            let Some(bytes) = self.files.get(&path) else {
                continue;
            };
            let Ok(source) = std::str::from_utf8(bytes) else {
                self.structural_finding(
                    &path,
                    "CONTRACT_NOT_UTF8",
                    format!("Module contract `{path}` is not valid UTF-8."),
                )?;
                continue;
            };
            let contract = match ModuleContract::from_json_str(source) {
                Ok(contract) => contract,
                Err(error) => {
                    self.structural_finding(
                        &path,
                        "CONTRACT_INVALID",
                        format!("Module contract `{path}` is invalid: {error}"),
                    )?;
                    continue;
                }
            };
            if let Some(first_path) = self.contract_paths.get(contract.id()) {
                self.structural_finding(
                    &path,
                    "DUPLICATE_MODULE_IDENTITY",
                    format!(
                        "Module identity `{}` duplicates the contract at `{first_path}`.",
                        contract.id()
                    ),
                )?;
                continue;
            }
            self.contract_paths.insert(contract.id().into(), path);
            self.contracts.insert(module.clone(), contract);
        }
        self.summary.contract_relationships = self
            .contracts
            .values()
            .map(|contract| authoritative_relationships(contract).len())
            .sum();
        Ok(())
    }

    fn validate_contract_graph(&mut self) -> Result<(), FindingError> {
        if self.ccg.is_some() {
            return Ok(());
        }
        let identities: BTreeSet<String> = self
            .contracts
            .values()
            .map(|contract| contract.id().to_owned())
            .collect();
        let contracts: Vec<(String, String, Vec<String>)> = self
            .contracts
            .iter()
            .map(|(module, contract)| {
                (
                    module.clone(),
                    contract.id().into(),
                    contract
                        .requires()
                        .iter()
                        .map(|requirement| requirement.provider().to_owned())
                        .collect(),
                )
            })
            .collect();
        let declared_targets: Vec<(String, String, String)> = self
            .contracts
            .iter()
            .flat_map(|(module, contract)| {
                contract
                    .requires()
                    .iter()
                    .map(crate::contract_coherency::RequiredCapability::provider)
                    .chain(
                        contract
                            .relationships()
                            .iter()
                            .map(crate::contract_coherency::ModuleRelationship::target),
                    )
                    .map(|target| (module.clone(), contract.id().to_owned(), target.to_owned()))
            })
            .collect();
        for (module, source, target) in declared_targets {
            if !identities.contains(&target) {
                self.structural_finding(
                    &child_path(&module, "contract.json"),
                    &semantic_discriminator("STALE_RELATIONSHIP", &target),
                        format!("Module `{source}` declares a stale relationship to nonexistent Module `{target}`."),
                )?;
            }
        }
        if let Some(cycle) = dependency_cycle(&contracts) {
            let source = cycle.first().map_or("", String::as_str);
            let module = contracts
                .iter()
                .find(|(_, id, _)| id == source)
                .map_or("", |(module, _, _)| module.as_str());
            self.structural_finding(
                &child_path(module, "contract.json"),
                "DEPENDENCY_CYCLE",
                format!(
                    "Module `depends_on` relationships contain a prohibited cycle: {}.",
                    cycle.join(" -> ")
                ),
            )?;
        }
        Ok(())
    }

    fn parse_markdown(&mut self) -> Result<(), FindingError> {
        let canonical: Vec<String> = self
            .modules
            .iter()
            .flat_map(|module| {
                std::iter::once(child_path(module, "README.md")).chain(
                    CANONICAL_DOCS
                        .iter()
                        .map(|name| child_path(&child_path(module, "docs"), name)),
                )
            })
            .filter(|path| self.paths.contains(path))
            .collect();
        self.summary.markdown_files_inspected = canonical.len();
        for path in canonical {
            let bytes = &self.files[&path];
            let Ok(source) = std::str::from_utf8(bytes) else {
                self.structural_finding(
                    &path,
                    "MARKDOWN_NOT_UTF8",
                    format!("Canonical Markdown `{path}` is not valid UTF-8."),
                )?;
                continue;
            };
            self.parsed.insert(path, MarkdownDocument::parse(source));
        }
        Ok(())
    }

    fn validate_markdown_documents(&mut self) -> Result<(), FindingError> {
        let modules: Vec<String> = self.modules.iter().cloned().collect();
        for module in modules {
            self.validate_readme(&module)?;
            for (attribute, documentation, h1, h2) in [
                (
                    "code",
                    "code_docs.md",
                    "Code",
                    &["Role", "Execution", "State", "Failure Semantics", "Files"][..],
                ),
                (
                    "data",
                    "data_docs.md",
                    "Data",
                    &[
                        "Role",
                        "Origin",
                        "Semantics",
                        "Validity",
                        "Lifecycle",
                        "Files",
                    ][..],
                ),
                (
                    "info",
                    "info_docs.md",
                    "Info",
                    &["Role", "Production", "Semantics", "Lifecycle", "Files"][..],
                ),
            ] {
                let path = child_path(&child_path(&module, "docs"), documentation);
                if self.parsed.contains_key(&path) {
                    self.validate_element_document(&module, attribute, &path, h1, h2)?;
                }
            }
            let mods_path = child_path(&child_path(&module, "docs"), "mods_docs.md");
            if self.parsed.contains_key(&mods_path) {
                self.validate_mods_document(&module, &mods_path)?;
            }
        }
        Ok(())
    }

    fn validate_readme(&mut self, module: &str) -> Result<(), FindingError> {
        let path = child_path(module, "README.md");
        let Some(document) = self.parsed.get(&path).cloned() else {
            return Ok(());
        };
        let expected_h1 = self.contracts.get(module).map_or_else(
            || module_name(module).to_owned(),
            |contract| contract.display_name().to_owned(),
        );
        self.validate_common(
            &path,
            &document,
            &expected_h1,
            &[
                "Purpose",
                "Responsibility",
                "Scope",
                "Relationships",
                "Guarantees",
            ],
        )?;

        let scope_h3: Vec<&Heading> = document
            .headings
            .iter()
            .filter(|heading| heading.level == 3 && heading.parent_h2.as_deref() == Some("Scope"))
            .collect();
        if scope_h3
            .iter()
            .map(|heading| heading.text.as_str())
            .collect::<Vec<_>>()
            != ["Includes", "Excludes"]
        {
            self.markdown_finding(
                &path,
                "README_SCOPE_STRUCTURE",
                "README `Scope` must contain exactly `Includes` then `Excludes`.".into(),
            )?;
        }
        for heading in &document.headings {
            if heading.level == 3
                && !matches!(
                    heading.parent_h2.as_deref(),
                    Some("Scope" | "Relationships")
                )
            {
                self.markdown_finding(
                    &path,
                    &semantic_discriminator("README_H3_PARENT", &heading.text),
                    format!(
                        "H3 `{}` is not allowed beneath README section `{}`.",
                        heading.text,
                        heading.parent_h2.as_deref().unwrap_or("none")
                    ),
                )?;
            }
        }
        self.validate_relationship_projection(module, &path, &document)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_relationship_projection(
        &mut self,
        module: &str,
        path: &str,
        document: &MarkdownDocument,
    ) -> Result<(), FindingError> {
        let findings_before = self.findings.len();
        let mut documented = BTreeMap::<String, Vec<ResolvedRelationshipType>>::new();
        for heading in document.headings.iter().filter(|heading| {
            heading.level == 3 && heading.parent_h2.as_deref() == Some("Relationships")
        }) {
            self.summary.documented_relationships += 1;
            if heading.links.len() != 1 {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_LINK_COUNT", &heading.text),
                    format!(
                        "Relationship heading `{}` must contain exactly one Module README link.",
                        heading.text
                    ),
                )?;
                continue;
            }
            let Some(target_path) = resolve_relative(path, &heading.links[0]) else {
                continue;
            };
            let Some((target_display_name, target_id)) = self
                .contracts
                .iter()
                .find(|(candidate, _)| child_path(candidate, "README.md") == target_path)
                .map(|(_, contract)| {
                    (contract.display_name().to_owned(), contract.id().to_owned())
                })
            else {
                continue;
            };
            if heading.text != target_display_name {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_DISPLAY_NAME", &target_id),
                    format!(
                        "Relationship link text `{}` does not match target display name `{}`.",
                        heading.text, target_display_name
                    ),
                )?;
            }
            let paragraphs = document.paragraphs_for_h3(heading.index);
            let Some(types_paragraph) = paragraphs.first() else {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_TYPES_MISSING", &target_id),
                    format!(
                        "Relationship `{}` has no canonical Types paragraph.",
                        heading.text
                    ),
                )?;
                continue;
            };
            let types: Vec<ResolvedRelationshipType> = types_paragraph
                .codes
                .iter()
                .filter_map(|value| match value.as_str() {
                    "depends_on" => Some(ResolvedRelationshipType::DependsOn),
                    "verifies" => Some(ResolvedRelationshipType::Verifies),
                    _ => None,
                })
                .collect();
            let expected_text = format!(
                "Types: {}",
                types
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if types.is_empty() || types_paragraph.text.trim() != expected_text {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_TYPES_INVALID", &target_id),
                    format!("Relationship `{}` must begin with canonical `Types:` and code-formatted supported relationship types.", heading.text),
                )?;
            }
            if paragraphs
                .iter()
                .skip(1)
                .all(|paragraph| !is_substantive(&paragraph.text))
            {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_RATIONALE_MISSING", &target_id),
                    format!(
                        "Relationship `{}` must explain why the relationship exists.",
                        heading.text
                    ),
                )?;
            }
            if documented.insert(target_id.clone(), types).is_some() {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("RELATIONSHIP_DUPLICATE", &target_id),
                    format!("Relationship target `{target_id}` is documented more than once."),
                )?;
            }
        }

        if let Some(contract) = self.contracts.get(module) {
            let authoritative: BTreeMap<String, Vec<ResolvedRelationshipType>> = self
                .ccg
                .and_then(|ccg| ccg.expected_readme_relationships().get(contract.id()))
                .cloned()
                .unwrap_or_else(|| authoritative_relationships(contract))
                .into_iter()
                .map(|(target, types)| (target, types.into_iter().collect()))
                .collect();
            for (target, types) in &authoritative {
                match documented.get(target) {
                    None => self.markdown_finding(
                        path,
                        &semantic_discriminator("RELATIONSHIP_PROJECTION_MISSING", target),
                        format!("Contract relationship to `{target}` is missing from README `Relationships`."),
                    )?,
                    Some(documented_types) if documented_types != types => self.markdown_finding(
                        path,
                        &semantic_discriminator("RELATIONSHIP_PROJECTION_TYPES", target),
                        format!("README relationship types for `{target}` do not match the Module contract."),
                    )?,
                    Some(_) => {}
                }
            }
            for target in documented.keys() {
                if !authoritative.contains_key(target) {
                    self.markdown_finding(
                        path,
                        &semantic_discriminator("RELATIONSHIP_WITHOUT_AUTHORITY", target),
                        format!(
                            "README relationship to `{target}` has no Module contract authority."
                        ),
                    )?;
                }
            }
        }
        self.summary.relationship_violations += self.findings.len() - findings_before;
        Ok(())
    }

    fn validate_element_document(
        &mut self,
        module: &str,
        attribute: &str,
        path: &str,
        h1: &str,
        h2: &[&str],
    ) -> Result<(), FindingError> {
        let document = self.parsed[path].clone();
        self.validate_common(path, &document, h1, h2)?;
        for heading in &document.headings {
            if heading.level == 3 && heading.parent_h2.as_deref() != Some("Files") {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("ELEMENT_H3_PARENT", &heading.text),
                    format!(
                        "H3 `{}` is allowed only beneath `Files` in `{}`.",
                        heading.text,
                        file_name(path)
                    ),
                )?;
            }
        }
        let physical =
            element_catalog_entries(self.paths, &child_path(module, attribute), attribute);
        let mut documented = BTreeSet::new();
        for heading in document
            .headings
            .iter()
            .filter(|heading| heading.level == 3 && heading.parent_h2.as_deref() == Some("Files"))
        {
            if !documented.insert(heading.text.clone()) {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CATALOG_ENTRY_DUPLICATE", &heading.text),
                    format!(
                        "File entry `{}` is documented more than once.",
                        heading.text
                    ),
                )?;
            }
            let structured_catalog =
                matches!(attribute, "data" | "info") && heading.text.ends_with('/');
            let valid_projection = if structured_catalog {
                heading.links.is_empty() && heading.codes.as_slice() == [heading.text.as_str()]
            } else {
                heading.links.len() == 1
                    && heading.codes.as_slice() == [heading.text.as_str()]
                    && resolve_relative(path, heading.links.first().map_or("", String::as_str))
                        == Some(child_path(&child_path(module, attribute), &heading.text))
            };
            if !valid_projection {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CATALOG_ENTRY_PROJECTION", &heading.text),
                    if structured_catalog {
                        format!("Structured `{attribute}` catalog entry `{}` must be one code-formatted role/ or role/collection/ scope without a leaf-file link.", heading.text)
                    } else {
                        format!("File entry `{}` must link its code-formatted filename to the direct `{attribute}/` element.", heading.text)
                    },
                )?;
            }
            if document
                .paragraphs_for_h3(heading.index)
                .iter()
                .all(|paragraph| !is_substantive(&paragraph.text))
            {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CATALOG_ENTRY_DESCRIPTION", &heading.text),
                    format!(
                        "File entry `{}` lacks a substantive contribution description.",
                        heading.text
                    ),
                )?;
            }
        }
        match attribute {
            "code" => {
                self.summary.physical_code_elements += physical.len();
                self.summary.documented_code_elements += documented.len();
            }
            "data" => {
                self.summary.physical_data_elements += physical.len();
                self.summary.documented_data_elements += documented.len();
            }
            "info" => {
                self.summary.physical_info_elements += physical.len();
                self.summary.documented_info_elements += documented.len();
            }
            _ => {}
        }
        self.validate_bijection(path, attribute, &physical, &documented)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_mods_document(&mut self, module: &str, path: &str) -> Result<(), FindingError> {
        let document = self.parsed[path].clone();
        self.validate_common(
            path,
            &document,
            "Modules",
            &["Composition", "Modules", "Coordination"],
        )?;
        for heading in &document.headings {
            if heading.level == 3 && heading.parent_h2.as_deref() != Some("Modules") {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("MODS_H3_PARENT", &heading.text),
                    format!(
                        "H3 `{}` is allowed only beneath `Modules` in `mods_docs.md`.",
                        heading.text
                    ),
                )?;
            }
        }
        let physical: BTreeSet<String> = immediate_children(self.modules, module)
            .into_iter()
            .map(|child| child.rsplit('/').next().unwrap_or(&child).to_owned())
            .collect();
        let mut documented = BTreeSet::new();
        for heading in document
            .headings
            .iter()
            .filter(|heading| heading.level == 3 && heading.parent_h2.as_deref() == Some("Modules"))
        {
            let Some(link) = heading.links.first() else {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_LINK_MISSING", &heading.text),
                    format!(
                        "Child Module heading `{}` must link to its canonical README.",
                        heading.text
                    ),
                )?;
                continue;
            };
            let resolved = resolve_relative(path, link);
            let expected_child =
                immediate_children(self.modules, module)
                    .into_iter()
                    .find(|child| {
                        child_path(child, "README.md") == resolved.clone().unwrap_or_default()
                    });
            let Some(child) = expected_child else {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_NOT_IMMEDIATE", &heading.text),
                    format!("Child Module entry `{}` does not identify an immediate physical child README.", heading.text),
                )?;
                continue;
            };
            let child_name = child.rsplit('/').next().unwrap_or(&child).to_owned();
            if !documented.insert(child_name.clone()) {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_DUPLICATE", &child_name),
                    format!("Child Module `{child_name}` is documented more than once."),
                )?;
            }
            if heading.links.len() != 1 {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_LINK_COUNT", &child_name),
                    format!(
                        "Child Module heading `{}` must contain exactly one canonical README link.",
                        heading.text
                    ),
                )?;
            }
            if let Some(contract) = self.contracts.get(&child)
                && heading.text != contract.display_name()
            {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_DISPLAY_NAME", &child_name),
                    format!(
                        "Child Module link text `{}` does not match `{}`.",
                        heading.text,
                        contract.display_name()
                    ),
                )?;
            }
            if document
                .paragraphs_for_h3(heading.index)
                .iter()
                .all(|paragraph| !is_substantive(&paragraph.text))
            {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("CHILD_MODULE_DESCRIPTION", &child_name),
                    format!(
                        "Child Module `{}` lacks a substantive contribution description.",
                        heading.text
                    ),
                )?;
            }
        }
        self.summary.physical_child_modules += physical.len();
        self.summary.documented_child_modules += documented.len();
        self.validate_bijection(path, "mods", &physical, &documented)
    }

    fn validate_bijection(
        &mut self,
        path: &str,
        attribute: &str,
        physical: &BTreeSet<String>,
        documented: &BTreeSet<String>,
    ) -> Result<(), FindingError> {
        for missing in physical.difference(documented) {
            self.markdown_finding(
                path,
                &semantic_discriminator(
                    "PHYSICAL_CATALOG_ENTRY_MISSING",
                    &format!("{attribute}:{missing}"),
                ),
                format!("Physical `{attribute}` element `{missing}` is missing from the canonical documentation catalog."),
            )?;
        }
        for phantom in documented.difference(physical) {
            self.markdown_finding(
                path,
                &semantic_discriminator(
                    "DOCUMENTED_CATALOG_ENTRY_MISSING",
                    &format!("{attribute}:{phantom}"),
                ),
                format!("Documented `{attribute}` element `{phantom}` does not exist as a direct physical element."),
            )?;
        }
        Ok(())
    }

    fn validate_common(
        &mut self,
        path: &str,
        document: &MarkdownDocument,
        expected_h1: &str,
        expected_h2: &[&str],
    ) -> Result<(), FindingError> {
        let h1: Vec<&Heading> = document
            .headings
            .iter()
            .filter(|heading| heading.level == 1)
            .collect();
        if h1.len() != 1 || h1.first().is_none_or(|heading| heading.text != expected_h1) {
            self.markdown_finding(
                path,
                "CANONICAL_H1",
                format!("Canonical Markdown must contain exactly one H1 `# {expected_h1}`."),
            )?;
        }
        if document
            .headings
            .first()
            .is_none_or(|heading| heading.level != 1)
        {
            self.markdown_finding(
                path,
                "CANONICAL_H1_POSITION",
                "The canonical H1 must be the first heading.".into(),
            )?;
        }
        let actual_h2: Vec<&str> = document
            .headings
            .iter()
            .filter(|heading| heading.level == 2)
            .map(|heading| heading.text.as_str())
            .collect();
        if actual_h2 != expected_h2 {
            self.markdown_finding(
                path,
                "CANONICAL_H2_SEQUENCE",
                format!(
                    "H2 sections must be exactly `{}` in canonical order.",
                    expected_h2.join("`, `")
                ),
            )?;
        }
        for heading in document
            .headings
            .iter()
            .filter(|heading| heading.level >= 4)
        {
            self.markdown_finding(
                path,
                &semantic_discriminator("PROHIBITED_HEADING_DEPTH", &heading.text),
                format!(
                    "Heading `{}` uses prohibited H{} depth.",
                    heading.text, heading.level
                ),
            )?;
        }
        for section in expected_h2 {
            if !document.section_is_substantive(section) {
                self.markdown_finding(
                    path,
                    &semantic_discriminator("EMPTY_REQUIRED_SECTION", section),
                    format!("Required section `{section}` has no substantive content."),
                )?;
            }
        }
        for placeholder in document.placeholders() {
            self.markdown_finding(
                path,
                &semantic_discriminator("PLACEHOLDER_CONTENT", placeholder),
                format!("Canonical Markdown contains placeholder content `{placeholder}`."),
            )?;
        }
        if document.empty_list_items > 0 {
            self.markdown_finding(
                path,
                "EMPTY_LIST_ITEMS",
                format!(
                    "Canonical Markdown contains {} empty list item(s).",
                    document.empty_list_items
                ),
            )?;
        }
        Ok(())
    }

    fn validate_all_links(&mut self) -> Result<(), FindingError> {
        let parsed: Vec<(String, Vec<String>)> = self
            .parsed
            .iter()
            .map(|(path, document)| (path.clone(), document.links.clone()))
            .collect();
        for (path, links) in parsed {
            for link in links {
                if is_external_or_fragment(&link) {
                    continue;
                }
                if resolve_relative(&path, &link).is_none_or(|target| !self.paths.contains(&target))
                {
                    self.summary.broken_or_stale_links += 1;
                    self.finding(
                        &path,
                        &semantic_discriminator("BROKEN_RELATIVE_LINK", &link),
                        format!("Relative Markdown link `{link}` is broken or stale."),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn structural_finding(
        &mut self,
        path: &str,
        discriminator: &str,
        message: String,
    ) -> Result<(), FindingError> {
        self.finding(path, discriminator, message)
    }

    fn markdown_finding(
        &mut self,
        path: &str,
        discriminator: &str,
        message: String,
    ) -> Result<(), FindingError> {
        self.summary.structural_markdown_violations += 1;
        self.finding(path, discriminator, message)
    }

    fn finding(
        &mut self,
        path: &str,
        discriminator: &str,
        message: String,
    ) -> Result<(), FindingError> {
        self.findings.push(CanonicalFinding::failure(
            self.definition.clone(),
            FindingOccurrence::new(Vec::new(), FindingLocation::at_path(path)?, message)?
                .with_discriminator(discriminator)?,
            self.evaluator.clone(),
            self.standard_edition,
        )?);
        Ok(())
    }
}

fn semantic_discriminator(kind: &str, target: &str) -> String {
    format!("{kind}:{:x}", Sha256::digest(target.as_bytes()))
}

#[derive(Clone, Debug)]
struct MarkdownDocument {
    headings: Vec<Heading>,
    paragraphs: Vec<Paragraph>,
    links: Vec<String>,
    empty_list_items: usize,
}

impl MarkdownDocument {
    #[allow(clippy::too_many_lines)]
    fn parse(source: &str) -> Self {
        let mut document = Self {
            headings: Vec::new(),
            paragraphs: Vec::new(),
            links: Vec::new(),
            empty_list_items: 0,
        };
        let mut heading: Option<HeadingBuilder> = None;
        let mut paragraph: Option<ParagraphBuilder> = None;
        let mut current_h2: Option<String> = None;
        let mut current_h3: Option<usize> = None;
        let mut list_items = Vec::new();

        for event in Parser::new_ext(source, Options::all()) {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    heading = Some(HeadingBuilder {
                        level: heading_level(level),
                        text: String::new(),
                        links: Vec::new(),
                        codes: Vec::new(),
                        parent_h2: current_h2.clone(),
                    });
                }
                Event::End(TagEnd::Heading(_)) => {
                    if let Some(builder) = heading.take() {
                        let index = document.headings.len();
                        let complete = Heading {
                            index,
                            level: builder.level,
                            text: builder.text.trim().to_owned(),
                            links: builder.links,
                            codes: builder.codes,
                            parent_h2: builder.parent_h2,
                        };
                        match complete.level {
                            1 => {
                                current_h2 = None;
                                current_h3 = None;
                            }
                            2 => {
                                current_h2 = Some(complete.text.clone());
                                current_h3 = None;
                            }
                            3 => current_h3 = Some(index),
                            _ => {}
                        }
                        document.headings.push(complete);
                    }
                }
                Event::Start(Tag::Paragraph) => {
                    paragraph = Some(ParagraphBuilder {
                        text: String::new(),
                        codes: Vec::new(),
                        h2: current_h2.clone(),
                        h3: current_h3,
                    });
                }
                Event::End(TagEnd::Paragraph) => {
                    if let Some(builder) = paragraph.take() {
                        document.paragraphs.push(Paragraph {
                            text: builder.text.trim().to_owned(),
                            codes: builder.codes,
                            h2: builder.h2,
                            h3: builder.h3,
                        });
                    }
                }
                Event::Start(Tag::Item) => list_items.push(false),
                Event::End(TagEnd::Item) => {
                    if !list_items.pop().unwrap_or(false) {
                        document.empty_list_items += 1;
                    }
                }
                Event::Start(Tag::Link { dest_url, .. }) => {
                    let destination = dest_url.into_string();
                    document.links.push(destination.clone());
                    if let Some(builder) = &mut heading {
                        builder.links.push(destination);
                    }
                }
                Event::Text(text) | Event::InlineHtml(text) => {
                    if is_substantive(&text) {
                        list_items.fill(true);
                    }
                    if let Some(builder) = &mut heading {
                        builder.text.push_str(&text);
                    }
                    if let Some(builder) = &mut paragraph {
                        builder.text.push_str(&text);
                    }
                }
                Event::Code(code) => {
                    if is_substantive(&code) {
                        list_items.fill(true);
                    }
                    if let Some(builder) = &mut heading {
                        builder.text.push_str(&code);
                        builder.codes.push(code.to_string());
                    }
                    if let Some(builder) = &mut paragraph {
                        builder.text.push_str(&code);
                        builder.codes.push(code.to_string());
                    }
                }
                Event::SoftBreak | Event::HardBreak => {
                    if let Some(builder) = &mut paragraph {
                        builder.text.push(' ');
                    }
                }
                _ => {}
            }
        }
        document
    }

    fn section_is_substantive(&self, h2: &str) -> bool {
        self.paragraphs
            .iter()
            .any(|paragraph| paragraph.h2.as_deref() == Some(h2) && is_substantive(&paragraph.text))
    }

    fn paragraphs_for_h3(&self, index: usize) -> Vec<&Paragraph> {
        self.paragraphs
            .iter()
            .filter(|paragraph| paragraph.h3 == Some(index))
            .collect()
    }

    fn placeholders(&self) -> BTreeSet<&'static str> {
        let text = self
            .headings
            .iter()
            .map(|heading| heading.text.as_str())
            .chain(
                self.paragraphs
                    .iter()
                    .map(|paragraph| paragraph.text.as_str()),
            )
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        PLACEHOLDERS
            .iter()
            .copied()
            .filter(|placeholder| contains_phrase(&text, placeholder))
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Heading {
    index: usize,
    level: u8,
    text: String,
    links: Vec<String>,
    codes: Vec<String>,
    parent_h2: Option<String>,
}

struct HeadingBuilder {
    level: u8,
    text: String,
    links: Vec<String>,
    codes: Vec<String>,
    parent_h2: Option<String>,
}

#[derive(Clone, Debug)]
struct Paragraph {
    text: String,
    codes: Vec<String>,
    h2: Option<String>,
    h3: Option<usize>,
}

struct ParagraphBuilder {
    text: String,
    codes: Vec<String>,
    h2: Option<String>,
    h3: Option<usize>,
}

fn heading_level(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

fn discover_modules(paths: &BTreeSet<String>) -> BTreeSet<String> {
    let mut modules = BTreeSet::from([String::new()]);
    for path in paths {
        let segments: Vec<&str> = path.split('/').collect();
        let mut offset = 0;
        while offset + 1 < segments.len() {
            if segments[offset] == "mods" {
                modules.insert(segments[..=offset + 1].join("/"));
                offset += 2;
            } else {
                offset += 1;
            }
        }
    }
    modules
}

fn immediate_children(modules: &BTreeSet<String>, module: &str) -> Vec<String> {
    let mods = child_path(module, "mods");
    modules
        .iter()
        .filter(|candidate| !candidate.is_empty() && parent_path(candidate) == Some(mods.as_str()))
        .cloned()
        .collect()
}

fn direct_files(paths: &BTreeSet<String>, directory: &str) -> BTreeSet<String> {
    paths
        .iter()
        .filter(|path| parent_path(path) == Some(directory))
        .map(|path| file_name(path).to_owned())
        .collect()
}

fn element_catalog_entries(
    paths: &BTreeSet<String>,
    directory: &str,
    attribute: &str,
) -> BTreeSet<String> {
    if !matches!(attribute, "data" | "info") {
        return direct_files(paths, directory);
    }
    let prefix = format!("{directory}/");
    paths
        .iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(&prefix)?;
            let segments: Vec<&str> = relative.split('/').collect();
            match segments.as_slice() {
                [file] => Some((*file).to_owned()),
                [role, _file] => Some(format!("{role}/")),
                [role, collection, ..] => Some(format!("{role}/{collection}/")),
                [] => None,
            }
        })
        .collect()
}

fn has_descendant(paths: &BTreeSet<String>, directory: &str) -> bool {
    paths.iter().any(|path| is_descendant(path, directory))
}

fn is_descendant(path: &str, directory: &str) -> bool {
    path.strip_prefix(directory)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn module_name(module: &str) -> &str {
    if module.is_empty() { "." } else { module }
}

fn is_substantive(value: &str) -> bool {
    value.chars().any(char::is_alphanumeric)
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(start, matched)| {
        let end = start + matched.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        before.is_none_or(|character| !character.is_ascii_alphanumeric())
            && after.is_none_or(|character| !character.is_ascii_alphanumeric())
    })
}

fn is_external_or_fragment(link: &str) -> bool {
    link.starts_with('#') || link.contains("://") || link.starts_with("mailto:")
}

fn resolve_relative(source_path: &str, link: &str) -> Option<String> {
    if is_external_or_fragment(link) {
        return None;
    }
    let link = link.split(['#', '?']).next().unwrap_or(link);
    if link.is_empty() || link.contains('\\') {
        return None;
    }
    let base = Path::new(source_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let combined = base.join(link);
    let mut segments = Vec::new();
    for component in combined.components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy().into_owned()),
            Component::ParentDir => {
                segments.pop()?;
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(segments.join("/"))
}

fn authoritative_relationships(
    contract: &ModuleContract,
) -> BTreeMap<String, BTreeSet<ResolvedRelationshipType>> {
    let mut relationships = BTreeMap::<String, BTreeSet<ResolvedRelationshipType>>::new();
    for requirement in contract.requires() {
        relationships
            .entry(requirement.provider().to_owned())
            .or_default()
            .insert(ResolvedRelationshipType::DependsOn);
    }
    for relationship in contract.relationships() {
        relationships
            .entry(relationship.target().to_owned())
            .or_default()
            .insert(ResolvedRelationshipType::Verifies);
    }
    relationships
}

fn dependency_cycle(contracts: &[(String, String, Vec<String>)]) -> Option<Vec<String>> {
    let adjacency: BTreeMap<&str, Vec<&str>> = contracts
        .iter()
        .map(|(_, id, dependencies)| {
            (
                id.as_str(),
                dependencies.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let mut states = HashMap::new();
    for start in adjacency.keys().copied() {
        if states.contains_key(start) {
            continue;
        }
        states.insert(start, VisitState::Visiting);
        let mut path = vec![start];
        let mut stack = vec![(start, 0_usize)];
        while let Some(&(node, next_offset)) = stack.last() {
            let dependencies = adjacency.get(node).map_or(&[][..], Vec::as_slice);
            let Some(&dependency) = dependencies.get(next_offset) else {
                states.insert(node, VisitState::Complete);
                stack.pop();
                path.pop();
                continue;
            };
            if let Some(last) = stack.last_mut() {
                last.1 += 1;
            }
            if !adjacency.contains_key(dependency) {
                continue;
            }
            match states
                .get(dependency)
                .copied()
                .unwrap_or(VisitState::Unseen)
            {
                VisitState::Unseen => {
                    states.insert(dependency, VisitState::Visiting);
                    path.push(dependency);
                    stack.push((dependency, 0));
                }
                VisitState::Visiting => {
                    let start = path.iter().position(|candidate| *candidate == dependency)?;
                    let mut cycle: Vec<String> = path[start..]
                        .iter()
                        .map(|candidate| (*candidate).to_owned())
                        .collect();
                    cycle.push(dependency.to_owned());
                    return Some(cycle);
                }
                VisitState::Complete => {}
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
enum VisitState {
    Unseen,
    Visiting,
    Complete,
}

/// Explains why repository-bound documentation evaluation could not complete.
#[derive(Debug)]
pub enum DocumentationEvaluationError {
    /// A stabilized file could not be reread.
    Io {
        /// Absolute path used for the read.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: std::io::Error,
    },
    /// Reread bytes did not match the stabilized snapshot.
    SnapshotMismatch(Box<str>),
    /// A canonical finding could not be constructed.
    Finding(FindingError),
}

impl Display for DocumentationEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::SnapshotMismatch(path) => write!(
                formatter,
                "documentation input `{path}` does not match the stabilized snapshot"
            ),
            Self::Finding(error) => {
                write!(
                    formatter,
                    "documentation finding normalization failed: {error}"
                )
            }
        }
    }
}

impl Error for DocumentationEvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Finding(error) => Some(error),
            Self::SnapshotMismatch(_) => None,
        }
    }
}
