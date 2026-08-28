//! Evaluation of the canonical recursive Fortress Module grammar.

use std::collections::BTreeSet;

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of the recursive Fortress Module grammar.
pub const REPO_MODULE_RULE_ID: &str = "REPO-MODULE-001";

const REMEDIATION: &str = "Converge the path to the recursive Module grammar: keep README.md and contract.json at every Module root, keep direct elements in code/data/info/docs, place child Modules only beneath mods, add every bidirectional canonical documentation file including mods_docs.md, and use canonical lowercase underscore names.";
const CANONICAL_DIRECTORIES: [&str; 5] = ["code", "data", "info", "docs", "mods"];
const ATTRIBUTE_DIRECTORIES: [&str; 4] = ["code", "data", "info", "docs"];
const ROOT_SPECIAL_FILES: [&str; 9] = [
    ".gitattributes",
    ".gitignore",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "LICENSE",
    "LICENSE.md",
];
const ECOSYSTEM_FILENAMES: [&str; 3] = [
    "Cargo.toml",
    "Cargo.lock",
    "realized_behavioral_flow_graph.json",
];

/// Evaluates observed repository paths against the recursive Module grammar.
///
/// The root is a Module. Every immediate directory beneath a Module's `mods/`
/// is another Module. The GitHub-controlled `.github/` namespace and recognized
/// root community-health files are the only opaque repository-level surfaces.
/// Empty directories cannot be inferred from a file inventory and therefore
/// remain outside this content-based evaluator's observation boundary.
///
/// # Errors
///
/// Returns [`FindingError`] if a canonical finding cannot be constructed.
pub fn evaluate_module_grammar(
    observed_paths: &[String],
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let definition = RuleFindingDefinition::new(
        REPO_MODULE_RULE_ID,
        1,
        FindingCategory::Repository,
        REMEDIATION,
    )?;
    let evaluator =
        EvaluatorProvenance::new("fortress-core/module-grammar", env!("CARGO_PKG_VERSION"))?;
    let files: BTreeSet<String> = observed_paths.iter().cloned().collect();
    let directories = observed_directories(&files);
    let modules = discover_modules(&directories);
    let mut findings = Vec::new();

    evaluate_root_entries(
        &files,
        &directories,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    evaluate_filenames(
        &files,
        &modules,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    for module in &modules {
        evaluate_module(
            module,
            &files,
            &directories,
            &modules,
            &definition,
            &evaluator,
            standard_edition,
            &mut findings,
        )?;
    }

    findings.sort();
    findings.dedup();
    Ok(findings)
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
        let mut discovered = Vec::new();
        for module in &modules {
            let mods = child_path(module, "mods");
            for directory in directories {
                if parent_path(directory) == Some(mods.as_str()) {
                    discovered.push(directory.clone());
                }
            }
        }
        let previous = modules.len();
        modules.extend(discovered);
        if modules.len() == previous {
            break;
        }
    }
    modules
}

#[allow(clippy::too_many_arguments)]
fn evaluate_root_entries(
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for directory in directories
        .iter()
        .filter(|directory| parent_path(directory).is_none())
    {
        if directory == ".github" || CANONICAL_DIRECTORIES.contains(&directory.as_str()) {
            continue;
        }
        let message = CANONICAL_DIRECTORIES
            .iter()
            .find(|canonical| canonical.eq_ignore_ascii_case(directory))
            .map_or_else(
                || format!("Root directory `{directory}` is not a canonical Module directory or the GitHub integration namespace."),
                |canonical| {
                    format!("Directory `{directory}` must use canonical spelling `{canonical}`.")
                },
            );
        findings.push(path_finding(
            definition,
            evaluator,
            directory,
            message,
            standard_edition,
        )?);
    }
    for file in files.iter().filter(|path| !path.contains('/')) {
        if matches!(file.as_str(), "README.md" | "contract.json")
            || ROOT_SPECIAL_FILES.contains(&file.as_str())
        {
            continue;
        }
        findings.push(path_finding(
            definition,
            evaluator,
            file,
            format!("Root file `{file}` is not README.md, contract.json, or a recognized GitHub repository surface."),
            standard_edition,
        )?);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_module(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    modules: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    let readme = child_path(module, "README.md");
    if !files.contains(&readme) {
        findings.push(path_finding(
            definition,
            evaluator,
            &readme,
            format!(
                "Module `{}` is missing its mandatory `README.md`.",
                module_name(module)
            ),
            standard_edition,
        )?);
    }
    let contract = child_path(module, "contract.json");
    if !files.contains(&contract) {
        findings.push(path_finding(
            definition,
            evaluator,
            &contract,
            format!(
                "Module `{}` is missing its mandatory `contract.json`.",
                module_name(module)
            ),
            standard_edition,
        )?);
    }

    if !module.is_empty() {
        let name = module.rsplit('/').next().unwrap_or(module);
        if !is_lexical_name(name, false) {
            findings.push(path_finding(
                definition,
                evaluator,
                module,
                format!("Module name `{name}` violates the lowercase underscore filename grammar."),
                standard_edition,
            )?);
        }
    }

    evaluate_directories(
        module,
        directories,
        definition,
        evaluator,
        standard_edition,
        findings,
    )?;
    evaluate_direct_files(
        module,
        files,
        definition,
        evaluator,
        standard_edition,
        findings,
    )?;
    evaluate_attributes(
        module,
        files,
        directories,
        definition,
        evaluator,
        standard_edition,
        findings,
    )?;

    let code = child_path(module, "code");
    let has_code = directories.contains(&code);
    let mods = child_path(module, "mods");
    let child_modules = modules
        .iter()
        .any(|candidate| !candidate.is_empty() && parent_path(candidate) == Some(mods.as_str()));
    if !has_code && !child_modules {
        findings.push(path_finding(
            definition,
            evaluator,
            &readme,
            format!(
                "Module `{}` has neither directly owned `code/` nor child Modules beneath `mods/`.",
                module_name(module)
            ),
            standard_edition,
        )?);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_directories(
    module: &str,
    directories: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    if module.is_empty() {
        return Ok(());
    }
    for directory in directories
        .iter()
        .filter(|directory| parent_path(directory) == module_parent(module))
    {
        let name = directory.rsplit('/').next().unwrap_or(directory);
        if module.is_empty() && name == ".github" {
            continue;
        }
        if !CANONICAL_DIRECTORIES.contains(&name) {
            let message = CANONICAL_DIRECTORIES
                .iter()
                .find(|canonical| canonical.eq_ignore_ascii_case(name))
                .map_or_else(
                    || format!("Directory `{directory}` is not one of code/data/info/docs/mods."),
                    |canonical| {
                        format!(
                            "Directory `{directory}` must use canonical spelling `{canonical}`."
                        )
                    },
                );
            findings.push(path_finding(
                definition,
                evaluator,
                directory,
                message,
                standard_edition,
            )?);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_direct_files(
    module: &str,
    files: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    if !module.is_empty() {
        for file in files
            .iter()
            .filter(|file| parent_path(file) == module_parent(module))
        {
            let name = file.rsplit('/').next().unwrap_or(file);
            if !matches!(name, "README.md" | "contract.json") {
                findings.push(path_finding(
                    definition,
                    evaluator,
                    file,
                    format!(
                        "Module `{}` contains loose file `{name}` other than README.md or contract.json outside code/data/info/docs.",
                        module_name(module)
                    ),
                    standard_edition,
                )?);
            }
        }
    }

    let mods = child_path(module, "mods");
    for file in files
        .iter()
        .filter(|file| parent_path(file) == Some(mods.as_str()))
    {
        findings.push(path_finding(
            definition,
            evaluator,
            file,
            format!("File `{file}` is loose beneath `mods/`; `mods/` may contain Module directories only."),
            standard_edition,
        )?);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_attributes(
    module: &str,
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for attribute in ATTRIBUTE_DIRECTORIES {
        let attribute_path = child_path(module, attribute);
        for directory in directories
            .iter()
            .filter(|directory| parent_path(directory) == Some(attribute_path.as_str()))
        {
            findings.push(path_finding(
                definition,
                evaluator,
                directory,
                format!("Attribute directory `{attribute_path}/` contains nested directory `{directory}`; attribute elements must be direct files."),
                standard_edition,
            )?);
        }

        for file in files
            .iter()
            .filter(|file| parent_path(file) == Some(attribute_path.as_str()))
        {
            let name = file.rsplit('/').next().unwrap_or(file);
            if attribute == "docs" && !is_allowed_docs_filename(name) {
                findings.push(path_finding(
                    definition,
                    evaluator,
                    file,
                    format!("Documentation file `{file}` is not one of code_docs.md, data_docs.md, info_docs.md, or mods_docs.md."),
                    standard_edition,
                )?);
            }
        }
    }

    for (attribute, documentation) in [
        ("code", "code_docs.md"),
        ("data", "data_docs.md"),
        ("info", "info_docs.md"),
        ("mods", "mods_docs.md"),
    ] {
        let attribute_path = child_path(module, attribute);
        let documentation_path = child_path(&child_path(module, "docs"), documentation);
        let attribute_exists = directories.contains(&attribute_path);
        let documentation_exists = files.contains(&documentation_path);
        if attribute_exists && !documentation_exists {
            findings.push(path_finding(
                definition,
                evaluator,
                &documentation_path,
                format!(
                    "Module `{}` has `{attribute}/` but is missing `docs/{documentation}`.",
                    module_name(module)
                ),
                standard_edition,
            )?);
        } else if !attribute_exists && documentation_exists {
            findings.push(path_finding(
                definition,
                evaluator,
                &documentation_path,
                format!("Module `{}` has `docs/{documentation}` without the corresponding `{attribute}/` directory.", module_name(module)),
                standard_edition,
            )?);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_filenames(
    files: &BTreeSet<String>,
    modules: &BTreeSet<String>,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    let readmes: BTreeSet<String> = modules
        .iter()
        .map(|module| child_path(module, "README.md"))
        .collect();
    for file in files {
        if file.starts_with(".github/")
            || readmes.contains(file)
            || (!file.contains('/') && ROOT_SPECIAL_FILES.contains(&file.as_str()))
        {
            continue;
        }
        let name = file.rsplit('/').next().unwrap_or(file);
        if ECOSYSTEM_FILENAMES.contains(&name) {
            let required_parent = if name == "Cargo.toml" { "data" } else { "info" };
            let actual_parent = parent_path(file)
                .and_then(|parent| parent.rsplit('/').next())
                .unwrap_or("");
            if actual_parent != required_parent {
                findings.push(path_finding(
                    definition,
                    evaluator,
                    file,
                    format!("Ecosystem file `{name}` is derived or consumed as `{required_parent}/` and must be placed there."),
                    standard_edition,
                )?);
            }
            continue;
        }
        if !is_lexical_name(name, true) {
            findings.push(path_finding(
                definition,
                evaluator,
                file,
                format!("Filename `{name}` violates the lowercase underscore filename grammar."),
                standard_edition,
            )?);
        }
    }
    Ok(())
}

fn is_allowed_docs_filename(name: &str) -> bool {
    matches!(
        name,
        "code_docs.md" | "data_docs.md" | "info_docs.md" | "mods_docs.md"
    )
}

/// Returns whether a Fortress-controlled file or Module name satisfies the
/// canonical lexical grammar.
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

    let semantic = if let Some((base, version)) = stem.rsplit_once("_v") {
        if version.bytes().all(|byte| byte.is_ascii_digit()) {
            if version.is_empty() || version.starts_with('0') {
                return false;
            }
            base
        } else {
            stem
        }
    } else {
        stem
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

fn module_name(module: &str) -> &str {
    if module.is_empty() { "." } else { module }
}

fn module_parent(module: &str) -> Option<&str> {
    if module.is_empty() {
        None
    } else {
        Some(module)
    }
}

fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

fn path_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    path: &str,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(Vec::new(), FindingLocation::at_path(path)?, message)?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}
