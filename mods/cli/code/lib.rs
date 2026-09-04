//! Terminal presentation and argument dispatch for the Fortress CLI.
//!
//! This crate renders the provider-independent command registry and executes
//! the real Snapshot Governance audit pipeline from `fortress-core`. It
//! registers no placeholder operation and reports unsupported commands with a
//! non-success exit code.

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, warnings)]

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

use fortress_core::affected_analysis::{IncrementalCacheState, ProjectionKind};
use fortress_core::audit::{
    RepositoryProjectionCache, audit_repository, compile_repository_affected_analysis,
    compile_repository_bfg, compile_repository_ccg, compile_repository_certification_bundle,
    compile_repository_environmental_analysis, compile_repository_information_flow_analysis,
    compile_repository_psm, compile_repository_realized_bfg,
    compile_repository_reference_resolution, compile_repository_semantic_analysis,
    compile_repository_semantic_conformance, compile_repository_source_artifact_model,
    compile_repository_state_effect_analysis, inspect_repository_modules,
    prepare_repository_certification_source, prepare_repository_projection_cache,
};
use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, BootstrapProposal, apply_repository_bootstrap,
    discover_repository_bootstrap,
};
use fortress_core::certification::{CertificationStatus, RustSuiteExecution};
use fortress_core::contract_coherency::CcgCoherencyStatus;
use fortress_core::finding_governance::{FINDING_GOVERNANCE_PATH, FindingGovernanceDocument};
pub mod command;

use command::{CommandDescriptor, CommandRegistry};

/// Successful process exit status.
pub const EXIT_SUCCESS: u8 = 0;
/// Evaluated mandatory snapshot rule violation exit status.
pub const EXIT_VIOLATION: u8 = 1;
/// User invocation or unsupported-command exit status.
pub const EXIT_USAGE: u8 = 2;

fn projection_cache(root: &PathBuf, kind: ProjectionKind) -> Option<RepositoryProjectionCache> {
    prepare_repository_projection_cache(root, kind).ok()
}

fn cached_projection(binding: Option<&RepositoryProjectionCache>) -> Option<(Vec<u8>, u8)> {
    let binding = binding?;
    let loaded = binding.cache().load(binding.key()).ok()?;
    (loaded.state() == IncrementalCacheState::ReusableCurrent)
        .then(|| Some((loaded.content()?.to_vec(), loaded.exit_code()?)))?
}

fn store_projection(binding: Option<&RepositoryProjectionCache>, bytes: &[u8], exit_code: u8) {
    if let Some(binding) = binding {
        let _ = binding.cache().store(binding.key(), bytes, exit_code);
    }
}

fn write_projection<O: Write>(
    destination: Option<PathBuf>,
    output: &mut O,
    bytes: &[u8],
) -> io::Result<()> {
    if let Some(destination) = destination {
        fs::write(destination, bytes)
    } else {
        output.write_all(bytes)
    }
}

/// Runs Fortress CLI dispatch against caller-provided streams.
///
/// The iterator contains arguments after the executable name. Empty input
/// renders top-level help. Unsupported operations are never treated as success.
///
/// # Errors
///
/// Returns an I/O error when writing user-visible output fails.
pub fn run<I, S, O, E>(arguments: I, output: &mut O, error: &mut E) -> io::Result<u8>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    O: Write,
    E: Write,
{
    let registry = CommandRegistry::builtin();
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let Some(first) = arguments.first() else {
        render_top_level_help(&registry, output)?;
        return Ok(EXIT_SUCCESS);
    };

    let Some(command) = registry.find(first) else {
        writeln!(
            error,
            "unsupported command `{first}`; run `fortress help` to list implemented commands"
        )?;
        return Ok(EXIT_USAGE);
    };

    match command.id() {
        "CMD-CORE-HELP" => run_help(&registry, &arguments[1..], output, error),
        "CMD-CORE-VERSION" => run_version(&arguments[1..], output, error),
        "CMD-SNAPSHOT-AUDIT" => run_audit(&arguments[1..], output, error),
        "CMD-FINDING-CHECK" => run_check(&arguments[1..], output, error),
        "CMD-FINDING-LIST" => run_findings(&arguments[1..], output, error),
        "CMD-FINDING-BASELINE" => run_baseline(&arguments[1..], output, error),
        "CMD-FINDING-EXCEPTION" => run_exceptions(&arguments[1..], output, error),
        "CMD-REPOSITORY-INIT" => run_init(&arguments[1..], output, error),
        "CMD-MODULE-INSPECTION" => run_modules(&arguments[1..], output, error),
        "CMD-AFFECTED-ANALYSIS" => run_affected(&arguments[1..], output, error),
        "CMD-CONTRACT-CCG" => run_ccg(&arguments[1..], output, error),
        "CMD-BEHAVIOR-BFG" => run_bfg(&arguments[1..], output, error),
        "CMD-BEHAVIOR-REALIZED-BFG" => run_realized_bfg(&arguments[1..], output, error),
        "CMD-PROGRAM-PSM" => run_psm(&arguments[1..], output, error),
        "CMD-SEMANTIC-ANALYSIS" => run_semantic(&arguments[1..], output, error),
        "CMD-STATE-EFFECT-ANALYSIS" => run_state_effect(&arguments[1..], output, error),
        "CMD-SEMANTIC-CONFORMANCE" => run_semantic_conformance(&arguments[1..], output, error),
        "CMD-INFORMATION-FLOW" => run_information_flow(&arguments[1..], output, error),
        "CMD-ENVIRONMENTAL-ANALYSIS" => run_environmental(&arguments[1..], output, error),
        "CMD-REFERENCE-RESOLUTION" => run_references(&arguments[1..], output, error),
        "CMD-SOURCE-ARTIFACT-MODEL" => run_source_artifacts(&arguments[1..], output, error),
        "CMD-CERTIFICATION-FULL-SNAPSHOT" => run_certify(&arguments[1..], output, error),
        _ => {
            writeln!(
                error,
                "registered command `{}` has no CLI executor",
                command.id()
            )?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_affected<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress affected [path] --from snapshot-path [--format human|json] [--output path]";
    let mut root = None;
    let mut previous = None;
    let mut destination = None;
    let mut format = "human";
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--from" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                if previous.replace(PathBuf::from(value)).is_some() {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            }
            "--format" => {
                index += 1;
                format = match arguments.get(index).map(String::as_str) {
                    Some("human") => "human",
                    Some("json") => "json",
                    _ => {
                        writeln!(error, "{USAGE}")?;
                        return Ok(EXIT_USAGE);
                    }
                };
            }
            value if value.starts_with("--format=") => {
                format = match value.strip_prefix("--format=") {
                    Some("human") => "human",
                    Some("json") => "json",
                    _ => {
                        writeln!(error, "{USAGE}")?;
                        return Ok(EXIT_USAGE);
                    }
                };
            }
            "--output" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                if destination.replace(PathBuf::from(value)).is_some() {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            }
            value if !value.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(value));
            }
            _ => {
                writeln!(error, "{USAGE}")?;
                return Ok(EXIT_USAGE);
            }
        }
        index += 1;
    }
    let Some(previous) = previous else {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    };
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    let analysis = match compile_repository_affected_analysis(&root, previous) {
        Ok(value) => value,
        Err(analysis_error) => {
            writeln!(error, "affected analysis failed: {analysis_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let document = if format == "json" {
        analysis.to_canonical_json().map_err(io::Error::other)?
    } else {
        analysis.to_human()
    };
    write_projection(destination, output, document.as_bytes())?;
    Ok(EXIT_SUCCESS)
}

fn run_modules<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress modules [path] [--format human|json]";
    let mut root = None;
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                match arguments.get(index).map(String::as_str) {
                    Some("json") => json = true,
                    Some("human") => json = false,
                    _ => {
                        writeln!(error, "{USAGE}")?;
                        return Ok(EXIT_USAGE);
                    }
                }
            }
            value if value.starts_with("--format=") => match value.strip_prefix("--format=") {
                Some("json") => json = true,
                Some("human") => json = false,
                _ => {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            },
            value if !value.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(value));
            }
            _ => {
                writeln!(error, "{USAGE}")?;
                return Ok(EXIT_USAGE);
            }
        }
        index += 1;
    }
    let inspection = match inspect_repository_modules(root.unwrap_or_else(|| PathBuf::from("."))) {
        Ok(value) => value,
        Err(inspection_error) => {
            writeln!(error, "Module inspection failed: {inspection_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    if json {
        write!(
            output,
            "{}",
            inspection.to_canonical_json().map_err(io::Error::other)?
        )?;
    } else {
        writeln!(output, "Declared Modules: {}", inspection.modules().len())?;
        for module in inspection.modules() {
            writeln!(
                output,
                "  {} [{}] contract={} bindings={} sources={}",
                module.module(),
                module.authority(),
                module.contract(),
                module.bindings().len(),
                module.observed_sources()
            )?;
        }
        writeln!(
            output,
            "Unmapped analysis territories: {}",
            inspection.analysis_territories().len()
        )?;
        for territory in inspection.analysis_territories() {
            writeln!(
                output,
                "  {} path={} sources={}",
                territory.territory(),
                territory.path(),
                territory.observed_sources()
            )?;
        }
        for diagnostic in inspection.ownership_diagnostics() {
            writeln!(
                output,
                "  INVALID {} path={} modules={} {}",
                diagnostic.code(),
                diagnostic.source_path(),
                diagnostic.modules().join(","),
                diagnostic.detail()
            )?;
        }
    }
    Ok(if inspection.is_valid() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn run_init<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    if arguments.first().map(String::as_str) == Some("apply") {
        return run_init_apply(&arguments[1..], output, error);
    }
    let request = match parse_init_discovery_arguments(arguments) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    if let Some(destination) = &request.destination
        && path_is_within(&request.root, destination)
    {
        writeln!(
            error,
            "initialization proposal output must be outside the subject repository so discovery remains read-only"
        )?;
        return Ok(EXIT_USAGE);
    }
    let proposal = match discover_repository_bootstrap(
        &request.root,
        &BootstrapDiscoveryOptions::new(request.project_id, request.display_name),
    ) {
        Ok(value) => value,
        Err(discovery_error) => {
            writeln!(error, "initialization discovery failed: {discovery_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let document = proposal.to_canonical_json().map_err(io::Error::other)?;
    if let Some(destination) = request.destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(EXIT_SUCCESS)
}

struct InitDiscoveryArguments {
    root: PathBuf,
    destination: Option<PathBuf>,
    project_id: Option<String>,
    display_name: Option<String>,
}

fn parse_init_discovery_arguments(
    arguments: &[String],
) -> Result<InitDiscoveryArguments, &'static str> {
    const USAGE: &str = "usage: fortress init [path] [--project-id ID --display-name NAME] [--format json] [--output path]";
    let mut root = None;
    let mut destination = None;
    let mut project_id = None;
    let mut display_name = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                if arguments.get(index).map(String::as_str) != Some("json") {
                    return Err(USAGE);
                }
            }
            "--output" | "--project-id" | "--display-name" => {
                let flag = arguments[index].as_str();
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err(USAGE);
                };
                let duplicate = match flag {
                    "--output" => destination.replace(PathBuf::from(value)).is_some(),
                    "--project-id" => project_id.replace(value.clone()).is_some(),
                    "--display-name" => display_name.replace(value.clone()).is_some(),
                    _ => unreachable!(),
                };
                if duplicate {
                    return Err(USAGE);
                }
            }
            value if value.starts_with("--format=") => {
                if value.strip_prefix("--format=") != Some("json") {
                    return Err(USAGE);
                }
            }
            value if !value.starts_with('-') && root.is_none() => root = Some(PathBuf::from(value)),
            _ => return Err(USAGE),
        }
        index += 1;
    }
    Ok(InitDiscoveryArguments {
        root: root.unwrap_or_else(|| PathBuf::from(".")),
        destination,
        project_id,
        display_name,
    })
}

fn run_init_apply<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress init apply [path] --proposal path [--baseline-current]";
    let mut root = None;
    let mut proposal_path = None;
    let mut baseline_current = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--proposal" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                if proposal_path.replace(PathBuf::from(value)).is_some() {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            }
            "--baseline-current" if !baseline_current => baseline_current = true,
            value if !value.starts_with('-') && root.is_none() => root = Some(PathBuf::from(value)),
            _ => {
                writeln!(error, "{USAGE}")?;
                return Ok(EXIT_USAGE);
            }
        }
        index += 1;
    }
    let Some(proposal_path) = proposal_path else {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    };
    let proposal_source = match fs::read_to_string(&proposal_path) {
        Ok(value) => value,
        Err(source) => {
            writeln!(
                error,
                "failed to read proposal {}: {source}",
                proposal_path.display()
            )?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let proposal = match BootstrapProposal::from_json_str(&proposal_source) {
        Ok(value) => value,
        Err(proposal_error) => {
            writeln!(error, "initialization apply failed: {proposal_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    match apply_repository_bootstrap(&root, &proposal, baseline_current) {
        Ok(result) => {
            write!(
                output,
                "{}",
                result.to_canonical_json().map_err(io::Error::other)?
            )?;
            Ok(EXIT_SUCCESS)
        }
        Err(apply_error) => {
            writeln!(error, "initialization apply failed: {apply_error}")?;
            Ok(EXIT_VIOLATION)
        }
    }
}

fn path_is_within(root: &std::path::Path, candidate: &std::path::Path) -> bool {
    let Ok(root) = fs::canonicalize(root) else {
        return false;
    };
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(
            |_| candidate.to_path_buf(),
            |current| current.join(candidate),
        )
    };
    let parent = absolute.parent().unwrap_or(&absolute);
    fs::canonicalize(parent).is_ok_and(|parent| parent.starts_with(root))
}

fn run_source_artifacts<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination, format) = match parse_source_artifact_arguments(arguments) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let cache = (format == "json")
        .then(|| projection_cache(&root, ProjectionKind::SourceArtifacts))
        .flatten();
    if let Some((bytes, exit_code)) = cached_projection(cache.as_ref()) {
        write_projection(destination, output, &bytes)?;
        return Ok(exit_code);
    }
    let model = match cache.as_ref().map_or_else(
        || compile_repository_source_artifact_model(&root),
        RepositoryProjectionCache::compile_source_artifacts,
    ) {
        Ok(value) => value,
        Err(model_error) => {
            writeln!(error, "source artifact compilation failed: {model_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = if format == "human" {
        model.to_human()
    } else {
        model.to_canonical_json().map_err(io::Error::other)?
    };
    let exit_code = if model.summary().findings() == 0 {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    };
    store_projection(cache.as_ref(), document.as_bytes(), exit_code);
    write_projection(destination, output, document.as_bytes())?;
    Ok(exit_code)
}

fn parse_source_artifact_arguments(
    arguments: &[String],
) -> Result<(PathBuf, Option<PathBuf>, &'static str), &'static str> {
    const USAGE: &str =
        "usage: fortress source-artifacts [path] [--format human|json] [--output path]";
    let mut root = None;
    let mut destination = None;
    let mut format = "json";
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            format = match arguments.get(index).map(String::as_str) {
                Some("human") => "human",
                Some("json") => "json",
                _ => return Err(USAGE),
            };
        } else if let Some(value) = argument.strip_prefix("--format=") {
            format = match value {
                "human" => "human",
                "json" => "json",
                _ => return Err("source-artifacts format must be `human` or `json`"),
            };
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err(USAGE);
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err(USAGE);
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err(USAGE);
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((
        root.unwrap_or_else(|| PathBuf::from(".")),
        destination,
        format,
    ))
}

struct ReferenceArguments {
    root: PathBuf,
    destination: Option<PathBuf>,
    move_module: Option<String>,
    move_parent: Option<String>,
}

fn run_references<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let request = match parse_reference_arguments(arguments) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let evaluation = match compile_repository_reference_resolution(&request.root) {
        Ok(value) => value,
        Err(resolution_error) => {
            writeln!(error, "reference resolution failed: {resolution_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = if let (Some(module), Some(parent)) = (
        request.move_module.as_deref(),
        request.move_parent.as_deref(),
    ) {
        match evaluation.index().preview_move(module, parent) {
            Ok(preview) => preview.to_canonical_json().map_err(io::Error::other)?,
            Err(move_error) => {
                writeln!(error, "relocation preview failed: {move_error}")?;
                return Ok(EXIT_USAGE);
            }
        }
    } else {
        evaluation
            .index()
            .to_canonical_json()
            .map_err(io::Error::other)?
    };
    if let Some(destination) = request.destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(if evaluation.findings().is_empty() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn parse_reference_arguments(arguments: &[String]) -> Result<ReferenceArguments, &'static str> {
    const USAGE: &str = "usage: fortress references [path] [--format json] [--output path] [--move Module-ID --to Parent-Module-ID]";
    let mut root = None;
    let mut destination = None;
    let mut move_module = None;
    let mut move_parent = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err(USAGE);
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err(USAGE);
            }
        } else if ["--output", "--move", "--to"].contains(&argument.as_str()) {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err(USAGE);
            };
            let replaced = match argument.as_str() {
                "--output" => destination.replace(PathBuf::from(value)).is_some(),
                "--move" => move_module.replace(value.clone()).is_some(),
                _ => move_parent.replace(value.clone()).is_some(),
            };
            if replaced {
                return Err(USAGE);
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err(USAGE);
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    if move_module.is_some() != move_parent.is_some() {
        return Err(USAGE);
    }
    Ok(ReferenceArguments {
        root: root.unwrap_or_else(|| PathBuf::from(".")),
        destination,
        move_module,
        move_parent,
    })
}

#[derive(Clone, Copy)]
enum CertificationOutputFormat {
    Human,
    Json,
}

struct CertificationArguments {
    root: PathBuf,
    format: CertificationOutputFormat,
    evidence_output: Option<PathBuf>,
    certification_output: Option<PathBuf>,
    verified_bfg_output: Option<PathBuf>,
    projection_output_dir: Option<PathBuf>,
    audit_output: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
fn run_certify<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let request = match parse_certification_arguments(arguments) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let before = match prepare_repository_certification_source(&request.root) {
        Ok(value) => value,
        Err(source_error) => {
            writeln!(
                error,
                "certification source preparation failed: {source_error}"
            )?;
            return Ok(EXIT_USAGE);
        }
    };
    let suite_passed = execute_canonical_rust_suite(&request.root, error)?;
    let after = match prepare_repository_certification_source(&request.root) {
        Ok(value) => value,
        Err(source_error) => {
            writeln!(
                error,
                "post-execution certification source preparation failed: {source_error}"
            )?;
            return Ok(EXIT_USAGE);
        }
    };
    if before != after {
        writeln!(
            error,
            "certification source or test inventory changed during local execution"
        )?;
        return Ok(EXIT_USAGE);
    }
    let bundle = match compile_repository_certification_bundle(
        &request.root,
        RustSuiteExecution {
            executor: "fortress-local-rust-executor".into(),
            executor_version: env!("CARGO_PKG_VERSION").into(),
            toolchain: "1.97.1".into(),
            certification_source_digest: before.digest,
            test_inventory_digest: before.test_inventory_digest,
            canonical_unfiltered: true,
            passed: suite_passed,
            eligible_test_ids: before.eligible_test_ids,
            ignored_test_ids: before.ignored_test_ids,
        },
    ) {
        Ok(value) => value,
        Err(certification_error) => {
            writeln!(
                error,
                "certification compilation failed: {certification_error}"
            )?;
            return Ok(EXIT_USAGE);
        }
    };
    if let Some(directory) = &request.projection_output_dir {
        for (logical_path, document) in bundle.projections() {
            let destination = directory.join(logical_path);
            let parent = destination
                .parent()
                .ok_or_else(|| io::Error::other("projection output path has no parent"))?;
            fs::create_dir_all(parent)?;
            fs::write(destination, document)?;
        }
    }
    if let Some(path) = request.audit_output {
        fs::write(path, bundle.audit_json())?;
    }
    let products = bundle.products();
    let evidence = products
        .evidence_graph
        .to_json_pretty()
        .map_err(io::Error::other)?;
    let certification = products
        .certification
        .to_json_pretty()
        .map_err(io::Error::other)?;
    let verified = products
        .verified_bfg
        .to_json_pretty()
        .map_err(io::Error::other)?;
    if let Some(path) = request.evidence_output {
        fs::write(path, evidence)?;
    }
    if let Some(path) = request.certification_output {
        fs::write(path, &certification)?;
    }
    if let Some(path) = request.verified_bfg_output {
        fs::write(path, verified)?;
    }
    match request.format {
        CertificationOutputFormat::Json => write!(output, "{certification}")?,
        CertificationOutputFormat::Human => {
            writeln!(output, "Fortress Snapshot Certification")?;
            writeln!(output, "Profile: CERT-FULL-SNAPSHOT-V1")?;
            writeln!(output, "Status: {:?}", products.certification.status())?;
            writeln!(
                output,
                "Digest: {}",
                products.certification.certification_digest()
            )?;
            writeln!(
                output,
                "Obligations: {}",
                products.certification.summary().obligations
            )?;
        }
    }
    Ok(
        if products.certification.status() == CertificationStatus::Pass {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
}

fn execute_canonical_rust_suite<E: Write>(root: &PathBuf, error: &mut E) -> io::Result<bool> {
    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|home| home.join(".cargo/bin/cargo.exe"))
                .filter(|path| path.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("cargo"));
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::env::temp_dir().join("fortress-certification-target"),
        PathBuf::from,
    );
    let canonical_root = fs::canonicalize(root)?;
    if !target.is_absolute() || target.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "certification Cargo target must be absolute and outside the governed repository",
        ));
    }
    writeln!(
        error,
        "[fortress-certify] executing canonical local Rust suite with external build target"
    )?;
    let status = Command::new(cargo)
        .current_dir(root)
        .env("RUSTUP_TOOLCHAIN", "1.97.1")
        .env("CARGO_TARGET_DIR", target)
        .arg("--config")
        .arg("data/cargo_config.toml")
        .arg("test")
        .arg("--manifest-path")
        .arg("data/Cargo.toml")
        .arg("--workspace")
        .arg("--all-targets")
        .arg("--all-features")
        .status()?;
    Ok(status.success())
}

fn parse_certification_arguments(
    arguments: &[String],
) -> Result<CertificationArguments, &'static str> {
    const USAGE: &str = "usage: fortress certify [path] [--format human|json] [--evidence-output path] [--certification-output path] [--verified-bfg-output path] [--projection-output-dir path] [--audit-output path]";
    let mut root = None;
    let mut format = CertificationOutputFormat::Human;
    let mut evidence_output = None;
    let mut certification_output = None;
    let mut verified_bfg_output = None;
    let mut projection_output_dir = None;
    let mut audit_output = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            format = match arguments.get(index).map(String::as_str) {
                Some("human") => CertificationOutputFormat::Human,
                Some("json") => CertificationOutputFormat::Json,
                _ => return Err(USAGE),
            };
        } else if let Some(value) = argument.strip_prefix("--format=") {
            format = match value {
                "human" => CertificationOutputFormat::Human,
                "json" => CertificationOutputFormat::Json,
                _ => return Err(USAGE),
            };
        } else if [
            "--evidence-output",
            "--certification-output",
            "--verified-bfg-output",
            "--projection-output-dir",
            "--audit-output",
        ]
        .contains(&argument.as_str())
        {
            index += 1;
            let Some(path) = arguments.get(index).map(PathBuf::from) else {
                return Err(USAGE);
            };
            let slot = match argument.as_str() {
                "--evidence-output" => &mut evidence_output,
                "--certification-output" => &mut certification_output,
                "--verified-bfg-output" => &mut verified_bfg_output,
                "--projection-output-dir" => &mut projection_output_dir,
                _ => &mut audit_output,
            };
            if slot.replace(path).is_some() {
                return Err(USAGE);
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err(USAGE);
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok(CertificationArguments {
        root: root.unwrap_or_else(|| PathBuf::from(".")),
        format,
        evidence_output,
        certification_output,
        verified_bfg_output,
        projection_output_dir,
        audit_output,
    })
}

fn run_realized_bfg<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_derived_json_arguments(
        arguments,
        "usage: fortress realized-bfg [path] [--format json] [--output path]",
        "Realized BFG format must be json",
    ) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let graph = match compile_repository_realized_bfg(&root) {
        Ok(graph) => graph,
        Err(graph_error) => {
            writeln!(error, "Realized BFG compilation failed: {graph_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = graph.to_canonical_json().map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(
        if graph.summary().realization_violations() == 0 && graph.summary().proven_bypasses() == 0 {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
}

fn parse_derived_json_arguments(
    arguments: &[String],
    usage: &'static str,
    format_error: &'static str,
) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err(usage);
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err(format_error);
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err(usage);
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err(usage);
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err(usage);
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_environmental<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_environmental_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let evaluation = match compile_repository_environmental_analysis(&root) {
        Ok(evaluation) => evaluation,
        Err(analysis_error) => {
            writeln!(error, "environmental analysis failed: {analysis_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = evaluation
        .model()
        .to_canonical_json()
        .map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(
        if evaluation.environment_findings().is_empty()
            && evaluation.retry_findings().is_empty()
            && evaluation.recovery_findings().is_empty()
        {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
}

fn parse_environmental_arguments(
    arguments: &[String],
) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress environmental [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("environmental format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress environmental [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress environmental [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress environmental [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_information_flow<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_information_flow_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let evaluation = match compile_repository_information_flow_analysis(&root) {
        Ok(evaluation) => evaluation,
        Err(analysis_error) => {
            writeln!(error, "information-flow analysis failed: {analysis_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = evaluation
        .model()
        .to_canonical_json()
        .map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(if evaluation.findings().is_empty() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn parse_information_flow_arguments(
    arguments: &[String],
) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err(
                    "usage: fortress information-flow [path] [--format json] [--output path]",
                );
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("information-flow format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err(
                    "usage: fortress information-flow [path] [--format json] [--output path]",
                );
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err(
                    "usage: fortress information-flow [path] [--format json] [--output path]",
                );
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress information-flow [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_state_effect<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_state_effect_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let cache = projection_cache(&root, ProjectionKind::StateEffect);
    if let Some((bytes, exit_code)) = cached_projection(cache.as_ref()) {
        write_projection(destination, output, &bytes)?;
        return Ok(exit_code);
    }
    let evaluation = match cache.as_ref().map_or_else(
        || compile_repository_state_effect_analysis(&root),
        RepositoryProjectionCache::compile_state_effect,
    ) {
        Ok(evaluation) => evaluation,
        Err(analysis_error) => {
            writeln!(error, "state and effect analysis failed: {analysis_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = evaluation
        .model()
        .to_canonical_json()
        .map_err(io::Error::other)?;
    let exit_code =
        if evaluation.state_findings().is_empty() && evaluation.effect_findings().is_empty() {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        };
    store_projection(cache.as_ref(), document.as_bytes(), exit_code);
    write_projection(destination, output, document.as_bytes())?;
    Ok(exit_code)
}

fn parse_state_effect_arguments(
    arguments: &[String],
) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress state-effect [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("state-effect format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress state-effect [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress state-effect [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress state-effect [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

#[allow(clippy::too_many_lines)]
fn run_semantic_conformance<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress semantic-conformance [path] [--module ID] [--format human|json] [--output path]";
    let mut root = None;
    let mut module_id = None;
    let mut destination = None;
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--module" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                module_id = Some(value.clone());
            }
            "--format" => {
                index += 1;
                match arguments.get(index).map(String::as_str) {
                    Some("json") => json = true,
                    Some("human") => json = false,
                    _ => {
                        writeln!(error, "{USAGE}")?;
                        return Ok(EXIT_USAGE);
                    }
                }
            }
            value if value.starts_with("--format=") => match value.strip_prefix("--format=") {
                Some("json") => json = true,
                Some("human") => json = false,
                _ => {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            },
            "--output" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                if destination.replace(PathBuf::from(value)).is_some() {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            }
            value if !value.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(value));
            }
            _ => {
                writeln!(error, "{USAGE}")?;
                return Ok(EXIT_USAGE);
            }
        }
        index += 1;
    }
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    let cache = (json && module_id.is_none())
        .then(|| projection_cache(&root, ProjectionKind::SemanticConformance))
        .flatten();
    if let Some((bytes, exit_code)) = cached_projection(cache.as_ref()) {
        write_projection(destination, output, &bytes)?;
        return Ok(exit_code);
    }
    let evaluation = match cache.as_ref().map_or_else(
        || compile_repository_semantic_conformance(&root),
        RepositoryProjectionCache::compile_semantic_conformance,
    ) {
        Ok(value) => value,
        Err(analysis_error) => {
            writeln!(error, "semantic conformance failed: {analysis_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let modules = if let Some(id) = module_id.as_deref() {
        let Some(module) = evaluation.model().module(id) else {
            writeln!(error, "unknown declared Module `{id}`")?;
            return Ok(EXIT_USAGE);
        };
        vec![module]
    } else {
        evaluation.model().modules().iter().collect::<Vec<_>>()
    };
    if destination.is_some() && !json {
        writeln!(
            error,
            "semantic-conformance output files require `--format json`"
        )?;
        return Ok(EXIT_USAGE);
    }
    if json {
        let document = if module_id.is_some() {
            modules[0].to_canonical_json().map_err(io::Error::other)?
        } else {
            evaluation
                .model()
                .to_canonical_json()
                .map_err(io::Error::other)?
        };
        let exit_code = if evaluation.is_success() {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        };
        store_projection(cache.as_ref(), document.as_bytes(), exit_code);
        write_projection(destination, output, document.as_bytes())?;
        return Ok(exit_code);
    }
    for module in modules {
        writeln!(
            output,
            "Module {} policy={} result={:?} contract={}\n  Rule: {}",
            module.module(),
            module.policy_state(),
            module.state(),
            module.contract_path(),
            fortress_core::semantic_conformance::ARCH_SEMANTIC_RULE_ID,
        )?;
        for conclusion in module.conclusions() {
            writeln!(
                output,
                "  Policy: {:?} {} {:?}\n  Result: {:?} / {:?} (observations={})",
                conclusion.target_kind(),
                conclusion.target(),
                conclusion.disposition(),
                conclusion.state(),
                conclusion.blocking_eligibility(),
                conclusion.observation_count(),
            )?;
            for reason in conclusion.coverage_reasons() {
                writeln!(output, "    Coverage: {reason}")?;
            }
        }
        for observation in module.observations().iter().filter(|observation| {
            observation.policy_disposition()
                == Some(fortress_core::semantic_conformance::PolicyDisposition::Deny)
        }) {
            writeln!(
                output,
                "    {:?} effect={} capability={} operation={} source={}:{}:{} authority={} chain={}",
                observation.evidence_kind(),
                observation.effect().stable_id(),
                observation
                    .capability()
                    .map_or("none", |capability| capability.stable_id()),
                observation.operation(),
                observation.path(),
                observation.line(),
                observation.column(),
                observation.authority(),
                observation.call_chain().join(" -> "),
            )?;
        }
        if module.state() == fortress_core::semantic_conformance::SemanticConformanceState::Fail {
            writeln!(
                output,
                "  Remediation: remove or isolate the forbidden reachable operation, or explicitly revise the Module Contract policy after architectural review."
            )?;
        }
        if module.state() == fortress_core::semantic_conformance::SemanticConformanceState::Unknown
        {
            writeln!(
                output,
                "  Remediation: resolve the claim-relevant opaque operation; missing semantic authority is not conformance."
            )?;
        }
    }
    Ok(if evaluation.is_success() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn run_semantic<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_semantic_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let evaluation = match compile_repository_semantic_analysis(&root) {
        Ok(evaluation) => evaluation,
        Err(analysis_error) => {
            writeln!(error, "semantic analysis failed: {analysis_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = evaluation
        .model()
        .to_canonical_json()
        .map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(if evaluation.findings().is_empty() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn parse_semantic_arguments(
    arguments: &[String],
) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress semantic [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("semantic format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress semantic [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress semantic [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress semantic [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_psm<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_psm_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let cache = projection_cache(&root, ProjectionKind::Psm);
    if let Some((bytes, exit_code)) = cached_projection(cache.as_ref()) {
        write_projection(destination, output, &bytes)?;
        return Ok(exit_code);
    }
    let model = match cache.as_ref().map_or_else(
        || compile_repository_psm(&root),
        RepositoryProjectionCache::compile_psm,
    ) {
        Ok(model) => model,
        Err(model_error) => {
            writeln!(error, "PSM compilation failed: {model_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = model.to_canonical_json().map_err(io::Error::other)?;
    let exit_code =
        if model.analyzer_coherency().is_coherent() && model.coverage().invalid_calls() == 0 {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        };
    store_projection(cache.as_ref(), document.as_bytes(), exit_code);
    write_projection(destination, output, document.as_bytes())?;
    Ok(exit_code)
}

fn parse_psm_arguments(arguments: &[String]) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress psm [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("PSM format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress psm [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress psm [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress psm [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_bfg<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_bfg_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let graph = match compile_repository_bfg(&root) {
        Ok(graph) => graph,
        Err(graph_error) => {
            writeln!(error, "BFG compilation failed: {graph_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = graph.to_canonical_json().map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(if graph.violations().is_empty() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn parse_bfg_arguments(arguments: &[String]) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress bfg [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("BFG format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress bfg [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress bfg [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress bfg [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

fn run_ccg<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, destination) = match parse_ccg_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let graph = match compile_repository_ccg(&root) {
        Ok(graph) => graph,
        Err(graph_error) => {
            writeln!(error, "CCG compilation failed: {graph_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = graph.to_canonical_json().map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(
        if graph.coherency_status() == CcgCoherencyStatus::Coherent {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
}

fn parse_ccg_arguments(arguments: &[String]) -> Result<(PathBuf, Option<PathBuf>), &'static str> {
    let mut root = None;
    let mut destination = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            if arguments.get(index).map(String::as_str) != Some("json") {
                return Err("usage: fortress ccg [path] [--format json] [--output path]");
            }
        } else if let Some(value) = argument.strip_prefix("--format=") {
            if value != "json" {
                return Err("CCG format must be `json`");
            }
        } else if argument == "--output" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress ccg [path] [--format json] [--output path]");
            };
            if destination.replace(PathBuf::from(value)).is_some() {
                return Err("usage: fortress ccg [path] [--format json] [--output path]");
            }
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress ccg [path] [--format json] [--output path]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), destination))
}

#[derive(Clone, Copy)]
enum AuditFormat {
    Human,
    Json,
}

fn run_check<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, format) = match parse_audit_arguments(arguments) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let result = match audit_repository(&root) {
        Ok(result) => result,
        Err(audit_error) => {
            writeln!(error, "check failed: {audit_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    match format {
        AuditFormat::Human => write!(output, "{}", result.to_human())?,
        AuditFormat::Json => writeln!(
            output,
            "{}",
            result.to_json_pretty().map_err(io::Error::other)?
        )?,
    }
    Ok(if result.enforcement_success() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
}

fn run_findings<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run_check(arguments, output, error)
}

fn run_baseline<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress baseline create|prune [path]";
    let [operation, rest @ ..] = arguments else {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    };
    if !["create", "prune"].contains(&operation.as_str()) || rest.len() > 1 {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    }
    let root = rest
        .first()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let audit = match audit_repository(&root) {
        Ok(value) if value.is_governed() => value,
        Ok(_) => {
            writeln!(error, "baseline requires valid authored project governance")?;
            return Ok(EXIT_VIOLATION);
        }
        Err(audit_error) => {
            writeln!(error, "baseline evaluation failed: {audit_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let mut authority = match load_finding_governance(&root) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let mutation = if operation == "create" {
        authority.create_baseline(
            audit.standard_id(),
            audit.standard_edition(),
            audit.findings(),
        )
    } else {
        authority.prune_baseline(audit.findings())
    };
    let summary = match mutation {
        Ok(value) => value,
        Err(authority_error) => {
            writeln!(error, "baseline mutation failed: {authority_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    persist_finding_governance(&root, &authority)?;
    writeln!(
        output,
        "baseline {operation}: active={}, removed={}, ineligible={}",
        summary.active, summary.removed, summary.ineligible
    )?;
    Ok(EXIT_SUCCESS)
}

fn run_exceptions<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let Some(operation) = arguments.first().map(String::as_str) else {
        writeln!(error, "usage: fortress exceptions list|create|retire ...")?;
        return Ok(EXIT_USAGE);
    };
    match operation {
        "list" => {
            if arguments.len() > 2 {
                writeln!(error, "usage: fortress exceptions list [path]")?;
                return Ok(EXIT_USAGE);
            }
            let root = arguments
                .get(1)
                .map_or_else(|| PathBuf::from("."), PathBuf::from);
            let authority = match load_finding_governance(&root) {
                Ok(value) => value,
                Err(message) => {
                    writeln!(error, "{message}")?;
                    return Ok(EXIT_VIOLATION);
                }
            };
            write!(
                output,
                "{}",
                authority.to_canonical_json().map_err(io::Error::other)?
            )?;
            Ok(EXIT_SUCCESS)
        }
        "retire" => {
            if !(2..=3).contains(&arguments.len()) {
                writeln!(
                    error,
                    "usage: fortress exceptions retire <exception-id> [path]"
                )?;
                return Ok(EXIT_USAGE);
            }
            let root = arguments
                .get(2)
                .map_or_else(|| PathBuf::from("."), PathBuf::from);
            let mut authority = match load_finding_governance(&root) {
                Ok(value) => value,
                Err(message) => {
                    writeln!(error, "{message}")?;
                    return Ok(EXIT_VIOLATION);
                }
            };
            if let Err(authority_error) = authority.retire_exception(&arguments[1]) {
                writeln!(error, "exception retirement failed: {authority_error}")?;
                return Ok(EXIT_VIOLATION);
            }
            persist_finding_governance(&root, &authority)?;
            writeln!(output, "exception {} retired", arguments[1])?;
            Ok(EXIT_SUCCESS)
        }
        "create" => run_exception_create(&arguments[1..], output, error),
        _ => {
            writeln!(error, "usage: fortress exceptions list|create|retire ...")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_exception_create<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    const USAGE: &str = "usage: fortress exceptions create <exception-id> <finding-id> --authority <reference> --rationale <text> [path]";
    if arguments.len() < 6 {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    }
    let exception_id = &arguments[0];
    let finding_id = &arguments[1];
    let mut authority_reference = None;
    let mut rationale = None;
    let mut root = None;
    let mut index = 2;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--authority" | "--rationale" => {
                let flag = arguments[index].as_str();
                index += 1;
                let Some(value) = arguments.get(index) else {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                };
                let replaced = if flag == "--authority" {
                    authority_reference.replace(value.clone()).is_some()
                } else {
                    rationale.replace(value.clone()).is_some()
                };
                if replaced {
                    writeln!(error, "{USAGE}")?;
                    return Ok(EXIT_USAGE);
                }
            }
            value if !value.starts_with('-') && root.is_none() => root = Some(PathBuf::from(value)),
            _ => {
                writeln!(error, "{USAGE}")?;
                return Ok(EXIT_USAGE);
            }
        }
        index += 1;
    }
    let (Some(authority_reference), Some(rationale)) = (authority_reference, rationale) else {
        writeln!(error, "{USAGE}")?;
        return Ok(EXIT_USAGE);
    };
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    let audit = match audit_repository(&root) {
        Ok(value) if value.is_governed() => value,
        Ok(_) => {
            writeln!(
                error,
                "exception creation requires valid authored project governance"
            )?;
            return Ok(EXIT_VIOLATION);
        }
        Err(audit_error) => {
            writeln!(error, "exception evaluation failed: {audit_error}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    let mut authority = match load_finding_governance(&root) {
        Ok(value) => value,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_VIOLATION);
        }
    };
    if let Err(authority_error) = authority.create_exception(
        exception_id,
        finding_id,
        authority_reference,
        rationale,
        audit.findings(),
    ) {
        writeln!(error, "exception creation failed: {authority_error}")?;
        return Ok(EXIT_VIOLATION);
    }
    persist_finding_governance(&root, &authority)?;
    writeln!(output, "exception {exception_id} created for {finding_id}")?;
    Ok(EXIT_SUCCESS)
}

fn load_finding_governance(root: &std::path::Path) -> Result<FindingGovernanceDocument, String> {
    let path = root.join(FINDING_GOVERNANCE_PATH);
    match fs::read_to_string(&path) {
        Ok(source) => FindingGovernanceDocument::from_json_str(&source)
            .map_err(|error| format!("finding governance is invalid: {error}")),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Ok(FindingGovernanceDocument::empty())
        }
        Err(source) => Err(format!("failed to read {}: {source}", path.display())),
    }
}

fn persist_finding_governance(
    root: &std::path::Path,
    authority: &FindingGovernanceDocument,
) -> io::Result<()> {
    let path = root.join(FINDING_GOVERNANCE_PATH);
    fs::write(
        path,
        authority.to_canonical_json().map_err(io::Error::other)?,
    )
}

fn run_audit<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (root, format) = match parse_audit_arguments(arguments) {
        Ok(parsed) => parsed,
        Err(message) => {
            writeln!(error, "{message}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let cache = matches!(format, AuditFormat::Json)
        .then(|| projection_cache(&root, ProjectionKind::Audit))
        .flatten();
    if let Some((bytes, exit_code)) = cached_projection(cache.as_ref()) {
        output.write_all(&bytes)?;
        return Ok(exit_code);
    }
    let result: fortress_core::audit::AuditResult = match cache
        .as_ref()
        .map_or_else(|| audit_repository(&root), RepositoryProjectionCache::audit)
    {
        Ok(result) => result,
        Err(audit_error) => {
            writeln!(error, "audit failed: {audit_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let exit_code = if result.is_success() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    };
    match format {
        AuditFormat::Human => write!(output, "{}", result.to_human())?,
        AuditFormat::Json => {
            let mut bytes = result
                .to_json_pretty()
                .map_err(io::Error::other)?
                .into_bytes();
            bytes.push(b'\n');
            store_projection(cache.as_ref(), &bytes, exit_code);
            output.write_all(&bytes)?;
        }
    }
    Ok(exit_code)
}

fn parse_audit_arguments(arguments: &[String]) -> Result<(PathBuf, AuditFormat), &'static str> {
    let mut root = None;
    let mut format = AuditFormat::Human;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err("usage: fortress audit [path] [--format human|json]");
            };
            format = parse_audit_format(value)?;
        } else if let Some(value) = argument.strip_prefix("--format=") {
            format = parse_audit_format(value)?;
        } else if argument.starts_with('-') || root.is_some() {
            return Err("usage: fortress audit [path] [--format human|json]");
        } else {
            root = Some(PathBuf::from(argument));
        }
        index += 1;
    }
    Ok((root.unwrap_or_else(|| PathBuf::from(".")), format))
}

fn parse_audit_format(value: &str) -> Result<AuditFormat, &'static str> {
    match value {
        "human" => Ok(AuditFormat::Human),
        "json" => Ok(AuditFormat::Json),
        _ => Err("audit format must be `human` or `json`"),
    }
}

fn run_help<O: Write, E: Write>(
    registry: &CommandRegistry,
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match arguments {
        [] => {
            render_top_level_help(registry, output)?;
            Ok(EXIT_SUCCESS)
        }
        [name] => {
            if let Some(command) = registry.find(name) {
                render_command_help(command, output)?;
                Ok(EXIT_SUCCESS)
            } else {
                writeln!(error, "no implemented command named `{name}`")?;
                Ok(EXIT_USAGE)
            }
        }
        _ => {
            writeln!(error, "usage: fortress help [command]")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_version<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    if arguments.is_empty() {
        writeln!(output, "fortress {}", env!("CARGO_PKG_VERSION"))?;
        Ok(EXIT_SUCCESS)
    } else {
        writeln!(error, "usage: fortress --version")?;
        Ok(EXIT_USAGE)
    }
}

fn render_top_level_help<O: Write>(registry: &CommandRegistry, output: &mut O) -> io::Result<()> {
    writeln!(output, "Fortress {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(
        output,
        "Engineering control plane for coherent, auditable software systems."
    )?;
    writeln!(output)?;
    writeln!(output, "USAGE:")?;
    writeln!(output, "    fortress <command>")?;
    writeln!(output, "    fortress --version")?;
    writeln!(output)?;
    writeln!(output, "IMPLEMENTED COMMANDS:")?;
    for command in registry.commands() {
        writeln!(
            output,
            "    {:<10} {}",
            command.name(),
            command.description()
        )?;
    }
    writeln!(output)?;
    writeln!(
        output,
        "Only listed commands are implemented. No certification claim is made."
    )
}

fn render_command_help<O: Write>(command: &CommandDescriptor, output: &mut O) -> io::Result<()> {
    writeln!(output, "{} — {}", command.name(), command.description())?;
    writeln!(output)?;
    writeln!(output, "USAGE:")?;
    writeln!(output, "    {}", command.usage())?;
    if !command.aliases().is_empty() {
        writeln!(output)?;
        writeln!(output, "ALIASES:")?;
        writeln!(output, "    {}", command.aliases().join(", "))?;
    }
    Ok(())
}
