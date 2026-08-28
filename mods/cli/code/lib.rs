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

use fortress_core::audit::{
    audit_repository, compile_repository_bfg, compile_repository_ccg,
    compile_repository_certification, compile_repository_environmental_analysis,
    compile_repository_information_flow_analysis, compile_repository_psm,
    compile_repository_realized_bfg, compile_repository_semantic_analysis,
    compile_repository_state_effect_analysis, prepare_repository_certification_source,
};
use fortress_core::certification::{CertificationStatus, RustSuiteExecution};
use fortress_core::contract_coherency::CcgCoherencyStatus;
pub mod command;

use command::{CommandDescriptor, CommandRegistry};

/// Successful process exit status.
pub const EXIT_SUCCESS: u8 = 0;
/// Evaluated mandatory snapshot rule violation exit status.
pub const EXIT_VIOLATION: u8 = 1;
/// User invocation or unsupported-command exit status.
pub const EXIT_USAGE: u8 = 2;

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
        "CMD-CONTRACT-CCG" => run_ccg(&arguments[1..], output, error),
        "CMD-BEHAVIOR-BFG" => run_bfg(&arguments[1..], output, error),
        "CMD-BEHAVIOR-REALIZED-BFG" => run_realized_bfg(&arguments[1..], output, error),
        "CMD-PROGRAM-PSM" => run_psm(&arguments[1..], output, error),
        "CMD-SEMANTIC-ANALYSIS" => run_semantic(&arguments[1..], output, error),
        "CMD-STATE-EFFECT-ANALYSIS" => run_state_effect(&arguments[1..], output, error),
        "CMD-INFORMATION-FLOW" => run_information_flow(&arguments[1..], output, error),
        "CMD-ENVIRONMENTAL-ANALYSIS" => run_environmental(&arguments[1..], output, error),
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
    let products = match compile_repository_certification(
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
    writeln!(
        error,
        "[fortress-certify] executing canonical local Rust suite"
    )?;
    let status = Command::new(cargo)
        .current_dir(root)
        .env("RUSTUP_TOOLCHAIN", "1.97.1")
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
    const USAGE: &str = "usage: fortress certify [path] [--format human|json] [--evidence-output path] [--certification-output path] [--verified-bfg-output path]";
    let mut root = None;
    let mut format = CertificationOutputFormat::Human;
    let mut evidence_output = None;
    let mut certification_output = None;
    let mut verified_bfg_output = None;
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
                _ => &mut verified_bfg_output,
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
    let evaluation = match compile_repository_state_effect_analysis(&root) {
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
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(
        if evaluation.state_findings().is_empty() && evaluation.effect_findings().is_empty() {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
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
    let model = match compile_repository_psm(&root) {
        Ok(model) => model,
        Err(model_error) => {
            writeln!(error, "PSM compilation failed: {model_error}")?;
            return Ok(EXIT_USAGE);
        }
    };
    let document = model.to_canonical_json().map_err(io::Error::other)?;
    if let Some(destination) = destination {
        fs::write(destination, document)?;
    } else {
        write!(output, "{document}")?;
    }
    Ok(
        if model.analyzer_coherency().is_coherent() && model.coverage().invalid_calls() == 0 {
            EXIT_SUCCESS
        } else {
            EXIT_VIOLATION
        },
    )
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
    let result: fortress_core::audit::AuditResult = match audit_repository(&root) {
        Ok(result) => result,
        Err(audit_error) => {
            writeln!(error, "audit failed: {audit_error}")?;
            return Ok(EXIT_USAGE);
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
    Ok(if result.is_success() {
        EXIT_SUCCESS
    } else {
        EXIT_VIOLATION
    })
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
