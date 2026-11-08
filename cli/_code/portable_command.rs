//! Explicit export and independent offline verification adapters.

use fortress_core::portable::{PortableError, canonical, failure, parse};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Immutable reviewed public-consumer bytes, never a candidate repository script.
// This consumer contains neither expected answers nor internal Rust types.
const VERIFIER: &str = include_str!("../_data/offline_verifier_v1.txt");
type Options = BTreeMap<String, String>;
type LoadedArtifacts = (Option<String>, BTreeMap<String, Vec<u8>>);

pub(super) fn run<O: Write, E: Write>(
    name: &str,
    args: &[String],
    out: &mut O,
    err: &mut E,
) -> io::Result<u8> {
    match execute(name, args) {
        Ok((value, human, exit)) => {
            if human {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&value).map_err(io::Error::other)?
                )?;
            } else {
                out.write_all(&canonical(&value).map_err(io::Error::other)?)?;
                writeln!(out)?;
            }
            Ok(exit)
        }
        Err(error) => {
            out.write_all(
                &canonical(&json!({"schema_version":1,"error":error})).map_err(io::Error::other)?,
            )?;
            writeln!(out)?;
            writeln!(err, "portable operation failed: {error}")?;
            Ok(crate::EXIT_USAGE)
        }
    }
}

fn execute(name: &str, args: &[String]) -> Result<(Value, bool, u8), PortableError> {
    let (operation, args) = if name == "sarif" {
        ("sarif", args)
    } else {
        (
            args.first()
                .map(String::as_str)
                .ok_or_else(|| failure("INVALID_PARAMETERS", "bundle export|verify required"))?,
            &args[1..],
        )
    };
    let (paths, options) = options(args)?;
    if paths.len() > 1 || (operation == "verify" && paths.is_empty()) {
        return Err(failure(
            "INVALID_PARAMETERS",
            "verify requires one bundle; other commands allow one repository path",
        ));
    }
    let path = PathBuf::from(paths.first().map_or(".", String::as_str));
    let human = match options.get("--format").map_or("json", String::as_str) {
        "json" => false,
        "human" => true,
        _ => {
            return Err(failure(
                "INVALID_PARAMETERS",
                "format must be human or json",
            ));
        }
    };
    let (value, exit) = match operation {
        "verify" => verify(&path, &options)?,
        "export" => export(&path, &options)?,
        "sarif" => sarif(&path, &options)?,
        _ => return Err(failure("INVALID_PARAMETERS", "unknown portable operation")),
    };
    Ok((value, human, exit))
}

fn allowed(options: &Options, names: &[&str]) -> Result<(), PortableError> {
    if options.keys().any(|key| !names.contains(&key.as_str())) {
        return Err(failure("INVALID_PARAMETERS", "unsupported option"));
    }
    Ok(())
}

fn verify(path: &Path, options: &Options) -> Result<(Value, u8), PortableError> {
    allowed(
        options,
        &[
            "--format",
            "--predicate-type",
            "--current-state",
            "--expected-subject",
            "--expected-context",
            "--expected-authority",
            "--expected-profile",
        ],
    )?;
    let predicate = options
        .get("--predicate-type")
        .ok_or_else(|| failure("INVALID_PARAMETERS", "--predicate-type is required"))?;
    let mut command = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" });
    command
        .args(["-I", "-B", "-"])
        .arg(path)
        .args(["--predicate-type", predicate]);
    for part in [
        "--current-state",
        "--expected-subject",
        "--expected-context",
        "--expected-authority",
        "--expected-profile",
    ] {
        if let Some(value) = options.get(part) {
            command.args([part, value]);
        }
    }
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| failure("VERIFIER_UNAVAILABLE", e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| failure("VERIFIER_UNAVAILABLE", "verifier input unavailable"))?
        .write_all(VERIFIER.as_bytes())
        .map_err(|e| failure("VERIFIER_UNAVAILABLE", e.to_string()))?;
    let result = child
        .wait_with_output()
        .map_err(|e| failure("VERIFIER_UNAVAILABLE", e.to_string()))?;
    if result.stdout.is_empty() {
        return Err(failure(
            "VERIFIER_FAILURE",
            String::from_utf8_lossy(&result.stderr)
                .chars()
                .take(1024)
                .collect::<String>(),
        ));
    }
    Ok((
        parse(&result.stdout)?,
        u8::try_from(result.status.code().unwrap_or(2)).unwrap_or(2),
    ))
}

fn load(root: &Path, options: &Options) -> Result<LoadedArtifacts, PortableError> {
    if let Some(state) = options.get("--state") {
        if options.contains_key("--generation") || options.contains_key("--selection") {
            return Err(failure(
                "INVALID_PARAMETERS",
                "state, generation and selection are exclusive",
            ));
        }
        return Ok((
            None,
            fortress_core::portable_load::load_portable_state(root, &PathBuf::from(state))?,
        ));
    }
    let (generation, artifacts) = fortress_core::portable_load::load_portable_artifacts(
        root,
        options.get("--generation").map(String::as_str),
        options.get("--selection").map(String::as_str),
    )?;
    Ok((Some(generation), artifacts))
}

fn export(root: &Path, options: &Options) -> Result<(Value, u8), PortableError> {
    allowed(
        options,
        &[
            "--format",
            "--predicate-type",
            "--generation",
            "--selection",
            "--state",
            "--output",
        ],
    )?;
    let predicate = options
        .get("--predicate-type")
        .ok_or_else(|| failure("INVALID_PARAMETERS", "--predicate-type is required"))?;
    let destination = options
        .get("--output")
        .ok_or_else(|| failure("INVALID_PARAMETERS", "--output must name a new directory"))?;
    let (generation, artifacts) = load(root, options)?;
    let bundle = fortress_core::bundle::PortableBundle::assemble(artifacts, generation, predicate)?;
    fortress_core::portable_load::write_portable_bundle(&bundle, &PathBuf::from(destination))?;
    Ok((
        json!({"schema_version":1,"manifest":bundle.manifest,"authenticity":"UNVERIFIED"}),
        0,
    ))
}

fn sarif(root: &Path, options: &Options) -> Result<(Value, u8), PortableError> {
    allowed(
        options,
        &[
            "--format",
            "--generation",
            "--selection",
            "--state",
            "--output",
            "--audit",
            "--declaration",
            "--authority",
        ],
    )?;
    let value = if let Some(audit) = options.get("--audit") {
        if ["--state", "--generation", "--selection"]
            .iter()
            .any(|key| options.contains_key(*key))
        {
            return Err(failure(
                "INVALID_PARAMETERS",
                "explicit audit and retained state selection are exclusive",
            ));
        }
        let audit = fortress_core::portable_load::load_portable_json(root, &PathBuf::from(audit))?;
        let report = |key| {
            options
                .get(key)
                .map(|p| fortress_core::portable_load::load_portable_json(root, &PathBuf::from(p)))
                .transpose()
        };
        let declaration = report("--declaration")?;
        let authority = report("--authority")?;
        crate::sarif::export(
            &audit,
            declaration.as_ref().unwrap_or(&Value::Null),
            authority.as_ref(),
        )?
    } else {
        if options.contains_key("--declaration") || options.contains_key("--authority") {
            return Err(failure(
                "INVALID_PARAMETERS",
                "declaration/authority reports require an explicit audit",
            ));
        }
        let (_, artifacts) = load(root, options)?;
        sarif_from_artifacts(&artifacts)?
    };
    if let Some(destination) = options.get("--output") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|e| failure("IO_ERROR", e.to_string()))?;
        file.write_all(&canonical(&value)?)
            .map_err(|e| failure("IO_ERROR", e.to_string()))?;
    }
    Ok((value, 0))
}

fn sarif_from_artifacts(artifacts: &BTreeMap<String, Vec<u8>>) -> Result<Value, PortableError> {
    let graph = parse(
        artifacts
            .get("evidence-graph")
            .ok_or_else(|| failure("MISSING_ARTIFACT", "evidence-graph"))?,
    )?;
    let replays = graph["nodes"]
        .as_array()
        .ok_or_else(|| failure("INVALID_GRAPH", "nodes missing"))?
        .iter()
        .filter(|n| n["kind"] == "assessment_replay")
        .collect::<Vec<_>>();
    let [replay] = replays.as_slice() else {
        return Err(failure(
            "UNAVAILABLE",
            "historical generation lacks retained normalized audit; no analysis was initiated",
        ));
    };
    let declaration = parse(
        artifacts
            .get("conformance-declaration")
            .ok_or_else(|| failure("MISSING_ARTIFACT", "conformance-declaration"))?,
    )?;
    crate::sarif::export(
        &replay["payload"]["audit"],
        &declaration,
        Some(&replay["payload"]["authority"]),
    )
}

fn options(args: &[String]) -> Result<(Vec<String>, Options), PortableError> {
    let mut paths = Vec::new();
    let mut options = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            let value = args
                .get(i + 1)
                .filter(|s| !s.starts_with("--"))
                .ok_or_else(|| failure("INVALID_PARAMETERS", "option requires a value"))?;
            if options.insert(args[i].clone(), value.clone()).is_some() {
                return Err(failure("INVALID_PARAMETERS", "duplicate option"));
            }
            i += 2;
        } else {
            paths.push(args[i].clone());
            i += 1;
        }
    }
    Ok((paths, options))
}
