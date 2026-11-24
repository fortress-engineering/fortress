//! Explicit host activation for the compile-only Python lexical worker.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fortress_core::portable::{canonical, digest};
use fortress_core::python_observation::{
    PYTHON_LEXICAL_WORKER, PythonGrammar, PythonImportScope, PythonLexicalMode,
    PythonLexicalProducer, PythonLexicalRequest, PythonObservationError, observe_python_lexical,
    observe_python_static_dependencies, observe_python_static_imports, observe_python_tests,
};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_public_json, readable_text};
use serde::Deserialize;
use serde_json::{Value, json};

const USAGE: &str = concat!(
    "fortress source-artifacts --observe-python project host-registration source-path lexical|syntax",
    "\n       fortress source-artifacts --observe-python project host-registration source-path imports|dependencies root-scope root-scope-sha256",
);
const REGISTRATION_SCHEMA: &str = "urn:fortress:host:v1:python-lexical-registration";
const OBSERVATION_SCHEMA: &str = "urn:fortress:derived:v1:python-lexical-observation";
const REQUEST_SCHEMA: &str = "fortress-research/python-lexical-request/1";
const READY_SCHEMA: &str = "fortress-host/python-lexical-ready/1";
const REGISTRATION_LIMIT: usize = 16 * 1024;
const IMPORT_SCOPE_LIMIT: usize = 8192;
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
pub(super) enum Grammar {
    #[serde(rename = "cpython3.12")]
    Cpython312,
    #[serde(rename = "cpython3.13")]
    Cpython313,
}

impl Grammar {
    pub(super) const fn wire_name(self) -> &'static str {
        match self {
            Self::Cpython312 => "cpython3.12",
            Self::Cpython313 => "cpython3.13",
        }
    }
}

impl From<Grammar> for PythonGrammar {
    fn from(grammar: Grammar) -> Self {
        match grammar {
            Grammar::Cpython312 => Self::Cpython312,
            Grammar::Cpython313 => Self::Cpython313,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    interpreter: PathBuf,
    interpreter_sha256: String,
    worker: PathBuf,
    runtime_ref: String,
    grammar: Grammar,
}

impl Registration {
    fn load(root: &Path, path: &Path) -> Result<(Self, Vec<u8>), String> {
        super::verifier_process::require_external_asset(path, root)?;
        let bytes = super::provider_command::read_bounded(path, REGISTRATION_LIMIT)?;
        admit_json(
            &bytes,
            JsonAdmissionLimits {
                bytes: REGISTRATION_LIMIT,
                depth: 4,
                nodes: 32,
                token_bytes: 4096,
            },
        )
        .map_err(|error| error.to_string())?;
        let document: Self =
            parse_public_json(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if document.schema != REGISTRATION_SCHEMA || document.schema_version != 1 {
            return Err("UNSUPPORTED_PYTHON_WORKER_REGISTRATION".into());
        }
        super::verifier_process::require_external_asset(&document.interpreter, root)?;
        document.revalidate_worker(root)?;
        Ok((document, bytes))
    }

    fn revalidate_worker(&self, root: &Path) -> Result<(), String> {
        super::verifier_process::require_external_asset(&self.worker, root)?;
        let worker =
            super::provider_command::read_bounded(&self.worker, PYTHON_LEXICAL_WORKER.len())?;
        if worker == PYTHON_LEXICAL_WORKER {
            return Ok(());
        }
        Err("PYTHON_WORKER_IDENTITY_MISMATCH".into())
    }

    fn command(&self, host_directory: &Path, worker_ref: &str) -> Command {
        let mut command = Command::new(&self.interpreter);
        command
            .env_clear()
            .current_dir(host_directory)
            .args(["-I", "-S", "-B"])
            .arg(&self.worker)
            .args([
                "--serve",
                "--worker-ref",
                worker_ref,
                "--runtime-ref",
                &self.runtime_ref,
            ]);
        #[cfg(windows)]
        if let Some(value) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", value);
        }
        command
    }
}

fn readiness(
    grammar: Grammar,
    runtime_ref: &str,
    worker_ref: &str,
) -> Result<(Vec<u8>, &'static str), String> {
    let (profile, limits) = resource_profile()?;
    let mut ready_frame = encode(&json!({
        "schema": READY_SCHEMA,
        "status": "READY",
        "worker_ref": worker_ref,
        "runtime_ref": runtime_ref,
        "grammar": grammar.wire_name(),
        "profile": profile,
        "limits": limits,
    }))?;
    ready_frame.push(b'\n');
    Ok((ready_frame, profile))
}

pub(super) fn resource_profile() -> Result<(&'static str, Value), String> {
    let limits = match std::env::consts::OS {
        "linux" => (
            "LINUX_AS_CPU_V1",
            json!({"address_space_bytes":100_663_296,"cpu_seconds":1,"core_bytes":0}),
        ),
        "windows" => (
            "WINDOWS_JOB_WALL_V1",
            json!({"commit_bytes":100_663_296,"active_processes":1,"kill_on_close":true}),
        ),
        _ => return Err("PYTHON_WORKER_RESOURCE_PROFILE_UNAVAILABLE".into()),
    };
    Ok(limits)
}

fn encode(value: &Value) -> Result<Vec<u8>, String> {
    canonical(value).map_err(|error| error.to_string())
}

fn one_request(
    command: Command,
    registration: &Registration,
    ready_frame: Vec<u8>,
    request: &PythonLexicalRequest,
    source: &[u8],
    mode: &str,
) -> Result<Vec<u8>, PythonObservationError> {
    let payload = canonical(&json!({
        "schema": REQUEST_SCHEMA,
        "id": request.id(),
        "source_ref": request.source_ref(),
        "byte_count": source.len(),
        "mode": mode,
        "source": STANDARD.encode(source),
        "worker_ref": request.worker_ref(),
        "runtime_ref": request.runtime_ref(),
    }))
    .map_err(|_| PythonObservationError::HostUnavailable)?;
    let (output, status) = super::verifier_process::run_pinned_input_after_ready(
        command,
        payload,
        DEADLINE,
        &registration.interpreter_sha256,
        ready_frame,
    )
    .map_err(|_| PythonObservationError::HostUnavailable)?;
    if status == 0 {
        Ok(output)
    } else {
        Err(PythonObservationError::HostUnavailable)
    }
}

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match collect(arguments) {
        Ok(bytes) => {
            super::write_projection(None, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            let mode = match arguments.get(3).map(String::as_str) {
                Some("imports") => "static import",
                Some("dependencies") => "static dependency",
                _ => "lexical",
            };
            writeln!(
                error,
                "Python {mode} observation failed: {}",
                readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

pub(super) fn run_tests<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match collect_tests(arguments) {
        Ok(bytes) => {
            super::write_projection(None, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "Python test declaration observation failed: {}",
                readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn collect_tests(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [root, registration_path, roots @ ..] = arguments else {
        return Err("usage: fortress source-artifacts --observe-python-tests project host-registration test-root [test-root ...]".into());
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration_path = Path::new(registration_path);
    let roots = roots.iter().map(String::as_str).collect::<Vec<_>>();
    let (registration, registration_bytes) = Registration::load(&root, registration_path)?;
    let worker_ref = digest(PYTHON_LEXICAL_WORKER);
    let producer = PythonLexicalProducer::new(
        registration.grammar.into(),
        &registration.runtime_ref,
        &worker_ref,
    )
    .map_err(|error| error.to_string())?;
    let (ready_frame, _) = readiness(registration.grammar, &registration.runtime_ref, &worker_ref)?;
    let host_root = registration_path
        .parent()
        .ok_or("Missing trusted registration parent")?;
    let result = observe_python_tests(&root, &roots, &producer, |request, source| {
        registration
            .revalidate_worker(&root)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        verify_external_input(
            &root,
            registration_path,
            REGISTRATION_LIMIT,
            &registration_bytes,
        )?;
        one_request(
            registration.command(host_root, &worker_ref),
            &registration,
            ready_frame.clone(),
            request,
            source,
            "LEXICAL",
        )
    })
    .map_err(|error| error.to_string())?;
    registration.revalidate_worker(&root)?;
    verify_external_input(
        &root,
        registration_path,
        REGISTRATION_LIMIT,
        &registration_bytes,
    )
    .map_err(|error| error.to_string())?;
    let projection = serde_json::to_value(result).map_err(|error| error.to_string())?;
    encode(&projection)
}

fn collect(arguments: &[String]) -> Result<Vec<u8>, String> {
    if let [root, registration, source, mode, scope, scope_ref] = arguments
        && matches!(mode.as_str(), "imports" | "dependencies")
    {
        return collect_imports(
            root,
            registration,
            source,
            scope,
            scope_ref,
            mode == "dependencies",
        );
    }
    let [root, registration_path, source_path, mode] = arguments else {
        return Err(format!("usage: {USAGE}"));
    };
    let (mode, wire_mode) = match mode.as_str() {
        "lexical" => (PythonLexicalMode::Lexical, "LEXICAL"),
        "syntax" => (PythonLexicalMode::Syntax, "SYNTAX"),
        _ => return Err(format!("usage: {USAGE}")),
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration_path = Path::new(registration_path);
    let (registration, registration_bytes) = Registration::load(&root, registration_path)?;
    let worker_ref = digest(PYTHON_LEXICAL_WORKER);
    let producer = PythonLexicalProducer::new(
        registration.grammar.into(),
        &registration.runtime_ref,
        &worker_ref,
    )
    .map_err(|error| error.to_string())?;
    let (ready_frame, profile) =
        readiness(registration.grammar, &registration.runtime_ref, &worker_ref)?;
    let host_root = registration_path
        .parent()
        .ok_or("Missing trusted registration parent")?;
    let command = registration.command(host_root, &worker_ref);
    let result = observe_python_lexical(&root, source_path, mode, &producer, |request, source| {
        one_request(
            command,
            &registration,
            ready_frame,
            request,
            source,
            wire_mode,
        )
    })
    .map_err(|error| error.to_string())?;
    registration.revalidate_worker(&root)?;
    super::verifier_process::require_external_asset(registration_path, &root)?;
    if super::provider_command::read_bounded(registration_path, REGISTRATION_LIMIT)?
        != registration_bytes
    {
        return Err("PYTHON_WORKER_REGISTRATION_CHANGED".into());
    }
    let observation =
        serde_json::to_value(result.observation()).map_err(|error| error.to_string())?;
    encode(&json!({
        "$schema": OBSERVATION_SCHEMA,
        "schema_version": 1,
        "evaluation": result.evaluation_key(),
        "registration_ref": digest(&registration_bytes),
        "interpreter_ref": registration.interpreter_sha256,
        "resource_profile": profile,
        "worker_timeout_ms": DEADLINE.as_millis(),
        "observation": observation,
    }))
}

fn collect_imports(
    root: &str,
    registration_path: &str,
    source_path: &str,
    scope_path: &str,
    scope_ref: &str,
    with_dependencies: bool,
) -> Result<Vec<u8>, String> {
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration_path = Path::new(registration_path);
    let scope_path = Path::new(scope_path);
    let (scope, scope_bytes) = load_import_scope(&root, scope_path, scope_ref)?;
    let (registration, registration_bytes) = Registration::load(&root, registration_path)?;
    let worker_ref = digest(PYTHON_LEXICAL_WORKER);
    let producer = PythonLexicalProducer::new(
        registration.grammar.into(),
        &registration.runtime_ref,
        &worker_ref,
    )
    .map_err(|error| error.to_string())?;
    let (ready_frame, profile) =
        readiness(registration.grammar, &registration.runtime_ref, &worker_ref)?;
    let host_root = registration_path
        .parent()
        .ok_or("Missing trusted registration parent")?;
    let command = registration.command(host_root, &worker_ref);
    let receive = |request: &PythonLexicalRequest, source: &[u8]| {
        let output = one_request(
            command,
            &registration,
            ready_frame,
            request,
            source,
            "LEXICAL",
        )?;
        registration
            .revalidate_worker(&root)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        verify_external_input(
            &root,
            registration_path,
            REGISTRATION_LIMIT,
            &registration_bytes,
        )?;
        verify_import_scope(&root, scope_path, &scope_bytes)?;
        Ok(output)
    };
    if !with_dependencies {
        let report = observe_python_static_imports(&root, source_path, &producer, &scope, receive)
            .map_err(|error| error.to_string())?;
        return encode(&static_import_report(
            &report,
            &registration,
            &registration_bytes,
            &scope,
            profile,
        ));
    }
    let dependency_report =
        observe_python_static_dependencies(&root, source_path, &producer, &scope, receive)
            .map_err(|error| error.to_string())?;
    // The static dependency projection can take longer than the existing
    // import-only lookup. Recheck distinct host inputs before publishing it.
    registration.revalidate_worker(&root)?;
    verify_external_input(
        &root,
        registration_path,
        REGISTRATION_LIMIT,
        &registration_bytes,
    )
    .map_err(|error| error.to_string())?;
    verify_import_scope(&root, scope_path, &scope_bytes).map_err(|error| error.to_string())?;
    encode(&json!({
        "$schema": "urn:fortress:derived:v1:python-static-dependency-observation",
        "schema_version": 1,
        "static_imports": static_import_report(dependency_report.imports(), &registration, &registration_bytes, &scope, profile),
        "dependencies": dependency_report.dependencies(),
    }))
}

fn static_import_report(
    result: &fortress_core::python_observation::ActualPythonStaticImportObservation,
    registration: &Registration,
    registration_bytes: &[u8],
    scope: &PythonImportScope,
    profile: &str,
) -> Value {
    json!({
        "$schema": "urn:fortress:derived:v1:python-static-import-observation",
        "schema_version": 1,
        "evaluation": result.evaluation_key(),
        "registration_ref": digest(registration_bytes),
        "interpreter_ref": registration.interpreter_sha256,
        "root_scope_ref": scope.scope_ref(),
        "resource_profile": profile,
        "worker_timeout_ms": DEADLINE.as_millis(),
        "lexical": result.lexical(),
        "imports": result.outcome(),
        "scope": {
            "runtime_imports": "UNRESOLVED",
            "execution": "NOT_RUN",
            "authority": "OBSERVATION_ONLY",
        },
    })
}

pub(super) fn load_import_scope(
    root: &Path,
    path: &Path,
    scope_ref: &str,
) -> Result<(PythonImportScope, Vec<u8>), String> {
    super::verifier_process::require_external_asset(path, root)?;
    let bytes = super::provider_command::read_bounded(path, IMPORT_SCOPE_LIMIT)?;
    let scope = PythonImportScope::admit(&bytes, scope_ref).map_err(|error| error.to_string())?;
    Ok((scope, bytes))
}

pub(super) fn verify_import_scope(
    root: &Path,
    path: &Path,
    expected: &[u8],
) -> Result<(), PythonObservationError> {
    verify_external_input(root, path, IMPORT_SCOPE_LIMIT, expected)
}

fn verify_external_input(
    root: &Path,
    path: &Path,
    maximum: usize,
    expected: &[u8],
) -> Result<(), PythonObservationError> {
    super::verifier_process::require_external_asset(path, root)
        .map_err(|_| PythonObservationError::HostUnavailable)?;
    let current = super::provider_command::read_bounded(path, maximum)
        .map_err(|_| PythonObservationError::HostUnavailable)?;
    if current != expected {
        return Err(PythonObservationError::HostUnavailable);
    }
    Ok(())
}
