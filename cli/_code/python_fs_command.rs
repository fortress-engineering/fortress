//! Explicit local host for a conditional Python filesystem observation.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::portable::{canonical, digest};
use fortress_core::python_observation::{
    PYTHON_FILESYSTEM_WORKER, PYTHON_LEXICAL_WORKER, PYTHON_ORIGIN_WORKER, PythonFilesystemHost,
    PythonFilesystemProfile, PythonObservationError, PythonScalarProducer, PythonScalarSubject,
    observe_hypothetical_python_filesystem, observe_hypothetical_python_filesystem_policy,
};
use fortress_core::wire::{
    JsonAdmissionLimits, admit_json, parse_strict_json_bytes, readable_text,
};
use serde::Deserialize;
use serde_json::json;

use super::provider_command::read_bounded;
use super::python_observe_command::{load_import_scope, verify_import_scope};
use super::verifier_process::{require_external_asset, run_pinned, run_pinned_input_after_ready};

const REGISTRATION_SCHEMA: &str = "urn:fortress:host:v1:python-filesystem-registration";
const REGISTRATION_LIMIT: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
const MODELS: &str = "ISOLATED_CLOSED_REFERENCE_V1";
const USAGE: &str = "fortress source-artifacts --observe-python-filesystem PROJECT REGISTRATION ROOT_SCOPE ROOT_SCOPE_SHA256 [--policy]";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    interpreter: PathBuf,
    interpreter_sha256: String,
    worker: PathBuf,
    bootstrap: PathBuf,
    origin_worker: PathBuf,
    runtime_ref: String,
    model: String,
    subject: PythonScalarSubject,
}

impl Registration {
    fn load(path: &Path, root: &Path) -> Result<(Self, Vec<u8>), String> {
        require_external_asset(path, root)?;
        let raw = read_bounded(path, REGISTRATION_LIMIT)?;
        admit_json(
            &raw,
            JsonAdmissionLimits {
                bytes: REGISTRATION_LIMIT,
                depth: 5,
                nodes: 64,
                token_bytes: 4096,
            },
        )
        .map_err(|failure| failure.to_string())?;
        let config: Self = parse_strict_json_bytes(&raw).map_err(|failure| failure.to_string())?;
        if config.schema != REGISTRATION_SCHEMA
            || config.schema_version != 1
            || config.model != MODELS
        {
            return Err("UNSUPPORTED_PYTHON_FILESYSTEM_CONTEXT".into());
        }
        config.verify_files(root)?;
        Ok((config, raw))
    }

    fn verify_files(&self, root: &Path) -> Result<(), String> {
        require_external_asset(&self.interpreter, root)?;
        if self.worker.file_name().and_then(|name| name.to_str())
            != Some("python_filesystem_worker.py")
            || self.bootstrap != self.worker.with_file_name("python_lexical_worker.py")
            || self.origin_worker != self.worker.with_file_name("python_origin_worker.py")
        {
            return Err("PYTHON_FILESYSTEM_WORKER_SIBLING_MISMATCH".into());
        }
        for (path, bytes) in [
            (&self.worker, PYTHON_FILESYSTEM_WORKER),
            (&self.bootstrap, PYTHON_LEXICAL_WORKER),
            (&self.origin_worker, PYTHON_ORIGIN_WORKER),
        ] {
            require_external_asset(path, root)?;
            if read_bounded(path, bytes.len())? != bytes {
                return Err("PYTHON_FILESYSTEM_WORKER_BYTES_MISMATCH".into());
            }
        }
        Ok(())
    }

    fn revalidate(
        &self,
        root: &Path,
        path: &Path,
        raw: &[u8],
    ) -> Result<(), PythonObservationError> {
        require_external_asset(path, root).map_err(|_| PythonObservationError::HostUnavailable)?;
        if read_bounded(path, REGISTRATION_LIMIT)
            .map_err(|_| PythonObservationError::HostUnavailable)?
            != raw
        {
            return Err(PythonObservationError::HostUnavailable);
        }
        self.verify_files(root)
            .map_err(|_| PythonObservationError::HostUnavailable)
    }

    fn command(&self, cwd: &Path, script: &Path) -> Command {
        let mut command = Command::new(&self.interpreter);
        command
            .env_clear()
            .current_dir(cwd)
            .args(["-I", "-S", "-B"])
            .arg(script);
        #[cfg(windows)]
        if let Some(value) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", value);
        }
        command
    }
}

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let (arguments, policy) = match arguments.split_last() {
        Some((flag, preceding)) if flag == "--policy" => (preceding, true),
        _ => (arguments, false),
    };
    match collect(arguments, policy) {
        Ok(bytes) => {
            super::write_projection(None, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "Python filesystem inspection failed: {}\nusage: {USAGE}",
                readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn collect(arguments: &[String], policy: bool) -> Result<Vec<u8>, String> {
    let [root, registration, scope_path, scope_ref] = arguments else {
        return Err("An exact project, trusted filesystem registration and independent import root scope are required.".into());
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|failure| failure.to_string())?;
    let registration = Path::new(registration);
    let scope_path = Path::new(scope_path);
    let (selected, raw) = Registration::load(registration, &root)?;
    let (scope, scope_raw) = load_import_scope(&root, scope_path, scope_ref)?;
    let cwd = registration
        .parent()
        .ok_or("Missing trusted registration directory")?;
    let profile = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => PythonFilesystemProfile::WindowsX64,
        ("linux", "x86_64") => PythonFilesystemProfile::LinuxX64,
        _ => return Err("PYTHON_FILESYSTEM_PLATFORM_UNAVAILABLE".into()),
    };
    let worker_ref = digest(PYTHON_FILESYSTEM_WORKER);
    let bootstrap_ref = digest(PYTHON_LEXICAL_WORKER);
    let producer = PythonScalarProducer::new(&worker_ref, &bootstrap_ref, &selected.runtime_ref)
        .map_err(|failure| failure.to_string())?;
    let supervisor = canonical(&json!({
        "format":"pinned-python-filesystem-host-v1",
        "registration_ref":digest(&raw),
        "origin_worker_ref":digest(PYTHON_ORIGIN_WORKER),
        "selected_runtime_ref": profile.runtime_ref(),
        "flags":["-I","-S","-B"],
        "deadline_ms":DEADLINE.as_millis(),
        "model":MODELS,
    }))
    .map_err(|failure| failure.to_string())?;
    let revalidate = || {
        selected.revalidate(&root, registration, &raw)?;
        verify_import_scope(&root, scope_path, &scope_raw)
    };
    let compile = |payload: &[u8], ready: &[u8]| {
        revalidate()?;
        let mut command = selected.command(cwd, &selected.worker);
        command.args([
            "--serve",
            "--worker-ref",
            &worker_ref,
            "--bootstrap-ref",
            &bootstrap_ref,
            "--runtime-ref",
            &selected.runtime_ref,
        ]);
        checked(run_pinned_input_after_ready(
            command,
            payload.to_vec(),
            DEADLINE,
            &selected.interpreter_sha256,
            ready.to_vec(),
        ))
    };
    let origin = || {
        revalidate()?;
        checked(run_pinned(
            selected.command(cwd, &selected.origin_worker),
            DEADLINE,
            &selected.interpreter_sha256,
        ))
    };
    let host = PythonFilesystemHost {
        producer: &producer,
        profile,
        supervisor_ref: &digest(&supervisor),
    };
    let value = if policy {
        observe_hypothetical_python_filesystem_policy(
            &root,
            &selected.subject,
            &scope,
            host,
            compile,
            origin,
        )
        .and_then(|report| {
            serde_json::to_value(report).map_err(PythonObservationError::FilesystemJson)
        })
    } else {
        observe_hypothetical_python_filesystem(
            &root,
            &selected.subject,
            &scope,
            host,
            compile,
            origin,
        )
        .and_then(|report| {
            serde_json::to_value(report).map_err(PythonObservationError::FilesystemJson)
        })
    }
    .map_err(|failure| failure.to_string())?;
    revalidate().map_err(|failure| failure.to_string())?;
    canonical(&value).map_err(|failure| failure.to_string())
}

fn checked(
    process: Result<(Vec<u8>, u8), fortress_core::portable::PortableError>,
) -> Result<Vec<u8>, PythonObservationError> {
    match process {
        Ok((stdout, 0)) => Ok(stdout),
        _ => Err(PythonObservationError::HostUnavailable),
    }
}
