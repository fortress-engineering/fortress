//! Explicitly hosted, read-only Python scalar observations.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::portable::{canonical, digest};
use fortress_core::python_observation::{
    ActualPythonScalarObservation, NativeBodyOutcome, PYTHON_LEXICAL_WORKER, PYTHON_SCALAR_WORKER,
    PythonObservationError, PythonScalarProducer, PythonScalarSubject, observe_python_scalar,
};
use fortress_core::wire::{
    JsonAdmissionLimits, admit_json, parse_strict_json_bytes, readable_text,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::python_observe_command::{Grammar, resource_profile};
use super::verifier_process::{require_external_asset, run_pinned_input_after_ready};

const USAGE: &str = "fortress source-artifacts --observe-python-scalar project host-registration";
const REGISTRATION_SCHEMA: &str = "urn:fortress:host:v1:python-scalar-registration";
const OBSERVATION_SCHEMA: &str = "urn:fortress:derived:v1:python-scalar-observation";
const READY_SCHEMA: &str = "fortress-host/python-scalar-ready/1";
const BOOTSTRAP_NAME: &str = "python_lexical_worker.py";
const WORKER_NAME: &str = "python_scalar_worker.py";
const REGISTRATION_MAX: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);

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
    runtime_ref: String,
    grammar: Grammar,
    subject: PythonScalarSubject,
}

impl Registration {
    fn load(root: &Path, path: &Path) -> Result<(Self, Vec<u8>), String> {
        require_external_asset(path, root)?;
        let bytes = super::provider_command::read_bounded(path, REGISTRATION_MAX)?;
        admit_json(
            &bytes,
            JsonAdmissionLimits {
                bytes: REGISTRATION_MAX,
                depth: 5,
                nodes: 64,
                token_bytes: 4096,
            },
        )
        .map_err(|error| error.to_string())?;
        let registration: Self =
            parse_strict_json_bytes(&bytes).map_err(|error| error.to_string())?;
        if registration.schema != REGISTRATION_SCHEMA || registration.schema_version != 1 {
            return Err("UNSUPPORTED_PYTHON_SCALAR_REGISTRATION".into());
        }
        require_external_asset(&registration.interpreter, root)?;
        registration.verify_worker_files(root)?;
        Ok((registration, bytes))
    }

    fn verify_worker_files(&self, root: &Path) -> Result<(), String> {
        if self.worker.file_name() != Some(OsStr::new(WORKER_NAME))
            || self.bootstrap != self.worker.with_file_name(BOOTSTRAP_NAME)
        {
            return Err("PYTHON_SCALAR_WORKER_SIBLING_MISMATCH".into());
        }
        for (path, expected) in [
            (&self.worker, PYTHON_SCALAR_WORKER),
            (&self.bootstrap, PYTHON_LEXICAL_WORKER),
        ] {
            require_external_asset(path, root)?;
            if super::provider_command::read_bounded(path, expected.len())? != expected {
                return Err("PYTHON_SCALAR_WORKER_BYTES_MISMATCH".into());
            }
        }
        Ok(())
    }

    fn command(&self, cwd: &Path, worker_ref: &str, bootstrap_ref: &str) -> Command {
        let mut command = Command::new(&self.interpreter);
        command
            .env_clear()
            .current_dir(cwd)
            .args(["-I", "-S", "-B"])
            .arg(&self.worker)
            .args([
                "--serve",
                "--worker-ref",
                worker_ref,
                "--bootstrap-ref",
                bootstrap_ref,
                "--runtime-ref",
                &self.runtime_ref,
            ]);
        #[cfg(windows)]
        if let Some(value) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", value);
        }
        command
    }

    fn ready(
        &self,
        worker_ref: &str,
        bootstrap_ref: &str,
    ) -> Result<(Vec<u8>, &'static str), String> {
        if std::env::consts::ARCH != "x86_64" {
            return Err("PYTHON_SCALAR_PLATFORM_UNAVAILABLE".into());
        }
        let (profile, limits) = resource_profile()?;
        let mut frame = canonical(&json!({
            "schema": READY_SCHEMA,
            "status": "READY",
            "grammar": self.grammar.wire_name(),
            "profile": profile,
            "limits": limits,
            "worker_ref": worker_ref,
            "bootstrap_ref": bootstrap_ref,
            "runtime_ref": self.runtime_ref,
        }))
        .map_err(|error| error.to_string())?;
        frame.push(b'\n');
        Ok((frame, profile))
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
            writeln!(
                error,
                "Python scalar observation failed: {}",
                readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn collect(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [root, registration_path] = arguments else {
        return Err(format!("usage: {USAGE}"));
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration_path = Path::new(registration_path);
    let (registration, registration_bytes) = Registration::load(&root, registration_path)?;
    let worker_ref = digest(PYTHON_SCALAR_WORKER);
    let bootstrap_ref = digest(PYTHON_LEXICAL_WORKER);
    let producer =
        PythonScalarProducer::new(&worker_ref, &bootstrap_ref, &registration.runtime_ref)
            .map_err(|error| error.to_string())?;
    let (ready, profile) = registration.ready(&worker_ref, &bootstrap_ref)?;
    let host = registration_path
        .parent()
        .ok_or("Missing trusted registration parent")?;
    let command = registration.command(host, &worker_ref, &bootstrap_ref);
    let result = observe_python_scalar(&root, &registration.subject, &producer, |request| {
        let (bytes, status) = run_pinned_input_after_ready(
            command,
            request,
            DEADLINE,
            &registration.interpreter_sha256,
            ready,
        )
        .map_err(|_| PythonObservationError::HostUnavailable)?;
        if status != 0 {
            return Err(PythonObservationError::HostUnavailable);
        }
        registration
            .verify_worker_files(&root)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        require_external_asset(registration_path, &root)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        if super::provider_command::read_bounded(registration_path, REGISTRATION_MAX)
            .map_err(|_| PythonObservationError::HostUnavailable)?
            != registration_bytes
        {
            return Err(PythonObservationError::HostUnavailable);
        }
        Ok(bytes)
    })
    .map_err(|error| error.to_string())?;
    projection(&registration, &registration_bytes, profile, &result)
}

fn projection(
    registration: &Registration,
    registration_bytes: &[u8],
    profile: &str,
    result: &ActualPythonScalarObservation,
) -> Result<Vec<u8>, String> {
    let observation = match result.outcome() {
        NativeBodyOutcome::Lowered(body) => {
            let inference = result.inferred_output().map_or_else(
                || json!({"status":"UNAVAILABLE","output_domain":null}),
                |domain| json!({"status":"UPPER_BOUND_UNDER_EXACT_INPUT_ASSUMPTIONS","output_domain":domain}),
            );
            json!({
                "status":"LOWERED",
                "binding":body.binding(),
                "parameters":body.parameters(),
                "locals":body.locals(),
                "result_scalar":body.result(),
                "body":body.body(),
                "inference":inference,
            })
        }
        NativeBodyOutcome::Unavailable(reason) => json!({
            "status":"UNAVAILABLE",
            "code":reason.code(),
            "location":reason.location(),
        }),
    };
    let report: Value = json!({
        "$schema": OBSERVATION_SCHEMA,
        "schema_version": 1,
        "evaluation": result.evaluation_key(),
        "registration_ref": digest(registration_bytes),
        "interpreter_ref": registration.interpreter_sha256,
        "grammar": registration.grammar.wire_name(),
        "resource_profile": profile,
        "worker_timeout_ms": DEADLINE.as_millis(),
        "request": result.request(),
        "observation": observation,
        "scope": {
            "execution": "NOT_RUN",
            "runtime_argument_types": "UNPROVEN",
            "canonical_model": "NOT_INCLUDED",
            "assessment": "NOT_PERFORMED",
        },
    });
    canonical(&report).map_err(|error| error.to_string())
}
