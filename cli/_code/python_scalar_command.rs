//! Explicitly hosted, read-only Python scalar observations.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::candidate::{
    CandidateWorkspace, HypotheticalNativeBodyInspection, NativeCandidateSelection,
};
use fortress_core::migration_governance::MigrationError;
use fortress_core::portable::{canonical, digest};
use fortress_core::python_observation::{
    ActualPythonScalarObservation, NativeBodyOutcome, PYTHON_LEXICAL_WORKER, PYTHON_SCALAR_WORKER,
    PythonCallableSelection, PythonObservationError, PythonScalarError, PythonScalarProducer,
    PythonScalarSubject, observe_python_authored_native_return,
    observe_python_candidate_sensitivity, observe_python_scalar, observe_python_scalar_flow,
    observe_python_scalar_sensitivity,
};
use fortress_core::wire::{
    JsonAdmissionLimits, admit_json, parse_strict_json_bytes, readable_text,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::python_observe_command::{
    Grammar, load_import_scope, resource_profile, verify_import_scope,
};
use super::verifier_process::{require_external_asset, run_pinned_input_after_ready};

const USAGE: &str = concat!(
    "fortress source-artifacts --observe-python-scalar project host-registration [--flow|--return-sensitivity]",
    "\n       fortress source-artifacts --observe-python-scalar project host-registration --contract module root-scope root-scope-sha256",
);
const REGISTRATION_SCHEMA: &str = "urn:fortress:host:v1:python-scalar-registration";
const OBSERVATION_SCHEMA: &str = "urn:fortress:derived:v1:python-scalar-observation";
const READY_SCHEMA: &str = "fortress-host/python-scalar-ready/1";
const BOOTSTRAP_NAME: &str = "python_lexical_worker.py";
const WORKER_NAME: &str = "python_scalar_worker.py";
// Retain existing exact local registrations through a compatible scalar wire edition.
const PRIOR_WORKER_BYTES: usize = 16_457;
const PRIOR_WORKER_REF: &str =
    "sha256:7df54ae0f4affba51191d62fbe4b12bc484ba0f7b15594222652a0a2ce2abc0f";
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
    fn load(root: &Path, path: &Path) -> Result<(Self, Vec<u8>, String), String> {
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
        let worker_ref = registration.verify_worker_files(root)?;
        Ok((registration, bytes, worker_ref))
    }

    fn verify_worker_files(&self, root: &Path) -> Result<String, String> {
        if self.worker.file_name() != Some(OsStr::new(WORKER_NAME))
            || self.bootstrap != self.worker.with_file_name(BOOTSTRAP_NAME)
        {
            return Err("PYTHON_SCALAR_WORKER_SIBLING_MISMATCH".into());
        }
        require_external_asset(&self.worker, root)?;
        require_external_asset(&self.bootstrap, root)?;
        let worker = super::provider_command::read_bounded(
            &self.worker,
            PYTHON_SCALAR_WORKER.len().max(PRIOR_WORKER_BYTES),
        )?;
        let worker_ref = digest(&worker);
        if (worker != PYTHON_SCALAR_WORKER
            && (worker.len() != PRIOR_WORKER_BYTES || worker_ref != PRIOR_WORKER_REF))
            || super::provider_command::read_bounded(&self.bootstrap, PYTHON_LEXICAL_WORKER.len())?
                != PYTHON_LEXICAL_WORKER
        {
            return Err("PYTHON_SCALAR_WORKER_BYTES_MISMATCH".into());
        }
        Ok(worker_ref)
    }

    fn revalidate(
        &self,
        root: &Path,
        path: &Path,
        expected: &[u8],
        expected_worker: &str,
    ) -> Result<(), PythonObservationError> {
        let worker_ref = self
            .verify_worker_files(root)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        if worker_ref != expected_worker {
            return Err(PythonObservationError::HostUnavailable);
        }
        require_external_asset(path, root).map_err(|_| PythonObservationError::HostUnavailable)?;
        let current = super::provider_command::read_bounded(path, REGISTRATION_MAX)
            .map_err(|_| PythonObservationError::HostUnavailable)?;
        if current != expected {
            return Err(PythonObservationError::HostUnavailable);
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

struct RegisteredScalarHost<'a> {
    root: &'a Path,
    registration_path: &'a Path,
    working_directory: &'a Path,
    registration: Registration,
    registration_bytes: Vec<u8>,
    worker_ref: String,
    bootstrap_ref: String,
    producer: PythonScalarProducer,
    ready: Vec<u8>,
    profile: &'static str,
}

impl<'a> RegisteredScalarHost<'a> {
    fn load(root: &'a Path, registration_path: &'a Path) -> Result<Self, String> {
        let (registration, registration_bytes, worker_ref) =
            Registration::load(root, registration_path)?;
        let bootstrap_ref = digest(PYTHON_LEXICAL_WORKER);
        let producer =
            PythonScalarProducer::new(&worker_ref, &bootstrap_ref, &registration.runtime_ref)
                .map_err(|error| error.to_string())?;
        let (ready, profile) = registration.ready(&worker_ref, &bootstrap_ref)?;
        let working_directory = registration_path
            .parent()
            .ok_or("Missing trusted registration parent")?;
        Ok(Self {
            root,
            registration_path,
            working_directory,
            registration,
            registration_bytes,
            worker_ref,
            bootstrap_ref,
            producer,
            ready,
            profile,
        })
    }

    fn revalidate(&self) -> Result<(), PythonObservationError> {
        self.registration.revalidate(
            self.root,
            self.registration_path,
            &self.registration_bytes,
            &self.worker_ref,
        )
    }

    fn exchange(&self, request: Vec<u8>) -> Result<Vec<u8>, PythonObservationError> {
        self.revalidate()?;
        let command = self.registration.command(
            self.working_directory,
            &self.worker_ref,
            &self.bootstrap_ref,
        );
        let (bytes, status) = run_pinned_input_after_ready(
            command,
            request,
            DEADLINE,
            &self.registration.interpreter_sha256,
            self.ready.clone(),
        )
        .map_err(|_| PythonObservationError::HostUnavailable)?;
        if status != 0 {
            return Err(PythonObservationError::HostUnavailable);
        }
        self.revalidate()?;
        Ok(bytes)
    }
}

fn candidate_host_error(failure: impl std::fmt::Display) -> MigrationError {
    MigrationError {
        code: "NATIVE_OBSERVATION_UNAVAILABLE".into(),
        message: failure.to_string(),
        transaction_ref: None,
    }
}

pub(super) fn inspect_candidate(
    root: &Path,
    registration_path: &Path,
    workspace: &CandidateWorkspace,
    retained: NativeCandidateSelection<'_>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    let host = RegisteredScalarHost::load(root, registration_path).map_err(candidate_host_error)?;
    let result = observe_python_candidate_sensitivity(
        workspace,
        retained,
        &host.registration.subject,
        &host.producer,
        |request| host.exchange(request),
    );
    host.revalidate().map_err(candidate_host_error)?;
    result
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

#[derive(Clone, Copy)]
enum ScalarInspection {
    Observation,
    Flow,
    ReturnSensitivity,
}

fn collect(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [root, registration_path, mode @ ..] = arguments else {
        return Err(format!("usage: {USAGE}"));
    };
    let (inspection, authored) = match mode {
        [] => (ScalarInspection::Observation, None),
        [flag] if flag == "--flow" => (ScalarInspection::Flow, None),
        [flag] if flag == "--return-sensitivity" => (ScalarInspection::ReturnSensitivity, None),
        [flag, module, scope_path, scope_ref] if flag == "--contract" => (
            ScalarInspection::Observation,
            Some((module.as_str(), Path::new(scope_path), scope_ref.as_str())),
        ),
        _ => return Err(format!("usage: {USAGE}")),
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let authored = authored
        .map(|(module, scope_path, scope_ref)| {
            load_import_scope(&root, scope_path, scope_ref)
                .map(|(scope, bytes)| (module, scope_path, scope, bytes))
        })
        .transpose()?;
    let host = RegisteredScalarHost::load(&root, Path::new(registration_path))?;
    let exchange = |request| host.exchange(request);
    if let Some((module, scope_path, scope, scope_bytes)) = authored {
        let subject = &host.registration.subject;
        if !subject.exact_bool_parameters.is_empty() {
            return Err("PYTHON_AUTHORED_RETURN_REQUIRES_ZERO_ARGUMENT_SUBJECT".into());
        }
        let selected = PythonCallableSelection {
            module,
            function: &subject.function,
        };
        let result = observe_python_authored_native_return(
            &root,
            selected,
            &scope,
            &host.producer,
            |request| {
                check_contract_subject(subject, &request)?;
                host.revalidate()?;
                verify_import_scope(&root, scope_path, &scope_bytes)?;
                exchange(request)
            },
        )
        .map_err(|error| error.to_string())?;
        host.revalidate().map_err(|error| error.to_string())?;
        verify_import_scope(&root, scope_path, &scope_bytes).map_err(|error| error.to_string())?;
        return crate::native_return_command::serialize(&result);
    }
    serialize_scalar_inspection(
        &root,
        &host.registration,
        &host.registration_bytes,
        host.profile,
        &host.producer,
        exchange,
        inspection,
    )
}

fn serialize_scalar_inspection(
    root: &Path,
    registration: &Registration,
    registration_bytes: &[u8],
    profile: &str,
    producer: &PythonScalarProducer,
    exchange: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, PythonObservationError>,
    inspection: ScalarInspection,
) -> Result<Vec<u8>, String> {
    if matches!(inspection, ScalarInspection::ReturnSensitivity) {
        let (result, sensitivity) =
            observe_python_scalar_sensitivity(root, &registration.subject, producer, exchange)
                .map_err(|error| error.to_string())?;
        return super::native_return_command::serialize_sensitivity(
            "python",
            None,
            &projection(registration, registration_bytes, profile, &result),
            sensitivity.as_ref(),
        );
    }
    let (result, flow) = if matches!(inspection, ScalarInspection::Flow) {
        observe_python_scalar_flow(root, &registration.subject, producer, exchange)
            .map(|(report, flow)| (report, Some(flow)))
    } else {
        observe_python_scalar(root, &registration.subject, producer, exchange)
            .map(|report| (report, None))
    }
    .map_err(|error| error.to_string())?;
    let receipt = projection(registration, registration_bytes, profile, &result);
    let value = if let Some(flow) = flow {
        json!({
            "$schema":"urn:fortress:derived:v1:native-scalar-flow-inspection",
            "schema_version":1,
            "language":"python",
            "scope":"SCOPED_EXPLICIT_TRANSFERS",
            "requested_occurrence":null,
            "selection":"BOUND",
            "native_receipt":receipt,
            "flow":flow,
        })
    } else {
        receipt
    };
    canonical(&value).map_err(|error| error.to_string())
}

fn check_contract_subject(
    expected: &PythonScalarSubject,
    core_request: &[u8],
) -> Result<(), PythonObservationError> {
    #[derive(Deserialize)]
    struct SelectedSubject {
        source_path: String,
        source_ref: String,
        function: String,
        parameter_domains: Vec<String>,
    }
    // This request is built from the original source capture by Snapshot Governance.
    let actual: SelectedSubject =
        parse_strict_json_bytes(core_request).map_err(|_| PythonScalarError::Binding)?;
    if actual.source_path != expected.source_path
        || actual.source_ref != expected.source_ref
        || actual.function != expected.function
        || !actual.parameter_domains.is_empty()
    {
        return Err(PythonScalarError::Binding.into());
    }
    Ok(())
}

fn projection(
    registration: &Registration,
    registration_bytes: &[u8],
    profile: &str,
    result: &ActualPythonScalarObservation,
) -> Value {
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
    json!({
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
    })
}
