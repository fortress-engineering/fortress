//! Explicit CLI host for the bounded native Go scalar-body producer.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::go_observation::{
    ActualGoNativeBodyObservation, GoCollectorPin, GoObservationError, GoPackageSelection,
    observe_go_native_body, observe_go_native_body_flow, observe_go_native_body_sensitivity,
    observe_go_native_bound_calls, observe_go_native_call_return,
    observe_go_native_call_sensitivity, observe_go_native_call_topology,
};
use fortress_core::information_flow::NativeScalarFlowObservation;
use fortress_core::portable::{canonical, digest};
use fortress_core::wire::{
    JsonAdmissionLimits, admit_json, parse_strict_json_bytes, readable_text,
};
use serde::Deserialize;
use serde_json::json;

const SCHEMA: &str = "urn:fortress:host:v1:go-body-registration";
const REGISTRATION_LIMIT: usize = 16 * 1024;
pub(super) const TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const ENVIRONMENT: [(&str, &str); 3] = [
    ("GOMAXPROCS", "2"),
    ("GODEBUG", "gotypesalias=0"),
    ("GOMEMLIMIT", "128MiB"),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    executable: PathBuf,
    executable_sha256: String,
    toolchain: String,
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
                "Go body observation failed: {}\nusage: fortress psm --observe-go-body project host-registration directory package-path go-version target-os target-arch [--flow exact-occurrence | --return-sensitivity exact-occurrence | --bound-calls | --call-return exact-occurrence | --call-topology exact-occurrence | --call-sensitivity exact-occurrence]",
                readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn collect(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [
        root,
        registration,
        directory,
        package_path,
        go_version,
        target_os,
        target_arch,
        mode @ ..,
    ] = arguments
    else {
        return Err(
            "Explicit source, trusted host registration and package context are required.".into(),
        );
    };
    let (occurrence, sensitivity, with_calls) = match mode {
        [flag] if flag == "--bound-calls" => (None, false, true),
        [flag, binding]
            if matches!(
                flag.as_str(),
                "--call-return" | "--call-topology" | "--call-sensitivity"
            ) =>
        {
            (Some(binding.as_str()), false, true)
        }
        [] => (None, false, false),
        [flag, binding] if flag == "--flow" => (Some(binding.as_str()), false, false),
        [flag, binding] if flag == "--return-sensitivity" => (Some(binding.as_str()), true, false),
        _ => return Err("Expected an exact body occurrence selection.".into()),
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|failure| failure.to_string())?;
    let registration = Path::new(registration);
    let selection = GoPackageSelection {
        directory: if directory == "." { "" } else { directory },
        package_path,
        go_version,
        target_os,
        target_arch,
    };
    if with_calls {
        let report = with_registered_body_mode(&root, registration, true, |pin, collector| {
            let launch = |input: &[u8]| collector.run(input);
            if let Some(binding) = occurrence {
                match mode.first().map(String::as_str) {
                    Some("--call-topology") => {
                        observe_go_native_call_topology(&root, selection, binding, pin, launch)
                    }
                    Some("--call-sensitivity") => {
                        observe_go_native_call_sensitivity(&root, selection, binding, pin, launch)
                    }
                    _ => observe_go_native_call_return(&root, selection, binding, pin, launch),
                }
            } else {
                observe_go_native_bound_calls(&root, selection, pin, launch)
            }
            .map_err(|failure| failure.to_string())
        })?;
        return canonical(&report).map_err(|failure| failure.to_string());
    }
    if let Some(binding) = occurrence.filter(|_| sensitivity) {
        let (receipt, result) = with_registered_body(&root, registration, |pin, collector| {
            observe_go_native_body_sensitivity(&root, selection, pin, binding, |input| {
                collector.run(input)
            })
            .map_err(|failure| failure.to_string())
        })?;
        return super::native_return_command::serialize_sensitivity(
            "go",
            Some(binding),
            &serde_json::to_value(receipt).map_err(|failure| failure.to_string())?,
            result.as_ref(),
        );
    }
    let (result, flow) = with_registered_body(&root, registration, |pin, collector| {
        let launch = |input: &[u8]| collector.run(input);
        if let Some(binding) = occurrence {
            observe_go_native_body_flow(&root, selection, pin, binding, launch)
        } else {
            observe_go_native_body(&root, selection, pin, launch).map(|result| (result, None))
        }
        .map_err(|failure| failure.to_string())
    })?;
    serialize_report(result, occurrence, flow.as_ref())
}

pub(super) struct BodyLaunch<'a> {
    command: Command,
    executable_ref: &'a str,
}

impl BodyLaunch<'_> {
    pub(super) fn run(self, input: &[u8]) -> Result<Vec<u8>, GoObservationError> {
        let (stdout, status) = super::verifier_process::run_pinned_input(
            self.command,
            input.to_vec(),
            TIMEOUT,
            self.executable_ref,
        )
        .map_err(|failure| GoObservationError::Execution(failure.code))?;
        if status != 0 {
            return Err(GoObservationError::Execution(
                "NATIVE_COLLECTOR_EXIT_FAILURE".into(),
            ));
        }
        Ok(stdout)
    }
}

pub(super) fn with_registered_body<T>(
    root: &Path,
    registration: &Path,
    observe: impl FnOnce(&GoCollectorPin<'_>, BodyLaunch<'_>) -> Result<T, String>,
) -> Result<T, String> {
    with_registered_body_mode(root, registration, false, observe)
}

pub(super) fn with_registered_body_mode<T>(
    root: &Path,
    registration: &Path,
    with_calls: bool,
    observe: impl FnOnce(&GoCollectorPin<'_>, BodyLaunch<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let (declared, original) = read_host_registration(registration, root)?;
    let host_directory = registration
        .parent()
        .ok_or("Host registration needs an external working directory.")?;
    let (selector, format) = if with_calls {
        ("--lower-go-bound-calls", "pinned-go-bound-call-host-v1")
    } else {
        ("--lower-first-order-go", "pinned-go-body-collector-host-v1")
    };
    let (launch, system_root) = prepare_native_go_launch(
        &declared.executable,
        &declared.executable_sha256,
        host_directory,
        selector,
    );
    let host_context = json!({
        "format": format,
        "registration_sha256": digest(&original),
        "transport": "bounded_one_shot_stdio",
        "timeout_ms": TIMEOUT.as_millis(),
        "host_os": std::env::consts::OS,
        "host_arch": std::env::consts::ARCH,
        "environment": ENVIRONMENT,
        "system_root_sha256": system_root.as_ref().map(|root| digest(root.as_bytes())),
    });
    let context_sha256 = digest(&canonical(&host_context).map_err(|failure| failure.to_string())?);
    let pin = GoCollectorPin {
        executable_sha256: &declared.executable_sha256,
        supervisor_context_sha256: &context_sha256,
        go_toolchain: &declared.toolchain,
    };
    let result = observe(&pin, launch)?;
    super::verifier_process::require_external_asset(registration, root)?;
    if super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)? != original {
        return Err("SOURCE_DRIFT: Native collector registration changed.".into());
    }
    Ok(result)
}

pub(super) fn prepare_native_go_launch<'a>(
    executable: &Path,
    executable_ref: &'a str,
    host_directory: &Path,
    selector: &str,
) -> (BodyLaunch<'a>, Option<String>) {
    let mut command = Command::new(executable);
    command
        .arg(selector)
        .env_clear()
        .current_dir(host_directory)
        .envs(ENVIRONMENT);
    #[cfg(windows)]
    let system_root = std::env::var("SystemRoot").ok();
    #[cfg(not(windows))]
    let system_root: Option<String> = None;
    if let Some(value) = &system_root {
        command.env("SystemRoot", value);
    }
    (
        BodyLaunch {
            command,
            executable_ref,
        },
        system_root,
    )
}

fn read_host_registration(
    registration: &Path,
    root: &Path,
) -> Result<(Registration, Vec<u8>), String> {
    super::verifier_process::require_external_asset(registration, root)?;
    let original = super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)?;
    admit_json(
        &original,
        JsonAdmissionLimits {
            bytes: REGISTRATION_LIMIT,
            depth: 4,
            nodes: 32,
            token_bytes: 4096,
        },
    )
    .map_err(|failure| failure.to_string())?;
    let declared: Registration =
        parse_strict_json_bytes(&original).map_err(|failure| failure.to_string())?;
    if declared.schema != SCHEMA || declared.schema_version != 1 {
        return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into());
    }
    super::verifier_process::require_external_asset(&declared.executable, root)?;
    Ok((declared, original))
}

fn serialize_report(
    result: ActualGoNativeBodyObservation,
    occurrence: Option<&str>,
    flow: Option<&NativeScalarFlowObservation>,
) -> Result<Vec<u8>, String> {
    let projection = serde_json::to_value(result).map_err(|failure| failure.to_string())?;
    let report = if let Some(binding) = occurrence {
        json!({
            "$schema":"urn:fortress:derived:v1:native-scalar-flow-inspection",
            "schema_version":1,
            "language":"go",
            "scope":"SCOPED_EXPLICIT_TRANSFERS",
            "requested_occurrence":binding,
            "selection":if flow.is_some() {"BOUND"} else {"OCCURRENCE_UNAVAILABLE"},
            "native_receipt":projection,
            "flow":flow,
        })
    } else {
        projection
    };
    canonical(&report).map_err(|failure| failure.to_string())
}
