//! Explicit, read-only host admission for bounded Go compiler observations.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::go_observation::{
    GoCollectorPin, GoObservationError, GoPackageSelection, observe_go_native,
};
use fortress_core::portable::{canonical, digest};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_public_json, readable_text};
use serde::Deserialize;
use serde_json::json;

const SCHEMA: &str = "urn:fortress:host:v1:go-collector-registration";
const REGISTRATION_LIMIT: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const ENVIRONMENT: [(&str, &str); 3] = [
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
                "Go observation failed: {}\nusage: fortress psm --observe-go project host-registration directory package-path go-version target-os target-arch",
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
    ] = arguments
    else {
        return Err(
            "Explicit source, trusted host registration and package context are required.".into(),
        );
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration = Path::new(registration);
    super::verifier_process::require_external_asset(registration, &root)?;
    let registration_bytes =
        super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)?;
    admit_json(
        &registration_bytes,
        JsonAdmissionLimits {
            bytes: REGISTRATION_LIMIT,
            depth: 4,
            nodes: 32,
            token_bytes: 4096,
        },
    )
    .map_err(|error| error.to_string())?;
    let declared: Registration = parse_public_json(
        std::str::from_utf8(&registration_bytes).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if declared.schema != SCHEMA || declared.schema_version != 1 {
        return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into());
    }
    super::verifier_process::require_external_asset(&declared.executable, &root)?;
    let host_directory = registration
        .parent()
        .ok_or("Host registration needs an external working directory.")?;
    let mut command = Command::new(&declared.executable);
    command
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
    let host_context = json!({
        "format": "pinned-go-collector-host-v1",
        "registration_sha256": digest(&registration_bytes),
        "transport": "bounded_one_shot_stdio",
        "timeout_ms": TIMEOUT.as_millis(),
        "host_os": std::env::consts::OS,
        "host_arch": std::env::consts::ARCH,
        "environment": ENVIRONMENT,
        "system_root_sha256": system_root.as_ref().map(|root| digest(root.as_bytes())),
    });
    let host_context_sha256 = digest(&canonical(&host_context).map_err(|error| error.to_string())?);
    let pin = GoCollectorPin {
        executable_sha256: &declared.executable_sha256,
        supervisor_context_sha256: &host_context_sha256,
        go_toolchain: &declared.toolchain,
    };
    let selection = GoPackageSelection {
        directory: if directory == "." { "" } else { directory },
        package_path,
        go_version,
        target_os,
        target_arch,
    };
    let result = observe_go_native(&root, selection, &pin, |bytes| {
        run_collector(command, bytes, pin.executable_sha256)
    })
    .map_err(|error| error.to_string())?;
    super::verifier_process::require_external_asset(registration, &root)?;
    if super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)?
        != registration_bytes
    {
        return Err("SOURCE_DRIFT: Native collector registration changed.".into());
    }
    let projection = serde_json::to_value(result).map_err(|error| error.to_string())?;
    canonical(&projection).map_err(|error| error.to_string())
}

fn run_collector(
    command: Command,
    input: &[u8],
    executable_ref: &str,
) -> Result<Vec<u8>, GoObservationError> {
    let (output, status) =
        super::verifier_process::run_pinned_input(command, input.to_vec(), TIMEOUT, executable_ref)
            .map_err(|error| GoObservationError::Execution(error.code))?;
    if status != 0 {
        return Err(GoObservationError::Execution(
            "NATIVE_COLLECTOR_EXIT_FAILURE".into(),
        ));
    }
    Ok(output)
}
