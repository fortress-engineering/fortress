//! Explicit, read-only host admission for bounded Go compiler observations.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::go_observation::{
    GoBuildContext, GoCollectorPin, GoModuleSelection, GoObservationError, GoPackageSelection,
    GoTypeComparison, GoTypeSelector, observe_go_module_dependencies, observe_go_native,
    observe_go_native_build, observe_go_native_module,
};
use fortress_core::portable::{canonical, digest};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_public_json, readable_text};
use serde::{Deserialize, Serialize};
use serde_json::json;

const SCHEMA: &str = "urn:fortress:host:v1:go-collector-registration";
const MODULE_SCHEMA: &str = "urn:fortress:host:v3:go-module-collector-registration";
const BUILD_SCHEMA: &str = "urn:fortress:host:v2:go-build-collector-registration";
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRegistration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    executable: PathBuf,
    executable_sha256: String,
    toolchain: String,
    build_context: GoBuildContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Legacy,
    Build,
    Module,
}

impl Mode {
    fn cli_usage(self) -> &'static str {
        match self {
            Self::Legacy => {
                "--observe-go project host-registration directory package-path go-version target-os target-arch"
            }
            Self::Build => {
                "--observe-go-build project host-registration directory package-path go-version target-os target-arch"
            }
            Self::Module => {
                "--observe-go-module project host-registration module-directory module-path entry-path target-os target-arch [--dependencies | left-package left-type right-package right-type]"
            }
        }
    }

    fn format(self) -> &'static str {
        match self {
            Self::Legacy => "pinned-go-collector-host-v1",
            Self::Build => "pinned-go-build-collector-host-v2",
            Self::Module => "pinned-go-module-collector-host-v3",
        }
    }
}

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run_mode(arguments, output, error, Mode::Legacy)
}

pub(super) fn run_build<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run_mode(arguments, output, error, Mode::Build)
}

pub(super) fn run_module<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run_mode(arguments, output, error, Mode::Module)
}

fn run_mode<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
    mode: Mode,
) -> io::Result<u8> {
    match collect(arguments, mode) {
        Ok(bytes) => {
            super::write_projection(None, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "Go observation failed: {}\nusage: fortress psm {}",
                readable_text(&failure),
                mode.cli_usage()
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn collect(arguments: &[String], mode: Mode) -> Result<Vec<u8>, String> {
    let [
        root,
        registration,
        directory,
        scope,
        version_or_entry,
        target_os,
        target_arch,
        compare @ ..,
    ] = arguments
    else {
        return Err(
            "Explicit source, trusted host registration and package context are required.".into(),
        );
    };
    let dependencies = mode == Mode::Module && compare == ["--dependencies"];
    let comparison = if dependencies {
        None
    } else {
        parse_comparison(mode, compare)?
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let registration = Path::new(registration);
    super::verifier_process::require_external_asset(registration, &root)?;
    let registration_bytes =
        super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)?;
    let (declared, build_context) = parse_registration(&registration_bytes, mode)?;
    super::verifier_process::require_external_asset(&declared.executable, &root)?;
    let (command, host_context_sha256) =
        prepare_command(mode, &declared, registration, &registration_bytes)?;
    let pin = GoCollectorPin {
        executable_sha256: &declared.executable_sha256,
        supervisor_context_sha256: &host_context_sha256,
        go_toolchain: &declared.toolchain,
    };
    let directory = if directory == "." { "" } else { directory };
    let launch = |bytes: &[u8]| run_collector(command, bytes, pin.executable_sha256);
    let projection = match (mode, build_context) {
        (Mode::Module, Some(context)) => {
            let selection = GoModuleSelection {
                directory,
                module_path: scope,
                entry_path: version_or_entry,
                target_os,
                target_arch,
                comparison: comparison.as_ref(),
            };
            if dependencies {
                observe_go_module_dependencies(&root, selection, context, &pin, launch)
                    .map_err(|error| error.to_string())
            } else {
                let result = observe_go_native_module(&root, selection, context, &pin, launch)
                    .map_err(|error| error.to_string())?;
                encode_observation(result)
            }
        }
        (mode, context) => {
            let selection = GoPackageSelection {
                directory,
                package_path: scope,
                go_version: version_or_entry,
                target_os,
                target_arch,
            };
            match (mode, context) {
                (Mode::Build, Some(context)) => {
                    let result = observe_go_native_build(&root, selection, context, &pin, launch)
                        .map_err(|error| error.to_string())?;
                    encode_observation(result)
                }
                (Mode::Legacy, None) => {
                    let result = observe_go_native(&root, selection, &pin, launch)
                        .map_err(|error| error.to_string())?;
                    encode_observation(result)
                }
                _ => return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into()),
            }
        }
    }?;
    super::verifier_process::require_external_asset(registration, &root)?;
    if super::provider_command::read_bounded(registration, REGISTRATION_LIMIT)?
        != registration_bytes
    {
        return Err("SOURCE_DRIFT: Native collector registration changed.".into());
    }
    Ok(projection)
}

fn encode_observation(observation: impl Serialize) -> Result<Vec<u8>, String> {
    let projection = serde_json::to_value(observation).map_err(|error| error.to_string())?;
    canonical(&projection).map_err(|error| error.to_string())
}

fn parse_comparison(mode: Mode, compare: &[String]) -> Result<Option<GoTypeComparison>, String> {
    match (mode, compare) {
        (_, []) => Ok(None),
        (Mode::Module, [left_package, left_type, right_package, right_type]) => {
            Ok(Some(GoTypeComparison {
                left: GoTypeSelector {
                    package_path: left_package.clone(),
                    name: left_type.clone(),
                },
                right: GoTypeSelector {
                    package_path: right_package.clone(),
                    name: right_type.clone(),
                },
            }))
        }
        (Mode::Module, _) => {
            Err("An explicit type comparison requires two complete selectors.".into())
        }
        _ => Err(
            "Explicit source, trusted host registration and package context are required.".into(),
        ),
    }
}

fn prepare_command(
    mode: Mode,
    declared: &Registration,
    registration: &Path,
    registration_bytes: &[u8],
) -> Result<(Command, String), String> {
    let host_directory = registration
        .parent()
        .ok_or("Host registration needs an external working directory.")?;
    let mut command = Command::new(&declared.executable);
    match mode {
        Mode::Legacy => {}
        Mode::Build => {
            command.arg("--select-build-go");
        }
        Mode::Module => {
            if !matches!(
                (
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    declared.toolchain.as_str()
                ),
                ("windows", "x86_64", "go1.22.12") | ("linux", "x86_64", "go1.22.2")
            ) {
                return Err("UNSUPPORTED_GO_MODULE_HOST_TOOLCHAIN".into());
            }
            command.arg("--observe-go-module");
        }
    }
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
        "format": mode.format(),
        "registration_sha256": digest(registration_bytes),
        "transport": "bounded_one_shot_stdio",
        "timeout_ms": TIMEOUT.as_millis(),
        "host_os": std::env::consts::OS,
        "host_arch": std::env::consts::ARCH,
        "environment": ENVIRONMENT,
        "system_root_sha256": system_root.as_ref().map(|root| digest(root.as_bytes())),
    });
    let host_context_sha256 = digest(&canonical(&host_context).map_err(|error| error.to_string())?);
    Ok((command, host_context_sha256))
}

fn parse_registration(
    bytes: &[u8],
    mode: Mode,
) -> Result<(Registration, Option<GoBuildContext>), String> {
    admit_json(
        bytes,
        JsonAdmissionLimits {
            bytes: REGISTRATION_LIMIT,
            depth: 4,
            nodes: if mode == Mode::Legacy { 32 } else { 80 },
            token_bytes: 4096,
        },
    )
    .map_err(|error| error.to_string())?;
    let json = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if mode == Mode::Legacy {
        let declared: Registration = parse_public_json(json).map_err(|error| error.to_string())?;
        if declared.schema != SCHEMA || declared.schema_version != 1 {
            return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into());
        }
        return Ok((declared, None));
    }
    let declared: BuildRegistration = parse_public_json(json).map_err(|error| error.to_string())?;
    let (schema, version) = if mode == Mode::Module {
        (MODULE_SCHEMA, 3)
    } else {
        (BUILD_SCHEMA, 2)
    };
    if declared.schema != schema || declared.schema_version != version {
        return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into());
    }
    Ok((
        Registration {
            schema: declared.schema,
            schema_version: declared.schema_version,
            executable: declared.executable,
            executable_sha256: declared.executable_sha256,
            toolchain: declared.toolchain,
        },
        Some(declared.build_context),
    ))
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
