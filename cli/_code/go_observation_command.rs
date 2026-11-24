//! Explicit, read-only host admission for bounded Go compiler observations.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::go_observation::{
    GoBuildContext, GoCallableHost, GoCallableSelection, GoCollectorPin, GoModuleSelection,
    GoObservationError, GoPackageSelection, GoTypeComparison, GoTypeSelector,
    observe_go_authored_native_return, observe_go_module_dependencies, observe_go_native,
    observe_go_native_build, observe_go_native_module, observe_go_native_tests,
};
use fortress_core::portable::{canonical, digest};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_public_json, readable_text};
use serde::{Deserialize, Serialize};
use serde_json::json;

const SCHEMA: &str = "urn:fortress:host:v1:go-collector-registration";
const MODULE_SCHEMA: &str = "urn:fortress:host:v3:go-module-collector-registration";
const BUILD_SCHEMA: &str = "urn:fortress:host:v2:go-build-collector-registration";
const TEST_SCHEMA: &str = "urn:fortress:host:v1:go-test-registration";
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
    Tests,
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
            Self::Tests => {
                "--observe-go-tests project host-registration directory package-path go-version target-os target-arch"
            }
            Self::Module => {
                "--observe-go-module project host-registration module-directory module-path entry-path target-os target-arch [--dependencies | --authored-return function body-registration | left-package left-type right-package right-type]"
            }
        }
    }

    fn format(self) -> &'static str {
        match self {
            Self::Legacy => "pinned-go-collector-host-v1",
            Self::Build => "pinned-go-build-collector-host-v2",
            Self::Tests => "pinned-go-test-declaration-host-v1",
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

pub(super) fn run_tests<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run_mode(arguments, output, error, Mode::Tests)
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
    let operation = parse_operation(mode, compare)?;
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
                comparison: None,
            };
            collect_module(&root, selection, context, operation, &pin, launch)
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
                (Mode::Tests, Some(context)) => {
                    let result = observe_go_native_tests(&root, selection, context, &pin, launch)
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

enum ModuleOperation<'a> {
    Observe(Option<GoTypeComparison>),
    Dependencies,
    AuthoredReturn {
        function: &'a str,
        body_registration: &'a Path,
    },
}

fn parse_operation(mode: Mode, options: &[String]) -> Result<ModuleOperation<'_>, String> {
    match (mode, options) {
        (_, []) => Ok(ModuleOperation::Observe(None)),
        (Mode::Module, [flag]) if flag == "--dependencies" => Ok(ModuleOperation::Dependencies),
        (Mode::Module, [flag, function, body_registration])
            if flag == "--authored-return"
                && !function.is_empty()
                && !function.starts_with('-')
                && Path::new(body_registration).is_absolute() =>
        {
            Ok(ModuleOperation::AuthoredReturn { function, body_registration: Path::new(body_registration) })
        }
        (Mode::Module, [flag, ..]) if flag == "--authored-return" => {
            Err("An authored return requires one function and an absolute trusted body registration path.".into())
        }
        (Mode::Module, [left_package, left_type, right_package, right_type]) => {
            Ok(ModuleOperation::Observe(Some(GoTypeComparison {
                left: GoTypeSelector {
                    package_path: left_package.clone(),
                    name: left_type.clone(),
                },
                right: GoTypeSelector {
                    package_path: right_package.clone(),
                    name: right_type.clone(),
                },
            })))
        }
        (Mode::Module, _) => {
            Err("An explicit type comparison requires two complete selectors.".into())
        }
        _ => Err(
            "Explicit source, trusted host registration and package context are required.".into(),
        ),
    }
}

fn collect_module(
    root: &Path,
    selection: GoModuleSelection<'_>,
    context: GoBuildContext,
    operation: ModuleOperation<'_>,
    pin: &GoCollectorPin<'_>,
    launch: impl FnOnce(&[u8]) -> Result<Vec<u8>, GoObservationError>,
) -> Result<Vec<u8>, String> {
    match operation {
        ModuleOperation::Observe(comparison) => {
            let selection = GoModuleSelection {
                comparison: comparison.as_ref(),
                ..selection
            };
            let result = observe_go_native_module(root, selection, context, pin, launch)
                .map_err(|error| error.to_string())?;
            encode_observation(result)
        }
        ModuleOperation::Dependencies => {
            observe_go_module_dependencies(root, selection, context, pin, launch)
                .map_err(|error| error.to_string())
        }
        ModuleOperation::AuthoredReturn {
            function,
            body_registration,
        } => {
            let result = super::go_body_command::with_registered_body(
                root,
                body_registration,
                |body, process| {
                    observe_go_authored_native_return(
                        root,
                        GoCallableSelection {
                            module: selection,
                            function,
                        },
                        context,
                        GoCallableHost { module: pin, body },
                        launch,
                        |bytes| process.run(bytes),
                    )
                    .map_err(|error| error.to_string())
                },
            )?;
            super::native_return_command::serialize(&result)
        }
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
        Mode::Module | Mode::Tests => {
            if !matches!(
                (
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    declared.toolchain.as_str()
                ),
                ("windows", "x86_64", "go1.22.12") | ("linux", "x86_64", "go1.22.2")
            ) {
                return Err(if mode == Mode::Module {
                    "UNSUPPORTED_GO_MODULE_HOST_TOOLCHAIN".into()
                } else {
                    "UNSUPPORTED_GO_TEST_HOST_TOOLCHAIN".into()
                });
            }
            command.arg(if mode == Mode::Module {
                "--observe-go-module"
            } else {
                "--observe-go-tests"
            });
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
    let (schema, version) = match mode {
        Mode::Module => (MODULE_SCHEMA, 3),
        Mode::Tests => (TEST_SCHEMA, 1),
        Mode::Build | Mode::Legacy => (BUILD_SCHEMA, 2),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_return_requires_a_complete_separate_host_selection() {
        let body = std::env::current_dir()
            .unwrap()
            .join("body-registration.json");
        let arguments = [
            "--authored-return".to_owned(),
            "Keep".to_owned(),
            body.to_str().unwrap().to_owned(),
        ];
        assert!(matches!(
            parse_operation(Mode::Module, &arguments).unwrap(),
            ModuleOperation::AuthoredReturn { function: "Keep", body_registration }
                if body_registration == body
        ));
        assert!(parse_operation(Mode::Module, &arguments[..2]).is_err());
        assert!(parse_operation(Mode::Build, &arguments).is_err());
        for tail in [
            ["--authored-return", "Keep", "relative.json"],
            [
                "--authored-return",
                "--dependencies",
                body.to_str().unwrap(),
            ],
        ] {
            assert!(parse_operation(Mode::Module, &tail.map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn module_options_keep_the_existing_empty_dependency_and_type_modes() {
        for mode in [Mode::Legacy, Mode::Build, Mode::Tests] {
            assert!(matches!(
                parse_operation(mode, &[]).unwrap(),
                ModuleOperation::Observe(None)
            ));
        }
        assert!(matches!(
            parse_operation(Mode::Module, &[]).unwrap(),
            ModuleOperation::Observe(None)
        ));
        assert!(matches!(
            parse_operation(Mode::Module, &["--dependencies".into()]).unwrap(),
            ModuleOperation::Dependencies
        ));
        let selectors = ["example.test/left", "First", "example.test/right", "Second"];
        let ModuleOperation::Observe(Some(comparison)) =
            parse_operation(Mode::Module, &selectors.map(str::to_owned)).unwrap()
        else {
            panic!("explicit type selectors must retain their original dispatch");
        };
        assert_eq!(comparison.left.package_path, selectors[0]);
        assert_eq!(comparison.left.name, selectors[1]);
        assert_eq!(comparison.right.package_path, selectors[2]);
        assert_eq!(comparison.right.name, selectors[3]);
    }
}
