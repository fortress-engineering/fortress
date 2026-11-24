//! Explicit stdio host for the pinned Go filesystem observer.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fortress_core::go_observation::{
    GoCollectorPin, GoFilesystemHost, GoFilesystemLibraryPin, GoPackageSelection,
    observe_go_filesystem_effects,
};
use fortress_core::portable::{canonical, digest};
use fortress_core::wire::{
    JsonAdmissionLimits, admit_json, parse_strict_json_bytes, readable_text,
};
use serde::Deserialize;
use serde_json::json;

use super::go_body_command::{ENVIRONMENT, TIMEOUT, prepare_native_go_launch};
use super::provider_command::read_bounded;
use super::verifier_process::require_external_asset;

const SCHEMA: &str = "urn:fortress:host:v1:go-filesystem-registration";
const RECIPE: &str = "INSTALLED_STDLIB_GC_NO_CGO_V1";
const MODE: &str = "--observe-go-filesystem";
const REGISTRATION_LIMIT: usize = 16 * 1024;
const USAGE: &str = "fortress psm --observe-go-filesystem project host-registration directory package-path go-version target-os target-arch";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    executable: PathBuf,
    executable_sha256: String,
    toolchain: String,
    package_source_ref: String,
    export_set_ref: String,
    preparation: String,
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
                "Go filesystem observation failed: {}\nusage: {USAGE}",
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
            "An exact project, external registration and target context are required.".into(),
        );
    };
    let root = Path::new(root)
        .canonicalize()
        .map_err(|failure| failure.to_string())?;
    let registration = Path::new(registration);
    require_external_asset(registration, &root)?;
    let original = read_bounded(registration, REGISTRATION_LIMIT)?;
    admit_json(
        &original,
        JsonAdmissionLimits {
            bytes: REGISTRATION_LIMIT,
            depth: 4,
            nodes: 48,
            token_bytes: 4096,
        },
    )
    .map_err(|failure| failure.to_string())?;
    let declared: Registration =
        parse_strict_json_bytes(&original).map_err(|failure| failure.to_string())?;
    if declared.schema != SCHEMA || declared.schema_version != 1 || declared.preparation != RECIPE {
        return Err("UNSUPPORTED_FILESYSTEM_REGISTRATION_CONTEXT".into());
    }
    require_external_asset(&declared.executable, &root)?;
    let host_directory = registration
        .parent()
        .ok_or("Missing registration directory")?;
    let (launch, system_root) = prepare_native_go_launch(
        &declared.executable,
        &declared.executable_sha256,
        host_directory,
        MODE,
    );
    let context = canonical(&json!({
        "format":"pinned-go-filesystem-collector-host-v1",
        "registration_ref":digest(&original),
        "transport":"bounded_one_shot_stdio",
        "selected_mode": MODE,
        "timeout_ms":TIMEOUT.as_millis(),
        "environment":ENVIRONMENT,
        "host_os":std::env::consts::OS,
        "host_arch":std::env::consts::ARCH,
        "system_root_ref":system_root.as_ref().map(|path| digest(path.as_bytes())),
    }))
    .map_err(|failure| failure.to_string())?;
    let pin = GoCollectorPin {
        executable_sha256: &declared.executable_sha256,
        supervisor_context_sha256: &digest(&context),
        go_toolchain: &declared.toolchain,
    };
    let report = observe_go_filesystem_effects(
        &root,
        GoPackageSelection {
            directory: if directory == "." { "" } else { directory },
            package_path,
            go_version,
            target_os,
            target_arch,
        },
        GoFilesystemHost {
            collector: &pin,
            library: GoFilesystemLibraryPin {
                package_source_ref: &declared.package_source_ref,
                export_set_ref: &declared.export_set_ref,
            },
        },
        |request| launch.run(request),
    )
    .map_err(|failure| failure.to_string())?;
    require_external_asset(registration, &root)?;
    if read_bounded(registration, REGISTRATION_LIMIT)? != original {
        return Err("SOURCE_DRIFT: Native collector registration changed.".into());
    }
    let value = serde_json::to_value(report).map_err(|failure| failure.to_string())?;
    canonical(&value).map_err(|failure| failure.to_string())
}
