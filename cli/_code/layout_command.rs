//! Read-only native layout profile selection.

use std::io::{self, Write};
use std::path::Path;

use fortress_core::filing::{LayoutExtension, ObservedLayoutPath, inspect_layout_extensions};
use fortress_core::observation::{ObservationPolicy, observe_source_manifest};

const USAGE: &str =
    "fortress layout inspect path --profile file sha256:digest [--profile file sha256:digest ...]";

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match inspect(arguments) {
        Ok(bytes) => {
            output.write_all(&bytes)?;
            output.write_all(b"\n")?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "{}\nusage: {USAGE}",
                fortress_core::wire::readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}

fn inspect(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [verb, root, flags @ ..] = arguments else {
        return Err("layout requires an explicit repository and selection".into());
    };
    if verb != "inspect" || flags.is_empty() || flags.len() > 48 || !flags.len().is_multiple_of(3) {
        return Err("unsupported layout operation or selection count".into());
    }
    let profiles = flags
        .chunks_exact(3)
        .map(|row| {
            if row[0] != "--profile" {
                return Err("invalid layout selection option".into());
            }
            let bytes = super::provider_command::read_bounded(Path::new(&row[1]), 64 * 1024)?;
            LayoutExtension::from_pinned_bytes(&bytes, &row[2])
        })
        .collect::<Result<Vec<_>, String>>()?;
    let observed = observe_source_manifest(root, &ObservationPolicy::default())
        .map_err(|error| error.to_string())?;
    let paths = observed
        .entries()
        .iter()
        .map(|entry| ObservedLayoutPath {
            path: entry.repository_relative_path(),
            limitation: entry.limitation_ref(),
        })
        .collect::<Vec<_>>();
    let report = inspect_layout_extensions(&paths, observed.entries_digest(), &profiles)?;
    fortress_core::portable::canonical(&report).map_err(|error| error.to_string())
}
