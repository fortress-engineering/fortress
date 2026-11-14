//! Explicit external materialization of one complete canonical static stack.
use fortress_core::audit::{
    compile_repository_projection_bundle, prepare_repository_certification_source,
};
use fortress_core::heavy_admission::DirectoryIdentity;
use fortress_core::observation::physical;
use fortress_core::portable::digest;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const USAGE: &str =
    "usage: fortress projections [path] --output-dir new-external-directory [--format human|json]";
const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_MEMBER_BYTES: usize = 512 * 1024 * 1024;

fn parse(arguments: &[String]) -> Result<(PathBuf, PathBuf, bool), String> {
    let (mut root, mut destination, mut human) = (None, None, true);
    let mut arguments = arguments.iter();
    while let Some(value) = arguments.next() {
        match value.as_str() {
            "--output-dir" if destination.is_none() => {
                destination = Some(PathBuf::from(arguments.next().ok_or(USAGE)?));
            }
            "--format" => {
                human = match arguments.next().map(String::as_str) {
                    Some("human") => true,
                    Some("json") => false,
                    _ => return Err(USAGE.into()),
                }
            }
            value if !value.starts_with('-') && root.is_none() => root = Some(PathBuf::from(value)),
            _ => return Err(USAGE.into()),
        }
    }
    Ok((
        root.unwrap_or_else(|| PathBuf::from(".")),
        destination.ok_or(USAGE)?,
        human,
    ))
}

fn admit_destination(root: &Path, destination: &Path) -> io::Result<(PathBuf, DirectoryIdentity)> {
    if destination
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::other("UNSAFE_PATH: parent traversal"));
    }
    let destination = std::path::absolute(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("UNSAFE_PATH: output parent missing"))?;
    let repository = DirectoryIdentity::capture(root)?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if repository.matches(ancestor)? {
            return Err(io::Error::other(
                "UNSAFE_PATH: output is physically inside source",
            ));
        }
        if physical::linked(&metadata) || !metadata.is_dir() {
            return Err(io::Error::other(
                "UNSAFE_PATH: output ancestor is not ordinary",
            ));
        }
    }
    let parent = parent.canonicalize()?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| io::Error::other("UNSAFE_PATH: output name missing"))?,
    );
    if destination.starts_with(root.canonicalize()?) || fs::symlink_metadata(&destination).is_ok() {
        return Err(io::Error::other(
            "UNSAFE_PATH: output must be a new directory outside source",
        ));
    }
    Ok((destination, DirectoryIdentity::capture(&parent)?))
}

fn admit_measurements(
    phases: &[fortress_core::audit::EvaluationPhaseMeasurement],
) -> io::Result<()> {
    for phase in phases {
        for count in [
            Some(phase.wall_time_ns),
            phase.process_cpu_time_ms,
            phase
                .resident_bytes_before
                .map(|v| u64::try_from(v).unwrap_or(u64::MAX)),
            phase
                .resident_bytes_after
                .map(|v| u64::try_from(v).unwrap_or(u64::MAX)),
            phase
                .platform_virtual_bytes_before
                .map(|v| u64::try_from(v).unwrap_or(u64::MAX)),
            phase
                .platform_virtual_bytes_after
                .map(|v| u64::try_from(v).unwrap_or(u64::MAX)),
            Some(phase.collector_wall_time_ns),
        ] {
            if count.is_some_and(|value| value > 9_007_199_254_740_991) {
                return Err(io::Error::other(
                    "RESOURCE_LIMIT: diagnostic integer outside exact public range",
                ));
            }
        }
    }
    Ok(())
}

fn materialize(root: &Path, destination: &Path) -> io::Result<Value> {
    let (destination, parent) = admit_destination(root, destination)?;
    let before = prepare_repository_certification_source(root).map_err(io::Error::other)?;
    let bundle = compile_repository_projection_bundle(root).map_err(io::Error::other)?;
    if bundle.source_ref != before.digest
        || prepare_repository_certification_source(root).map_err(io::Error::other)? != before
    {
        return Err(io::Error::other(
            "SOURCE_DRIFT: projection inputs changed during construction",
        ));
    }
    admit_measurements(&bundle.phase_measurements)?;
    let mut names = BTreeSet::new();
    let mut total = 0_usize;
    for (logical, bytes) in &bundle.projections {
        if bytes.len() > MAX_MEMBER_BYTES {
            return Err(io::Error::other(
                "RESOURCE_LIMIT: projection member exceeds 512 MiB",
            ));
        }
        let name = Path::new(logical)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("INVALID_PROJECTION_PATH"))?;
        if !names.insert(name) || name == "manifest.json" {
            return Err(io::Error::other("AMBIGUOUS_PROJECTION_PATH"));
        }
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_OUTPUT_BYTES)
            .ok_or_else(|| io::Error::other("RESOURCE_LIMIT: projection output exceeds two GiB"))?;
    }
    let parent_path = destination
        .parent()
        .ok_or_else(|| io::Error::other("UNSAFE_PATH"))?;
    if !parent.matches(parent_path)? {
        return Err(io::Error::other("SOURCE_DRIFT: output parent changed"));
    }
    fs::create_dir(&destination)?;
    let owned = DirectoryIdentity::capture(&destination)?;
    let mut files = Vec::new();
    let mut retained = Vec::new();
    for (logical, bytes) in &bundle.projections {
        if !parent.matches(parent_path)? || !owned.matches(&destination)? {
            return Err(io::Error::other("SOURCE_DRIFT: output directory changed"));
        }
        let name = Path::new(logical)
            .file_name()
            .ok_or_else(|| io::Error::other("INVALID_PROJECTION_PATH"))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(name))?;
        output.write_all(bytes.as_bytes())?;
        output.sync_all()?;
        let metadata = output.metadata()?;
        physical::verify_regular(&destination.join(name), &output, &metadata)?;
        retained.push((destination.join(name), output, metadata));
        files.push(json!({"logical_path":logical,"file_name":name.to_str(),"bytes":bytes.len(),"digest":digest(bytes.as_bytes())}));
    }
    let result = json!({"$schema":"urn:fortress:diagnostic:v1:projection-materialization","schema_version":1,"claim":"STATIC_PROJECTIONS_ONLY","source_domain":"CERTIFICATION_SOURCE_IDENTITY","source_ref":bundle.source_ref,"execution":"NOT_RUN","certification":"NOT_ISSUED","authenticity":"UNVERIFIED","complete":true,"files":files,"phase_measurements":bundle.phase_measurements});
    if !parent.matches(parent_path)? || !owned.matches(&destination)? {
        return Err(io::Error::other("SOURCE_DRIFT: output directory changed"));
    }
    for (path, handle, metadata) in &retained {
        physical::verify_regular(path, handle, metadata)?;
    }
    if prepare_repository_certification_source(root).map_err(io::Error::other)? != before {
        return Err(io::Error::other(
            "SOURCE_DRIFT: projection inputs changed before completion",
        ));
    }
    // This completion marker is last. A partial directory is never a complete bundle.
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("manifest.json"))?;
    serde_json::to_writer_pretty(&mut marker, &result).map_err(io::Error::other)?;
    marker.write_all(b"\n")?;
    marker.sync_all()?;
    if !parent.matches(parent_path)? || !owned.matches(&destination)? {
        return Err(io::Error::other("SOURCE_DRIFT: output directory changed"));
    }
    for (path, handle, metadata) in &retained {
        physical::verify_regular(path, handle, metadata)?;
    }
    Ok(result)
}

pub(super) fn run(
    arguments: &[String],
    output: &mut impl Write,
    error: &mut impl Write,
) -> io::Result<u8> {
    let (root, destination, human) = match parse(arguments) {
        Ok(v) => v,
        Err(e) => {
            writeln!(error, "{e}")?;
            return Ok(super::EXIT_USAGE);
        }
    };
    match materialize(&root, &destination) {
        Ok(result) => {
            if human {
                writeln!(
                    output,
                    "{}",
                    fortress_core::query::render_inspection_value(&result)
                )?;
            } else {
                serde_json::to_writer_pretty(&mut *output, &result).map_err(io::Error::other)?;
                writeln!(output)?;
            }
            Ok(super::EXIT_SUCCESS)
        }
        Err(e) => {
            writeln!(
                error,
                "{}",
                json!({"error":{"code":"MATERIALIZATION_FAILED","message":e.to_string()}})
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}
