//! Read-only native normalization; original payload bytes stay external inputs.
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let result = normalize(arguments);
    match result {
        Ok((destination, bytes)) => {
            super::write_projection(destination, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "provider import failed: {failure}\nusage: fortress evidence junit|sarif payload [--manifest path] [--output path]"
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}
fn normalize(arguments: &[String]) -> Result<(Option<PathBuf>, Vec<u8>), String> {
    use fortress_core::evidence_ingest::{ingest_junit, ingest_junit_observations, ingest_sarif};
    use fortress_core::provider::{MAX_PROVIDER_BYTES, ProviderRunManifest};
    let [format, payload, rest @ ..] = arguments else {
        return Err("format and original payload are required".into());
    };
    let mut manifest = None;
    let mut destination = None;
    let mut index = 0;
    while index < rest.len() {
        let slot = match rest[index].as_str() {
            "--manifest" => &mut manifest,
            "--output" => &mut destination,
            _ => return Err("unknown provider argument".into()),
        };
        if slot.is_some() {
            return Err("duplicate provider argument".into());
        }
        index += 1;
        let value = rest
            .get(index)
            .filter(|v| !v.starts_with('-'))
            .ok_or("provider option needs a path")?;
        *slot = Some(PathBuf::from(value));
        index += 1;
    }
    let payload = read_bounded(Path::new(payload), MAX_PROVIDER_BYTES)?;
    let manifest = manifest
        .map(|path| -> Result<_, String> {
            let bytes = read_bounded(&path, MAX_PROVIDER_BYTES)?;
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            ProviderRunManifest::from_json_str(text).map_err(|e| e.to_string())
        })
        .transpose()?;
    let envelope = match format.as_str() {
        "junit" => {
            if let Some(manifest) = manifest {
                let provider = manifest.provider.clone();
                let version = manifest.provider_version.clone();
                ingest_junit(&payload, Some(manifest), &provider, &version)
            } else {
                ingest_junit_observations(&payload)
            }
        }
        "sarif" => ingest_sarif(&payload, manifest),
        _ => return Err("supported formats are junit and sarif".into()),
    }
    .map_err(|e| e.to_string())?;
    Ok((
        destination,
        envelope.to_canonical_bytes().map_err(|e| e.to_string())?,
    ))
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("provider input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("provider input exceeds resource bound".into());
    }
    Ok(bytes)
}
