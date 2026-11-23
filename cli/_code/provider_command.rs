//! Read-only native normalization; original payload bytes stay external inputs.
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fortress_core::provider::{
    EvidenceAdapter, EvidenceEnvelope, ProviderFormat, ProviderRunManifest,
};

#[path = "provider_collection.rs"]
mod collection;

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let result = if arguments.first().is_some_and(|verb| verb == "collect") {
        collection::collect(&arguments[1..]).map(|bytes| (None, bytes))
    } else {
        normalize(arguments)
    };
    match result {
        Ok((destination, bytes)) => {
            super::write_projection(destination, output, &bytes)?;
            Ok(super::EXIT_SUCCESS)
        }
        Err(failure) => {
            writeln!(
                error,
                "provider import failed: {}\nusage: fortress evidence junit|sarif payload [--manifest path] [--adapter path sha256:digest] [--output path]; fortress evidence collect host-registration request project-root",
                fortress_core::wire::readable_text(&failure)
            )?;
            Ok(super::EXIT_USAGE)
        }
    }
}
fn normalize(arguments: &[String]) -> Result<(Option<PathBuf>, Vec<u8>), String> {
    use fortress_core::provider::MAX_PROVIDER_BYTES;
    let [format, payload, rest @ ..] = arguments else {
        return Err("format and original payload are required".into());
    };
    let mut manifest = None;
    let mut destination = None;
    let mut adapter = None;
    let mut index = 0;
    while index < rest.len() {
        if rest[index] == "--adapter" {
            if adapter.is_some() {
                return Err("duplicate adapter argument".into());
            }
            let [file, pin, ..] = &rest[index + 1..] else {
                return Err("adapter requires a file and exact digest".into());
            };
            adapter = Some(read_adapter(Path::new(file), pin)?);
            index += 3;
            continue;
        }
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
    let format = match format.as_str() {
        "junit" => ProviderFormat::JunitXml,
        "sarif" => ProviderFormat::Sarif210,
        _ => return Err("supported formats are junit and sarif".into()),
    };
    if let Some(adapter) = adapter {
        adapter.validate_manifest(
            format,
            manifest
                .as_ref()
                .ok_or("adapter requires an exact companion manifest")?,
        )?;
    }
    let envelope = normalize_payload(format, &payload, manifest)?;
    Ok((
        destination,
        envelope.to_canonical_bytes().map_err(|e| e.to_string())?,
    ))
}

fn normalize_payload(
    format: ProviderFormat,
    payload: &[u8],
    manifest: Option<ProviderRunManifest>,
) -> Result<EvidenceEnvelope, String> {
    use fortress_core::evidence_ingest::{ingest_junit, ingest_junit_observations, ingest_sarif};
    match format {
        ProviderFormat::JunitXml => {
            if let Some(manifest) = manifest {
                let provider = manifest.provider.clone();
                let version = manifest.provider_version.clone();
                ingest_junit(payload, Some(manifest), &provider, &version)
            } else {
                ingest_junit_observations(payload)
            }
        }
        ProviderFormat::Sarif210 => ingest_sarif(payload, manifest),
        ProviderFormat::CargoSuite => return Err("unsupported external Cargo executor".into()),
    }
    .map_err(|e| e.to_string())
}

fn read_adapter(path: &Path, pin: &str) -> Result<EvidenceAdapter, String> {
    use fortress_core::control_layout::ExtensionInputRole;
    let bytes = read_bounded(path, ExtensionInputRole::EvidenceAdapter.definition_bytes())?;
    EvidenceAdapter::from_pinned_bytes(&bytes, pin)
}

pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    use fortress_core::observation::physical;
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    for parent in absolute.ancestors().skip(1) {
        let metadata = parent.symlink_metadata().map_err(|e| e.to_string())?;
        if physical::linked(&metadata) || !metadata.is_dir() {
            return Err("UNSAFE_PATH: linked or non-directory ancestor".into());
        }
    }
    let mut file = physical::open_regular(&absolute).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.len() > limit as u64 {
        return Err("provider input exceeds resource bound".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("provider input exceeds resource bound".into());
    }
    physical::verify_regular(&absolute, &file, &metadata).map_err(|e| e.to_string())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("SOURCE_DRIFT: incomplete input read".into());
    }
    Ok(bytes)
}
