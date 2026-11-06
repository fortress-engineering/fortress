//! Explicit retained-evidence selection and out-of-candidate host admission.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(super) struct ApplicationInputArguments {
    pub(super) arguments: Vec<String>,
    selection: Option<PathBuf>,
    host_policy: Option<PathBuf>,
}

pub(super) fn split(arguments: &[String]) -> Result<ApplicationInputArguments, String> {
    let mut result = ApplicationInputArguments {
        arguments: vec![],
        selection: None,
        host_policy: None,
    };
    let mut index = 0;
    while index < arguments.len() {
        let slot = match arguments[index].as_str() {
            "--evidence-inputs" => Some(&mut result.selection),
            "--provider-policy" => Some(&mut result.host_policy),
            _ => None,
        };
        if let Some(slot) = slot {
            if slot.is_some() {
                return Err("duplicate provider argument".into());
            }
            index += 1;
            let value = arguments
                .get(index)
                .filter(|v| !v.starts_with('-'))
                .ok_or("provider argument needs a path")?;
            *slot = Some(PathBuf::from(value));
        } else {
            result.arguments.push(arguments[index].clone());
        }
        index += 1;
    }
    if result.host_policy.is_some() && result.selection.is_none() {
        return Err("host policy requires explicit evidence selection".into());
    }
    Ok(result)
}

pub(super) fn capture(
    root: &Path,
    inputs: &ApplicationInputArguments,
) -> Result<fortress_core::audit::StateView, String> {
    let Some(selection) = &inputs.selection else {
        return fortress_core::audit::compile_repository_state_view(root)
            .map_err(|e| e.to_string());
    };
    let selection = read_bounded(selection, 32 * 1024 * 1024)?;
    let selection = fortress_core::provider_inputs::EvidenceInputSet::from_json_str(&selection)
        .map_err(|e| e.to_string())?;
    let mut policy = if let Some(path) = &inputs.host_policy {
        let subject = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
        let authority = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
        if authority.starts_with(&subject) {
            return Err("provider policy must be an explicit host file outside the physical candidate repository".into());
        }
        fortress_core::provider::ProviderAcceptancePolicy::from_explicit_host_json(&read_bounded(
            &authority,
            1024 * 1024,
        )?)
        .map_err(|e| e.to_string())?
    } else {
        fortress_core::provider::ProviderAcceptancePolicy::default()
    };
    fortress_core::audit::compile_repository_state_view_with_evidence(root, &selection, &mut policy)
        .map_err(|e| e.to_string())
}

fn read_bounded(path: &Path, limit: u64) -> Result<String, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("provider input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("provider input exceeds resource bound".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
