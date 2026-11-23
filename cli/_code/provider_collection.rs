//! Explicitly pinned local collector execution through the existing bounded subprocess owner.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fortress_core::control_layout::{ControlLayout, ExtensionInputRole};
use fortress_core::portable::{canonical, digest};
use fortress_core::provider::{AdapterOperation, EvidenceAdapter, ProviderAdapterRequest};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_public_json};
use serde::Deserialize;
use serde_json::json;

const MAXIMUM: usize = 64 * 1024;
const REGISTRATION: &str = "urn:fortress:host:v1:evidence-collector-registration";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    executable: PathBuf,
    executable_digest: String,
    adapter: PathBuf,
    adapter_digest: String,
    script: Option<Script>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    path: PathBuf,
    digest: String,
}

pub(super) fn collect(arguments: &[String]) -> Result<Vec<u8>, String> {
    let [file, request, root] = arguments else {
        return Err(
            "collector requires explicit host registration, request and project root".into(),
        );
    };
    let file = Path::new(file);
    let root = Path::new(root)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    crate::verifier_process::require_external_asset(file, &root)?;
    let bytes = super::read_bounded(file, MAXIMUM)?;
    admit_json(
        &bytes,
        JsonAdmissionLimits {
            bytes: MAXIMUM,
            depth: 8,
            nodes: 256,
            token_bytes: 4096,
        },
    )
    .map_err(|error| error.to_string())?;
    let registration: Registration =
        parse_public_json(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if registration.schema != REGISTRATION || registration.schema_version != 1 {
        return Err("UNSUPPORTED_COLLECTOR_REGISTRATION_VERSION".into());
    }
    let directory = file
        .parent()
        .ok_or("host registration needs an external directory")?;
    crate::verifier_process::require_external_asset(&registration.executable, &root)?;
    crate::verifier_process::require_external_asset(&registration.adapter, &root)?;
    if let Some(script) = &registration.script {
        crate::verifier_process::require_external_asset(&script.path, &root)?;
        script.verify()?;
    }
    let adapter = super::read_adapter(&registration.adapter, &registration.adapter_digest)?;
    let input = super::read_bounded(Path::new(request), MAXIMUM)?;
    let request_digest = digest(&input);
    let request = ProviderAdapterRequest::from_bytes(&input)?;
    let reply = registration.exchange(directory, &adapter, input, &request)?;
    if bytes != super::read_bounded(file, MAXIMUM)? {
        return Err("SOURCE_DRIFT: collector registration changed".into());
    }
    if let Some(script) = &registration.script {
        script.verify()?;
    }
    super::read_adapter(&registration.adapter, &registration.adapter_digest)?;
    let data = match (reply.raw_utf8, reply.manifest) {
        (Some(raw), Some(manifest)) => {
            let envelope =
                super::normalize_payload(adapter.format(), raw.as_bytes(), Some(manifest))?;
            let envelope_digest = envelope.digest().map_err(|error| error.to_string())?;
            let layout = ControlLayout::standard();
            let retained = ExtensionInputRole::EvidenceAdapter
                .retained_roles()
                .iter()
                .map(|role| {
                    layout
                        .provider_path(&envelope_digest, *role)
                        .ok_or("missing required CONTROL role")
                })
                .collect::<Result<Vec<_>, _>>()?;
            json!({"outcome":"REPORTED", "raw_utf8":raw, "envelope":envelope, "retained_paths":retained})
        }
        _ => json!({"outcome": match request.operation {
            AdapterOperation::Hello => "CAPABILITIES",
            AdapterOperation::Cancel => "CANCELLED",
            AdapterOperation::Collect => "UNAVAILABLE",
        }}),
    };
    canonical(&json!({
        "$schema": "urn:fortress:schema:v1:evidence-collector-report",
        "schema_version": 1, "request_id": request.request_id, "request_digest": request_digest,
        "adapter_digest": registration.adapter_digest,
        "capabilities": adapter.capabilities(),
        "producer_authenticity": "UNVERIFIED",
        "evidence_admission": ExtensionInputRole::EvidenceAdapter.authority(),
        "result": data,
    }))
    .map_err(|error| error.to_string())
}

impl Script {
    fn verify(&self) -> Result<(), String> {
        if digest(&super::read_bounded(&self.path, MAXIMUM)?) != self.digest {
            return Err("COLLECTOR_SCRIPT_DIGEST_MISMATCH".into());
        }
        Ok(())
    }
}

impl Registration {
    fn exchange(
        &self,
        directory: &Path,
        adapter: &EvidenceAdapter,
        input: Vec<u8>,
        request: &ProviderAdapterRequest,
    ) -> Result<fortress_core::provider::AdapterResult, String> {
        if request.operation == AdapterOperation::Collect {
            let hello = canonical(&json!({
                "$schema":"urn:fortress:schema:v1:evidence-adapter-exchange",
                "schema_version":1, "operation":"HELLO",
                "request_id":request.request_id, "binding":null, "invocation_scope":null,
            }))
            .map_err(|error| error.to_string())?;
            let control = ProviderAdapterRequest::from_bytes(&hello)?;
            adapter.validate_reply(&control, &self.run(directory, hello)?)?;
        }
        adapter.validate_reply(request, &self.run(directory, input)?)
    }

    fn run(&self, directory: &Path, input: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut command = Command::new(&self.executable);
        command.env_clear().current_dir(directory);
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        if let Some(script) = &self.script {
            command.args(["-I", "-B"]).arg(&script.path);
        }
        let (output, status) = crate::verifier_process::run_pinned_input(
            command,
            input,
            Duration::from_secs(5),
            &self.executable_digest,
        )
        .map_err(|error| format!("COLLECTOR_{}", error.code))?;
        if status != 0 {
            return Err("COLLECTOR_EXIT_FAILURE".into());
        }
        Ok(output)
    }
}
