//! Bounded read-only provider normalization and explicitly authorized execution.

#[path = "junit_ingest.rs"]
mod junit_ingest;
#[path = "sarif_ingest.rs"]
mod sarif_ingest;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::declaration::{DeclarationBinding, canonical};
use crate::heavy_admission::DirectoryIdentity;
use crate::provider::{
    EvidenceEnvelope, ExecutionDescriptor, ExecutionDirectory, FreshExecutionReceipt,
    InvocationBasis, ProviderError, ProviderFormat, ProviderRunManifest, completed_fresh_execution,
    ensure, hash, preflight,
};
use crate::runtime_storage::{RunWorkspace, RuntimeStorage, StoragePolicy};

/// Loads only explicitly selected, content-addressed report pairs. Missing bytes
/// remain unavailable; no directory scan selects a newest or favorable report.
/// Reading an import never executes project code or authenticates its producer.
///
/// # Errors
/// Refuses linked paths, substituted bytes, malformed reports and aggregate excess.
pub fn load_selected_provider_inputs(
    root: &Path,
    selection: &crate::provider_inputs::EvidenceInputSet,
) -> Result<std::collections::BTreeMap<String, EvidenceEnvelope>, ProviderError> {
    selection.validate()?;
    let mut result = std::collections::BTreeMap::new();
    let mut normalized_budget = crate::provider::NormalizedBudget::default();
    let mut retained = 0_usize;
    for selected in &selection.selected {
        let digest = selected
            .envelope_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| ProviderError::Invalid("selected envelope digest".into()))?;
        let directory = format!("__fortress/evidence/imports/{digest}");
        let envelope = read_import_member(root, &format!("{directory}/envelope.json"))?;
        let payload = read_import_member(root, &format!("{directory}/payload.bin"))?;
        let (Some(envelope), Some(payload)) = (envelope, payload) else {
            continue;
        };
        retained = retained
            .checked_add(envelope.len())
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or(ProviderError::ResourceLimit("selected imports"))?;
        if retained > crate::provider::MAX_PROVIDER_NORMALIZED_BYTES {
            return Err(ProviderError::ResourceLimit("selected imports"));
        }
        let text = std::str::from_utf8(&envelope)
            .map_err(|_| ProviderError::Invalid("provider envelope requires UTF-8".into()))?;
        let envelope = EvidenceEnvelope::from_json_str(text)?;
        ensure(
            envelope.digest()? == selected.envelope_digest
                && envelope.payload_digest == selected.payload_digest
                && hash(&payload) == selected.payload_digest,
            "selected imported bytes differ",
        )?;
        let reconstructed = match envelope.format {
            ProviderFormat::JunitXml => match (&envelope.provider, &envelope.provider_version) {
                (Some(provider), Some(version)) => {
                    ingest_junit(&payload, envelope.run_manifest.clone(), provider, version)?
                }
                (None, None) if envelope.run_manifest.is_none() => {
                    ingest_junit_observations(&payload)?
                }
                _ => {
                    return Err(ProviderError::Invalid(
                        "unsupported partial JUnit producer identity".into(),
                    ));
                }
            },
            ProviderFormat::Sarif210 => ingest_sarif(&payload, envelope.run_manifest.clone())?,
            ProviderFormat::CargoSuite => {
                return Err(ProviderError::Invalid(
                    "controlled Cargo evidence requires the owned source/inventory adapter".into(),
                ));
            }
        };
        ensure(
            envelope == reconstructed,
            "raw payload does not reproduce selected provider envelope",
        )?;
        envelope.validate_into(&mut normalized_budget)?;
        result.insert(selected.envelope_digest.clone(), envelope);
    }
    Ok(result)
}

fn read_import_member(root: &Path, relative: &str) -> Result<Option<Vec<u8>>, ProviderError> {
    let mut pinned = vec![(root.to_path_buf(), DirectoryIdentity::pin(root)?)];
    let mut path = root.to_path_buf();
    for component in relative.split('/') {
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure(
            !metadata.file_type().is_symlink(),
            "linked provider import path",
        )?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure(
                metadata.file_attributes() & 0x400 == 0,
                "reparse provider import path",
            )?;
        }
        if metadata.is_dir() {
            pinned.push((path.clone(), DirectoryIdentity::pin(&path)?));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the member itself rather than following a last-component reparse.
        options.custom_flags(0x0020_0000).share_mode(1);
    }
    let mut file = options.open(&path)?;
    let before = file.metadata()?;
    ensure(before.is_file(), "provider import is not a regular file")?;
    if before.len() > crate::provider::MAX_PROVIDER_BYTES as u64 {
        return Err(ProviderError::ResourceLimit("provider import member"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(crate::provider::MAX_PROVIDER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    preflight(&bytes)?;
    for (path, identity) in &pinned {
        ensure(identity.matches(path)?, "provider import ancestor changed")?;
    }
    let current = fs::symlink_metadata(&path)?;
    ensure(
        !current.file_type().is_symlink() && current.is_file(),
        "provider import member changed kind",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            current.file_attributes() & 0x400 == 0,
            "provider import member became a reparse point",
        )?;
    }
    ensure(
        bytes.len() as u64 == before.len() && file.metadata()?.len() == before.len(),
        "provider import changed during read",
    )?;
    crate::observation::physical::verify_regular(&path, &file, &before)?;
    Ok(Some(bytes))
}

/// Exact structural invocation address supported by the initial SARIF adapter.
pub const SARIF_INVOCATION_SCOPE: &str = sarif_ingest::INVOCATION_SCOPE;

/// Reads bounded single-run SARIF2.1 without executing a tool, fetching external
/// properties, authenticating the producer or deciding software conformance.
///
/// # Errors
/// Refuses malformed, ambiguous, unsupported-scope and resource-excessive input.
pub fn ingest_sarif(
    payload: &[u8],
    manifest: Option<ProviderRunManifest>,
) -> Result<EvidenceEnvelope, ProviderError> {
    sarif_ingest::parse(payload, manifest)
}

/// Retained reporting whose original bytes reproduce its normalized envelope.
pub struct ImportedProviderEvidence {
    /// Deterministic normalized facts, with host admission still external.
    pub envelope: EvidenceEnvelope,
    /// Exact original payload, never replaced by a formatter's interpretation.
    pub payload: Vec<u8>,
}

/// Adapts the existing controlled Cargo record against independently compiled
/// source and inventory identities. Older missing binary/argv/environment data
/// remains explicit unknown and therefore never qualifies for reuse.
///
/// # Errors
/// Rejects contradictory or wrong-source inventories and resource excess.
pub fn ingest_controlled_cargo(
    suite: &crate::certification::RustSuiteExecution,
    expected: &crate::certification::CertificationSourceIdentity,
    binding: &DeclarationBinding,
) -> Result<ImportedProviderEvidence, ProviderError> {
    let (envelope, payload) =
        crate::provider::normalize_controlled_cargo(suite, expected, binding)?;
    Ok(ImportedProviderEvidence { envelope, payload })
}

/// Reads retained `JUnit` without importing project code or launching any process.
///
/// # Errors
/// Refuses malformed XML, contradictory scope or bounded resource excess.
pub fn ingest_junit(
    payload: &[u8],
    manifest: Option<ProviderRunManifest>,
    provider: &str,
    version: &str,
) -> Result<EvidenceEnvelope, ProviderError> {
    preflight(payload)?;
    if let Some(manifest) = &manifest {
        manifest.validate()?;
    }
    let parsed = junit_ingest::parse(payload, manifest.as_ref())?;
    let (invocation, basis) = manifest.as_ref().map_or_else(
        || {
            (
                crate::provider::InvocationOutcome::default(),
                InvocationBasis::Unknown,
            )
        },
        |m| (m.invocation.clone(), InvocationBasis::CompanionManifest),
    );
    EvidenceEnvelope::compose(
        ProviderFormat::JunitXml,
        Some(provider.into()),
        Some(version.into()),
        hash(payload),
        manifest,
        parsed.observations,
        invocation,
        basis,
        parsed.limitations,
    )
}

/// Imports unbound `JUnit` observations with explicitly unknown original producer
/// and process status. No missing manifest or name can establish complete execution.
///
/// # Errors
/// Refuses the same malformed or resource-excessive XML as the bound adapter.
pub fn ingest_junit_observations(payload: &[u8]) -> Result<EvidenceEnvelope, ProviderError> {
    let parsed = junit_ingest::parse(payload, None)?;
    EvidenceEnvelope::compose(
        ProviderFormat::JunitXml,
        None,
        None,
        hash(payload),
        None,
        parsed.observations,
        crate::provider::InvocationOutcome::default(),
        InvocationBasis::Unknown,
        parsed.limitations,
    )
}

/// Trusted host registration; never deserialized from a candidate manifest.
#[derive(Debug)]
pub struct RegisteredProviderCommand {
    id: String,
    binary: PathBuf,
    descriptor: ExecutionDescriptor,
    digest: String,
}
impl RegisteredProviderCommand {
    /// Registers the actual executable bytes and exact known argv/directory.
    /// Unknown environment dependencies remain fresh-only.
    ///
    /// # Errors
    /// Refuses absent/mismatched binaries, incomplete command registration or I/O errors.
    pub fn new(
        id: &str,
        binary: &Path,
        descriptor: ExecutionDescriptor,
    ) -> Result<Self, ProviderError> {
        descriptor.validate()?;
        ensure(
            !id.is_empty() && !id.chars().any(char::is_control),
            "registered command identity",
        )?;
        ensure(
            descriptor.arguments.is_some()
                && descriptor.tool_digest.is_some()
                && descriptor.working_directory == Some(ExecutionDirectory::SubjectRoot),
            "registered command needs exact argv/tool/subject directory",
        )?;
        let binary = fs::canonicalize(binary)?;
        ensure(
            descriptor.binary_digest.as_ref() == Some(&binary_digest(&binary)?),
            "registered executable bytes differ",
        )?;
        let digest = hash(
            &canonical(&("registered-provider-command-v1", id, &descriptor))
                .map_err(|e| ProviderError::Invalid(e.to_string()))?,
        );
        Ok(Self {
            id: id.into(),
            binary,
            descriptor,
            digest,
        })
    }
    /// Actual registered executable location; not a semantic cache identity.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }
    /// Exact ordered registered arguments.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        self.descriptor.arguments.as_deref().unwrap_or_default()
    }
    /// Exact execution dependency record, including explicit unknowns.
    #[must_use]
    pub const fn descriptor(&self) -> &ExecutionDescriptor {
        &self.descriptor
    }
    /// Human-readable registry identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Explicit host grant, bound to an open physical project directory and command.
/// Candidate files, producer strings and report imports cannot construct it.
#[derive(Debug)]
pub struct ProjectExecutionTrust {
    directory: DirectoryIdentity,
    command_digest: String,
}
impl ProjectExecutionTrust {
    /// Records an explicit caller authorization for this project and registered command.
    /// The host must obtain owner authorization before calling this operation.
    /// This does not launch a process or authenticate a result.
    ///
    /// # Errors
    /// Refuses directories whose physical identity cannot be established.
    pub fn authorize(
        root: &Path,
        command: &RegisteredProviderCommand,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            directory: DirectoryIdentity::capture(root)?,
            command_digest: command.digest.clone(),
        })
    }
}

/// Actual output returned only after a trusted host runner has reaped its owned
/// process tree. The raw report is normalized again at the orchestration boundary.
pub struct ProviderExecutionOutput {
    /// Original report bytes, retained exactly for independent assessment.
    pub payload: Vec<u8>,
    /// Explicit inventory, attempt accounting and current execution binding.
    pub manifest: ProviderRunManifest,
    /// Actual host-observed successful process completion.
    pub process_succeeded: bool,
    /// Actual host-observed exit code when available.
    pub exit_code: Option<i32>,
}

/// Host execution port, never supplied by a deserialized provider file.
/// Implementors must use the registered binary/argv, bound subject directory,
/// bounded capture and OPS child tracking; return only after all owned children
/// are closed, and preserve uncertainty on any interruption or tracking failure.
pub trait TrustedProviderExecutor {
    /// Executes the already authorized registered command under its owned workspace.
    ///
    /// # Errors
    /// Propagates execution, capture, resource and lifecycle failures.
    fn execute(
        &mut self,
        root: &Path,
        command: &RegisteredProviderCommand,
        workspace: &mut RunWorkspace,
    ) -> Result<ProviderExecutionOutput, ProviderError>;
}

/// A retained actual run with an opaque fresh capability, never a self-claimed flag.
pub struct ExecutedProviderEvidence {
    /// Reconstructed normalized observations, still locally UNVERIFIED.
    pub envelope: EvidenceEnvelope,
    /// Exact original report for independent replay.
    pub payload: Vec<u8>,
    /// Single-use host admission capability for this exact current request.
    pub fresh_receipt: FreshExecutionReceipt,
}

/// Executes only after matching explicit physical-project trust and the exact
/// registered command. The initial runnable adapter is native `JUnit`; SARIF
/// imports remain read-only. Existing canonical Cargo execution is separate.
///
/// # Errors
/// Refuses absent/wrong grants before calling the executor, source/input drift,
/// mismatched process status, malformed output and unresolved resource failures.
#[allow(clippy::too_many_arguments)]
pub fn execute_registered_junit(
    root: &Path,
    trust: Option<&ProjectExecutionTrust>,
    command: &RegisteredProviderCommand,
    expected: &DeclarationBinding,
    storage_root: &Path,
    policy: StoragePolicy,
    executor: &mut impl TrustedProviderExecutor,
) -> Result<ExecutedProviderEvidence, ProviderError> {
    let trust = trust.ok_or_else(|| {
        ProviderError::Invalid("explicit project execution trust is required".into())
    })?;
    ensure(
        trust.command_digest == command.digest && trust.directory.matches(root)?,
        "execution grant differs from physical project/registered command",
    )?;
    ensure(
        command.descriptor.binary_digest.as_ref() == Some(&binary_digest(&command.binary)?),
        "registered binary changed",
    )?;
    let before = crate::audit::prepare_repository_certification_source(root)
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    let view = crate::audit::compile_repository_state_view(root)
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    let actual = view.application.as_ref().ok_or_else(|| {
        ProviderError::Invalid("current governed application binding is required".into())
    })?;
    ensure(
        &actual.declaration.binding == expected,
        "execution request is not the current application binding",
    )?;
    let storage = RuntimeStorage::new(root, storage_root, policy)?;
    let mut workspace = storage.acquire_workspace()?;
    let output = executor.execute(root, command, &mut workspace)?;
    workspace.ensure_children_closed()?;
    preflight(&output.payload)?;
    workspace.reserve(
        u64::try_from(output.payload.len())
            .map_err(|_| ProviderError::ResourceLimit("captured payload"))?,
    )?;
    ensure(
        output.manifest.binding == *expected && output.manifest.execution == command.descriptor,
        "executor returned another request",
    )?;
    ensure(
        output.manifest.invocation.succeeded == Some(output.process_succeeded)
            && output.manifest.invocation.exit_code == output.exit_code,
        "companion differs from actual executor process outcome",
    )?;
    let envelope = ingest_junit(
        &output.payload,
        Some(output.manifest.clone()),
        &output.manifest.provider,
        &output.manifest.provider_version,
    )?;
    let after = crate::audit::prepare_repository_certification_source(root)
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    let after_view = crate::audit::compile_repository_state_view(root)
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    ensure(
        before == after
            && after_view
                .application
                .as_ref()
                .is_some_and(|a| &a.declaration.binding == expected)
            && trust.directory.matches(root)?,
        "source/context/inventory changed during registered execution",
    )?;
    ensure(
        command.descriptor.binary_digest.as_ref() == Some(&binary_digest(&command.binary)?),
        "registered binary changed during execution",
    )?;
    workspace.validating()?;
    workspace.publish(&envelope.digest()?)?;
    let report = workspace.release()?;
    ensure(
        report.lifecycle == "CLEANUP_COMPLETE",
        "provider run requires unresolved lifecycle recovery",
    )?;
    let receipt = completed_fresh_execution(&envelope, expected, &command.descriptor)?;
    Ok(ExecutedProviderEvidence {
        envelope,
        payload: output.payload,
        fresh_receipt: receipt,
    })
}

fn binary_digest(path: &Path) -> Result<String, ProviderError> {
    const LIMIT: u64 = 256 * 1024 * 1024;
    let mut file = crate::observation::physical::open_regular(path)?;
    let before = file.metadata()?;
    ensure(before.is_file(), "registered binary is not a regular file")?;
    if before.len() > LIMIT {
        return Err(ProviderError::ResourceLimit("registered binary"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| ProviderError::ResourceLimit("registered binary"))?,
            )
            .ok_or(ProviderError::ResourceLimit("registered binary"))?;
        if total > LIMIT {
            return Err(ProviderError::ResourceLimit("registered binary"));
        }
        hasher.update(&buffer[..count]);
    }
    ensure(
        file.metadata()?.len() == before.len() && total == before.len(),
        "registered binary changed while hashing",
    )?;
    crate::observation::physical::verify_regular(path, &file, &before)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
