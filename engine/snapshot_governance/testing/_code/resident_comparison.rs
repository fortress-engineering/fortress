//! Bounded consumer snapshots for serial exact-byte resident comparisons.
//!
//! These allocations belong to the comparison client, outside the Session's
//! model account. The estimate admits retained input backing, not just its Arc,
//! and is an operational allocation estimate rather than a process-RSS bound.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::mem::size_of;

use fortress_core::certification::certification_source_digest;
use fortress_core::observation::SourceView;
use fortress_core::program_semantics::ProgramContext;
use fortress_core::session::Generation;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) const MAX_COMPARISON_SCRATCH_BYTES: usize = 1024 * 1024 * 1024;
const MEMBER_COUNT: usize = 11;
const ENTRY_ALLOWANCE: usize = 2048;
const VALUE_ALLOCATION_MULTIPLIER: usize = 256;
const CONTEXT_COPIES: usize = 8;
const METADATA_COPIES: usize = 8;
const FIXED_ALLOWANCE: usize = 64 * 1024;
const PLACEHOLDER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug)]
pub(super) struct ComparisonError(&'static str);

impl Display for ComparisonError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ComparisonError {}

pub(super) fn checked_scratch_sum(
    parts: impl IntoIterator<Item = usize>,
) -> Result<usize, ComparisonError> {
    parts.into_iter().try_fold(0_usize, |sum, part| {
        sum.checked_add(part)
            .ok_or(ComparisonError("comparison scratch charge overflow"))
    })
}

fn scaled(bytes: usize, multiplier: usize) -> Result<usize, ComparisonError> {
    bytes
        .checked_mul(multiplier)
        .ok_or(ComparisonError("comparison scratch charge overflow"))
}

struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= MAX_COMPARISON_SCRATCH_BYTES)
            .ok_or_else(|| io::Error::other("comparison context exceeds scratch limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_digest(value: &impl Serialize, pretty: bool) -> String {
    let mut writer = HashWriter(Sha256::new());
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value).expect("fixed context serializes");
        writer.write_all(b"\n").expect("hash writer is infallible");
    } else {
        serde_json::to_writer(&mut writer, value).expect("fixed context serializes");
    }
    format!("sha256:{:x}", writer.0.finalize())
}

#[derive(Serialize)]
struct AvailabilityContext<'a> {
    entries: usize,
    inventory_digest: Cow<'a, str>,
    scope: &'static str,
}

#[derive(Serialize)]
struct GenerationContext<'a> {
    repository_identity: &'a str,
    source_view_digest: &'a str,
    source_manifest_entries_digest: &'a str,
    source_manifest_document_digest: Cow<'a, str>,
    certification_source_digest: Cow<'a, str>,
    program_source_identity: &'a str,
    program_context: &'a ProgramContext,
    context_digest: &'a str,
    authority_digest: &'a str,
    input_revision: &'a str,
    source_files: usize,
    source_bytes: usize,
    symbols: usize,
    calls: usize,
    execution_evidence_present: bool,
    operational_availability: AvailabilityContext<'a>,
}

fn borrowed_context(generation: &Generation, digests: bool) -> GenerationContext<'_> {
    GenerationContext {
        repository_identity: generation.repository_identity(),
        source_view_digest: generation.source_view().digest(),
        source_manifest_entries_digest: generation.source_manifest().entries_digest(),
        source_manifest_document_digest: if digests {
            Cow::Owned(serialized_digest(generation.source_manifest(), true))
        } else {
            Cow::Borrowed(PLACEHOLDER_DIGEST)
        },
        certification_source_digest: if digests {
            Cow::Owned(certification_source_digest(
                generation.source_view().files(),
            ))
        } else {
            Cow::Borrowed(PLACEHOLDER_DIGEST)
        },
        program_source_identity: generation.psm().source_identity(),
        program_context: generation.psm().program_context(),
        context_digest: generation.context_digest(),
        authority_digest: generation.authority_digest(),
        input_revision: generation.input_revision(),
        source_files: generation.source_view().len(),
        source_bytes: checked_scratch_sum(generation.source_view().values().map(Vec::len))
            .expect("completed Generation source bytes fit resident input admission"),
        symbols: generation.psm().symbols().len(),
        calls: generation.psm().calls().len(),
        execution_evidence_present: generation.execution_evidence_present(),
        operational_availability: AvailabilityContext {
            entries: generation.observed_availability().len(),
            inventory_digest: if digests {
                Cow::Owned(serialized_digest(generation.observed_availability(), false))
            } else {
                Cow::Borrowed(PLACEHOLDER_DIGEST)
            },
            scope: "operational availability; excluded from semantic identity",
        },
    }
}

pub(super) fn context(generation: &Generation) -> Value {
    serde_json::to_value(borrowed_context(generation, true)).expect("fixed context serializes")
}

/// Counts existing JSON allocations without cloning or serializing the value.
pub(super) fn value_allocation_bytes(value: &Value) -> Result<usize, ComparisonError> {
    let children = match value {
        Value::String(text) => text.capacity(),
        Value::Array(values) => {
            let mut bytes = scaled(values.capacity(), size_of::<Value>())?;
            for value in values {
                bytes = checked_scratch_sum([bytes, value_allocation_bytes(value)?])?;
            }
            bytes
        }
        Value::Object(values) => {
            let mut bytes = scaled(values.len(), ENTRY_ALLOWANCE)?;
            for (key, value) in values {
                bytes =
                    checked_scratch_sum([bytes, key.capacity(), value_allocation_bytes(value)?])?;
            }
            bytes
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    };
    checked_scratch_sum([size_of::<Value>(), children])
}

#[derive(Clone, Copy, Debug)]
struct ScratchCharge {
    canonical_content: usize,
    canonical_metadata: usize,
    canonical_path_bytes: usize,
    retained_source: usize,
    source_content_bytes: usize,
    source_content_capacity: usize,
    source_path_capacity: usize,
    source_path_bytes: usize,
    context_serialized_bytes: usize,
    context: usize,
    total: usize,
}

impl ScratchCharge {
    fn for_generation(generation: &Generation) -> Result<Self, ComparisonError> {
        if generation.canonical_artifacts().len() != MEMBER_COUNT
            || generation.execution_evidence_present()
        {
            return Err(ComparisonError(
                "comparison requires eleven members without supplied execution evidence",
            ));
        }
        let canonical_content =
            checked_scratch_sum(generation.canonical_artifacts().values().map(String::len))?;
        let canonical_path_bytes =
            checked_scratch_sum(generation.canonical_artifacts().keys().map(String::len))?;
        let canonical_metadata = scaled(
            checked_scratch_sum([scaled(MEMBER_COUNT, ENTRY_ALLOWANCE)?, canonical_path_bytes])?,
            METADATA_COPIES,
        )?;
        let source_content_bytes =
            checked_scratch_sum(generation.source_view().values().map(Vec::len))?;
        let source_content_capacity =
            checked_scratch_sum(generation.source_view().values().map(Vec::capacity))?;
        let source_path_capacity =
            checked_scratch_sum(generation.source_view().keys().map(String::capacity))?;
        let source_path_bytes =
            checked_scratch_sum(generation.source_view().keys().map(String::len))?;
        let mut retained_source = checked_scratch_sum([
            size_of::<SourceView>(),
            generation.source_view().digest().len(),
            scaled(generation.source_view().len(), ENTRY_ALLOWANCE)?,
        ])?;
        for (path, bytes) in generation.source_view() {
            retained_source =
                checked_scratch_sum([retained_source, path.capacity(), bytes.capacity()])?;
        }
        // Counting serialization borrows the context: no deep Value clone precedes admission.
        // Fixed-length SHA placeholders avoid even digest allocations during preflight.
        // Each wire byte reserves 256 bytes for strings, Value cells and BTreeMap nodes;
        // Eight context extents cover the retained baseline/snapshot, comparison
        // operands and serialization copies in the bounded raw sample record.
        let mut counter = CountingWriter(0);
        serde_json::to_writer(&mut counter, &borrowed_context(generation, false))
            .map_err(|_| ComparisonError("comparison context exceeds scratch limit"))?;
        let context = scaled(
            scaled(counter.0, VALUE_ALLOCATION_MULTIPLIER)?,
            CONTEXT_COPIES,
        )?;
        let total = checked_scratch_sum([
            canonical_content,
            canonical_metadata,
            retained_source,
            context,
            FIXED_ALLOWANCE,
        ])?;
        Ok(Self {
            canonical_content,
            canonical_metadata,
            canonical_path_bytes,
            retained_source,
            source_content_bytes,
            source_content_capacity,
            source_path_capacity,
            source_path_bytes,
            context_serialized_bytes: counter.0,
            context,
            total,
        })
    }
}

/// Immutable full comparison bytes and input backing without model-generation pins.
#[derive(Debug)]
pub(super) struct ComparisonSnapshot {
    artifacts: Vec<(Box<str>, Box<[u8]>)>,
    context: Value,
    source_view: SourceView,
    charge: ScratchCharge,
}

impl ComparisonSnapshot {
    pub(super) fn required_bytes(generation: &Generation) -> Result<usize, ComparisonError> {
        Ok(ScratchCharge::for_generation(generation)?.total)
    }

    pub(super) fn capture(
        generation: &Generation,
        max_bytes: usize,
    ) -> Result<Self, ComparisonError> {
        let charge = ScratchCharge::for_generation(generation)?;
        if charge.total > max_bytes.min(MAX_COMPARISON_SCRATCH_BYTES) {
            return Err(ComparisonError("comparison scratch exceeds admitted limit"));
        }
        let artifacts = generation
            .canonical_artifacts()
            .iter()
            .map(|(path, bytes)| {
                (
                    Box::<str>::from(path.as_str()),
                    Box::<[u8]>::from(bytes.as_bytes()),
                )
            })
            .collect();
        let context = context(generation);
        if value_allocation_bytes(&context)? > charge.context {
            return Err(ComparisonError(
                "comparison context exceeded its pre-admission",
            ));
        }
        Ok(Self {
            artifacts,
            context,
            source_view: generation.source_view().clone(),
            charge,
        })
    }

    pub(super) const fn source_view(&self) -> &SourceView {
        &self.source_view
    }

    pub(super) const fn context(&self) -> &Value {
        &self.context
    }

    pub(super) fn matches(&self, generation: &Generation) -> bool {
        let Ok(charge) = ScratchCharge::for_generation(generation) else {
            return false;
        };
        charge.context <= self.charge.context
            && self.artifacts.len() == generation.canonical_artifacts().len()
            && self
                .artifacts
                .iter()
                .zip(generation.canonical_artifacts())
                .all(|((path, bytes), (other_path, other_bytes))| {
                    path.as_ref() == other_path && bytes.as_ref() == other_bytes.as_bytes()
                })
            && self.context == context(generation)
    }

    pub(super) fn artifact_digests(&self) -> BTreeMap<String, String> {
        self.artifacts
            .iter()
            .map(|(path, bytes)| {
                (
                    path.to_string(),
                    format!("sha256:{:x}", Sha256::digest(bytes)),
                )
            })
            .collect()
    }

    pub(super) fn accounting(&self) -> Value {
        let artifacts: Vec<_> = self
            .artifacts
            .iter()
            .map(|(path, bytes)| {
                json!({
                    "path":path,"path_bytes":path.len(),"content_bytes":bytes.len(),
                    "boxed_content_capacity":bytes.len(),"boxed_path_capacity":path.len(),
                })
            })
            .collect();
        json!({"canonical_content_bytes":self.charge.canonical_content,
            "canonical_path_bytes":self.charge.canonical_path_bytes,
            "canonical_members":artifacts,"metadata_copies":METADATA_COPIES,
            "entry_allocation_allowance":ENTRY_ALLOWANCE,
            "canonical_metadata_charge":self.charge.canonical_metadata,
            "source_files":self.source_view.len(),
            "source_content_bytes":self.charge.source_content_bytes,
            "source_content_capacity":self.charge.source_content_capacity,
            "source_path_capacity":self.charge.source_path_capacity,
            "source_path_bytes":self.charge.source_path_bytes,
            "source_view_struct_bytes":size_of::<SourceView>(),
            "source_view_digest_bytes":self.source_view.digest().len(),
            "source_manifest_retained":false,
            "retained_source_allocation_charge":self.charge.retained_source,
            "context_serialized_bytes":self.charge.context_serialized_bytes,
            "retained_context_allocation_charge":value_allocation_bytes(&self.context)
                .expect("captured context already passed allocation admission"),
            "context_allocation_multiplier":VALUE_ALLOCATION_MULTIPLIER,
            "context_copies":CONTEXT_COPIES,
            "context_allocation_charge":self.charge.context,
            "fixed_allocation_allowance":FIXED_ALLOWANCE,
            "snapshot_accounted_bytes":self.charge.total,
            "scope":"comparison-client retained bytes and input backing; separate from Session model accounting; conservative estimate, not a hard RSS bound"})
    }
}
