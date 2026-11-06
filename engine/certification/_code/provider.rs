//! Context-bound provider reporting; integrity never authenticates a producer.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::declaration::{DeclarationBinding, canonical, canonical_strings, is_digest};

/// Initial normalized external-provider contract.
pub const PROVIDER_SCHEMA: &str = "urn:fortress:derived:v1:provider-evidence";
/// Current normalization algorithm, separate from the claimed execution tool version.
pub const PROVIDER_SEMANTIC_VERSION: &str = "1.0.0";
/// Maximum retained raw payload or canonical public provider document.
pub const MAX_PROVIDER_BYTES: usize = 32 * 1024 * 1024;
/// Maximum independently declared or observed native members.
pub const MAX_PROVIDER_RECORDS: usize = 100_000;
/// Conservative retained normalized metadata charge; not an RSS claim.
pub const MAX_PROVIDER_NORMALIZED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum selectors across an authored binding document.
pub const MAX_PROVIDER_SELECTORS: usize = 10_000;

/// Operational or malformed-input failure, separate from software truth.
#[derive(Debug)]
pub enum ProviderError {
    /// The retained reporting contract is malformed or inconsistent.
    Invalid(String),
    /// Admission refused before retaining further normalized data.
    ResourceLimit(&'static str),
    /// Reading retained input failed; never converted into conformance.
    Io(std::io::Error),
}

impl Display for ProviderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "invalid provider evidence: {detail}"),
            Self::ResourceLimit(kind) => write!(f, "provider resource limit: {kind}"),
            Self::Io(error) => write!(f, "provider input: {error}"),
        }
    }
}
impl Error for ProviderError {}
impl From<std::io::Error> for ProviderError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) fn ensure(condition: bool, detail: &str) -> Result<(), ProviderError> {
    if condition {
        Ok(())
    } else {
        Err(ProviderError::Invalid(detail.into()))
    }
}

/// Conservative budget shared by normalization and metadata validation.
#[derive(Default)]
pub(crate) struct NormalizedBudget(usize);
impl NormalizedBudget {
    pub(crate) fn charge(&mut self, count: usize) -> Result<(), ProviderError> {
        self.0 = self
            .0
            .checked_add(count)
            .ok_or(ProviderError::ResourceLimit("normalized metadata"))?;
        if self.0 > MAX_PROVIDER_NORMALIZED_BYTES {
            return Err(ProviderError::ResourceLimit("normalized metadata"));
        }
        Ok(())
    }
    pub(crate) fn text(&mut self, value: &str) -> Result<(), ProviderError> {
        self.charge(
            value
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(32))
                .ok_or(ProviderError::ResourceLimit("normalized text"))?,
        )
    }
}

fn bounded_records<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded provider sequence")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut result = Vec::new();
            while let Some(value) = seq.next_element()? {
                if result.len() >= MAX_PROVIDER_RECORDS {
                    return Err(serde::de::Error::custom("provider record limit"));
                }
                result.push(value);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
}

fn bounded_optional_records<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = Option<Vec<T>>;
        fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("known bounded arguments or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            bounded_records(d).map(Some)
        }
    }
    deserializer.deserialize_option(Visitor(std::marker::PhantomData))
}

/// Closed implemented parser boundary, not an inferred producer identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderFormat {
    /// Existing controlled unfiltered Fortress Cargo execution record.
    CargoSuite,
    /// Bounded native `JUnit` XML with optional explicit companion manifest.
    JunitXml,
    /// SARIF 2.1.0 single-tool/run analysis observations.
    Sarif210,
}
impl ProviderFormat {
    /// Exact normalized media type.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::CargoSuite => "application/vnd.fortress.cargo-suite+json",
            Self::JunitXml => "application/xml",
            Self::Sarif210 => "application/sarif+json",
        }
    }
    /// Whether this adapter observes actual tests rather than analysis findings.
    #[must_use]
    pub const fn is_test_execution(self) -> bool {
        !matches!(self, Self::Sarif210)
    }
}

/// Native names and existing governed Test IDs never share an implicit namespace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InventoryNamespace {
    /// Original native package/target/qualified name, with unknown qualifiers explicit.
    NativeQualified,
    /// An actually source-observed Fortress T ID, without invented native qualifiers.
    GovernedTestId,
}

/// Exact observed member; optional qualifiers mean unknown, never an invented name.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryKey {
    /// Explicit identity language.
    pub namespace: InventoryNamespace,
    /// Native package/tool when independently known.
    pub package: Option<String>,
    /// Native target/invocation scope when known.
    pub target: Option<String>,
    /// Exact native qualified name or governed Test ID.
    pub qualified_name: String,
}
impl InventoryKey {
    /// Checks identity shape without asserting complete native qualification.
    ///
    /// # Errors
    /// Rejects invalid names or fabricated qualifiers for a governed T ID.
    pub fn validate(&self) -> Result<(), ProviderError> {
        validate_key(
            self.namespace,
            self.package.as_deref(),
            self.target.as_deref(),
            &self.qualified_name,
        )
    }
    /// Whether the inventory can support exact unique native selection.
    #[must_use]
    pub fn fully_qualified(&self) -> bool {
        self.validate().is_ok()
            && (self.namespace == InventoryNamespace::GovernedTestId
                || (self.package.is_some() && self.target.is_some()))
    }
    pub(crate) fn charge(&self, budget: &mut NormalizedBudget) -> Result<(), ProviderError> {
        budget.charge(128)?;
        budget.text(&self.qualified_name)?;
        for value in [&self.package, &self.target].into_iter().flatten() {
            budget.text(value)?;
        }
        Ok(())
    }
}

/// Independently enumerated eligible or explicitly excluded member.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryMember {
    /// Exact identity, separate from execution results.
    pub key: InventoryKey,
    /// False for ignored/disabled members; they never prove full execution.
    pub enabled: bool,
}

/// Provider outcome, never a Fortress software-policy verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderOutcome {
    /// A native test passed or a complete scoped analysis reported no findings.
    Passed,
    /// A native test failed or an analysis reported a finding.
    Failed,
    /// Execution was skipped/ignored.
    Skipped,
    /// The provider explicitly reports that its rule does not apply.
    NotApplicable,
    /// The provider cannot establish a terminal result.
    Unknown,
}

/// Exact raw observation with separately established retry accounting.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderObservation {
    /// Observed member, possibly not fully qualified without a companion.
    pub key: InventoryKey,
    /// Raw result; analysis findings are not failed test execution.
    pub outcome: ProviderOutcome,
    /// Explicit companion count, absent when unknown; never inferred from silence.
    pub attempts: Option<u64>,
    /// Raw retry hints remain visible even when the exact count is unknown.
    pub retry_metadata_present: bool,
    /// SARIF finding count when known; tests do not invent such a count.
    pub finding_count: Option<u64>,
}

/// Exact known invocation outcome; exit code alone does not imply success.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationOutcome {
    /// Explicit successful execution assertion; null means unavailable.
    pub succeeded: Option<bool>,
    /// Actual reported exit code when available.
    pub exit_code: Option<i32>,
}

/// Origin of the invocation assertion, not an authenticity claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvocationBasis {
    /// The original result payload explicitly reports it.
    Payload,
    /// `JUnit` does not report process status; the companion asserts it.
    CompanionManifest,
    /// No outcome is available.
    Unknown,
}

/// One hashed input or environment dependency; no secret value is serialized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    /// Stable dependency selector.
    pub name: String,
    /// Exact content/value identity.
    pub digest: String,
}

/// Supported logical invocation directory, independent of temporary host paths.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionDirectory {
    /// Exact subject root whose content is bound separately.
    SubjectRoot,
}

/// Execution closure separate from semantic source and `ProgramContext`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDescriptor {
    /// Actual executable identity, absent when the older provider did not retain it.
    pub binary_digest: Option<String>,
    /// Exact tool/configuration identity, absent rather than fabricated.
    pub tool_digest: Option<String>,
    /// Actual ordered arguments; machine-dependent executable location is separate.
    #[serde(default, deserialize_with = "bounded_optional_records")]
    pub arguments: Option<Vec<String>>,
    /// Logical directory when known; null is unavailable rather than a fake path.
    pub working_directory: Option<ExecutionDirectory>,
    /// Complete known data/code input descriptors.
    #[serde(deserialize_with = "bounded_records")]
    pub inputs: Vec<ExecutionInput>,
    /// Known environment/network/generated dependencies.
    #[serde(deserialize_with = "bounded_records")]
    pub environment_dependencies: Vec<ExecutionInput>,
    /// False when any relevant dependency is unknown; forces fresh execution.
    pub dependencies_complete: bool,
}
impl ExecutionDescriptor {
    /// Validates identities and canonical dependency sets without inferring completeness.
    ///
    /// # Errors
    /// Rejects malformed, duplicate or resource-excessive descriptors.
    pub fn validate(&self) -> Result<(), ProviderError> {
        let mut budget = NormalizedBudget::default();
        self.validate_into(&mut budget)
    }
    fn validate_into(&self, budget: &mut NormalizedBudget) -> Result<(), ProviderError> {
        for digest in [&self.binary_digest, &self.tool_digest]
            .into_iter()
            .flatten()
        {
            ensure(is_digest(digest), "execution identity")?;
            budget.text(digest)?;
        }
        ensure(
            !self.dependencies_complete
                || (self.binary_digest.is_some()
                    && self.tool_digest.is_some()
                    && self.arguments.is_some()
                    && self.working_directory.is_some()),
            "complete closure needs actual executable/tool/argv/directory identities",
        )?;
        if let Some(arguments) = &self.arguments {
            if arguments.len() > MAX_PROVIDER_RECORDS {
                return Err(ProviderError::ResourceLimit("arguments"));
            }
            for value in arguments {
                budget.text(value)?;
            }
        }
        for entries in [&self.inputs, &self.environment_dependencies] {
            if entries.len() > MAX_PROVIDER_RECORDS {
                return Err(ProviderError::ResourceLimit("execution dependencies"));
            }
            ensure(
                entries.windows(2).all(|p| p[0].name < p[1].name),
                "dependency names must be unique and sorted",
            )?;
            for input in entries {
                ensure(
                    stable_text(&input.name) && is_digest(&input.digest),
                    "execution dependency",
                )?;
                budget.text(&input.name)?;
                budget.text(&input.digest)?;
            }
        }
        Ok(())
    }
    /// Reuse is permitted only for the complete exact independently supplied current closure.
    #[must_use]
    pub fn reusable_for(&self, current: &Self) -> bool {
        self.dependencies_complete
            && current.dependencies_complete
            && self == current
            && self.validate().is_ok()
            && current.validate().is_ok()
    }
}

/// Explicit independently supplied count for an inventory member.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptCount {
    /// Exact enumerated member.
    pub key: InventoryKey,
    /// Total attempts, not merely the final successful attempt.
    pub count: u64,
}

/// Companion scope, inventory and invocation assertions, not host acceptance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRunManifest {
    /// Exact declared source, `ProgramContext` and authored authority.
    pub binding: DeclarationBinding,
    /// Claimed provider identity.
    pub provider: String,
    /// Claimed exact provider version.
    pub provider_version: String,
    /// Explicit stable invocation scope referenced by authored bindings.
    pub invocation_scope: String,
    /// Exact execution input descriptors and known unknowns.
    pub execution: ExecutionDescriptor,
    /// Independently supplied inventory, separate from result rows.
    #[serde(deserialize_with = "bounded_records")]
    pub inventory: Vec<InventoryMember>,
    /// Explicit enumeration completeness, not inferred from row count.
    pub inventory_complete: bool,
    /// Every active filter/selection, in supplied invocation order.
    #[serde(deserialize_with = "bounded_records")]
    pub filters: Vec<String>,
    /// False when the actual selection/filter state was not retained.
    pub filtering_known: bool,
    /// Whether every independently inventoried member has exact attempt accounting.
    pub attempts_complete: bool,
    /// Sorted exact known attempt counts.
    #[serde(deserialize_with = "bounded_records")]
    pub attempts: Vec<AttemptCount>,
    /// Explicit companion process outcome; raw payloads may separately contradict it.
    pub invocation: InvocationOutcome,
    /// Exact raw payload identity.
    pub payload_digest: String,
    /// Explicit conditional premises requiring independent admission.
    #[serde(deserialize_with = "bounded_records")]
    pub assumptions: Vec<String>,
}
impl ProviderRunManifest {
    /// Checks companion metadata without granting trust or completeness.
    ///
    /// # Errors
    /// Rejects malformed scope, duplicate members and resource excess.
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.validate_into(&mut NormalizedBudget::default())
    }
    /// Parses strict public companion metadata without executing or trusting it.
    ///
    /// # Errors
    /// Rejects duplicate keys, malformed identities and resource excess.
    pub fn from_json_str(source: &str) -> Result<Self, ProviderError> {
        preflight_json(source.as_bytes())?;
        let result: Self = crate::wire::parse_public_json(source)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        result.validate_into(&mut NormalizedBudget::default())?;
        Ok(result)
    }
    fn validate_into(&self, budget: &mut NormalizedBudget) -> Result<(), ProviderError> {
        ensure(
            [
                &self.binding.subject_ref,
                &self.binding.context_ref,
                &self.binding.authority_ref,
                &self.payload_digest,
            ]
            .into_iter()
            .all(|d| is_digest(d)),
            "manifest binding",
        )?;
        ensure(
            stable_text(&self.provider)
                && stable_text(&self.provider_version)
                && stable_text(&self.invocation_scope),
            "manifest provider/scope",
        )?;
        budget.text(&self.provider)?;
        budget.text(&self.provider_version)?;
        budget.text(&self.invocation_scope)?;
        self.execution.validate_into(budget)?;
        if self.inventory.len() > MAX_PROVIDER_RECORDS
            || self.attempts.len() > MAX_PROVIDER_RECORDS
            || self.filters.len() > MAX_PROVIDER_RECORDS
            || self.assumptions.len() > MAX_PROVIDER_RECORDS
        {
            return Err(ProviderError::ResourceLimit("manifest records"));
        }
        ensure(
            self.inventory.windows(2).all(|p| p[0].key < p[1].key),
            "inventory must be sorted and unique",
        )?;
        for member in &self.inventory {
            member.key.validate()?;
            member.key.charge(budget)?;
            ensure(
                !self.inventory_complete || member.key.fully_qualified(),
                "complete inventory contains unknown qualifiers",
            )?;
        }
        ensure(
            self.attempts.windows(2).all(|p| p[0].key < p[1].key),
            "attempt identities must be sorted and unique",
        )?;
        for attempt in &self.attempts {
            attempt.key.validate()?;
            attempt.key.charge(budget)?;
            ensure(
                attempt.count <= crate::wire::MAX_EXACT_PUBLIC_INTEGER,
                "attempt count",
            )?;
            ensure(
                self.inventory
                    .binary_search_by(|m| m.key.cmp(&attempt.key))
                    .is_ok(),
                "attempt outside inventory",
            )?;
        }
        ensure(
            !self.attempts_complete
                || (self.attempts.len() == self.inventory.len()
                    && self
                        .attempts
                        .iter()
                        .zip(&self.inventory)
                        .all(|(a, b)| a.key == b.key)),
            "complete attempt accounting differs from inventory",
        )?;
        canonical_strings(&self.assumptions).map_err(|e| ProviderError::Invalid(e.to_string()))?;
        for text in self.filters.iter().chain(&self.assumptions) {
            budget.text(text)?;
        }
        Ok(())
    }
}

/// Normalized reporting bound to exact retained raw bytes; never self-authenticating.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Exact normalized producer algorithm; not an execution authentication claim.
    pub normalizer_semantic_version: String,
    /// Exact implemented input grammar.
    pub format: ProviderFormat,
    /// Claimed provider identity; not an authentication root.
    pub provider: Option<String>,
    /// Claimed exact provider version.
    pub provider_version: Option<String>,
    /// Registered media type for this parser boundary.
    pub media_type: String,
    /// SHA-256 of retained raw input, not a canonicalized replacement.
    pub payload_digest: String,
    /// Missing companion metadata remains explicitly unknown.
    pub run_manifest: Option<ProviderRunManifest>,
    /// Native results in strict identity order.
    #[serde(deserialize_with = "bounded_records")]
    pub observations: Vec<ProviderObservation>,
    /// Reported invocation state, separate from per-member outcomes.
    pub invocation: InvocationOutcome,
    /// Whether status came from raw payload, companion or is unavailable.
    pub invocation_basis: InvocationBasis,
    /// Closed or bounded reason codes withholding complete-run claims.
    #[serde(deserialize_with = "bounded_records")]
    pub limitations: Vec<String>,
    /// Always UNVERIFIED for local unsigned reporting, even after host admission.
    pub authenticity: String,
}

impl EvidenceEnvelope {
    /// Normalizes parser facts and merges only explicit companion attempt counts.
    ///
    /// # Errors
    /// Rejects contradictory identities, resource excess or malformed metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn compose(
        format: ProviderFormat,
        provider: Option<String>,
        provider_version: Option<String>,
        payload_digest: String,
        run_manifest: Option<ProviderRunManifest>,
        mut observations: Vec<ProviderObservation>,
        invocation: InvocationOutcome,
        invocation_basis: InvocationBasis,
        mut limitations: Vec<String>,
    ) -> Result<Self, ProviderError> {
        observations.sort_by(|a, b| a.key.cmp(&b.key));
        if let Some(manifest) = &run_manifest {
            for row in &mut observations {
                let count = manifest
                    .attempts
                    .binary_search_by(|a| a.key.cmp(&row.key))
                    .ok()
                    .map(|i| manifest.attempts[i].count);
                row.attempts = if row.retry_metadata_present && count.is_some_and(|n| n <= 1) {
                    limitations.push("RETRY_CONTRADICTS_ATTEMPT_MANIFEST".into());
                    None
                } else {
                    count
                };
            }
        }
        limitations.sort();
        limitations.dedup();
        let result = Self {
            schema: PROVIDER_SCHEMA.into(),
            schema_version: 1,
            normalizer_semantic_version: PROVIDER_SEMANTIC_VERSION.into(),
            format,
            provider,
            provider_version,
            media_type: format.media_type().into(),
            payload_digest,
            run_manifest,
            observations,
            invocation,
            invocation_basis,
            limitations,
            authenticity: "UNVERIFIED".into(),
        };
        result.validate()?;
        Ok(result)
    }
    /// Strict public reader; a producer name or fresh flag cannot grant admission.
    ///
    /// # Errors
    /// Rejects duplicate keys, unknown fields/versions and inconsistent metadata.
    pub fn from_json_str(source: &str) -> Result<Self, ProviderError> {
        preflight_json(source.as_bytes())?;
        let result: Self = crate::wire::parse_public_json(source)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        result.validate()?;
        Ok(result)
    }
    /// Canonical RFC8785 bytes with a replayable public-size bound.
    ///
    /// # Errors
    /// Refuses invalid or oversized normalized output.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        self.validate()?;
        let bytes = canonical(self).map_err(|e| ProviderError::Invalid(e.to_string()))?;
        if bytes.len() > MAX_PROVIDER_BYTES {
            return Err(ProviderError::ResourceLimit("canonical envelope"));
        }
        Ok(bytes)
    }
    /// Binds all metadata and raw identity, never just a producer name.
    ///
    /// # Errors
    /// Rejects invalid reporting or serialization.
    pub fn digest(&self) -> Result<String, ProviderError> {
        Ok(hash(&self.to_canonical_bytes()?))
    }
    /// Checks reporting integrity without admitting its truth or producer.
    ///
    /// # Errors
    /// Refuses malformed scope, duplicates, unknown identities and resource excess.
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.validate_into(&mut NormalizedBudget::default())
    }
    pub(crate) fn validate_into(&self, budget: &mut NormalizedBudget) -> Result<(), ProviderError> {
        ensure(
            self.schema == PROVIDER_SCHEMA
                && self.schema_version == 1
                && self.normalizer_semantic_version == PROVIDER_SEMANTIC_VERSION,
            "unsupported provider version",
        )?;
        ensure(
            self.authenticity == "UNVERIFIED" && self.media_type == self.format.media_type(),
            "self-claimed authenticity or wrong media type",
        )?;
        ensure(
            self.provider.as_deref().is_none_or(stable_text)
                && self.provider_version.as_deref().is_none_or(stable_text)
                && (self.provider_version.is_none() || self.provider.is_some())
                && is_digest(&self.payload_digest),
            "provider identity",
        )?;
        if self.observations.len() > MAX_PROVIDER_RECORDS {
            return Err(ProviderError::ResourceLimit("observations"));
        }
        for value in [&self.provider, &self.provider_version]
            .into_iter()
            .flatten()
        {
            budget.text(value)?;
        }
        ensure(
            self.observations.windows(2).all(|p| p[0].key < p[1].key),
            "duplicate or unsorted result identities",
        )?;
        canonical_strings(&self.limitations).map_err(|e| ProviderError::Invalid(e.to_string()))?;
        for text in &self.limitations {
            budget.text(text)?;
        }
        ensure(
            self.invocation_basis != InvocationBasis::Unknown
                || self.invocation == InvocationOutcome::default(),
            "unavailable invocation has invented status",
        )?;
        ensure(
            self.format != ProviderFormat::JunitXml
                || self.invocation_basis != InvocationBasis::Payload,
            "JUnit has no raw process outcome",
        )?;
        ensure(
            self.format == ProviderFormat::JunitXml
                || self.invocation_basis != InvocationBasis::CompanionManifest,
            "analysis/Cargo invocation must come from its payload",
        )?;
        if let Some(manifest) = &self.run_manifest {
            manifest.validate_into(budget)?;
            ensure(
                Some(manifest.provider.as_str()) == self.provider.as_deref()
                    && Some(manifest.provider_version.as_str()) == self.provider_version.as_deref()
                    && manifest.payload_digest == self.payload_digest,
                "companion provider/payload mismatch",
            )?;
            if self.invocation_basis == InvocationBasis::CompanionManifest {
                ensure(
                    self.format == ProviderFormat::JunitXml
                        && self.invocation == manifest.invocation,
                    "companion invocation mismatch",
                )?;
            }
            if let (Some(raw), Some(companion)) =
                (self.invocation.succeeded, manifest.invocation.succeeded)
            {
                ensure(raw == companion, "raw/companion invocation conflict")?;
            }
        } else {
            ensure(
                self.invocation_basis != InvocationBasis::CompanionManifest,
                "companion status without manifest",
            )?;
        }
        self.validate_rows(budget)
    }
    fn validate_rows(&self, budget: &mut NormalizedBudget) -> Result<(), ProviderError> {
        for row in &self.observations {
            row.key.validate()?;
            row.key.charge(budget)?;
            ensure(
                row.attempts
                    .is_none_or(|n| n <= crate::wire::MAX_EXACT_PUBLIC_INTEGER),
                "result attempt count",
            )?;
            ensure(
                row.finding_count
                    .is_none_or(|n| n <= crate::wire::MAX_EXACT_PUBLIC_INTEGER),
                "finding count",
            )?;
            ensure(
                !self.format.is_test_execution() || row.finding_count.is_none(),
                "test reporting has invented analysis counts",
            )?;
            ensure(
                self.format != ProviderFormat::CargoSuite
                    || row.key.namespace == InventoryNamespace::GovernedTestId,
                "Cargo namespace",
            )?;
            ensure(
                self.format == ProviderFormat::CargoSuite
                    || row.key.namespace == InventoryNamespace::NativeQualified,
                "native import namespace",
            )?;
            let expected = self.run_manifest.as_ref().and_then(|m| {
                m.attempts
                    .binary_search_by(|a| a.key.cmp(&row.key))
                    .ok()
                    .map(|i| m.attempts[i].count)
            });
            let expected = if row.retry_metadata_present && expected.is_some_and(|n| n <= 1) {
                None
            } else {
                expected
            };
            ensure(
                row.attempts == expected,
                "attempts differ from explicit companion accounting",
            )?;
        }
        Ok(())
    }
    /// Complete nonempty inventory/attempt accounting, including truthful failures.
    #[must_use]
    pub fn inventory_accounted(&self) -> bool {
        if self.validate().is_err() {
            return false;
        }
        let Some(m) = &self.run_manifest else {
            return false;
        };
        m.inventory_complete
            && m.attempts_complete
            && !m.inventory.is_empty()
            && m.filters.is_empty()
            && m.filtering_known
            && self.limitations.is_empty()
            && m.inventory.len() == self.observations.len()
            && m.inventory
                .iter()
                .zip(&self.observations)
                .all(|(member, row)| {
                    member.enabled
                        && member.key.fully_qualified()
                        && member.key == row.key
                        && row.attempts == Some(1)
                        && !row.retry_metadata_present
                        && matches!(
                            row.outcome,
                            ProviderOutcome::Passed | ProviderOutcome::Failed
                        )
                })
    }
    /// Complete current reported success; host trust/freshness is still separate.
    #[must_use]
    pub fn full_success(&self) -> bool {
        self.inventory_accounted()
            && self.invocation.succeeded == Some(true)
            && self
                .observations
                .iter()
                .all(|r| r.outcome == ProviderOutcome::Passed)
    }
    /// Exact independently enumerated inventory identity, not an outcome digest.
    ///
    /// # Errors
    /// Rejects missing/invalid inventory metadata.
    pub fn inventory_digest(&self) -> Result<String, ProviderError> {
        self.validate()?;
        let m = self
            .run_manifest
            .as_ref()
            .ok_or_else(|| ProviderError::Invalid("missing inventory".into()))?;
        Ok(hash(
            &canonical(&m.inventory).map_err(|e| ProviderError::Invalid(e.to_string()))?,
        ))
    }
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn stable_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 65_536 && !value.chars().any(char::is_control)
}
fn validate_key(
    namespace: InventoryNamespace,
    package: Option<&str>,
    target: Option<&str>,
    name: &str,
) -> Result<(), ProviderError> {
    ensure(stable_text(name), "member name")?;
    for value in [package, target].into_iter().flatten() {
        ensure(stable_text(value), "member qualifier")?;
    }
    if namespace == InventoryNamespace::GovernedTestId {
        ensure(
            package.is_none() && target.is_none(),
            "governed Test IDs have no invented native qualifiers",
        )?;
        ensure(
            name.starts_with("T-") && crate::identity::StableId::parse(name).is_ok(),
            "governed Test ID",
        )?;
    }
    Ok(())
}
pub(crate) fn preflight(bytes: &[u8]) -> Result<(), ProviderError> {
    if bytes.len() > MAX_PROVIDER_BYTES {
        return Err(ProviderError::ResourceLimit("input bytes"));
    }
    Ok(())
}

pub(crate) fn preflight_json(bytes: &[u8]) -> Result<(), ProviderError> {
    preflight(bytes)?;
    let mut depth = 0_u16;
    let mut tokens = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match *byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 64 {
                        return Err(ProviderError::ResourceLimit("JSON depth"));
                    }
                }
                b']' | b'}' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| ProviderError::Invalid("unmatched JSON delimiter".into()))?;
                }
                b',' | b':' => {
                    tokens += 1;
                    if tokens > 1_000_000 {
                        return Err(ProviderError::ResourceLimit("JSON tokens"));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Authored native selector; absent qualifiers are explicit unique-match requests.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTestSelector {
    /// The selector's actual identity namespace.
    pub namespace: InventoryNamespace,
    /// Optional exact native package.
    pub package: Option<String>,
    /// Optional exact native target.
    pub target: Option<String>,
    /// Exact native qualified name or already governed T ID.
    pub qualified_name: String,
}
impl NativeTestSelector {
    fn validate(&self) -> Result<(), ProviderError> {
        validate_key(
            self.namespace,
            self.package.as_deref(),
            self.target.as_deref(),
            &self.qualified_name,
        )
    }
}

/// Authored link to a real CCG Requirement, separate from selected execution data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequirementBinding {
    /// Existing Requirement ID whose external intent is independently compiled.
    pub requirement_id: String,
    /// Explicit provider selector, not an authenticated name.
    pub provider: String,
    /// Explicit invocation scope; never the latest green run.
    pub invocation_scope: String,
    /// Every uniquely selected member remains mandatory.
    #[serde(deserialize_with = "bounded_records")]
    pub selectors: Vec<NativeTestSelector>,
    /// May strengthen the selected profile's authenticity requirement.
    pub authenticated_producer_required: bool,
}
impl ProviderRequirementBinding {
    /// Checks authoring shape, not whether the Requirement exists or tests ran.
    ///
    /// # Errors
    /// Refuses invalid IDs, duplicate selectors or excessive resource requests.
    pub fn validate(&self) -> Result<(), ProviderError> {
        ensure(
            stable_text(&self.requirement_id)
                && crate::identity::StableId::parse(&self.requirement_id).is_ok(),
            "Requirement identity",
        )?;
        ensure(
            stable_text(&self.provider) && stable_text(&self.invocation_scope),
            "binding provider/scope",
        )?;
        ensure(!self.selectors.is_empty(), "empty required selectors")?;
        if self.selectors.len() > MAX_PROVIDER_SELECTORS {
            return Err(ProviderError::ResourceLimit("selectors"));
        }
        ensure(
            self.selectors.windows(2).all(|p| p[0] < p[1]),
            "selectors must be sorted and unique",
        )?;
        for selector in &self.selectors {
            selector.validate()?;
        }
        Ok(())
    }
}

/// Non-deserializable proof of one completed trusted registered invocation.
/// Its constructor is restricted to the trusted orchestration boundary.
#[derive(Debug)]
pub struct FreshExecutionReceipt {
    envelope_digest: String,
    request_digest: String,
}

/// Host inputs supplied outside candidate files. Hash admission is not identity authentication.
#[derive(Debug, Default)]
pub struct ProviderAcceptancePolicy {
    /// Exact independently admitted complete envelope metadata and payload identity.
    pub admitted_envelopes: BTreeSet<String>,
    /// Exact envelopes independently authenticated by a real external trust root.
    pub authenticated_envelopes: BTreeSet<String>,
    /// Explicitly admitted provider premises; they do not authorize static assumptions.
    pub accepted_assumptions: BTreeSet<String>,
    /// Independently supplied current descriptors, keyed by selected envelope identity.
    pub current_executions: BTreeMap<String, ExecutionDescriptor>,
    fresh_receipts: BTreeMap<String, FreshExecutionReceipt>,
}
impl ProviderAcceptancePolicy {
    /// Reads explicitly injected host admission, never candidate authority.
    /// The caller must establish that the bytes are an authorized host input.
    /// This format cannot assert authentication or manufacture fresh receipts.
    ///
    /// # Errors
    /// Refuses malformed, unordered, excessive or unsupported host inputs.
    pub fn from_explicit_host_json(source: &str) -> Result<Self, ProviderError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HostInput {
            #[serde(rename = "$schema")]
            schema: String,
            schema_version: u16,
            admitted_envelopes: Vec<String>,
            accepted_assumptions: Vec<String>,
            current_executions: BTreeMap<String, ExecutionDescriptor>,
        }
        if source.len() > 1024 * 1024 {
            return Err(ProviderError::ResourceLimit("explicit host input"));
        }
        preflight_json(source.as_bytes())?;
        let input: HostInput = crate::wire::parse_public_json(source)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        ensure(
            input.schema == "urn:fortress:host:v1:provider-admission" && input.schema_version == 1,
            "unsupported host admission",
        )?;
        ensure(
            input.admitted_envelopes.len() <= 1024
                && input.current_executions.len() <= 1024
                && input.accepted_assumptions.len() <= 1024,
            "host admission count",
        )?;
        canonical_strings(&input.admitted_envelopes)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        canonical_strings(&input.accepted_assumptions)
            .map_err(|e| ProviderError::Invalid(e.to_string()))?;
        ensure(
            input.admitted_envelopes.iter().all(|d| is_digest(d)),
            "host envelope identity",
        )?;
        for (digest, execution) in &input.current_executions {
            ensure(is_digest(digest), "host execution identity")?;
            execution.validate()?;
        }
        Ok(Self {
            admitted_envelopes: input.admitted_envelopes.into_iter().collect(),
            accepted_assumptions: input.accepted_assumptions.into_iter().collect(),
            current_executions: input.current_executions,
            ..Self::default()
        })
    }

    /// Consumes one actual fresh-run capability without authenticating its producer.
    pub fn admit_fresh(&mut self, receipt: FreshExecutionReceipt) {
        self.admitted_envelopes
            .insert(receipt.envelope_digest.clone());
        self.fresh_receipts
            .insert(receipt.envelope_digest.clone(), receipt);
    }
}

pub(crate) fn execution_request_digest(
    binding: &DeclarationBinding,
    execution: &ExecutionDescriptor,
) -> Result<String, ProviderError> {
    Ok(hash(
        &canonical(&("provider-execution-request-v1", binding, execution))
            .map_err(|e| ProviderError::Invalid(e.to_string()))?,
    ))
}

/// Called only after the explicitly granted registered executor has exited,
/// source/input brackets match, and retained raw output reproduces this envelope.
pub(crate) fn completed_fresh_execution(
    envelope: &EvidenceEnvelope,
    binding: &DeclarationBinding,
    execution: &ExecutionDescriptor,
) -> Result<FreshExecutionReceipt, ProviderError> {
    envelope.validate()?;
    let m = envelope
        .run_manifest
        .as_ref()
        .ok_or_else(|| ProviderError::Invalid("fresh execution has no exact manifest".into()))?;
    ensure(
        &m.binding == binding && &m.execution == execution,
        "fresh execution request differs from retained result",
    )?;
    Ok(FreshExecutionReceipt {
        envelope_digest: envelope.digest()?,
        request_digest: execution_request_digest(binding, execution)?,
    })
}

/// Exact reason withholding provider proof; none is a Module policy violation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderBlocker {
    /// Subject, `ProgramContext` or authority differs from the trusted request.
    WrongBinding,
    /// No complete independently enumerated inventory is available.
    IncompleteInventory,
    /// Filters, ignored rows, retries, omissions or unknowns prevent complete execution.
    IncompleteRun,
    /// The selected provider or invocation scope differs.
    WrongProvider,
    /// Analysis observations cannot replace actually required tests.
    IncompatibleEvidenceClass,
    /// Host did not admit the exact raw payload and all normalized metadata.
    UntrustedEnvelope,
    /// No actual authenticated identity satisfies an explicit requirement.
    ProducerNotAuthenticated,
    /// A conditional premise remains unaccepted.
    AssumptionNotAccepted,
    /// Unknown dependencies or unavailable current descriptors require a fresh run.
    FreshExecutionRequired,
    /// Complete known execution descriptors differ from the independently supplied current ones.
    StaleExecution,
    /// A selector resolves to zero or multiple inventory members, or repeats a member.
    SelectorRequiresReview,
    /// Admitted current execution actually failed its required verification proposition.
    ExecutionFailed,
}

#[derive(Default)]
struct SelectorIndex<'a> {
    names: BTreeMap<(InventoryNamespace, &'a str), Option<&'a InventoryKey>>,
    packages: BTreeMap<(InventoryNamespace, &'a str, &'a str), Option<&'a InventoryKey>>,
    targets: BTreeMap<(InventoryNamespace, &'a str, &'a str), Option<&'a InventoryKey>>,
}
fn unique_insert<'a, K: Ord>(
    map: &mut BTreeMap<K, Option<&'a InventoryKey>>,
    key: K,
    value: &'a InventoryKey,
) {
    map.entry(key)
        .and_modify(|entry| *entry = None)
        .or_insert(Some(value));
}
impl<'a> SelectorIndex<'a> {
    fn new(inventory: &'a [InventoryMember]) -> Self {
        let mut result = Self::default();
        for member in inventory {
            let key = &member.key;
            let name = key.qualified_name.as_str();
            unique_insert(&mut result.names, (key.namespace, name), key);
            if let Some(package) = key.package.as_deref() {
                unique_insert(&mut result.packages, (key.namespace, package, name), key);
            }
            if let Some(target) = key.target.as_deref() {
                unique_insert(&mut result.targets, (key.namespace, target, name), key);
            }
        }
        result
    }
    fn resolve(
        &self,
        inventory: &'a [InventoryMember],
        selector: &NativeTestSelector,
    ) -> Option<&'a InventoryKey> {
        let namespace = selector.namespace;
        let name = selector.qualified_name.as_str();
        match (selector.package.as_deref(), selector.target.as_deref()) {
            (Some(package), Some(target)) => inventory
                .binary_search_by(|member| {
                    (
                        member.key.namespace,
                        member.key.package.as_deref(),
                        member.key.target.as_deref(),
                        member.key.qualified_name.as_str(),
                    )
                        .cmp(&(namespace, Some(package), Some(target), name))
                })
                .ok()
                .map(|index| &inventory[index].key),
            (Some(package), None) => self
                .packages
                .get(&(namespace, package, name))
                .copied()
                .flatten(),
            (None, Some(target)) => self
                .targets
                .get(&(namespace, target, name))
                .copied()
                .flatten(),
            (None, None) => self.names.get(&(namespace, name)).copied().flatten(),
        }
    }
}

/// Replayable provider-to-obligation result, not a claim about software correctness.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderResolution {
    /// Real authored Requirement identity supplied by the trusted compiler.
    pub requirement_id: String,
    /// Exact selected retained provider record.
    pub envelope_digest: String,
    /// Independently enumerated inventory, when available.
    pub inventory_digest: Option<String>,
    /// Exact uniquely resolved native members; no synthetic T IDs.
    pub members: Vec<InventoryKey>,
    /// Sufficiency of this required execution policy, separate from software truth.
    pub decision: crate::assessment::AssessmentDecision,
    /// Sorted exact reasons; known failure never masquerades as a Module violation.
    pub blockers: Vec<ProviderBlocker>,
    /// Typed shared proof, with each required premise retained.
    pub proof: Option<crate::proof::ProofGraph>,
    /// Scope-bound leaves; producer trust is never inferred from these records.
    pub evidence: Vec<crate::assessment::AssessmentEvidence>,
    #[serde(skip)]
    pub(crate) acceptance: crate::assessment::EvidenceAcceptancePolicy,
}

/// Cached structural validation, host admission and borrowed uniqueness indexes.
/// One preparation serves all authored requirements without rescanning inventory.
pub struct PreparedProvider<'a> {
    envelope: &'a EvidenceEnvelope,
    digest: String,
    inventory_digest: Option<String>,
    index: SelectorIndex<'a>,
    blockers: Vec<ProviderBlocker>,
    authenticated: bool,
    accounted: bool,
    accepted_assumptions: BTreeSet<String>,
}

impl<'a> PreparedProvider<'a> {
    /// Validates reporting once, then consumes a fresh receipt or checks the
    /// independently supplied complete current execution closure.
    ///
    /// # Errors
    /// Propagates malformed reporting and resource failures, not semantic verdicts.
    pub fn new(
        envelope: &'a EvidenceEnvelope,
        expected: &DeclarationBinding,
        policy: &mut ProviderAcceptancePolicy,
    ) -> Result<Self, ProviderError> {
        envelope.validate()?;
        let digest = envelope.digest()?;
        let mut blockers = BTreeSet::new();
        let authenticated = policy.authenticated_envelopes.contains(&digest);
        if !policy.admitted_envelopes.contains(&digest) {
            blockers.insert(ProviderBlocker::UntrustedEnvelope);
        }
        let mut inventory_digest = None;
        let mut index = SelectorIndex::default();
        if let Some(m) = &envelope.run_manifest {
            if &m.binding != expected {
                blockers.insert(ProviderBlocker::WrongBinding);
            }
            if !m.inventory_complete || m.inventory.is_empty() {
                blockers.insert(ProviderBlocker::IncompleteInventory);
            }
            if m.assumptions
                .iter()
                .any(|a| !policy.accepted_assumptions.contains(a))
            {
                blockers.insert(ProviderBlocker::AssumptionNotAccepted);
            }
            let request_digest = execution_request_digest(expected, &m.execution)?;
            let fresh = policy
                .fresh_receipts
                .remove(&digest)
                .is_some_and(|receipt| receipt.request_digest == request_digest);
            if !fresh {
                if let Some(current) = policy.current_executions.get(&digest) {
                    current.validate()?;
                }
                match policy.current_executions.get(&digest) {
                    Some(current) if m.execution.reusable_for(current) => {}
                    Some(current)
                        if m.execution.dependencies_complete && current.dependencies_complete =>
                    {
                        blockers.insert(ProviderBlocker::StaleExecution);
                    }
                    _ => {
                        blockers.insert(ProviderBlocker::FreshExecutionRequired);
                    }
                }
            }
            inventory_digest = Some(envelope.inventory_digest()?);
            index = SelectorIndex::new(&m.inventory);
        } else {
            blockers.insert(ProviderBlocker::IncompleteInventory);
            blockers.insert(ProviderBlocker::FreshExecutionRequired);
        }
        Ok(Self {
            envelope,
            digest,
            inventory_digest,
            index,
            blockers: blockers.into_iter().collect(),
            authenticated,
            accounted: envelope.inventory_accounted(),
            accepted_assumptions: policy.accepted_assumptions.clone(),
        })
    }
    /// Resolves every required member uniquely and composes complete-run,
    /// invocation and member premises through the shared proof algebra.
    ///
    /// # Errors
    /// Refuses malformed binding shape and retained metadata amplification.
    pub fn resolve_requirement(
        &self,
        binding: &ProviderRequirementBinding,
    ) -> Result<ProviderResolution, ProviderError> {
        self.resolve_with_budget(binding, &mut NormalizedBudget::default())
    }
    pub(crate) fn resolve_with_budget(
        &self,
        binding: &ProviderRequirementBinding,
        budget: &mut NormalizedBudget,
    ) -> Result<ProviderResolution, ProviderError> {
        use crate::assessment::{AssessmentDecision, EvidenceAcceptancePolicy};
        binding.validate()?;
        let mut blockers = self.blockers.iter().copied().collect::<BTreeSet<_>>();
        let mut result = ProviderResolution {
            requirement_id: binding.requirement_id.clone(),
            envelope_digest: self.digest.clone(),
            inventory_digest: self.inventory_digest.clone(),
            members: vec![],
            decision: AssessmentDecision::NotEvaluable,
            blockers: vec![],
            proof: None,
            evidence: vec![],
            acceptance: EvidenceAcceptancePolicy::default(),
        };
        let Some(m) = &self.envelope.run_manifest else {
            result.blockers = blockers.into_iter().collect();
            return Ok(result);
        };
        if m.provider != binding.provider || m.invocation_scope != binding.invocation_scope {
            blockers.insert(ProviderBlocker::WrongProvider);
        }
        if !self.envelope.format.is_test_execution() {
            blockers.insert(ProviderBlocker::IncompatibleEvidenceClass);
            result.blockers = blockers.into_iter().collect();
            return Ok(result);
        }
        if binding.authenticated_producer_required && !self.authenticated {
            blockers.insert(ProviderBlocker::ProducerNotAuthenticated);
        }
        if blockers.contains(&ProviderBlocker::IncompleteInventory)
            || blockers.contains(&ProviderBlocker::WrongBinding)
            || blockers.contains(&ProviderBlocker::WrongProvider)
        {
            result.blockers = blockers.into_iter().collect();
            return Ok(result);
        }
        let mut selected = BTreeSet::new();
        for selector in &binding.selectors {
            let Some(key) = self.index.resolve(&m.inventory, selector) else {
                blockers.insert(ProviderBlocker::SelectorRequiresReview);
                result.blockers = blockers.into_iter().collect();
                return Ok(result);
            };
            if !selected.insert(key) {
                blockers.insert(ProviderBlocker::SelectorRequiresReview);
                result.blockers = blockers.into_iter().collect();
                return Ok(result);
            }
            key.charge(budget)?;
            result.members.push(key.clone());
        }
        result.members.sort();
        let admitted = blockers.is_empty();
        let facts = self.requirement_facts(&result.members)?;
        let states =
            self.append_requirement_evidence(binding, &mut result, facts, admitted, budget)?;
        finalize_requirement_proof(&mut result, blockers, &states)?;
        Ok(result)
    }

    fn requirement_facts(
        &self,
        members: &[InventoryKey],
    ) -> Result<Vec<(String, crate::proof::ProofState)>, ProviderError> {
        use crate::proof::ProofState;
        let mut facts = vec![(
            "inventory".to_owned(),
            if self.accounted {
                ProofState::Satisfied
            } else {
                ProofState::Unknown
            },
        )];
        facts.push((
            "invocation".into(),
            match self.envelope.invocation.succeeded {
                Some(true) => ProofState::Satisfied,
                Some(false) => ProofState::Refuted,
                None => ProofState::Unknown,
            },
        ));
        for key in members {
            let outcome = self
                .envelope
                .observations
                .binary_search_by(|row| row.key.cmp(key))
                .ok()
                .map(|i| &self.envelope.observations[i]);
            let state = match outcome {
                Some(row) if row.attempts == Some(1) && !row.retry_metadata_present => {
                    match row.outcome {
                        ProviderOutcome::Passed => ProofState::Satisfied,
                        ProviderOutcome::Failed => ProofState::Refuted,
                        _ => ProofState::Unknown,
                    }
                }
                _ => ProofState::Unknown,
            };
            facts.push((
                format!(
                    "member:{}",
                    hash(&canonical(key).map_err(|e| ProviderError::Invalid(e.to_string()))?)
                ),
                state,
            ));
        }
        Ok(facts)
    }
    fn append_requirement_evidence(
        &self,
        binding: &ProviderRequirementBinding,
        result: &mut ProviderResolution,
        facts: Vec<(String, crate::proof::ProofState)>,
        admitted: bool,
        budget: &mut NormalizedBudget,
    ) -> Result<BTreeMap<String, crate::proof::ProofState>, ProviderError> {
        use crate::assessment::{AssessmentEvidence, EvidenceProposition};
        use crate::certification::EvidenceClass;
        use crate::proof::ProofState;
        let m = self
            .envelope
            .run_manifest
            .as_ref()
            .ok_or_else(|| ProviderError::Invalid("provider manifest is unavailable".into()))?;
        let mut states = BTreeMap::new();
        let scoped_assumptions = m
            .assumptions
            .iter()
            .map(|a| {
                format!(
                    "provider-assumption:{}",
                    hash(&canonical(&(&self.digest, a)).expect("strings serialize"))
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let assumption_charge = scoped_assumptions
            .iter()
            .try_fold(0usize, |sum, a| sum.checked_add(a.len() * 2 + 32))
            .ok_or(ProviderError::ResourceLimit("scoped assumptions"))?;
        for (fact, state) in facts {
            budget.charge(1024)?;
            budget.text(&binding.requirement_id)?;
            budget.charge(assumption_charge)?;
            let source_ref = format!(
                "provider-premise:{}",
                hash(
                    &canonical(&(&self.digest, &fact))
                        .map_err(|e| ProviderError::Invalid(e.to_string()))?
                )
            );
            let id = format!(
                "provider-leaf:{}",
                hash(
                    &canonical(&(&m.binding, &binding.requirement_id, &source_ref))
                        .map_err(|e| ProviderError::Invalid(e.to_string()))?
                )
            );
            let leaf = AssessmentEvidence {
                id: id.clone(),
                source_ref,
                binding: m.binding.clone(),
                scope_ref: binding.requirement_id.clone(),
                evidence_class: EvidenceClass::ExecutedTest,
                proposition: match state {
                    ProofState::Satisfied => EvidenceProposition::ExecutionSucceeded,
                    ProofState::Refuted => EvidenceProposition::ExecutionFailed,
                    ProofState::Unknown => EvidenceProposition::Unavailable,
                },
                payload_digest: self.envelope.payload_digest.clone(),
                assumptions: scoped_assumptions.clone(),
                valid_until: None,
            };
            if admitted && state != ProofState::Unknown {
                result
                    .acceptance
                    .verified_payloads
                    .insert(id.clone(), leaf.payload_digest.clone());
                result.acceptance.verified_metadata.insert(
                    id.clone(),
                    leaf.metadata_digest()
                        .map_err(|e| ProviderError::Invalid(e.to_string()))?,
                );
                if self.authenticated {
                    result.acceptance.authenticated_evidence.insert(id.clone());
                }
                if m.assumptions
                    .iter()
                    .all(|a| self.accepted_assumptions.contains(a))
                {
                    result
                        .acceptance
                        .accepted_assumptions
                        .extend(leaf.assumptions.iter().cloned());
                }
                states.insert(id, state);
            }
            result.evidence.push(leaf);
        }
        Ok(states)
    }
}

fn finalize_requirement_proof(
    result: &mut ProviderResolution,
    mut blockers: BTreeSet<ProviderBlocker>,
    states: &BTreeMap<String, crate::proof::ProofState>,
) -> Result<(), ProviderError> {
    use crate::assessment::AssessmentDecision;
    use crate::proof::{EvidenceReference, ProofExpression, ProofGraph, ProofOperator, ProofState};
    result.evidence.sort_by(|a, b| a.id.cmp(&b.id));
    let known = result
        .evidence
        .iter()
        .map(|e| e.id.clone())
        .collect::<BTreeSet<_>>();
    let proof = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".into(),
            operator: ProofOperator::All,
            required_refs: known
                .iter()
                .map(|id| EvidenceReference::new(id).expect("hashed identity"))
                .collect(),
            children: vec![],
        }],
    );
    let state = proof
        .evaluate(&known, states)
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    result.decision = match state {
        ProofState::Satisfied => AssessmentDecision::Satisfied,
        ProofState::Refuted => AssessmentDecision::NotSatisfied,
        ProofState::Unknown => AssessmentDecision::NotEvaluable,
    };
    if state == ProofState::Refuted {
        blockers.insert(ProviderBlocker::ExecutionFailed);
    }
    if state == ProofState::Unknown && blockers.is_empty() {
        blockers.insert(ProviderBlocker::IncompleteRun);
    }
    result.blockers = blockers.into_iter().collect();
    result.proof = Some(proof);
    Ok(())
}

/// Normalizes the controlled Cargo record against independently compiled source
/// and inventory. Missing execution dependencies stay unknown and fresh-only.
///
/// # Errors
/// Rejects wrong-source, contradictory or resource-excessive records.
pub fn normalize_controlled_cargo(
    suite: &crate::certification::RustSuiteExecution,
    expected: &crate::certification::CertificationSourceIdentity,
    binding: &DeclarationBinding,
) -> Result<(EvidenceEnvelope, Vec<u8>), ProviderError> {
    use crate::provider::{
        AttemptCount, ExecutionInput, InvocationOutcome, ProviderObservation, ProviderOutcome,
    };
    suite
        .validate()
        .map_err(|e| ProviderError::Invalid(e.to_string()))?;
    ensure(
        suite.certification_source_digest == expected.digest
            && suite.test_inventory_digest == expected.test_inventory_digest
            && suite.eligible_test_ids == expected.eligible_test_ids
            && suite.ignored_test_ids == expected.ignored_test_ids,
        "Cargo source/inventory differs from independently compiled identity",
    )?;
    let payload = canonical(suite).map_err(|e| ProviderError::Invalid(e.to_string()))?;
    preflight(&payload)?;
    let inventory = controlled_inventory(suite)?;
    let completed = suite.passed && suite.canonical_unfiltered;
    let attempts = if completed {
        inventory
            .iter()
            .map(|m| AttemptCount {
                key: m.key.clone(),
                count: u64::from(m.enabled),
            })
            .collect()
    } else {
        vec![]
    };
    let observations = inventory
        .iter()
        .map(|m| ProviderObservation {
            key: m.key.clone(),
            outcome: if !completed {
                ProviderOutcome::Unknown
            } else if m.enabled {
                ProviderOutcome::Passed
            } else {
                ProviderOutcome::Skipped
            },
            attempts: None,
            retry_metadata_present: false,
            finding_count: None,
        })
        .collect();
    let invocation = InvocationOutcome {
        succeeded: Some(suite.passed),
        exit_code: None,
    };
    let manifest = ProviderRunManifest {
        binding: binding.clone(),
        provider: suite.executor.clone(),
        provider_version: suite.executor_version.clone(),
        invocation_scope: "canonical-unfiltered-workspace".into(),
        execution: ExecutionDescriptor {
            binary_digest: None,
            tool_digest: None,
            arguments: None,
            working_directory: None,
            inputs: vec![
                ExecutionInput {
                    name: "certification-source".into(),
                    digest: expected.digest.clone(),
                },
                ExecutionInput {
                    name: "test-inventory".into(),
                    digest: expected.test_inventory_digest.clone(),
                },
            ],
            environment_dependencies: vec![],
            dependencies_complete: false,
        },
        inventory,
        inventory_complete: true,
        filters: vec![],
        filtering_known: suite.canonical_unfiltered,
        attempts_complete: completed,
        attempts,
        invocation: invocation.clone(),
        payload_digest: hash(&payload),
        assumptions: vec![],
    };
    let envelope = EvidenceEnvelope::compose(
        ProviderFormat::CargoSuite,
        Some(suite.executor.clone()),
        Some(suite.executor_version.clone()),
        hash(&payload),
        Some(manifest),
        observations,
        invocation,
        InvocationBasis::Payload,
        vec![],
    )?;
    Ok((envelope, payload))
}

fn controlled_inventory(
    suite: &crate::certification::RustSuiteExecution,
) -> Result<Vec<InventoryMember>, ProviderError> {
    let mut budget = NormalizedBudget::default();
    for id in suite
        .eligible_test_ids
        .iter()
        .chain(&suite.ignored_test_ids)
    {
        let charge = id
            .len()
            .checked_mul(5)
            .and_then(|n| n.checked_add(1024))
            .ok_or(ProviderError::ResourceLimit("controlled Cargo inventory"))?;
        budget.charge(charge)?;
    }
    let mut inventory = suite
        .eligible_test_ids
        .iter()
        .map(|id| (id, true))
        .chain(suite.ignored_test_ids.iter().map(|id| (id, false)))
        .map(|(id, enabled)| InventoryMember {
            key: InventoryKey {
                namespace: InventoryNamespace::GovernedTestId,
                package: None,
                target: None,
                qualified_name: id.clone(),
            },
            enabled,
        })
        .collect::<Vec<_>>();
    inventory.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(inventory)
}
