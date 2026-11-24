//! Bounded exact observation of one Python filesystem call shape.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

use super::{
    PythonScalarError, PythonScalarProducer, admitted_source, digest, identifier, valid_digest,
};
use crate::observation::SourceView;
use crate::project::EvaluationKey;
use crate::wire::{JsonAdmissionLimits, admit_json, parse_strict_json_bytes};

const READY_SCHEMA: &str = "fortress-host/python-filesystem-calls-ready/1";
const REQUEST_SCHEMA: &str = "fortress:python:filesystem-calls-request:1";
const RESPONSE_SCHEMA: &str = "fortress:python:filesystem-calls-response:1";
const MAX_FRAME: usize = 4096;
// Exact reviewed tool identities for this response edition. The trusted host
// selects and verifies the worker bytes before sending source.
const FILESYSTEM_WORKER_REF: &str =
    "sha256:1fca1c074f3dca8c2fe1a6676fdfaa3978d639f18eff772d4ac8b92b93a69ffe";
const LEXICAL_BOOTSTRAP_REF: &str =
    "sha256:19ca652a6ed8908d128ac231da47b45d0b0a86a9baffaff9626fb2d1609c9836";
const RESPONSE_LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: MAX_FRAME - 1,
    depth: 4,
    nodes: 48,
    token_bytes: 256,
};

/// Exact installed profiles for the separately qualified v1 worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PythonFilesystemProfile {
    /// Frozen `CPython` 3.13.5 installed receiver on Windows x64.
    WindowsX64,
    /// Frozen `CPython` 3.12.3 installed receiver on Linux x64.
    LinuxX64,
}

impl PythonFilesystemProfile {
    /// Exact independently observed runtime descriptor digest, without framing.
    #[must_use]
    pub const fn runtime_ref(self) -> &'static str {
        match self {
            Self::WindowsX64 => {
                "sha256:c3c97417572f780314efe1ac3c4d5ce5e3cef99b1d5a93e5faec954a7c3fb7ce"
            }
            Self::LinuxX64 => {
                "sha256:043f738ca7ba9a9f6ee42cb1cf8a5a0cd453a1528d47d45cc021647dcd36802a"
            }
        }
    }

    /// Exact independently selected definition and receiver expectations.
    #[must_use]
    pub const fn installed_receiver(self) -> PythonInstalledFilesystemReceiver {
        let features = ["isolated", "no-site"];
        match self {
            Self::WindowsX64 => PythonInstalledFilesystemReceiver {
                context_ref: "sha256:e7fd36144d77040e4b15d5804817c959d91e5864426eb1a87083b5f346f37fb2",
                definition_symbol: "PathBase.write_bytes",
                entry_ref: "sha256:62b3b842bda77ca6245f8c8657b8c72540e383fb9aa70e4c3a705947cc8611fd",
                features,
                members: [
                    (
                        "definition",
                        "pathlib/_abc.py",
                        "sha256:e37c70955985422905b5ea77572f2e89b5bd45465f5d83a13e35bbc409f603c2",
                    ),
                    (
                        "receiver",
                        "pathlib/_local.py",
                        "sha256:f50e14b22650d169b2a4a33d71f8cee5546a306ddc38a5179aa3ec5a41bb1983",
                    ),
                ],
                receiver: "pathlib._local.WindowsPath",
                target: "windows/amd64",
                version: "3.13.5",
            },
            Self::LinuxX64 => {
                let file =
                    "sha256:b43e134bf7479759838b4ecec3d78e0e67fdfde2d671c5c2d7886a47da93885d";
                PythonInstalledFilesystemReceiver {
                    context_ref: "sha256:e8f5edbfdbb267a48b402ac87b416b6f574a07f3ec163c8ea74e927c5c35a85b",
                    definition_symbol: "Path.write_bytes",
                    entry_ref: file,
                    features,
                    members: [
                        ("definition", "pathlib.py", file),
                        ("receiver", "pathlib.py", file),
                    ],
                    receiver: "pathlib.PosixPath",
                    target: "linux/amd64",
                    version: "3.12.3",
                }
            }
        }
    }

    fn readiness(self) -> (&'static str, &'static str, Value) {
        match self {
            Self::WindowsX64 => (
                "cpython3.13",
                "WINDOWS_JOB_WALL_V1",
                json!({"active_processes":1,"commit_bytes":100_663_296,"kill_on_close":true}),
            ),
            Self::LinuxX64 => (
                "cpython3.12",
                "LINUX_AS_CPU_V1",
                json!({"address_space_bytes":100_663_296,"core_bytes":0,"cpu_seconds":1}),
            ),
        }
    }
}

/// Isolated worker's installed standard-library receiver. A separate pristine
/// process must establish isolated import origin for any hypothetical model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PythonInstalledFilesystemReceiver {
    /// Exact canonical ordered definition and receiver inventory digest.
    pub context_ref: &'static str,
    /// Qualified name of the verified installed method definition.
    pub definition_symbol: &'static str,
    /// Exact installed top-level module entry digest.
    pub entry_ref: &'static str,
    /// Explicitly qualified isolated runtime features.
    pub features: [&'static str; 2],
    /// Ordered role, physical installation-relative path, and exact member digest.
    pub members: [(&'static str, &'static str, &'static str); 2],
    /// Exact native concrete receiver type.
    pub receiver: &'static str,
    /// Fixed native operating system and architecture.
    pub target: &'static str,
    /// Exact selected `CPython` version.
    pub version: &'static str,
}

/// Bound compile-only exchange for one Python source and top-level function.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonFilesystemRequest {
    exchange_ref: String,
    source_view_ref: String,
    evaluation_ref: String,
    source_path: String,
    source_ref: String,
    function: String,
    producer: PythonScalarProducer,
    profile: PythonFilesystemProfile,
}

impl PythonFilesystemRequest {
    /// Selects exact immutable original inputs and qualified producer pins.
    ///
    /// # Errors
    /// Refuses a wrong profile, producer, invalid selected source, or unexpected identity.
    pub fn bind(
        view: &SourceView,
        evaluation: &EvaluationKey,
        path: &str,
        function: &str,
        producer: &PythonScalarProducer,
        profile: PythonFilesystemProfile,
    ) -> Result<Self, PythonFilesystemError> {
        if !identifier(function)
            || producer.worker != FILESYSTEM_WORKER_REF
            || producer.bootstrap != LEXICAL_BOOTSTRAP_REF
            || producer.runtime != profile.runtime_ref()
            || ![
                evaluation.source_manifest_digest(),
                evaluation.program_context_digest(),
                evaluation.authority_binding_digest(),
            ]
            .into_iter()
            .all(valid_digest)
        {
            return Err(PythonFilesystemError::Binding);
        }
        let source = admitted_source(view, path).map_err(PythonFilesystemError::Source)?;
        let source_ref = digest(source);
        let evaluation_ref = evaluation.digest();
        let material = canonical(&(
            REQUEST_SCHEMA,
            view.digest(),
            &evaluation_ref,
            path,
            &source_ref,
            function,
            producer,
            profile,
        ))?;
        Ok(Self {
            exchange_ref: digest(&material),
            source_view_ref: view.digest().into(),
            evaluation_ref,
            source_path: path.into(),
            source_ref,
            function: function.into(),
            producer: producer.clone(),
            profile,
        })
    }

    /// Identity of the exact request, including view, evaluation and producer.
    #[must_use]
    pub fn exchange_ref(&self) -> &str {
        &self.exchange_ref
    }

    /// Exact physical repository-relative source path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Exact original source digest.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    /// Builds the exact byte-for-byte READY line a pinned supervisor must compare
    /// with live output before forwarding source. This line is an expectation.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn expected_ready(&self) -> Result<Vec<u8>, PythonFilesystemError> {
        let (grammar, profile, limits) = self.profile.readiness();
        let mut wire = canonical(&json!({
            "schema": READY_SCHEMA,
            "status": "READY",
            "grammar": grammar,
            "profile": profile,
            "limits": limits,
            "worker_ref": self.producer.worker,
            "bootstrap_ref": self.producer.bootstrap,
            "runtime_ref": self.producer.runtime,
            "stdlib_receiver": self.profile.installed_receiver(),
        }))?;
        wire.push(b'\n');
        Ok(wire)
    }

    /// Encodes the bounded v1 request from the still-current original `SourceView`.
    ///
    /// # Errors
    /// Refuses source changes and canonical encoding errors.
    pub fn worker_payload(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
    ) -> Result<Vec<u8>, PythonFilesystemError> {
        let source = self.source_bytes(view, evaluation)?;
        canonical(&json!({
            "schema": REQUEST_SCHEMA,
            "id": self.wire_id(),
            "source": STANDARD.encode(source),
            "byte_count": source.len(),
            "source_path": self.source_path,
            "source_ref": self.source_ref,
            "function": self.function,
            "worker_ref": self.producer.worker,
            "bootstrap_ref": self.producer.bootstrap,
            "runtime_ref": self.producer.runtime,
        }))
    }

    /// Admits a correlated response only for the exact captured source and READY line.
    ///
    /// The host must supervise the reviewed executable, compare the live readiness
    /// expectation before releasing source and enforce its timeout and output limits.
    /// This parser authenticates no process or portable receipt.
    ///
    /// # Errors
    /// Refuses stale inputs, wrong readiness, malformed frames, mismatched identities,
    /// or invalid physical source coordinates.
    pub fn admit(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
        observed_ready: &[u8],
        reply: &[u8],
    ) -> Result<PythonFilesystemObservation, PythonFilesystemError> {
        let source = self.source_bytes(view, evaluation)?;
        if observed_ready != self.expected_ready()? {
            return Err(PythonFilesystemError::InvalidReady);
        }
        if reply.len() > MAX_FRAME {
            return Err(PythonFilesystemError::ResponseLimit);
        }
        let message = reply
            .strip_suffix(b"\n")
            .filter(|body| body.is_ascii() && !body.contains(&b'\n'))
            .ok_or(PythonFilesystemError::InvalidResponse)?;
        admit_json(message, RESPONSE_LIMITS).map_err(|_| PythonFilesystemError::InvalidResponse)?;
        let raw: RawReply =
            parse_strict_json_bytes(message).map_err(|_| PythonFilesystemError::InvalidResponse)?;
        let receiver = self.profile.installed_receiver();
        if canonical(&raw)? != message
            || raw.schema != RESPONSE_SCHEMA
            || raw.id != self.wire_id()
            || raw.byte_count != source.len()
            || raw.source_path != self.source_path
            || raw.source_ref != self.source_ref
            || raw.function != self.function
            || raw.worker_ref != self.producer.worker
            || raw.bootstrap_ref != self.producer.bootstrap
            || raw.runtime_ref != self.producer.runtime
            || raw.installed_context_ref != receiver.context_ref
            || raw.target_execution != "NOT_RUN"
            || raw.project_runtime_import_binding != "UNESTABLISHED"
            || raw.effect_projection != "NOT_PERFORMED"
        {
            return Err(PythonFilesystemError::InvalidResponse);
        }
        Ok(PythonFilesystemObservation {
            request: self.clone(),
            ready_ref: digest(observed_ready),
            response_ref: digest(reply),
            installed_receiver: receiver,
            outcome: raw.outcome(source)?,
            project_runtime_import_binding: "UNESTABLISHED",
            target_execution: "NOT_RUN",
            effect_projection: "NOT_PERFORMED",
        })
    }

    fn source_bytes<'a>(
        &self,
        view: &'a SourceView,
        evaluation: &EvaluationKey,
    ) -> Result<&'a [u8], PythonFilesystemError> {
        if view.digest() != self.source_view_ref || evaluation.digest() != self.evaluation_ref {
            return Err(PythonFilesystemError::StaleInput);
        }
        let source =
            admitted_source(view, &self.source_path).map_err(PythonFilesystemError::Source)?;
        if digest(source) != self.source_ref {
            return Err(PythonFilesystemError::StaleInput);
        }
        Ok(source)
    }

    fn wire_id(&self) -> &str {
        &self.exchange_ref["sha256:".len()..]
    }
}

/// Exact source byte span supplied by the pinned worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PythonFilesystemSite {
    /// Inclusive UTF-8 byte offset.
    pub start_byte: usize,
    /// Exclusive UTF-8 byte offset.
    pub end_byte: usize,
}

/// Fixed v1 reasons for unsupported or unavailable source shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonFilesystemReason {
    /// Runtime values would affect receiver or arguments.
    DynamicArgument,
    /// The expression lacks a directly constructed named receiver.
    IndirectReceiver,
    /// One matching lexical scope could not be established.
    LexicalScopeUnestablished,
    /// Additional module behavior prevents the closed shape.
    ModuleFormUnsupported,
    /// The required exact source import binding was absent.
    ImportBindingUnestablished,
    /// Physical spelling differed from the supported lexical form.
    NoncanonicalBindingSpelling,
    /// The declaration has behavior outside the supported syntax.
    FunctionFormUnsupported,
    /// There is no selected top-level function.
    MissingFunction,
    /// More than one declaration matches the selector.
    AmbiguousFunction,
    /// One direct return call could not be established.
    DirectReturnCallUnestablished,
    /// The source failed a compiler or lexical admission gate.
    InadmissibleSource,
}

impl PythonFilesystemReason {
    const fn is_unavailable(self) -> bool {
        matches!(
            self,
            Self::MissingFunction
                | Self::AmbiguousFunction
                | Self::DirectReturnCallUnestablished
                | Self::InadmissibleSource
        )
    }
}

/// Exact compiler observation with no runtime import or effect disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonFilesystemOutcome {
    /// One closed literal source shape, without actual callee authority.
    ClosedLiteralShape {
        /// Physical call range in the original bytes.
        site: PythonFilesystemSite,
    },
    /// A lexically local declaration shadows the candidate receiver.
    LocalOrShadowed {
        /// Physical call range in the original bytes.
        site: PythonFilesystemSite,
    },
    /// The exact call shape lies outside the supported scope.
    Unresolved {
        /// Physical call range in the original bytes.
        site: PythonFilesystemSite,
        /// Why the call shape is unresolved.
        reason: PythonFilesystemReason,
    },
    /// The observation did not establish a specific physical call.
    Unavailable {
        /// Why the selected source or declaration is unavailable.
        reason: PythonFilesystemReason,
    },
}

/// A single admitted compile-only observation and its independently pinned receiver.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonFilesystemObservation {
    request: PythonFilesystemRequest,
    ready_ref: String,
    response_ref: String,
    installed_receiver: PythonInstalledFilesystemReceiver,
    outcome: PythonFilesystemOutcome,
    project_runtime_import_binding: &'static str,
    target_execution: &'static str,
    effect_projection: &'static str,
}

impl PythonFilesystemObservation {
    /// Exact retained request and source binding.
    #[must_use]
    pub const fn request(&self) -> &PythonFilesystemRequest {
        &self.request
    }

    /// Digest of the admitted READY frame including its final LF.
    #[must_use]
    pub fn ready_ref(&self) -> &str {
        &self.ready_ref
    }

    /// Digest of the admitted response frame including its final LF.
    #[must_use]
    pub fn response_ref(&self) -> &str {
        &self.response_ref
    }

    /// Independently selected installed receiver matched by the worker.
    #[must_use]
    pub const fn installed_receiver(&self) -> PythonInstalledFilesystemReceiver {
        self.installed_receiver
    }

    /// Admitted source-side classification.
    #[must_use]
    pub const fn outcome(&self) -> &PythonFilesystemOutcome {
        &self.outcome
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RawStatus {
    ClosedLiteralShape,
    LocalOrShadowed,
    Unresolved,
    Unavailable,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawReply {
    schema: String,
    id: String,
    byte_count: usize,
    source_path: String,
    source_ref: String,
    function: String,
    worker_ref: String,
    bootstrap_ref: String,
    runtime_ref: String,
    installed_context_ref: String,
    target_execution: String,
    project_runtime_import_binding: String,
    effect_projection: String,
    status: RawStatus,
    #[serde(deserialize_with = "required_nullable")]
    reason: Option<PythonFilesystemReason>,
    #[serde(deserialize_with = "required_nullable")]
    site: Option<[usize; 2]>,
}

impl RawReply {
    fn outcome(&self, source: &[u8]) -> Result<PythonFilesystemOutcome, PythonFilesystemError> {
        use PythonFilesystemOutcome as Outcome;
        let site = self
            .site
            .map(|[start_byte, end_byte]| {
                let text = std::str::from_utf8(source)
                    .map_err(|_| PythonFilesystemError::InvalidResponse)?;
                if text.get(start_byte..end_byte).is_none_or(str::is_empty) {
                    return Err(PythonFilesystemError::InvalidResponse);
                }
                Ok(PythonFilesystemSite {
                    start_byte,
                    end_byte,
                })
            })
            .transpose()?;
        match (&self.status, site, self.reason) {
            (RawStatus::ClosedLiteralShape, Some(site), None) => {
                Ok(Outcome::ClosedLiteralShape { site })
            }
            (RawStatus::LocalOrShadowed, Some(site), None) => Ok(Outcome::LocalOrShadowed { site }),
            (RawStatus::Unresolved, Some(site), Some(reason)) if !reason.is_unavailable() => {
                Ok(Outcome::Unresolved { site, reason })
            }
            (RawStatus::Unavailable, None, Some(reason)) if reason.is_unavailable() => {
                Ok(Outcome::Unavailable { reason })
            }
            _ => Err(PythonFilesystemError::InvalidResponse),
        }
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, PythonFilesystemError> {
    serde_json_canonicalizer::to_vec(value).map_err(PythonFilesystemError::Json)
}

/// Exact compile-only filesystem exchange failure.
#[derive(Debug)]
pub enum PythonFilesystemError {
    /// Selected source or producer identities are invalid.
    Binding,
    /// Immutable view, source or evaluation differs from the request.
    StaleInput,
    /// The existing Python source admission gate refused the source.
    Source(PythonScalarError),
    /// The live READY frame differs from the exact configured expectation.
    InvalidReady,
    /// The bounded frame size was exceeded.
    ResponseLimit,
    /// The response is uncorrelated, malformed or outside the typed scope.
    InvalidResponse,
    /// Deterministic serialization failed.
    Json(serde_json::Error),
}

impl Display for PythonFilesystemError {
    fn fmt(&self, output: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding => output.write_str("invalid Python filesystem input binding"),
            Self::StaleInput => output.write_str("stale Python filesystem observation input"),
            Self::Source(error) => write!(output, "Python filesystem source refused: {error}"),
            Self::InvalidReady => output.write_str("invalid Python filesystem readiness frame"),
            Self::ResponseLimit => output.write_str("Python filesystem response exceeds its limit"),
            Self::InvalidResponse => output.write_str("invalid Python filesystem response frame"),
            Self::Json(error) => write!(
                output,
                "Python filesystem JSON construction failed: {error}"
            ),
        }
    }
}

impl Error for PythonFilesystemError {}
