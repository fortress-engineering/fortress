//! Exact admitted Go collector output for native observation version 1.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "go_build_selection.rs"]
mod build_selection;
pub(crate) use build_selection::admit_go_build;
pub use build_selection::{GoBuildContext, GoBuildTestMode, GoNativeBuildObservation};

use crate::observation::SourceView;
use crate::wire::{
    JsonAdmissionLimits, admit_json, canonicalize_public_json, parse_strict_json_bytes,
};

const PRODUCER: &str = "fortress.go-observations@0.1.1";
const MAX_WIRE: usize = 1 << 20;
const MAX_SOURCE: usize = 512 << 10;
const MAX_FILE: usize = 64 << 10;
const MAX_FILES: usize = 64;
const MAX_RECORDS: usize = 4096;
const LIMITATIONS: [&str; 5] = [
    "HOST_MUST_ESTABLISH_PACKAGE_AND_CONTEXT_COMPLETENESS",
    "NO_DEPENDENCIES_BUILD_CONDITIONS_OR_FOREIGN_CONTEXT",
    "BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
    "NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
    "INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
];

/// A bounded failure at the explicit Go observation boundary.
#[derive(Debug)]
pub enum GoObservationError {
    /// The selected package directory or language context is unsupported.
    UnsupportedContext,
    /// Required host identity information is missing or malformed.
    InvalidTrustedBinding,
    /// An input, response or admitted record exceeded its resource limit.
    ResourceLimit,
    /// The native response failed exact wire or source verification.
    InvalidResponse,
    /// The process identity differs from the previously selected identity.
    UnmatchedExecution,
    /// Canonical binding or request bytes could not be serialized.
    WireEncoding,
    /// Physical source or original governing authority could not be captured.
    SourceUnavailable(String),
    /// Physical source or governing inputs changed during observation.
    SourceChanged,
    /// The independently selected supervisor could not complete the process.
    Execution(String),
}

impl std::fmt::Display for GoObservationError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnsupportedContext => {
                "Go observation needs one supported closed source directory and exact target context"
            }
            Self::InvalidTrustedBinding => "Go collector host identity is incomplete",
            Self::ResourceLimit => "Go observation exceeded a bounded resource limit",
            Self::InvalidResponse => {
                "Go collector response does not bind the exact admitted input and known wire contract"
            }
            Self::UnmatchedExecution => {
                "Go collector execution identity differs from its selected binding"
            }
            Self::WireEncoding => "Go observation binding could not be serialized",
            Self::SourceChanged => {
                "Physical source or authority changed before Go observation publication"
            }
            Self::SourceUnavailable(detail) | Self::Execution(detail) => {
                return output.write_str(detail);
            }
        };
        output.write_str(message)
    }
}

impl std::error::Error for GoObservationError {}

// This must come from an exact actual or hypothetical Snapshot Governance owner,
// which attests complete ordinary-file observation with no exclusions affecting
// this directory or its ancestors. SourceView alone cannot establish completeness.
#[derive(Clone, Copy)]
pub(crate) struct ExactClosedPackage<'a> {
    pub(crate) source: &'a SourceView,
    pub(crate) source_fingerprint: &'a str,
    pub(crate) authority_digest: &'a str,
    pub(crate) actual: bool,
    pub(crate) directory: &'a str,
    pub(crate) package_path: &'a str,
    pub(crate) go_version: &'a str,
    pub(crate) target_os: &'a str,
    pub(crate) target_arch: &'a str,
}

/// Exact Go process identity selected independently of the repository.
#[derive(PartialEq, Eq, Serialize)]
pub struct GoCollectorPin<'a> {
    /// SHA-256 of the admitted native executable bytes.
    pub executable_sha256: &'a str,
    /// Digest of the supported supervisor and execution environment.
    pub supervisor_context_sha256: &'a str,
    /// Exact Go runtime version reported by the admitted executable.
    pub go_toolchain: &'a str,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    path: String,
    sha256: String,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    package_path: String,
    go_version: String,
    target_os: String,
    target_arch: String,
    source_inventory: Vec<SourceIdentity>,
}

#[derive(Serialize)]
struct Request<'a> {
    schema_version: u16,
    package_path: &'a str,
    go_version: &'a str,
    target_os: &'a str,
    target_arch: &'a str,
    files: Vec<RequestFile<'a>>,
}

#[derive(Serialize)]
struct RequestFile<'a> {
    path: &'a str,
    sha256: String,
    source_base64: String,
}

struct SourceText<'a> {
    text: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceText<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, GoObservationError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| GoObservationError::UnsupportedContext)?;
        // go/token only records starts strictly before EOF.
        let line_starts = std::iter::once(0)
            .chain(bytes.split_last().into_iter().flat_map(|(_, initial)| {
                initial
                    .iter()
                    .enumerate()
                    .filter_map(|(i, b)| (*b == b'\n').then_some(i + 1))
            }))
            .collect();
        Ok(Self { text, line_starts })
    }

    fn span(&self, span: &Span) -> Result<&str, GoObservationError> {
        let text = self
            .text
            .get(span.start_byte..span.end_byte)
            .ok_or(GoObservationError::InvalidResponse)?;
        let line = self
            .line_starts
            .partition_point(|&start| start <= span.start_byte);
        let column = span.start_byte - self.line_starts[line - 1] + 1;
        if span.start_line != line || span.start_byte_column != column {
            return Err(GoObservationError::InvalidResponse);
        }
        Ok(text)
    }
}

#[derive(Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Span {
    path: String,
    start_byte: usize,
    end_byte: usize,
    start_line: usize,
    start_byte_column: usize,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Implementation {
    SourceBody,
    ExternalBodyUnobserved,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DeclarationKind {
    Function,
    Method,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    name: String,
    kind: DeclarationKind,
    declared_signature: String,
    implementation: Implementation,
    span: Span,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Resolution {
    DirectFunction,
    DirectMethod,
    ExternalBodyUnobserved,
    TypeConversion,
    Builtin,
    UnresolvedCallForm,
    UnresolvedInterfaceDispatch,
    UnresolvedFunctionValue,
    UnresolvedDeclaration,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Activation {
    Ordinary,
    Goroutine,
    Deferred,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: Option<String>,
    resolution: Resolution,
    activation: Activation,
    span: Span,
    declaration: Option<Span>,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Status {
    Observed,
    InvalidRequest,
    InvalidSource,
    Unsupported,
    ResourceLimit,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    code: String,
    span: Option<Span>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u16,
    producer: String,
    go_toolchain: String,
    request_sha256: String,
    context_sha256: Option<String>,
    context: Option<Context>,
    status: Status,
    diagnostic: Option<Diagnostic>,
    package_name: Option<String>,
    declarations: Vec<Declaration>,
    calls: Vec<Call>,
    limitations: Vec<String>,
}

#[derive(Serialize)]
struct Provenance<'a> {
    kind: &'static str,
    source_view_sha256: &'a str,
    source_fingerprint: &'a str,
    authority_sha256: &'a str,
    actual: bool,
    package_directory: &'a str,
    process: &'a GoCollectorPin<'a>,
    wire_context_sha256: &'a str,
    request_sha256: &'a str,
}

/// Exact-source native Go observations outside canonical PSM and enforcement.
#[derive(Serialize)]
pub struct GoNativeObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    binding_sha256: String,
    response_sha256: String,
    provenance: serde_json::Value,
    observation: Response,
}

pub(crate) struct GoRequest<'a> {
    wire: Vec<u8>,
    files: BTreeMap<&'a str, SourceText<'a>>,
    context: Context,
    context_sha256: String,
    request_sha256: String,
    binding_sha256: String,
    provenance: serde_json::Value,
    pin: &'a GoCollectorPin<'a>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn portable_ascii_path(path: &str) -> bool {
    path.len() <= 240
        && path.split('/').all(|part| {
            !part.is_empty()
                && part.len() <= 96
                && !part.starts_with('.')
                && !part.ends_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
        && crate::observation::is_canonical_relative_path(path)
}

fn has_case_alias(path: &str, directory: &str) -> bool {
    for (actual, expected) in path.split('/').zip(directory.split('/')) {
        if actual != expected {
            return actual.eq_ignore_ascii_case(expected);
        }
    }
    false
}

pub(crate) fn admit_go<'a>(
    selection: ExactClosedPackage<'a>,
    pin: &'a GoCollectorPin<'a>,
) -> Result<GoRequest<'a>, GoObservationError> {
    admit_go_with(selection, pin, None)
}

#[allow(clippy::too_many_lines)]
fn admit_go_with<'a>(
    selection: ExactClosedPackage<'a>,
    pin: &'a GoCollectorPin<'a>,
    build: Option<&GoBuildContext>,
) -> Result<GoRequest<'a>, GoObservationError> {
    let ExactClosedPackage {
        source,
        source_fingerprint,
        authority_digest,
        actual,
        directory,
        package_path,
        go_version,
        target_os,
        target_arch,
    } = selection;
    if ![
        source_fingerprint,
        authority_digest,
        pin.executable_sha256,
        pin.supervisor_context_sha256,
    ]
    .into_iter()
    .all(digest)
        || !pin.go_toolchain.starts_with("go1.")
        || pin.go_toolchain.len() > 64
        || !pin
            .go_toolchain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
    {
        return Err(GoObservationError::InvalidTrustedBinding);
    }
    if (!directory.is_empty() && !portable_ascii_path(directory))
        || !portable_ascii_path(package_path)
        || directory
            .split('/')
            .any(|part| matches!(part, "vendor" | "__fortress"))
        || !matches!(go_version, "go1.17" | "go1.22")
        || !matches!(target_os, "windows" | "linux")
        || !(target_arch == "amd64" || build.is_some() && target_arch == "arm64")
    {
        return Err(GoObservationError::UnsupportedContext);
    }

    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut context = Context {
        package_path: package_path.into(),
        go_version: go_version.into(),
        target_os: target_os.into(),
        target_arch: target_arch.into(),
        source_inventory: Vec::new(),
    };
    let mut request = Request {
        schema_version: if build.is_some() { 2 } else { 1 },
        package_path,
        go_version,
        target_os,
        target_arch,
        files: Vec::new(),
    };
    let mut total = 0;
    for (path, bytes) in source.files() {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let ancestor = dir.is_empty()
            || directory
                .strip_prefix(dir)
                .is_some_and(|suffix| suffix.starts_with('/'));
        if has_case_alias(path, directory)
            || path == directory
            || (ancestor
                && ["go.mod", "go.work", "go.sum", "go.work.sum", "godebug"]
                    .iter()
                    .any(|marker| name.eq_ignore_ascii_case(marker)))
        {
            return Err(GoObservationError::UnsupportedContext);
        }
        if dir != directory {
            continue;
        }
        // The initial language/context experiment is Go-source-only. Never
        // silently omit test/target files, assembly, generated inputs or assets.
        let valid_path = if build.is_some() {
            build_selection::valid_source_path(path, dir, name)
        } else {
            portable_ascii_path(path)
        };
        if !valid_path
            || Path::new(name).extension() != Some(OsStr::new("go"))
            || (build.is_none() && name.contains('_'))
            || !folded.insert(name.to_ascii_lowercase())
        {
            return Err(GoObservationError::UnsupportedContext);
        }
        if bytes.len() > MAX_FILE || files.len() >= MAX_FILES {
            return Err(GoObservationError::ResourceLimit);
        }
        total += bytes.len();
        if total > MAX_SOURCE {
            return Err(GoObservationError::ResourceLimit);
        }
        files.insert(path.as_str(), SourceText::new(bytes)?);
        let sha256 = sha256(bytes);
        request.files.push(RequestFile {
            path,
            sha256: sha256.clone(),
            source_base64: STANDARD.encode(bytes),
        });
        context.source_inventory.push(SourceIdentity {
            path: path.clone(),
            sha256,
        });
    }
    if files.is_empty() {
        return Err(GoObservationError::UnsupportedContext);
    }
    let wire = if let Some(build_context) = build {
        build_selection::encode_request(&request, build_context)
    } else {
        serde_json::to_vec(&request)
    }
    .map_err(|_| GoObservationError::WireEncoding)?;
    if wire.len() > MAX_WIRE {
        return Err(GoObservationError::ResourceLimit);
    }
    // The collector's local protocol uses Go JSON struct order, with admitted
    // path/context characters having identical escaped bytes in both encoders.
    let context_bytes = if let Some(build_context) = build {
        build_selection::encode_context(&context, build_context)
    } else {
        serde_json::to_vec(&context)
    }
    .map_err(|_| GoObservationError::WireEncoding)?;
    let context_sha256 = sha256(&context_bytes);
    let request_sha256 = sha256(&wire);
    let envelope = Provenance {
        kind: if build.is_some() {
            "fortress-go-build-observation-input-v2"
        } else {
            "fortress-go-observation-input-v1"
        },
        source_view_sha256: source.digest(),
        source_fingerprint,
        authority_sha256: authority_digest,
        actual,
        package_directory: directory,
        process: pin,
        wire_context_sha256: &context_sha256,
        request_sha256: &request_sha256,
    };
    let provenance =
        serde_json::to_value(&envelope).map_err(|_| GoObservationError::WireEncoding)?;
    let canonical_input =
        serde_json::to_string(&provenance).map_err(|_| GoObservationError::WireEncoding)?;
    let canonical =
        canonicalize_public_json(&canonical_input).map_err(|_| GoObservationError::WireEncoding)?;
    Ok(GoRequest {
        wire,
        files,
        context,
        context_sha256,
        request_sha256,
        binding_sha256: sha256(&canonical),
        provenance,
        pin,
    })
}

impl GoRequest<'_> {
    pub(crate) fn request_bytes(&self) -> &[u8] {
        &self.wire
    }

    // Identity comes from the independent trusted supervisor's process evidence,
    // never stdout, a repository manifest or caller-supplied evaluation context.
    pub(crate) fn verify(
        &self,
        launched: &GoCollectorPin<'_>,
        stdout: &[u8],
    ) -> Result<GoNativeObservation, GoObservationError> {
        let line = self.verify_transport(launched, stdout)?;
        let answer: Response =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        self.verify_header(&answer, 1, PRODUCER, &LIMITATIONS)?;
        if answer.status == Status::ResourceLimit
            && answer
                .diagnostic
                .as_ref()
                .is_some_and(|d| d.code == "RESPONSE_BYTE_LIMIT")
            && answer.context.is_none()
            && answer.context_sha256.is_none()
            && answer.declarations.is_empty()
            && answer.calls.is_empty()
            && answer.package_name.is_none()
            && answer.diagnostic.as_ref().is_some_and(|d| d.span.is_none())
        {
            return Err(GoObservationError::ResourceLimit);
        }
        if answer.context.as_ref() != Some(&self.context)
            || answer.context_sha256.as_deref() != Some(self.context_sha256.as_str())
            || answer.declarations.len() + answer.calls.len() > MAX_RECORDS
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if answer.status == Status::Observed {
            if answer.diagnostic.is_some()
                || !answer.package_name.as_deref().is_some_and(display_name)
            {
                return Err(GoObservationError::InvalidResponse);
            }
            self.verify_records(&answer)?;
        } else {
            if !answer.calls.is_empty()
                || !answer.declarations.is_empty()
                || answer.package_name.is_some()
                || answer.status == Status::InvalidRequest
            {
                return Err(GoObservationError::InvalidResponse);
            }
            let diagnostic = answer
                .diagnostic
                .as_ref()
                .ok_or(GoObservationError::InvalidResponse)?;
            if !known_diagnostic(&answer.status, &diagnostic.code) {
                return Err(GoObservationError::InvalidResponse);
            }
            if let Some(span) = &diagnostic.span {
                self.span(span)?;
            }
        }
        Ok(GoNativeObservation {
            schema: "urn:fortress:derived:v1:go-native-observation",
            schema_version: 1,
            binding_sha256: self.binding_sha256.clone(),
            response_sha256: sha256(stdout),
            provenance: self.provenance.clone(),
            observation: answer,
        })
    }

    fn verify_transport<'o>(
        &self,
        launched: &GoCollectorPin<'_>,
        stdout: &'o [u8],
    ) -> Result<&'o [u8], GoObservationError> {
        if launched != self.pin {
            return Err(GoObservationError::UnmatchedExecution);
        }
        if stdout.len() > MAX_WIRE {
            return Err(GoObservationError::ResourceLimit);
        }
        let Some(line) = stdout.strip_suffix(b"\n") else {
            return Err(GoObservationError::InvalidResponse);
        };
        if line.first() != Some(&b'{')
            || line.last() != Some(&b'}')
            || line.contains(&b'\n')
            || line.contains(&b'\r')
        {
            return Err(GoObservationError::InvalidResponse);
        }
        admit_json(
            line,
            JsonAdmissionLimits {
                bytes: MAX_WIRE,
                depth: 12,
                nodes: 250_000,
                token_bytes: 16 << 10,
            },
        )
        .map_err(|_| GoObservationError::ResourceLimit)?;
        Ok(line)
    }

    fn verify_header(
        &self,
        answer: &Response,
        version: u16,
        producer: &str,
        limitations: &[&str],
    ) -> Result<(), GoObservationError> {
        if answer.schema_version != version
            || answer.producer != producer
            || answer.go_toolchain != self.pin.go_toolchain
            || answer.request_sha256 != self.request_sha256
            || !answer
                .limitations
                .iter()
                .map(String::as_str)
                .eq(limitations.iter().copied())
        {
            return Err(GoObservationError::InvalidResponse);
        }
        Ok(())
    }

    fn span(&self, span: &Span) -> Result<&str, GoObservationError> {
        self.files
            .get(span.path.as_str())
            .ok_or(GoObservationError::InvalidResponse)?
            .span(span)
    }

    fn verify_records(&self, answer: &Response) -> Result<(), GoObservationError> {
        let mut declarations = BTreeMap::new();
        for declaration in &answer.declarations {
            if self.span(&declaration.span)? != declaration.name
                || declaration.name == "_"
                || !display_name(&declaration.name)
                || !declaration.declared_signature.starts_with("func")
                || declaration.declared_signature.len() > 2048
                || declaration.declared_signature.chars().any(char::is_control)
                || declarations
                    .insert(&declaration.span, declaration)
                    .is_some()
            {
                return Err(GoObservationError::InvalidResponse);
            }
        }
        let mut calls = BTreeSet::new();
        for call in &answer.calls {
            if self.span(&call.span)?.is_empty()
                || call.name.as_deref().is_some_and(|name| !display_name(name))
                || !calls.insert(&call.span)
            {
                return Err(GoObservationError::InvalidResponse);
            }
            match (&call.resolution, &call.declaration) {
                (
                    Resolution::DirectFunction
                    | Resolution::DirectMethod
                    | Resolution::ExternalBodyUnobserved,
                    Some(span),
                ) => {
                    let Some(declaration) = declarations.get(span) else {
                        return Err(GoObservationError::InvalidResponse);
                    };
                    if call.name.as_deref() != Some(declaration.name.as_str())
                        || !matches!(
                            (
                                &call.resolution,
                                &declaration.kind,
                                &declaration.implementation
                            ),
                            (
                                Resolution::DirectFunction,
                                DeclarationKind::Function,
                                Implementation::SourceBody
                            ) | (
                                Resolution::DirectMethod,
                                DeclarationKind::Method,
                                Implementation::SourceBody
                            ) | (
                                Resolution::ExternalBodyUnobserved,
                                _,
                                Implementation::ExternalBodyUnobserved
                            )
                        )
                    {
                        return Err(GoObservationError::InvalidResponse);
                    }
                }
                (
                    Resolution::TypeConversion
                    | Resolution::Builtin
                    | Resolution::UnresolvedCallForm
                    | Resolution::UnresolvedInterfaceDispatch
                    | Resolution::UnresolvedFunctionValue
                    | Resolution::UnresolvedDeclaration,
                    None,
                ) => {}
                _ => return Err(GoObservationError::InvalidResponse),
            }
        }
        Ok(())
    }
}

fn display_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE
        && name.chars().all(|c| c == '_' || c.is_alphanumeric())
}

fn known_diagnostic(status: &Status, code: &str) -> bool {
    match status {
        Status::InvalidSource => matches!(
            code,
            "GO_PARSE_FAILURE" | "GO_TYPE_CHECK_REJECTED" | "INVALID_GO_IMPORT"
        ),
        Status::Unsupported => matches!(
            code,
            "BUILD_CONTEXT_REQUIRED"
                | "COMPILER_DIRECTIVE_CONTEXT_REQUIRED"
                | "DEPENDENCY_CONTEXT_REQUIRED"
                | "FOREIGN_CONTEXT_REQUIRED"
                | "GO_UNRESOLVED_DECLARATION"
        ),
        Status::ResourceLimit => matches!(code, "GO_AST_LIMIT" | "GO_OBSERVATION_LIMIT"),
        Status::Observed | Status::InvalidRequest => false,
    }
}
