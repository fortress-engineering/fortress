//! Admits a compile-only Python worker response against independently selected
//! immutable inputs. This boundary makes no claims about runtime semantics.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control_layout::CONTROL_ROOT;
use crate::observation::{SourceView, is_canonical_relative_path};
use crate::project::EvaluationKey;
use crate::wire::{JsonAdmissionLimits, admit_json, reject_duplicate_json_keys_bytes};

const RESPONSE_SCHEMA: &str = "fortress-research/python-lexical-response/1";
const MAX_SOURCE_BYTES: usize = 128 * 1024;
const MAX_SCOPES: usize = 256;
const MAX_BINDINGS: usize = 4000;
const MAX_FACTS: usize = 5000;
const MAX_NAME_BYTES: usize = 4096;
const RESPONSE_ADMISSION_LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 1024 * 1024,
    depth: 8,
    // Scope and binding objects, fact records and import aliases from the
    // worker's bounded AST can fit without letting small tokens exhaust memory.
    nodes: 180_000,
    // Valid non-ASCII names can triple in size when escaped by the worker.
    token_bytes: MAX_NAME_BYTES * 3 + 2,
};
const LIMITATIONS: [&str; 4] = [
    "IMPORT_TARGETS",
    "RUNTIME_CALL_TARGETS",
    "EFFECTS",
    "EXECUTION",
];

/// Compile-only Python observation selected by the caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonLexicalMode {
    /// Admit parser syntax only. Contextual validity remains unresolved.
    Syntax,
    /// Require compiler scope and module validity before admitting lexical facts.
    Lexical,
}

/// Supported worker interpreter family selected by the trusted host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PythonGrammar {
    /// `CPython` 3.12 in ordinary module mode.
    Cpython312,
    /// `CPython` 3.13 in ordinary module mode.
    Cpython313,
}

/// Independently selected runtime and embedded worker content identities.
///
/// The host owns executable and runtime verification. These references bind a
/// report; they do not authenticate a process or imply permission to run one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonLexicalProducer {
    grammar: PythonGrammar,
    runtime_ref: String,
    worker_ref: String,
}

impl PythonLexicalProducer {
    /// Records the selected grammar and exact runtime and worker digest bindings.
    ///
    /// # Errors
    /// Returns a binding error for noncanonical SHA-256 identities.
    pub fn new(
        grammar: PythonGrammar,
        runtime_ref: impl Into<String>,
        worker_ref: impl Into<String>,
    ) -> Result<Self, PythonLexicalError> {
        let runtime_ref = runtime_ref.into();
        let worker_ref = worker_ref.into();
        if !is_digest(&runtime_ref) || !is_digest(&worker_ref) {
            return Err(PythonLexicalError::InvalidBinding);
        }
        Ok(Self {
            grammar,
            runtime_ref,
            worker_ref,
        })
    }
}

/// Exact request binding owned by the caller's immutable evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonLexicalRequest {
    id: String,
    source_view_ref: String,
    evaluation_ref: String,
    source_path: String,
    source_ref: String,
    byte_count: usize,
    mode: PythonLexicalMode,
    producer: PythonLexicalProducer,
}

impl PythonLexicalRequest {
    /// Selects an exact source file from the existing caller-owned source view.
    ///
    /// The caller provides the independently selected evaluation key for this view.
    /// This method does not observe the filesystem or construct repository authority.
    ///
    /// # Errors
    /// Returns an error for an out-of-scope subject, byte budget, or evaluation key.
    pub fn for_source(
        view: &SourceView,
        evaluation: &EvaluationKey,
        source_path: &str,
        mode: PythonLexicalMode,
        producer: PythonLexicalProducer,
    ) -> Result<Self, PythonLexicalError> {
        let source = admitted_bytes(view, source_path)?;
        if [
            evaluation.source_manifest_digest(),
            evaluation.program_context_digest(),
            evaluation.authority_binding_digest(),
        ]
        .iter()
        .any(|identity| !is_digest(identity))
        {
            return Err(PythonLexicalError::InvalidBinding);
        }
        let source_view_ref = view.digest().to_owned();
        let evaluation_ref = evaluation.digest();
        let source_ref = digest(source);
        let bytes = serde_json_canonicalizer::to_vec(&(
            RESPONSE_SCHEMA,
            &source_view_ref,
            &evaluation_ref,
            source_path,
            &source_ref,
            source.len(),
            mode,
            &producer,
        ))
        .map_err(PythonLexicalError::Encoding)?;
        let id = format!("{:x}", Sha256::digest(bytes));
        Ok(Self {
            id,
            source_view_ref,
            evaluation_ref,
            source_path: source_path.to_owned(),
            source_ref,
            byte_count: source.len(),
            mode,
            producer,
        })
    }

    /// Returns the opaque worker request identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the selected exact source-byte digest.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    /// Returns the selected runtime identity.
    #[must_use]
    pub fn runtime_ref(&self) -> &str {
        &self.producer.runtime_ref
    }

    /// Returns the selected worker identity.
    #[must_use]
    pub fn worker_ref(&self) -> &str {
        &self.producer.worker_ref
    }
}

/// Preserves observation availability independently of semantic proof.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PythonLexicalOutcome {
    /// The selected parser admitted syntax; other phases were skipped.
    SyntaxOnly,
    /// The supported lexical facts were observed.
    Lexical,
    /// Some lexical facts were observed with explicit scope limitations.
    Partial,
    /// The admitted compiler or UTF-8 decoder rejected the input.
    InvalidSource,
    /// The input falls outside the supported encoding or source scope.
    Unsupported,
    /// The worker or an operational premise was unavailable.
    Unavailable,
}

/// Verified shape and exact correlation of a compile-only worker report.
///
/// This is an observational sidecar, separate from canonical source-profile,
/// PSM, execution evidence and conformance decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonLexicalObservation {
    request: PythonLexicalRequest,
    report: Report,
}

impl PythonLexicalObservation {
    /// Admits a bounded worker report for the currently selected immutable inputs.
    ///
    /// Both sides of the exchange must be trusted or derived outside project input
    /// for the admitted facts to describe an actual compiler observation. Successful
    /// admission here establishes integrity and scope, without proving that a
    /// particular process executed or that a reported import resolves at runtime.
    ///
    /// # Errors
    /// Rejects stale inputs, mismatched provenance, malformed responses, false
    /// phase claims, and observations outside the bounded lexical exchange.
    pub fn admit(
        request: &PythonLexicalRequest,
        current_view: &SourceView,
        current_evaluation: &EvaluationKey,
        response: &[u8],
    ) -> Result<Self, PythonLexicalError> {
        if current_view.digest() != request.source_view_ref
            || current_evaluation.digest() != request.evaluation_ref
        {
            return Err(PythonLexicalError::StaleInput);
        }
        let source = admitted_bytes(current_view, &request.source_path)?;
        admit_json(response, RESPONSE_ADMISSION_LIMITS)
            .map_err(|_| PythonLexicalError::ResourceLimit)?;
        reject_duplicate_json_keys_bytes(response).map_err(PythonLexicalError::Encoding)?;
        let report: Report =
            serde_json::from_slice(response).map_err(PythonLexicalError::Encoding)?;
        if report.schema != RESPONSE_SCHEMA {
            return Err(PythonLexicalError::UnsupportedProtocol);
        }
        if report.id != request.id
            || report.source_ref != request.source_ref
            || report.byte_count != request.byte_count
            || report.runtime_ref != request.producer.runtime_ref
            || report.worker_ref != request.producer.worker_ref
            || report.mode != request.mode
        {
            return Err(PythonLexicalError::InvalidBinding);
        }
        report.validate(source)?;
        Ok(Self {
            request: request.clone(),
            report,
        })
    }

    /// Returns the admitted compile-only outcome.
    #[must_use]
    pub const fn outcome(&self) -> PythonLexicalOutcome {
        self.report.outcome
    }

    /// Returns deterministic sidecar bytes with the exact originating request.
    ///
    /// # Errors
    /// Reports serialization failures without substituting a projection.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json_canonicalizer::to_vec(self)
    }
}

/// Failure to establish the requested lexical observation.
#[derive(Debug)]
pub enum PythonLexicalError {
    /// The selected path falls outside the bounded source scope.
    UnsupportedSource,
    /// The source entry is absent from the immutable view.
    MissingSource,
    /// The source or response exceeds an admission bound.
    ResourceLimit,
    /// The current source view or evaluation differs from the original request.
    StaleInput,
    /// One or more exact correlation or producer bindings differ.
    InvalidBinding,
    /// The response names an unsupported protocol revision.
    UnsupportedProtocol,
    /// The worker report is malformed or asserts an inadmissible fact.
    InvalidReport,
    /// JSON fails strict decoding or deterministic serialization.
    Encoding(serde_json::Error),
}

impl Display for PythonLexicalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSource => formatter.write_str("unsupported Python source selection"),
            Self::MissingSource => formatter.write_str("Python source is absent from the view"),
            Self::ResourceLimit => formatter.write_str("Python lexical resource limit exceeded"),
            Self::StaleInput => formatter.write_str("Python lexical evaluation input is stale"),
            Self::InvalidBinding => formatter.write_str("invalid Python lexical exchange binding"),
            Self::UnsupportedProtocol => formatter.write_str("unsupported Python lexical protocol"),
            Self::InvalidReport => formatter.write_str("invalid Python lexical worker observation"),
            Self::Encoding(_) => formatter.write_str("invalid Python lexical JSON"),
        }
    }
}

impl Error for PythonLexicalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

fn admitted_bytes<'a>(view: &'a SourceView, path: &str) -> Result<&'a [u8], PythonLexicalError> {
    let root = path.split('/').next().unwrap_or_default();
    if !is_canonical_relative_path(path)
        || root.eq_ignore_ascii_case(CONTROL_ROOT)
        || root.eq_ignore_ascii_case(".git")
        || Path::new(path).extension().and_then(|part| part.to_str()) != Some("py")
    {
        return Err(PythonLexicalError::UnsupportedSource);
    }
    let bytes = view.bytes(path).ok_or(PythonLexicalError::MissingSource)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(PythonLexicalError::ResourceLimit);
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    id: String,
    source_ref: String,
    byte_count: usize,
    runtime_ref: String,
    worker_ref: String,
    mode: PythonLexicalMode,
    outcome: PythonLexicalOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    stages: Stages,
    #[serde(deserialize_with = "present_option")]
    observations: Option<Facts>,
    target_execution: NotRun,
    runtime_limitations: [String; 4],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum NotRun {
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
struct Stages {
    syntax: Stage,
    lexical_scope: Stage,
    module_validity: Stage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    status: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Phase {
    Complete,
    Invalid,
    Incomplete,
    NotRun,
}

impl Report {
    fn validate(&self, source: &[u8]) -> Result<(), PythonLexicalError> {
        use Phase::{Complete, Incomplete, Invalid, NotRun};
        use PythonLexicalOutcome::{
            InvalidSource, Lexical, Partial, SyntaxOnly, Unavailable, Unsupported,
        };

        let stages = [
            &self.stages.syntax,
            &self.stages.lexical_scope,
            &self.stages.module_validity,
        ];
        let lines = source.split(|byte| *byte == b'\n').count();
        if self
            .runtime_limitations
            .iter()
            .map(String::as_str)
            .ne(LIMITATIONS)
            || stages.iter().any(|phase| {
                if phase.status == Invalid {
                    !matches!(
                        phase.reason.as_deref(),
                        Some("INVALID_UTF8" | "SyntaxError" | "IndentationError" | "TabError")
                    ) || phase.line.is_some_and(|line| line == 0 || line > lines)
                } else {
                    phase.reason.is_some() || phase.line.is_some()
                }
            })
        {
            return Err(PythonLexicalError::InvalidReport);
        }
        let phase = stages.map(|stage| stage.status);
        if self.mode == PythonLexicalMode::Syntax && phase[1..] != [NotRun, NotRun] {
            return Err(PythonLexicalError::InvalidReport);
        }
        let reason = self.reason.as_deref();
        match self.outcome {
            SyntaxOnly
                if self.mode == PythonLexicalMode::Syntax
                    && phase == [Complete, NotRun, NotRun]
                    && reason == Some("LEXICAL_AND_MODULE_VALIDITY_NOT_ADMITTED")
                    && self.observations.is_none() =>
            {
                validate_source_context(source)
            }
            Lexical | Partial if phase == [Complete; 3] && reason.is_none() => {
                let facts = self
                    .observations
                    .as_ref()
                    .ok_or(PythonLexicalError::InvalidReport)?;
                if (self.outcome == Partial) == facts.limitations.is_empty() {
                    return Err(PythonLexicalError::InvalidReport);
                }
                validate_source_context(source)?;
                facts.validate(source)
            }
            InvalidSource
                if matches!(
                    phase,
                    [Invalid, NotRun, NotRun]
                        | [Complete, Invalid, NotRun]
                        | [Complete, Complete, Invalid]
                ) && reason.is_none()
                    && self.observations.is_none() =>
            {
                let malformed_utf8 = std::str::from_utf8(source).is_err();
                if (self.stages.syntax.reason.as_deref() == Some("INVALID_UTF8")) != malformed_utf8
                    || stages[1..]
                        .iter()
                        .any(|stage| stage.reason.as_deref() == Some("INVALID_UTF8"))
                    || (malformed_utf8 && self.stages.syntax.line.is_some())
                {
                    return Err(PythonLexicalError::InvalidReport);
                }
                Ok(())
            }
            Unsupported
                if phase == [NotRun; 3]
                    && matches!(
                        reason,
                        Some(
                            "UNSUPPORTED_UTF8_BOM"
                                | "UNSUPPORTED_LINE_ENDING"
                                | "UNSUPPORTED_ENCODING_COOKIE"
                        )
                    )
                    && self.observations.is_none() =>
            {
                Ok(())
            }
            Unavailable
                if matches!(
                    phase,
                    [NotRun | Incomplete, NotRun, NotRun]
                        | [Complete, NotRun | Incomplete, NotRun]
                        | [Complete, Complete, NotRun | Incomplete | Complete]
                ) && self.observations.is_none()
                    && reason.is_some_and(|reason| valid_unavailable_reason(reason, phase)) =>
            {
                Ok(())
            }
            _ => Err(PythonLexicalError::InvalidReport),
        }
    }
}

fn valid_unavailable_reason(reason: &str, phases: [Phase; 3]) -> bool {
    match reason {
        "WORKER_BINDING_MISMATCH" | "RUNTIME_BINDING_MISMATCH" | "RUNTIME_BUILD_UNAVAILABLE" => {
            phases == [Phase::NotRun; 3]
        }
        "OUTPUT_LIMIT" => phases == [Phase::Complete; 3],
        "TOKEN_OR_NESTING_LIMIT"
        | "AST_NODE_OR_DEPTH_LIMIT"
        | "SCOPE_LIMIT"
        | "BINDING_LIMIT"
        | "FACT_LIMIT"
        | "INVALID_COMPILER_COORDINATE"
        | "RecursionError"
        | "MemoryError"
        | "OSError"
        | "FileNotFoundError"
        | "PermissionError"
        | "ValueError" => true,
        _ => false,
    }
}

fn validate_source_context(source: &[u8]) -> Result<(), PythonLexicalError> {
    if std::str::from_utf8(source).is_err()
        || source.starts_with(b"\xef\xbb\xbf")
        || source
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte == b'\r' && source.get(index + 1) != Some(&b'\n'))
    {
        return Err(PythonLexicalError::InvalidReport);
    }
    Ok(())
}

fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    scopes: Vec<Scope>,
    imports: Vec<Import>,
    constructs: Vec<Construct>,
    limitations: Vec<Limitation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    id: String,
    #[serde(deserialize_with = "present_option")]
    parent: Option<String>,
    kind: ScopeKind,
    name: String,
    #[serde(deserialize_with = "present_option")]
    span: Option<Span>,
    bindings: Vec<Binding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ScopeKind {
    Module,
    FunctionDef,
    AsyncFunctionDef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    name: String,
    flags: Vec<BindingFlag>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum BindingFlag {
    Assigned,
    DeclaredGlobal,
    Free,
    Global,
    Imported,
    Local,
    Namespace,
    Nonlocal,
    Parameter,
    Referenced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Import {
    scope: String,
    form: ImportForm,
    #[serde(deserialize_with = "present_option")]
    level: Option<usize>,
    #[serde(deserialize_with = "present_option")]
    module: Option<String>,
    names: Vec<(String, Option<String>)>,
    target: Unresolved,
    span: Span,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportForm {
    Import,
    From,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Unresolved {
    Unresolved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Construct {
    scope: String,
    kind: ConstructKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    spelling: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<Unresolved>,
    span: Span,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ConstructKind {
    Call,
    NameStore,
    AsyncFor,
    AsyncWith,
    Await,
    ExceptHandler,
    Try,
    TryStar,
    With,
    Raise,
    Return,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Limitation {
    scope: String,
    code: LimitationCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<OpaqueScope>,
    span: Span,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LimitationCode {
    UnmodeledFunctionScopeOrHeader,
    UnmodeledScopeForm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum OpaqueScope {
    ClassDef,
    Lambda,
    ListComp,
    SetComp,
    DictComp,
    GeneratorExp,
    TypeAlias,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Span(usize, usize, usize, usize);

impl Span {
    fn validate(self, lines: &[&str], scope: Option<Self>) -> bool {
        let Self(first, start, last, end) = self;
        (first, start) < (last, end)
            && valid_column(lines, first, start)
            && valid_column(lines, last, end)
            && scope.is_none_or(|Self(outer_first, outer_start, outer_last, outer_end)| {
                (outer_first, outer_start) <= (first, start)
                    && (last, end) <= (outer_last, outer_end)
            })
    }
}

fn valid_column(lines: &[&str], line: usize, offset: usize) -> bool {
    line.checked_sub(1)
        .and_then(|index| lines.get(index))
        .is_some_and(|text| {
            text.strip_suffix('\r')
                .unwrap_or(text)
                .is_char_boundary(offset)
        })
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_BYTES && !name.chars().any(char::is_control)
}

impl Facts {
    fn validate(&self, source: &[u8]) -> Result<(), PythonLexicalError> {
        let text = std::str::from_utf8(source).map_err(|_| PythonLexicalError::InvalidReport)?;
        let lines = text.split('\n').collect::<Vec<_>>();
        if self.scopes.is_empty()
            || self.scopes.len() > MAX_SCOPES
            || self
                .scopes
                .iter()
                .map(|scope| scope.bindings.len())
                .sum::<usize>()
                > MAX_BINDINGS
            || self.imports.len() + self.constructs.len() + self.limitations.len() > MAX_FACTS
        {
            return Err(PythonLexicalError::InvalidReport);
        }
        let scopes = self.validate_scopes(&lines)?;
        let span_valid = |scope: &str, span: Span| {
            scopes
                .get(scope)
                .is_some_and(|outer| span.validate(&lines, *outer))
        };
        if self
            .imports
            .iter()
            .any(|row| !row.validate() || !span_valid(&row.scope, row.span))
            || self
                .constructs
                .iter()
                .any(|row| !row.validate() || !span_valid(&row.scope, row.span))
            || self.limitations.iter().any(|row| {
                (row.code == LimitationCode::UnmodeledScopeForm) != row.kind.is_some()
                    || !span_valid(&row.scope, row.span)
            })
        {
            return Err(PythonLexicalError::InvalidReport);
        }
        Ok(())
    }

    fn validate_scopes<'a>(
        &'a self,
        lines: &[&str],
    ) -> Result<BTreeMap<&'a str, Option<Span>>, PythonLexicalError> {
        let mut scopes = BTreeMap::<&str, Option<Span>>::new();
        for (index, row) in self.scopes.iter().enumerate() {
            if row.id != format!("s{index}")
                || !valid_name(&row.name)
                || row
                    .bindings
                    .windows(2)
                    .any(|pair| pair[0].name >= pair[1].name)
                || row.bindings.iter().any(|binding| {
                    !valid_name(&binding.name)
                        || binding.flags.is_empty()
                        || binding.flags.windows(2).any(|pair| pair[0] >= pair[1])
                })
            {
                return Err(PythonLexicalError::InvalidReport);
            }
            match (index, row.kind, row.parent.as_deref(), row.span) {
                (0, ScopeKind::Module, None, None) if row.name == "top" => {}
                (
                    1..,
                    ScopeKind::FunctionDef | ScopeKind::AsyncFunctionDef,
                    Some(parent),
                    Some(span),
                ) if scopes
                    .get(parent)
                    .is_some_and(|outer| span.validate(lines, *outer)) => {}
                _ => return Err(PythonLexicalError::InvalidReport),
            }
            scopes.insert(&row.id, row.span);
        }
        Ok(scopes)
    }
}

impl Import {
    fn validate(&self) -> bool {
        let valid_form = match (self.form, self.level, &self.module) {
            (ImportForm::From, Some(_), Some(module)) => valid_name(module),
            (ImportForm::Import, None, None) | (ImportForm::From, Some(1..), None) => true,
            _ => false,
        };
        valid_form
            && !self.names.is_empty()
            && self.names.iter().all(|(name, alias)| {
                valid_name(name)
                    && alias.as_deref().is_none_or(valid_name)
                    && (name != "*" || (self.form == ImportForm::From && alias.is_none()))
            })
    }
}

impl Construct {
    fn validate(&self) -> bool {
        match (self.kind, self.spelling.as_deref(), self.target) {
            (ConstructKind::Call, Some(name), Some(Unresolved::Unresolved))
            | (ConstructKind::NameStore, Some(name), None) => valid_name(name),
            (ConstructKind::Call | ConstructKind::NameStore, _, _) => false,
            (_, None, None) => true,
            _ => false,
        }
    }
}
