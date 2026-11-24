//! Shared bounded admission for explicitly selected native scalar observations.
//!
//! This boundary constructs the Program Semantics owner's existing body nodes.
//! It preserves selected producer evidence but cannot authorize assessment or
//! alter the historical Rust model.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ProgramBody, ProgramExpression, ProgramPattern, ProgramProvenance, ProgramSourceLocation,
    ProgramStatement, canonical_fact_id,
};
use crate::observation::is_canonical_relative_path;
use crate::project::EvaluationKey;
use crate::wire::{JsonAdmissionLimits, admit_json, parse_strict_json_bytes};

const MAX_SOURCE_BYTES: usize = 128 * 1024;
const MAX_BINDINGS: usize = 128;
const LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 128 * 1024,
    depth: 32,
    nodes: 12_000,
    token_bytes: 1_024,
};

/// Native semantic scope selected independently of the returned reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeBodyLanguage {
    /// Native Go fixed-width boolean and signed integer subset.
    Go,
    /// Python exact booleans and bounded literal witnesses.
    Python,
}

impl NativeBodyLanguage {
    const fn extension(self) -> &'static str {
        match self {
            Self::Go => ".go",
            Self::Python => ".py",
        }
    }

    const fn analyzer(self) -> &'static str {
        match self {
            Self::Go => "fortress.go.native-scalar",
            Self::Python => "fortress.python.native-scalar",
        }
    }

    const fn integer(self) -> NativeScalar {
        match self {
            Self::Go => NativeScalar::SignedI64,
            Self::Python => NativeScalar::IntegerLiteral,
        }
    }
}

/// A scalar type supported by this restricted frontend boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeScalar {
    /// An exact boolean, without a general truthiness conversion.
    Bool,
    /// An exact Go signed 64-bit integer.
    #[serde(rename = "SIGNED_I64")]
    SignedI64,
    /// A bounded Python integer literal or copy, not a Python integer type.
    IntegerLiteral,
}

/// Exact metadata supplied by the existing owner of a native exchange.
///
/// The owner first verifies the native process and its response framing, source,
/// context, authority and producer identities. This data type is not an
/// authorization or evidence admission mechanism.
pub struct NativeBodyInput<'a> {
    /// Independently selected language.
    pub language: NativeBodyLanguage,
    /// Current exact evaluation identity.
    pub evaluation: &'a EvaluationKey,
    /// Exact native exchange binding, including producer and selected assumptions.
    pub exchange_ref: &'a str,
    /// Exact producer deployment identity.
    pub producer_ref: &'a str,
    /// Canonical path selected by the owner.
    pub source_path: &'a str,
    /// Exact previously bound digest of selected source bytes.
    pub source_ref: &'a str,
    /// The corresponding immutable ordinary source bytes.
    pub source: &'a [u8],
    /// Independently selected Python exact-boolean parameter names in source order.
    /// A Go exchange must supply no Python input assumptions.
    pub python_bool_parameters: &'a [&'a str],
}

/// Result of admission at the native scalar boundary.
#[derive(Debug)]
pub enum NativeBodyOutcome {
    /// Existing PSM nodes with exact occurrence and exchange provenance.
    Lowered(Box<NativeScalarBody>),
    /// An explicit limitation reported by the pinned frontend.
    Unavailable(NativeBodyLimitation),
}

/// A reported barrier with an optional verified physical location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBodyLimitation {
    code: String,
    location: Option<ProgramSourceLocation>,
}

impl NativeBodyLimitation {
    /// Returns the frontend's bounded reason code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the physical location when an exact span was supplied.
    #[must_use]
    pub const fn location(&self) -> Option<&ProgramSourceLocation> {
        self.location.as_ref()
    }
}

/// Exact transient scalar body and interface information.
///
/// The identifier names an exact occurrence, not a cross-revision authored
/// symbol. No deployed PSM version automatically consumes this result.
#[derive(Debug)]
pub struct NativeScalarBody {
    language: NativeBodyLanguage,
    binding: String,
    body: ProgramBody,
    parameters: Vec<(String, NativeScalar)>,
    locals: Vec<(String, NativeScalar)>,
    result: NativeScalar,
    calls: Vec<NativeBoundCall>,
}

/// An occurrence and an exact source declaration supplied by the separately
/// admitted native producer. Body availability and evaluation are separate.
#[derive(Debug, Serialize)]
pub(crate) struct NativeBoundCall {
    pub(crate) reference: String,
    pub(crate) span: Span,
    pub(crate) target: Symbol,
    pub(crate) argument_count: usize,
}

impl NativeScalarBody {
    pub(crate) fn bound_calls(&self) -> &[NativeBoundCall] {
        &self.calls
    }

    pub(crate) const fn integer_scalar(&self) -> NativeScalar {
        self.language.integer()
    }

    /// Returns the digest-bound occurrence identity.
    #[must_use]
    pub fn binding(&self) -> &str {
        &self.binding
    }

    /// Returns the Program Semantics owner's normalized body.
    #[must_use]
    pub const fn body(&self) -> &ProgramBody {
        &self.body
    }

    /// Returns the exact ordered parameter identities and admitted scalar scopes.
    #[must_use]
    pub fn parameters(&self) -> &[(String, NativeScalar)] {
        &self.parameters
    }

    /// Returns the reported local binding identities and admitted scalar scopes.
    #[must_use]
    pub fn locals(&self) -> &[(String, NativeScalar)] {
        &self.locals
    }

    /// Returns the declared scope of the returned value.
    #[must_use]
    pub const fn result(&self) -> NativeScalar {
        self.result
    }
}

/// A failed admission, with no lowered body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBodyError {
    /// The independently selected context or source binding is incomplete.
    InvalidBinding,
    /// A resource budget was exceeded.
    ResourceLimit,
    /// The response disagrees with the supported wire, source, or scalar scope.
    InvalidResponse,
}

impl std::fmt::Display for NativeBodyError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::InvalidBinding => "native body input binding is incomplete or stale",
            Self::ResourceLimit => "native body input exceeds its admission budget",
            Self::InvalidResponse => "native body response is invalid for the selected scope",
        })
    }
}

impl std::error::Error for NativeBodyError {}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Span {
    pub(crate) path: String,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) start_line: usize,
    pub(crate) start_byte_column: usize,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) span: Span,
    pub(crate) declaration_span: Span,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    name: String,
    scalar: NativeScalar,
    span: Span,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    code: String,
    span: Option<Span>,
}

#[derive(Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
enum Reply {
    Lowerable {
        symbol: Box<Symbol>,
        parameters: Vec<Binding>,
        result_scalar: NativeScalar,
        locals: Vec<Binding>,
        body: Vec<Statement>,
    },
    Unavailable {
        symbol: Option<Box<Symbol>>,
        parameters: Vec<Binding>,
        locals: Vec<Binding>,
        body: Vec<Statement>,
        diagnostic: Diagnostic,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Pattern {
    Binding { name: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Statement {
    Let {
        span: Span,
        pattern: Pattern,
        value: Expression,
    },
    Assign {
        span: Span,
        target: String,
        value: Expression,
    },
    If {
        span: Span,
        condition: Expression,
        then_branch: Vec<Self>,
        else_branch: Vec<Self>,
    },
    Return {
        span: Span,
        value: Expression,
    },
}

impl Statement {
    const fn span(&self) -> &Span {
        match self {
            Self::Let { span, .. }
            | Self::Assign { span, .. }
            | Self::If { span, .. }
            | Self::Return { span, .. } => span,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Expression {
    Binding {
        name: String,
    },
    Boolean {
        value: bool,
    },
    Integer {
        value: String,
    },
    Unary {
        operator: String,
        value: Box<Self>,
    },
    Binary {
        operator: String,
        left: Box<Self>,
        right: Box<Self>,
    },
    Call {
        call: Box<Call>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    span: Span,
    target: Symbol,
    arguments: Vec<Expression>,
}

struct Source<'a> {
    path: &'a str,
    text: &'a str,
    line_starts: Vec<usize>,
}

impl Source<'_> {
    fn range(&self, span: &Span) -> Result<Range<usize>, NativeBodyError> {
        let range = span.start_byte..span.end_byte;
        if span.path != self.path || range.is_empty() || self.text.get(range.clone()).is_none() {
            return Err(NativeBodyError::InvalidResponse);
        }
        let line = self
            .line_starts
            .partition_point(|&start| start <= range.start);
        if line != span.start_line
            || range.start - self.line_starts[line - 1] + 1 != span.start_byte_column
        {
            return Err(NativeBodyError::InvalidResponse);
        }
        Ok(range)
    }

    fn identifier(&self, span: &Span, name: &str) -> Result<Range<usize>, NativeBodyError> {
        let range = self.range(span)?;
        let mut characters = name.bytes();
        let first = characters.next();
        if !(first.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && characters.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && self.text[range.clone()] == *name)
        {
            return Err(NativeBodyError::InvalidResponse);
        }
        Ok(range)
    }

    fn declaration(&self, symbol: &Symbol) -> Result<Range<usize>, NativeBodyError> {
        let declaration = self.range(&symbol.declaration_span)?;
        let name = self.identifier(&symbol.span, &symbol.name)?;
        within(&name, &declaration)?;
        Ok(declaration)
    }
}

struct Lowering<'a> {
    language: NativeBodyLanguage,
    source: &'a Source<'a>,
    symbol: &'a str,
    result: NativeScalar,
    bindings: BTreeMap<String, NativeScalar>,
    parameters: BTreeSet<String>,
    allow_bound_calls: bool,
    calls: Vec<NativeBoundCall>,
}

impl Lowering<'_> {
    fn provenance(&self, span: &Span) -> Result<ProgramProvenance, NativeBodyError> {
        Ok(ProgramProvenance {
            path: self.source.path.to_owned(),
            location: location(span)?,
            symbol_context: Some(self.symbol.to_owned()),
            analyzer: self.language.analyzer().into(),
            analyzer_semantic_version: "1.0.0".into(),
        })
    }

    fn expression(
        &mut self,
        expression: Expression,
        enclosure: &Range<usize>,
    ) -> Result<(ProgramExpression, NativeScalar), NativeBodyError> {
        let (value, scalar) = match expression {
            Expression::Binding { name } => {
                let scalar = self.binding(&name)?;
                (ProgramExpression::Binding { name }, scalar)
            }
            Expression::Boolean { value } => {
                (ProgramExpression::Boolean { value }, NativeScalar::Bool)
            }
            Expression::Integer { value } => {
                let integer = value
                    .parse::<i64>()
                    .map_err(|_| NativeBodyError::InvalidResponse)?;
                if integer.to_string() != value
                    || self.language == NativeBodyLanguage::Python
                        && i32::try_from(integer).is_err()
                {
                    return Err(NativeBodyError::InvalidResponse);
                }
                (
                    ProgramExpression::Integer { value },
                    self.language.integer(),
                )
            }
            Expression::Unary { operator, value } if operator == "!" => (
                ProgramExpression::Unary {
                    operator,
                    value: Box::new(self.typed(*value, NativeScalar::Bool, enclosure)?),
                },
                NativeScalar::Bool,
            ),
            Expression::Binary {
                operator,
                left,
                right,
            } => {
                let (left, scalar) = self.expression(*left, enclosure)?;
                if !(matches!(operator.as_str(), "==" | "!=")
                    || scalar == self.language.integer()
                        && matches!(operator.as_str(), "<" | "<=" | ">" | ">="))
                {
                    return Err(NativeBodyError::InvalidResponse);
                }
                let right = self.typed(*right, scalar, enclosure)?;
                (
                    ProgramExpression::Binary {
                        operator,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    NativeScalar::Bool,
                )
            }
            Expression::Call { call } if self.allow_bound_calls => {
                (self.bound_call(*call, enclosure)?, NativeScalar::Bool)
            }
            Expression::Unary { .. } | Expression::Call { .. } => {
                return Err(NativeBodyError::InvalidResponse);
            }
        };
        Ok((value, scalar))
    }

    fn bound_call(
        &mut self,
        call: Call,
        enclosure: &Range<usize>,
    ) -> Result<ProgramExpression, NativeBodyError> {
        let span = self.source.range(&call.span)?;
        within(&span, enclosure)?;
        let site = self.source.text[span.clone()]
            .strip_prefix(&call.target.name)
            .ok_or(NativeBodyError::InvalidResponse)?;
        if !call_delimiters(self.language, site) || call.arguments.len() > 4 {
            return Err(NativeBodyError::InvalidResponse);
        }
        let arguments = call
            .arguments
            .into_iter()
            .map(|argument| self.typed(argument, NativeScalar::Bool, &span))
            .collect::<Result<Vec<_>, _>>()?;
        let reference = canonical_fact_id(
            "native_call_site:v1",
            &(self.symbol, &call.span, &call.target),
        );
        self.calls.push(NativeBoundCall {
            reference: reference.clone(),
            span: call.span,
            target: call.target,
            argument_count: arguments.len(),
        });
        Ok(ProgramExpression::Call {
            reference,
            arguments,
        })
    }

    fn typed(
        &mut self,
        expression: Expression,
        expected: NativeScalar,
        enclosure: &Range<usize>,
    ) -> Result<ProgramExpression, NativeBodyError> {
        let (value, scalar) = self.expression(expression, enclosure)?;
        if scalar != expected {
            return Err(NativeBodyError::InvalidResponse);
        }
        Ok(value)
    }

    fn binding(&self, name: &str) -> Result<NativeScalar, NativeBodyError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or(NativeBodyError::InvalidResponse)
    }

    fn statements(
        &mut self,
        statements: Vec<Statement>,
        enclosure: &Range<usize>,
    ) -> Result<(Vec<ProgramStatement>, usize), NativeBodyError> {
        let mut end = enclosure.start;
        let mut lowered = Vec::with_capacity(statements.len());
        for statement in statements {
            let span = statement.span();
            let range = self.source.range(span)?;
            within(&range, &(end..enclosure.end))?;
            end = range.end;
            let span_provenance = self.provenance(span)?;
            let normalized = match statement {
                Statement::Let {
                    pattern: Pattern::Binding { name },
                    value,
                    ..
                } => {
                    if self.parameters.contains(&name) {
                        return Err(NativeBodyError::InvalidResponse);
                    }
                    let value = self.typed(value, self.binding(&name)?, &range)?;
                    ProgramStatement::Let {
                        pattern: ProgramPattern::Binding { name },
                        value: Some(value),
                        provenance: span_provenance,
                    }
                }
                Statement::Assign { target, value, .. } => {
                    if self.language == NativeBodyLanguage::Python
                        && self.parameters.contains(&target)
                    {
                        return Err(NativeBodyError::InvalidResponse);
                    }
                    let value = self.typed(value, self.binding(&target)?, &range)?;
                    ProgramStatement::Assign {
                        target,
                        value,
                        provenance: span_provenance,
                    }
                }
                Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    let (then_branch, then_end) = self.statements(then_branch, &range)?;
                    let (else_branch, _) = self.statements(else_branch, &(then_end..range.end))?;
                    ProgramStatement::If {
                        condition: self.typed(condition, NativeScalar::Bool, &range)?,
                        then_branch,
                        else_branch,
                        provenance: span_provenance,
                    }
                }
                Statement::Return { value, .. } => ProgramStatement::Return {
                    value: Some(self.typed(value, self.result, &range)?),
                    provenance: span_provenance,
                },
            };
            lowered.push(normalized);
        }
        Ok((lowered, end))
    }
}

fn within(inner: &Range<usize>, outer: &Range<usize>) -> Result<(), NativeBodyError> {
    if inner.start < outer.start || inner.end > outer.end {
        return Err(NativeBodyError::InvalidResponse);
    }
    Ok(())
}

fn location(span: &Span) -> Result<ProgramSourceLocation, NativeBodyError> {
    let line = u32::try_from(span.start_line).map_err(|_| NativeBodyError::InvalidResponse)?;
    let column =
        u32::try_from(span.start_byte_column).map_err(|_| NativeBodyError::InvalidResponse)?;
    Ok(ProgramSourceLocation::new(line, column))
}

pub(super) fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

impl NativeBodyInput<'_> {
    /// Lowers the selected trusted frontend's bounded body payload.
    ///
    /// The function checks exact structure, source spans and scalar types. The
    /// pinned frontend owns native syntax, binding, and control-flow premises.
    /// No function contract, operation effect, execution or conformance follows
    /// from successful admission.
    ///
    /// # Errors
    /// Rejects invalid input bindings, oversized input, malformed replies and
    /// records that disagree with the bounded source or scalar scope.
    pub fn admit(&self, response: &[u8]) -> Result<NativeBodyOutcome, NativeBodyError> {
        self.admit_body(response, false)
    }

    pub(crate) fn admit_bound_calls(
        &self,
        response: &[u8],
    ) -> Result<NativeBodyOutcome, NativeBodyError> {
        self.admit_body(response, true)
    }

    fn admit_body(
        &self,
        response: &[u8],
        bound_calls: bool,
    ) -> Result<NativeBodyOutcome, NativeBodyError> {
        if self.source.len() > MAX_SOURCE_BYTES || self.python_bool_parameters.len() > MAX_BINDINGS
        {
            return Err(NativeBodyError::ResourceLimit);
        }
        if !is_canonical_relative_path(self.source_path)
            || !self.source_path.ends_with(self.language.extension())
            || self.language == NativeBodyLanguage::Go && !self.python_bool_parameters.is_empty()
            || [
                self.evaluation.source_manifest_digest(),
                self.evaluation.program_context_digest(),
                self.evaluation.authority_binding_digest(),
                self.exchange_ref,
                self.producer_ref,
                self.source_ref,
            ]
            .into_iter()
            .any(|value| !digest(value))
            || self.source_ref != format!("sha256:{:x}", Sha256::digest(self.source))
        {
            return Err(NativeBodyError::InvalidBinding);
        }
        let source = Source {
            path: self.source_path,
            text: std::str::from_utf8(self.source).map_err(|_| NativeBodyError::InvalidBinding)?,
            line_starts: std::iter::once(0)
                .chain(
                    self.source
                        .iter()
                        .enumerate()
                        .filter_map(|(index, &byte)| (byte == b'\n').then_some(index + 1)),
                )
                .collect(),
        };
        admit_json(response, LIMITS).map_err(|_| NativeBodyError::ResourceLimit)?;
        let reply =
            parse_strict_json_bytes(response).map_err(|_| NativeBodyError::InvalidResponse)?;
        match reply {
            Reply::Lowerable {
                symbol,
                parameters,
                result_scalar,
                locals,
                body,
            } => self.lower(
                &source,
                &symbol,
                &parameters,
                result_scalar,
                &locals,
                body,
                bound_calls,
            ),
            Reply::Unavailable {
                symbol,
                parameters,
                locals,
                body,
                diagnostic,
            } => {
                if !parameters.is_empty() || !locals.is_empty() || !body.is_empty() {
                    return Err(NativeBodyError::InvalidResponse);
                }
                if let Some(symbol) = symbol {
                    source.declaration(&symbol)?;
                }
                let Diagnostic { code, span } = diagnostic;
                if code.is_empty()
                    || code.len() > 96
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(NativeBodyError::InvalidResponse);
                }
                let location = span
                    .map(|span| {
                        source.range(&span)?;
                        location(&span)
                    })
                    .transpose()?;
                Ok(NativeBodyOutcome::Unavailable(NativeBodyLimitation {
                    code,
                    location,
                }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lower(
        &self,
        source: &Source<'_>,
        symbol: &Symbol,
        parameters: &[Binding],
        result: NativeScalar,
        locals: &[Binding],
        body: Vec<Statement>,
        allow_bound_calls: bool,
    ) -> Result<NativeBodyOutcome, NativeBodyError> {
        if parameters.len().saturating_add(locals.len()) > MAX_BINDINGS {
            return Err(NativeBodyError::ResourceLimit);
        }
        if body.is_empty() || !self.accepts(result) {
            return Err(NativeBodyError::InvalidResponse);
        }
        if self.language == NativeBodyLanguage::Python
            && (parameters
                .iter()
                .any(|parameter| parameter.scalar != NativeScalar::Bool)
                || parameters
                    .iter()
                    .map(|parameter| parameter.name.as_str())
                    .ne(self.python_bool_parameters.iter().copied()))
        {
            return Err(NativeBodyError::InvalidResponse);
        }
        let declaration = source.declaration(symbol)?;
        if self.language == NativeBodyLanguage::Go && symbol.name == "_" {
            return Err(NativeBodyError::InvalidResponse);
        }
        let mut bindings = BTreeMap::new();
        for binding in parameters.iter().chain(locals) {
            let name = source.identifier(&binding.span, &binding.name)?;
            within(&name, &declaration)?;
            if !self.accepts(binding.scalar)
                || self.language == NativeBodyLanguage::Go && binding.name == "_"
                || bindings
                    .insert(binding.name.clone(), binding.scalar)
                    .is_some()
            {
                return Err(NativeBodyError::InvalidResponse);
            }
        }
        let binding = canonical_fact_id(
            "native_body_occurrence:v1",
            &(
                self.language,
                self.evaluation,
                self.exchange_ref,
                self.producer_ref,
                self.source_path,
                self.source_ref,
                declaration.start,
                declaration.end,
                &symbol.name,
            ),
        );
        let mut lowering = Lowering {
            language: self.language,
            source,
            symbol: &binding,
            result,
            bindings,
            parameters: parameters.iter().map(|item| item.name.clone()).collect(),
            allow_bound_calls,
            calls: Vec::new(),
        };
        let (statements, _) = lowering.statements(body, &declaration)?;
        let provenance = lowering.provenance(&symbol.span)?;
        let calls = lowering.calls;
        Ok(NativeBodyOutcome::Lowered(Box::new(NativeScalarBody {
            language: self.language,
            body: ProgramBody {
                symbol: binding.clone(),
                statements,
                provenance,
            },
            binding,
            parameters: scalar_bindings(parameters),
            locals: scalar_bindings(locals),
            result,
            calls,
        })))
    }

    fn accepts(&self, scalar: NativeScalar) -> bool {
        scalar == NativeScalar::Bool || scalar == self.language.integer()
    }
}

fn call_delimiters(language: NativeBodyLanguage, mut suffix: &str) -> bool {
    if !suffix.ends_with(')') {
        return false;
    }
    loop {
        suffix = match language {
            NativeBodyLanguage::Go => suffix.trim_start_matches([' ', '\t', '\r']),
            NativeBodyLanguage::Python => {
                suffix.trim_start_matches([' ', '\t', '\r', '\n', '\x0c'])
            }
        };
        if suffix.starts_with('(') {
            return true;
        }
        let remainder = match language {
            NativeBodyLanguage::Go => suffix
                .strip_prefix("/*")
                .and_then(|comment| comment.split_once("*/"))
                // A Go block comment containing a newline can insert a semicolon.
                .filter(|(comment, _)| !comment.contains('\n'))
                .map(|(_, rest)| rest),
            NativeBodyLanguage::Python => suffix
                .strip_prefix("\\\n")
                .or_else(|| suffix.strip_prefix("\\\r\n"))
                .or_else(|| {
                    suffix
                        .strip_prefix('#')
                        .and_then(|comment| comment.split_once('\n'))
                        .map(|(_, rest)| rest)
                }),
        };
        let Some(rest) = remainder else {
            return false;
        };
        suffix = rest;
    }
}

fn scalar_bindings(bindings: &[Binding]) -> Vec<(String, NativeScalar)> {
    bindings
        .iter()
        .map(|binding| (binding.name.clone(), binding.scalar))
        .collect()
}
