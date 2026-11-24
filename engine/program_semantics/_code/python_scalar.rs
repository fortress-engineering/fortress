//! Exact exchange binding for the compile-only Python scalar worker.

#[path = "python_calls.rs"]
mod python_calls;
/// Compile-only Python filesystem call shape and installed receiver admission.
#[path = "python_filesystem.rs"]
pub mod python_filesystem;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::control_layout::CONTROL_ROOT;
use crate::observation::{SourceView, is_canonical_relative_path};
use crate::project::EvaluationKey;
use crate::wire::{JsonAdmissionLimits, admit_json, parse_strict_json_bytes};

use super::native_body::{NativeBodyError, NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome};

const REQUEST_SCHEMA: &str = "fortress:python:scalar-request:1";
const RESPONSE_SCHEMA: &str = "fortress:python:scalar-response:1";
const CALL_REQUEST_SCHEMA: &str = "fortress:python:lexical-call-request:1";
const CALL_RESPONSE_SCHEMA: &str = "fortress:python:lexical-call-response:1";
const MAX_CALL_PARAMETERS: usize = 4;
const MAX_SOURCE_BYTES: usize = 32 * 1024;
const MAX_NAMES: usize = 8;
const RESPONSE_LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 256 * 1024,
    depth: 48,
    nodes: 16_000,
    token_bytes: 1536,
};

/// Independently selected exact compiler runtime and reviewed worker assets.
///
/// The owner verifies the deployment, readiness, process, and stdout framing
/// before using the exchanged payload. This record does not authenticate them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonScalarProducer {
    worker: String,
    bootstrap: String,
    runtime: String,
}

impl PythonScalarProducer {
    /// Binds the selected worker, bootstrap and interpreter runtime identities.
    ///
    /// # Errors
    /// Refuses noncanonical SHA-256 identities.
    pub fn new(
        worker: impl Into<String>,
        bootstrap: impl Into<String>,
        runtime: impl Into<String>,
    ) -> Result<Self, PythonScalarError> {
        let result = Self {
            worker: worker.into(),
            bootstrap: bootstrap.into(),
            runtime: runtime.into(),
        };
        if [&result.worker, &result.bootstrap, &result.runtime]
            .iter()
            .any(|pin| !valid_digest(pin))
        {
            return Err(PythonScalarError::Binding);
        }
        Ok(result)
    }
}

/// Source- and context-bound request for a transient Python scalar body.
///
/// Exact boolean parameter names are independently selected assumptions in
/// source declaration order. They do not describe values used at runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PythonScalarRequest {
    exchange_ref: String,
    source_view_ref: String,
    evaluation_ref: String,
    source_path: String,
    source_ref: String,
    function: String,
    parameters: Vec<String>,
    producer: PythonScalarProducer,
    #[serde(skip)]
    lexical_calls: bool,
}

impl PythonScalarRequest {
    /// Selects an exact Python file, function name and ordered boolean scope.
    ///
    /// # Errors
    /// Refuses unsupported scope, stale input premises and excessive source.
    pub fn bind(
        view: &SourceView,
        evaluation: &EvaluationKey,
        path: &str,
        function: &str,
        boolean_parameters: &[&str],
        producer: &PythonScalarProducer,
    ) -> Result<Self, PythonScalarError> {
        if !identifier(function)
            || boolean_parameters.len() > MAX_NAMES
            || boolean_parameters.iter().enumerate().any(|(index, name)| {
                !identifier(name) || boolean_parameters[..index].contains(name)
            })
            || [
                evaluation.source_manifest_digest(),
                evaluation.program_context_digest(),
                evaluation.authority_binding_digest(),
            ]
            .into_iter()
            .any(|pin| !valid_digest(pin))
        {
            return Err(PythonScalarError::Binding);
        }
        let source = admitted_source(view, path)?;
        let source_ref = digest(source);
        let evaluation_ref = evaluation.digest();
        let material = serde_json_canonicalizer::to_vec(&(
            REQUEST_SCHEMA,
            view.digest(),
            &evaluation_ref,
            path,
            &source_ref,
            function,
            boolean_parameters,
            producer,
        ))
        .map_err(PythonScalarError::Json)?;
        Ok(Self {
            exchange_ref: digest(&material),
            source_view_ref: view.digest().to_owned(),
            evaluation_ref,
            source_path: path.to_owned(),
            source_ref,
            function: function.to_owned(),
            parameters: boolean_parameters
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            producer: producer.clone(),
            lexical_calls: false,
        })
    }

    pub(crate) fn into_lexical_calls(mut self) -> Result<Self, PythonScalarError> {
        if self.parameters.len() > MAX_CALL_PARAMETERS {
            return Err(PythonScalarError::Binding);
        }
        let material = serde_json_canonicalizer::to_vec(&(CALL_REQUEST_SCHEMA, &self.exchange_ref))
            .map_err(PythonScalarError::Json)?;
        self.exchange_ref = digest(&material);
        self.lexical_calls = true;
        Ok(self)
    }

    /// Returns the unique source, policy, producer and assumption binding.
    #[must_use]
    pub fn exchange_ref(&self) -> &str {
        &self.exchange_ref
    }

    /// Returns the exact selected source-byte identity.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    fn source_bytes<'a>(
        &self,
        view: &'a SourceView,
        evaluation: &EvaluationKey,
    ) -> Result<&'a [u8], PythonScalarError> {
        if view.digest() != self.source_view_ref || evaluation.digest() != self.evaluation_ref {
            return Err(PythonScalarError::StaleInput);
        }
        admitted_source(view, &self.source_path)
    }

    fn wire_id(&self) -> &str {
        &self.exchange_ref["sha256:".len()..]
    }

    /// Encodes the worker's bounded, immutable analysis request.
    ///
    /// # Errors
    /// Refuses changed input or serialization failure.
    pub fn worker_payload(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
    ) -> Result<Vec<u8>, PythonScalarError> {
        let source = self.source_bytes(view, evaluation)?;
        serde_json_canonicalizer::to_vec(&json!({
            "schema": if self.lexical_calls { CALL_REQUEST_SCHEMA } else { REQUEST_SCHEMA },
            "id": self.wire_id(),
            "source": STANDARD.encode(source),
            "byte_count": source.len(),
            "source_path": self.source_path,
            "source_ref": self.source_ref,
            "function": self.function,
            "parameter_domains": vec!["BOOL"; self.parameters.len()],
            "worker_ref": self.producer.worker,
            "bootstrap_ref": self.producer.bootstrap,
            "runtime_ref": self.producer.runtime,
        }))
        .map_err(PythonScalarError::Json)
    }

    /// Validates the selected worker response and delegates body admission.
    ///
    /// This makes an exact native report eligible for the shared scalar body
    /// validator. Even a lowered result does not establish runtime execution.
    ///
    /// # Errors
    /// Refuses malformed, stale, displaced, oversized or unsupported replies.
    pub fn admit(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
        response: &[u8],
    ) -> Result<NativeBodyOutcome, PythonScalarError> {
        if self.lexical_calls {
            return Err(PythonScalarError::InvalidResponse);
        }
        let source = self.source_bytes(view, evaluation)?;
        admit_json(response, RESPONSE_LIMITS).map_err(|_| PythonScalarError::ResourceLimit)?;
        let raw: WorkerResponse =
            parse_strict_json_bytes(response).map_err(|_| PythonScalarError::InvalidResponse)?;
        self.validate_response(source, &raw, RESPONSE_SCHEMA)?;
        let native = raw.into_native()?;
        let producer_ref =
            serde_json_canonicalizer::to_vec(&self.producer).map_err(PythonScalarError::Json)?;
        NativeBodyInput {
            language: NativeBodyLanguage::Python,
            evaluation,
            exchange_ref: self.exchange_ref(),
            producer_ref: &digest(&producer_ref),
            source_path: &self.source_path,
            source_ref: &self.source_ref,
            source,
            python_bool_parameters: &self
                .parameters
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        }
        .admit(&native)
        .map_err(PythonScalarError::Native)
    }

    fn validate_response(
        &self,
        source: &[u8],
        raw: &WorkerResponse,
        schema: &str,
    ) -> Result<(), PythonScalarError> {
        if raw.schema != schema
            || raw.id != self.wire_id()
            || raw.source_path != self.source_path
            || raw.source_ref != self.source_ref
            || raw.byte_count != source.len()
            || raw.function != self.function
            || raw.worker_ref != self.producer.worker
            || raw.bootstrap_ref != self.producer.bootstrap
            || raw.runtime_ref != self.producer.runtime
            || raw.parameter_domains.len() != self.parameters.len()
            || raw.parameter_domains.iter().any(|domain| domain != "BOOL")
            || raw.target_execution != "NOT_RUN"
            || raw
                .symbol
                .as_ref()
                .is_some_and(|symbol| symbol["name"].as_str() != Some(self.function.as_str()))
        {
            return Err(PythonScalarError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponse {
    schema: String,
    id: String,
    source_path: String,
    source_ref: String,
    byte_count: usize,
    function: String,
    parameter_domains: Vec<String>,
    worker_ref: String,
    bootstrap_ref: String,
    runtime_ref: String,
    target_execution: String,
    status: Status,
    #[serde(deserialize_with = "present_value")]
    symbol: Option<Value>,
    parameters: Vec<Value>,
    locals: Vec<Value>,
    #[serde(deserialize_with = "present_value")]
    result_scalar: Option<Value>,
    body: Vec<Value>,
    #[serde(deserialize_with = "present_value")]
    diagnostic: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Status {
    Lowerable,
    Unavailable,
}

fn present_value<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Option<Value>, D::Error> {
    Option::deserialize(input)
}

impl WorkerResponse {
    fn into_native(self) -> Result<Vec<u8>, PythonScalarError> {
        let payload = match (self.status, self.result_scalar, self.diagnostic) {
            (Status::Lowerable, Some(result), None) if self.symbol.is_some() => json!({
                "status":"LOWERABLE", "symbol": self.symbol, "parameters": self.parameters,
                "locals": self.locals, "result_scalar": result, "body": self.body,
            }),
            (Status::Unavailable, None, Some(diagnostic)) => json!({
                "status":"UNAVAILABLE", "symbol": self.symbol, "parameters": self.parameters,
                "locals": self.locals, "body": self.body, "diagnostic": diagnostic,
            }),
            _ => return Err(PythonScalarError::InvalidResponse),
        };
        serde_json_canonicalizer::to_vec(&payload).map_err(PythonScalarError::Json)
    }
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn admitted_source<'a>(view: &'a SourceView, path: &str) -> Result<&'a [u8], PythonScalarError> {
    let root = path.split('/').next().unwrap_or_default();
    if path.len() > 240
        || !is_canonical_relative_path(path)
        || Path::new(path).extension().and_then(|part| part.to_str()) != Some("py")
        || root.eq_ignore_ascii_case(CONTROL_ROOT)
        || root.eq_ignore_ascii_case(".git")
        || !path.split('/').all(|part| {
            part.len() <= 64
                && part
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
                && !part.ends_with('.')
        })
    {
        return Err(PythonScalarError::Binding);
    }
    let source = view
        .bytes(path)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(PythonScalarError::Binding)?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err(PythonScalarError::ResourceLimit);
    }
    if std::str::from_utf8(source).is_err() {
        return Err(PythonScalarError::UnsupportedEncoding);
    }
    Ok(source)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Failure to establish an exact Python native scalar exchange.
#[derive(Debug)]
pub enum PythonScalarError {
    /// The independently selected source, scope or producer binding is invalid.
    Binding,
    /// The current source view or evaluation differs from the request.
    StaleInput,
    /// A source or response resource bound was exceeded.
    ResourceLimit,
    /// The selected source is outside the admitted UTF-8 envelope.
    UnsupportedEncoding,
    /// The exchange response is malformed or disagrees with the selected inputs.
    InvalidResponse,
    /// Canonical output construction failed.
    Json(serde_json::Error),
    /// The shared native body validator refused the projection.
    Native(NativeBodyError),
}

impl Display for PythonScalarError {
    fn fmt(&self, output: &mut Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Binding => "invalid Python scalar input binding",
            Self::StaleInput => "stale Python scalar input",
            Self::ResourceLimit => "Python scalar resource limit exceeded",
            Self::UnsupportedEncoding => "unsupported Python scalar source encoding",
            Self::InvalidResponse => "invalid Python scalar exchange response",
            Self::Json(_) => "Python scalar JSON construction failed",
            Self::Native(_) => "Python scalar body refused by the shared validator",
        })
    }
}

impl Error for PythonScalarError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program_semantics::{ProgramExpression, ProgramStatement};

    const PATH: &str = "src/subject.py";
    const SOURCE: &[u8] = b"def subject(gate):\n    return not gate\n";

    fn pin(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn test_binding(names: &[&str]) -> (SourceView, EvaluationKey, PythonScalarRequest) {
        let view = SourceView::from_bytes([(PATH, SOURCE.to_vec())]).expect("fixture view");
        let evaluation = EvaluationKey::new(pin('a'), pin('b'), pin('c'));
        let producer =
            PythonScalarProducer::new(pin('d'), pin('e'), pin('f')).expect("fixture pins");
        let request =
            PythonScalarRequest::bind(&view, &evaluation, PATH, "subject", names, &producer)
                .expect("fixture request");
        (view, evaluation, request)
    }

    fn response(request: &PythonScalarRequest) -> Value {
        let first_line = |start: usize, end: usize| {
            json!({
                "path":PATH,"start_byte":start,"end_byte":end,
                "start_line":1,"start_byte_column":start+1,
            })
        };
        json!({
            "schema":"fortress:python:scalar-response:1",
            "id":request.wire_id(),"byte_count":SOURCE.len(),
            "source_path":PATH,"source_ref":digest(SOURCE),"function":"subject",
            "parameter_domains":["BOOL"],"worker_ref":pin('d'),"bootstrap_ref":pin('e'),
            "runtime_ref":pin('f'),"target_execution":"NOT_RUN","status":"LOWERABLE",
            "symbol":{"name":"subject","span":first_line(4,11),"declaration_span":first_line(0,38)},
            "parameters":[{"name":"gate","scalar":"BOOL","span":first_line(12,16)}],
            "locals":[],"result_scalar":"BOOL","diagnostic":null,
            "body":[{"kind":"return",
                "span":{"path":PATH,"start_byte":23,"end_byte":38,"start_line":2,"start_byte_column":5},
                "value":{"kind":"unary","operator":"!","value":{"kind":"binding","name":"gate"}}}],
        })
    }

    fn admit_fixture(
        view: &SourceView,
        key: &EvaluationKey,
        request: &PythonScalarRequest,
        response: &Value,
    ) -> Result<NativeBodyOutcome, PythonScalarError> {
        request.admit(
            view,
            key,
            &serde_json::to_vec(response).expect("bounded fixture response"),
        )
    }

    /// `T-PYTHON-SCALAR-REPLY-SCOPE-001`
    /// Fortress classification: infrastructure
    #[test]
    fn python_native_reply_reaches_shared_program_body_without_assuming_runtime_values() {
        let (view, key, req) = test_binding(&["gate"]);
        let wire: Value =
            serde_json::from_slice(&req.worker_payload(&view, &key).expect("worker input"))
                .expect("request decodes");
        assert_eq!(wire["parameter_domains"], json!(["BOOL"]));
        assert_eq!(wire["source_ref"], digest(SOURCE));
        let NativeBodyOutcome::Lowered(result) = admit_fixture(&view, &key, &req, &response(&req))
            .expect("shared Program Semantics admitted bounded witness")
        else {
            panic!("fixture requires a shared body");
        };
        assert!(matches!(
            result.body().statements(),
            [ProgramStatement::Return {value:Some(ProgramExpression::Unary {operator,value}),..}]
                if operator == "!"
                    && matches!(value.as_ref(), ProgramExpression::Binding {name} if name == "gate")
        ));

        let (_, _, mismatched) = test_binding(&["different"]);
        assert_ne!(mismatched.exchange_ref(), req.exchange_ref());
        assert!(matches!(
            admit_fixture(&view, &key, &mismatched, &response(&mismatched)),
            Err(PythonScalarError::Native(NativeBodyError::InvalidResponse))
        ));
    }

    /// `T-PYTHON-SCALAR-REPLY-REFUSAL-001`
    /// Fortress classification: infrastructure
    #[test]
    fn malformed_forged_or_displaced_scalar_replies_never_produce_a_shared_body() {
        let (view, key, req) = test_binding(&["gate"]);
        let stale = EvaluationKey::new(pin('a'), pin('b'), pin('1'));
        let original = response(&req);
        assert!(matches!(
            admit_fixture(&view, &stale, &req, &original),
            Err(PythonScalarError::StaleInput)
        ));
        let changed =
            SourceView::from_bytes([(PATH, b"def subject(gate): return gate\n".to_vec())])
                .expect("different exact source");
        assert!(matches!(
            admit_fixture(&changed, &key, &req, &original),
            Err(PythonScalarError::StaleInput)
        ));
        for (field, value) in [
            ("target_execution", json!("PASS")),
            ("worker_ref", json!(pin('0'))),
            ("source_ref", json!(pin('1'))),
            ("unknown_approval", Value::Bool(true)),
        ] {
            let mut forged = original.clone();
            forged[field] = value;
            assert!(matches!(
                admit_fixture(&view, &key, &req, &forged),
                Err(PythonScalarError::InvalidResponse)
            ));
        }

        let mut unavailable = original;
        unavailable["status"] = json!("UNAVAILABLE");
        unavailable["result_scalar"] = Value::Null;
        unavailable["diagnostic"] = json!({"code":"CALL_UNSUPPORTED","span":null});
        assert!(matches!(
            admit_fixture(&view, &key, &req, &unavailable),
            Err(PythonScalarError::Native(NativeBodyError::InvalidResponse))
        ));
        unavailable["body"] = json!([]);
        unavailable["parameters"] = json!([]);
        let NativeBodyOutcome::Unavailable(reason) = admit_fixture(&view, &key, &req, &unavailable)
            .expect("explicit unavailability retains its reason")
        else {
            panic!("unavailable result must not construct a body");
        };
        assert_eq!(reason.code(), "CALL_UNSUPPORTED");
    }
}
