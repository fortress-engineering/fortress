//! Admits exact native Go scalar body rows before shared body construction.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use super::{
    Diagnostic, GoCollectorPin, GoObservationError, GoRequest, SourceIdentity, Span, Status,
    digest, known_diagnostic, sha256,
};
use crate::program_semantics::native_body::{
    NativeBodyError, NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome, NativeScalarBody,
};
use crate::program_semantics::native_callable::NativeCallableLimitation as Limit;
use crate::project::EvaluationKey;
use crate::wire::parse_strict_json_bytes;

const PRODUCER: &str = "fortress.go-bodies@0.1.0";
const MAX_ROWS: usize = 1024;
const LIMITATIONS: [&str; 4] = [
    "CLOSED_PACKAGE_ONLY",
    "BOUNDED_BOOL_AND_SIGNED_I64_BODIES",
    "NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
    "NO_PSM_CONFORMANCE_OR_CERTIFICATION",
];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum BodyStatus {
    ObservedBodies,
    InvalidSource,
    Unsupported,
    ResourceLimit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeResponse {
    schema_version: u16,
    producer: String,
    go_toolchain: String,
    request_sha256: String,
    source_inventory: Vec<SourceIdentity>,
    status: BodyStatus,
    diagnostic: Option<Diagnostic>,
    functions: Vec<Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSymbol {
    name: String,
    span: Span,
    declaration_span: Span,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum GoBodyFunction {
    Lowered {
        span: Span,
        symbol: NativeSymbol,
        #[serde(flatten)]
        lowered: LoweredBody,
    },
    Unavailable {
        span: Span,
        symbol: Option<NativeSymbol>,
        diagnostic: Diagnostic,
        code: String,
    },
}

struct LoweredBody(Box<NativeScalarBody>);

impl Serialize for LoweredBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut wire = serializer.serialize_struct("LoweredBody", 5)?;
        wire.serialize_field("binding", self.0.binding())?;
        wire.serialize_field("parameters", self.0.parameters())?;
        wire.serialize_field("locals", self.0.locals())?;
        wire.serialize_field("result_scalar", &self.0.result())?;
        wire.serialize_field("body", self.0.body())?;
        wire.end()
    }
}

/// Exact native Go scalar bodies for the Snapshot Governance projection.
#[derive(Serialize)]
pub(crate) struct GoNativeBodyObservation {
    evaluation_key: EvaluationKey,
    exchange_sha256: String,
    producer_sha256: String,
    response_sha256: String,
    provenance: Value,
    source_inventory: Vec<SourceIdentity>,
    status: BodyStatus,
    diagnostic: Option<Diagnostic>,
    functions: Vec<GoBodyFunction>,
    limitations: [&'static str; 4],
}

pub(super) struct LinkedBody {
    pub(super) evaluation: EvaluationKey,
    pub(super) exchange: String,
    pub(super) body: Box<NativeScalarBody>,
}

impl GoNativeBodyObservation {
    pub(super) fn into_callable(self, name: &str, position: &Span) -> Result<LinkedBody, Limit> {
        if !matches!(self.status, BodyStatus::ObservedBodies) {
            return Err(Limit::BodyUnavailable);
        }

        for row in self.functions {
            match row {
                GoBodyFunction::Lowered {
                    symbol, lowered, ..
                } if symbol.name == name && &symbol.span == position => {
                    return Ok(LinkedBody {
                        evaluation: self.evaluation_key,
                        exchange: self.exchange_sha256,
                        body: lowered.0,
                    });
                }
                GoBodyFunction::Unavailable {
                    symbol: Some(symbol),
                    ..
                } if symbol.name == name && &symbol.span == position => {
                    return Err(Limit::BodyUnavailable);
                }
                _ => {}
            }
        }
        Err(Limit::OccurrenceUnresolved)
    }

    pub(crate) fn into_selected_body(
        self,
        source_path: &str,
        function: &str,
    ) -> (EvaluationKey, String, Option<Box<NativeScalarBody>>) {
        let mut matches = self.functions.into_iter().filter_map(|row| match row {
            GoBodyFunction::Lowered {
                symbol, lowered, ..
            } if symbol.span.path == source_path && symbol.name == function => Some(lowered.0),
            _ => None,
        });
        let selected = matches.next().filter(|_| matches.next().is_none());
        (self.evaluation_key, self.response_sha256, selected)
    }

    pub(crate) fn lowered_bodies(&self) -> impl Iterator<Item = Option<&NativeScalarBody>> {
        self.functions.iter().map(|function| match function {
            GoBodyFunction::Lowered { lowered, .. } => Some(lowered.0.as_ref()),
            GoBodyFunction::Unavailable { .. } => None,
        })
    }
}

impl GoRequest<'_> {
    pub(crate) fn verify_bodies(
        &self,
        launched: &GoCollectorPin<'_>,
        source_manifest: &str,
        stdout: &[u8],
    ) -> Result<GoNativeBodyObservation, GoObservationError> {
        if !digest(source_manifest) {
            return Err(GoObservationError::InvalidTrustedBinding);
        }
        let line = self.verify_transport_depth(launched, stdout, 40)?;
        let response: NativeResponse =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        self.verify_body_envelope(&response)?;

        let producer_sha256 = identity(&("fortress-go-body-producer-v1", PRODUCER, self.pin))?;
        let context_sha256 = identity(&(
            "fortress-go-body-context-v1",
            &self.context_sha256,
            &producer_sha256,
        ))?;
        let evaluation_key =
            EvaluationKey::new(source_manifest, context_sha256, self.authority_sha256);
        let response_sha256 = sha256(stdout);
        let exchange_sha256 = identity(&(
            "fortress-go-body-exchange-v1",
            &self.binding_sha256,
            &response_sha256,
            &evaluation_key,
        ))?;
        let mut previous = (String::new(), 0);
        let mut functions = Vec::with_capacity(response.functions.len());
        for row in response.functions {
            let span = occurrence(&row)?;
            if (span.path.as_str(), span.start_byte) < (previous.0.as_str(), previous.1) {
                return Err(GoObservationError::InvalidResponse);
            }
            previous = (span.path.clone(), span.end_byte);
            functions.push(self.verify_body_row(
                &row,
                span,
                &evaluation_key,
                &exchange_sha256,
                &producer_sha256,
            )?);
        }
        Ok(GoNativeBodyObservation {
            evaluation_key,
            exchange_sha256,
            producer_sha256,
            response_sha256,
            provenance: self.provenance.clone(),
            source_inventory: response.source_inventory,
            status: response.status,
            diagnostic: response.diagnostic,
            functions,
            limitations: LIMITATIONS,
        })
    }

    fn verify_body_row(
        &self,
        row: &Value,
        span: Span,
        evaluation: &EvaluationKey,
        exchange_ref: &str,
        producer_ref: &str,
    ) -> Result<GoBodyFunction, GoObservationError> {
        let original = self
            .files
            .get(span.path.as_str())
            .ok_or(GoObservationError::InvalidResponse)?;
        let index = self
            .context
            .source_inventory
            .binary_search_by(|entry| entry.path.cmp(&span.path))
            .map_err(|_| GoObservationError::InvalidResponse)?;
        let source = &self.context.source_inventory[index];
        if let Some(diagnostic) = row
            .pointer("/diagnostic/span")
            .filter(|value| !value.is_null())
        {
            let diagnostic: Span = serde_json::from_value(diagnostic.clone())
                .map_err(|_| GoObservationError::InvalidResponse)?;
            if diagnostic.path != span.path
                || diagnostic.start_byte < span.start_byte
                || diagnostic.end_byte > span.end_byte
            {
                return Err(GoObservationError::InvalidResponse);
            }
        }
        let row_bytes = serde_json::to_vec(row).map_err(|_| GoObservationError::WireEncoding)?;
        let outcome = NativeBodyInput {
            language: NativeBodyLanguage::Go,
            evaluation,
            exchange_ref,
            producer_ref,
            source_path: &span.path,
            source_ref: &source.sha256,
            source: original.text.as_bytes(),
            python_bool_parameters: &[],
        }
        .admit(&row_bytes)
        .map_err(|failure| match failure {
            NativeBodyError::ResourceLimit => GoObservationError::ResourceLimit,
            _ => GoObservationError::InvalidResponse,
        })?;
        let symbol: Option<NativeSymbol> = field(row, "symbol")?;
        match outcome {
            NativeBodyOutcome::Lowered(body) => Ok(GoBodyFunction::Lowered {
                span,
                symbol: symbol.ok_or(GoObservationError::InvalidResponse)?,
                lowered: LoweredBody(body),
            }),
            NativeBodyOutcome::Unavailable(limitation) => Ok(GoBodyFunction::Unavailable {
                span,
                symbol,
                diagnostic: field(row, "diagnostic")?,
                code: limitation.code().to_owned(),
            }),
        }
    }

    fn verify_body_envelope(&self, response: &NativeResponse) -> Result<(), GoObservationError> {
        if response.schema_version != 1
            || response.producer != PRODUCER
            || response.go_toolchain != self.pin.go_toolchain
            || response.request_sha256 != self.request_sha256
            || response.source_inventory != self.context.source_inventory
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if response.functions.len() > MAX_ROWS {
            return Err(GoObservationError::ResourceLimit);
        }
        let disposition = match response.status {
            BodyStatus::ObservedBodies if response.diagnostic.is_none() => return Ok(()),
            BodyStatus::ObservedBodies => return Err(GoObservationError::InvalidResponse),
            BodyStatus::InvalidSource => Status::InvalidSource,
            BodyStatus::Unsupported => Status::Unsupported,
            BodyStatus::ResourceLimit => Status::ResourceLimit,
        };
        let diagnostic = response
            .diagnostic
            .as_ref()
            .ok_or(GoObservationError::InvalidResponse)?;
        if !response.functions.is_empty() || !known_diagnostic(&disposition, &diagnostic.code) {
            return Err(GoObservationError::InvalidResponse);
        }
        if let Some(span) = &diagnostic.span {
            self.span(span)?;
        }
        Ok(())
    }
}

fn field<T: serde::de::DeserializeOwned>(row: &Value, name: &str) -> Result<T, GoObservationError> {
    serde_json::from_value(row.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|_| GoObservationError::InvalidResponse)
}

fn occurrence(row: &Value) -> Result<Span, GoObservationError> {
    let code = row.pointer("/diagnostic/code").and_then(Value::as_str);
    if let Some(code) = code
        && !matches!(
            code,
            "IDENTIFIER_OUTSIDE_ASCII_SCOPE"
                | "GO_SCALAR_BODY_LIMIT"
                | "UNBOUND_OR_NONLOCAL_VALUE"
                | "REPEATED_OR_SHADOWED_BINDING"
                | "SCALAR_TYPE_UNAVAILABLE"
                | "TYPE_EVIDENCE_UNAVAILABLE"
                | "EXACT_SCALAR_LITERAL_UNAVAILABLE"
                | "RUNTIME_INTEGER_ARITHMETIC_UNAVAILABLE"
                | "RUNTIME_CALL_OR_CONVERSION_UNAVAILABLE"
                | "EXPRESSION_SEMANTICS_UNAVAILABLE"
                | "STATEMENT_SEMANTICS_UNAVAILABLE"
                | "ASSIGNMENT_FORM_UNAVAILABLE"
                | "ASSIGNMENT_PLACE_UNAVAILABLE"
                | "RETURN_ARITY_UNAVAILABLE"
                | "CONDITIONAL_INITIALIZER_UNAVAILABLE"
                | "GOROUTINE_UNAVAILABLE"
                | "DEFER_UNAVAILABLE"
                | "NONFREE_OR_BODYLESS_FUNCTION"
                | "UNRESOLVED_SYMBOL"
                | "SIGNATURE_FORM_UNAVAILABLE"
                | "NAMED_RETURN_UNAVAILABLE"
        )
    {
        return Err(GoObservationError::InvalidResponse);
    }
    let span = row.pointer("/symbol/declaration_span").or_else(|| {
        (code == Some("IDENTIFIER_OUTSIDE_ASCII_SCOPE"))
            .then(|| row.pointer("/diagnostic/span"))
            .flatten()
    });
    serde_json::from_value(span.cloned().ok_or(GoObservationError::InvalidResponse)?)
        .map_err(|_| GoObservationError::InvalidResponse)
}

fn identity(value: &impl Serialize) -> Result<String, GoObservationError> {
    serde_json_canonicalizer::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| GoObservationError::WireEncoding)
}
