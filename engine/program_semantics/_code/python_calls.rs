//! Exact source and ordered declaration admission for Python lexical calls.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{
    CALL_RESPONSE_SCHEMA, MAX_CALL_PARAMETERS, PythonScalarError, PythonScalarRequest,
    RESPONSE_LIMITS, WorkerResponse, digest,
};
use crate::observation::SourceView;
use crate::program_semantics::native_body::{
    NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome, NativeCallBindings, NativeScalar,
    NativeScalarBody, Symbol,
};
use crate::project::EvaluationKey;
use crate::wire::{admit_json, parse_strict_json_bytes};

const MAX_HELPERS: usize = 16;

pub(crate) struct PythonLexicalCalls {
    pub(crate) root: NativeBodyOutcome,
    helpers: Vec<NativeScalarBody>,
}

impl PythonLexicalCalls {
    pub(crate) fn targets(&self) -> Result<NativeCallBindings<'_>, PythonScalarError> {
        let mut targets = NativeCallBindings::default();
        let NativeBodyOutcome::Lowered(root) = &self.root else {
            return Ok(targets);
        };
        let declarations = self
            .helpers
            .iter()
            .map(|body| (body.declaration().name.as_str(), body))
            .collect::<BTreeMap<_, _>>();
        for caller in std::iter::once(root.as_ref()).chain(&self.helpers) {
            for call in caller.bound_calls() {
                let name = &call.target.name;
                if caller
                    .parameters()
                    .iter()
                    .chain(caller.locals())
                    .any(|(binding, _)| binding == name)
                {
                    return Err(PythonScalarError::InvalidResponse);
                }
                let target = declarations
                    .get(name.as_str())
                    .ok_or(PythonScalarError::InvalidResponse)?;
                targets
                    .insert(caller, call, root.source_ref(), Some(*target))
                    .map_err(|_| PythonScalarError::InvalidResponse)?;
            }
        }
        Ok(targets)
    }
}

impl PythonScalarRequest {
    pub(crate) fn admit_lexical_calls(
        &self,
        view: &SourceView,
        evaluation: &EvaluationKey,
        response: &[u8],
    ) -> Result<PythonLexicalCalls, PythonScalarError> {
        if !self.lexical_calls {
            return Err(PythonScalarError::InvalidResponse);
        }
        let source = self.source_bytes(view, evaluation)?;
        admit_json(response, RESPONSE_LIMITS).map_err(|_| PythonScalarError::ResourceLimit)?;
        let mut wire: Value =
            parse_strict_json_bytes(response).map_err(|_| PythonScalarError::InvalidResponse)?;
        let helpers = wire
            .as_object_mut()
            .and_then(|object| object.remove("helpers"))
            .and_then(|helpers| match helpers {
                Value::Array(helpers) => Some(helpers),
                _ => None,
            })
            .ok_or(PythonScalarError::InvalidResponse)?;
        if helpers.len() > MAX_HELPERS {
            return Err(PythonScalarError::ResourceLimit);
        }
        let selected: WorkerResponse =
            serde_json::from_value(wire).map_err(|_| PythonScalarError::InvalidResponse)?;
        self.validate_response(source, &selected, CALL_RESPONSE_SCHEMA)?;
        let producer_ref = digest(
            &serde_json_canonicalizer::to_vec(&self.producer).map_err(PythonScalarError::Json)?,
        );
        let parameters = self
            .parameters
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let input = NativeBodyInput {
            language: NativeBodyLanguage::Python,
            evaluation,
            exchange_ref: self.exchange_ref(),
            producer_ref: &producer_ref,
            source_path: &self.source_path,
            source_ref: self.source_ref(),
            source,
            python_bool_parameters: &parameters,
        };
        let first_statement = selected
            .body
            .first()
            .and_then(|statement| statement.pointer("/span/start_byte"))
            .and_then(Value::as_u64)
            .and_then(|byte| usize::try_from(byte).ok());
        let root = input
            .admit_bound_calls(&selected.into_native()?)
            .map_err(PythonScalarError::Native)?;
        let helpers = match &root {
            NativeBodyOutcome::Lowered(body) => verify_helpers(
                &input,
                &helpers,
                body.declaration(),
                first_statement.ok_or(PythonScalarError::InvalidResponse)?,
            )?,
            NativeBodyOutcome::Unavailable(_) if helpers.is_empty() => Vec::new(),
            NativeBodyOutcome::Unavailable(_) => return Err(PythonScalarError::InvalidResponse),
        };
        let outcome = PythonLexicalCalls { root, helpers };
        outcome.targets()?;
        Ok(outcome)
    }
}

fn verify_helpers(
    input: &NativeBodyInput<'_>,
    helpers: &[Value],
    enclosing: &Symbol,
    first_statement: usize,
) -> Result<Vec<NativeScalarBody>, PythonScalarError> {
    if first_statement > enclosing.declaration_span.end_byte {
        return Err(PythonScalarError::InvalidResponse);
    }
    let mut previous_end = enclosing.span.end_byte;
    let mut names = BTreeSet::new();
    let mut bodies = Vec::with_capacity(helpers.len());
    for row in helpers {
        let symbol = row
            .get("symbol")
            .cloned()
            .map(serde_json::from_value::<Symbol>)
            .transpose()
            .map_err(|_| PythonScalarError::InvalidResponse)?
            .ok_or(PythonScalarError::InvalidResponse)?;
        let parameters = row
            .get("parameters")
            .and_then(Value::as_array)
            .ok_or(PythonScalarError::InvalidResponse)?
            .iter()
            .map(|parameter| parameter.get("name").and_then(Value::as_str))
            .collect::<Option<Vec<_>>>()
            .ok_or(PythonScalarError::InvalidResponse)?;
        if parameters.len() > MAX_CALL_PARAMETERS
            || !names.insert(symbol.name.clone())
            || input.python_bool_parameters.contains(&symbol.name.as_str())
            || symbol.declaration_span.start_byte < previous_end
            || symbol.declaration_span.end_byte > first_statement
        {
            return Err(PythonScalarError::InvalidResponse);
        }
        previous_end = symbol.declaration_span.end_byte;
        let source = NativeBodyInput {
            python_bool_parameters: &parameters,
            ..*input
        };
        let payload = serde_json_canonicalizer::to_vec(row).map_err(PythonScalarError::Json)?;
        let NativeBodyOutcome::Lowered(body) = source
            .admit_bound_calls(&payload)
            .map_err(PythonScalarError::Native)?
        else {
            return Err(PythonScalarError::InvalidResponse);
        };
        if body.result() != NativeScalar::Bool {
            return Err(PythonScalarError::InvalidResponse);
        }
        bodies.push(*body);
    }
    Ok(bodies)
}
